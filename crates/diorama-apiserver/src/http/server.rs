//! Accept loop for the API server HTTPS listener.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use diorama_datastore::{WatchEventType, WatchReceiver};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::channel::Channel;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::client::KubernetesApiClient;
use crate::error::ApiserverError;
use crate::service::ApiserverService;

use super::dispatch::{self, Payload};
use super::query;
use super::route::{self, ResourcePath, Route, wants_aggregated_discovery};
use super::tls::{self, PeerIdentity};

const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_CONNECTIONS: usize = 256;
/// Upper bound for a watch without `timeoutSeconds`; kubectl reconnects.
const DEFAULT_WATCH_TIMEOUT: Duration = Duration::from_mins(30);

type Body = BoxBody<Bytes, Infallible>;

pub(crate) async fn bind_listener(
    config: &crate::config::ApiserverConfig,
) -> Result<TcpListener, ApiserverError> {
    let preferred = SocketAddr::new(config.bind_address, config.secure_port);
    match TcpListener::bind(preferred).await {
        Ok(listener) => Ok(listener),
        Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
            let fallback = SocketAddr::new(config.bind_address, 0);
            TcpListener::bind(fallback)
                .await
                .map_err(ApiserverError::from)
        },
        Err(err) => Err(err.into()),
    }
}

pub(crate) async fn serve(
    listener: TcpListener,
    service: ApiserverService,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ApiserverError> {
    let tls_config = tls::server_config(service.config())?;
    let acceptor = TlsAcceptor::from(tls_config);
    let mut connections = JoinSet::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                let (stream, _) = match accepted {
                    Ok(conn) => conn,
                    Err(err) => {
                        eprintln!("apiserver accept error: {err}");
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let service = service.clone();
                let shutdown_rx = shutdown.clone();
                connections.spawn(async move {
                    let Ok(Ok(tls)) =
                        tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await
                    else {
                        return;
                    };
                    let peer = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|chain| chain.first())
                        .and_then(|cert| tls::identity_from_der(cert.as_ref()));
                    let io = TokioIo::new(tls);
                    let mut hyper = hyper::server::conn::http1::Builder::new();
                    hyper.timer(TokioTimer::new());
                    hyper.header_read_timeout(Duration::from_secs(30));
                    let connection = hyper.serve_connection(
                        io,
                        service_fn(move |request| {
                            let service = service.clone();
                            let peer = peer.clone();
                            let shutdown_rx = shutdown_rx.clone();
                            async move {
                                Ok::<_, Infallible>(
                                    handle(request, &service, peer.as_ref(), shutdown_rx).await,
                                )
                            }
                        }),
                    );
                    let _ = connection.await;
                });
            }
        }
    }
    drop(listener);
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn handle(
    request: Request<Incoming>,
    service: &ApiserverService,
    peer: Option<&PeerIdentity>,
    shutdown: watch::Receiver<bool>,
) -> Response<Body> {
    let path = request.uri().path().to_string();
    let route = route::parse(&path);
    if matches!(route, Route::Health) {
        return health(service, &path).await;
    }
    if matches!(route, Route::Version) {
        return json_response(StatusCode::OK, &version());
    }

    let query = request.uri().query().map(str::to_owned);
    let bearer = bearer_token(&request);
    let client = client_for(service, peer, bearer.as_deref());
    let accept = request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let method = request.method().clone();
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if !matches!(route, Route::Resource(_)) && method != Method::GET {
        return status_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "method is not supported",
        );
    }
    let body = match Limited::new(request.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return status_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "RequestEntityTooLarge",
                "request body exceeds 1MiB",
            );
        },
    };

    match route {
        Route::Health | Route::Version => unreachable!("handled above"),
        Route::NotFound => status_response(
            StatusCode::NOT_FOUND,
            "NotFound",
            "the server could not find the requested resource",
        ),
        Route::ApiVersions => authenticated_document(&client, || api_versions(service)),
        Route::OpenApiV3Index => authenticated_document(&client, crate::openapi::v3_index),
        Route::OpenApiV3Core => authenticated_document(&client, crate::openapi::v3_core),
        Route::OpenApiV3StorageV1 => authenticated_document(&client, crate::openapi::v3_storage_v1),
        Route::CoreDiscovery => aggregated_or(
            accept.as_deref(),
            || core_aggregated(&client),
            || client.discover_core(),
        ),
        Route::ApiGroupList => aggregated_or(
            accept.as_deref(),
            || groups_aggregated(&client),
            || client.discover_apis(),
        ),
        Route::GroupDiscovery { group, version } => {
            discovery_result(client.discover_group_resources(&group, &version))
        },
        Route::Resource(path) => {
            let params = query::parse(query.as_deref());
            if method == Method::GET && path.name.is_none() && is_watch(&params) {
                return watch_response(service, &client, &path, &params, shutdown).await;
            }
            match dispatch::dispatch(
                service,
                &client,
                &method,
                &path,
                content_type.as_deref(),
                query.as_deref(),
                &body,
            )
            .await
            {
                Ok(outcome) => outcome_to_response(outcome, &path, accept.as_deref()),
                Err(err) => error_response(&err),
            }
        },
    }
}

fn outcome_to_response(
    outcome: dispatch::Outcome,
    path: &ResourcePath,
    accept: Option<&str>,
) -> Response<Body> {
    match outcome.body {
        Payload::Json(body) => {
            if outcome.status.is_success()
                && is_table_request(accept)
                && supports_table(path)
                && body.get("kind").and_then(Value::as_str) != Some("Status")
            {
                let content_type = table_content_type(accept);
                json_response_with_type(
                    outcome.status,
                    content_type,
                    &resource_to_table(&path.resource, &body),
                )
            } else {
                json_response(outcome.status, &body)
            }
        },
        Payload::Text(body) => text_response(outcome.status, body),
        Payload::ChunkedText(body) => chunked_text_response(outcome.status, body),
    }
}

fn is_watch(params: &BTreeMap<String, String>) -> bool {
    params
        .get("watch")
        .is_some_and(|value| value == "true" || value == "1")
}

/// Streams Kubernetes watch events as newline-delimited JSON.
///
/// Two client protocols are served. A classic watch sends the current collection
/// as `ADDED` events newer than `resourceVersion`, then live datastore events.
/// A watch-list request (`sendInitialEvents=true`, used by kubectl's informers
/// and its delete waiter) sends the whole collection, then a `BOOKMARK` carrying
/// the `k8s.io/initial-events-end` annotation, then live events. Either way the
/// stream ends when `timeoutSeconds` elapses or the client goes away.
/// `fieldSelector=metadata.name=<name>` is the only selector honoured.
async fn watch_response(
    service: &ApiserverService,
    client: &KubernetesApiClient,
    path: &ResourcePath,
    params: &BTreeMap<String, String>,
    shutdown: watch::Receiver<bool>,
) -> Response<Body> {
    let receiver = match client
        .watch_resource(&path.group, &path.resource, path.namespace.as_deref())
        .await
    {
        Ok(receiver) => receiver,
        Err(err) => return error_response(&err),
    };
    let initial =
        match dispatch::dispatch(service, client, &Method::GET, path, None, None, &[]).await {
            Ok(outcome) => match outcome.body {
                Payload::Json(body) => body,
                Payload::Text(_) | Payload::ChunkedText(_) => Value::Null,
            },
            Err(err) => return error_response(&err),
        };
    let filter = WatchFilter {
        name: params
            .get("fieldSelector")
            .and_then(|selector| selector.strip_prefix("metadata.name="))
            .map(str::to_owned),
        since: params
            .get("resourceVersion")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        send_initial_events: params
            .get("sendInitialEvents")
            .is_some_and(|value| value == "true"),
        namespaced: path.namespace.is_some() || dispatch_is_namespaced(&path.resource),
        namespace: path.namespace.clone(),
        api_version: if path.group.is_empty() {
            "v1".to_string()
        } else {
            format!("{}/v1", path.group)
        },
        kind: dispatch::kind_name(&path.resource)
            .unwrap_or("Object")
            .to_string(),
    };
    let timeout = params
        .get("timeoutSeconds")
        .and_then(|value| value.parse().ok())
        .map_or(DEFAULT_WATCH_TIMEOUT, Duration::from_secs);
    let (sender, channel) = Channel::<Bytes, Infallible>::new(32);
    tokio::spawn(stream_watch(
        sender, receiver, initial, filter, timeout, shutdown,
    ));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(channel.boxed())
        .unwrap_or_else(|_| {
            status_response(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", "watch")
        })
}

fn dispatch_is_namespaced(resource: &str) -> bool {
    !matches!(
        resource,
        "namespaces" | "nodes" | "persistentvolumes" | "storageclasses"
    )
}

struct WatchFilter {
    name: Option<String>,
    since: u64,
    send_initial_events: bool,
    namespaced: bool,
    namespace: Option<String>,
    api_version: String,
    kind: String,
}

impl WatchFilter {
    /// Minimal typed object for a storage key such as `/registry/pods/default/hello`.
    fn object_from_key(&self, key: &str) -> Value {
        let mut segments = key.trim_end_matches('/').rsplit('/');
        let name = segments.next().unwrap_or_default();
        let mut metadata = json!({ "name": name });
        if self.namespaced
            && let Some(namespace) = segments.next()
        {
            metadata["namespace"] = json!(namespace);
        }
        json!({ "kind": self.kind, "apiVersion": self.api_version, "metadata": metadata })
    }

    fn accepts(&self, object: &Value) -> bool {
        self.name.as_deref().is_none_or(|wanted| {
            object.pointer("/metadata/name").and_then(Value::as_str) == Some(wanted)
        })
    }
}

async fn stream_watch(
    mut sender: http_body_util::channel::Sender<Bytes, Infallible>,
    receiver: WatchReceiver,
    initial: Value,
    filter: WatchFilter,
    timeout: Duration,
    shutdown: watch::Receiver<bool>,
) {
    if *shutdown.borrow() {
        return;
    }
    let mut sent: BTreeMap<String, u64> = BTreeMap::new();
    let mut found = false;
    let list_version = resource_version(&initial);
    for item in initial
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if *shutdown.borrow() {
            return;
        }
        if !filter.accepts(item) {
            continue;
        }
        found = true;
        let version = resource_version(item);
        sent.insert(object_key(item), version);
        let wanted = filter.send_initial_events || version > filter.since;
        if wanted && send_event(&mut sender, "ADDED", item).await.is_err() {
            return;
        }
    }
    // Live events start after what the client already has: the list for a
    // watch-list request, its own resourceVersion for a classic watch.
    let threshold = if filter.send_initial_events {
        list_version.max(filter.since)
    } else {
        filter.since
    };
    if filter.send_initial_events {
        let bookmark = json!({
            "kind": filter.kind,
            "apiVersion": filter.api_version,
            "metadata": {
                "resourceVersion": threshold.to_string(),
                "annotations": { "k8s.io/initial-events-end": "true" }
            }
        });
        if send_event(&mut sender, "BOOKMARK", &bookmark)
            .await
            .is_err()
        {
            return;
        }
    } else if !found
        && filter.since > 0
        && let Some(name) = &filter.name
    {
        // The named object vanished between the client's GET and this watch.
        let mut metadata = json!({ "name": name });
        if let Some(namespace) = &filter.namespace {
            metadata["namespace"] = json!(namespace);
        }
        let gone = json!({
            "kind": filter.kind,
            "apiVersion": filter.api_version,
            "metadata": metadata
        });
        let _ = send_event(&mut sender, "DELETED", &gone).await;
        return;
    }
    stream_live_events(
        sender, receiver, &filter, &mut sent, threshold, timeout, shutdown,
    )
    .await;
}

/// Forwards datastore events newer than `threshold` until the timeout or disconnect.
async fn stream_live_events(
    mut sender: http_body_util::channel::Sender<Bytes, Infallible>,
    mut receiver: WatchReceiver,
    filter: &WatchFilter,
    sent: &mut BTreeMap<String, u64>,
    threshold: u64,
    timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if *shutdown.borrow() {
            break;
        }
        let event = tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            event = receiver.recv() => match event {
                Ok(event) => event,
                Err(_) => break,
            },
        };
        let (kind, source) = match event.event_type {
            WatchEventType::Put if event.prev_kv.is_none() => ("ADDED", Some(&event.kv)),
            WatchEventType::Put => ("MODIFIED", Some(&event.kv)),
            WatchEventType::Delete => ("DELETED", event.prev_kv.as_ref()),
        };
        // A delete may arrive without the previous value; the key still names the object.
        let mut object = match source.and_then(|kv| serde_json::from_slice::<Value>(&kv.value).ok())
        {
            Some(object) => object,
            None if kind == "DELETED" => filter.object_from_key(&event.kv.key),
            None => continue,
        };
        if let Some(meta) = object.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(event.kv.mod_revision.to_string()),
            );
        }
        if !filter.accepts(&object) {
            continue;
        }
        let key = object_key(&object);
        // The datastore reports a delete with the deleted entry's own revision, so
        // the revision threshold applies only to puts; a delete always moves forward.
        let stale = kind != "DELETED"
            && (sent
                .get(&key)
                .is_some_and(|last| *last >= event.kv.mod_revision)
                || event.kv.mod_revision <= threshold);
        if stale {
            continue;
        }
        if !filter.namespaced && object.pointer("/metadata/namespace").is_some() {
            continue;
        }
        sent.insert(key, event.kv.mod_revision);
        if send_event(&mut sender, kind, &object).await.is_err() {
            return;
        }
    }
}

async fn send_event(
    sender: &mut http_body_util::channel::Sender<Bytes, Infallible>,
    kind: &str,
    object: &Value,
) -> Result<(), http_body_util::channel::SendError> {
    let mut line = serde_json::to_vec(&json!({ "type": kind, "object": object }))
        .unwrap_or_else(|_| b"{}".to_vec());
    line.push(b'\n');
    sender.send_data(Bytes::from(line)).await
}

fn resource_version(object: &Value) -> u64 {
    object
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn object_key(object: &Value) -> String {
    format!(
        "{}/{}",
        object
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or(""),
        object
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("")
    )
}

fn version() -> Value {
    json!({
        "major": "1",
        "minor": "35",
        "gitVersion": "v1.35.7",
        "platform": format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
    })
}

/// Serves a static document to any client that may read core discovery.
fn authenticated_document(
    client: &KubernetesApiClient,
    document: impl FnOnce() -> Value,
) -> Response<Body> {
    match client.discover_core() {
        Ok(_) => json_response(StatusCode::OK, &document()),
        Err(err) => error_response(&err),
    }
}

fn aggregated_or(
    accept: Option<&str>,
    aggregated: impl FnOnce() -> Result<Value, ApiserverError>,
    legacy: impl FnOnce() -> Result<Value, ApiserverError>,
) -> Response<Body> {
    if wants_aggregated_discovery(accept) {
        discovery_result(aggregated())
    } else {
        discovery_result(legacy())
    }
}

fn discovery_result(result: Result<Value, ApiserverError>) -> Response<Body> {
    match result {
        Ok(body) => json_response(StatusCode::OK, &body),
        Err(err) => error_response(&err),
    }
}

fn api_versions(service: &ApiserverService) -> Value {
    let server = service.bound_addr().map_or_else(
        || {
            format!(
                "{}:{}",
                service.config().bind_address,
                service.config().secure_port
            )
        },
        |addr| addr.to_string(),
    );
    json!({
        "kind": "APIVersions",
        "versions": ["v1"],
        "serverAddressByClientCIDRs": [{
            "clientCIDR": "0.0.0.0/0",
            "serverAddress": server
        }]
    })
}

fn core_aggregated(client: &KubernetesApiClient) -> Result<Value, ApiserverError> {
    let legacy = client.discover_core()?;
    Ok(discovery_list("", "v1", &legacy))
}

fn groups_aggregated(client: &KubernetesApiClient) -> Result<Value, ApiserverError> {
    let groups = client.discover_apis()?;
    let mut items = Vec::new();
    let Some(entries) = groups.get("groups").and_then(Value::as_array) else {
        return Ok(json!({
            "kind": "APIGroupDiscoveryList",
            "apiVersion": "apidiscovery.k8s.io/v2",
            "metadata": {},
            "items": items
        }));
    };
    for group in entries {
        let Some(name) = group.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(version) = group
            .pointer("/preferredVersion/version")
            .and_then(Value::as_str)
        else {
            continue;
        };
        let resources = client.discover_group_resources(name, version)?;
        items.push(group_item(name, version, &resources));
    }
    Ok(json!({
        "kind": "APIGroupDiscoveryList",
        "apiVersion": "apidiscovery.k8s.io/v2",
        "metadata": {},
        "items": items
    }))
}

fn discovery_list(group: &str, version: &str, resources: &Value) -> Value {
    json!({
        "kind": "APIGroupDiscoveryList",
        "apiVersion": "apidiscovery.k8s.io/v2",
        "metadata": {},
        "items": [group_item(group, version, resources)]
    })
}

fn group_item(group: &str, version: &str, resources: &Value) -> Value {
    let entries = resources
        .get("resources")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|resource| {
                    json!({
                        "resource": resource["name"],
                        "singularResource": resource["singularName"],
                        "shortNames": resource.get("shortNames").cloned().unwrap_or(json!([])),
                        "responseKind": {
                            "group": group,
                            "version": version,
                            "kind": resource["kind"]
                        },
                        "scope": if resource["namespaced"].as_bool() == Some(true) {
                            "Namespaced"
                        } else {
                            "Cluster"
                        },
                        "verbs": resource["verbs"]
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "metadata": { "name": group },
        "versions": [{
            "version": version,
            "resources": entries
        }]
    })
}

async fn health(service: &ApiserverService, path: &str) -> Response<Body> {
    if path == "/readyz" {
        match service.check_readiness().await {
            Ok(report) if report.is_healthy => text(StatusCode::OK, "ok"),
            Ok(_) | Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "not ready"),
        }
    } else if service.is_running() {
        text(StatusCode::OK, "ok")
    } else {
        text(StatusCode::INTERNAL_SERVER_ERROR, "not ready")
    }
}

fn client_for(
    service: &ApiserverService,
    peer: Option<&PeerIdentity>,
    bearer: Option<&str>,
) -> KubernetesApiClient {
    if let Some(peer) = peer {
        service.user_client(peer.username.clone(), peer.groups.clone())
    } else if let Some(token) = bearer {
        service.token_client(token)
    } else {
        service.anonymous_client()
    }
}

fn bearer_token(request: &Request<Incoming>) -> Option<String> {
    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    value.strip_prefix("Bearer ").map(str::to_owned)
}

fn error_response(err: &ApiserverError) -> Response<Body> {
    let (status, reason) = match &err {
        ApiserverError::Unauthenticated { .. } => (StatusCode::UNAUTHORIZED, "Unauthorized"),
        ApiserverError::Unauthorized { .. } | ApiserverError::AdmissionDenied { .. } => {
            (StatusCode::FORBIDDEN, "Forbidden")
        },
        ApiserverError::NotFound { .. } => (StatusCode::NOT_FOUND, "NotFound"),
        ApiserverError::Conflict { .. } => (StatusCode::CONFLICT, "AlreadyExists"),
        ApiserverError::BadRequest { .. } | ApiserverError::InvalidInput { .. } => {
            (StatusCode::BAD_REQUEST, "BadRequest")
        },
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
    };
    status_response(status, reason, &err.to_string())
}

fn status_response(status: StatusCode, reason: &str, message: &str) -> Response<Body> {
    json_response(
        status,
        &json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": if status.is_success() { "Success" } else { "Failure" },
            "message": message,
            "reason": reason,
            "code": status.as_u16()
        }),
    )
}

fn json_response(status: StatusCode, body: &Value) -> Response<Body> {
    json_response_with_type(status, "application/json", body)
}

fn json_response_with_type(
    status: StatusCode,
    content_type: &'static str,
    body: &Value,
) -> Response<Body> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    response(status, content_type, Bytes::from(bytes))
}

fn chunked_text_response(status: StatusCode, body: String) -> Response<Body> {
    let (mut sender, channel) = Channel::<Bytes, Infallible>::new(1);
    tokio::spawn(async move {
        if !body.is_empty() {
            let _ = sender.send_data(Bytes::from(body)).await;
        }
    });
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(channel.boxed())
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"")).boxed()))
}

fn format_age(created: u64, now: u64) -> String {
    let secs = now.saturating_sub(created);
    if secs < 120 {
        format!("{secs}s")
    } else if secs < 7_200 {
        format!("{}m", secs / 60)
    } else if secs < 172_800 {
        format!("{}h", secs / 3_600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

fn item_age(item: &Value, now: u64) -> String {
    item.pointer("/metadata/creationTimestamp")
        .and_then(Value::as_str)
        .and_then(crate::time::parse_rfc3339_seconds)
        .map_or_else(
            || "<unknown>".to_string(),
            |created| format_age(created, now),
        )
}

fn pod_row(pod: &Value, now: u64) -> Value {
    let name = pod
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let total = pod
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let ready = pod
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
        .map_or(0, |statuses| {
            statuses
                .iter()
                .filter(|s| s.get("ready").and_then(Value::as_bool).unwrap_or(false))
                .count()
        });
    let ready_str = format!("{ready}/{total}");

    let phase = pod
        .pointer("/status/phase")
        .and_then(Value::as_str)
        .unwrap_or("Unknown");
    let mut status_str = phase.to_string();
    if let Some(statuses) = pod
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
    {
        for cs in statuses {
            if let Some(reason) = cs.pointer("/state/waiting/reason").and_then(Value::as_str) {
                status_str = reason.to_string();
                break;
            }
        }
    }

    let restarts: i64 = pod
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
        .map_or(0, |statuses| {
            statuses
                .iter()
                .filter_map(|s| s.get("restartCount").and_then(Value::as_i64))
                .sum()
        });

    let age = item_age(pod, now);

    json!({
        "cells": [name, ready_str, status_str, restarts.to_string(), age],
        "object": pod
    })
}

fn namespace_row(namespace: &Value, now: u64) -> Value {
    let name = namespace
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let status = namespace
        .pointer("/status/phase")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("Active");
    let age = item_age(namespace, now);

    json!({
        "cells": [name, status, age],
        "object": namespace
    })
}

fn service_row(service: &Value, now: u64) -> Value {
    let name = service
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let svc_type = service
        .pointer("/spec/type")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("ClusterIP");
    let cluster_ip = service
        .pointer("/spec/clusterIP")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("<none>");
    let external_ip = if svc_type == "ExternalName" {
        service
            .pointer("/spec/externalName")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("<none>")
            .to_string()
    } else if let Some(ips) = service
        .pointer("/spec/externalIPs")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
    {
        let ip_strs: Vec<&str> = ips.iter().filter_map(Value::as_str).collect();
        if ip_strs.is_empty() {
            "<none>".to_string()
        } else {
            ip_strs.join(",")
        }
    } else if let Some(ing) = service
        .pointer("/status/loadBalancer/ingress")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
    {
        let list: Vec<&str> = ing
            .iter()
            .filter_map(|i| {
                i.get("ip")
                    .and_then(Value::as_str)
                    .or_else(|| i.get("hostname").and_then(Value::as_str))
            })
            .collect();
        if list.is_empty() {
            "<none>".to_string()
        } else {
            list.join(",")
        }
    } else {
        "<none>".to_string()
    };

    let ports = service
        .pointer("/spec/ports")
        .and_then(Value::as_array)
        .map_or_else(
            || "<none>".to_string(),
            |ports| {
                if ports.is_empty() {
                    "<none>".to_string()
                } else {
                    ports
                        .iter()
                        .map(|p| {
                            let port = p.get("port").and_then(Value::as_i64).unwrap_or(0);
                            let proto = p.get("protocol").and_then(Value::as_str).unwrap_or("TCP");
                            if let Some(node_port) = p
                                .get("nodePort")
                                .and_then(Value::as_i64)
                                .filter(|&np| np > 0)
                            {
                                format!("{port}:{node_port}/{proto}")
                            } else {
                                format!("{port}/{proto}")
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                }
            },
        );

    let age = item_age(service, now);

    json!({
        "cells": [name, svc_type, cluster_ip, external_ip, ports, age],
        "object": service
    })
}

fn configmap_row(cm: &Value, now: u64) -> Value {
    let name = cm
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let data_count = cm
        .get("data")
        .and_then(Value::as_object)
        .map_or(0, serde_json::Map::len)
        + cm.get("binaryData")
            .and_then(Value::as_object)
            .map_or(0, serde_json::Map::len);
    let age = item_age(cm, now);

    json!({
        "cells": [name, data_count.to_string(), age],
        "object": cm
    })
}

fn secret_row(secret: &Value, now: u64) -> Value {
    let name = secret
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let secret_type = secret
        .get("type")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("Opaque");
    let data_count = secret
        .get("data")
        .and_then(Value::as_object)
        .map_or(0, serde_json::Map::len)
        + secret
            .get("stringData")
            .and_then(Value::as_object)
            .map_or(0, serde_json::Map::len);
    let age = item_age(secret, now);

    json!({
        "cells": [name, secret_type, data_count.to_string(), age],
        "object": secret
    })
}

fn format_endpoints_str(endpoints: &Value) -> String {
    let mut eps = Vec::new();
    let Some(subsets) = endpoints.get("subsets").and_then(Value::as_array) else {
        return "<none>".to_string();
    };
    for subset in subsets {
        extract_subset_endpoints(subset, &mut eps);
    }
    if eps.is_empty() {
        "<none>".to_string()
    } else {
        eps.join(",")
    }
}

fn extract_subset_endpoints(subset: &Value, eps: &mut Vec<String>) {
    let Some(addrs) = subset.get("addresses").and_then(Value::as_array) else {
        return;
    };
    let ports = subset.get("ports").and_then(Value::as_array);
    for addr in addrs {
        let Some(ip) = addr.get("ip").and_then(Value::as_str) else {
            continue;
        };
        match ports {
            Some(ports) => {
                for port_val in ports {
                    if let Some(port) = port_val.get("port").and_then(Value::as_i64) {
                        eps.push(format!("{ip}:{port}"));
                    }
                }
            },
            None => eps.push(ip.to_string()),
        }
    }
}

fn endpoints_row(endpoints: &Value, now: u64) -> Value {
    let name = endpoints
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let endpoints_str = format_endpoints_str(endpoints);
    let age = item_age(endpoints, now);

    json!({
        "cells": [name, endpoints_str, age],
        "object": endpoints
    })
}

fn col(
    name: &'static str,
    col_type: &'static str,
    format: &'static str,
    desc: &'static str,
) -> Value {
    json!({
        "name": name,
        "type": col_type,
        "format": format,
        "description": desc,
        "priority": 0
    })
}

fn resource_column_definitions(resource: &str) -> Vec<Value> {
    match resource {
        "namespaces" => vec![
            col("Name", "string", "name", "Resource name"),
            col("Status", "string", "", "Namespace status"),
            col("Age", "string", "", "Namespace age"),
        ],
        "services" => vec![
            col("Name", "string", "name", "Resource name"),
            col("Type", "string", "", "Service type"),
            col("Cluster-IP", "string", "", "Cluster IP"),
            col("External-IP", "string", "", "External IP"),
            col("Port(s)", "string", "", "Service ports"),
            col("Age", "string", "", "Service age"),
        ],
        "endpoints" => vec![
            col("Name", "string", "name", "Resource name"),
            col("Endpoints", "string", "", "Endpoints"),
            col("Age", "string", "", "Endpoints age"),
        ],
        "configmaps" => vec![
            col("Name", "string", "name", "Resource name"),
            col("Data", "string", "", "ConfigMap data"),
            col("Age", "string", "", "ConfigMap age"),
        ],
        "secrets" => vec![
            col("Name", "string", "name", "Resource name"),
            col("Type", "string", "", "Secret type"),
            col("Data", "string", "", "Secret data"),
            col("Age", "string", "", "Secret age"),
        ],
        _ => vec![
            col("Name", "string", "name", "Resource name"),
            col("Ready", "string", "", "Readiness of containers"),
            col("Status", "string", "", "Pod status"),
            col("Restarts", "string", "", "Number of restarts"),
            col("Age", "string", "", "Pod age"),
        ],
    }
}

fn resource_row(resource: &str, item: &Value, now: u64) -> Value {
    match resource {
        "namespaces" => namespace_row(item, now),
        "services" => service_row(item, now),
        "endpoints" => endpoints_row(item, now),
        "configmaps" => configmap_row(item, now),
        "secrets" => secret_row(item, now),
        _ => pod_row(item, now),
    }
}

fn extract_table_items(value: &Value) -> (Value, Vec<Value>) {
    let is_list = value
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|k| k.ends_with("List"))
        || value.get("items").and_then(Value::as_array).is_some();
    if is_list {
        (
            value.get("metadata").cloned().unwrap_or_else(|| json!({})),
            value
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        )
    } else {
        (
            json!({
                "resourceVersion": value.pointer("/metadata/resourceVersion").unwrap_or(&Value::Null)
            }),
            vec![value.clone()],
        )
    }
}

fn resource_to_table(resource: &str, value: &Value) -> Value {
    let now = crate::time::now_unix();
    let (metadata, items) = extract_table_items(value);
    let rows: Vec<Value> = items
        .iter()
        .map(|item| resource_row(resource, item, now))
        .collect();

    json!({
        "kind": "Table",
        "apiVersion": "meta.k8s.io/v1",
        "metadata": metadata,
        "columnDefinitions": resource_column_definitions(resource),
        "rows": rows
    })
}

fn is_table_request(accept: Option<&str>) -> bool {
    accept.is_some_and(|a| a.to_ascii_lowercase().contains("as=table"))
}

fn table_content_type(accept: Option<&str>) -> &'static str {
    if let Some(accept) = accept {
        let lower = accept.to_ascii_lowercase();
        if lower.contains("g=meta.k8s.io;v=1") || lower.contains("v=1;g=meta.k8s.io") {
            return "application/json;as=Table;g=meta.k8s.io;v=1";
        }
    }
    "application/json;as=Table;v=v1;g=meta.k8s.io"
}

fn supports_table(path: &ResourcePath) -> bool {
    path.subresource.is_none()
        && matches!(
            path.resource.as_str(),
            "pods" | "namespaces" | "services" | "endpoints" | "configmaps" | "secrets"
        )
}

fn text_response(status: StatusCode, body: String) -> Response<Body> {
    response(status, "text/plain", Bytes::from(body))
}

fn text(status: StatusCode, body: &'static str) -> Response<Body> {
    response(status, "text/plain", Bytes::from_static(body.as_bytes()))
}

fn response(status: StatusCode, content_type: &'static str, bytes: Bytes) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Full::new(bytes).boxed())
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from_static(b"{\"kind\":\"Status\"}")).boxed())
        })
}
