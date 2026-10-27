//! Accept loop for the API server HTTPS listener.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};
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
use tokio::sync::{RwLock, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::client::KubernetesApiClient;
use crate::error::ApiserverError;
use crate::exec::{PodExecOptions, select_subprotocol, serve_exec};
use crate::service::ApiserverService;

use super::dispatch::{self, Payload};
use super::query;
use super::route::{self, ResourcePath, Route, aggregated_discovery_version};
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
                    let mut buf = [0u8; 1];
                    let is_tls = match stream.peek(&mut buf).await {
                        Ok(n) if n > 0 => buf[0] == 0x16,
                        _ => false,
                    };
                    if is_tls {
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
                        serve_connection(TokioIo::new(tls), service, peer, shutdown_rx).await;
                    } else {
                        serve_connection(TokioIo::new(stream), service, None, shutdown_rx).await;
                    }
                });
            }
        }
    }
    drop(listener);
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn serve_connection<I>(
    io: TokioIo<I>,
    service: ApiserverService,
    peer: Option<PeerIdentity>,
    shutdown_rx: watch::Receiver<bool>,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut hyper = hyper::server::conn::http1::Builder::new();
    hyper.timer(TokioTimer::new());
    hyper.header_read_timeout(Duration::from_secs(30));
    let connection = hyper
        .serve_connection(
            io,
            service_fn(move |request| {
                let service = service.clone();
                let peer = peer.clone();
                let shutdown_rx = shutdown_rx.clone();
                async move {
                    Ok::<_, Infallible>(handle(request, &service, peer.as_ref(), shutdown_rx).await)
                }
            }),
        )
        .with_upgrades();
    let _ = connection.await;
}

#[allow(clippy::too_many_lines)]
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
    if matches!(route, Route::OpenIdConfig) {
        let issuer = &service.config().service_account_issuer;
        let jwks_uri = format!("{issuer}/openid/v1/jwks");
        return json_response(
            StatusCode::OK,
            &json!({
                "issuer": issuer,
                "jwks_uri": jwks_uri,
                "response_types_supported": ["id_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"]
            }),
        );
    }
    if matches!(route, Route::OpenIdJwks) {
        let keys = service
            .token_service_opt()
            .map_or_else(|| json!([]), |ts| ts.jwks());
        return json_response(StatusCode::OK, &json!({ "keys": keys }));
    }

    let query = request.uri().query().map(str::to_owned);
    let bearer = bearer_token(&request);
    let client = client_for(service, peer, bearer.as_deref());
    if is_websocket_upgrade(&request)
        && let Route::Resource(path) = &route
    {
        if path.subresource.as_deref() == Some("exec") {
            return exec_upgrade(request, service, &client, path).await;
        }
        if path.subresource.as_deref() == Some("log") {
            return log_upgrade(request, service, &client, path).await;
        }
    }
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
        Route::Health | Route::Version | Route::OpenIdConfig | Route::OpenIdJwks => {
            unreachable!("handled above")
        },
        Route::NotFound => status_response(
            StatusCode::NOT_FOUND,
            "NotFound",
            "the server could not find the requested resource",
        ),
        Route::ApiVersions => aggregated_or(
            accept.as_deref(),
            || core_aggregated(&client),
            || Ok(api_versions(service)),
        ),
        Route::OpenApiV2 => {
            let wants_proto = accept.as_deref().is_some_and(|a| {
                a.contains("proto-openapi.spec.v2")
                    || (a.contains("protobuf") && !a.contains("json"))
            });
            if wants_proto {
                match client.discover_core() {
                    Ok(_) => response(
                        StatusCode::OK,
                        "application/com.github.proto-openapi.spec.v2.v1.0+protobuf",
                        Bytes::from_static(crate::openapi::OPENAPI_V2_PROTO_BYTES),
                    ),
                    Err(err) => error_response(&err),
                }
            } else {
                authenticated_document(&client, || {
                    let crds = client.list_registered_crds();
                    crate::openapi::v2_with_crds(&crds)
                })
            }
        },
        Route::OpenApiV3Index => authenticated_document(&client, || {
            let crds = client.list_registered_crds();
            crate::openapi::v3_index_with_crds(&crds)
        }),
        Route::OpenApiV3Core => authenticated_document(&client, crate::openapi::v3_core),
        Route::OpenApiV3StorageV1 => authenticated_document(&client, crate::openapi::v3_storage_v1),
        Route::OpenApiV3Group { group, version } => authenticated_document(&client, || {
            let crds = client.list_registered_crds();
            crate::openapi::v3_group_with_crds(&group, &version, &crds)
        }),
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
        Route::ApiGroup { group } => discovery_result(client.discover_api_group(&group)),
        Route::GroupDiscovery { group, version } => discovery_result(
            discover_group_resources_with_crds(&client, &group, &version),
        ),
        Route::Resource(path) => {
            let params = query::parse(query.as_deref());
            if method == Method::GET && path.name.is_none() && is_watch(&params) {
                return watch_response(service, &client, &path, &params, shutdown).await;
            }
            if method == Method::POST && is_table_request(accept.as_deref()) {
                let res = path.resource.as_str();
                if matches!(
                    res,
                    "selfsubjectaccessreviews"
                        | "subjectaccessreviews"
                        | "localsubjectaccessreviews"
                        | "tokenreviews"
                        | "selfsubjectrulesreviews"
                ) {
                    return status_response(
                        StatusCode::NOT_ACCEPTABLE,
                        "NotAcceptable",
                        "Table representation is not supported for this resource",
                    );
                }
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

fn is_websocket_upgrade(request: &Request<Incoming>) -> bool {
    let upgrade = request
        .headers()
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let connection = request
        .headers()
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    upgrade.contains("websocket") && connection.contains("upgrade")
}

/// Upgrades a pod `exec` request to the channel subprotocol and streams the
/// command output. Pre-upgrade failures (bad query, missing pod, no kubelet)
/// are plain HTTP errors so clients fail fast without switching protocols.
async fn exec_upgrade(
    request: Request<Incoming>,
    service: &ApiserverService,
    client: &KubernetesApiClient,
    path: &ResourcePath,
) -> Response<Body> {
    let query = request.uri().query().map(str::to_owned);
    let options = match PodExecOptions::from_query(query.as_deref()) {
        Ok(options) => options,
        Err(err) => return error_response(&err),
    };
    let (Some(namespace), Some(name)) = (&path.namespace, &path.name) else {
        return status_response(
            StatusCode::BAD_REQUEST,
            "BadRequest",
            "exec requires a namespaced pod",
        );
    };
    if let Err(err) = client.authorize_pod_exec(namespace, name) {
        return error_response(&err);
    }
    let pod = match client.get_pod(namespace, name).await {
        Ok(pod) => pod,
        Err(err) => return error_response(&err),
    };
    let container = match options.resolve_container(&pod) {
        Ok(container) => container,
        Err(err) => return error_response(&err),
    };
    let Some(exec) = service.pod_exec() else {
        return error_response(&ApiserverError::Internal {
            reason: "no kubelet is registered to serve pod exec".to_string(),
        });
    };
    let Some(key) = request
        .headers()
        .get("sec-websocket-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
    else {
        return status_response(
            StatusCode::BAD_REQUEST,
            "BadRequest",
            "missing Sec-WebSocket-Key",
        );
    };
    let protocol = select_subprotocol(
        request
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok()),
    );
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let upgrade = hyper::upgrade::on(request);
    tokio::spawn(async move {
        match upgrade.await {
            Ok(upgraded) => {
                serve_exec(TokioIo::new(upgraded), exec, pod, options, container).await;
            },
            Err(err) => eprintln!("exec upgrade failed: {err}"),
        }
    });
    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header("sec-websocket-accept", accept);
    if let Some(protocol) = protocol {
        builder = builder.header("sec-websocket-protocol", protocol);
    }
    builder
        .body(Full::new(Bytes::new()).boxed())
        .unwrap_or_else(|_| {
            status_response(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", "exec")
        })
}

async fn log_upgrade(
    request: Request<Incoming>,
    service: &ApiserverService,
    client: &KubernetesApiClient,
    path: &ResourcePath,
) -> Response<Body> {
    let (Some(namespace), Some(name)) = (&path.namespace, &path.name) else {
        return status_response(
            StatusCode::BAD_REQUEST,
            "BadRequest",
            "log requires a namespaced pod",
        );
    };
    if let Err(err) = client.check_auth_detailed("get", "", "pods/log", Some(namespace), Some(name))
    {
        return error_response(&err);
    }
    let pod = match client.get_pod(namespace, name).await {
        Ok(pod) => pod,
        Err(err) => return error_response(&err),
    };
    let Some(reader) = service.pod_log_reader() else {
        return error_response(&ApiserverError::Internal {
            reason: "no kubelet is registered to serve pod logs".to_string(),
        });
    };
    let query = request.uri().query().map(str::to_owned);
    let options = crate::logs::PodLogOptions::from_params(&query::parse(query.as_deref()));
    let text = match reader.read_pod_log(&pod, &options).await {
        Ok(t) => t,
        Err(err) => return error_response(&err),
    };
    let Some(key) = request
        .headers()
        .get("sec-websocket-key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
    else {
        return status_response(
            StatusCode::BAD_REQUEST,
            "BadRequest",
            "missing Sec-WebSocket-Key",
        );
    };
    let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
    let upgrade = hyper::upgrade::on(request);
    tokio::spawn(async move {
        if let Ok(upgraded) = upgrade.await {
            use futures_util::SinkExt;
            let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                TokioIo::new(upgraded),
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            let _ = ws
                .send(tokio_tungstenite::tungstenite::Message::Text(text.into()))
                .await;
            let _ = ws
                .close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code:
                        tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                    reason: "".into(),
                }))
                .await;
        }
    });
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "Upgrade")
        .header("sec-websocket-accept", accept)
        .body(Full::new(Bytes::new()).boxed())
        .unwrap_or_else(|_| {
            status_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "log upgrade failed",
            )
        })
}

fn outcome_to_response(
    outcome: dispatch::Outcome,
    path: &ResourcePath,
    accept: Option<&str>,
) -> Response<Body> {
    let mut resp = match outcome.body {
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
    };
    for (name, val) in outcome.headers {
        resp.headers_mut().insert(name, val);
    }
    resp
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
struct WatchHub {
    inner: RwLock<WatchHubInner>,
}

struct WatchHubInner {
    last_assigned_rev: u64,
    buffer: VecDeque<Arc<BufferedWatchEvent>>,
    broadcast_tx: tokio::sync::broadcast::Sender<Arc<BufferedWatchEvent>>,
}

struct BufferedWatchEvent {
    resource_version: u64,
    event_type: String, // "ADDED", "MODIFIED", "DELETED"
    key: String,
    object: Value,
    prev_object: Option<Value>,
}

static WATCH_HUBS: LazyLock<Mutex<HashMap<usize, Arc<WatchHub>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

async fn get_or_init_watch_hub(service: &ApiserverService) -> Arc<WatchHub> {
    let key = Arc::as_ptr(service.crd_registry()) as usize;
    {
        let guard = WATCH_HUBS.lock().unwrap();
        if let Some(hub) = guard.get(&key) {
            return Arc::clone(hub);
        }
    }
    let cur_rev = service.storage().current_revision().await;
    let (broadcast_tx, _) = tokio::sync::broadcast::channel(8192);
    let hub = Arc::new(WatchHub {
        inner: RwLock::new(WatchHubInner {
            last_assigned_rev: cur_rev.max(1),
            buffer: VecDeque::with_capacity(10_000),
            broadcast_tx,
        }),
    });
    let raw_rx = service.storage().client().watch("").await;
    let hub_clone = Arc::clone(&hub);
    tokio::spawn(async move {
        watch_hub_loop(hub_clone, raw_rx).await;
    });

    let mut guard = WATCH_HUBS.lock().unwrap();
    guard.entry(key).or_insert_with(|| Arc::clone(&hub)).clone()
}

async fn watch_hub_loop(hub: Arc<WatchHub>, mut raw_rx: WatchReceiver) {
    loop {
        let event = match raw_rx.recv().await {
            Ok(event) => event,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        };
        let mut inner = hub.inner.write().await;
        let assigned_rev = match event.event_type {
            WatchEventType::Put => event.kv.mod_revision.max(inner.last_assigned_rev + 1),
            WatchEventType::Delete => inner.last_assigned_rev + 1,
        };
        inner.last_assigned_rev = assigned_rev;

        let event_type = match event.event_type {
            WatchEventType::Put => {
                if event.prev_kv.is_some() {
                    "MODIFIED".to_string()
                } else {
                    "ADDED".to_string()
                }
            },
            WatchEventType::Delete => "DELETED".to_string(),
        };

        let mut object = serde_json::from_slice(&event.kv.value).unwrap_or(Value::Null);
        let prev_object: Option<Value> = event
            .prev_kv
            .as_ref()
            .and_then(|kv| serde_json::from_slice::<Value>(&kv.value).ok());
        if object.is_null()
            && let Some(prev) = &prev_object
        {
            object = prev.clone();
        }
        if let Some(meta) = object.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(assigned_rev.to_string()),
            );
        }

        let buffered = Arc::new(BufferedWatchEvent {
            resource_version: assigned_rev,
            event_type,
            key: event.kv.key,
            object,
            prev_object,
        });

        if inner.buffer.len() >= 10_000 {
            inner.buffer.pop_front();
        }
        inner.buffer.push_back(Arc::clone(&buffered));
        let _ = inner.broadcast_tx.send(buffered);
    }
}

fn compute_resource_key_prefix(storage_prefix: &str, path: &ResourcePath) -> String {
    let group_segment = if path.group.is_empty() {
        String::new()
    } else {
        format!("/{}", path.group)
    };
    let namespace_segment = path
        .namespace
        .as_ref()
        .map_or_else(String::new, |ns| format!("{ns}/"));
    format!(
        "{}{group_segment}/{}/{namespace_segment}",
        storage_prefix, path.resource
    )
}

async fn build_watch_filter(
    service: &ApiserverService,
    path: &ResourcePath,
    params: &BTreeMap<String, String>,
    resource_key_prefix: &str,
) -> WatchFilter {
    let name_filter = params
        .get("fieldSelector")
        .and_then(|selector| selector.strip_prefix("metadata.name="))
        .map(str::to_owned);
    let object_exists = if let Some(ref name) = name_filter {
        let key = format!("{resource_key_prefix}{name}");
        service.storage().get(&key).await.ok().flatten().is_some()
    } else {
        false
    };

    WatchFilter {
        name: name_filter,
        field_selector: params.get("fieldSelector").cloned().unwrap_or_default(),
        label_selector: params.get("labelSelector").cloned().unwrap_or_default(),
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
        object_exists,
    }
}

async fn watch_response(
    service: &ApiserverService,
    client: &KubernetesApiClient,
    path: &ResourcePath,
    params: &BTreeMap<String, String>,
    shutdown: watch::Receiver<bool>,
) -> Response<Body> {
    let hub = get_or_init_watch_hub(service).await;
    let broadcast_rx = hub.inner.read().await.broadcast_tx.subscribe();

    let storage_prefix = service.storage().prefix();
    let resource_key_prefix = compute_resource_key_prefix(storage_prefix, path);
    let filter = build_watch_filter(service, path, params, &resource_key_prefix).await;

    let timeout = params
        .get("timeoutSeconds")
        .and_then(|value| value.parse().ok())
        .map_or(DEFAULT_WATCH_TIMEOUT, Duration::from_secs);

    let (initial, snapshot_rev, buffered_events) = if params
        .get("resourceVersion")
        .map(String::as_str)
        == Some("0")
        || filter.send_initial_events
        || (params.get("resourceVersion").is_none() && filter.label_selector.is_empty())
    {
        let initial_doc =
            match dispatch::dispatch(service, client, &Method::GET, path, None, None, &[]).await {
                Ok(outcome) => match outcome.body {
                    Payload::Json(body) => body,
                    Payload::Text(_) | Payload::ChunkedText(_) => Value::Null,
                },
                Err(err) => return error_response(&err),
            };
        let snapshot_rev = hub.inner.read().await.last_assigned_rev;
        (Some(initial_doc), snapshot_rev, Vec::new())
    } else {
        let guard = hub.inner.read().await;
        let events: Vec<Arc<BufferedWatchEvent>> = guard
            .buffer
            .iter()
            .filter(|ev| ev.resource_version > filter.since)
            .cloned()
            .collect();
        let snapshot_rev = guard.last_assigned_rev;
        (None, snapshot_rev, events)
    };

    let (sender, channel) = Channel::<Bytes, Infallible>::new(32);
    tokio::spawn(stream_watch(
        sender,
        broadcast_rx,
        initial,
        snapshot_rev,
        buffered_events,
        filter,
        resource_key_prefix,
        timeout,
        shutdown,
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
    !dispatch::is_cluster_resource(resource)
}

struct WatchFilter {
    name: Option<String>,
    label_selector: String,
    field_selector: String,
    since: u64,
    send_initial_events: bool,
    namespaced: bool,
    namespace: Option<String>,
    api_version: String,
    kind: String,
    object_exists: bool,
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
        }) && dispatch::matches_label_selector(object, &self.label_selector)
            && dispatch::matches_field_selector(object, &self.field_selector)
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn stream_watch(
    mut sender: http_body_util::channel::Sender<Bytes, Infallible>,
    mut broadcast_rx: tokio::sync::broadcast::Receiver<Arc<BufferedWatchEvent>>,
    initial: Option<Value>,
    snapshot_rev: u64,
    buffered_events: Vec<Arc<BufferedWatchEvent>>,
    filter: WatchFilter,
    resource_key_prefix: String,
    timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    if *shutdown.borrow() {
        return;
    }
    let mut sent: BTreeMap<String, u64> = BTreeMap::new();
    let mut last_delivered_rv: u64 = filter.since;
    let mut found = false;

    if let Some(initial_doc) = initial {
        for item in initial_doc
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
            last_delivered_rv = last_delivered_rv.max(version);
            if send_event(&mut sender, "ADDED", item).await.is_err() {
                return;
            }
        }
    }

    if filter.send_initial_events {
        let bookmark_rv = last_delivered_rv.max(snapshot_rev);
        let bookmark = json!({
            "kind": filter.kind,
            "apiVersion": filter.api_version,
            "metadata": {
                "resourceVersion": bookmark_rv.to_string(),
                "annotations": { "k8s.io/initial-events-end": "true" }
            }
        });
        if send_event(&mut sender, "BOOKMARK", &bookmark)
            .await
            .is_err()
        {
            return;
        }
        last_delivered_rv = bookmark_rv;
    }

    for event in buffered_events {
        if *shutdown.borrow() {
            return;
        }
        if !event.key.starts_with(&resource_key_prefix) {
            continue;
        }
        if event.resource_version <= last_delivered_rv {
            continue;
        }
        let mut object = if event.object.is_null() {
            filter.object_from_key(&event.key)
        } else {
            event.object.clone()
        };
        if let Some(meta) = object.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(event.resource_version.to_string()),
            );
        }
        if !filter.namespaced && object.pointer("/metadata/namespace").is_some() {
            continue;
        }
        let key = object_key(&object);
        let mut kind = event.event_type.as_str();
        if !filter.accepts(&object) {
            if kind == "MODIFIED"
                && (event
                    .prev_object
                    .as_ref()
                    .is_some_and(|prev| filter.accepts(prev))
                    || sent.remove(&key).is_some())
            {
                sent.remove(&key);
                if send_event(&mut sender, "DELETED", &object).await.is_err() {
                    return;
                }
            }
            continue;
        }
        found = true;
        if kind == "MODIFIED"
            && event
                .prev_object
                .as_ref()
                .is_some_and(|prev| !filter.accepts(prev))
        {
            kind = "ADDED";
        }
        if kind == "DELETED" {
            sent.remove(&key);
        } else {
            sent.insert(key, event.resource_version);
        }
        last_delivered_rv = event.resource_version;
        if send_event(&mut sender, kind, &object).await.is_err() {
            return;
        }
    }

    if !found
        && filter.since > 0
        && !filter.object_exists
        && let Some(name) = &filter.name
    {
        let mut metadata =
            json!({ "name": name, "resourceVersion": (filter.since + 1).to_string() });
        if let Some(namespace) = &filter.namespace {
            metadata["namespace"] = json!(namespace);
        }
        let gone = json!({
            "kind": filter.kind,
            "apiVersion": filter.api_version,
            "metadata": metadata,
        });
        if send_event(&mut sender, "DELETED", &gone).await.is_err() {
            return;
        }
        last_delivered_rv = filter.since + 1;
    }

    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);

    loop {
        tokio::select! {
            biased;
            () = &mut sleep => return,
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            recv_result = broadcast_rx.recv() => {
                let event = match recv_result {
                    Ok(ev) => ev,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                };
                if !event.key.starts_with(&resource_key_prefix) {
                    continue;
                }
                if event.resource_version <= last_delivered_rv {
                    continue;
                }
                let mut object = if event.object.is_null() {
                    filter.object_from_key(&event.key)
                } else {
                    event.object.clone()
                };
                if let Some(meta) = object.get_mut("metadata").and_then(Value::as_object_mut) {
                    meta.insert(
                        "resourceVersion".to_string(),
                        json!(event.resource_version.to_string()),
                    );
                }
                if !filter.namespaced && object.pointer("/metadata/namespace").is_some() {
                    continue;
                }
                let key = object_key(&object);
                let mut kind = event.event_type.as_str();
                if !filter.accepts(&object) {
                    if kind == "MODIFIED"
                        && (event
                            .prev_object
                            .as_ref()
                            .is_some_and(|prev| filter.accepts(prev))
                            || sent.remove(&key).is_some())
                    {
                        sent.remove(&key);
                        if send_event(&mut sender, "DELETED", &object).await.is_err() {
                            return;
                        }
                    }
                    continue;
                }
                if kind == "MODIFIED"
                    && event
                        .prev_object
                        .as_ref()
                        .is_some_and(|prev| !filter.accepts(prev))
                {
                    kind = "ADDED";
                }
                if kind == "DELETED" {
                    sent.remove(&key);
                } else {
                    sent.insert(key, event.resource_version);
                }
                last_delivered_rv = event.resource_version;
                if send_event(&mut sender, kind, &object).await.is_err() {
                    return;
                }
            }
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
    let (major, minor) = split_kubernetes_version(crate::KUBERNETES_VERSION);
    json!({
        "major": major,
        "minor": minor,
        "gitVersion": crate::KUBERNETES_VERSION,
        "platform": format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
    })
}

/// `v1.37.1` splits into major `1` and minor `37`.
fn split_kubernetes_version(version: &str) -> (&str, &str) {
    let rest = version.strip_prefix('v').unwrap_or(version);
    let (major, rest) = rest.split_once('.').unwrap_or((rest, "0"));
    let minor = rest.split_once('.').map_or(rest, |(minor, _)| minor);
    (major, minor)
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

/// Media types clients use to recognise an aggregated discovery document.
/// client-go falls back to legacy parsing when this is absent.
const AGGREGATED_DISCOVERY_V2_TYPE: &str =
    "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList";
const AGGREGATED_DISCOVERY_V2BETA1_TYPE: &str =
    "application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList";

fn aggregated_or(
    accept: Option<&str>,
    aggregated: impl FnOnce() -> Result<Value, ApiserverError>,
    legacy: impl FnOnce() -> Result<Value, ApiserverError>,
) -> Response<Body> {
    if let Some(ver) = aggregated_discovery_version(accept) {
        match aggregated() {
            Ok(mut body) => {
                if let Some(obj) = body.as_object_mut() {
                    obj.insert(
                        "apiVersion".to_string(),
                        json!(format!("apidiscovery.k8s.io/{ver}")),
                    );
                }
                let content_type = if ver == "v2beta1" {
                    AGGREGATED_DISCOVERY_V2BETA1_TYPE
                } else {
                    AGGREGATED_DISCOVERY_V2_TYPE
                };
                json_response_with_type(StatusCode::OK, content_type, &body)
            },
            Err(err) => error_response(&err),
        }
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

#[allow(clippy::too_many_lines)]
fn discover_group_resources_with_crds(
    client: &KubernetesApiClient,
    group: &str,
    version: &str,
) -> Result<Value, ApiserverError> {
    let apis = client.discover_apis()?;
    let groups = apis
        .get("groups")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiserverError::NotFound {
            resource: "apigroups".to_string(),
            name: group.to_string(),
        })?;
    let group_entry = groups
        .iter()
        .find(|g| g.get("name").and_then(Value::as_str) == Some(group))
        .ok_or_else(|| ApiserverError::NotFound {
            resource: "apigroups".to_string(),
            name: group.to_string(),
        })?;

    let version_exists = group_entry
        .get("versions")
        .and_then(Value::as_array)
        .is_some_and(|vers| {
            vers.iter()
                .any(|v| v.get("version").and_then(Value::as_str) == Some(version))
        });
    if !version_exists {
        return Err(ApiserverError::NotFound {
            resource: "groupversions".to_string(),
            name: format!("{group}/{version}"),
        });
    }

    let mut doc = client.discover_group_resources(group, version)?;
    let Some(resources) = doc.get_mut("resources").and_then(Value::as_array_mut) else {
        return Ok(doc);
    };

    if group == "apiextensions.k8s.io" && version == "v1" {
        for res in resources.iter_mut() {
            if res.get("name").and_then(Value::as_str) == Some("customresourcedefinitions")
                && let Some(obj) = res.as_object_mut()
            {
                obj.insert("shortNames".to_string(), json!(["crd", "crds"]));
            }
        }
    }

    let crds = client.list_registered_crds();
    for crd in &crds {
        let Some(spec) = crd.get("spec") else {
            continue;
        };
        if spec.get("group").and_then(Value::as_str) != Some(group) {
            continue;
        }
        let Some(versions) = spec.get("versions").and_then(Value::as_array) else {
            continue;
        };
        let Some(v) = versions.iter().find(|v| {
            v.get("name").and_then(Value::as_str) == Some(version)
                && v.get("served").and_then(Value::as_bool) != Some(false)
        }) else {
            continue;
        };
        let plural = spec
            .pointer("/names/plural")
            .and_then(Value::as_str)
            .unwrap_or("customresources");
        let singular = spec
            .pointer("/names/singular")
            .and_then(Value::as_str)
            .unwrap_or("customresource");
        let kind = spec
            .pointer("/names/kind")
            .and_then(Value::as_str)
            .unwrap_or("CustomResource");
        let namespaced = spec.get("scope").and_then(Value::as_str) != Some("Cluster");

        let short_names = spec.pointer("/names/shortNames").and_then(Value::as_array);
        let categories = spec.pointer("/names/categories").and_then(Value::as_array);

        let subresources = v.get("subresources").or_else(|| spec.get("subresources"));
        let has_status = subresources.and_then(|s| s.get("status")).is_some();
        let has_scale = subresources.and_then(|s| s.get("scale")).is_some();

        if let Some(res) = resources
            .iter_mut()
            .find(|r| r.get("name").and_then(Value::as_str) == Some(plural))
        {
            if let Some(obj) = res.as_object_mut() {
                obj.insert("singularName".to_string(), json!(singular));
                obj.insert("kind".to_string(), json!(kind));
                obj.insert("namespaced".to_string(), json!(namespaced));
                if let Some(sn) = short_names {
                    obj.insert("shortNames".to_string(), json!(sn));
                }
                if let Some(cat) = categories {
                    obj.insert("categories".to_string(), json!(cat));
                }
            }
        } else {
            let mut obj = json!({
                "name": plural,
                "singularName": singular,
                "namespaced": namespaced,
                "kind": kind,
                "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
            });
            if let Some(sn) = short_names {
                obj["shortNames"] = json!(sn);
            }
            if let Some(cat) = categories {
                obj["categories"] = json!(cat);
            }
            resources.push(obj);
        }

        let status_name = format!("{plural}/status");
        if has_status {
            if !resources
                .iter()
                .any(|r| r.get("name").and_then(Value::as_str) == Some(&status_name))
            {
                resources.push(json!({
                    "name": status_name,
                    "singularName": "",
                    "namespaced": namespaced,
                    "kind": kind,
                    "verbs": ["get", "patch", "update"]
                }));
            }
        } else {
            resources.retain(|r| r.get("name").and_then(Value::as_str) != Some(&status_name));
        }

        let scale_name = format!("{plural}/scale");
        if has_scale {
            if !resources
                .iter()
                .any(|r| r.get("name").and_then(Value::as_str) == Some(&scale_name))
            {
                resources.push(json!({
                    "name": scale_name,
                    "singularName": "",
                    "namespaced": namespaced,
                    "group": "autoscaling",
                    "version": "v1",
                    "kind": "Scale",
                    "verbs": ["get", "patch", "update"]
                }));
            }
        } else {
            resources.retain(|r| r.get("name").and_then(Value::as_str) != Some(&scale_name));
        }
    }

    Ok(doc)
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
        let declared_versions: Vec<&str> = group
            .get("versions")
            .and_then(Value::as_array)
            .map(|vers| {
                vers.iter()
                    .filter_map(|v| v.get("version").and_then(Value::as_str))
                    .collect()
            })
            .unwrap_or_default();
        let fallback_versions: Vec<&str> = if declared_versions.is_empty() {
            group
                .pointer("/preferredVersion/version")
                .and_then(Value::as_str)
                .into_iter()
                .collect()
        } else {
            declared_versions
        };
        let mut version_items = Vec::new();
        for version in fallback_versions {
            let Ok(resources) = discover_group_resources_with_crds(client, name, version) else {
                continue;
            };
            // client-go fails the whole discovery when a group lists no resources,
            // so versions without served kinds are left out of the aggregated view.
            if resources
                .get("resources")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            {
                continue;
            }
            version_items.push(group_version_item(name, version, &resources));
        }
        if !version_items.is_empty() {
            items.push(json!({
                "metadata": { "name": name },
                "versions": version_items
            }));
        }
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
    json!({
        "metadata": { "name": group },
        "versions": [group_version_item(group, version, resources)]
    })
}

fn group_version_item(group: &str, version: &str, resources: &Value) -> Value {
    let empty_vec = Vec::new();
    let items = resources
        .get("resources")
        .and_then(Value::as_array)
        .unwrap_or(&empty_vec);

    let mut subresources_map: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for r in items {
        let name = r.get("name").and_then(Value::as_str).unwrap_or_default();
        if let Some((parent, sub)) = name.split_once('/') {
            let (resp_group, resp_version, resp_kind) = if sub == "scale" {
                ("autoscaling", "v1", "Scale")
            } else {
                (
                    group,
                    version,
                    r.get("kind").and_then(Value::as_str).unwrap_or(""),
                )
            };
            let sub_entry = json!({
                "subresource": sub,
                "responseKind": {
                    "group": resp_group,
                    "version": resp_version,
                    "kind": resp_kind,
                },
                "verbs": r.get("verbs").cloned().unwrap_or_else(|| json!([]))
            });
            subresources_map
                .entry(parent.to_string())
                .or_default()
                .push(sub_entry);
        }
    }

    let mut top_resources = Vec::new();
    for r in items {
        let name = r.get("name").and_then(Value::as_str).unwrap_or_default();
        if !name.contains('/') {
            let subs = subresources_map.remove(name).unwrap_or_default();
            let mut entry = json!({
                "resource": name,
                "singularResource": r.get("singularName").and_then(Value::as_str).unwrap_or_default(),
                "shortNames": r.get("shortNames").cloned().unwrap_or_else(|| json!([])),
                "responseKind": {
                    "group": group,
                    "version": version,
                    "kind": r.get("kind").and_then(Value::as_str).unwrap_or_default()
                },
                "scope": if r["namespaced"].as_bool() == Some(true) {
                    "Namespaced"
                } else {
                    "Cluster"
                },
                "verbs": r["verbs"]
            });
            if !subs.is_empty() {
                entry["subresources"] = json!(subs);
            }
            top_resources.push(entry);
        }
    }

    json!({
        "version": version,
        "freshness": "Current",
        "resources": top_resources
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
        ApiserverError::BadRequest { .. } => (StatusCode::BAD_REQUEST, "BadRequest"),
        ApiserverError::InvalidInput { .. } => (StatusCode::UNPROCESSABLE_ENTITY, "Invalid"),
        ApiserverError::Expired { continue_token } => {
            return json_response(
                StatusCode::GONE,
                &json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "metadata": { "continue": continue_token },
                    "status": "Failure",
                    "message": "The provided continue parameter is too old to display a consistent list result. Start a new list request without the continue token.",
                    "reason": "Expired",
                    "code": 410
                }),
            );
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
            Some(ports) if !ports.is_empty() => {
                for port_val in ports {
                    if let Some(port) = port_val.get("port").and_then(Value::as_i64) {
                        eps.push(format!("{ip}:{port}"));
                    }
                }
            },
            _ => eps.push(ip.to_string()),
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

#[cfg(test)]
mod tests {
    use super::group_item;
    use serde_json::json;

    #[test]
    fn version_advertises_the_conformance_release() {
        let body = super::version();
        assert_eq!(body["major"], "1");
        assert_eq!(body["minor"], "37");
        assert_eq!(body["gitVersion"], "v1.37.1");
        let spec = crate::openapi::v3_group("apps", "v1");
        assert_eq!(spec["info"]["version"], "v1.37.1");
    }

    #[test]
    fn aggregated_discovery_uses_aggregated_media_type() {
        let response = super::aggregated_or(
            Some("application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList"),
            || Ok(json!({ "items": [] })),
            || Ok(json!({ "groups": [] })),
        );
        assert_eq!(
            response.headers()["content-type"],
            "application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList"
        );
        let response_v2beta1 = super::aggregated_or(
            Some("application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList"),
            || Ok(json!({ "items": [] })),
            || Ok(json!({ "groups": [] })),
        );
        assert_eq!(
            response_v2beta1.headers()["content-type"],
            "application/json;g=apidiscovery.k8s.io;v=v2beta1;as=APIGroupDiscoveryList"
        );
        let legacy = super::aggregated_or(None, || Ok(json!({})), || Ok(json!({ "groups": [] })));
        assert_eq!(legacy.headers()["content-type"], "application/json");
    }

    #[test]
    fn aggregated_versions_are_marked_current() {
        let resources = json!({ "resources": [{
            "name": "deployments",
            "singularName": "deployment",
            "namespaced": true,
            "kind": "Deployment",
            "verbs": ["get"]
        }]});
        let item = group_item("apps", "v1", &resources);
        assert_eq!(item["versions"][0]["freshness"], "Current");
        assert_eq!(
            item["versions"][0]["resources"][0]["resource"],
            "deployments"
        );
    }

    #[tokio::test]
    async fn crd_discovery_metadata_and_subresources() {
        let dir = tempfile::TempDir::new().unwrap();
        let (engine, _) = diorama_datastore::DatastoreEngine::open(
            diorama_datastore::DatastoreConfig::new(dir.path().join("ds")),
        )
        .unwrap();
        let storage = crate::storage::KubernetesStorage::new(engine.client(), "/registry");
        let pki_dir = dir.path().join("pki");
        let config =
            crate::config::ApiserverConfig::default_for_pki(&pki_dir, "127.0.0.1".parse().unwrap());
        let service = crate::service::ApiserverService::new(config, storage);
        let client = service.admin_client();

        // Register CRD with shortNames, categories, status, and scale
        let crd = json!({
            "spec": {
                "group": "example.com",
                "names": {
                    "kind": "CronTab",
                    "plural": "crontabs",
                    "singular": "crontab",
                    "shortNames": ["ct", "cron"],
                    "categories": ["all", "batch"]
                },
                "scope": "Namespaced",
                "versions": [{
                    "name": "v1",
                    "served": true,
                    "storage": true,
                    "subresources": {
                        "status": {},
                        "scale": {
                            "specReplicasPath": ".spec.replicas",
                            "statusReplicasPath": ".status.replicas"
                        }
                    }
                }]
            }
        });
        service
            .crd_registry()
            .write()
            .unwrap()
            .insert("crontabs.example.com".to_string(), crd);

        // 1. Discover registered CRD group/version
        let doc = super::discover_group_resources_with_crds(&client, "example.com", "v1")
            .expect("discovery succeeds");
        let res_list = doc["resources"].as_array().expect("resources array");

        let crontabs = res_list
            .iter()
            .find(|r| r["name"] == "crontabs")
            .expect("crontabs found");
        assert_eq!(crontabs["singularName"], "crontab");
        assert_eq!(crontabs["kind"], "CronTab");
        assert_eq!(crontabs["shortNames"], json!(["ct", "cron"]));
        assert_eq!(crontabs["categories"], json!(["all", "batch"]));

        let status = res_list
            .iter()
            .find(|r| r["name"] == "crontabs/status")
            .expect("status subresource found");
        assert_eq!(status["kind"], "CronTab");

        let scale = res_list
            .iter()
            .find(|r| r["name"] == "crontabs/scale")
            .expect("scale subresource found");
        assert_eq!(scale["kind"], "Scale");
        assert_eq!(scale["group"], "autoscaling");

        // 2. Unserved version returns 404
        let err =
            super::discover_group_resources_with_crds(&client, "example.com", "v2").unwrap_err();
        assert!(matches!(err, crate::error::ApiserverError::NotFound { .. }));

        // 3. Builtin apiextensions.k8s.io has crd/crds shortNames
        let crd_group =
            super::discover_group_resources_with_crds(&client, "apiextensions.k8s.io", "v1")
                .expect("apiextensions discovery succeeds");
        let crd_res = crd_group["resources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "customresourcedefinitions")
            .expect("crd resource found");
        assert_eq!(crd_res["shortNames"], json!(["crd", "crds"]));
    }

    #[tokio::test]
    async fn watch_hub_consistency_across_concurrent_subscribers() {
        use std::time::Duration;

        let dir = tempfile::TempDir::new().unwrap();
        let (engine, _) = diorama_datastore::DatastoreEngine::open(
            diorama_datastore::DatastoreConfig::new(dir.path().join("ds")),
        )
        .unwrap();
        let storage = crate::storage::KubernetesStorage::new(engine.client(), "/registry");
        let pki_dir = dir.path().join("pki");
        let config =
            crate::config::ApiserverConfig::default_for_pki(&pki_dir, "127.0.0.1".parse().unwrap());
        let service = crate::service::ApiserverService::new(config, storage.clone());

        let hub = super::get_or_init_watch_hub(&service).await;
        let mut rx1 = hub.inner.read().await.broadcast_tx.subscribe();
        let mut rx2 = hub.inner.read().await.broadcast_tx.subscribe();

        // Perform concurrent operations: create, update, delete
        let pod_json = serde_json::to_vec(&json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "pod-1", "namespace": "default" }
        }))
        .unwrap();
        storage
            .client()
            .create("/registry/pods/default/pod-1", pod_json.clone())
            .await
            .unwrap();

        let other_pod_json = serde_json::to_vec(&json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "pod-2", "namespace": "default" }
        }))
        .unwrap();
        storage
            .client()
            .create("/registry/pods/default/pod-2", other_pod_json)
            .await
            .unwrap();

        let updated_pod = serde_json::to_vec(&json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "pod-1", "namespace": "default", "labels": { "app": "test" } }
        }))
        .unwrap();
        storage
            .client()
            .update("/registry/pods/default/pod-1", updated_pod, None)
            .await
            .unwrap();

        storage
            .client()
            .delete("/registry/pods/default/pod-2", None)
            .await
            .unwrap();

        let mut events1 = Vec::new();
        let mut events2 = Vec::new();
        for _ in 0..4 {
            events1.push(
                tokio::time::timeout(Duration::from_secs(2), rx1.recv())
                    .await
                    .expect("recv rx1")
                    .unwrap(),
            );
            events2.push(
                tokio::time::timeout(Duration::from_secs(2), rx2.recv())
                    .await
                    .expect("recv rx2")
                    .unwrap(),
            );
        }

        // Both subscribers received identical events in identical order
        assert_eq!(events1.len(), 4);
        assert_eq!(events2.len(), 4);
        for i in 0..4 {
            assert_eq!(events1[i].resource_version, events2[i].resource_version);
            assert_eq!(events1[i].event_type, events2[i].event_type);
            assert_eq!(events1[i].key, events2[i].key);
        }

        // ResourceVersions are strictly monotonically increasing
        for window in events1.windows(2) {
            assert!(
                window[0].resource_version < window[1].resource_version,
                "rv must strictly increase: {} < {}",
                window[0].resource_version,
                window[1].resource_version
            );
        }

        // Deletion event has strictly greater resourceVersion than preceding update
        assert_eq!(events1[3].event_type, "DELETED");
        assert!(events1[3].resource_version > events1[2].resource_version);
    }
}
