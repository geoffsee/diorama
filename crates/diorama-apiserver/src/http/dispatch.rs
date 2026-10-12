//! Map Kubernetes HTTP verbs onto `KubernetesApiClient`.

use http::Method;
use serde_json::{Value, json};

use crate::client::KubernetesApiClient;
use crate::error::ApiserverError;
use crate::logs::PodLogOptions;
use crate::service::ApiserverService;

use super::query;
use super::route::ResourcePath;

pub(crate) enum Payload {
    Json(Value),
    Text(String),
    ChunkedText(String),
}

pub(crate) struct Outcome {
    pub(crate) status: http::StatusCode,
    pub(crate) body: Payload,
}

pub(crate) async fn dispatch(
    service: &ApiserverService,
    client: &KubernetesApiClient,
    method: &Method,
    path: &ResourcePath,
    content_type: Option<&str>,
    query: Option<&str>,
    body: &[u8],
) -> Result<Outcome, ApiserverError> {
    if let Some(subresource) = &path.subresource {
        return subresource_read(service, client, method, path, subresource, query).await;
    }
    if !matches!(*method, Method::GET | Method::POST | Method::DELETE) {
        return Ok(status_outcome(
            http::StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "method is not supported",
        ));
    }
    if method == Method::GET {
        return read(client, path).await.map(ok_json);
    }
    if method == Method::DELETE {
        return delete(client, path, query, body).await;
    }
    let doc = decode_body(content_type, body, path)?;
    create(client, path, doc).await.map(created_json)
}

async fn read(client: &KubernetesApiClient, path: &ResourcePath) -> Result<Value, ApiserverError> {
    if is_namespaced(&path.resource) {
        if let Some(namespace) = &path.namespace {
            if let Some(name) = &path.name {
                get_namespaced(client, &path.group, &path.resource, namespace, name).await
            } else {
                list_namespaced(client, &path.group, &path.resource, namespace).await
            }
        } else if path.name.is_none() {
            list_all_namespaces(client, &path.group, &path.resource).await
        } else {
            Err(ApiserverError::BadRequest {
                message: format!("{} requires a namespace", path.resource),
            })
        }
    } else if path.namespace.is_some() {
        Err(ApiserverError::NotFound {
            resource: path.resource.clone(),
            name: path.name.clone().unwrap_or_default(),
        })
    } else if let Some(name) = &path.name {
        get_cluster(client, &path.resource, name).await
    } else {
        list_cluster(client, &path.resource).await
    }
}

async fn delete(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    query: Option<&str>,
    body: &[u8],
) -> Result<Outcome, ApiserverError> {
    let Some(name) = &path.name else {
        return Err(ApiserverError::BadRequest {
            message: "delete requires a resource name".to_string(),
        });
    };
    let deleted = status_outcome(http::StatusCode::OK, "Success", "deleted");
    if is_namespaced(&path.resource) {
        let Some(namespace) = &path.namespace else {
            return Err(ApiserverError::BadRequest {
                message: format!("{} requires a namespace", path.resource),
            });
        };
        if path.group.is_empty() && path.resource == "pods" {
            // Pods delete gracefully: the kubelet owns the final removal.
            let grace = grace_period_seconds(query, body);
            return Ok(client
                .delete_pod_options(namespace, name, grace)
                .await?
                .map_or(deleted, ok_json));
        }
        delete_namespaced(client, &path.group, &path.resource, namespace, name).await?;
    } else {
        delete_cluster(client, &path.resource, name).await?;
    }
    Ok(deleted)
}

/// `gracePeriodSeconds` from the query or a `DeleteOptions` body, whichever is given.
fn grace_period_seconds(query: Option<&str>, body: &[u8]) -> Option<i64> {
    if let Some(value) = query::parse(query)
        .get("gracePeriodSeconds")
        .and_then(|v| v.parse().ok())
    {
        return Some(value);
    }
    serde_json::from_slice::<Value>(body)
        .ok()?
        .get("gracePeriodSeconds")?
        .as_i64()
}

async fn create(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    doc: Value,
) -> Result<Value, ApiserverError> {
    if path.name.is_some() {
        return Err(ApiserverError::BadRequest {
            message: "create does not take a resource name in the path".to_string(),
        });
    }
    if is_namespaced(&path.resource) {
        let Some(namespace) = &path.namespace else {
            return Err(ApiserverError::BadRequest {
                message: format!("{} requires a namespace", path.resource),
            });
        };
        create_namespaced(client, &path.group, &path.resource, namespace, doc).await
    } else {
        create_cluster(client, &path.resource, doc).await
    }
}

fn is_namespaced(resource: &str) -> bool {
    !matches!(
        resource,
        "namespaces" | "nodes" | "persistentvolumes" | "storageclasses"
    )
}

async fn list_all_namespaces(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
) -> Result<Value, ApiserverError> {
    if group.is_empty() && resource == "pods" {
        return client.list_all_pods().await;
    }
    let namespaces = client.list_namespaces().await?;
    let mut items = Vec::new();
    let mut version = String::new();
    if let Some(entries) = namespaces.get("items").and_then(Value::as_array) {
        for entry in entries {
            let Some(name) = entry.pointer("/metadata/name").and_then(Value::as_str) else {
                continue;
            };
            let page = list_namespaced(client, group, resource, name).await?;
            if let Some(page_items) = page.get("items").and_then(Value::as_array) {
                items.extend(page_items.iter().cloned());
            }
            if let Some(resource_version) = page
                .pointer("/metadata/resourceVersion")
                .and_then(Value::as_str)
            {
                version = resource_version.to_string();
            }
        }
    }
    let api_version = if group.is_empty() {
        "v1".to_string()
    } else {
        format!("{group}/v1")
    };
    Ok(json!({
        "apiVersion": api_version,
        "kind": list_kind(resource),
        "metadata": { "resourceVersion": version },
        "items": items
    }))
}

async fn list_namespaced(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    namespace: &str,
) -> Result<Value, ApiserverError> {
    match (group, resource) {
        ("", "pods") => client.list_pods(namespace).await,
        ("", "configmaps") => client.list_configmaps(namespace).await,
        ("", "secrets") => client.list_secrets(namespace).await,
        ("", "services") => client.list_services(namespace).await,
        ("", "serviceaccounts") => client.list_service_accounts(namespace).await,
        ("", "persistentvolumeclaims") => client.list_pvcs(namespace).await,
        ("apps", "deployments") => client.list_deployments(namespace).await,
        ("apps", "replicasets") => client.list_replicasets(namespace).await,
        ("apps", "statefulsets") => client.list_statefulsets(namespace).await,
        ("apps", "daemonsets") => client.list_daemonsets(namespace).await,
        _ => Err(unknown(resource)),
    }
}

async fn get_namespaced(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    namespace: &str,
    name: &str,
) -> Result<Value, ApiserverError> {
    match (group, resource) {
        ("", "pods") => client.get_pod(namespace, name).await,
        ("", "configmaps") => client.get_configmap(namespace, name).await,
        ("", "secrets") => client.get_secret(namespace, name).await,
        ("", "services") => client.get_service(namespace, name).await,
        ("", "serviceaccounts") => client.get_service_account(namespace, name).await,
        ("", "persistentvolumeclaims") => client.get_pvc(namespace, name).await,
        ("apps", "deployments") => client.get_deployment(namespace, name).await,
        ("apps", "replicasets") => client.get_replicaset(namespace, name).await,
        ("apps", "statefulsets") => client.get_statefulset(namespace, name).await,
        ("apps", "daemonsets") => client.get_daemonset(namespace, name).await,
        _ => Err(unknown(resource)),
    }
}

async fn delete_namespaced(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    namespace: &str,
    name: &str,
) -> Result<(), ApiserverError> {
    match (group, resource) {
        ("", "configmaps") => client.delete_configmap(namespace, name, None).await,
        ("", "secrets") => client.delete_secret(namespace, name, None).await,
        ("", "services") => client.delete_service(namespace, name).await,
        ("", "serviceaccounts") => client.delete_service_account(namespace, name).await,
        ("", "persistentvolumeclaims") => client.delete_pvc(namespace, name).await,
        ("apps", "deployments") => client.delete_deployment(namespace, name).await,
        ("apps", "replicasets") => client.delete_replicaset(namespace, name).await,
        ("apps", "statefulsets") => client.delete_statefulset(namespace, name).await,
        ("apps", "daemonsets") => client.delete_daemonset(namespace, name).await,
        _ => Err(unknown(resource)),
    }
}

async fn create_namespaced(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    namespace: &str,
    doc: Value,
) -> Result<Value, ApiserverError> {
    match (group, resource) {
        ("", "pods") => client.create_pod(namespace, doc).await,
        ("", "configmaps") => client.create_configmap_object(namespace, doc).await,
        ("", "secrets") => client.create_secret_object(namespace, doc).await,
        ("", "services") => client.create_service(namespace, doc).await,
        ("", "serviceaccounts") => client.create_service_account(namespace, doc).await,
        ("", "persistentvolumeclaims") => client.create_pvc(namespace, doc).await,
        ("apps", "deployments") => client.create_deployment(namespace, doc).await,
        ("apps", "replicasets") => client.create_replicaset(namespace, doc).await,
        ("apps", "statefulsets") => client.create_statefulset(namespace, doc).await,
        ("apps", "daemonsets") => client.create_daemonset(namespace, doc).await,
        _ => Err(unknown(resource)),
    }
}

async fn list_cluster(
    client: &KubernetesApiClient,
    resource: &str,
) -> Result<Value, ApiserverError> {
    match resource {
        "namespaces" => client.list_namespaces().await,
        "nodes" => client.list_nodes().await,
        "persistentvolumes" => client.list_pvs().await,
        "storageclasses" => client.list_storage_classes().await,
        _ => Err(unknown(resource)),
    }
}

async fn get_cluster(
    client: &KubernetesApiClient,
    resource: &str,
    name: &str,
) -> Result<Value, ApiserverError> {
    match resource {
        "namespaces" => client.get_namespace(name).await,
        "nodes" => client.get_node(name).await,
        "persistentvolumes" => client.get_pv(name).await,
        "storageclasses" => client.get_storage_class(name).await,
        _ => Err(unknown(resource)),
    }
}

async fn delete_cluster(
    client: &KubernetesApiClient,
    resource: &str,
    name: &str,
) -> Result<(), ApiserverError> {
    match resource {
        "namespaces" => client.delete_namespace(name).await,
        "nodes" => client.delete_node(name).await,
        "persistentvolumes" => client.delete_pv(name).await,
        "storageclasses" => client.delete_storage_class(name).await,
        _ => Err(unknown(resource)),
    }
}

async fn create_cluster(
    client: &KubernetesApiClient,
    resource: &str,
    doc: Value,
) -> Result<Value, ApiserverError> {
    let name = object_name(&doc)?;
    match resource {
        "namespaces" => client.create_namespace(&name).await,
        "nodes" => client.create_node(doc).await,
        "persistentvolumes" => client.create_pv(doc).await,
        "storageclasses" => client.create_storage_class(doc).await,
        _ => Err(unknown(resource)),
    }
}

fn decode_body(
    content_type: Option<&str>,
    body: &[u8],
    path: &ResourcePath,
) -> Result<Value, ApiserverError> {
    if body.is_empty() {
        return Ok(Value::Null);
    }
    if content_type.is_some_and(|value| value.contains("protobuf")) {
        let mut value = decode_protobuf_body(body, &path.resource)?;
        stamp_type_meta(&mut value, path);
        return Ok(value);
    }
    serde_json::from_slice(body).map_err(|err| ApiserverError::BadRequest {
        message: format!("request body is not JSON: {err}"),
    })
}

fn decode_protobuf_body(body: &[u8], resource: &str) -> Result<Value, ApiserverError> {
    let payload = body
        .strip_prefix(b"k8s\x00")
        .ok_or_else(|| ApiserverError::BadRequest {
            message: "kubernetes protobuf body is missing the k8s prefix".to_string(),
        })?;
    let raw = protobuf_unknown_raw(payload)?;
    if raw.is_empty() {
        return Err(ApiserverError::BadRequest {
            message: "kubernetes protobuf body did not contain an object".to_string(),
        });
    }
    if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
        return Ok(value);
    }
    protobuf_object_to_json(&raw, resource)
}

fn stamp_type_meta(doc: &mut Value, path: &ResourcePath) {
    let Some(object) = doc.as_object_mut() else {
        return;
    };
    let api_version = if path.group.is_empty() {
        "v1".to_string()
    } else {
        format!("{}/v1", path.group)
    };
    object
        .entry("apiVersion".to_string())
        .or_insert(Value::String(api_version));
    if let Some(kind) = kind_name(&path.resource) {
        object
            .entry("kind".to_string())
            .or_insert(Value::String(kind.to_string()));
    }
}

pub(crate) fn kind_name(resource: &str) -> Option<&'static str> {
    Some(match resource {
        "namespaces" => "Namespace",
        "configmaps" => "ConfigMap",
        "secrets" => "Secret",
        "pods" => "Pod",
        "services" => "Service",
        "serviceaccounts" => "ServiceAccount",
        "nodes" => "Node",
        "persistentvolumeclaims" => "PersistentVolumeClaim",
        "persistentvolumes" => "PersistentVolume",
        "deployments" => "Deployment",
        "replicasets" => "ReplicaSet",
        "statefulsets" => "StatefulSet",
        "daemonsets" => "DaemonSet",
        _ => return None,
    })
}

/// Reads field 2 (`raw`) from a `runtime.Unknown` protobuf message.
fn protobuf_unknown_raw(payload: &[u8]) -> Result<Vec<u8>, ApiserverError> {
    let mut input = payload;
    while !input.is_empty() {
        let (key, rest) = read_varint(input)?;
        input = rest;
        let field = key >> 3;
        let wire = key & 0x07;
        match wire {
            2 => {
                let (len, rest) = read_varint(input)?;
                let len = usize::try_from(len).map_err(|_| ApiserverError::BadRequest {
                    message: "kubernetes protobuf length is invalid".to_string(),
                })?;
                if rest.len() < len {
                    return Err(ApiserverError::BadRequest {
                        message: "kubernetes protobuf body is truncated".to_string(),
                    });
                }
                let (chunk, rest) = rest.split_at(len);
                input = rest;
                if field == 2 {
                    return Ok(chunk.to_vec());
                }
            },
            0 => {
                let (_, rest) = read_varint(input)?;
                input = rest;
            },
            _ => {
                return Err(ApiserverError::BadRequest {
                    message: format!("unsupported kubernetes protobuf wire type {wire}"),
                });
            },
        }
    }
    Err(ApiserverError::BadRequest {
        message: "kubernetes protobuf body has no raw object".to_string(),
    })
}

fn read_varint(input: &[u8]) -> Result<(u64, &[u8]), ApiserverError> {
    let mut value = 0u64;
    let mut shift = 0;
    for (index, byte) in input.iter().enumerate() {
        if shift >= 64 {
            break;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, &input[index + 1..]));
        }
        shift += 7;
    }
    Err(ApiserverError::BadRequest {
        message: "kubernetes protobuf varint is truncated".to_string(),
    })
}

/// Best-effort decode of a Kubernetes protobuf object into JSON.
///
/// kubectl sends built-in objects as `runtime.Unknown.raw`. That payload is
/// itself protobuf. The fields we need for create are `metadata.name` and a
/// few nested strings; everything else is preserved when it is length-delimited
/// UTF-8. This is enough for `kubectl create` and `kubectl apply`-style JSON
/// fallbacks are handled separately.
fn protobuf_object_to_json(raw: &[u8], resource: &str) -> Result<Value, ApiserverError> {
    let mut metadata = serde_json::Map::new();
    let mut data = serde_json::Map::new();
    let mut object = serde_json::Map::new();
    let mut input = raw;
    while !input.is_empty() {
        let (key, rest) = read_varint(input)?;
        input = rest;
        let field = key >> 3;
        let wire = key & 0x07;
        match wire {
            2 => {
                let (len, rest) = read_varint(input)?;
                let len = usize::try_from(len).unwrap_or(0);
                if rest.len() < len {
                    return Err(ApiserverError::BadRequest {
                        message: "kubernetes protobuf object is truncated".to_string(),
                    });
                }
                let (chunk, rest) = rest.split_at(len);
                input = rest;
                if field == 2 && resource == "configmaps" {
                    if let Some((key, value)) = protobuf_map_entry(chunk) {
                        data.insert(key, Value::String(value));
                    }
                    continue;
                }
                if let Some((name, value)) = protobuf_string_field(field, chunk) {
                    store_decoded_field(&mut object, &mut metadata, name, value);
                }
            },
            0 => {
                let (_, rest) = read_varint(input)?;
                input = rest;
            },
            _ => {
                return Err(ApiserverError::BadRequest {
                    message: format!("unsupported kubernetes object wire type {wire}"),
                });
            },
        }
    }
    if !metadata.is_empty() {
        object.insert("metadata".to_string(), Value::Object(metadata));
    }
    if !data.is_empty() {
        object.insert("data".to_string(), Value::Object(data));
    }
    if object.is_empty() {
        return Err(ApiserverError::BadRequest {
            message: "kubernetes protobuf object had no recognized fields".to_string(),
        });
    }
    Ok(Value::Object(object))
}

fn store_decoded_field(
    object: &mut serde_json::Map<String, Value>,
    metadata: &mut serde_json::Map<String, Value>,
    name: &str,
    value: Value,
) {
    if name == "metadata" {
        if let Value::Object(meta) = value {
            *metadata = meta;
        }
        return;
    }
    object.insert(name.to_string(), value);
}

fn protobuf_string_field(field: u64, chunk: &[u8]) -> Option<(&'static str, Value)> {
    // Kubernetes core `ObjectMeta` is field 1 on most objects. Nested strings
    // use the standard ObjectMeta field numbers: name=1, namespace=3.
    if field == 1 && !chunk.is_empty() && chunk[0] != b'{' {
        let mut meta = serde_json::Map::new();
        let mut input = chunk;
        while !input.is_empty() {
            let Ok((key, rest)) = read_varint(input) else {
                return None;
            };
            input = rest;
            let inner = key >> 3;
            let wire = key & 0x07;
            if wire == 0 {
                let Ok((_, rest)) = read_varint(input) else {
                    return None;
                };
                input = rest;
                continue;
            }
            if wire != 2 {
                return None;
            }
            let Ok((len, rest)) = read_varint(input) else {
                return None;
            };
            let Ok(len) = usize::try_from(len) else {
                return None;
            };
            if rest.len() < len {
                return None;
            }
            let (value, rest) = rest.split_at(len);
            input = rest;
            let Ok(text) = std::str::from_utf8(value) else {
                continue;
            };
            if text.is_empty() {
                continue;
            }
            let key_name = match inner {
                1 => "name",
                3 => "namespace",
                4 => "selfLink",
                _ => continue,
            };
            meta.insert(key_name.to_string(), Value::String(text.to_string()));
        }
        if meta.is_empty() {
            return None;
        }
        return Some(("metadata", Value::Object(meta)));
    }
    None
}

fn protobuf_map_entry(chunk: &[u8]) -> Option<(String, String)> {
    let mut key = None;
    let mut value = None;
    let mut input = chunk;
    while !input.is_empty() {
        let (tag, rest) = read_varint(input).ok()?;
        input = rest;
        if tag & 0x07 != 2 {
            return None;
        }
        let (len, rest) = read_varint(input).ok()?;
        let len = usize::try_from(len).ok()?;
        if rest.len() < len {
            return None;
        }
        let (bytes, rest) = rest.split_at(len);
        input = rest;
        let text = std::str::from_utf8(bytes).ok()?.to_string();
        match tag >> 3 {
            1 => key = Some(text),
            2 => value = Some(text),
            _ => {},
        }
    }
    Some((key?, value?))
}

fn object_name(doc: &Value) -> Result<String, ApiserverError> {
    doc.pointer("/metadata/name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ApiserverError::InvalidInput {
            field: "metadata.name".to_string(),
            reason: "resource requires metadata.name".to_string(),
        })
}

fn unknown(resource: &str) -> ApiserverError {
    ApiserverError::NotFound {
        resource: resource.to_string(),
        name: resource.to_string(),
    }
}

fn list_kind(resource: &str) -> &'static str {
    match resource {
        "pods" => "PodList",
        "configmaps" => "ConfigMapList",
        "secrets" => "SecretList",
        "services" => "ServiceList",
        "serviceaccounts" => "ServiceAccountList",
        "persistentvolumeclaims" => "PersistentVolumeClaimList",
        "deployments" => "DeploymentList",
        "replicasets" => "ReplicaSetList",
        "statefulsets" => "StatefulSetList",
        "daemonsets" => "DaemonSetList",
        _ => "List",
    }
}

fn ok_json(body: Value) -> Outcome {
    Outcome {
        status: http::StatusCode::OK,
        body: Payload::Json(body),
    }
}

fn created_json(body: Value) -> Outcome {
    Outcome {
        status: http::StatusCode::CREATED,
        body: Payload::Json(body),
    }
}

fn status_outcome(status: http::StatusCode, reason: &str, message: &str) -> Outcome {
    Outcome {
        status,
        body: Payload::Json(json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": if status.is_success() { "Success" } else { "Failure" },
            "message": message,
            "reason": reason,
            "code": status.as_u16()
        })),
    }
}

/// Serves the read-only subresources kubectl needs: `status` echoes the stored
/// object and `log` streams captured container output from the kubelet.
async fn subresource_read(
    service: &ApiserverService,
    client: &KubernetesApiClient,
    method: &Method,
    path: &ResourcePath,
    subresource: &str,
    query: Option<&str>,
) -> Result<Outcome, ApiserverError> {
    if method != Method::GET {
        return Ok(status_outcome(
            http::StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "method is not supported",
        ));
    }
    if path.name.is_none() {
        return Err(ApiserverError::BadRequest {
            message: format!("{subresource} requires a resource name"),
        });
    }
    match (path.group.as_str(), path.resource.as_str(), subresource) {
        (_, _, "status") => {
            let object = ResourcePath {
                subresource: None,
                ..path.clone()
            };
            read(client, &object).await.map(ok_json)
        },
        ("", "pods", "log") => {
            let (Some(namespace), Some(name)) = (&path.namespace, &path.name) else {
                return Err(ApiserverError::BadRequest {
                    message: "pods requires a namespace".to_string(),
                });
            };
            let pod = client.get_pod(namespace, name).await?;
            let Some(reader) = service.pod_log_reader() else {
                return Err(ApiserverError::Internal {
                    reason: "no kubelet is registered to serve pod logs".to_string(),
                });
            };
            let options = PodLogOptions::from_params(&query::parse(query));
            let follow = options.follow;
            let text = reader.read_pod_log(&pod, &options).await?;
            let body = if follow {
                Payload::ChunkedText(text)
            } else {
                Payload::Text(text)
            };
            Ok(Outcome {
                status: http::StatusCode::OK,
                body,
            })
        },
        _ => Err(ApiserverError::NotFound {
            resource: format!("{}/{subresource}", path.resource),
            name: path.name.clone().unwrap_or_default(),
        }),
    }
}
