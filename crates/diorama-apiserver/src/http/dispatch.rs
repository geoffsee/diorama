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
        return subresource_dispatch(
            service,
            client,
            method,
            path,
            subresource,
            query,
            content_type,
            body,
        )
        .await;
    }
    if method == Method::GET {
        return read(client, path, query).await.map(ok_json);
    }
    if method == Method::DELETE {
        return delete(client, path, query, body).await;
    }
    if method == Method::PUT {
        let doc = decode_body(content_type, body, path)?;
        return replace(client, path, query, doc).await.map(ok_json);
    }
    if method == Method::PATCH {
        return patch(client, path, content_type, query, body)
            .await
            .map(ok_json);
    }
    if method == Method::POST {
        let doc = decode_body(content_type, body, path)?;
        return create(client, path, doc).await.map(created_json);
    }
    Ok(status_outcome(
        http::StatusCode::METHOD_NOT_ALLOWED,
        "MethodNotAllowed",
        "method is not supported",
    ))
}

async fn read(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    query: Option<&str>,
) -> Result<Value, ApiserverError> {
    if is_namespaced(&path.resource) {
        if let Some(namespace) = &path.namespace {
            if let Some(name) = &path.name {
                get_namespaced(client, &path.group, &path.resource, namespace, name).await
            } else {
                let list = list_namespaced(client, &path.group, &path.resource, namespace).await?;
                page_list(filter_list(list, query), query)
            }
        } else if path.name.is_none() {
            let list = list_all_namespaces(client, &path.group, &path.resource).await?;
            page_list(filter_list(list, query), query)
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
        get_cluster(client, &path.group, &path.resource, name).await
    } else {
        let list = list_cluster(client, &path.group, &path.resource).await?;
        page_list(filter_list(list, query), query)
    }
}

/// Pages a filtered list. `continue` is `c.<issued>.<rv>.<lastName>` and stays
/// consistent for 30 seconds. After that the server returns 410 with an
/// inconsistent token so clients can resume without the original resourceVersion.
fn page_list(mut list: Value, query: Option<&str>) -> Result<Value, ApiserverError> {
    let params = query::parse(query);
    let Some(limit) = params
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
    else {
        return Ok(list);
    };
    if limit == 0 {
        return Ok(list);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let token = params.get("continue").cloned().unwrap_or_default();
    let (start_after, response_rv, inconsistent) = if token.is_empty() {
        (String::new(), None, false)
    } else {
        let mut parts = token.split('.');
        let mode = parts.next().unwrap_or("");
        let issued = parts.next().and_then(|value| value.parse::<u64>().ok());
        let rv = parts.next().unwrap_or("").to_string();
        let name = parts.collect::<Vec<_>>().join(".");
        if !matches!(mode, "c" | "i") || issued.is_none() || rv.is_empty() {
            return Err(ApiserverError::BadRequest {
                message: "continue token is invalid".to_string(),
            });
        }
        let issued = issued.unwrap_or(0);
        if mode == "c" && now.saturating_sub(issued) >= 30 {
            let next = format!("i.{now}.{rv}i.{name}");
            return Err(ApiserverError::Expired {
                continue_token: next,
            });
        }
        (name, Some(rv), mode == "i")
    };
    let Some(items) = list.get_mut("items").and_then(Value::as_array_mut) else {
        return Ok(list);
    };
    items.sort_by(|left, right| {
        let left = left
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let right = right
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        left.cmp(right)
    });
    let start = if start_after.is_empty() {
        0
    } else {
        items
            .iter()
            .position(|item| {
                item.pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    > start_after.as_str()
            })
            .unwrap_or(items.len())
    };
    let end = (start + limit).min(items.len());
    let page = items[start..end].to_vec();
    let remaining = items.len().saturating_sub(end);
    let last_name = page
        .last()
        .and_then(|item| item.pointer("/metadata/name"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    *items = page;
    let current_rv = list
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .unwrap_or("0")
        .to_string();
    let rv = response_rv.unwrap_or(current_rv);
    if let Some(meta) = list.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.insert("resourceVersion".to_string(), json!(rv));
        if remaining > 0 {
            let mode = if inconsistent { "i" } else { "c" };
            meta.insert(
                "continue".to_string(),
                json!(format!("{mode}.{now}.{rv}.{last_name}")),
            );
            meta.insert("remainingItemCount".to_string(), json!(remaining));
        } else {
            meta.remove("continue");
            meta.remove("remainingItemCount");
        }
    }
    Ok(list)
}

/// Applies `labelSelector` (`key=value,key2=value2`) and `fieldSelector`
/// (`metadata.name=x`) to a list response. Selectors kubectl always sends
/// (`spec.nodeName`, `status.phase`) that we do not index are ignored rather
/// than rejected so list calls succeed.
fn filter_list(mut list: Value, query: Option<&str>) -> Value {
    let params = query::parse(query);
    let label_selector = params.get("labelSelector").cloned().unwrap_or_default();
    let field_selector = params.get("fieldSelector").cloned().unwrap_or_default();
    if label_selector.is_empty() && field_selector.is_empty() {
        return list;
    }
    let labels = parse_label_selector(&label_selector);
    let fields = parse_label_selector(&field_selector);
    let Some(items) = list.get_mut("items").and_then(Value::as_array_mut) else {
        return list;
    };
    items.retain(|item| {
        labels.iter().all(|(key, want)| {
            item.pointer("/metadata/labels")
                .and_then(|v| v.get(key))
                .and_then(Value::as_str)
                == Some(want.as_str())
        }) && fields.iter().all(|(key, want)| match key.as_str() {
            "metadata.name" => {
                item.pointer("/metadata/name").and_then(Value::as_str) == Some(want.as_str())
            },
            "metadata.namespace" => {
                item.pointer("/metadata/namespace").and_then(Value::as_str) == Some(want.as_str())
            },
            // Unindexed selectors (spec.nodeName, status.phase, ...) match
            // everything so controllers can list without field indexing.
            _ => true,
        })
    });
    list
}

fn parse_label_selector(selector: &str) -> Vec<(String, String)> {
    selector
        .split(',')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || key.contains('!') || value.is_empty() {
                return None;
            }
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

async fn delete(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    query: Option<&str>,
    body: &[u8],
) -> Result<Outcome, ApiserverError> {
    let Some(name) = &path.name else {
        // Collection delete: remove every selected object, like upstream.
        return delete_collection(client, path, query).await;
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
        delete_cluster(client, &path.group, &path.resource, name).await?;
    }
    Ok(deleted)
}

/// Deletes every object selected by a collection `DELETE`, honouring
/// `labelSelector`/`fieldSelector` like `GET`. Missing objects are skipped so
/// clients can clean up by label without knowing exact names.
async fn delete_collection(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    query: Option<&str>,
) -> Result<Outcome, ApiserverError> {
    let list = read(client, path, query).await?;
    let items = list
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for item in items {
        let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) else {
            continue;
        };
        let deleted = if is_namespaced(&path.resource) {
            let namespace = item
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .or(path.namespace.as_deref());
            let Some(namespace) = namespace else {
                continue;
            };
            if path.group.is_empty() && path.resource == "pods" {
                // Best effort; the kubelet owns graceful pod removal.
                client
                    .delete_pod_options(namespace, name, None)
                    .await
                    .map(|_| ())
            } else {
                delete_namespaced(client, &path.group, &path.resource, namespace, name).await
            }
        } else {
            delete_cluster(client, &path.group, &path.resource, name).await
        };
        // An object deleted concurrently is already at the desired state.
        if let Err(ApiserverError::NotFound { .. }) = deleted {
            continue;
        }
        deleted?;
    }
    Ok(status_outcome(http::StatusCode::OK, "Success", "deleted"))
}

async fn replace(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    query: Option<&str>,
    doc: Value,
) -> Result<Value, ApiserverError> {
    let Some(name) = &path.name else {
        return Err(ApiserverError::BadRequest {
            message: "replace requires a resource name".to_string(),
        });
    };
    if is_dry_run(query) {
        // Validate the object exists, then echo the replacement without storing.
        let _ = read_single(client, path, name).await?;
        return Ok(stamp_replacement(doc, path, name));
    }
    if is_namespaced(&path.resource) {
        let Some(namespace) = &path.namespace else {
            return Err(ApiserverError::BadRequest {
                message: format!("{} requires a namespace", path.resource),
            });
        };
        update_namespaced(client, &path.group, &path.resource, namespace, name, doc).await
    } else {
        update_cluster(client, &path.group, &path.resource, name, doc).await
    }
}

fn stamp_replacement(mut doc: Value, path: &ResourcePath, name: &str) -> Value {
    if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.insert("name".to_string(), json!(name));
        if let Some(namespace) = &path.namespace {
            meta.insert("namespace".to_string(), json!(namespace));
        }
    }
    doc
}

async fn read_single(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    name: &str,
) -> Result<Value, ApiserverError> {
    if is_namespaced(&path.resource) {
        let Some(namespace) = &path.namespace else {
            return Err(ApiserverError::BadRequest {
                message: format!("{} requires a namespace", path.resource),
            });
        };
        get_namespaced(client, &path.group, &path.resource, namespace, name).await
    } else {
        get_cluster(client, &path.group, &path.resource, name).await
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PatchType {
    Json,
    Merge,
    Apply,
}

fn patch_type(content_type: Option<&str>) -> PatchType {
    let content = content_type.unwrap_or_default().to_ascii_lowercase();
    if content.contains("json-patch") {
        PatchType::Json
    } else if content.contains("apply-patch") {
        PatchType::Apply
    } else {
        // merge-patch, strategic-merge-patch and plain JSON all merge objects.
        PatchType::Merge
    }
}

fn is_dry_run(query: Option<&str>) -> bool {
    query::parse(query).contains_key("dryRun")
}

async fn patch(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    content_type: Option<&str>,
    query: Option<&str>,
    body: &[u8],
) -> Result<Value, ApiserverError> {
    let Some(name) = &path.name else {
        return Err(ApiserverError::BadRequest {
            message: "patch requires a resource name".to_string(),
        });
    };
    let kind = patch_type(content_type);
    let existing = read_single(client, path, name).await;
    if kind == PatchType::Apply {
        return apply_patch(client, path, query, name, body, existing).await;
    }
    let mut target = match existing {
        Ok(doc) => doc,
        Err(err) => return Err(err),
    };
    match kind {
        PatchType::Json => {
            crate::admission::apply_json_patch(&mut target, body)?;
        },
        PatchType::Merge => {
            let merge: Value =
                serde_json::from_slice(body).map_err(|err| ApiserverError::BadRequest {
                    message: format!("patch body is not JSON: {err}"),
                })?;
            crate::client::json_merge_patch(&mut target, merge);
        },
        PatchType::Apply => unreachable!("handled above"),
    }
    if is_dry_run(query) {
        return Ok(target);
    }
    if is_namespaced(&path.resource) {
        let Some(namespace) = &path.namespace else {
            return Err(ApiserverError::BadRequest {
                message: format!("{} requires a namespace", path.resource),
            });
        };
        update_namespaced(client, &path.group, &path.resource, namespace, name, target).await
    } else {
        update_cluster(client, &path.group, &path.resource, name, target).await
    }
}

/// Server-side apply: creates the object when absent, otherwise merges the
/// applied manifest onto the stored object. Field ownership tracking is
/// simplified to a full merge; `force` and `fieldManager` are accepted.
async fn apply_patch(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    query: Option<&str>,
    name: &str,
    body: &[u8],
    existing: Result<Value, ApiserverError>,
) -> Result<Value, ApiserverError> {
    let mut applied: Value =
        serde_json::from_slice(body).map_err(|err| ApiserverError::BadRequest {
            message: format!("apply body is not JSON: {err}"),
        })?;
    // The applied manifest wins for its fields; strip server-assigned metadata
    // that must never be taken from the client.
    if let Some(meta) = applied.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.remove("resourceVersion");
        meta.remove("uid");
        meta.remove("creationTimestamp");
        meta.insert("name".to_string(), json!(name));
        if let Some(namespace) = &path.namespace {
            meta.insert("namespace".to_string(), json!(namespace));
        }
    }
    let dry_run = is_dry_run(query);
    match existing {
        Err(ApiserverError::NotFound { .. }) => {
            if dry_run {
                return Ok(applied);
            }
            if is_namespaced(&path.resource) {
                let Some(namespace) = &path.namespace else {
                    return Err(ApiserverError::BadRequest {
                        message: format!("{} requires a namespace", path.resource),
                    });
                };
                create_namespaced(client, &path.group, &path.resource, namespace, applied).await
            } else {
                create_cluster(client, &path.group, &path.resource, applied).await
            }
        },
        Err(err) => Err(err),
        Ok(mut current) => {
            crate::client::json_merge_patch(&mut current, applied);
            if dry_run {
                return Ok(current);
            }
            if is_namespaced(&path.resource) {
                let Some(namespace) = &path.namespace else {
                    return Err(ApiserverError::BadRequest {
                        message: format!("{} requires a namespace", path.resource),
                    });
                };
                update_namespaced(
                    client,
                    &path.group,
                    &path.resource,
                    namespace,
                    name,
                    current,
                )
                .await
            } else {
                update_cluster(client, &path.group, &path.resource, name, current).await
            }
        },
    }
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
        create_cluster(client, &path.group, &path.resource, doc).await
    }
}

fn is_namespaced(resource: &str) -> bool {
    !matches!(
        resource,
        "namespaces"
            | "nodes"
            | "persistentvolumes"
            | "storageclasses"
            | "clusterroles"
            | "clusterrolebindings"
            | "customresourcedefinitions"
            | "validatingwebhookconfigurations"
            | "mutatingwebhookconfigurations"
            | "apiservices"
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
        ("", "endpoints") => client.list_endpoints(namespace).await,
        ("", "serviceaccounts") => client.list_service_accounts(namespace).await,
        ("", "persistentvolumeclaims") => client.list_pvcs(namespace).await,
        ("", "events") => {
            client
                .list_namespaced_objects("", "EventList", "events", namespace)
                .await
        },
        ("discovery.k8s.io", "endpointslices") => client.list_endpointslices(namespace).await,
        ("apps", "deployments") => client.list_deployments(namespace).await,
        ("apps", "replicasets") => client.list_replicasets(namespace).await,
        ("apps", "statefulsets") => client.list_statefulsets(namespace).await,
        ("apps", "daemonsets") => client.list_daemonsets(namespace).await,
        ("batch", "jobs") => client.list_jobs(namespace).await,
        ("batch", "cronjobs") => client.list_cronjobs(namespace).await,
        ("coordination.k8s.io", "leases") => client.list_leases(namespace).await,
        ("events.k8s.io", "events") => {
            client
                .list_namespaced_objects("events.k8s.io", "EventList", "events", namespace)
                .await
        },
        ("rbac.authorization.k8s.io", "roles") => {
            client
                .list_namespaced_objects(
                    "rbac.authorization.k8s.io",
                    "RoleList",
                    "roles",
                    namespace,
                )
                .await
        },
        ("rbac.authorization.k8s.io", "rolebindings") => {
            client
                .list_namespaced_objects(
                    "rbac.authorization.k8s.io",
                    "RoleBindingList",
                    "rolebindings",
                    namespace,
                )
                .await
        },
        _ => {
            client
                .list_namespaced_objects(group, list_kind(resource), resource, namespace)
                .await
        },
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
        ("", "endpoints") => client.get_endpoints(namespace, name).await,
        ("", "serviceaccounts") => client.get_service_account(namespace, name).await,
        ("", "persistentvolumeclaims") => client.get_pvc(namespace, name).await,
        ("", "events") => {
            client
                .get_namespaced_object("", "events", namespace, name)
                .await
        },
        ("discovery.k8s.io", "endpointslices") => client.get_endpointslice(namespace, name).await,
        ("apps", "deployments") => client.get_deployment(namespace, name).await,
        ("apps", "replicasets") => client.get_replicaset(namespace, name).await,
        ("apps", "statefulsets") => client.get_statefulset(namespace, name).await,
        ("apps", "daemonsets") => client.get_daemonset(namespace, name).await,
        ("batch", "jobs") => client.get_job(namespace, name).await,
        ("batch", "cronjobs") => client.get_cronjob(namespace, name).await,
        ("coordination.k8s.io", "leases") => client.get_lease(namespace, name).await,
        ("events.k8s.io", "events") => {
            client
                .get_namespaced_object("events.k8s.io", "events", namespace, name)
                .await
        },
        ("rbac.authorization.k8s.io", "roles") => {
            client
                .get_namespaced_object("rbac.authorization.k8s.io", "roles", namespace, name)
                .await
        },
        ("rbac.authorization.k8s.io", "rolebindings") => {
            client
                .get_namespaced_object("rbac.authorization.k8s.io", "rolebindings", namespace, name)
                .await
        },
        _ => {
            client
                .get_namespaced_object(group, resource, namespace, name)
                .await
        },
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
        ("", "endpoints") => client.delete_endpoints(namespace, name).await,
        ("", "serviceaccounts") => client.delete_service_account(namespace, name).await,
        ("", "persistentvolumeclaims") => client.delete_pvc(namespace, name).await,
        ("", "events") => {
            client
                .delete_namespaced_object("", "events", namespace, name)
                .await
        },
        ("discovery.k8s.io", "endpointslices") => {
            client.delete_endpointslice(namespace, name).await
        },
        ("apps", "deployments") => client.delete_deployment(namespace, name).await,
        ("apps", "replicasets") => client.delete_replicaset(namespace, name).await,
        ("apps", "statefulsets") => client.delete_statefulset(namespace, name).await,
        ("apps", "daemonsets") => client.delete_daemonset(namespace, name).await,
        ("batch", "jobs") => client.delete_job(namespace, name).await,
        ("batch", "cronjobs") => client.delete_cronjob(namespace, name).await,
        ("coordination.k8s.io", "leases") => client.delete_lease(namespace, name).await,
        ("events.k8s.io", "events") => {
            client
                .delete_namespaced_object("events.k8s.io", "events", namespace, name)
                .await
        },
        ("rbac.authorization.k8s.io", "roles") => {
            client
                .delete_namespaced_object("rbac.authorization.k8s.io", "roles", namespace, name)
                .await
        },
        ("rbac.authorization.k8s.io", "rolebindings") => {
            client
                .delete_namespaced_object(
                    "rbac.authorization.k8s.io",
                    "rolebindings",
                    namespace,
                    name,
                )
                .await
        },
        _ => {
            client
                .delete_namespaced_object(group, resource, namespace, name)
                .await
        },
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
        ("", "endpoints") => client.create_endpoints(namespace, doc).await,
        ("", "serviceaccounts") => client.create_service_account(namespace, doc).await,
        ("", "persistentvolumeclaims") => client.create_pvc(namespace, doc).await,
        ("", "events") => {
            client
                .create_namespaced_object("", "Event", "events", namespace, doc)
                .await
        },
        ("discovery.k8s.io", "endpointslices") => client.create_endpointslice(namespace, doc).await,
        ("apps", "deployments") => client.create_deployment(namespace, doc).await,
        ("apps", "replicasets") => client.create_replicaset(namespace, doc).await,
        ("apps", "statefulsets") => client.create_statefulset(namespace, doc).await,
        ("apps", "daemonsets") => client.create_daemonset(namespace, doc).await,
        ("batch", "jobs") => client.create_job(namespace, doc).await,
        ("batch", "cronjobs") => client.create_cronjob(namespace, doc).await,
        ("coordination.k8s.io", "leases") => client.create_lease(namespace, doc).await,
        ("events.k8s.io", "events") => {
            client
                .create_namespaced_object("events.k8s.io", "Event", "events", namespace, doc)
                .await
        },
        ("rbac.authorization.k8s.io", "roles") => {
            client
                .create_namespaced_object(
                    "rbac.authorization.k8s.io",
                    "Role",
                    "roles",
                    namespace,
                    doc,
                )
                .await
        },
        ("rbac.authorization.k8s.io", "rolebindings") => {
            client
                .create_namespaced_object(
                    "rbac.authorization.k8s.io",
                    "RoleBinding",
                    "rolebindings",
                    namespace,
                    doc,
                )
                .await
        },
        _ => {
            let kind = kind_name(resource).unwrap_or("Object");
            client
                .create_namespaced_object(group, kind, resource, namespace, doc)
                .await
        },
    }
}

async fn update_namespaced(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    namespace: &str,
    name: &str,
    doc: Value,
) -> Result<Value, ApiserverError> {
    match (group, resource) {
        ("", "pods") => client.update_pod(namespace, name, doc).await,
        ("", "services") => client.update_service(namespace, name, doc).await,
        ("", "endpoints") => client.update_endpoints(namespace, name, doc).await,
        ("", "persistentvolumeclaims") => client.update_pvc(namespace, name, doc).await,
        ("discovery.k8s.io", "endpointslices") => {
            client.update_endpointslice(namespace, name, doc).await
        },
        ("apps", "deployments") => client.update_deployment(namespace, name, doc).await,
        ("apps", "replicasets") => client.update_replicaset(namespace, name, doc).await,
        ("apps", "statefulsets") => client.update_statefulset(namespace, name, doc).await,
        ("apps", "daemonsets") => client.update_daemonset(namespace, name, doc).await,
        ("batch", "jobs") => client.update_job(namespace, name, doc).await,
        ("batch", "cronjobs") => client.update_cronjob(namespace, name, doc).await,
        ("coordination.k8s.io", "leases") => client.update_lease(namespace, name, doc).await,
        _ => {
            let kind = kind_name(resource).unwrap_or("Object");
            client
                .replace_namespaced_object(group, kind, resource, namespace, name, doc)
                .await
        },
    }
}

async fn list_cluster(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
) -> Result<Value, ApiserverError> {
    match (group, resource) {
        ("", "namespaces") => client.list_namespaces().await,
        ("", "nodes") => client.list_nodes().await,
        ("", "persistentvolumes") => client.list_pvs().await,
        ("storage.k8s.io" | "", "storageclasses") => client.list_storage_classes().await,
        ("rbac.authorization.k8s.io", "clusterroles") => {
            client
                .list_cluster_objects(
                    "rbac.authorization.k8s.io",
                    "ClusterRoleList",
                    "clusterroles",
                )
                .await
        },
        ("rbac.authorization.k8s.io", "clusterrolebindings") => {
            client
                .list_cluster_objects(
                    "rbac.authorization.k8s.io",
                    "ClusterRoleBindingList",
                    "clusterrolebindings",
                )
                .await
        },
        ("apiextensions.k8s.io", "customresourcedefinitions") => client.list_crds().await,
        ("admissionregistration.k8s.io", "validatingwebhookconfigurations") => {
            client.list_validating_webhook_configurations().await
        },
        ("admissionregistration.k8s.io", "mutatingwebhookconfigurations") => {
            client.list_mutating_webhook_configurations().await
        },
        ("apiregistration.k8s.io", "apiservices") => client.list_api_services().await,
        _ => {
            client
                .list_cluster_objects(group, list_kind(resource), resource)
                .await
        },
    }
}

async fn get_cluster(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    name: &str,
) -> Result<Value, ApiserverError> {
    match (group, resource) {
        ("", "namespaces") => client.get_namespace(name).await,
        ("", "nodes") => client.get_node(name).await,
        ("", "persistentvolumes") => client.get_pv(name).await,
        ("storage.k8s.io" | "", "storageclasses") => client.get_storage_class(name).await,
        ("rbac.authorization.k8s.io", "clusterroles") => cluster_role_to_json(
            client
                .get_cluster_object("rbac.authorization.k8s.io", "clusterroles", name)
                .await,
        ),
        ("rbac.authorization.k8s.io", "clusterrolebindings") => {
            client
                .get_cluster_object("rbac.authorization.k8s.io", "clusterrolebindings", name)
                .await
        },
        ("apiextensions.k8s.io", "customresourcedefinitions") => client.get_crd(name).await,
        ("admissionregistration.k8s.io", "validatingwebhookconfigurations") => {
            client.get_validating_webhook_configuration(name).await
        },
        ("admissionregistration.k8s.io", "mutatingwebhookconfigurations") => {
            client.get_mutating_webhook_configuration(name).await
        },
        ("apiregistration.k8s.io", "apiservices") => client.get_api_service(name).await,
        _ => client.get_cluster_object(group, resource, name).await,
    }
}

/// Stored cluster roles are already standard objects; passthrough helper keeps
/// the match arms symmetric while leaving room for bootstrap-role fallback.
fn cluster_role_to_json(result: Result<Value, ApiserverError>) -> Result<Value, ApiserverError> {
    result
}

async fn delete_cluster(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    name: &str,
) -> Result<(), ApiserverError> {
    match (group, resource) {
        ("", "namespaces") => client.delete_namespace(name).await,
        ("", "nodes") => client.delete_node(name).await,
        ("", "persistentvolumes") => client.delete_pv(name).await,
        ("storage.k8s.io" | "", "storageclasses") => client.delete_storage_class(name).await,
        ("rbac.authorization.k8s.io", "clusterroles") => {
            client
                .delete_cluster_object("rbac.authorization.k8s.io", "clusterroles", name)
                .await
        },
        ("rbac.authorization.k8s.io", "clusterrolebindings") => {
            client
                .delete_cluster_object("rbac.authorization.k8s.io", "clusterrolebindings", name)
                .await
        },
        ("apiextensions.k8s.io", "customresourcedefinitions") => client.delete_crd(name).await,
        ("admissionregistration.k8s.io", "validatingwebhookconfigurations") => {
            client.delete_validating_webhook_configuration(name).await
        },
        ("admissionregistration.k8s.io", "mutatingwebhookconfigurations") => {
            client.delete_mutating_webhook_configuration(name).await
        },
        ("apiregistration.k8s.io", "apiservices") => client.delete_api_service(name).await,
        _ => client.delete_cluster_object(group, resource, name).await,
    }
}

async fn create_cluster(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    doc: Value,
) -> Result<Value, ApiserverError> {
    match (group, resource) {
        ("", "namespaces") => {
            let name = object_name(&doc)?;
            client.create_namespace(&name).await
        },
        ("", "nodes") => client.create_node(doc).await,
        ("", "persistentvolumes") => client.create_pv(doc).await,
        ("storage.k8s.io" | "", "storageclasses") => client.create_storage_class(doc).await,
        ("rbac.authorization.k8s.io", "clusterroles") => {
            client
                .create_cluster_object(
                    "rbac.authorization.k8s.io",
                    "ClusterRole",
                    "clusterroles",
                    doc,
                )
                .await
        },
        ("rbac.authorization.k8s.io", "clusterrolebindings") => {
            client
                .create_cluster_object(
                    "rbac.authorization.k8s.io",
                    "ClusterRoleBinding",
                    "clusterrolebindings",
                    doc,
                )
                .await
        },
        ("apiextensions.k8s.io", "customresourcedefinitions") => client.create_crd(doc).await,
        ("admissionregistration.k8s.io", "validatingwebhookconfigurations") => {
            client.create_validating_webhook_configuration(doc).await
        },
        ("admissionregistration.k8s.io", "mutatingwebhookconfigurations") => {
            client.create_mutating_webhook_configuration(doc).await
        },
        ("apiregistration.k8s.io", "apiservices") => client.create_api_service(doc).await,
        _ => {
            let kind = kind_name(resource).unwrap_or("Object");
            client
                .create_cluster_object(group, kind, resource, doc)
                .await
        },
    }
}

async fn update_cluster(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    name: &str,
    doc: Value,
) -> Result<Value, ApiserverError> {
    match (group, resource) {
        ("", "nodes") => client.update_node(name, doc).await,
        ("", "persistentvolumes") => client.update_pv(name, doc).await,
        ("storage.k8s.io" | "", "storageclasses") => client.update_storage_class(name, doc).await,
        _ => {
            let kind = kind_name(resource).unwrap_or("Object");
            client
                .replace_cluster_object(group, kind, resource, name, doc)
                .await
        },
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
        if let Some(mut value) = crate::http::protojson::decode_k8s_protobuf(body, &path.resource)?
        {
            stamp_type_meta(&mut value, path);
            return Ok(value);
        }
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
        "podtemplates" => "PodTemplate",
        "limitranges" => "LimitRange",
        "resourcequotas" => "ResourceQuota",
        "replicationcontrollers" => "ReplicationController",
        "bindings" => "Binding",
        "services" => "Service",
        "endpoints" => "Endpoints",
        "endpointslices" => "EndpointSlice",
        "serviceaccounts" => "ServiceAccount",
        "nodes" => "Node",
        "persistentvolumeclaims" => "PersistentVolumeClaim",
        "persistentvolumes" => "PersistentVolume",
        "deployments" => "Deployment",
        "replicasets" => "ReplicaSet",
        "statefulsets" => "StatefulSet",
        "daemonsets" => "DaemonSet",
        "jobs" => "Job",
        "cronjobs" => "CronJob",
        "leases" => "Lease",
        "events" => "Event",
        "roles" => "Role",
        "rolebindings" => "RoleBinding",
        "clusterroles" => "ClusterRole",
        "clusterrolebindings" => "ClusterRoleBinding",
        "storageclasses" => "StorageClass",
        "customresourcedefinitions" => "CustomResourceDefinition",
        "validatingwebhookconfigurations" => "ValidatingWebhookConfiguration",
        "mutatingwebhookconfigurations" => "MutatingWebhookConfiguration",
        "apiservices" => "APIService",
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

fn list_kind(resource: &str) -> &'static str {
    match resource {
        "pods" => "PodList",
        "podtemplates" => "PodTemplateList",
        "limitranges" => "LimitRangeList",
        "resourcequotas" => "ResourceQuotaList",
        "replicationcontrollers" => "ReplicationControllerList",
        "configmaps" => "ConfigMapList",
        "secrets" => "SecretList",
        "services" => "ServiceList",
        "endpoints" => "EndpointsList",
        "endpointslices" => "EndpointSliceList",
        "serviceaccounts" => "ServiceAccountList",
        "persistentvolumeclaims" => "PersistentVolumeClaimList",
        "deployments" => "DeploymentList",
        "replicasets" => "ReplicaSetList",
        "statefulsets" => "StatefulSetList",
        "daemonsets" => "DaemonSetList",
        "jobs" => "JobList",
        "cronjobs" => "CronJobList",
        "leases" => "LeaseList",
        "events" => "EventList",
        "roles" => "RoleList",
        "rolebindings" => "RoleBindingList",
        "clusterroles" => "ClusterRoleList",
        "clusterrolebindings" => "ClusterRoleBindingList",
        "storageclasses" => "StorageClassList",
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

/// Serves the subresources kubectl needs: `status` echoes or replaces the stored
/// object, `scale` reports or sets replicas, and `log` streams captured
/// container output from the kubelet.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn subresource_dispatch(
    service: &ApiserverService,
    client: &KubernetesApiClient,
    method: &Method,
    path: &ResourcePath,
    subresource: &str,
    query: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Outcome, ApiserverError> {
    if path.name.is_none() {
        return Err(ApiserverError::BadRequest {
            message: format!("{subresource} requires a resource name"),
        });
    }
    match (path.group.as_str(), path.resource.as_str(), subresource) {
        (_, _, "status") => match *method {
            Method::GET => {
                let object = ResourcePath {
                    subresource: None,
                    ..path.clone()
                };
                read(client, &object, query).await.map(ok_json)
            },
            Method::PUT | Method::PATCH => {
                let Some(name) = &path.name else {
                    return Err(ApiserverError::BadRequest {
                        message: "status requires a resource name".to_string(),
                    });
                };
                let mut current = read_single(client, &strip_subresource(path), name).await?;
                if method == Method::PUT {
                    let doc = decode_body(content_type, body, path)?;
                    if let Some(status) = doc.get("status") {
                        current["status"] = status.clone();
                    }
                } else {
                    apply_body_patch(&mut current, content_type, body)?;
                }
                persist_object(client, path, name, current)
                    .await
                    .map(ok_json)
            },
            _ => Ok(status_outcome(
                http::StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "method is not supported",
            )),
        },
        (_, "deployments" | "replicasets" | "statefulsets", "scale") => match *method {
            Method::GET => {
                let Some(name) = &path.name else {
                    return Err(ApiserverError::BadRequest {
                        message: "scale requires a resource name".to_string(),
                    });
                };
                let current = read_single(client, &strip_subresource(path), name).await?;
                Ok(ok_json(scale_from(&current, path)))
            },
            Method::PUT | Method::PATCH => {
                let Some(name) = &path.name else {
                    return Err(ApiserverError::BadRequest {
                        message: "scale requires a resource name".to_string(),
                    });
                };
                let mut current = read_single(client, &strip_subresource(path), name).await?;
                let replicas = if method == Method::PUT {
                    let doc = decode_body(content_type, body, path)?;
                    scale_replicas(&doc)
                } else {
                    let mut scale = scale_from(&current, path);
                    apply_body_patch(&mut scale, content_type, body)?;
                    scale_replicas(&scale)
                };
                let Some(replicas) = replicas else {
                    return Err(ApiserverError::BadRequest {
                        message: "scale requires spec.replicas".to_string(),
                    });
                };
                if current.get("spec").is_none_or(|v| !v.is_object()) {
                    current["spec"] = json!({});
                }
                current["spec"]["replicas"] = json!(replicas);
                let updated = persist_object(client, path, name, current).await?;
                Ok(ok_json(scale_from(&updated, path)))
            },
            _ => Ok(status_outcome(
                http::StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "method is not supported",
            )),
        },
        ("", "pods", "log") => {
            if method != Method::GET {
                return Ok(status_outcome(
                    http::StatusCode::METHOD_NOT_ALLOWED,
                    "MethodNotAllowed",
                    "method is not supported",
                ));
            }
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
        (_, "pods", "exec" | "attach" | "portforward") => Err(ApiserverError::BadRequest {
            message: format!("{subresource} requires a websocket upgrade"),
        }),
        _ => Err(ApiserverError::NotFound {
            resource: format!("{}/{subresource}", path.resource),
            name: path.name.clone().unwrap_or_default(),
        }),
    }
}

fn strip_subresource(path: &ResourcePath) -> ResourcePath {
    ResourcePath {
        subresource: None,
        ..path.clone()
    }
}

fn apply_body_patch(
    target: &mut Value,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<(), ApiserverError> {
    match patch_type(content_type) {
        PatchType::Json => crate::admission::apply_json_patch(target, body),
        PatchType::Merge | PatchType::Apply => {
            let patch: Value =
                serde_json::from_slice(body).map_err(|err| ApiserverError::BadRequest {
                    message: format!("patch body is not JSON: {err}"),
                })?;
            crate::client::json_merge_patch(target, patch);
            Ok(())
        },
    }
}

async fn persist_object(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    name: &str,
    doc: Value,
) -> Result<Value, ApiserverError> {
    if is_namespaced(&path.resource) {
        let Some(namespace) = &path.namespace else {
            return Err(ApiserverError::BadRequest {
                message: format!("{} requires a namespace", path.resource),
            });
        };
        update_namespaced(client, &path.group, &path.resource, namespace, name, doc).await
    } else {
        update_cluster(client, &path.group, &path.resource, name, doc).await
    }
}

fn scale_replicas(doc: &Value) -> Option<i64> {
    doc.pointer("/spec/replicas")
        .and_then(Value::as_i64)
        .or_else(|| {
            doc.pointer("/spec/replicas")
                .and_then(Value::as_u64)
                .and_then(|v| i64::try_from(v).ok())
        })
}

/// Minimal `autoscaling/v1` Scale view backed by `spec.replicas` / `status.replicas`.
fn scale_from(current: &Value, path: &ResourcePath) -> Value {
    let replicas = current
        .pointer("/spec/replicas")
        .and_then(Value::as_i64)
        .unwrap_or(1);
    let status_replicas = current
        .pointer("/status/replicas")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let selector = current
        .pointer("/spec/selector/matchLabels")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let name = current
        .pointer("/metadata/name")
        .cloned()
        .unwrap_or(Value::Null);
    let namespace = current
        .pointer("/metadata/namespace")
        .cloned()
        .unwrap_or(Value::Null);
    let resource_version = current
        .pointer("/metadata/resourceVersion")
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "kind": "Scale",
        "apiVersion": "autoscaling/v1",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "resourceVersion": resource_version,
        },
        "spec": { "replicas": replicas },
        "status": {
            "replicas": status_replicas,
            "selector": selector,
        },
        "_target": {
            "group": path.group,
            "resource": path.resource,
        }
    })
}
