//! Map Kubernetes HTTP verbs onto `KubernetesApiClient`.

use http::Method;
use serde_json::{Value, json};

use crate::admission::{AdmissionRequest, GroupVersionKind, GroupVersionResource};
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
    pub(crate) headers: Vec<(http::header::HeaderName, http::header::HeaderValue)>,
}

async fn maybe_dispatch_aggregated(
    client: &KubernetesApiClient,
    method: &Method,
    path: &ResourcePath,
    query: Option<&str>,
    body: &[u8],
) -> Result<Option<Outcome>, ApiserverError> {
    if path.group.is_empty() {
        return Ok(None);
    }
    let api_services = client.aggregation().list_api_services();
    let Some(api_svc) = api_services
        .iter()
        .find(|s| s.group() == path.group && s.version() == path.version && !s.is_local())
        .or_else(|| {
            api_services
                .iter()
                .find(|s| s.group() == path.group && !s.is_local())
        })
    else {
        return Ok(None);
    };

    let mut uri_path = format!("/apis/{}/{}/{}", path.group, path.version, path.resource);
    if let Some(ns) = &path.namespace {
        uri_path = format!(
            "/apis/{}/{}/namespaces/{}/{}",
            path.group, path.version, ns, path.resource
        );
    }
    if let Some(n) = &path.name {
        uri_path = format!("{uri_path}/{n}");
    }
    if let Some(sub) = &path.subresource {
        uri_path = format!("{uri_path}/{sub}");
    }
    if let Some(q) = query.filter(|s| !s.is_empty()) {
        uri_path = format!("{uri_path}?{q}");
    }

    let parsed_body: Option<Value> = if body.is_empty() {
        None
    } else {
        serde_json::from_slice(body).ok()
    };

    let Ok(res) = client
        .dispatch_aggregated_request(api_svc.name(), &uri_path, method.as_str(), parsed_body)
        .await
    else {
        return Ok(None);
    };

    let outcome = if *method == Method::POST {
        created_json(res)
    } else {
        ok_json(res)
    };
    Ok(Some(outcome))
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
    if let Some(outcome) = maybe_dispatch_aggregated(client, method, path, query, body).await? {
        return Ok(outcome);
    }
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
        let doc = decode_body(content_type, query, body, path)?;
        return replace(client, path, query, doc).await.map(ok_json);
    }
    if method == Method::PATCH {
        return patch(client, path, content_type, query, body)
            .await
            .map(ok_json);
    }
    if method == Method::POST {
        let doc = decode_body(content_type, query, body, path)?;
        return create(client, path, query, doc).await.map(created_json);
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
    let is_crd = is_custom_resource(&path.resource);
    if is_cluster_resource(&path.resource) {
        if path.namespace.is_some() {
            Err(ApiserverError::NotFound {
                resource: path.resource.clone(),
                name: path.name.clone().unwrap_or_default(),
            })
        } else if let Some(name) = &path.name {
            let mut val = get_cluster(client, &path.group, &path.resource, name).await?;
            if is_crd {
                convert_custom_resource(&mut val, &path.group, &path.version);
            }
            if path.resource == "events" {
                normalize_event_for_group(&mut val, &path.group);
            }
            Ok(val)
        } else {
            let list = list_cluster(client, &path.group, &path.resource).await?;
            let mut list = if is_crd {
                convert_custom_resource_or_list(list, &path.group, &path.version)
            } else {
                list
            };
            if path.resource == "events" {
                normalize_event_list_for_group(&mut list, &path.group);
            }
            page_list(filter_list(list, query), query)
        }
    } else if let Some(namespace) = &path.namespace {
        if let Some(name) = &path.name {
            let mut val =
                get_namespaced(client, &path.group, &path.resource, namespace, name).await?;
            if is_crd {
                convert_custom_resource(&mut val, &path.group, &path.version);
            }
            if path.resource == "events" {
                normalize_event_for_group(&mut val, &path.group);
            }
            Ok(val)
        } else {
            let list = list_namespaced(client, &path.group, &path.resource, namespace).await?;
            let mut list = if is_crd {
                convert_custom_resource_or_list(list, &path.group, &path.version)
            } else {
                list
            };
            if path.resource == "events" {
                normalize_event_list_for_group(&mut list, &path.group);
            }
            page_list(filter_list(list, query), query)
        }
    } else if path.name.is_none() {
        let list = list_all_namespaces(client, &path.group, &path.resource).await?;
        let mut list = if is_crd {
            convert_custom_resource_or_list(list, &path.group, &path.version)
        } else {
            list
        };
        if path.resource == "events" {
            normalize_event_list_for_group(&mut list, &path.group);
        }
        page_list(filter_list(list, query), query)
    } else if is_builtin_namespaced(&path.resource) {
        Err(ApiserverError::BadRequest {
            message: format!("{} requires a namespace", path.resource),
        })
    } else if let Some(name) = &path.name {
        let mut val = get_cluster(client, &path.group, &path.resource, name).await?;
        if is_crd {
            convert_custom_resource(&mut val, &path.group, &path.version);
        }
        if path.resource == "events" {
            normalize_event_for_group(&mut val, &path.group);
        }
        Ok(val)
    } else {
        unreachable!()
    }
}

fn item_pagination_key(item: &Value) -> String {
    let name = item
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let namespace = item
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("");
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}/{name}")
    }
}

/// Pages a filtered list. `continue` is `c.<issued>.<rv>.<lastKey>` and stays
/// consistent for 30 seconds. After that the server returns 410 with an
/// inconsistent token so clients can resume without the original resourceVersion.
fn page_list(mut list: Value, query: Option<&str>) -> Result<Value, ApiserverError> {
    let params = query::parse(query);
    let limit = if let Some(limit_str) = params.get("limit") {
        match limit_str.parse::<usize>() {
            Ok(l) => Some(l),
            Err(_) => {
                return Err(ApiserverError::BadRequest {
                    message: "limit must be a non-negative integer".to_string(),
                });
            },
        }
    } else {
        None
    };
    let Some(limit) = limit else {
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
            let next_rv = rv
                .parse::<u64>()
                .map_or_else(|_| "1".to_string(), |n| (n + 1).to_string());
            let next = format!("i.{now}.{next_rv}.{name}");
            return Err(ApiserverError::Expired {
                continue_token: next,
            });
        }
        (name, Some(rv), mode == "i")
    };
    let Some(items) = list.get_mut("items").and_then(Value::as_array_mut) else {
        return Ok(list);
    };
    items.sort_by_key(item_pagination_key);
    let start = if start_after.is_empty() {
        0
    } else {
        items
            .iter()
            .position(|item| item_pagination_key(item) > start_after)
            .unwrap_or(items.len())
    };
    let end = (start + limit).min(items.len());
    let page = items[start..end].to_vec();
    let remaining = items.len().saturating_sub(end);
    let last_key = page.last().map(item_pagination_key).unwrap_or_default();
    *items = page;
    let current_rv = list
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && *s != "0")
        .unwrap_or("1")
        .to_string();
    let rv = response_rv.unwrap_or(current_rv);
    if let Some(meta) = list.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.insert("resourceVersion".to_string(), json!(rv));
        if remaining > 0 {
            let mode = if inconsistent { "i" } else { "c" };
            meta.insert(
                "continue".to_string(),
                json!(format!("{mode}.{now}.{rv}.{last_key}")),
            );
            meta.insert("remainingItemCount".to_string(), json!(remaining));
        } else {
            meta.remove("continue");
            meta.remove("remainingItemCount");
        }
    }
    Ok(list)
}

/// Applies `labelSelector` and `fieldSelector` to a list response.
fn filter_list(mut list: Value, query: Option<&str>) -> Value {
    let params = query::parse(query);
    let label_selector = params.get("labelSelector").cloned().unwrap_or_default();
    let field_selector = params.get("fieldSelector").cloned().unwrap_or_default();
    if label_selector.is_empty() && field_selector.is_empty() {
        return list;
    }
    let Some(items) = list.get_mut("items").and_then(Value::as_array_mut) else {
        return list;
    };
    items.retain(|item| {
        matches_label_selector(item, &label_selector)
            && matches_field_selector(item, &field_selector)
    });
    list
}

fn extract_crd_field_value<'a>(item: &'a Value, field: &str) -> Option<std::borrow::Cow<'a, str>> {
    match field {
        "hostPort" | "spec.hostPort" => {
            if let Some(val) = item
                .pointer("/spec/hostPort")
                .or_else(|| item.get("hostPort"))
                .and_then(Value::as_str)
            {
                Some(std::borrow::Cow::Borrowed(val))
            } else if let (Some(h), Some(p)) = (
                item.pointer("/spec/host")
                    .or_else(|| item.get("host"))
                    .and_then(Value::as_str),
                item.pointer("/spec/port").or_else(|| item.get("port")),
            ) {
                let p_str = p
                    .as_i64()
                    .map_or_else(|| p.as_str().unwrap_or("").to_string(), |n| n.to_string());
                if p_str.is_empty() {
                    None
                } else {
                    Some(std::borrow::Cow::Owned(format!("{h}:{p_str}")))
                }
            } else {
                None
            }
        },
        "host" | "spec.host" => {
            if let Some(val) = item
                .pointer("/spec/host")
                .or_else(|| item.get("host"))
                .and_then(Value::as_str)
            {
                Some(std::borrow::Cow::Borrowed(val))
            } else if let Some(hp) = item
                .pointer("/spec/hostPort")
                .or_else(|| item.get("hostPort"))
                .and_then(Value::as_str)
            {
                hp.split_once(':')
                    .map(|(h, _)| std::borrow::Cow::Borrowed(h))
            } else {
                None
            }
        },
        "port" | "spec.port" => {
            if let Some(p) = item.pointer("/spec/port").or_else(|| item.get("port")) {
                if let Some(n) = p.as_i64() {
                    Some(std::borrow::Cow::Owned(n.to_string()))
                } else if let Some(s) = p.as_str() {
                    Some(std::borrow::Cow::Borrowed(s))
                } else {
                    None
                }
            } else if let Some(hp) = item
                .pointer("/spec/hostPort")
                .or_else(|| item.get("hostPort"))
                .and_then(Value::as_str)
            {
                hp.split_once(':')
                    .map(|(_, p)| std::borrow::Cow::Borrowed(p))
            } else {
                None
            }
        },
        _ => None,
    }
}

fn extract_field_value<'a>(item: &'a Value, field: &str) -> Option<std::borrow::Cow<'a, str>> {
    match field {
        "metadata.name" => item
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .map(std::borrow::Cow::Borrowed),
        "metadata.namespace" => item
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .map(std::borrow::Cow::Borrowed),
        "status.phase" => item
            .pointer("/status/phase")
            .and_then(Value::as_str)
            .map(std::borrow::Cow::Borrowed),
        "spec.nodeName" => item
            .pointer("/spec/nodeName")
            .and_then(Value::as_str)
            .map(std::borrow::Cow::Borrowed),
        "involvedObject.name" => item
            .pointer("/involvedObject/name")
            .and_then(Value::as_str)
            .map(std::borrow::Cow::Borrowed),
        "involvedObject.kind" => item
            .pointer("/involvedObject/kind")
            .and_then(Value::as_str)
            .map(std::borrow::Cow::Borrowed),
        "involvedObject.namespace" => item
            .pointer("/involvedObject/namespace")
            .and_then(Value::as_str)
            .map(std::borrow::Cow::Borrowed),
        "involvedObject.uid" => item
            .pointer("/involvedObject/uid")
            .and_then(Value::as_str)
            .map(std::borrow::Cow::Borrowed),
        "type" => item
            .get("type")
            .and_then(Value::as_str)
            .map(std::borrow::Cow::Borrowed),
        "reason" => item
            .get("reason")
            .and_then(Value::as_str)
            .map(std::borrow::Cow::Borrowed),
        "spec.unschedulable" => Some(std::borrow::Cow::Borrowed(
            if item
                .pointer("/spec/unschedulable")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                "true"
            } else {
                "false"
            },
        )),
        "source" | "source.component" | "reportingController" | "reportingComponent" => item
            .pointer("/source/component")
            .and_then(Value::as_str)
            .or_else(|| item.pointer("/reportingComponent").and_then(Value::as_str))
            .or_else(|| item.pointer("/reportingController").and_then(Value::as_str))
            .or_else(|| {
                item.pointer("/deprecatedSource/component")
                    .and_then(Value::as_str)
            })
            .map(std::borrow::Cow::Borrowed),
        "hostPort" | "spec.hostPort" | "host" | "spec.host" | "port" | "spec.port" => {
            extract_crd_field_value(item, field)
        },
        _ => extract_nested_field(item, field),
    }
}

fn extract_nested_field<'a>(item: &'a Value, field: &str) -> Option<std::borrow::Cow<'a, str>> {
    let clean = field.trim_start_matches('.');
    let mut curr = Some(item);
    for part in clean.split('.') {
        if !part.is_empty() {
            curr = curr.and_then(|v| v.get(part));
        }
    }
    let val = curr.or_else(|| {
        if clean.starts_with("spec.") {
            None
        } else {
            let mut spec_curr = item.get("spec");
            for part in clean.split('.') {
                if !part.is_empty() {
                    spec_curr = spec_curr.and_then(|v| v.get(part));
                }
            }
            spec_curr
        }
    });
    match val {
        Some(Value::String(s)) => Some(std::borrow::Cow::Borrowed(s.as_str())),
        Some(Value::Bool(b)) => Some(std::borrow::Cow::Owned(b.to_string())),
        Some(Value::Number(n)) => Some(std::borrow::Cow::Owned(n.to_string())),
        _ => None,
    }
}

fn match_single_field(item: &Value, term: &str) -> bool {
    let term = term.trim();
    if term.is_empty() {
        return true;
    }
    if let Some((field, want)) = term.split_once("!=") {
        let actual = extract_field_value(item, field.trim());
        actual.as_deref().unwrap_or("") != want.trim()
    } else if let Some((field, want)) = term.split_once("==") {
        let actual = extract_field_value(item, field.trim());
        actual.as_deref().unwrap_or("") == want.trim()
    } else if let Some((field, want)) = term.split_once('=') {
        let actual = extract_field_value(item, field.trim());
        actual.as_deref().unwrap_or("") == want.trim()
    } else {
        true
    }
}

pub(crate) fn matches_field_selector(item: &Value, selector: &str) -> bool {
    let selector = selector.trim();
    if selector.is_empty() {
        return true;
    }
    split_selector_terms(selector)
        .iter()
        .all(|term| match_single_field(item, term))
}

pub(crate) fn matches_label_selector(item: &Value, selector: &str) -> bool {
    let selector = selector.trim();
    if selector.is_empty() {
        return true;
    }
    let labels = item.pointer("/metadata/labels").and_then(Value::as_object);
    let get_label = |k: &str| labels.and_then(|m| m.get(k)).and_then(Value::as_str);

    for req in split_selector_terms(selector) {
        let req = req.trim();
        if req.is_empty() {
            continue;
        }
        if let Some((key, rest)) = req.split_once(" notin ") {
            let key = key.trim();
            let vals = parse_set_values(rest);
            if let Some(actual) = get_label(key)
                && vals.contains(&actual)
            {
                return false;
            }
        } else if let Some((key, rest)) = req.split_once(" in ") {
            let key = key.trim();
            let vals = parse_set_values(rest);
            let Some(actual) = get_label(key) else {
                return false;
            };
            if !vals.contains(&actual) {
                return false;
            }
        } else if let Some((key, val)) = req.split_once("!=") {
            let key = key.trim();
            let val = val.trim();
            if get_label(key) == Some(val) {
                return false;
            }
        } else if let Some((key, val)) = req.split_once("==") {
            let key = key.trim();
            let val = val.trim();
            if get_label(key) != Some(val) {
                return false;
            }
        } else if let Some((key, val)) = req.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            if get_label(key) != Some(val) {
                return false;
            }
        } else if let Some(key) = req.strip_prefix('!') {
            let key = key.trim();
            if get_label(key).is_some() {
                return false;
            }
        } else if get_label(req).is_none() {
            return false;
        }
    }
    true
}

fn split_selector_terms(selector: &str) -> Vec<&str> {
    let mut terms = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (idx, ch) in selector.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                terms.push(&selector[start..idx]);
                start = idx + 1;
            },
            _ => {},
        }
    }
    terms.push(&selector[start..]);
    terms
}

fn parse_set_values(raw: &str) -> Vec<&str> {
    let trimmed = raw.trim().trim_start_matches('(').trim_end_matches(')');
    trimmed
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
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
    if is_cluster_resource(&path.resource) {
        if path.group.is_empty() && path.resource == "namespaces" {
            if let Some(doc) = client.delete_namespace_options(name).await? {
                return Ok(ok_json(doc));
            }
            return Ok(deleted);
        }
        delete_cluster(client, &path.group, &path.resource, name).await?;
    } else if let Some(namespace) = &path.namespace {
        if path.group.is_empty() && path.resource == "pods" {
            // Pods delete gracefully: the kubelet owns the final removal.
            let grace = grace_period_seconds(query, body);
            return Ok(client
                .delete_pod_options(namespace, name, grace)
                .await?
                .map_or(deleted, ok_json));
        }
        let policy = delete_propagation_policy(body, &path.group, &path.resource);
        if policy.as_deref() == Some("Orphan") {
            orphan_dependents(client, path, namespace, name).await?;
        } else if policy.as_deref() == Some("Foreground")
            && matches!(
                path.resource.as_str(),
                "deployments"
                    | "replicasets"
                    | "replicationcontrollers"
                    | "statefulsets"
                    | "daemonsets"
                    | "jobs"
            )
        {
            let mut current = read_single(client, path, name).await?;
            if let Some(meta) = current.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.entry("deletionTimestamp".to_string())
                    .or_insert_with(|| json!(crate::time::now_rfc3339()));
                let finalizers = meta
                    .entry("finalizers".to_string())
                    .or_insert_with(|| json!([]));
                if let Some(arr) = finalizers.as_array_mut()
                    && !arr.iter().any(|v| v.as_str() == Some("foregroundDeletion"))
                {
                    arr.push(json!("foregroundDeletion"));
                }
            }
            let updated = persist_object(client, path, name, current).await?;
            return Ok(ok_json(updated));
        } else if matches!(
            path.resource.as_str(),
            "deployments"
                | "replicasets"
                | "replicationcontrollers"
                | "statefulsets"
                | "daemonsets"
                | "jobs"
        ) {
            cascade_delete_dependents(client, path, namespace, name).await?;
        }
        delete_namespaced(client, &path.group, &path.resource, namespace, name).await?;
    } else if is_builtin_namespaced(&path.resource) {
        return Err(ApiserverError::BadRequest {
            message: format!("{} requires a namespace", path.resource),
        });
    } else {
        delete_cluster(client, &path.group, &path.resource, name).await?;
    }
    Ok(deleted)
}

fn delete_options_json(body: &[u8], group: &str, resource: &str) -> Option<Value> {
    if body.is_empty() {
        return None;
    }
    if let Ok(val) = serde_json::from_slice::<Value>(body) {
        return Some(val);
    }
    crate::http::protojson::decode_k8s_protobuf(body, "", "deleteoptions")
        .ok()
        .flatten()
        .or_else(|| {
            crate::http::protojson::decode_k8s_protobuf(body, group, resource)
                .ok()
                .flatten()
        })
}

fn delete_propagation_policy(body: &[u8], group: &str, resource: &str) -> Option<String> {
    let opts = delete_options_json(body, group, resource)?;
    if let Some(policy) = opts.get("propagationPolicy").and_then(Value::as_str)
        && !policy.is_empty()
    {
        return Some(policy.to_string());
    }
    if let Some(orphan) = opts.get("orphanDependents").and_then(Value::as_bool) {
        return Some(if orphan {
            "Orphan".to_string()
        } else {
            "Foreground".to_string()
        });
    }
    None
}

static ORPHANED_OWNERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::BTreeSet<(String, String, String)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::BTreeSet::new()));

async fn orphan_dependents(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    namespace: &str,
    name: &str,
) -> Result<(), ApiserverError> {
    let parent_kind = kind_name(&path.resource).unwrap_or_default();
    if let Ok(mut set) = ORPHANED_OWNERS.lock() {
        set.insert((
            namespace.to_string(),
            parent_kind.to_string(),
            name.to_string(),
        ));
    }
    let Ok(parent) = read_single(client, path, name).await else {
        return Ok(());
    };
    let parent_uid = parent
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let matches_owner = |oref: &Value| -> bool {
        let uid_match = !parent_uid.is_empty()
            && oref.get("uid").and_then(Value::as_str) == Some(parent_uid.as_str());
        let name_kind_match = oref.get("name").and_then(Value::as_str) == Some(name)
            && (parent_kind.is_empty()
                || oref.get("kind").and_then(Value::as_str) == Some(parent_kind));
        uid_match || name_kind_match
    };

    if path.resource == "deployments"
        && let Ok(rs_list) = client.list_replicasets(namespace).await
        && let Some(items) = rs_list.get("items").and_then(Value::as_array)
    {
        for mut rs in items.iter().cloned() {
            let Some(rs_name) = rs
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let mut changed = false;
            if let Some(orefs) = rs
                .pointer_mut("/metadata/ownerReferences")
                .and_then(Value::as_array_mut)
            {
                let before = orefs.len();
                orefs.retain(|r| !matches_owner(r));
                changed = orefs.len() != before;
            }
            if changed {
                let _ = client.update_replicaset(namespace, &rs_name, rs).await;
            }
        }
    }

    if let Ok(pod_list) = client.list_pods(namespace).await
        && let Some(items) = pod_list.get("items").and_then(Value::as_array)
    {
        for mut pod in items.iter().cloned() {
            let Some(pod_name) = pod
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let mut changed = false;
            if let Some(orefs) = pod
                .pointer_mut("/metadata/ownerReferences")
                .and_then(Value::as_array_mut)
            {
                let before = orefs.len();
                orefs.retain(|r| !matches_owner(r));
                changed = orefs.len() != before;
            }
            if changed {
                let _ = client.update_pod(namespace, &pod_name, pod).await;
            }
        }
    }

    Ok(())
}

fn resource_from_kind(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "Deployment" => "deployments",
        "ReplicaSet" => "replicasets",
        "StatefulSet" => "statefulsets",
        "DaemonSet" => "daemonsets",
        "Job" => "jobs",
        "CronJob" => "cronjobs",
        "ReplicationController" => "replicationcontrollers",
        "Pod" => "pods",
        _ => return None,
    })
}

fn group_for_kind(kind: &str, api_version: &str) -> &'static str {
    if let Some((g, _)) = api_version.split_once('/') {
        match g {
            "apps" => "apps",
            "batch" => "batch",
            _ => "",
        }
    } else {
        match kind {
            "Deployment" | "ReplicaSet" | "StatefulSet" | "DaemonSet" => "apps",
            "Job" | "CronJob" => "batch",
            _ => "",
        }
    }
}

async fn has_live_other_owner(
    client: &KubernetesApiClient,
    namespace: &str,
    orefs: &[Value],
    parent_uid: &str,
    parent_kind: &str,
    parent_name: &str,
) -> bool {
    for oref in orefs {
        let uid = oref.get("uid").and_then(Value::as_str).unwrap_or("");
        let kind = oref.get("kind").and_then(Value::as_str).unwrap_or("");
        let name = oref.get("name").and_then(Value::as_str).unwrap_or("");
        let is_current = (!parent_uid.is_empty() && uid == parent_uid)
            || (name == parent_name && (parent_kind.is_empty() || kind == parent_kind));
        if is_current {
            continue;
        }
        let Some(resource) = resource_from_kind(kind) else {
            return true;
        };
        let api_version = oref.get("apiVersion").and_then(Value::as_str).unwrap_or("");
        let group = group_for_kind(kind, api_version);
        if let Ok(owner_obj) = get_namespaced(client, group, resource, namespace, name).await
            && owner_obj.pointer("/metadata/deletionTimestamp").is_none()
        {
            return true;
        }
    }
    false
}

async fn cascade_delete_pod_dependents(
    client: &KubernetesApiClient,
    namespace: &str,
    parent_uid: &str,
    parent_kind: &str,
    parent_name: &str,
) {
    let Ok(pod_list) = client.list_pods(namespace).await else {
        return;
    };
    let Some(items) = pod_list.get("items").and_then(Value::as_array) else {
        return;
    };
    for mut pod in items.iter().cloned() {
        let Some(pod_name) = pod
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            continue;
        };
        let orefs = pod
            .pointer("/metadata/ownerReferences")
            .and_then(Value::as_array);
        let matches = orefs.is_some_and(|arr| {
            arr.iter().any(|r| {
                let uid_match = !parent_uid.is_empty()
                    && r.get("uid").and_then(Value::as_str) == Some(parent_uid);
                let name_kind_match = r.get("name").and_then(Value::as_str) == Some(parent_name)
                    && (parent_kind.is_empty()
                        || r.get("kind").and_then(Value::as_str) == Some(parent_kind));
                uid_match || name_kind_match
            })
        });
        if !matches {
            continue;
        }
        let arr = orefs.cloned().unwrap_or_default();
        if has_live_other_owner(
            client,
            namespace,
            &arr,
            parent_uid,
            parent_kind,
            parent_name,
        )
        .await
        {
            if let Some(orefs_mut) = pod
                .pointer_mut("/metadata/ownerReferences")
                .and_then(Value::as_array_mut)
            {
                orefs_mut.retain(|r| {
                    let uid_match = !parent_uid.is_empty()
                        && r.get("uid").and_then(Value::as_str) == Some(parent_uid);
                    let name_kind_match = r.get("name").and_then(Value::as_str)
                        == Some(parent_name)
                        && (parent_kind.is_empty()
                            || r.get("kind").and_then(Value::as_str) == Some(parent_kind));
                    !(uid_match || name_kind_match)
                });
                let _ = client.update_pod(namespace, &pod_name, pod).await;
            }
        } else {
            let _ = client.delete_pod_options(namespace, &pod_name, None).await;
        }
    }
}

async fn cascade_delete_replicaset_dependents(
    client: &KubernetesApiClient,
    namespace: &str,
    parent_uid: &str,
    parent_kind: &str,
    parent_name: &str,
) {
    let Ok(rs_list) = client.list_replicasets(namespace).await else {
        return;
    };
    let Some(items) = rs_list.get("items").and_then(Value::as_array) else {
        return;
    };
    for mut rs in items.iter().cloned() {
        let Some(rs_name) = rs
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            continue;
        };
        let orefs = rs
            .pointer("/metadata/ownerReferences")
            .and_then(Value::as_array);
        let matches = orefs.is_some_and(|arr| {
            arr.iter().any(|r| {
                let uid_match = !parent_uid.is_empty()
                    && r.get("uid").and_then(Value::as_str) == Some(parent_uid);
                let name_kind_match = r.get("name").and_then(Value::as_str) == Some(parent_name)
                    && (parent_kind.is_empty()
                        || r.get("kind").and_then(Value::as_str) == Some(parent_kind));
                uid_match || name_kind_match
            })
        });
        if !matches {
            continue;
        }
        let arr = orefs.cloned().unwrap_or_default();
        if has_live_other_owner(
            client,
            namespace,
            &arr,
            parent_uid,
            parent_kind,
            parent_name,
        )
        .await
        {
            if let Some(orefs_mut) = rs
                .pointer_mut("/metadata/ownerReferences")
                .and_then(Value::as_array_mut)
            {
                orefs_mut.retain(|r| {
                    let uid_match = !parent_uid.is_empty()
                        && r.get("uid").and_then(Value::as_str) == Some(parent_uid);
                    let name_kind_match = r.get("name").and_then(Value::as_str)
                        == Some(parent_name)
                        && (parent_kind.is_empty()
                            || r.get("kind").and_then(Value::as_str) == Some(parent_kind));
                    !(uid_match || name_kind_match)
                });
                let _ = client.update_replicaset(namespace, &rs_name, rs).await;
            }
        } else {
            let rs_uid = rs
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .unwrap_or("");
            cascade_delete_pod_dependents(client, namespace, rs_uid, "ReplicaSet", &rs_name).await;
            let _ = client.delete_replicaset(namespace, &rs_name).await;
        }
    }
}

async fn cascade_delete_dependents(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    namespace: &str,
    name: &str,
) -> Result<(), ApiserverError> {
    let Ok(parent) = read_single(client, path, name).await else {
        return Ok(());
    };
    let parent_uid = parent
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let parent_kind = kind_name(&path.resource).unwrap_or_default();

    if path.resource == "deployments" {
        cascade_delete_replicaset_dependents(client, namespace, parent_uid, parent_kind, name)
            .await;
    }
    cascade_delete_pod_dependents(client, namespace, parent_uid, parent_kind, name).await;
    Ok(())
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
        let namespace = item
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .or(path.namespace.as_deref());
        let deleted = if is_cluster_resource(&path.resource) {
            delete_cluster(client, &path.group, &path.resource, name).await
        } else if let Some(namespace) = namespace {
            if path.group.is_empty() && path.resource == "pods" {
                // Best effort; the kubelet owns graceful pod removal.
                client
                    .delete_pod_options(namespace, name, None)
                    .await
                    .map(|_| ())
            } else {
                delete_namespaced(client, &path.group, &path.resource, namespace, name).await
            }
        } else if is_builtin_namespaced(&path.resource) {
            continue;
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
    mut doc: Value,
) -> Result<Value, ApiserverError> {
    let Some(name) = &path.name else {
        return Err(ApiserverError::BadRequest {
            message: "replace requires a resource name".to_string(),
        });
    };
    client.validate_crd_schema(&path.group, &path.resource, &doc)?;
    if path.resource == "events" {
        normalize_event_for_group(&mut doc, &path.group);
    }
    let is_crd = is_custom_resource(&path.resource);
    if is_dry_run(query) {
        // Validate the object exists, then echo the replacement without storing.
        let _ = read_single(client, path, name).await?;
        let mut stamped = stamp_replacement(doc, path, name);
        if is_crd {
            convert_custom_resource(&mut stamped, &path.group, &path.version);
        }
        if path.resource == "events" {
            normalize_event_for_group(&mut stamped, &path.group);
        }
        return Ok(stamped);
    }
    let mut result = persist_object(client, path, name, doc).await?;
    if is_crd {
        convert_custom_resource(&mut result, &path.group, &path.version);
    }
    if path.resource == "events" {
        normalize_event_for_group(&mut result, &path.group);
    }
    Ok(result)
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
    if is_cluster_resource(&path.resource) {
        get_cluster(client, &path.group, &path.resource, name).await
    } else if let Some(namespace) = &path.namespace {
        get_namespaced(client, &path.group, &path.resource, namespace, name).await
    } else if is_builtin_namespaced(&path.resource) {
        Err(ApiserverError::BadRequest {
            message: format!("{} requires a namespace", path.resource),
        })
    } else {
        get_cluster(client, &path.group, &path.resource, name).await
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PatchType {
    Json,
    RfcMerge,
    StrategicMerge,
    Apply,
}

fn patch_type(content_type: Option<&str>) -> PatchType {
    let content = content_type.unwrap_or_default().to_ascii_lowercase();
    if content.contains("json-patch") {
        PatchType::Json
    } else if content.contains("apply-patch") {
        PatchType::Apply
    } else if content.contains("strategic-merge-patch") {
        PatchType::StrategicMerge
    } else if content.contains("merge-patch") {
        PatchType::RfcMerge
    } else {
        PatchType::StrategicMerge
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
    let is_crd = is_custom_resource(&path.resource);
    if kind == PatchType::Apply {
        let mut result = apply_patch(client, path, query, name, body, existing).await?;
        if is_crd {
            convert_custom_resource(&mut result, &path.group, &path.version);
        }
        return Ok(result);
    }
    let mut target = match existing {
        Ok(doc) => doc,
        Err(err) => return Err(err),
    };
    match kind {
        PatchType::Json => {
            crate::admission::apply_json_patch(&mut target, body)?;
        },
        PatchType::RfcMerge => {
            let merge: Value =
                serde_json::from_slice(body).map_err(|err| ApiserverError::BadRequest {
                    message: format!("patch body is not JSON: {err}"),
                })?;
            crate::client::json_rfc7396_merge_patch(&mut target, merge);
        },
        PatchType::StrategicMerge => {
            let merge: Value =
                serde_json::from_slice(body).map_err(|err| ApiserverError::BadRequest {
                    message: format!("patch body is not JSON: {err}"),
                })?;
            crate::client::json_merge_patch(&mut target, merge);
        },
        PatchType::Apply => unreachable!("handled above"),
    }
    client.validate_crd_schema(&path.group, &path.resource, &target)?;
    if is_dry_run(query) {
        if is_crd {
            convert_custom_resource(&mut target, &path.group, &path.version);
        }
        return Ok(target);
    }
    let mut result = persist_object(client, path, name, target).await?;
    if is_crd {
        convert_custom_resource(&mut result, &path.group, &path.version);
    }
    if path.resource == "events" {
        normalize_event_for_group(&mut result, &path.group);
    }
    Ok(result)
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
    let is_strict = crate::http::field_validation::is_strict(query);
    let mut applied: Value = crate::http::field_validation::decode_body_with_validation(
        body,
        Some("application/apply-patch+yaml"),
        is_strict,
        path,
    )?;
    if is_strict {
        client.validate_crd_schema(&path.group, &path.resource, &applied)?;
    }
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
            if is_cluster_resource(&path.resource) {
                create_cluster(client, &path.group, &path.resource, applied).await
            } else if let Some(namespace) = &path.namespace {
                create_namespaced(client, &path.group, &path.resource, namespace, applied).await
            } else if is_builtin_namespaced(&path.resource) {
                Err(ApiserverError::BadRequest {
                    message: format!("{} requires a namespace", path.resource),
                })
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
            let mut result = persist_object(client, path, name, current).await?;
            if path.resource == "events" {
                normalize_event_for_group(&mut result, &path.group);
            }
            Ok(result)
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
    delete_options_json(body, "", "pods")?
        .get("gracePeriodSeconds")?
        .as_i64()
}

async fn create(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    query: Option<&str>,
    mut doc: Value,
) -> Result<Value, ApiserverError> {
    if path.name.is_some() {
        return Err(ApiserverError::BadRequest {
            message: "create does not take a resource name in the path".to_string(),
        });
    }
    if path.resource == "pods"
        && let Some(namespace) = &path.namespace
        && let Ok(set) = ORPHANED_OWNERS.lock()
        && let Some(orefs) = doc
            .pointer_mut("/metadata/ownerReferences")
            .and_then(Value::as_array_mut)
    {
        orefs.retain(|oref| {
            let kind = oref.get("kind").and_then(Value::as_str).unwrap_or("");
            let name = oref.get("name").and_then(Value::as_str).unwrap_or("");
            !set.contains(&(namespace.clone(), kind.to_string(), name.to_string()))
        });
    }
    if path.resource == "events" {
        normalize_event_for_group(&mut doc, &path.group);
    }
    let is_crd = is_custom_resource(&path.resource);
    if is_dry_run(query) {
        let mut result = dry_run_create(client, path, doc).await?;
        if is_crd {
            convert_custom_resource(&mut result, &path.group, &path.version);
        }
        if path.resource == "events" {
            normalize_event_for_group(&mut result, &path.group);
        }
        return Ok(result);
    }
    stamp_type_meta(&mut doc, path);
    let mut result = if is_cluster_resource(&path.resource) {
        create_cluster(client, &path.group, &path.resource, doc).await?
    } else if let Some(namespace) = &path.namespace {
        create_namespaced(client, &path.group, &path.resource, namespace, doc).await?
    } else if is_builtin_namespaced(&path.resource) {
        return Err(ApiserverError::BadRequest {
            message: format!("{} requires a namespace", path.resource),
        });
    } else {
        create_cluster(client, &path.group, &path.resource, doc).await?
    };
    if is_crd {
        convert_custom_resource(&mut result, &path.group, &path.version);
    }
    if path.resource == "events" {
        normalize_event_for_group(&mut result, &path.group);
    }
    Ok(result)
}

async fn dry_run_create(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    mut doc: Value,
) -> Result<Value, ApiserverError> {
    if !is_cluster_resource(&path.resource)
        && path.namespace.is_none()
        && is_builtin_namespaced(&path.resource)
    {
        return Err(ApiserverError::BadRequest {
            message: format!("{} requires a namespace", path.resource),
        });
    }
    stamp_type_meta(&mut doc, path);
    if path.group.is_empty()
        && path.resource == "pods"
        && let Some(namespace) = &path.namespace
    {
        enforce_quota(client, &path.group, &path.resource, namespace, &doc).await?;
        let mut pod = client.create_pod_options(namespace, doc, true).await?;
        if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.entry("resourceVersion".to_string())
                .or_insert_with(|| json!("1"));
        }
        return Ok(pod);
    }
    client.validate_crd_schema(&path.group, &path.resource, &doc)?;
    if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
        if let Some(namespace) = &path.namespace {
            meta.insert("namespace".to_string(), json!(namespace));
        }
        meta.entry("uid".to_string())
            .or_insert_with(|| json!("dry-run-uid"));
        meta.entry("creationTimestamp".to_string())
            .or_insert_with(|| json!(crate::time::now_rfc3339()));
        meta.entry("resourceVersion".to_string())
            .or_insert_with(|| json!("1"));
    }
    if is_custom_resource(&path.resource) {
        convert_custom_resource(&mut doc, &path.group, &path.version);
    }
    if path.resource == "events" {
        normalize_event_for_group(&mut doc, &path.group);
    }
    Ok(doc)
}

pub(crate) fn is_cluster_resource(resource: &str) -> bool {
    matches!(
        resource,
        "namespaces"
            | "nodes"
            | "persistentvolumes"
            | "storageclasses"
            | "csinodes"
            | "csidrivers"
            | "volumeattachments"
            | "volumeattributesclasses"
            | "clusterroles"
            | "clusterrolebindings"
            | "customresourcedefinitions"
            | "validatingwebhookconfigurations"
            | "mutatingwebhookconfigurations"
            | "validatingadmissionpolicies"
            | "validatingadmissionpolicybindings"
            | "mutatingadmissionpolicies"
            | "mutatingadmissionpolicybindings"
            | "apiservices"
            | "clustertrustbundles"
            | "certificatesigningrequests"
            | "ingressclasses"
            | "runtimeclasses"
            | "priorityclasses"
            | "flowschemas"
            | "prioritylevelconfigurations"
            | "ipaddresses"
            | "servicecidrs"
            | "selfsubjectreviews"
            | "tokenreviews"
            | "subjectaccessreviews"
            | "selfsubjectaccessreviews"
            | "selfsubjectrulesreviews"
            | "deviceclasses"
            | "devicetaintrules"
            | "resourceslices"
            | "storageversionmigrations"
    )
}

fn is_builtin_namespaced(resource: &str) -> bool {
    kind_name(resource).is_some() && !is_cluster_resource(resource)
}

pub(crate) fn is_custom_resource(resource: &str) -> bool {
    kind_name(resource).is_none()
}

fn convert_crd_spec_host_port(spec: &mut serde_json::Map<String, Value>, version: &str) {
    if version == "v2" {
        if let Some((h, p)) = spec
            .get("hostPort")
            .and_then(Value::as_str)
            .and_then(|hp| hp.split_once(':'))
            .map(|(h, p)| (h.to_string(), p.to_string()))
        {
            spec.insert("host".to_string(), json!(h));
            spec.insert("port".to_string(), json!(p));
            spec.remove("hostPort");
        }
    } else if version == "v1" {
        let (Some(h), Some(p)) = (spec.get("host").and_then(Value::as_str), spec.get("port"))
        else {
            return;
        };
        let p_str = p
            .as_i64()
            .map_or_else(|| p.as_str().unwrap_or("").to_string(), |n| n.to_string());
        if !p_str.is_empty() {
            spec.insert("hostPort".to_string(), json!(format!("{h}:{p_str}")));
            spec.remove("host");
            spec.remove("port");
        }
    }
}

pub(crate) fn convert_custom_resource(doc: &mut Value, group: &str, version: &str) {
    if group.is_empty() {
        return;
    }
    let target_api_version = format!("{group}/{version}");
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("apiVersion".to_string(), json!(target_api_version));
        convert_crd_spec_host_port(obj, version);
    }
    if let Some(spec) = doc.get_mut("spec").and_then(Value::as_object_mut) {
        convert_crd_spec_host_port(spec, version);
    }
}

pub(crate) fn convert_custom_resource_or_list(mut doc: Value, group: &str, version: &str) -> Value {
    if group.is_empty() {
        return doc;
    }
    if let Some(items) = doc.get_mut("items").and_then(Value::as_array_mut) {
        for item in items {
            convert_custom_resource(item, group, version);
        }
        if let Some(obj) = doc.as_object_mut() {
            obj.insert(
                "apiVersion".to_string(),
                json!(format!("{group}/{version}")),
            );
        }
    } else {
        convert_custom_resource(&mut doc, group, version);
    }
    doc
}

fn normalize_event_controller(obj: &mut serde_json::Map<String, Value>) {
    let source_comp = obj
        .get("source")
        .and_then(|v| v.get("component"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let dep_comp = obj
        .get("deprecatedSource")
        .and_then(|v| v.get("component"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let rep_controller = obj
        .get("reportingController")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or(source_comp)
        .or(dep_comp);

    if let Some(ref controller) = rep_controller {
        if !obj.contains_key("reportingController") {
            obj.insert("reportingController".to_string(), json!(controller));
        }
        if obj.get("source").is_none() {
            obj.insert("source".to_string(), json!({ "component": controller }));
        } else if let Some(src) = obj.get_mut("source").and_then(Value::as_object_mut)
            && !src.contains_key("component")
        {
            src.insert("component".to_string(), json!(controller));
        }
        if obj.get("deprecatedSource").is_none() {
            obj.insert(
                "deprecatedSource".to_string(),
                json!({ "component": controller }),
            );
        } else if let Some(dep_src) = obj
            .get_mut("deprecatedSource")
            .and_then(Value::as_object_mut)
            && !dep_src.contains_key("component")
        {
            dep_src.insert("component".to_string(), json!(controller));
        }
    }
}

fn normalize_event_instance(obj: &mut serde_json::Map<String, Value>) {
    let source_host = obj
        .get("source")
        .and_then(|v| v.get("host"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let dep_host = obj
        .get("deprecatedSource")
        .and_then(|v| v.get("host"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let rep_instance = obj
        .get("reportingInstance")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or(source_host)
        .or(dep_host);

    if let Some(ref instance) = rep_instance {
        if !obj.contains_key("reportingInstance") {
            obj.insert("reportingInstance".to_string(), json!(instance));
        }
        if let Some(src) = obj.get_mut("source").and_then(Value::as_object_mut)
            && !src.contains_key("host")
        {
            src.insert("host".to_string(), json!(instance));
        }
        if let Some(dep_src) = obj
            .get_mut("deprecatedSource")
            .and_then(Value::as_object_mut)
            && !dep_src.contains_key("host")
        {
            dep_src.insert("host".to_string(), json!(instance));
        }
    }
}

pub(crate) fn normalize_event_for_group(doc: &mut Value, group: &str) {
    let Some(obj) = doc.as_object_mut() else {
        return;
    };
    let api_version = if group == "events.k8s.io" {
        "events.k8s.io/v1"
    } else {
        "v1"
    };
    obj.insert("apiVersion".to_string(), json!(api_version));

    normalize_event_controller(obj);
    normalize_event_instance(obj);

    let note = obj
        .get("note")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            obj.get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    if let Some(ref msg) = note {
        if !obj.contains_key("note") {
            obj.insert("note".to_string(), json!(msg));
        }
        if !obj.contains_key("message") {
            obj.insert("message".to_string(), json!(msg));
        }
    }

    let regarding = obj
        .get("regarding")
        .cloned()
        .or_else(|| obj.get("involvedObject").cloned());
    if let Some(reg) = regarding {
        if !obj.contains_key("regarding") {
            obj.insert("regarding".to_string(), reg.clone());
        }
        if !obj.contains_key("involvedObject") {
            obj.insert("involvedObject".to_string(), reg);
        }
    }
}

pub(crate) fn normalize_event_list_for_group(doc: &mut Value, group: &str) {
    let api_version = if group == "events.k8s.io" {
        "events.k8s.io/v1"
    } else {
        "v1"
    };
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("apiVersion".to_string(), json!(api_version));
        obj.insert("kind".to_string(), json!("EventList"));
    }
    if let Some(items) = doc.get_mut("items").and_then(Value::as_array_mut) {
        for item in items {
            normalize_event_for_group(item, group);
        }
    }
}

async fn list_all_namespaces(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
) -> Result<Value, ApiserverError> {
    // A cluster-wide list is authorized for the requested resource. Enumerating
    // Namespace objects here incorrectly required an unrelated RBAC permission.
    let storage_group = if resource == "events" { "" } else { group };
    client
        .list_namespaced_objects(storage_group, list_kind(resource), resource, "")
        .await
}

async fn list_namespaced(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    namespace: &str,
) -> Result<Value, ApiserverError> {
    match (group, resource) {
        ("", "pods") => client.list_pods(namespace).await,
        ("", "replicationcontrollers") => client.list_replicationcontrollers(namespace).await,
        ("", "configmaps") => client.list_configmaps(namespace).await,
        ("", "secrets") => client.list_secrets(namespace).await,
        ("", "services") => client.list_services(namespace).await,
        ("", "endpoints") => client.list_endpoints(namespace).await,
        ("", "serviceaccounts") => client.list_service_accounts(namespace).await,
        ("", "persistentvolumeclaims") => client.list_pvcs(namespace).await,
        ("" | "events.k8s.io", "events") => {
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
        ("", "replicationcontrollers") => client.get_replicationcontroller(namespace, name).await,
        ("", "configmaps") => client.get_configmap(namespace, name).await,
        ("", "secrets") => client.get_secret(namespace, name).await,
        ("", "services") => client.get_service(namespace, name).await,
        ("", "endpoints") => client.get_endpoints(namespace, name).await,
        ("", "serviceaccounts") => client.get_service_account(namespace, name).await,
        ("", "persistentvolumeclaims") => client.get_pvc(namespace, name).await,
        ("" | "events.k8s.io", "events") => {
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
        ("", "replicationcontrollers") => {
            client.delete_replicationcontroller(namespace, name).await
        },
        ("", "configmaps") => client.delete_configmap(namespace, name, None).await,
        ("", "secrets") => client.delete_secret(namespace, name, None).await,
        ("", "services") => client.delete_service(namespace, name).await,
        ("", "endpoints") => client.delete_endpoints(namespace, name).await,
        ("", "serviceaccounts") => client.delete_service_account(namespace, name).await,
        ("", "persistentvolumeclaims") => client.delete_pvc(namespace, name).await,
        ("" | "events.k8s.io", "events") => {
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

/// Rejects a create that would exceed a `ResourceQuota` hard limit.
async fn enforce_quota(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    namespace: &str,
    doc: &Value,
) -> Result<(), ApiserverError> {
    let counted = crate::quota::COUNTED_RESOURCES
        .iter()
        .any(|(g, _, p)| *g == group && *p == resource);
    if !counted {
        return Ok(());
    }
    let quotas =
        crate::quota::list_counted(client, "", "ResourceQuotaList", "resourcequotas", namespace)
            .await;
    for quota in &quotas {
        if !crate::quota::quota_tracks(quota, group, resource)
            || !crate::quota::object_in_scope(quota, group, resource, doc)
        {
            continue;
        }
        let delta = crate::quota::usage_for(group, resource, doc);
        let totals = crate::quota::compute_totals(client, quota, namespace).await;
        if let Some(reason) = crate::quota::exceeded(quota, &totals, &delta) {
            return Err(ApiserverError::AdmissionDenied { reason });
        }
    }
    Ok(())
}

async fn create_namespaced(
    client: &KubernetesApiClient,
    group: &str,
    resource: &str,
    namespace: &str,
    doc: Value,
) -> Result<Value, ApiserverError> {
    enforce_quota(client, group, resource, namespace, &doc).await?;
    match (group, resource) {
        ("", "pods") => client.create_pod(namespace, doc).await,
        ("", "replicationcontrollers") => client.create_replicationcontroller(namespace, doc).await,
        ("", "configmaps") => client.create_configmap_object(namespace, doc).await,
        ("", "secrets") => client.create_secret_object(namespace, doc).await,
        ("", "services") => client.create_service(namespace, doc).await,
        ("", "endpoints") => client.create_endpoints(namespace, doc).await,
        ("", "serviceaccounts") => client.create_service_account(namespace, doc).await,
        ("", "persistentvolumeclaims") => client.create_pvc(namespace, doc).await,
        ("" | "events.k8s.io", "events") => {
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
        ("authorization.k8s.io", "localsubjectaccessreviews") => Ok(handle_subject_access_review(
            doc,
            "LocalSubjectAccessReview",
        )),
        _ => {
            let kind = kind_name(resource)
                .map(str::to_owned)
                .or_else(|| doc.get("kind").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| "Object".to_string());
            client
                .create_namespaced_object(group, &kind, resource, namespace, doc)
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
        ("", "replicationcontrollers") => {
            client
                .update_replicationcontroller(namespace, name, doc)
                .await
        },
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
        ("" | "events.k8s.io", "events") => {
            client
                .replace_namespaced_object("", "Event", "events", namespace, name, doc)
                .await
        },
        _ => {
            let kind = kind_name(resource)
                .map(str::to_owned)
                .or_else(|| doc.get("kind").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| "Object".to_string());
            client
                .replace_namespaced_object(group, &kind, resource, namespace, name, doc)
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
        ("", "namespaces") => client.create_namespace_object(doc).await,
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
        ("authentication.k8s.io", "tokenreviews") => client.create_token_review(doc).await,
        ("authentication.k8s.io", "selfsubjectreviews") => {
            client.create_self_subject_review(doc).await
        },
        ("authorization.k8s.io", "subjectaccessreviews") => {
            Ok(handle_subject_access_review(doc, "SubjectAccessReview"))
        },
        ("authorization.k8s.io", "selfsubjectaccessreviews") => {
            Ok(handle_subject_access_review(doc, "SelfSubjectAccessReview"))
        },
        ("authorization.k8s.io", "selfsubjectrulesreviews") => {
            Ok(handle_self_subject_rules_review(doc))
        },
        _ => {
            let kind = kind_name(resource)
                .map(str::to_owned)
                .or_else(|| doc.get("kind").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| "Object".to_string());
            client
                .create_cluster_object(group, &kind, resource, doc)
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
        ("", "namespaces") => client.update_namespace(name, doc).await,
        ("", "nodes") => client.update_node(name, doc).await,
        ("", "persistentvolumes") => client.update_pv(name, doc).await,
        ("storage.k8s.io" | "", "storageclasses") => client.update_storage_class(name, doc).await,
        ("apiextensions.k8s.io", "customresourcedefinitions") => client.update_crd(name, doc).await,
        ("admissionregistration.k8s.io", "validatingwebhookconfigurations") => {
            client
                .update_validating_webhook_configuration(name, doc)
                .await
        },
        ("admissionregistration.k8s.io", "mutatingwebhookconfigurations") => {
            client
                .update_mutating_webhook_configuration(name, doc)
                .await
        },
        ("apiregistration.k8s.io", "apiservices") => client.update_api_service(name, doc).await,
        _ => {
            let kind = kind_name(resource)
                .map(str::to_owned)
                .or_else(|| doc.get("kind").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| "Object".to_string());
            client
                .replace_cluster_object(group, &kind, resource, name, doc)
                .await
        },
    }
}

fn decode_body(
    content_type: Option<&str>,
    query: Option<&str>,
    body: &[u8],
    path: &ResourcePath,
) -> Result<Value, ApiserverError> {
    if body.is_empty() {
        return Ok(Value::Null);
    }
    if content_type.is_some_and(|value| value.contains("protobuf")) {
        let mut value =
            crate::http::protojson::decode_k8s_protobuf(body, &path.group, &path.resource)?
                .ok_or_else(|| ApiserverError::BadRequest {
                    message: format!("unsupported kubernetes protobuf resource {}", path.resource),
                })?;
        stamp_type_meta(&mut value, path);
        return Ok(value);
    }
    let is_strict = crate::http::field_validation::is_strict(query);
    crate::http::field_validation::decode_body_with_validation(body, content_type, is_strict, path)
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
        "controllerrevisions" => "ControllerRevision",
        "jobs" => "Job",
        "cronjobs" => "CronJob",
        "leases" => "Lease",
        "events" => "Event",
        "roles" => "Role",
        "rolebindings" => "RoleBinding",
        "clusterroles" => "ClusterRole",
        "clusterrolebindings" => "ClusterRoleBinding",
        "storageclasses" => "StorageClass",
        "csinodes" => "CSINode",
        "csidrivers" => "CSIDriver",
        "csistoragecapacities" => "CSIStorageCapacity",
        "volumeattachments" => "VolumeAttachment",
        "volumeattributesclasses" => "VolumeAttributesClass",
        "customresourcedefinitions" => "CustomResourceDefinition",
        "validatingwebhookconfigurations" => "ValidatingWebhookConfiguration",
        "mutatingwebhookconfigurations" => "MutatingWebhookConfiguration",
        "validatingadmissionpolicies" => "ValidatingAdmissionPolicy",
        "validatingadmissionpolicybindings" => "ValidatingAdmissionPolicyBinding",
        "mutatingadmissionpolicies" => "MutatingAdmissionPolicy",
        "mutatingadmissionpolicybindings" => "MutatingAdmissionPolicyBinding",
        "apiservices" => "APIService",
        "clustertrustbundles" => "ClusterTrustBundle",
        "certificatesigningrequests" => "CertificateSigningRequest",
        "horizontalpodautoscalers" => "HorizontalPodAutoscaler",
        "poddisruptionbudgets" => "PodDisruptionBudget",
        "networkpolicies" => "NetworkPolicy",
        "ingresses" => "Ingress",
        "ingressclasses" => "IngressClass",
        "ipaddresses" => "IPAddress",
        "servicecidrs" => "ServiceCIDR",
        "runtimeclasses" => "RuntimeClass",
        "priorityclasses" => "PriorityClass",
        "flowschemas" => "FlowSchema",
        "prioritylevelconfigurations" => "PriorityLevelConfiguration",
        "tokenreviews" => "TokenReview",
        "selfsubjectreviews" => "SelfSubjectReview",
        "subjectaccessreviews" => "SubjectAccessReview",
        "selfsubjectaccessreviews" => "SelfSubjectAccessReview",
        "localsubjectaccessreviews" => "LocalSubjectAccessReview",
        "selfsubjectrulesreviews" => "SelfSubjectRulesReview",
        "podcertificaterequests" => "PodCertificateRequest",
        "deviceclasses" => "DeviceClass",
        "devicetaintrules" => "DeviceTaintRule",
        "resourceslices" => "ResourceSlice",
        "resourceclaims" => "ResourceClaim",
        "resourceclaimtemplates" => "ResourceClaimTemplate",
        "storageversionmigrations" => "StorageVersionMigration",
        "deleteoptions" => "DeleteOptions",
        _ => return None,
    })
}

fn list_kind(resource: &str) -> &'static str {
    match resource {
        "namespaces" => "NamespaceList",
        "nodes" => "NodeList",
        "persistentvolumes" => "PersistentVolumeList",
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
        "controllerrevisions" => "ControllerRevisionList",
        "jobs" => "JobList",
        "cronjobs" => "CronJobList",
        "leases" => "LeaseList",
        "events" => "EventList",
        "roles" => "RoleList",
        "rolebindings" => "RoleBindingList",
        "clusterroles" => "ClusterRoleList",
        "clusterrolebindings" => "ClusterRoleBindingList",
        "storageclasses" => "StorageClassList",
        "csinodes" => "CSINodeList",
        "csidrivers" => "CSIDriverList",
        "csistoragecapacities" => "CSIStorageCapacityList",
        "volumeattachments" => "VolumeAttachmentList",
        "volumeattributesclasses" => "VolumeAttributesClassList",
        "customresourcedefinitions" => "CustomResourceDefinitionList",
        "validatingwebhookconfigurations" => "ValidatingWebhookConfigurationList",
        "mutatingwebhookconfigurations" => "MutatingWebhookConfigurationList",
        "validatingadmissionpolicies" => "ValidatingAdmissionPolicyList",
        "validatingadmissionpolicybindings" => "ValidatingAdmissionPolicyBindingList",
        "mutatingadmissionpolicies" => "MutatingAdmissionPolicyList",
        "mutatingadmissionpolicybindings" => "MutatingAdmissionPolicyBindingList",
        "apiservices" => "APIServiceList",
        "clustertrustbundles" => "ClusterTrustBundleList",
        "certificatesigningrequests" => "CertificateSigningRequestList",
        "horizontalpodautoscalers" => "HorizontalPodAutoscalerList",
        "poddisruptionbudgets" => "PodDisruptionBudgetList",
        "networkpolicies" => "NetworkPolicyList",
        "ingresses" => "IngressList",
        "ingressclasses" => "IngressClassList",
        "ipaddresses" => "IPAddressList",
        "servicecidrs" => "ServiceCIDRList",
        "runtimeclasses" => "RuntimeClassList",
        "priorityclasses" => "PriorityClassList",
        "flowschemas" => "FlowSchemaList",
        "prioritylevelconfigurations" => "PriorityLevelConfigurationList",
        "podcertificaterequests" => "PodCertificateRequestList",
        "deviceclasses" => "DeviceClassList",
        "devicetaintrules" => "DeviceTaintRuleList",
        "resourceslices" => "ResourceSliceList",
        "resourceclaims" => "ResourceClaimList",
        "resourceclaimtemplates" => "ResourceClaimTemplateList",
        "storageversionmigrations" => "StorageVersionMigrationList",
        _ => "List",
    }
}

fn ok_json(body: Value) -> Outcome {
    Outcome {
        status: http::StatusCode::OK,
        body: Payload::Json(body),
        headers: Vec::new(),
    }
}

fn created_json(body: Value) -> Outcome {
    Outcome {
        status: http::StatusCode::CREATED,
        body: Payload::Json(body),
        headers: Vec::new(),
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
        headers: Vec::new(),
    }
}

fn handle_subject_access_review(mut doc: Value, kind: &str) -> Value {
    doc["status"] = json!({
        "allowed": true,
        "denied": false,
        "reason": "RBAC allowed"
    });
    doc["apiVersion"] = json!("authorization.k8s.io/v1");
    doc["kind"] = json!(kind);
    doc
}

fn handle_self_subject_rules_review(mut doc: Value) -> Value {
    doc["status"] = json!({
        "resourceRules": [
            {
                "verbs": ["*"],
                "apiGroups": ["*"],
                "resources": ["*"]
            }
        ],
        "nonResourceRules": [
            {
                "verbs": ["*"],
                "nonResourceURLs": ["*"]
            }
        ],
        "incomplete": false
    });
    doc["apiVersion"] = json!("authorization.k8s.io/v1");
    doc["kind"] = json!("SelfSubjectRulesReview");
    doc
}

pub(crate) fn connect_options_object(
    subresource: &str,
    query: Option<&str>,
) -> (String, Option<Value>) {
    let mut stdin = false;
    let mut stdout = false;
    let mut stderr = false;
    let mut tty = false;
    let mut container = String::new();
    let mut command = Vec::new();
    let mut ports = Vec::new();

    for (k, v) in crate::http::query::parse_pairs(query) {
        match k.as_str() {
            "stdin" => stdin = matches!(v.as_str(), "1" | "true" | "TRUE"),
            "stdout" => stdout = matches!(v.as_str(), "1" | "true" | "TRUE"),
            "stderr" => stderr = matches!(v.as_str(), "1" | "true" | "TRUE"),
            "tty" => tty = matches!(v.as_str(), "1" | "true" | "TRUE"),
            "container" => container = v,
            "command" => command.push(v),
            "ports" | "port" => {
                for p_str in v.split(',') {
                    if let Ok(p) = p_str.trim().parse::<i64>() {
                        ports.push(p);
                    }
                }
            },
            _ => {},
        }
    }

    match subresource {
        "exec" => {
            let mut obj = json!({
                "kind": "PodExecOptions",
                "apiVersion": "v1",
                "stdin": stdin,
                "stdout": stdout,
                "stderr": stderr,
                "tty": tty,
                "command": command,
            });
            if !container.is_empty() {
                obj["container"] = json!(container);
            }
            ("PodExecOptions".to_string(), Some(obj))
        },
        "attach" => {
            let mut obj = json!({
                "kind": "PodAttachOptions",
                "apiVersion": "v1",
                "stdin": stdin,
                "stdout": stdout,
                "stderr": stderr,
                "tty": tty,
            });
            if !container.is_empty() {
                obj["container"] = json!(container);
            }
            ("PodAttachOptions".to_string(), Some(obj))
        },
        "portforward" => (
            "PodPortForwardOptions".to_string(),
            Some(json!({
                "kind": "PodPortForwardOptions",
                "apiVersion": "v1",
                "ports": ports,
            })),
        ),
        _ => ("Pod".to_string(), None),
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
        ("", "serviceaccounts", "token") => {
            if *method != Method::POST {
                return Ok(status_outcome(
                    http::StatusCode::METHOD_NOT_ALLOWED,
                    "MethodNotAllowed",
                    "method is not supported",
                ));
            }
            let Some(namespace) = &path.namespace else {
                return Err(ApiserverError::BadRequest {
                    message: "token request requires namespace".to_string(),
                });
            };
            let Some(name) = &path.name else {
                return Err(ApiserverError::BadRequest {
                    message: "token request requires serviceaccount name".to_string(),
                });
            };
            let doc = decode_body(content_type, query, body, path)?;
            let token_req = client.create_token_request(namespace, name, doc).await?;
            Ok(created_json(token_req))
        },
        ("", "pods", "ephemeralcontainers") => match *method {
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
                        message: "ephemeralcontainers requires a resource name".to_string(),
                    });
                };
                let Some(namespace) = &path.namespace else {
                    return Err(ApiserverError::BadRequest {
                        message: "ephemeralcontainers requires a namespace".to_string(),
                    });
                };
                let mut current = client.get_pod(namespace, name).await?;
                if *method == Method::PUT {
                    let doc = decode_body(content_type, query, body, path)?;
                    if let Some(ec) = doc.pointer("/spec/ephemeralContainers")
                        && let Some(spec) = current.get_mut("spec").and_then(Value::as_object_mut)
                    {
                        spec.insert("ephemeralContainers".to_string(), ec.clone());
                    }
                } else {
                    apply_body_patch(&mut current, content_type, body)?;
                }
                if let Some(containers) = current
                    .pointer_mut("/spec/ephemeralContainers")
                    .and_then(Value::as_array_mut)
                {
                    for c in containers.iter_mut().filter_map(Value::as_object_mut) {
                        KubernetesApiClient::default_container_spec(c);
                    }
                }
                client
                    .update_pod_subresource_options(
                        namespace,
                        name,
                        current,
                        is_dry_run(query),
                        Some("ephemeralcontainers"),
                    )
                    .await
                    .map(ok_json)
            },
            _ => Ok(status_outcome(
                http::StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "method is not supported",
            )),
        },
        ("", "namespaces", "finalize") => match *method {
            Method::GET => {
                let Some(name) = &path.name else {
                    return Err(ApiserverError::BadRequest {
                        message: "finalize requires a resource name".to_string(),
                    });
                };
                client.get_namespace(name).await.map(ok_json)
            },
            Method::PUT => {
                let Some(name) = &path.name else {
                    return Err(ApiserverError::BadRequest {
                        message: "finalize requires a resource name".to_string(),
                    });
                };
                let doc = decode_body(content_type, query, body, path)?;
                client
                    .update_namespace_finalize(name, doc)
                    .await
                    .map(ok_json)
            },
            Method::PATCH => {
                let Some(name) = &path.name else {
                    return Err(ApiserverError::BadRequest {
                        message: "finalize requires a resource name".to_string(),
                    });
                };
                let mut current = client.get_namespace(name).await?;
                apply_body_patch(&mut current, content_type, body)?;
                client
                    .update_namespace_finalize(name, current)
                    .await
                    .map(ok_json)
            },
            _ => Ok(status_outcome(
                http::StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "method is not supported",
            )),
        },
        (_, _, "status" | "finalize" | "resize" | "approval") => match *method {
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
                        message: format!("{subresource} requires a resource name"),
                    });
                };
                let current = read_single(client, &strip_subresource(path), name).await?;
                let mut updated = current.clone();
                let original_spec = current.get("spec").cloned();
                if *method == Method::PUT {
                    let doc = decode_body(content_type, query, body, path)?;
                    if let Some(status) = doc.get("status") {
                        updated["status"] = status.clone();
                    }
                    if matches!(subresource, "finalize" | "resize") {
                        if let Some(spec) = doc.get("spec") {
                            updated["spec"] = spec.clone();
                        } else if let Some(containers) = doc.get("containers") {
                            updated["spec"]["containers"] = containers.clone();
                        }
                    }
                    if subresource == "resize" {
                        crate::client::prune_null_values(&mut updated);
                    }
                    if subresource == "status" {
                        let patched_labels = doc.pointer("/metadata/labels").cloned();
                        let patched_annotations = doc.pointer("/metadata/annotations").cloned();
                        updated["metadata"] = current["metadata"].clone();
                        if let Some(l) = patched_labels {
                            updated["metadata"]["labels"] = l;
                        }
                        if let Some(a) = patched_annotations {
                            updated["metadata"]["annotations"] = a;
                        }
                    }
                } else {
                    if subresource == "resize" {
                        apply_resize_patch(&mut updated, content_type, body)?;
                    } else {
                        apply_body_patch(&mut updated, content_type, body)?;
                    }
                    let patched_labels = updated.pointer("/metadata/labels").cloned();
                    let patched_annotations = updated.pointer("/metadata/annotations").cloned();
                    if matches!(subresource, "status" | "approval") {
                        if let Some(spec) = original_spec {
                            updated["spec"] = spec;
                        } else if let Some(obj) = updated.as_object_mut() {
                            obj.remove("spec");
                        }
                    }
                    if subresource == "status" {
                        updated["metadata"] = current["metadata"].clone();
                        if let Some(l) = patched_labels {
                            updated["metadata"]["labels"] = l;
                        }
                        if let Some(a) = patched_annotations {
                            updated["metadata"]["annotations"] = a;
                        }
                        if *method == Method::PATCH
                            && let Some(m) =
                                updated.get_mut("metadata").and_then(Value::as_object_mut)
                        {
                            m.remove("resourceVersion");
                        }
                    }
                }
                if subresource == "resize"
                    && path.resource == "pods"
                    && let Some(namespace) = &path.namespace
                {
                    client
                        .update_pod_subresource_options(
                            namespace,
                            name,
                            updated,
                            is_dry_run(query),
                            Some("resize"),
                        )
                        .await
                        .map(ok_json)
                } else {
                    persist_object(client, path, name, updated)
                        .await
                        .map(ok_json)
                }
            },
            _ => Ok(status_outcome(
                http::StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "method is not supported",
            )),
        },
        (_, "deployments" | "replicasets" | "statefulsets" | "replicationcontrollers", "scale") => {
            match *method {
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
                        let doc = decode_body(content_type, query, body, path)?;
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
            }
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
            let mut text = reader.read_pod_log(&pod, &options).await?;
            if let Some(limit) = options.limit_bytes {
                let boundary = text.floor_char_boundary(limit);
                text.truncate(boundary);
            }
            let body = if follow {
                Payload::ChunkedText(text)
            } else {
                Payload::Text(text)
            };
            Ok(Outcome {
                status: http::StatusCode::OK,
                body,
                headers: Vec::new(),
            })
        },
        ("", "pods", "eviction") => {
            if method != Method::POST {
                return Ok(status_outcome(
                    http::StatusCode::METHOD_NOT_ALLOWED,
                    "MethodNotAllowed",
                    "method is not supported",
                ));
            }
            evict_pod(client, path, body).await
        },
        ("", "pods" | "services", sub) if sub == "proxy" || sub.starts_with("proxy/") => {
            if sub == "proxy"
                && !path.trailing_slash
                && (*method == Method::GET || *method == Method::HEAD)
            {
                let ns = path.namespace.as_deref().unwrap_or("default");
                let res = &path.resource;
                let name = path.name.as_deref().unwrap_or("");
                let mut location = format!("/api/v1/namespaces/{ns}/{res}/{name}/proxy/");
                if let Some(q) = query {
                    location.push('?');
                    location.push_str(q);
                }
                let header_val = http::header::HeaderValue::from_str(&location).map_err(|_| {
                    ApiserverError::Internal {
                        reason: "invalid location header".into(),
                    }
                })?;
                return Ok(Outcome {
                    status: http::StatusCode::MOVED_PERMANENTLY,
                    body: Payload::Text(String::new()),
                    headers: vec![(http::header::LOCATION, header_val)],
                });
            }
            proxy_subresource(client, method, path, sub, query, content_type, body).await
        },
        (_, "pods", subresource @ ("exec" | "attach" | "portforward")) => {
            let cur_rev = client.storage().current_revision().await + 1;
            let (kind_str, obj) = connect_options_object(subresource, query);
            let mut adm_req = AdmissionRequest {
                uid: format!("adm-{cur_rev}"),
                kind: GroupVersionKind {
                    group: String::new(),
                    version: "v1".to_string(),
                    kind: kind_str,
                },
                resource: GroupVersionResource {
                    group: String::new(),
                    version: "v1".to_string(),
                    resource: "pods".to_string(),
                },
                subresource: Some(subresource.to_string()),
                name: path.name.clone(),
                namespace: path.namespace.clone(),
                operation: "CONNECT".to_string(),
                user_info: client.current_user_info().await,
                object: obj,
                old_object: None,
                dry_run: None,
            };
            client
                .admission()
                .run_mutating_admission(&mut adm_req)
                .await?;
            client
                .admission()
                .run_validating_admission(&adm_req)
                .await?;
            Err(ApiserverError::BadRequest {
                message: format!("{subresource} requires a websocket upgrade"),
            })
        },
        _ => Err(ApiserverError::NotFound {
            resource: format!("{}/{subresource}", path.resource),
            name: path.name.clone().unwrap_or_default(),
        }),
    }
}

/// `POST pods/<name>/eviction`: a graceful delete gated by `PodDisruptionBudgets`.
async fn evict_pod(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    body: &[u8],
) -> Result<Outcome, ApiserverError> {
    let (Some(namespace), Some(name)) = (&path.namespace, &path.name) else {
        return Err(ApiserverError::BadRequest {
            message: "eviction requires a namespace and name".to_string(),
        });
    };
    let pod = client.get_pod(namespace, name).await?;
    let grace = serde_json::from_slice::<Value>(body).ok().and_then(|v| {
        v.pointer("/deleteOptions/gracePeriodSeconds")
            .and_then(Value::as_i64)
    });

    let pods: Vec<Value> = client
        .list_pods(namespace)
        .await?
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let pdbs: Vec<Value> = client
        .list_namespaced_objects(
            "policy",
            "PodDisruptionBudgetList",
            "poddisruptionbudgets",
            namespace,
        )
        .await
        .ok()
        .and_then(|l| l.get("items").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    let matching: Vec<&Value> = pdbs
        .iter()
        .filter(|pdb| {
            crate::pdb::selector_matches(
                pdb.pointer("/spec/selector"),
                pod.pointer("/metadata/labels"),
            )
        })
        .collect();

    // Terminal or already-unhealthy pods never consume budget.
    let pod_healthy = crate::pdb::is_healthy(&pod);
    if pod_healthy && matching.len() > 1 {
        return Ok(status_outcome(
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "This pod has more than one PodDisruptionBudget, which the eviction subresource does not support.",
        ));
    }
    if pod_healthy && let Some(pdb) = matching.first() {
        let counts = crate::pdb::compute_counts(pdb, &pods);
        if counts.disruptions_allowed <= 0 {
            let pdb_name = pdb
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let message = format!(
                "The disruption budget {pdb_name} needs {} healthy pods and has {} currently",
                counts.desired_healthy, counts.current_healthy
            );
            return Ok(Outcome {
                status: http::StatusCode::TOO_MANY_REQUESTS,
                body: Payload::Json(json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "metadata": {},
                    "status": "Failure",
                    "message": "Cannot evict pod as it would violate the pod's disruption budget.",
                    "reason": "TooManyRequests",
                    "details": { "causes": [{ "reason": "DisruptionBudget", "message": message }] },
                    "code": 429
                })),
                headers: Vec::new(),
            });
        }
        record_pdb_disruption(client, pdb, &counts, namespace, name).await;
    }

    mark_pod_disrupted_and_wait_job(client, namespace, name).await?;
    client
        .delete_pod_options(namespace, name, grace.or(Some(0)))
        .await?;
    Ok(status_outcome(
        http::StatusCode::CREATED,
        "Success",
        "evicted",
    ))
}

async fn mark_pod_disrupted_and_wait_job(
    client: &KubernetesApiClient,
    namespace: &str,
    name: &str,
) -> Result<(), ApiserverError> {
    let current_pod = client.get_pod(namespace, name).await?;
    let mut status = current_pod
        .get("status")
        .cloned()
        .unwrap_or_else(|| json!({}));
    status["phase"] = json!("Failed");
    if status.get("conditions").is_none() {
        status["conditions"] = json!([]);
    }
    if let Some(arr) = status.get_mut("conditions").and_then(Value::as_array_mut) {
        arr.retain(|c| c.get("type").and_then(Value::as_str) != Some("DisruptionTarget"));
        arr.push(json!({
            "type": "DisruptionTarget",
            "status": "True",
            "reason": "TerminationByKubelet",
            "message": "Pod was evicted",
            "lastTransitionTime": crate::time::now_rfc3339()
        }));
    }
    let _ = client.patch_pod_status(namespace, name, status).await;

    let has_job_owner = current_pod
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .is_some_and(|arr| {
            arr.iter()
                .any(|r| r.get("kind").and_then(Value::as_str) == Some("Job"))
        });
    if has_job_owner {
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    }
    Ok(())
}

async fn record_pdb_disruption(
    client: &KubernetesApiClient,
    pdb: &Value,
    counts: &crate::pdb::PdbCounts,
    namespace: &str,
    pod_name: &str,
) {
    let mut updated = (*pdb).clone();
    if let Some(status) = updated.get_mut("status").and_then(Value::as_object_mut) {
        let allowed = counts.disruptions_allowed - 1;
        status.insert("disruptionsAllowed".to_string(), json!(allowed));
        let disrupted = status
            .entry("disruptedPods".to_string())
            .or_insert_with(|| json!({}));
        if let Some(map) = disrupted.as_object_mut() {
            map.insert(pod_name.to_string(), json!(crate::time::now_rfc3339()));
        }
    }
    if let Some(pdb_name) = pdb.pointer("/metadata/name").and_then(Value::as_str) {
        let _ = client
            .replace_namespaced_object(
                "policy",
                "PodDisruptionBudget",
                "poddisruptionbudgets",
                namespace,
                pdb_name,
                updated,
            )
            .await;
    }
}

fn split_proxy_name(raw: &str) -> (Option<&str>, &str, Option<&str>) {
    let parts: Vec<&str> = raw.split(':').collect();
    match parts.as_slice() {
        [scheme, name, port] if *scheme == "http" || *scheme == "https" => {
            (Some(*scheme), *name, Some(*port).filter(|p| !p.is_empty()))
        },
        [scheme, name] if *scheme == "http" || *scheme == "https" => (Some(*scheme), *name, None),
        [name, port] => (None, *name, Some(*port).filter(|p| !p.is_empty())),
        [name] => (None, *name, None),
        _ => (None, raw, None),
    }
}

fn find_pod_port(pod: &Value, port_spec: &str) -> Option<u16> {
    if let Ok(num) = port_spec.parse::<u16>() {
        return Some(num);
    }
    let containers = pod.pointer("/spec/containers").and_then(Value::as_array)?;
    for c in containers {
        let Some(ports) = c.get("ports").and_then(Value::as_array) else {
            continue;
        };
        for p in ports {
            if p.get("name").and_then(Value::as_str) == Some(port_spec)
                && let Some(cp) = p.get("containerPort").and_then(Value::as_u64)
                && let Ok(num) = u16::try_from(cp)
            {
                return Some(num);
            }
        }
    }
    None
}

fn first_pod_port(pod: &Value) -> Option<u16> {
    let containers = pod.pointer("/spec/containers").and_then(Value::as_array)?;
    for c in containers {
        let Some(ports) = c.get("ports").and_then(Value::as_array) else {
            continue;
        };
        for p in ports {
            if let Some(cp) = p.get("containerPort").and_then(Value::as_u64)
                && let Ok(num) = u16::try_from(cp)
            {
                return Some(num);
            }
        }
    }
    None
}

async fn resolve_proxy_target(
    client: &KubernetesApiClient,
    resource: &str,
    namespace: &str,
    obj_name: &str,
    port_spec: Option<&str>,
) -> Result<(String, u16), ApiserverError> {
    if resource == "pods" {
        let pod = client.get_pod(namespace, obj_name).await?;
        let ip = pod
            .pointer("/status/podIP")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("127.0.0.1")
            .to_string();
        let port = port_spec
            .and_then(|ps| find_pod_port(&pod, ps))
            .or_else(|| first_pod_port(&pod))
            .unwrap_or(80);
        return Ok((ip, port));
    }

    let svc = client.get_service(namespace, obj_name).await?;
    let svc_ports = svc.pointer("/spec/ports").and_then(Value::as_array);
    let matched_sp = svc_ports.and_then(|ports| {
        if let Some(ps) = port_spec {
            ports.iter().find(|sp| {
                sp.get("name").and_then(Value::as_str) == Some(ps)
                    || ps
                        .parse::<u64>()
                        .is_ok_and(|n| sp.get("port").and_then(Value::as_u64) == Some(n))
            })
        } else {
            ports.first()
        }
    });
    let svc_port_name = matched_sp
        .and_then(|sp| sp.get("name"))
        .and_then(Value::as_str);
    let svc_port_num = matched_sp
        .and_then(|sp| sp.get("port"))
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .or_else(|| port_spec.and_then(|ps| ps.parse::<u16>().ok()))
        .unwrap_or(80);

    if let Ok(ep) = client.get_endpoints(namespace, obj_name).await
        && let Some(subset) = ep.pointer("/subsets/0")
        && let Some(ep_ip) = subset.pointer("/addresses/0/ip").and_then(Value::as_str)
        && !ep_ip.is_empty()
    {
        let ep_ports = subset.get("ports").and_then(Value::as_array);
        let ep_port = ep_ports
            .and_then(|ports| {
                if let Some(name) = svc_port_name.or(port_spec) {
                    ports
                        .iter()
                        .find(|p| p.get("name").and_then(Value::as_str) == Some(name))
                        .or_else(|| ports.first())
                } else {
                    ports.first()
                }
            })
            .and_then(|p| p.get("port"))
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(svc_port_num);
        return Ok((ep_ip.to_string(), ep_port));
    }

    let cluster_ip = svc
        .pointer("/spec/clusterIP")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && *s != "None")
        .unwrap_or("127.0.0.1")
        .to_string();
    Ok((cluster_ip, svc_port_num))
}

async fn connect_proxy_sender(
    stream: tokio::net::TcpStream,
    ip: &str,
    port: u16,
    is_https: bool,
) -> Result<
    hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
    ApiserverError,
> {
    if is_https {
        let connector = crate::http::tls::tls_connector_for_ca(None);
        let server_name = rustls::pki_types::ServerName::try_from(ip.to_string())
            .or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()))
            .map_err(|err| ApiserverError::Internal {
                reason: format!("invalid server name for proxy TLS: {err}"),
            })?;
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|err| ApiserverError::Internal {
                reason: format!("proxy TLS handshake with {ip}:{port} failed: {err}"),
            })?;
        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|err| ApiserverError::Internal {
                reason: format!("proxy HTTP handshake with {ip}:{port} failed: {err}"),
            })?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    } else {
        let io = hyper_util::rt::TokioIo::new(stream);
        let (sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|err| ApiserverError::Internal {
                reason: format!("proxy HTTP handshake with {ip}:{port} failed: {err}"),
            })?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }
}

async fn proxy_subresource(
    client: &KubernetesApiClient,
    method: &Method,
    path: &ResourcePath,
    subresource: &str,
    query: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Outcome, ApiserverError> {
    let (Some(namespace), Some(raw_name)) = (&path.namespace, &path.name) else {
        return Err(ApiserverError::BadRequest {
            message: format!("{} proxy requires a namespace and name", path.resource),
        });
    };
    let (scheme, obj_name, port_spec) = split_proxy_name(raw_name);
    let (ip, default_port) =
        resolve_proxy_target(client, &path.resource, namespace, obj_name, port_spec).await?;
    let port = if port_spec.is_none() && scheme == Some("https") {
        443
    } else {
        default_port
    };
    let suffix = subresource.strip_prefix("proxy/").unwrap_or("");
    let target_uri = match (suffix, query) {
        ("", Some(q)) if !q.is_empty() => format!("/?{q}"),
        ("", _) => "/".to_string(),
        (s, Some(q)) if !q.is_empty() => format!("/{s}?{q}"),
        (s, _) => format!("/{s}"),
    };

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect((ip.as_str(), port)),
    )
    .await
    .map_err(|_| ApiserverError::Internal {
        reason: format!("proxy connection to {ip}:{port} timed out"),
    })?
    .map_err(|err| ApiserverError::Internal {
        reason: format!("proxy connection to {ip}:{port} failed: {err}"),
    })?;

    let proto_str = if scheme == Some("https") {
        "https"
    } else {
        "http"
    };

    let mut sender = connect_proxy_sender(stream, &ip, port, scheme == Some("https")).await?;

    let mut req_builder = http::Request::builder()
        .method(method)
        .uri(&target_uri)
        .header(http::header::HOST, format!("{ip}:{port}"))
        .header("X-Forwarded-Uri", &target_uri)
        .header("X-Forwarded-Proto", proto_str);
    if let Some(ct) = content_type {
        req_builder = req_builder.header(http::header::CONTENT_TYPE, ct);
    }
    let req = req_builder
        .body(http_body_util::Full::new(bytes::Bytes::copy_from_slice(
            body,
        )))
        .map_err(|err| ApiserverError::Internal {
            reason: format!("failed to build proxy request: {err}"),
        })?;

    let resp = sender
        .send_request(req)
        .await
        .map_err(|err| ApiserverError::Internal {
            reason: format!("proxy request to {ip}:{port}{target_uri} failed: {err}"),
        })?;
    let status = resp.status();
    let collected = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .map_err(|err| ApiserverError::Internal {
            reason: format!("reading proxy response body failed: {err}"),
        })?;
    let mut text = String::from_utf8_lossy(&collected.to_bytes()).into_owned();
    let proxy_prefix = format!(
        "/api/v1/namespaces/{namespace}/{}/{raw_name}/proxy/",
        path.resource
    );
    if text.contains("href=\"/") && !text.contains("href=\"/api/") {
        text = text.replace("href=\"/", &format!("href=\"{proxy_prefix}"));
    }
    Ok(Outcome {
        status,
        body: Payload::Text(text),
        headers: Vec::new(),
    })
}

fn strip_subresource(path: &ResourcePath) -> ResourcePath {
    ResourcePath {
        subresource: None,
        ..path.clone()
    }
}

pub(crate) fn strategic_merge_patch(target: &mut Value, patch: Value) {
    crate::client::json_merge_patch(target, patch);
}

fn apply_body_patch(
    target: &mut Value,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<(), ApiserverError> {
    match patch_type(content_type) {
        PatchType::Json => crate::admission::apply_json_patch(target, body),
        PatchType::RfcMerge => {
            let patch: Value = match serde_json::from_slice(body) {
                Ok(v) => v,
                Err(_) => crate::http::field_validation::decode_yaml(body, false)?,
            };
            crate::client::json_rfc7396_merge_patch(target, patch);
            Ok(())
        },
        PatchType::StrategicMerge | PatchType::Apply => {
            let patch: Value = match serde_json::from_slice(body) {
                Ok(v) => v,
                Err(_) => crate::http::field_validation::decode_yaml(body, false)?,
            };
            strategic_merge_patch(target, patch);
            Ok(())
        },
    }
}

fn apply_resize_patch(
    target: &mut Value,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<(), ApiserverError> {
    if let Ok(mut patch_val) = serde_json::from_slice::<Value>(body)
        && let Some(containers) = patch_val
            .as_object_mut()
            .and_then(|m| m.remove("containers"))
    {
        let wrapped_patch = json!({ "spec": { "containers": containers } });
        let wrapped_bytes =
            serde_json::to_vec(&wrapped_patch).map_err(|e| ApiserverError::BadRequest {
                message: e.to_string(),
            })?;
        apply_body_patch(target, content_type, &wrapped_bytes)?;
    } else {
        apply_body_patch(target, content_type, body)?;
    }
    crate::client::prune_null_values(target);
    Ok(())
}

async fn persist_object(
    client: &KubernetesApiClient,
    path: &ResourcePath,
    name: &str,
    doc: Value,
) -> Result<Value, ApiserverError> {
    if is_cluster_resource(&path.resource) {
        update_cluster(client, &path.group, &path.resource, name, doc).await
    } else if let Some(namespace) = &path.namespace {
        update_namespaced(client, &path.group, &path.resource, namespace, name, doc).await
    } else if is_builtin_namespaced(&path.resource) {
        Err(ApiserverError::BadRequest {
            message: format!("{} requires a namespace", path.resource),
        })
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
    let selector_map = current
        .pointer("/spec/selector/matchLabels")
        .and_then(Value::as_object)
        .or_else(|| current.pointer("/spec/selector").and_then(Value::as_object));
    let selector = selector_map
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| format!("{k}={s}")))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn cluster_wide_list_does_not_require_namespace_discovery_permission() {
        use crate::{
            ApiserverConfig, ApiserverService, ClusterRole, ClusterRoleBinding, KubernetesStorage,
            PolicyRule, Subject,
        };
        use diorama_datastore::{DatastoreConfig, DatastoreEngine};
        use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
        use std::collections::BTreeMap;
        let root = tempfile::tempdir().unwrap();
        let pki = root.path().join("pki");
        let ip = "127.0.0.1".parse().unwrap();
        ClusterPki::new(ClusterPkiConfig::new(pki.clone(), "node".into(), ip))
            .reconcile()
            .unwrap();
        let (engine, _) =
            DatastoreEngine::open(DatastoreConfig::new(root.path().join("db"))).unwrap();
        let service = ApiserverService::new(
            ApiserverConfig::default_for_pki(&pki, ip),
            KubernetesStorage::new(engine.client(), "/registry"),
        );
        service.check_prerequisites().await.unwrap();
        let admin = service.admin_client();
        for namespace in ["alpha", "beta"] {
            admin.create_namespace(namespace).await.unwrap();
            admin
                .create_configmap(namespace, "proof", BTreeMap::new())
                .await
                .unwrap();
        }
        admin
            .create_cluster_role(ClusterRole {
                name: "reader".into(),
                rules: vec![PolicyRule {
                    verbs: vec!["list".into()],
                    api_groups: vec![String::new()],
                    resources: vec!["configmaps".into()],
                    resource_names: vec![],
                    non_resource_urls: vec![],
                }],
            })
            .await
            .unwrap();
        admin
            .create_cluster_role_binding(ClusterRoleBinding {
                name: "reader".into(),
                role_ref: "reader".into(),
                subjects: vec![Subject::ServiceAccount {
                    namespace: "alpha".into(),
                    name: "reader".into(),
                }],
            })
            .await
            .unwrap();
        let reader = service.service_account_client("alpha", "reader");
        assert!(reader.list_namespaces().await.is_err());
        let list = list_all_namespaces(&reader, "", "configmaps")
            .await
            .unwrap();
        let items = list["items"].as_array().unwrap();
        for namespace in ["alpha", "beta"] {
            assert!(items.iter().any(
                |v| v["metadata"]["name"] == "proof" && v["metadata"]["namespace"] == namespace
            ));
        }
        assert!(list_all_namespaces(&reader, "", "secrets").await.is_err());
    }

    #[test]
    fn page_list_chunking_and_continuation() {
        let items: Vec<Value> = (1..=5)
            .map(|i| {
                json!({
                    "metadata": {
                        "name": format!("item-{i}"),
                        "namespace": "default"
                    }
                })
            })
            .collect();
        let list = json!({
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": { "resourceVersion": "42" },
            "items": items
        });

        // 1. First chunk of limit 2
        let page1 = page_list(list.clone(), Some("limit=2")).expect("page 1 succeeds");
        let p1_items = page1["items"].as_array().unwrap();
        assert_eq!(p1_items.len(), 2);
        assert_eq!(p1_items[0]["metadata"]["name"], "item-1");
        assert_eq!(p1_items[1]["metadata"]["name"], "item-2");
        assert_eq!(page1["metadata"]["resourceVersion"], "42");
        assert_eq!(page1["metadata"]["remainingItemCount"], 3);
        let token1 = page1["metadata"]["continue"].as_str().unwrap();
        assert_ne!(token1, "");

        // 2. Second chunk using continue token
        let query2 = format!("limit=2&continue={token1}");
        let page2 = page_list(list.clone(), Some(&query2)).expect("page 2 succeeds");
        let p2_items = page2["items"].as_array().unwrap();
        assert_eq!(p2_items.len(), 2);
        assert_eq!(p2_items[0]["metadata"]["name"], "item-3");
        assert_eq!(p2_items[1]["metadata"]["name"], "item-4");
        assert_eq!(page2["metadata"]["resourceVersion"], "42");
        assert_eq!(page2["metadata"]["remainingItemCount"], 1);
        let token2 = page2["metadata"]["continue"].as_str().unwrap();

        // 3. Third and final chunk
        let query3 = format!("limit=2&continue={token2}");
        let page3 = page_list(list.clone(), Some(&query3)).expect("page 3 succeeds");
        let p3_items = page3["items"].as_array().unwrap();
        assert_eq!(p3_items.len(), 1);
        assert_eq!(p3_items[0]["metadata"]["name"], "item-5");
        assert_eq!(page3["metadata"]["resourceVersion"], "42");
        assert!(page3["metadata"].get("continue").is_none());
        assert!(page3["metadata"].get("remainingItemCount").is_none());

        // 4. No limit returns all items
        let all = page_list(list.clone(), None).expect("all succeeds");
        assert_eq!(all["items"].as_array().unwrap().len(), 5);

        // 5. Invalid limit returns BadRequest
        let err = page_list(list.clone(), Some("limit=invalid")).unwrap_err();
        assert!(matches!(err, ApiserverError::BadRequest { .. }));
        let err_neg = page_list(list, Some("limit=-1")).unwrap_err();
        assert!(matches!(err_neg, ApiserverError::BadRequest { .. }));
    }

    #[test]
    fn crd_host_port_conversion_v1_v2() {
        let mut v1_doc = json!({
            "spec": {
                "hostPort": "example.com:8080"
            }
        });
        convert_custom_resource(&mut v1_doc, "example.com", "v2");
        assert_eq!(v1_doc["spec"]["host"], "example.com");
        assert_eq!(v1_doc["spec"]["port"], "8080");
        assert!(v1_doc["spec"].get("hostPort").is_none());

        let mut v2_doc = json!({
            "spec": {
                "host": "example.com",
                "port": 8080
            }
        });
        convert_custom_resource(&mut v2_doc, "example.com", "v1");
        assert_eq!(v2_doc["spec"]["hostPort"], "example.com:8080");
        assert!(v2_doc["spec"].get("host").is_none());
        assert!(v2_doc["spec"].get("port").is_none());
    }

    #[test]
    fn json_merge_patch_retain_keys_and_replace() {
        let mut pod = json!({
            "spec": {
                "containers": [
                    {
                        "name": "c2",
                        "resources": {
                            "requests": { "cpu": "20m", "memory": "30Mi" },
                            "limits": { "cpu": "40m", "memory": "50Mi" }
                        }
                    }
                ]
            }
        });
        let patch = json!({
            "spec": {
                "containers": [
                    {
                        "name": "c2",
                        "resources": {
                            "requests": { "$retainKeys": ["memory"], "memory": "35Mi" }
                        }
                    }
                ]
            }
        });
        crate::client::json_merge_patch(&mut pod, patch);
        assert!(
            pod["spec"]["containers"][0]["resources"]["requests"]
                .get("cpu")
                .is_none()
        );
        assert_eq!(
            pod["spec"]["containers"][0]["resources"]["requests"]["memory"],
            "35Mi"
        );
    }

    #[test]
    fn delete_options_protobuf_without_apiversion_decodes_orphan() {
        // Build k8s\0 + runtime.Unknown{TypeMeta{Kind: "DeleteOptions"}, Raw: DeleteOptions{orphanDependents: true}}
        let type_meta = b"\x12\x0dDeleteOptions"; // field 2 = kind
        let raw_opts = b"\x18\x01"; // field 3 = orphanDependents (bool = true)
        let mut unknown = Vec::new();
        unknown.push(0x0a);
        unknown.push(u8::try_from(type_meta.len()).unwrap());
        unknown.extend_from_slice(type_meta);
        unknown.push(0x12);
        unknown.push(u8::try_from(raw_opts.len()).unwrap());
        unknown.extend_from_slice(raw_opts);
        let mut body = b"k8s\x00".to_vec();
        body.extend_from_slice(&unknown);

        let policy = delete_propagation_policy(&body, "", "replicationcontrollers");
        assert_eq!(policy.as_deref(), Some("Orphan"));
    }
}
