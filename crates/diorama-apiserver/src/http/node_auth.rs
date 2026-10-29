//! Node authorization uses stored assignments, never caller-supplied Pod specs.
use super::{query, route::ResourcePath};
use crate::{ApiserverError, ApiserverService, ClientIdentity, KubernetesApiClient};
use http::Method;
use serde_json::Value;

fn denied() -> ApiserverError {
    ApiserverError::Unauthorized {
        reason: "request exceeds this node's authority".into(),
    }
}
pub(crate) fn node_name(client: &KubernetesApiClient) -> Option<&str> {
    match client.identity() {
        ClientIdentity::User { username, .. } => username.strip_prefix("system:node:"),
        _ => None,
    }
}
fn named_selector(query: Option<&str>, field: &str, name: &str) -> bool {
    query::parse(query).get("fieldSelector").is_some_and(|s| {
        s.split(',')
            .any(|p| p == format!("{field}={name}") || p == format!("{field}=={name}"))
    })
}
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn authorize(
    service: &ApiserverService,
    client: &KubernetesApiClient,
    method: &Method,
    path: &ResourcePath,
    query: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<(), ApiserverError> {
    let Some(node) = node_name(client) else {
        return Ok(());
    };
    if !matches!(client.identity(), ClientIdentity::User { groups, .. } if groups.iter().any(|g| g == "system:nodes"))
    {
        return Err(denied());
    }
    let read = method == Method::GET;
    let write = matches!(*method, Method::POST | Method::PATCH | Method::PUT);
    let ns = path.namespace.as_deref().unwrap_or("");
    let selected_name = query::parse(query)
        .get("fieldSelector")
        .and_then(|s| {
            s.split(',').find_map(|term| {
                term.strip_prefix("metadata.name==")
                    .or_else(|| term.strip_prefix("metadata.name="))
            })
        })
        .map(str::to_owned);
    let name = path
        .name
        .as_deref()
        .or(selected_name.as_deref())
        .unwrap_or("");
    let sub = path.subresource.as_deref().unwrap_or("");
    let doc = if body.is_empty() {
        Value::Null
    } else {
        super::dispatch::decode_body(content_type, query, body, path)?
    };
    let admin = service.admin_client();
    let allowed = match (path.group.as_str(), path.resource.as_str(), sub) {
        ("", "nodes", "" | "status") => {
            if method == Method::PATCH
                && sub.is_empty()
                && (!doc.is_object() || doc.get("spec").is_some())
            {
                return Err(denied());
            }
            let own = name == node
                || (method == Method::POST
                    && doc.pointer("/metadata/name").and_then(Value::as_str) == Some(node));
            if own && sub.is_empty() && method == Method::PUT {
                // Controller-owned spec fields (including PodCIDR and taints) cannot be changed here.
                let old = admin.get_node(node).await?;
                if doc.get("spec") != old.get("spec") {
                    return Err(denied());
                }
            }
            (read && (sub.is_empty() || own)) || (write && own)
        },
        ("coordination.k8s.io", "leases", "") => {
            ns == "kube-node-lease"
                && (name == node
                    || (method == Method::POST
                        && doc.pointer("/metadata/name").and_then(Value::as_str) == Some(node)))
                && (read || write)
        },
        ("", "pods", "" | "status") => {
            if name.is_empty() {
                read && named_selector(query, "spec.nodeName", node)
            } else {
                let pod = admin.get_pod(ns, name).await?;
                pod.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node)
                    && (read
                        || (write && sub == "status")
                        || (*method == Method::DELETE && sub.is_empty()))
            }
        },
        ("", "services", "")
        | ("node.k8s.io", "runtimeclasses", "")
        | ("storage.k8s.io", "csidrivers", "") => read,
        ("storage.k8s.io", "csinodes", "") => {
            let own = name == node || (method == Method::POST && doc["metadata"]["name"] == node);
            own && (read || write)
        },
        ("" | "events.k8s.io", "events", "") => write,
        ("certificates.k8s.io", "certificatesigningrequests", "") => {
            if method == Method::POST {
                true
            } else if read && !name.is_empty() {
                let csr = admin
                    .get_cluster_object("certificates.k8s.io", "certificatesigningrequests", name)
                    .await?;
                csr.pointer("/spec/username").and_then(Value::as_str)
                    == Some(&format!("system:node:{node}"))
            } else {
                false
            }
        },
        (
            "",
            "secrets"
            | "configmaps"
            | "persistentvolumeclaims"
            | "persistentvolumes"
            | "serviceaccounts",
            "" | "token",
        ) => {
            if name.is_empty() {
                false
            } else {
                referenced_resource(&admin, node, path, name, &doc).await?
                    && (read || (method == Method::POST && sub == "token"))
            }
        },
        _ => false,
    };
    if allowed { Ok(()) } else { Err(denied()) }
}
async fn referenced_resource(
    admin: &KubernetesApiClient,
    node: &str,
    path: &ResourcePath,
    name: &str,
    doc: &Value,
) -> Result<bool, ApiserverError> {
    let list = admin.list_all_pods().await?;
    for pod in list["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node))
    {
        let ns = pod
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("");
        if path.resource == "persistentvolumes" {
            if references_volume(admin, pod, ns, name).await {
                return Ok(true);
            }
            continue;
        }
        if path.namespace.as_deref() != Some(ns) || !references(pod, &path.resource, name) {
            continue;
        }
        if path.subresource.as_deref() != Some("token") {
            return Ok(true);
        }
        if doc
            .pointer("/spec/boundObjectRef/kind")
            .and_then(Value::as_str)
            == Some("Pod")
            && doc.pointer("/spec/boundObjectRef/name") == pod.pointer("/metadata/name")
            && doc.pointer("/spec/boundObjectRef/uid") == pod.pointer("/metadata/uid")
        {
            return Ok(true);
        }
    }
    Ok(false)
}
async fn references_volume(admin: &KubernetesApiClient, pod: &Value, ns: &str, name: &str) -> bool {
    for volume in pod
        .pointer("/spec/volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(claim) = volume
            .pointer("/persistentVolumeClaim/claimName")
            .and_then(Value::as_str)
            && let Ok(pvc) = admin.get_pvc(ns, claim).await
            && pvc.pointer("/spec/volumeName").and_then(Value::as_str) == Some(name)
        {
            return true;
        }
    }
    false
}
fn references(pod: &Value, resource: &str, name: &str) -> bool {
    let spec = &pod["spec"];
    if resource == "configmaps" && name == "kube-root-ca.crt" {
        return true;
    }
    if resource == "serviceaccounts" {
        return spec["serviceAccountName"].as_str().unwrap_or("default") == name;
    }
    if resource == "secrets"
        && spec["imagePullSecrets"]
            .as_array()
            .is_some_and(|xs| xs.iter().any(|x| x["name"] == name))
    {
        return true;
    }
    for volume in spec["volumes"].as_array().into_iter().flatten() {
        let key = match resource {
            "secrets" => "/secret/secretName",
            "configmaps" => "/configMap/name",
            "persistentvolumeclaims" => "/persistentVolumeClaim/claimName",
            _ => "",
        };
        if volume.pointer(key).and_then(Value::as_str) == Some(name) {
            return true;
        }
        for source in volume
            .pointer("/projected/sources")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let key = if resource == "secrets" {
                "/secret/name"
            } else if resource == "configmaps" {
                "/configMap/name"
            } else {
                continue;
            };
            if source.pointer(key).and_then(Value::as_str) == Some(name) {
                return true;
            }
        }
    }
    for kind in ["containers", "initContainers", "ephemeralContainers"] {
        for container in spec[kind].as_array().into_iter().flatten() {
            let (env, from) = match resource {
                "secrets" => ("secretKeyRef", "secretRef"),
                "configmaps" => ("configMapKeyRef", "configMapRef"),
                _ => continue,
            };
            if container["env"]
                .as_array()
                .is_some_and(|xs| xs.iter().any(|x| x["valueFrom"][env]["name"] == name))
                || container["envFrom"]
                    .as_array()
                    .is_some_and(|xs| xs.iter().any(|x| x[from]["name"] == name))
            {
                return true;
            }
        }
    }
    false
}
