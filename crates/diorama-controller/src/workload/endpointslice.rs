use std::sync::Arc;
use std::time::Duration;

use diorama_apiserver::client::KubernetesApiClient;
use serde_json::{Map, Value, json};

use crate::error::ControllerError;
use crate::workload::ReconcileOutcome;

/// Reconciler for `EndpointSlice` resources (discovery.k8s.io/v1).
///
/// Preserves upstream Kubernetes defaults: `endpointslice_updates_batch_period` = 0s
/// (per KS-29 / PR #111) ensuring immediate reconciliation of backend membership changes.
#[derive(Clone, Debug)]
pub struct EndpointSliceReconciler {
    client: Arc<KubernetesApiClient>,
    batch_period: Duration,
}

impl EndpointSliceReconciler {
    #[must_use]
    pub fn new(client: Arc<KubernetesApiClient>) -> Self {
        Self {
            client,
            batch_period: Duration::ZERO,
        }
    }

    #[must_use]
    pub fn with_batch_period(client: Arc<KubernetesApiClient>, batch_period: Duration) -> Self {
        Self {
            client,
            batch_period,
        }
    }

    #[must_use]
    pub fn batch_period(&self) -> Duration {
        self.batch_period
    }

    /// Reconciles all `EndpointSlices` for Services in the specified namespace.
    pub async fn reconcile_all(
        &self,
        namespace: &str,
    ) -> Result<ReconcileOutcome, ControllerError> {
        let list = self.client.list_services(namespace).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "services".to_string(),
                reason: e.to_string(),
            }
        })?;

        let items = list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut count = 0;
        let mut errors = Vec::new();
        for svc in items {
            match self.reconcile_service_endpointslice(namespace, &svc).await {
                Ok(Some(_)) => count += 1,
                Ok(None) => {},
                Err(err) => errors.push(err.to_string()),
            }
        }

        Ok(ReconcileOutcome {
            reconciled: count,
            errors,
        })
    }

    /// Reconciles `EndpointSlice` resources for a single `Service`.
    /// Returns `Ok(Some(slice))` if a slice was managed/reconciled, or `Ok(None)` if the service has no selector.
    pub async fn reconcile_service_endpointslice(
        &self,
        namespace: &str,
        service: &Value,
    ) -> Result<Option<Value>, ControllerError> {
        let name = service
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ControllerError::InvalidConfiguration {
                field: "metadata.name".to_string(),
                reason: "Service missing metadata.name".to_string(),
            })?;

        let uid = service
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let selector = service
            .get("spec")
            .and_then(|s| s.get("selector"))
            .and_then(Value::as_object);

        let Some(selector) = selector else {
            return Ok(None);
        };

        if selector.is_empty() {
            return Ok(None);
        }

        let (endpoints, matching_pods) = self
            .extract_matching_pod_endpoints(namespace, selector)
            .await?;
        let slice_ports = extract_service_slice_ports(service, &matching_pods);

        let existing_slices = self
            .client
            .list_endpointslices(namespace)
            .await
            .map_err(|e| ControllerError::ReconciliationFailed {
                resource: "endpointslices".to_string(),
                reason: e.to_string(),
            })?;

        let existing_items = existing_slices
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let matching_existing = existing_items
            .into_iter()
            .find(|es| is_matching_endpointslice(es, name, uid));

        let slice_name = matching_existing
            .as_ref()
            .and_then(|es| es.get("metadata"))
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .map_or_else(|| format!("{name}-1"), ToString::to_string);

        let desired_slice = json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": slice_name,
                "namespace": namespace,
                "labels": {
                    "kubernetes.io/service-name": name,
                    "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
                },
                "ownerReferences": [
                    {
                        "apiVersion": "v1",
                        "kind": "Service",
                        "name": name,
                        "uid": uid,
                        "controller": true,
                        "blockOwnerDeletion": true,
                    }
                ]
            },
            "addressType": "IPv4",
            "ports": slice_ports,
            "endpoints": endpoints,
        });

        self.apply_endpointslice(namespace, &slice_name, matching_existing, desired_slice)
            .await
    }

    async fn extract_matching_pod_endpoints(
        &self,
        namespace: &str,
        selector: &Map<String, Value>,
    ) -> Result<(Vec<Value>, Vec<Value>), ControllerError> {
        let pod_list = self.client.list_pods(namespace).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "pods".to_string(),
                reason: e.to_string(),
            }
        })?;

        let all_pods = pod_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut endpoints = Vec::new();
        let mut matching_pods = Vec::new();
        for pod in all_pods {
            let pod_labels = pod
                .get("metadata")
                .and_then(|m| m.get("labels"))
                .and_then(Value::as_object);

            let matches = selector.iter().all(|(k, v)| {
                pod_labels
                    .and_then(|labels| labels.get(k))
                    .is_some_and(|lv| lv == v)
            });

            if !matches {
                continue;
            }

            if let Some(ep) = build_endpoint_from_pod(namespace, &pod) {
                endpoints.push(ep);
                matching_pods.push(pod);
            }
        }

        endpoints.sort_by(|a, b| {
            let a_name = a
                .pointer("/targetRef/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let b_name = b
                .pointer("/targetRef/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            a_name.cmp(b_name)
        });

        Ok((endpoints, matching_pods))
    }

    async fn apply_endpointslice(
        &self,
        namespace: &str,
        slice_name: &str,
        matching_existing: Option<Value>,
        mut desired_slice: Value,
    ) -> Result<Option<Value>, ControllerError> {
        if !self.batch_period.is_zero() {
            tokio::time::sleep(self.batch_period).await;
        }

        if let Some(existing) = matching_existing {
            let existing_eps = existing.get("endpoints").unwrap_or(&Value::Null);
            let existing_ports = existing.get("ports").unwrap_or(&Value::Null);
            let desired_eps = desired_slice.get("endpoints").unwrap_or(&Value::Null);
            let desired_ports = desired_slice.get("ports").unwrap_or(&Value::Null);

            if existing_eps == desired_eps && existing_ports == desired_ports {
                return Ok(Some(existing));
            }

            if let Some(rv) = existing
                .get("metadata")
                .and_then(|m| m.get("resourceVersion"))
                && let Some(meta) = desired_slice
                    .get_mut("metadata")
                    .and_then(Value::as_object_mut)
            {
                meta.insert("resourceVersion".to_string(), rv.clone());
            }

            let updated = self
                .client
                .update_endpointslice(namespace, slice_name, desired_slice)
                .await
                .map_err(|e| ControllerError::ReconciliationFailed {
                    resource: "endpointslices".to_string(),
                    reason: e.to_string(),
                })?;
            Ok(Some(updated))
        } else {
            let created = self
                .client
                .create_endpointslice(namespace, desired_slice)
                .await
                .map_err(|e| ControllerError::ReconciliationFailed {
                    resource: "endpointslices".to_string(),
                    reason: e.to_string(),
                })?;
            Ok(Some(created))
        }
    }
}

fn build_endpoint_from_pod(namespace: &str, pod: &Value) -> Option<Value> {
    let pname = pod
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let puid = pod
        .get("metadata")
        .and_then(|m| m.get("uid"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let node_name = pod
        .get("spec")
        .and_then(|s| s.get("nodeName"))
        .and_then(Value::as_str)
        .unwrap_or("diorama-single-node");

    let pod_ip = pod
        .get("status")
        .and_then(|s| s.get("podIP"))
        .and_then(Value::as_str)
        .or_else(|| {
            pod.get("metadata")
                .and_then(|m| m.get("annotations"))
                .and_then(|a| a.get("cni.projectcalico.org/podIP"))
                .and_then(Value::as_str)
        })?;

    let phase = pod
        .get("status")
        .and_then(|s| s.get("phase"))
        .and_then(Value::as_str)
        .unwrap_or("Pending");

    let is_terminating = pod
        .get("metadata")
        .and_then(|m| m.get("deletionTimestamp"))
        .is_some();

    let is_ready = if is_terminating {
        false
    } else if let Some(conditions) = pod
        .get("status")
        .and_then(|s| s.get("conditions"))
        .and_then(Value::as_array)
    {
        conditions.iter().any(|c| {
            c.get("type").and_then(Value::as_str) == Some("Ready")
                && c.get("status").and_then(Value::as_str) == Some("True")
        })
    } else {
        phase == "Running"
    };

    Some(json!({
        "addresses": [pod_ip],
        "conditions": {
            "ready": is_ready,
            "serving": is_ready,
            "terminating": is_terminating,
        },
        "targetRef": {
            "kind": "Pod",
            "name": pname,
            "namespace": namespace,
            "uid": puid,
        },
        "nodeName": node_name,
    }))
}

pub(crate) fn resolve_service_target_port(sp: &Value, pods: &[Value]) -> i64 {
    let fallback = sp.get("port").and_then(Value::as_i64).unwrap_or(80);
    let Some(tp) = sp.get("targetPort") else {
        return fallback;
    };
    if let Some(n) = tp.as_i64() {
        return if n > 0 { n } else { fallback };
    }
    if let Some(s) = tp.as_str() {
        if s.is_empty() || s == "0" {
            return fallback;
        }
        if let Ok(n) = s.parse::<i64>() {
            return if n > 0 { n } else { fallback };
        }
        if let Some(cp) = find_named_container_port(pods, s) {
            return cp;
        }
    }
    if let Some(obj) = tp.as_object() {
        if let Some(n) = obj.get("intVal").and_then(Value::as_i64)
            && n > 0
        {
            return n;
        }
        if let Some(s) = obj.get("strVal").and_then(Value::as_str)
            && !s.is_empty()
            && s != "0"
        {
            if let Ok(n) = s.parse::<i64>()
                && n > 0
            {
                return n;
            }
            if let Some(cp) = find_named_container_port(pods, s) {
                return cp;
            }
        }
    }
    fallback
}

fn find_named_container_port(pods: &[Value], name: &str) -> Option<i64> {
    for pod in pods {
        let Some(containers) = pod.pointer("/spec/containers").and_then(Value::as_array) else {
            continue;
        };
        for c in containers {
            let Some(ports) = c.get("ports").and_then(Value::as_array) else {
                continue;
            };
            for p in ports {
                if p.get("name").and_then(Value::as_str) == Some(name)
                    && let Some(cp) = p.get("containerPort").and_then(Value::as_i64)
                    && cp > 0
                {
                    return Some(cp);
                }
            }
        }
    }
    None
}

fn extract_service_slice_ports(service: &Value, pods: &[Value]) -> Vec<Value> {
    let service_ports = service
        .get("spec")
        .and_then(|s| s.get("ports"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut slice_ports = Vec::new();
    for sp in service_ports {
        let port_num = resolve_service_target_port(&sp, pods);
        let port_name = sp.get("name").and_then(Value::as_str).unwrap_or("");
        let protocol = sp.get("protocol").and_then(Value::as_str).unwrap_or("TCP");

        let mut port_obj = Map::new();
        port_obj.insert("name".to_string(), json!(port_name));
        port_obj.insert("port".to_string(), json!(port_num));
        port_obj.insert("protocol".to_string(), json!(protocol));
        if let Some(ap) = sp.get("appProtocol").and_then(Value::as_str) {
            port_obj.insert("appProtocol".to_string(), json!(ap));
        }
        slice_ports.push(Value::Object(port_obj));
    }
    slice_ports
}

fn is_matching_endpointslice(es: &Value, name: &str, uid: &str) -> bool {
    let labels = es.get("metadata").and_then(|m| m.get("labels"));
    let is_svc = labels
        .and_then(|l| l.get("kubernetes.io/service-name"))
        .and_then(Value::as_str)
        == Some(name);
    let is_managed = labels
        .and_then(|l| l.get("endpointslice.kubernetes.io/managed-by"))
        .and_then(Value::as_str)
        == Some("endpointslice-controller.k8s.io");

    let is_owner = if uid.is_empty() {
        true
    } else {
        es.get("metadata")
            .and_then(|m| m.get("ownerReferences"))
            .and_then(Value::as_array)
            .is_some_and(|owners| {
                owners.iter().any(|o| {
                    o.get("kind").and_then(Value::as_str) == Some("Service")
                        && o.get("uid").and_then(Value::as_str) == Some(uid)
                })
            })
    };

    is_svc && is_managed && is_owner
}
