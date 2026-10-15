use std::sync::Arc;
use std::time::Duration;

use diorama_apiserver::ApiserverError;
use diorama_apiserver::client::KubernetesApiClient;
use serde_json::{Map, Value, json};

use crate::error::ControllerError;
use crate::workload::ReconcileOutcome;

/// Reconciler for legacy `Endpoints` resources (core/v1).
///
/// Preserves upstream Kubernetes defaults: `endpoint_updates_batch_period` = 0s
/// (per KS-29 / PR #111) ensuring immediate reconciliation of backend membership changes.
#[derive(Clone, Debug)]
pub struct EndpointsReconciler {
    client: Arc<KubernetesApiClient>,
    batch_period: Duration,
}

impl EndpointsReconciler {
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

    /// Reconciles all `Endpoints` for Services in the specified namespace.
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
            match self.reconcile_service_endpoints(namespace, &svc).await {
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

    /// Reconciles `Endpoints` resources for a single `Service`.
    /// Returns `Ok(Some(endpoints))` if endpoints were managed/reconciled, or `Ok(None)` if the service has no selector.
    pub async fn reconcile_service_endpoints(
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

        let (ready_addrs, not_ready_addrs, matching_pods) = self
            .extract_matching_pod_addresses(namespace, selector)
            .await?;
        let subsets = build_subsets(service, &ready_addrs, &not_ready_addrs, &matching_pods);

        let desired_endpoints = json!({
            "apiVersion": "v1",
            "kind": "Endpoints",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    "kubernetes.io/service-name": name,
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
            "subsets": subsets,
        });

        self.apply_endpoints(namespace, name, desired_endpoints)
            .await
    }

    async fn extract_matching_pod_addresses(
        &self,
        namespace: &str,
        selector: &Map<String, Value>,
    ) -> Result<(Vec<Value>, Vec<Value>, Vec<Value>), ControllerError> {
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

        let mut ready_addresses = Vec::new();
        let mut not_ready_addresses = Vec::new();
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

            if let Some((addr_obj, is_ready)) = build_endpoint_address(namespace, &pod) {
                if is_ready {
                    ready_addresses.push(addr_obj);
                } else {
                    not_ready_addresses.push(addr_obj);
                }
                matching_pods.push(pod);
            }
        }

        sort_addresses(&mut ready_addresses);
        sort_addresses(&mut not_ready_addresses);

        Ok((ready_addresses, not_ready_addresses, matching_pods))
    }

    async fn apply_endpoints(
        &self,
        namespace: &str,
        name: &str,
        mut desired_endpoints: Value,
    ) -> Result<Option<Value>, ControllerError> {
        if !self.batch_period.is_zero() {
            tokio::time::sleep(self.batch_period).await;
        }

        let existing = match self.client.get_endpoints(namespace, name).await {
            Ok(v) => Some(v),
            Err(ApiserverError::NotFound { .. }) => None,
            Err(e) => {
                return Err(ControllerError::ReconciliationFailed {
                    resource: "endpoints".to_string(),
                    reason: e.to_string(),
                });
            },
        };

        if let Some(existing) = existing {
            let existing_subsets = existing.get("subsets").unwrap_or(&Value::Null);
            let desired_subsets = desired_endpoints.get("subsets").unwrap_or(&Value::Null);

            if existing_subsets == desired_subsets {
                return Ok(Some(existing));
            }

            if let Some(rv) = existing
                .get("metadata")
                .and_then(|m| m.get("resourceVersion"))
                && let Some(meta) = desired_endpoints
                    .get_mut("metadata")
                    .and_then(Value::as_object_mut)
            {
                meta.insert("resourceVersion".to_string(), rv.clone());
            }

            let updated = self
                .client
                .update_endpoints(namespace, name, desired_endpoints)
                .await
                .map_err(|e| ControllerError::ReconciliationFailed {
                    resource: "endpoints".to_string(),
                    reason: e.to_string(),
                })?;
            Ok(Some(updated))
        } else {
            let created = self
                .client
                .create_endpoints(namespace, desired_endpoints)
                .await
                .map_err(|e| ControllerError::ReconciliationFailed {
                    resource: "endpoints".to_string(),
                    reason: e.to_string(),
                })?;
            Ok(Some(created))
        }
    }
}

fn build_endpoint_address(namespace: &str, pod: &Value) -> Option<(Value, bool)> {
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

    let addr_obj = json!({
        "ip": pod_ip,
        "targetRef": {
            "kind": "Pod",
            "name": pname,
            "namespace": namespace,
            "uid": puid,
        },
        "nodeName": node_name,
    });

    Some((addr_obj, is_ready))
}

fn sort_addresses(addrs: &mut [Value]) {
    addrs.sort_by(|a, b| {
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
}

struct EndpointGroup {
    ready: Vec<Value>,
    not_ready: Vec<Value>,
    ports: Vec<Value>,
}

/// Packs addresses into subsets keyed by the port set each pod resolves to.
fn build_subsets(
    service: &Value,
    ready: &[Value],
    not_ready: &[Value],
    pods: &[Value],
) -> Vec<Value> {
    use std::collections::BTreeMap;

    let pod_for = |addr: &Value| -> Option<&Value> {
        let name = addr.pointer("/targetRef/name").and_then(Value::as_str)?;
        pods.iter()
            .find(|p| p.pointer("/metadata/name").and_then(Value::as_str) == Some(name))
    };

    let mut groups: BTreeMap<String, EndpointGroup> = BTreeMap::new();
    for (addrs, is_ready) in [(ready, true), (not_ready, false)] {
        for addr in addrs {
            let pod_slice: Vec<Value> = pod_for(addr).cloned().into_iter().collect();
            let ports = extract_service_endpoints_ports(service, &pod_slice);
            let key = serde_json::to_string(&ports).unwrap_or_default();
            let entry = groups.entry(key).or_insert_with(|| EndpointGroup {
                ready: Vec::new(),
                not_ready: Vec::new(),
                ports,
            });
            if is_ready {
                entry.ready.push(addr.clone());
            } else {
                entry.not_ready.push(addr.clone());
            }
        }
    }
    groups
        .into_values()
        .map(|grp| {
            let mut subset = Map::new();
            if !grp.ready.is_empty() {
                subset.insert("addresses".to_string(), Value::Array(grp.ready));
            }
            if !grp.not_ready.is_empty() {
                subset.insert("notReadyAddresses".to_string(), Value::Array(grp.not_ready));
            }
            subset.insert("ports".to_string(), Value::Array(grp.ports));
            Value::Object(subset)
        })
        .collect()
}

fn extract_service_endpoints_ports(service: &Value, pods: &[Value]) -> Vec<Value> {
    let service_ports = service
        .get("spec")
        .and_then(|s| s.get("ports"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut ports = Vec::new();
    for sp in service_ports {
        let port_num = super::endpointslice::resolve_service_target_port(&sp, pods);
        let port_name = sp.get("name").and_then(Value::as_str);
        let protocol = sp.get("protocol").and_then(Value::as_str).unwrap_or("TCP");

        let mut port_obj = Map::new();
        port_obj.insert("port".to_string(), json!(port_num));
        port_obj.insert("protocol".to_string(), json!(protocol));
        if let Some(pn) = port_name {
            port_obj.insert("name".to_string(), json!(pn));
        }
        if let Some(ap) = sp.get("appProtocol").and_then(Value::as_str) {
            port_obj.insert("appProtocol".to_string(), json!(ap));
        }
        ports.push(Value::Object(port_obj));
    }
    ports
}
