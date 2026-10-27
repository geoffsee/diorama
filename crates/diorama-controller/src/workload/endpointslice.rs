use std::sync::Arc;
use std::time::Duration;

use diorama_apiserver::ApiserverError;
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

pub const LABEL_SERVICE_NAME: &str = "kubernetes.io/service-name";
pub const LABEL_MANAGED_BY: &str = "endpointslice.kubernetes.io/managed-by";
pub const LABEL_SKIP_MIRROR: &str = "endpointslice.kubernetes.io/skip-mirror";
pub const MANAGED_BY_CONTROLLER: &str = "endpointslice-controller.k8s.io";
pub const MANAGED_BY_MIRROR: &str = "endpointslicemirroring-controller.k8s.io";

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

    /// Reconciles all `EndpointSlices` for Services in the specified namespace,
    /// as well as mirrored `EndpointSlices` for custom `Endpoints`.
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

        match self.reconcile_mirrored_endpoints(namespace).await {
            Ok(mirrored) => count += mirrored,
            Err(err) => errors.push(err.to_string()),
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

        let publish_not_ready = service
            .pointer("/spec/publishNotReadyAddresses")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| {
                service
                    .pointer("/metadata/annotations/service.alpha.kubernetes.io~1tolerate-unready-endpoints")
                    .and_then(Value::as_str)
                    == Some("true")
            });

        let (endpoints, matching_pods) = self
            .extract_matching_pod_endpoints(namespace, selector, publish_not_ready)
            .await?;
        let groups = build_service_slice_groups(service, &endpoints, &matching_pods);

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

        let existing_managed: Vec<Value> = existing_items
            .into_iter()
            .filter(|es| is_matching_endpointslice(es, name, uid))
            .collect();

        let (assignments, excess_names) =
            assign_slice_groups_to_existing(name, &groups, &existing_managed);

        for excess in excess_names {
            let _ = self.client.delete_endpointslice(namespace, &excess).await;
        }

        let mut primary_result = None;
        for assign in assignments {
            let desired_slice = json!({
                "apiVersion": "discovery.k8s.io/v1",
                "kind": "EndpointSlice",
                "metadata": {
                    "name": assign.slice_name,
                    "namespace": namespace,
                    "labels": {
                        LABEL_SERVICE_NAME: name,
                        LABEL_MANAGED_BY: MANAGED_BY_CONTROLLER,
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
                "ports": assign.group.ports,
                "endpoints": assign.group.endpoints,
            });

            let res = self
                .apply_endpointslice(
                    namespace,
                    &assign.slice_name,
                    assign.existing,
                    desired_slice,
                )
                .await?;
            if primary_result.is_none() {
                primary_result = res;
            }
        }

        Ok(primary_result)
    }

    /// Reconciles all mirrored `EndpointSlice` objects for custom `Endpoints` resources.
    pub async fn reconcile_mirrored_endpoints(
        &self,
        namespace: &str,
    ) -> Result<usize, ControllerError> {
        let ep_list = match self.client.list_endpoints(namespace).await {
            Ok(v) => v,
            Err(e) => {
                return Err(ControllerError::ReconciliationFailed {
                    resource: "endpoints".to_string(),
                    reason: e.to_string(),
                });
            },
        };

        let ep_items = ep_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let svc_list = self.client.list_services(namespace).await.map_err(|e| {
            ControllerError::ReconciliationFailed {
                resource: "services".to_string(),
                reason: e.to_string(),
            }
        })?;
        let svc_items = svc_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        // Track services with non-empty selectors
        let mut selector_services = std::collections::HashSet::new();
        for svc in &svc_items {
            let name = svc
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let has_selector = svc
                .pointer("/spec/selector")
                .and_then(Value::as_object)
                .is_some_and(|sel| !sel.is_empty());
            if has_selector {
                selector_services.insert(name.to_string());
            }
        }

        let mut mirrored_count = 0;
        let mut active_mirrored_names = std::collections::HashSet::new();

        for ep in &ep_items {
            let ep_name = ep
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            if ep_name.is_empty() || selector_services.contains(ep_name) {
                continue;
            }

            // Skip mirror label check
            let skip_mirror = ep
                .pointer("/metadata/labels/endpointslice.kubernetes.io~1skip-mirror")
                .and_then(Value::as_str)
                == Some("true");
            if skip_mirror {
                continue;
            }

            // Leader election annotation check
            let is_leader_election = ep
                .pointer("/metadata/annotations/control-plane.alpha.kubernetes.io~1leader")
                .is_some();
            if is_leader_election {
                continue;
            }

            if self
                .reconcile_endpoints_mirror(namespace, ep)
                .await?
                .is_some()
            {
                mirrored_count += 1;
                active_mirrored_names.insert(ep_name.to_string());
            }
        }

        // Clean up orphaned mirrored EndpointSlices whose parent Endpoints no longer exist or skip-mirror
        if let Ok(slice_list) = self.client.list_endpointslices(namespace).await
            && let Some(slices) = slice_list.get("items").and_then(Value::as_array)
        {
            for slice in slices {
                let managed_by = slice
                    .pointer("/metadata/labels/endpointslice.kubernetes.io~1managed-by")
                    .and_then(Value::as_str);
                if managed_by != Some(MANAGED_BY_MIRROR) {
                    continue;
                }
                let svc_name = slice
                    .pointer("/metadata/labels/kubernetes.io~1service-name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let slice_name = slice
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");

                if !active_mirrored_names.contains(svc_name) && !slice_name.is_empty() {
                    let _ = self
                        .client
                        .delete_endpointslice(namespace, slice_name)
                        .await;
                }
            }
        }

        Ok(mirrored_count)
    }

    /// Reconciles an individual custom `Endpoints` resource into a mirrored `EndpointSlice`.
    pub async fn reconcile_endpoints_mirror(
        &self,
        namespace: &str,
        endpoints: &Value,
    ) -> Result<Option<Value>, ControllerError> {
        let ep_name = endpoints
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .ok_or_else(|| ControllerError::InvalidConfiguration {
                field: "metadata.name".to_string(),
                reason: "Endpoints missing metadata.name".to_string(),
            })?;
        let ep_uid = endpoints
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or("");

        let subsets = endpoints
            .get("subsets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let ports = extract_subset_ports(&subsets);
        let slice_endpoints = extract_subset_endpoints(&subsets);

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

        let has_manual_slice = existing_items.iter().any(|es| {
            let labels = es.get("metadata").and_then(|m| m.get("labels"));
            let is_svc = labels
                .and_then(|l| l.get(LABEL_SERVICE_NAME))
                .and_then(Value::as_str)
                == Some(ep_name);
            let managed_by = labels
                .and_then(|l| l.get(LABEL_MANAGED_BY))
                .and_then(Value::as_str);
            is_svc && managed_by != Some(MANAGED_BY_MIRROR)
        });
        if has_manual_slice {
            return Ok(None);
        }

        let matching_existing = existing_items.into_iter().find(|es| {
            let labels = es.get("metadata").and_then(|m| m.get("labels"));
            let is_svc = labels
                .and_then(|l| l.get(LABEL_SERVICE_NAME))
                .and_then(Value::as_str)
                == Some(ep_name);
            let is_mirror = labels
                .and_then(|l| l.get(LABEL_MANAGED_BY))
                .and_then(Value::as_str)
                == Some(MANAGED_BY_MIRROR);
            is_svc && is_mirror
        });

        let slice_name = matching_existing
            .as_ref()
            .and_then(|es| es.pointer("/metadata/name"))
            .and_then(Value::as_str)
            .map_or_else(|| format!("{ep_name}-1"), ToString::to_string);

        let desired_slice = json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": slice_name,
                "namespace": namespace,
                "labels": {
                    LABEL_SERVICE_NAME: ep_name,
                    LABEL_MANAGED_BY: MANAGED_BY_MIRROR,
                },
                "ownerReferences": [
                    {
                        "apiVersion": "v1",
                        "kind": "Endpoints",
                        "name": ep_name,
                        "uid": ep_uid,
                        "controller": true,
                        "blockOwnerDeletion": true,
                    }
                ]
            },
            "addressType": "IPv4",
            "ports": ports,
            "endpoints": slice_endpoints,
        });

        self.apply_endpointslice(namespace, &slice_name, matching_existing, desired_slice)
            .await
    }

    async fn extract_matching_pod_endpoints(
        &self,
        namespace: &str,
        selector: &Map<String, Value>,
        publish_not_ready: bool,
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

            if let Some(ep) = build_endpoint_from_pod(namespace, &pod, publish_not_ready) {
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

        let existing = if let Some(existing) = matching_existing {
            Some(existing)
        } else {
            match self.client.get_endpointslice(namespace, slice_name).await {
                Ok(v) => Some(v),
                Err(ApiserverError::NotFound { .. }) => None,
                Err(e) => {
                    return Err(ControllerError::ReconciliationFailed {
                        resource: "endpointslices".to_string(),
                        reason: e.to_string(),
                    });
                },
            }
        };

        if let Some(existing) = existing {
            let existing_managed = existing
                .pointer("/metadata/labels/endpointslice.kubernetes.io~1managed-by")
                .and_then(Value::as_str);
            let desired_managed = desired_slice
                .pointer("/metadata/labels/endpointslice.kubernetes.io~1managed-by")
                .and_then(Value::as_str);

            if existing_managed != desired_managed {
                return Ok(Some(existing));
            }

            let existing_eps = existing.get("endpoints").unwrap_or(&Value::Null);
            let existing_ports = existing.get("ports").unwrap_or(&Value::Null);
            let desired_eps = desired_slice.get("endpoints").unwrap_or(&Value::Null);
            let desired_ports = desired_slice.get("ports").unwrap_or(&Value::Null);
            let existing_owners = existing
                .pointer("/metadata/ownerReferences")
                .unwrap_or(&Value::Null);
            let desired_owners = desired_slice
                .pointer("/metadata/ownerReferences")
                .unwrap_or(&Value::Null);

            if existing_eps == desired_eps
                && existing_ports == desired_ports
                && existing_owners == desired_owners
            {
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

fn build_endpoint_from_pod(namespace: &str, pod: &Value, publish_not_ready: bool) -> Option<Value> {
    let phase = pod
        .get("status")
        .and_then(|s| s.get("phase"))
        .and_then(Value::as_str)
        .unwrap_or("Pending");

    if phase == "Failed" || phase == "Succeeded" {
        return None;
    }

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

    let is_terminating = pod
        .get("metadata")
        .and_then(|m| m.get("deletionTimestamp"))
        .is_some();

    let has_ready_condition = if let Some(conditions) = pod
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

    let is_ready = if publish_not_ready {
        true
    } else if is_terminating {
        false
    } else {
        has_ready_condition
    };

    let is_serving = if publish_not_ready {
        true
    } else {
        has_ready_condition
    };

    let mut ep = json!({
        "addresses": [pod_ip],
        "conditions": {
            "ready": is_ready,
            "serving": is_serving,
            "terminating": is_terminating,
        },
        "targetRef": {
            "kind": "Pod",
            "name": pname,
            "namespace": namespace,
            "uid": puid,
        },
        "nodeName": node_name,
    });

    if let Some(hostname) = pod
        .pointer("/spec/hostname")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        && let Some(obj) = ep.as_object_mut()
    {
        obj.insert("hostname".to_string(), json!(hostname));
    }

    Some(ep)
}

pub(crate) fn resolve_service_target_port(sp: &Value, pods: &[Value]) -> i64 {
    let fallback = sp.get("port").and_then(Value::as_i64).unwrap_or(80);
    let protocol = sp.get("protocol").and_then(Value::as_str).unwrap_or("TCP");
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
        if let Some(cp) = find_named_container_port(pods, s, protocol) {
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
            if let Some(cp) = find_named_container_port(pods, s, protocol) {
                return cp;
            }
        }
    }
    fallback
}

pub(crate) fn resolve_target_port_for_pod(sp: &Value, pod: &Value) -> Option<i64> {
    let fallback = sp.get("port").and_then(Value::as_i64).unwrap_or(80);
    let protocol = sp.get("protocol").and_then(Value::as_str).unwrap_or("TCP");
    let Some(tp) = sp.get("targetPort") else {
        return Some(fallback);
    };
    if let Some(n) = tp.as_i64() {
        return Some(if n > 0 { n } else { fallback });
    }
    if let Some(s) = tp.as_str() {
        if s.is_empty() || s == "0" {
            return Some(fallback);
        }
        if let Ok(n) = s.parse::<i64>() {
            return Some(if n > 0 { n } else { fallback });
        }
        return find_named_container_port(std::slice::from_ref(pod), s, protocol);
    }
    if let Some(obj) = tp.as_object() {
        if let Some(n) = obj.get("intVal").and_then(Value::as_i64)
            && n > 0
        {
            return Some(n);
        }
        if let Some(s) = obj.get("strVal").and_then(Value::as_str)
            && !s.is_empty()
            && s != "0"
        {
            if let Ok(n) = s.parse::<i64>()
                && n > 0
            {
                return Some(n);
            }
            return find_named_container_port(std::slice::from_ref(pod), s, protocol);
        }
    }
    Some(fallback)
}

fn match_container_port(p: &Value, name: &str, protocol: &str) -> Option<i64> {
    if p.get("name").and_then(Value::as_str) != Some(name) {
        return None;
    }
    let p_proto = p.get("protocol").and_then(Value::as_str).unwrap_or("TCP");
    if !p_proto.eq_ignore_ascii_case(protocol) {
        return None;
    }
    p.get("containerPort")
        .and_then(Value::as_i64)
        .filter(|&cp| cp > 0)
}

fn find_named_container_port(pods: &[Value], name: &str, protocol: &str) -> Option<i64> {
    for pod in pods {
        let containers = pod.pointer("/spec/containers").and_then(Value::as_array);
        let init_containers = pod
            .pointer("/spec/initContainers")
            .and_then(Value::as_array);

        let all_containers = containers.into_iter().chain(init_containers).flatten();

        for c in all_containers {
            let Some(ports) = c.get("ports").and_then(Value::as_array) else {
                continue;
            };
            for p in ports {
                if let Some(cp) = match_container_port(p, name, protocol) {
                    return Some(cp);
                }
            }
        }
    }
    None
}

#[derive(Clone, Debug)]
struct ServiceSliceGroup {
    ports: Vec<Value>,
    endpoints: Vec<Value>,
}

fn extract_service_slice_ports_for_pod(service: &Value, pod: &Value) -> Option<Vec<Value>> {
    let service_ports = service
        .get("spec")
        .and_then(|s| s.get("ports"))
        .and_then(Value::as_array)?;

    let mut slice_ports = Vec::new();
    for sp in service_ports {
        let port_num = resolve_target_port_for_pod(sp, pod)?;
        let port_name = sp.get("name").and_then(Value::as_str);
        let protocol = sp.get("protocol").and_then(Value::as_str).unwrap_or("TCP");

        let mut port_obj = Map::new();
        port_obj.insert("name".to_string(), json!(port_name.unwrap_or("")));
        port_obj.insert("port".to_string(), json!(port_num));
        port_obj.insert("protocol".to_string(), json!(protocol));
        if let Some(ap) = sp.get("appProtocol").and_then(Value::as_str) {
            port_obj.insert("appProtocol".to_string(), json!(ap));
        }
        slice_ports.push(Value::Object(port_obj));
    }
    Some(slice_ports)
}

fn build_service_slice_groups(
    service: &Value,
    endpoints: &[Value],
    matching_pods: &[Value],
) -> Vec<ServiceSliceGroup> {
    use std::collections::BTreeMap;

    if endpoints.is_empty() {
        let ports = extract_service_slice_ports(service, &[]);
        return vec![ServiceSliceGroup {
            ports,
            endpoints: Vec::new(),
        }];
    }

    let pod_for = |ep: &Value| -> Option<&Value> {
        let name = ep.pointer("/targetRef/name").and_then(Value::as_str)?;
        matching_pods
            .iter()
            .find(|p| p.pointer("/metadata/name").and_then(Value::as_str) == Some(name))
    };

    let mut groups: BTreeMap<String, ServiceSliceGroup> = BTreeMap::new();
    for ep in endpoints {
        let Some(pod) = pod_for(ep) else {
            continue;
        };
        let Some(ports) = extract_service_slice_ports_for_pod(service, pod) else {
            continue;
        };
        let key = serde_json::to_string(&ports).unwrap_or_default();
        let entry = groups.entry(key).or_insert_with(|| ServiceSliceGroup {
            ports,
            endpoints: Vec::new(),
        });
        entry.endpoints.push(ep.clone());
    }

    if groups.is_empty() {
        let ports = extract_service_slice_ports(service, &[]);
        return vec![ServiceSliceGroup {
            ports,
            endpoints: Vec::new(),
        }];
    }

    groups.into_values().collect()
}

struct SliceAssignment {
    group: ServiceSliceGroup,
    existing: Option<Value>,
    slice_name: String,
}

fn assign_slice_groups_to_existing(
    name: &str,
    groups: &[ServiceSliceGroup],
    existing_managed: &[Value],
) -> (Vec<SliceAssignment>, Vec<String>) {
    let mut assignments = Vec::new();
    let mut used_existing = std::collections::HashSet::new();
    let mut used_names = std::collections::HashSet::new();

    // Pass 1: exact ports match
    for group in groups {
        let g_ports_json = serde_json::to_string(&group.ports).unwrap_or_default();
        for (idx, existing) in existing_managed.iter().enumerate() {
            if used_existing.contains(&idx) {
                continue;
            }
            let e_ports = existing.get("ports").unwrap_or(&Value::Null);
            let e_ports_json = serde_json::to_string(e_ports).unwrap_or_default();
            if g_ports_json == e_ports_json {
                let sname = existing
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                used_existing.insert(idx);
                used_names.insert(sname.clone());
                assignments.push(SliceAssignment {
                    group: group.clone(),
                    existing: Some(existing.clone()),
                    slice_name: sname,
                });
                break;
            }
        }
    }

    // Pass 2: remaining groups match to remaining existing slices or allocate new name
    for group in groups {
        let already_matched = assignments.iter().any(|a| {
            serde_json::to_string(&a.group.ports).unwrap_or_default()
                == serde_json::to_string(&group.ports).unwrap_or_default()
        });
        if already_matched {
            continue;
        }

        let unused_existing = existing_managed
            .iter()
            .enumerate()
            .find(|(idx, _)| !used_existing.contains(idx));

        if let Some((idx, existing)) = unused_existing {
            let sname = existing
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            used_existing.insert(idx);
            used_names.insert(sname.clone());
            assignments.push(SliceAssignment {
                group: group.clone(),
                existing: Some(existing.clone()),
                slice_name: sname,
            });
        } else {
            let candidate = find_next_slice_name(name, &used_names);
            used_names.insert(candidate.clone());
            assignments.push(SliceAssignment {
                group: group.clone(),
                existing: None,
                slice_name: candidate,
            });
        }
    }

    let mut excess_names = Vec::new();
    for (idx, existing) in existing_managed.iter().enumerate() {
        if !used_existing.contains(&idx)
            && let Some(sname) = existing.pointer("/metadata/name").and_then(Value::as_str)
        {
            excess_names.push(sname.to_string());
        }
    }

    (assignments, excess_names)
}

fn find_next_slice_name(name: &str, used_names: &std::collections::HashSet<String>) -> String {
    let mut n = 1;
    let mut candidate = format!("{name}-{n}");
    while used_names.contains(&candidate) {
        n += 1;
        candidate = format!("{name}-{n}");
    }
    candidate
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
        let port_name = sp.get("name").and_then(Value::as_str);
        let protocol = sp.get("protocol").and_then(Value::as_str).unwrap_or("TCP");

        let mut port_obj = Map::new();
        port_obj.insert("name".to_string(), json!(port_name.unwrap_or("")));
        port_obj.insert("port".to_string(), json!(port_num));
        port_obj.insert("protocol".to_string(), json!(protocol));
        if let Some(ap) = sp.get("appProtocol").and_then(Value::as_str) {
            port_obj.insert("appProtocol".to_string(), json!(ap));
        }
        slice_ports.push(Value::Object(port_obj));
    }
    slice_ports
}

fn parse_subset_port(p: &Value) -> (String, Value) {
    let port_name = p.get("name").and_then(Value::as_str).unwrap_or("");
    let protocol = p.get("protocol").and_then(Value::as_str).unwrap_or("TCP");
    let port_num = p.get("port").and_then(Value::as_i64).unwrap_or(80);
    let key = format!("{port_name}:{protocol}");

    let mut p_obj = Map::new();
    p_obj.insert("name".to_string(), json!(port_name));
    p_obj.insert("port".to_string(), json!(port_num));
    p_obj.insert("protocol".to_string(), json!(protocol));
    if let Some(ap) = p.get("appProtocol").and_then(Value::as_str) {
        p_obj.insert("appProtocol".to_string(), json!(ap));
    }
    (key, Value::Object(p_obj))
}

fn extract_subset_ports(subsets: &[Value]) -> Vec<Value> {
    let mut ports_map: std::collections::BTreeMap<String, Value> =
        std::collections::BTreeMap::new();
    for subset in subsets {
        let Some(ports) = subset.get("ports").and_then(Value::as_array) else {
            continue;
        };
        for p in ports {
            let (key, val) = parse_subset_port(p);
            ports_map.insert(key, val);
        }
    }
    ports_map.into_values().collect()
}

fn make_mirror_endpoint(addr: &Value, ready: bool) -> Option<Value> {
    let ip = addr.get("ip").and_then(Value::as_str)?;
    let mut ep_obj = Map::new();
    ep_obj.insert("addresses".to_string(), json!([ip]));
    ep_obj.insert(
        "conditions".to_string(),
        json!({
            "ready": ready,
            "serving": ready,
            "terminating": false,
        }),
    );
    if let Some(nn) = addr.get("nodeName") {
        ep_obj.insert("nodeName".to_string(), nn.clone());
    }
    if let Some(tr) = addr.get("targetRef") {
        ep_obj.insert("targetRef".to_string(), tr.clone());
    }
    if let Some(hn) = addr.get("hostname") {
        ep_obj.insert("hostname".to_string(), hn.clone());
    }
    Some(Value::Object(ep_obj))
}

fn extract_subset_endpoints(subsets: &[Value]) -> Vec<Value> {
    let mut slice_endpoints = Vec::new();
    for subset in subsets {
        if let Some(addresses) = subset.get("addresses").and_then(Value::as_array) {
            for addr in addresses {
                if let Some(ep) = make_mirror_endpoint(addr, true) {
                    slice_endpoints.push(ep);
                }
            }
        }
        if let Some(not_ready) = subset.get("notReadyAddresses").and_then(Value::as_array) {
            for addr in not_ready {
                if let Some(ep) = make_mirror_endpoint(addr, false) {
                    slice_endpoints.push(ep);
                }
            }
        }
    }
    slice_endpoints.sort_by(|a, b| {
        let a_ip = a
            .pointer("/addresses/0")
            .and_then(Value::as_str)
            .unwrap_or("");
        let b_ip = b
            .pointer("/addresses/0")
            .and_then(Value::as_str)
            .unwrap_or("");
        a_ip.cmp(b_ip)
    });
    slice_endpoints
}

fn is_matching_endpointslice(es: &Value, name: &str, uid: &str) -> bool {
    let labels = es.get("metadata").and_then(|m| m.get("labels"));
    let is_svc = labels
        .and_then(|l| l.get(LABEL_SERVICE_NAME))
        .and_then(Value::as_str)
        == Some(name);
    let is_managed = labels
        .and_then(|l| l.get(LABEL_MANAGED_BY))
        .and_then(Value::as_str)
        == Some(MANAGED_BY_CONTROLLER);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_endpoint_conditions_ready_serving_terminating() {
        let ready_pod = json!({
            "metadata": { "name": "pod-1", "uid": "uid-1" },
            "status": {
                "phase": "Running",
                "podIP": "10.42.0.10",
                "conditions": [{ "type": "Ready", "status": "True" }]
            }
        });
        let unready_pod = json!({
            "metadata": { "name": "pod-2", "uid": "uid-2" },
            "status": {
                "phase": "Running",
                "podIP": "10.42.0.11",
                "conditions": [{ "type": "Ready", "status": "False" }]
            }
        });
        let terminating_ready_pod = json!({
            "metadata": {
                "name": "pod-3",
                "uid": "uid-3",
                "deletionTimestamp": "2026-10-15T00:00:00Z"
            },
            "status": {
                "phase": "Running",
                "podIP": "10.42.0.12",
                "conditions": [{ "type": "Ready", "status": "True" }]
            }
        });

        let ep1 = build_endpoint_from_pod("default", &ready_pod, false).expect("ep1");
        assert_eq!(ep1["conditions"]["ready"], true);
        assert_eq!(ep1["conditions"]["serving"], true);
        assert_eq!(ep1["conditions"]["terminating"], false);

        let ep2 = build_endpoint_from_pod("default", &unready_pod, false).expect("ep2");
        assert_eq!(ep2["conditions"]["ready"], false);
        assert_eq!(ep2["conditions"]["serving"], false);
        assert_eq!(ep2["conditions"]["terminating"], false);

        // Terminating pod: ready=false, serving=true (while gracefully shutting down), terminating=true
        let ep3 = build_endpoint_from_pod("default", &terminating_ready_pod, false).expect("ep3");
        assert_eq!(ep3["conditions"]["ready"], false);
        assert_eq!(ep3["conditions"]["serving"], true);
        assert_eq!(ep3["conditions"]["terminating"], true);
    }

    #[test]
    fn test_build_endpoint_publish_not_ready_addresses() {
        let unready_pod = json!({
            "metadata": { "name": "pod-unready", "uid": "uid-unready" },
            "status": {
                "phase": "Running",
                "podIP": "10.42.0.15",
                "conditions": [{ "type": "Ready", "status": "False" }]
            }
        });

        let ep = build_endpoint_from_pod("default", &unready_pod, true).expect("ep");
        assert_eq!(ep["conditions"]["ready"], true);
        assert_eq!(ep["conditions"]["serving"], true);
        assert_eq!(ep["conditions"]["terminating"], false);
    }

    #[test]
    fn test_resolve_service_target_port_protocol_and_named() {
        let pods = vec![json!({
            "metadata": { "name": "pod-app" },
            "spec": {
                "containers": [{
                    "name": "server",
                    "ports": [
                        { "name": "dns-tcp", "containerPort": 5353, "protocol": "TCP" },
                        { "name": "dns-udp", "containerPort": 53, "protocol": "UDP" },
                        { "name": "web", "containerPort": 8080 }
                    ]
                }]
            }
        })];

        // 1. Numeric target port
        let sp_num = json!({ "port": 80, "targetPort": 9000, "protocol": "TCP" });
        assert_eq!(resolve_service_target_port(&sp_num, &pods), 9000);

        // 2. Named target port TCP
        let sp_tcp = json!({ "port": 53, "targetPort": "dns-tcp", "protocol": "TCP" });
        assert_eq!(resolve_service_target_port(&sp_tcp, &pods), 5353);

        // 3. Named target port UDP
        let sp_udp = json!({ "port": 53, "targetPort": "dns-udp", "protocol": "UDP" });
        assert_eq!(resolve_service_target_port(&sp_udp, &pods), 53);

        // 4. Default container port protocol is TCP
        let sp_web = json!({ "port": 80, "targetPort": "web", "protocol": "TCP" });
        assert_eq!(resolve_service_target_port(&sp_web, &pods), 8080);

        // 5. Unmatched named port falls back to service port
        let sp_missing = json!({ "port": 7777, "targetPort": "nonexistent", "protocol": "TCP" });
        assert_eq!(resolve_service_target_port(&sp_missing, &pods), 7777);
    }

    #[test]
    fn test_extract_service_slice_ports_multi_port() {
        let svc = json!({
            "spec": {
                "ports": [
                    { "name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP", "appProtocol": "http" },
                    { "name": "https", "port": 443, "targetPort": 8443, "protocol": "TCP" }
                ]
            }
        });

        let ports = extract_service_slice_ports(&svc, &[]);
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0]["name"], "http");
        assert_eq!(ports[0]["port"], 8080);
        assert_eq!(ports[0]["appProtocol"], "http");
        assert_eq!(ports[1]["name"], "https");
        assert_eq!(ports[1]["port"], 8443);
    }

    #[test]
    fn test_extract_service_slice_ports_unnamed_port() {
        let svc = json!({
            "spec": {
                "ports": [{ "port": 80, "protocol": "TCP" }]
            }
        });
        let ports = extract_service_slice_ports(&svc, &[]);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0]["name"], "");
        assert_eq!(ports[0]["port"], 80);
    }

    #[test]
    fn test_custom_endpoints_mirroring_constants_and_label_parity() {
        assert_eq!(LABEL_SERVICE_NAME, "kubernetes.io/service-name");
        assert_eq!(LABEL_MANAGED_BY, "endpointslice.kubernetes.io/managed-by");
        assert_eq!(LABEL_SKIP_MIRROR, "endpointslice.kubernetes.io/skip-mirror");
        assert_eq!(MANAGED_BY_CONTROLLER, "endpointslice-controller.k8s.io");
        assert_eq!(
            MANAGED_BY_MIRROR,
            "endpointslicemirroring-controller.k8s.io"
        );
    }

    #[test]
    fn test_is_matching_endpointslice_identifies_controller_and_service() {
        let matching = json!({
            "metadata": {
                "name": "svc-1",
                "labels": {
                    "kubernetes.io/service-name": "svc",
                    "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
                },
                "ownerReferences": [{
                    "kind": "Service",
                    "uid": "uid-100"
                }]
            }
        });
        assert!(is_matching_endpointslice(&matching, "svc", "uid-100"));
        assert!(!is_matching_endpointslice(
            &matching,
            "other-svc",
            "uid-100"
        ));
        assert!(!is_matching_endpointslice(
            &matching,
            "svc",
            "different-uid"
        ));

        let non_managed = json!({
            "metadata": {
                "name": "svc-1",
                "labels": {
                    "kubernetes.io/service-name": "svc",
                    "endpointslice.kubernetes.io/managed-by": "custom-controller.k8s.io",
                }
            }
        });
        assert!(!is_matching_endpointslice(&non_managed, "svc", ""));
    }

    #[test]
    fn test_build_endpoint_with_hostname() {
        let pod = json!({
            "metadata": { "name": "pod-h", "uid": "uid-h" },
            "spec": {
                "hostname": "pod-hostname",
                "subdomain": "different-subdomain",
                "nodeName": "node-worker"
            },
            "status": {
                "phase": "Running",
                "podIP": "10.42.0.88",
                "conditions": [{ "type": "Ready", "status": "True" }]
            }
        });

        let ep = build_endpoint_from_pod("default", &pod, false).expect("ep");
        assert_eq!(ep["hostname"], "pod-hostname");
        assert_eq!(ep["addresses"][0], "10.42.0.88");
        assert_eq!(ep["nodeName"], "node-worker");
    }

    #[test]
    fn test_build_service_slice_groups_partitions_by_resolved_pod_ports() {
        let svc = json!({
            "metadata": { "name": "my-svc" },
            "spec": {
                "ports": [{ "name": "port100", "port": 80, "targetPort": "port100", "protocol": "TCP" }]
            }
        });

        let pod1 = json!({
            "metadata": { "name": "pod-1" },
            "spec": {
                "containers": [{
                    "ports": [{ "name": "port100", "containerPort": 100, "protocol": "TCP" }]
                }]
            }
        });
        let pod2 = json!({
            "metadata": { "name": "pod-2" },
            "spec": {
                "containers": [{
                    "ports": [{ "name": "port100", "containerPort": 101, "protocol": "TCP" }]
                }]
            }
        });

        let ep1 = json!({
            "addresses": ["10.42.0.1"],
            "targetRef": { "kind": "Pod", "name": "pod-1" }
        });
        let ep2 = json!({
            "addresses": ["10.42.0.2"],
            "targetRef": { "kind": "Pod", "name": "pod-2" }
        });

        let groups = build_service_slice_groups(&svc, &[ep1, ep2], &[pod1, pod2]);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].ports[0]["port"], 100);
        assert_eq!(groups[0].endpoints.len(), 1);
        assert_eq!(groups[0].endpoints[0]["targetRef"]["name"], "pod-1");

        assert_eq!(groups[1].ports[0]["port"], 101);
        assert_eq!(groups[1].endpoints.len(), 1);
        assert_eq!(groups[1].endpoints[0]["targetRef"]["name"], "pod-2");
    }
}
