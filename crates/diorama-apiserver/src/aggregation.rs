use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::admission::ServiceReference;
use crate::error::ApiserverError;
use crate::storage::KubernetesStorage;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct APIServiceSpec {
    pub group: String,
    pub version: String,
    #[serde(rename = "groupPriorityMinimum")]
    pub group_priority_minimum: i32,
    #[serde(rename = "versionPriority")]
    pub version_priority: i32,
    pub service: Option<ServiceReference>,
    #[serde(rename = "caBundle")]
    pub ca_bundle: Option<String>,
    #[serde(rename = "insecureSkipTLSVerify")]
    pub insecure_skip_tls_verify: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct APIServiceCondition {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
    #[serde(rename = "lastTransitionTime", skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct APIServiceStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<APIServiceCondition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct APIService {
    pub metadata: BTreeMap<String, Value>,
    pub spec: APIServiceSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<APIServiceStatus>,
}

impl APIService {
    #[must_use]
    pub fn name(&self) -> &str {
        self.metadata
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    #[must_use]
    pub fn is_local(&self) -> bool {
        self.spec.service.is_none()
    }

    #[must_use]
    pub fn group(&self) -> &str {
        &self.spec.group
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.spec.version
    }

    #[must_use]
    pub fn group_priority_minimum(&self) -> i32 {
        self.spec.group_priority_minimum
    }

    #[must_use]
    pub fn version_priority(&self) -> i32 {
        self.spec.version_priority
    }

    #[must_use]
    pub fn get_condition(&self, type_: &str) -> Option<&APIServiceCondition> {
        self.status
            .as_ref()?
            .conditions
            .iter()
            .find(|c| c.type_ == type_)
    }

    pub fn set_condition(&mut self, condition: APIServiceCondition) {
        let status = self.status.get_or_insert_with(APIServiceStatus::default);
        if let Some(existing) = status
            .conditions
            .iter_mut()
            .find(|c| c.type_ == condition.type_)
        {
            *existing = condition;
        } else {
            status.conditions.push(condition);
        }
    }

    pub fn update_available_condition(&mut self, status: &str, reason: &str, message: &str) {
        let now = crate::time::now_rfc3339();
        let last_transition_time = if let Some(prev) = self.get_condition("Available") {
            if prev.status == status {
                prev.last_transition_time.clone().unwrap_or(now)
            } else {
                now
            }
        } else {
            now
        };

        self.set_condition(APIServiceCondition {
            type_: "Available".to_string(),
            status: status.to_string(),
            last_transition_time: Some(last_transition_time),
            reason: Some(reason.to_string()),
            message: Some(message.to_string()),
        });
    }
}

#[derive(Clone, Debug)]
pub struct AggregatedRequestContext {
    pub path: String,
    pub method: String,
    pub caller_username: String,
    pub caller_groups: Vec<String>,
    pub body: Option<Value>,
}

#[async_trait]
pub trait AggregatedApiHandler: Send + Sync {
    async fn handle_request(&self, ctx: &AggregatedRequestContext)
    -> Result<Value, ApiserverError>;
}

struct RegisteredService {
    handler: Arc<dyn AggregatedApiHandler>,
    server_cert_pem: Option<String>,
}

#[derive(Clone, Default)]
pub struct AggregationManager {
    services: Arc<RwLock<BTreeMap<String, APIService>>>,
    endpoints: Arc<RwLock<BTreeMap<String, Arc<RegisteredService>>>>,
}

impl std::fmt::Debug for AggregationManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregationManager")
            .field(
                "services_count",
                &self.services.read().map_or(0, |s| s.len()),
            )
            .field(
                "endpoints_count",
                &self.endpoints.read().map_or(0, |e| e.len()),
            )
            .finish()
    }
}

/// Verifies the aggregated service TLS certificate against its `caBundle`.
fn verify_service_trust(
    service_name: &str,
    spec: &APIServiceSpec,
    endpoint: &RegisteredService,
) -> Result<(), ApiserverError> {
    if spec.insecure_skip_tls_verify == Some(true) {
        return Ok(());
    }

    let Some(ca_bundle_b64) = &spec.ca_bundle else {
        return Ok(());
    };

    let ca_bytes = diorama_pki::base64_decode(ca_bundle_b64).map_err(|e| {
        ApiserverError::InvalidCredentials {
            reason: format!("invalid base64 in APIService '{service_name}' caBundle: {e}"),
        }
    })?;

    let ca_pem =
        std::str::from_utf8(&ca_bytes).map_err(|e| ApiserverError::InvalidCredentials {
            reason: format!("invalid UTF-8 in APIService '{service_name}' caBundle: {e}"),
        })?;

    let Some(server_cert) = &endpoint.server_cert_pem else {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!(
                "APIService '{service_name}' expects TLS verification against caBundle, but endpoint provided no certificate"
            ),
        });
    };

    diorama_pki::verify_certificate_chain(server_cert, ca_pem).map_err(|e| {
        ApiserverError::InvalidCredentials {
            reason: format!(
                "APIService '{service_name}' server TLS certificate rejected by caBundle trust: {e}"
            ),
        }
    })?;

    Ok(())
}

impl AggregationManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn evaluate_service_condition(
        spec: &APIServiceSpec,
        service_name: &str,
        endpoint: Option<&RegisteredService>,
    ) -> (String, String, String) {
        if spec.service.is_none() {
            return (
                "True".to_string(),
                "Local".to_string(),
                "Local APIService is always available".to_string(),
            );
        }

        let Some(ep) = endpoint else {
            return (
                "False".to_string(),
                "MissingHandler".to_string(),
                "no backend handler registered for aggregated service".to_string(),
            );
        };

        match verify_service_trust(service_name, spec, ep) {
            Ok(()) => (
                "True".to_string(),
                "Passed".to_string(),
                "endpoint is available and TLS trust verified".to_string(),
            ),
            Err(e) => (
                "False".to_string(),
                "FailedTrustVerification".to_string(),
                e.to_string(),
            ),
        }
    }

    pub fn register_api_service(&self, mut service: APIService) {
        let name = service.name().to_string();
        let endpoint = {
            let ep_guard = self.endpoints.read().unwrap();
            let mut ep = ep_guard.get(&name).cloned();
            if ep.is_none()
                && let Some(svc_ref) = &service.spec.service
            {
                ep = ep_guard.get(&svc_ref.name).cloned();
            }
            ep
        };

        let (status, reason, msg) =
            Self::evaluate_service_condition(&service.spec, &name, endpoint.as_deref());
        service.update_available_condition(&status, &reason, &msg);

        let mut guard = self.services.write().unwrap();
        guard.insert(name, service);
    }

    pub fn remove_api_service(&self, name: &str) -> Option<APIService> {
        let mut guard = self.services.write().unwrap();
        guard.remove(name)
    }

    pub fn get_api_service(&self, name: &str) -> Option<APIService> {
        let guard = self.services.read().unwrap();
        guard.get(name).cloned()
    }

    pub fn list_api_services(&self) -> Vec<APIService> {
        let guard = self.services.read().unwrap();
        guard.values().cloned().collect()
    }

    pub fn register_endpoint(
        &self,
        service_name: impl Into<String>,
        handler: Arc<dyn AggregatedApiHandler>,
        server_cert_pem: Option<String>,
    ) {
        let s_name = service_name.into();
        let reg = Arc::new(RegisteredService {
            handler,
            server_cert_pem,
        });

        {
            let mut guard = self.endpoints.write().unwrap();
            guard.insert(s_name.clone(), reg.clone());
        }

        let mut services_guard = self.services.write().unwrap();
        for (name, service) in services_guard.iter_mut() {
            let matches = name == &s_name
                || service
                    .spec
                    .service
                    .as_ref()
                    .is_some_and(|s| s.name == s_name);
            if matches {
                let (status, reason, msg) =
                    Self::evaluate_service_condition(&service.spec, name, Some(&reg));
                service.update_available_condition(&status, &reason, &msg);
            }
        }
    }

    pub fn update_service_condition(
        &self,
        name: &str,
        available: bool,
        reason: &str,
        message: &str,
    ) -> bool {
        let mut guard = self.services.write().unwrap();
        if let Some(service) = guard.get_mut(name) {
            let status = if available { "True" } else { "False" };
            service.update_available_condition(status, reason, message);
            true
        } else {
            false
        }
    }

    pub fn sync_all_statuses(&self) {
        let ep_guard = self.endpoints.read().unwrap();
        let mut services_guard = self.services.write().unwrap();
        for (name, service) in services_guard.iter_mut() {
            let mut ep = ep_guard.get(name).cloned();
            if ep.is_none()
                && let Some(svc_ref) = &service.spec.service
            {
                ep = ep_guard.get(&svc_ref.name).cloned();
            }
            let (status, reason, msg) =
                Self::evaluate_service_condition(&service.spec, name, ep.as_deref());
            service.update_available_condition(&status, &reason, &msg);
        }
    }

    pub fn sort_api_services(services: &mut [APIService]) {
        services.sort_by(|a, b| {
            b.spec
                .group_priority_minimum
                .cmp(&a.spec.group_priority_minimum)
                .then_with(|| a.spec.group.cmp(&b.spec.group))
                .then_with(|| b.spec.version_priority.cmp(&a.spec.version_priority))
                .then_with(|| a.spec.version.cmp(&b.spec.version))
        });
    }

    #[must_use]
    pub fn prioritized_api_services(&self) -> Vec<APIService> {
        let mut list = self.list_api_services();
        Self::sort_api_services(&mut list);
        list
    }

    #[must_use]
    pub fn group_priority_minimum(&self, group: &str) -> Option<i32> {
        let guard = self.services.read().unwrap();
        guard
            .values()
            .filter(|s| s.spec.group == group)
            .map(|s| s.spec.group_priority_minimum)
            .max()
    }

    #[must_use]
    pub fn preferred_version(&self, group: &str) -> Option<String> {
        let guard = self.services.read().unwrap();
        guard
            .values()
            .filter(|s| s.spec.group == group)
            .max_by_key(|s| s.spec.version_priority)
            .map(|s| s.spec.version.clone())
    }

    #[must_use]
    pub fn sorted_versions_for_group(&self, group: &str) -> Vec<String> {
        let guard = self.services.read().unwrap();
        let mut group_services: Vec<_> = guard.values().filter(|s| s.spec.group == group).collect();
        group_services.sort_by(|a, b| {
            b.spec
                .version_priority
                .cmp(&a.spec.version_priority)
                .then_with(|| a.spec.version.cmp(&b.spec.version))
        });
        group_services
            .into_iter()
            .map(|s| s.spec.version.clone())
            .collect()
    }
}

struct GroupVersionEntry {
    version_priority: i32,
    version: String,
    group_version: String,
}

struct DiscoveryGroupEntry {
    group_priority: i32,
    versions: Vec<GroupVersionEntry>,
}

impl AggregationManager {
    #[must_use]
    pub fn merge_discovery_groups(&self, base_groups: &[Value]) -> Vec<Value> {
        use serde_json::json;

        let mut groups_map: BTreeMap<String, DiscoveryGroupEntry> = BTreeMap::new();

        for bg in base_groups {
            let Some(name) = bg.get("name").and_then(Value::as_str) else {
                continue;
            };
            let versions_arr = bg.get("versions").and_then(Value::as_array);
            let mut vers = Vec::new();
            if let Some(arr) = versions_arr {
                for (idx, v) in arr.iter().enumerate() {
                    let v_str = v
                        .get("version")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let gv_str = v
                        .get("groupVersion")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let prio = i32::try_from(idx).map_or(0, |i| 1000 - i);
                    vers.push(GroupVersionEntry {
                        version_priority: prio,
                        version: v_str,
                        group_version: gv_str,
                    });
                }
            }
            groups_map.insert(
                name.to_string(),
                DiscoveryGroupEntry {
                    group_priority: 15000,
                    versions: vers,
                },
            );
        }

        for s in self.list_api_services() {
            let g = s.spec.group;
            let v = s.spec.version;
            let gv = format!("{g}/{v}");
            let entry = groups_map.entry(g).or_insert_with(|| DiscoveryGroupEntry {
                group_priority: s.spec.group_priority_minimum,
                versions: Vec::new(),
            });
            entry.group_priority = entry.group_priority.max(s.spec.group_priority_minimum);
            if !entry.versions.iter().any(|ver| ver.version == v) {
                entry.versions.push(GroupVersionEntry {
                    version_priority: s.spec.version_priority,
                    version: v,
                    group_version: gv,
                });
            }
        }

        let mut sorted_groups: Vec<(i32, String, Value)> = Vec::new();
        for (g_name, mut group_entry) in groups_map {
            group_entry.versions.sort_by(|a, b| {
                b.version_priority
                    .cmp(&a.version_priority)
                    .then_with(|| a.version.cmp(&b.version))
            });
            let preferred = group_entry.versions.first().map_or_else(
                || json!({}),
                |entry| {
                    json!({
                        "groupVersion": entry.group_version,
                        "version": entry.version,
                    })
                },
            );

            let versions_json: Vec<Value> = group_entry
                .versions
                .into_iter()
                .map(|entry| {
                    json!({
                        "groupVersion": entry.group_version,
                        "version": entry.version,
                    })
                })
                .collect();

            let group_doc = json!({
                "name": g_name,
                "versions": versions_json,
                "preferredVersion": preferred,
            });

            sorted_groups.push((group_entry.group_priority, g_name, group_doc));
        }

        sorted_groups.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        sorted_groups.into_iter().map(|(_, _, doc)| doc).collect()
    }

    pub fn merge_api_resource_lists(
        base: &Value,
        aggregated: &Value,
    ) -> Result<Value, ApiserverError> {
        use serde_json::json;

        let mut merged = base.clone();
        let group_version = base
            .get("groupVersion")
            .and_then(Value::as_str)
            .or_else(|| aggregated.get("groupVersion").and_then(Value::as_str))
            .unwrap_or("");

        let mut resources = Vec::new();
        let mut seen = std::collections::BTreeSet::new();

        if let Some(base_res) = base.get("resources").and_then(Value::as_array) {
            for res in base_res {
                let Some(name) = res.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if seen.insert(name.to_string()) {
                    resources.push(res.clone());
                }
            }
        }

        if let Some(agg_res) = aggregated.get("resources").and_then(Value::as_array) {
            for res in agg_res {
                let Some(name) = res.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if seen.insert(name.to_string()) {
                    resources.push(res.clone());
                }
            }
        }

        if let Some(obj) = merged.as_object_mut() {
            obj.insert("groupVersion".to_string(), json!(group_version));
            obj.insert("resources".to_string(), json!(resources));
        }

        Ok(merged)
    }

    pub fn merge_discovery_documents(
        &self,
        base_apigroup_list: &Value,
        aggregated_apigroup_lists: &[Value],
    ) -> Result<Value, ApiserverError> {
        use serde_json::json;

        let mut all_groups = Vec::new();
        if let Some(groups) = base_apigroup_list.get("groups").and_then(Value::as_array) {
            all_groups.extend(groups.iter().cloned());
        }

        for doc in aggregated_apigroup_lists {
            if let Some(groups) = doc.get("groups").and_then(Value::as_array) {
                all_groups.extend(groups.iter().cloned());
            }
        }

        let merged_groups = self.merge_discovery_groups(&all_groups);

        Ok(json!({
            "kind": "APIGroupList",
            "apiVersion": "v1",
            "groups": merged_groups
        }))
    }

    pub async fn dispatch(
        &self,
        service_name: &str,
        ctx: &AggregatedRequestContext,
    ) -> Result<Value, ApiserverError> {
        let service =
            self.get_api_service(service_name)
                .ok_or_else(|| ApiserverError::NotFound {
                    resource: "apiservices".to_string(),
                    name: service_name.to_string(),
                })?;

        let endpoint = {
            let guard = self.endpoints.read().unwrap();
            guard.get(service_name).cloned()
        };

        let Some(endpoint) = endpoint else {
            return Err(ApiserverError::AggregatedApiError {
                service: service_name.to_string(),
                reason: "no backend handler registered for aggregated service".to_string(),
            });
        };

        verify_service_trust(service_name, &service.spec, &endpoint)?;
        endpoint.handler.handle_request(ctx).await
    }

    /// Restores persisted `APIServices` from storage upon startup or restart.
    pub async fn restore_from_storage(
        &self,
        storage: &KubernetesStorage,
    ) -> Result<(), ApiserverError> {
        let prefix = format!("{}/apiservices", storage.prefix());
        let kvs = storage.list(&prefix).await?;
        for kv in kvs {
            let api_service: APIService = serde_json::from_slice(&kv.value)?;
            self.register_api_service(api_service);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct TestHandler {
        payload: Value,
    }

    #[async_trait]
    impl AggregatedApiHandler for TestHandler {
        async fn handle_request(
            &self,
            _ctx: &AggregatedRequestContext,
        ) -> Result<Value, ApiserverError> {
            Ok(self.payload.clone())
        }
    }

    #[test]
    fn local_apiservice_availability() {
        let manager = AggregationManager::new();
        let service = APIService {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("v1."));
                m
            },
            spec: APIServiceSpec {
                group: String::new(),
                version: "v1".to_string(),
                group_priority_minimum: 1000,
                version_priority: 100,
                service: None,
                ca_bundle: None,
                insecure_skip_tls_verify: None,
            },
            status: None,
        };

        manager.register_api_service(service);
        let retrieved = manager.get_api_service("v1.").expect("retrieved");
        let cond = retrieved
            .get_condition("Available")
            .expect("available condition");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("Local"));
    }

    #[test]
    fn aggregated_apiservice_missing_endpoint() {
        let manager = AggregationManager::new();
        let service = APIService {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("v1beta1.metrics.k8s.io"));
                m
            },
            spec: APIServiceSpec {
                group: "metrics.k8s.io".to_string(),
                version: "v1beta1".to_string(),
                group_priority_minimum: 100,
                version_priority: 10,
                service: Some(ServiceReference {
                    namespace: "kube-system".to_string(),
                    name: "metrics-server".to_string(),
                    path: None,
                    port: Some(443),
                }),
                ca_bundle: None,
                insecure_skip_tls_verify: Some(true),
            },
            status: None,
        };

        manager.register_api_service(service);
        let retrieved = manager.get_api_service("v1beta1.metrics.k8s.io").unwrap();
        let cond = retrieved.get_condition("Available").unwrap();
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason.as_deref(), Some("MissingHandler"));
    }

    #[test]
    fn aggregated_apiservice_endpoint_registration_updates_condition() {
        let manager = AggregationManager::new();
        let service = APIService {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("v1beta1.metrics.k8s.io"));
                m
            },
            spec: APIServiceSpec {
                group: "metrics.k8s.io".to_string(),
                version: "v1beta1".to_string(),
                group_priority_minimum: 100,
                version_priority: 10,
                service: Some(ServiceReference {
                    namespace: "kube-system".to_string(),
                    name: "metrics-server".to_string(),
                    path: None,
                    port: Some(443),
                }),
                ca_bundle: None,
                insecure_skip_tls_verify: Some(true),
            },
            status: None,
        };

        manager.register_api_service(service);
        assert_eq!(
            manager
                .get_api_service("v1beta1.metrics.k8s.io")
                .unwrap()
                .get_condition("Available")
                .unwrap()
                .status,
            "False"
        );

        manager.register_endpoint(
            "v1beta1.metrics.k8s.io",
            Arc::new(TestHandler {
                payload: json!({ "ok": true }),
            }),
            None,
        );

        let retrieved = manager.get_api_service("v1beta1.metrics.k8s.io").unwrap();
        let cond = retrieved.get_condition("Available").unwrap();
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("Passed"));
    }

    #[test]
    fn priority_ordering_and_preferred_version() {
        let manager = AggregationManager::new();

        let s1 = APIService {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("v1beta1.metrics.k8s.io"));
                m
            },
            spec: APIServiceSpec {
                group: "metrics.k8s.io".to_string(),
                version: "v1beta1".to_string(),
                group_priority_minimum: 100,
                version_priority: 10,
                service: None,
                ca_bundle: None,
                insecure_skip_tls_verify: None,
            },
            status: None,
        };

        let s2 = APIService {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("v1.metrics.k8s.io"));
                m
            },
            spec: APIServiceSpec {
                group: "metrics.k8s.io".to_string(),
                version: "v1".to_string(),
                group_priority_minimum: 100,
                version_priority: 20,
                service: None,
                ca_bundle: None,
                insecure_skip_tls_verify: None,
            },
            status: None,
        };

        let s3 = APIService {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("v1.custom.example.com"));
                m
            },
            spec: APIServiceSpec {
                group: "custom.example.com".to_string(),
                version: "v1".to_string(),
                group_priority_minimum: 500,
                version_priority: 100,
                service: None,
                ca_bundle: None,
                insecure_skip_tls_verify: None,
            },
            status: None,
        };

        manager.register_api_service(s1);
        manager.register_api_service(s2);
        manager.register_api_service(s3);

        let prioritized = manager.prioritized_api_services();
        assert_eq!(prioritized.len(), 3);
        assert_eq!(prioritized[0].name(), "v1.custom.example.com");
        assert_eq!(prioritized[1].name(), "v1.metrics.k8s.io");
        assert_eq!(prioritized[2].name(), "v1beta1.metrics.k8s.io");

        assert_eq!(
            manager.preferred_version("metrics.k8s.io"),
            Some("v1".to_string())
        );
        assert_eq!(
            manager.sorted_versions_for_group("metrics.k8s.io"),
            vec!["v1".to_string(), "v1beta1".to_string()]
        );
        assert_eq!(manager.group_priority_minimum("metrics.k8s.io"), Some(100));
    }

    #[test]
    fn discovery_group_and_resource_merging() {
        let manager = AggregationManager::new();

        let s1 = APIService {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("v1beta1.metrics.k8s.io"));
                m
            },
            spec: APIServiceSpec {
                group: "metrics.k8s.io".to_string(),
                version: "v1beta1".to_string(),
                group_priority_minimum: 100,
                version_priority: 10,
                service: None,
                ca_bundle: None,
                insecure_skip_tls_verify: None,
            },
            status: None,
        };
        let s2 = APIService {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("v1.metrics.k8s.io"));
                m
            },
            spec: APIServiceSpec {
                group: "metrics.k8s.io".to_string(),
                version: "v1".to_string(),
                group_priority_minimum: 100,
                version_priority: 20,
                service: None,
                ca_bundle: None,
                insecure_skip_tls_verify: None,
            },
            status: None,
        };
        manager.register_api_service(s1);
        manager.register_api_service(s2);

        let base_groups = vec![json!({
            "name": "apps",
            "versions": [{ "groupVersion": "apps/v1", "version": "v1" }],
            "preferredVersion": { "groupVersion": "apps/v1", "version": "v1" }
        })];

        let merged_groups = manager.merge_discovery_groups(&base_groups);
        assert_eq!(merged_groups.len(), 2);
        let metrics_grp = merged_groups
            .iter()
            .find(|g| g["name"] == "metrics.k8s.io")
            .unwrap();
        assert_eq!(metrics_grp["preferredVersion"]["version"], "v1");
        assert_eq!(metrics_grp["versions"].as_array().unwrap().len(), 2);

        let base_res = json!({
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": "metrics.k8s.io/v1beta1",
            "resources": [
                { "name": "nodes", "namespaced": false, "kind": "NodeMetrics" }
            ]
        });
        let agg_res = json!({
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": "metrics.k8s.io/v1beta1",
            "resources": [
                { "name": "nodes", "namespaced": false, "kind": "NodeMetrics" },
                { "name": "pods", "namespaced": true, "kind": "PodMetrics" }
            ]
        });
        let merged_res = AggregationManager::merge_api_resource_lists(&base_res, &agg_res).unwrap();
        let items = merged_res["resources"].as_array().unwrap();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn aggregated_apiservice_tls_trust_verification() {
        let manager = AggregationManager::new();

        let ca_pair =
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
                .unwrap();
        let mut ca_params =
            rcgen::CertificateParams::new(vec!["aggregated-ca".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_pair).unwrap();

        let leaf_pair =
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
                .unwrap();
        let leaf_params =
            rcgen::CertificateParams::new(vec!["metrics-server.kube-system.svc".to_string()])
                .unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_pair).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_pair, &issuer).unwrap();

        let ca_bundle_b64 = diorama_pki::base64_encode(ca_cert.pem().as_bytes());

        let service = APIService {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("v1beta1.metrics.k8s.io"));
                m
            },
            spec: APIServiceSpec {
                group: "metrics.k8s.io".to_string(),
                version: "v1beta1".to_string(),
                group_priority_minimum: 100,
                version_priority: 10,
                service: Some(ServiceReference {
                    namespace: "kube-system".to_string(),
                    name: "metrics-server".to_string(),
                    path: None,
                    port: Some(443),
                }),
                ca_bundle: Some(ca_bundle_b64),
                insecure_skip_tls_verify: None,
            },
            status: None,
        };

        manager.register_api_service(service);

        // Register endpoint with untrusted/rogue cert
        let rogue_pair =
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
                .unwrap();
        let mut rogue_params = rcgen::CertificateParams::new(vec!["rogue-ca".to_string()]).unwrap();
        rogue_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let rogue_ca = rogue_params.self_signed(&rogue_pair).unwrap();

        manager.register_endpoint(
            "v1beta1.metrics.k8s.io",
            Arc::new(TestHandler {
                payload: json!({ "ok": true }),
            }),
            Some(rogue_ca.pem()),
        );

        let retrieved_untrusted = manager.get_api_service("v1beta1.metrics.k8s.io").unwrap();
        let cond_untrusted = retrieved_untrusted.get_condition("Available").unwrap();
        assert_eq!(cond_untrusted.status, "False");
        assert_eq!(
            cond_untrusted.reason.as_deref(),
            Some("FailedTrustVerification")
        );

        // Now register with trusted cert signed by CA
        manager.register_endpoint(
            "v1beta1.metrics.k8s.io",
            Arc::new(TestHandler {
                payload: json!({ "ok": true }),
            }),
            Some(leaf_cert.pem()),
        );

        let retrieved_trusted = manager.get_api_service("v1beta1.metrics.k8s.io").unwrap();
        let cond_trusted = retrieved_trusted.get_condition("Available").unwrap();
        assert_eq!(cond_trusted.status, "True");
        assert_eq!(cond_trusted.reason.as_deref(), Some("Passed"));
    }
}
