use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use serde_json::{Value, json};

pub use diorama_datastore::{WatchEvent, WatchEventType, WatchReceiver};

use crate::admission::{
    AdmissionEngine, AdmissionRequest, GroupVersionKind, GroupVersionResource, UserInfo,
};
use crate::aggregation::{APIService, AggregatedRequestContext, AggregationManager};
use crate::config::{ApiserverConfig, parse_ipv4_cidr, parse_port_range};
use crate::error::ApiserverError;
use crate::rbac::{
    AuthzRequest, ClusterRole, ClusterRoleBinding, PolicyRule, RbacAuthorizer, Role, RoleBinding,
};
use crate::storage::KubernetesStorage;
use crate::token::TokenService;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientIdentity {
    AdminCertificate,
    BearerToken(String),
    ServiceAccount {
        namespace: String,
        name: String,
    },
    User {
        username: String,
        groups: Vec<String>,
    },
    RestrictedUser {
        username: String,
        groups: Vec<String>,
    },
    FrontProxy {
        client_cert_pem: String,
        username: String,
        groups: Vec<String>,
    },
    Anonymous,
}

#[derive(Clone)]
pub struct KubernetesApiClient {
    storage: KubernetesStorage,
    identity: ClientIdentity,
    rbac: Arc<RbacAuthorizer>,
    token_service: Option<Arc<TokenService>>,
    admission: Arc<AdmissionEngine>,
    aggregation: Arc<AggregationManager>,
    crd_registry: Arc<RwLock<BTreeMap<String, Value>>>,
    anonymous_auth_allowed: bool,
    request_header_ca_file: std::path::PathBuf,
    request_header_allowed_names: Vec<String>,
    service_cluster_ip_range: String,
    service_node_port_range: String,
}

impl std::fmt::Debug for KubernetesApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubernetesApiClient")
            .field("identity", &self.identity)
            .field("anonymous_auth_allowed", &self.anonymous_auth_allowed)
            .finish_non_exhaustive()
    }
}

/// Applies an RFC 7386 JSON Merge Patch to a target JSON value.
pub fn json_merge_patch(target: &mut Value, patch: Value) {
    if let Value::Object(patch_obj) = patch {
        if !target.is_object() {
            *target = Value::Object(serde_json::Map::new());
        }
        let target_obj = target.as_object_mut().unwrap();
        for (key, value) in patch_obj {
            if value.is_null() {
                target_obj.remove(&key);
            } else if value.is_object() {
                if let Some(existing_sub) = target_obj.get_mut(&key) {
                    json_merge_patch(existing_sub, value);
                } else {
                    target_obj.insert(key, value);
                }
            } else {
                target_obj.insert(key, value);
            }
        }
    } else {
        *target = patch;
    }
}

impl KubernetesApiClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: KubernetesStorage,
        identity: ClientIdentity,
        rbac: Arc<RbacAuthorizer>,
        token_service: Option<Arc<TokenService>>,
        admission: Arc<AdmissionEngine>,
        aggregation: Arc<AggregationManager>,
        crd_registry: Arc<RwLock<BTreeMap<String, Value>>>,
        config: &ApiserverConfig,
    ) -> Self {
        Self {
            storage,
            identity,
            rbac,
            token_service,
            admission,
            aggregation,
            crd_registry,
            anonymous_auth_allowed: config.anonymous_auth,
            request_header_ca_file: config.request_header_ca_file.clone(),
            request_header_allowed_names: vec!["system:auth-proxy".to_string()],
            service_cluster_ip_range: config.service_cluster_ip_range.clone(),
            service_node_port_range: config.service_node_port_range.clone(),
        }
    }

    #[must_use]
    pub fn identity(&self) -> &ClientIdentity {
        &self.identity
    }

    #[must_use]
    pub fn service_cluster_ip_range(&self) -> &str {
        &self.service_cluster_ip_range
    }

    pub fn admission(&self) -> &Arc<AdmissionEngine> {
        &self.admission
    }

    pub fn aggregation(&self) -> &Arc<AggregationManager> {
        &self.aggregation
    }

    fn current_user_info(&self) -> UserInfo {
        match &self.identity {
            ClientIdentity::AdminCertificate => UserInfo {
                username: "system:admin".to_string(),
                uid: None,
                groups: vec![
                    "system:masters".to_string(),
                    "system:authenticated".to_string(),
                ],
            },
            ClientIdentity::BearerToken(_) => UserInfo {
                username: "system:serviceaccount:default:token".to_string(),
                uid: None,
                groups: vec![
                    "system:serviceaccounts".to_string(),
                    "system:authenticated".to_string(),
                ],
            },
            ClientIdentity::ServiceAccount { namespace, name } => UserInfo {
                username: format!("system:serviceaccount:{namespace}:{name}"),
                uid: None,
                groups: vec![
                    "system:serviceaccounts".to_string(),
                    format!("system:serviceaccounts:{namespace}"),
                    "system:authenticated".to_string(),
                ],
            },
            ClientIdentity::User { username, groups }
            | ClientIdentity::RestrictedUser { username, groups }
            | ClientIdentity::FrontProxy {
                username, groups, ..
            } => UserInfo {
                username: username.clone(),
                uid: None,
                groups: groups.clone(),
            },
            ClientIdentity::Anonymous => UserInfo {
                username: "system:anonymous".to_string(),
                uid: None,
                groups: vec!["system:unauthenticated".to_string()],
            },
        }
    }

    fn check_rbac_permission(&self, req: &AuthzRequest<'_>) -> Result<(), ApiserverError> {
        if self.rbac.authorize(req) {
            Ok(())
        } else {
            Err(ApiserverError::Unauthorized {
                reason: format!(
                    "RBAC: {} is forbidden to {} {} in namespace {:?}",
                    req.username, req.verb, req.resource, req.namespace
                ),
            })
        }
    }

    fn check_token_auth(&self, token: &str, req: &AuthzRequest<'_>) -> Result<(), ApiserverError> {
        if let Some(ts) = &self.token_service {
            let claims = ts.verify_token(token, Some("https://kubernetes.default.svc"))?;
            let groups = vec![
                "system:serviceaccounts".to_string(),
                format!("system:serviceaccounts:{}", claims.namespace),
                "system:authenticated".to_string(),
            ];
            self.check_rbac_permission(&AuthzRequest {
                username: &claims.sub,
                groups: &groups,
                ..*req
            })
        } else {
            Err(ApiserverError::Unauthorized {
                reason: format!(
                    "bearer token cannot be verified (token service unavailable) for {} on {}",
                    req.verb, req.resource
                ),
            })
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn check_auth_detailed(
        &self,
        verb: &str,
        api_group: &str,
        resource: &str,
        namespace: Option<&str>,
        resource_name: Option<&str>,
    ) -> Result<(), ApiserverError> {
        let base_req = AuthzRequest {
            username: "",
            groups: &[],
            verb,
            api_group,
            resource,
            namespace,
            resource_name,
        };

        match &self.identity {
            ClientIdentity::AdminCertificate => Ok(()),
            ClientIdentity::BearerToken(token) => self.check_token_auth(token, &base_req),
            ClientIdentity::ServiceAccount {
                namespace: sa_ns,
                name: sa_name,
            } => {
                let username = format!("system:serviceaccount:{sa_ns}:{sa_name}");
                let groups = vec![
                    "system:serviceaccounts".to_string(),
                    format!("system:serviceaccounts:{sa_ns}"),
                    "system:authenticated".to_string(),
                ];
                self.check_rbac_permission(&AuthzRequest {
                    username: &username,
                    groups: &groups,
                    ..base_req
                })
            },
            ClientIdentity::User { username, groups } => {
                self.check_rbac_permission(&AuthzRequest {
                    username,
                    groups,
                    ..base_req
                })
            },
            ClientIdentity::RestrictedUser { username, groups } => {
                if self
                    .check_rbac_permission(&AuthzRequest {
                        username,
                        groups,
                        ..base_req
                    })
                    .is_ok()
                {
                    return Ok(());
                }

                // Default fallback: allow read on namespaces for restricted users
                if (verb == "get" || verb == "list") && resource == "namespaces" {
                    return Ok(());
                }

                Err(ApiserverError::Unauthorized {
                    reason: format!("user '{username}' is forbidden from {verb} on {resource}"),
                })
            },
            ClientIdentity::FrontProxy {
                client_cert_pem,
                username,
                groups,
            } => {
                if !self.request_header_ca_file.exists() {
                    return Err(ApiserverError::InvalidCredentials {
                        reason: format!(
                            "request-header CA file not found at {}",
                            self.request_header_ca_file.display()
                        ),
                    });
                }
                let ca_pem =
                    std::fs::read_to_string(&self.request_header_ca_file).map_err(|e| {
                        ApiserverError::InvalidCredentials {
                            reason: format!("failed to read request-header CA: {e}"),
                        }
                    })?;

                let id = diorama_pki::verify_certificate_chain(client_cert_pem, &ca_pem).map_err(
                    |e| ApiserverError::Unauthenticated {
                        reason: format!(
                            "front-proxy client certificate rejected by request-header CA: {e}"
                        ),
                    },
                )?;

                let allowed = self
                    .request_header_allowed_names
                    .iter()
                    .any(|allowed_name| id.matches(allowed_name));

                if !allowed {
                    return Err(ApiserverError::Unauthenticated {
                        reason: format!(
                            "front-proxy client certificate identity '{}' not in allowed names {:?}",
                            id.common_name, self.request_header_allowed_names
                        ),
                    });
                }

                self.check_rbac_permission(&AuthzRequest {
                    username,
                    groups,
                    ..base_req
                })
            },
            ClientIdentity::Anonymous => {
                if self.anonymous_auth_allowed {
                    let groups = vec!["system:unauthenticated".to_string()];
                    self.check_rbac_permission(&AuthzRequest {
                        username: "system:anonymous",
                        groups: &groups,
                        ..base_req
                    })
                } else {
                    Err(ApiserverError::Unauthenticated {
                        reason: "anonymous requests are disabled (--anonymous-auth=false)"
                            .to_string(),
                    })
                }
            },
        }
    }

    pub fn check_auth(&self, verb: &str, resource: &str) -> Result<(), ApiserverError> {
        self.check_auth_detailed(verb, "", resource, None, None)
    }

    // --- Discovery API ---

    pub fn discover_core(&self) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "", "discovery", None, None)?;
        Ok(json!({
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": "v1",
            "resources": [
                {
                    "name": "namespaces",
                    "singularName": "namespace",
                    "namespaced": false,
                    "kind": "Namespace",
                    "shortNames": ["ns"],
                    "verbs": ["create", "delete", "get", "list", "watch"]
                },
                {
                    "name": "configmaps",
                    "singularName": "configmap",
                    "namespaced": true,
                    "kind": "ConfigMap",
                    "shortNames": ["cm"],
                    "verbs": ["create", "delete", "get", "list", "update", "watch"]
                },
                {
                    "name": "secrets",
                    "singularName": "secret",
                    "namespaced": true,
                    "kind": "Secret",
                    "verbs": ["create", "delete", "get", "list", "update", "watch"]
                },
                {
                    "name": "pods",
                    "singularName": "pod",
                    "namespaced": true,
                    "kind": "Pod",
                    "shortNames": ["po"],
                    "verbs": ["create", "delete", "get", "list", "update", "watch"]
                },
                {
                    "name": "services",
                    "singularName": "service",
                    "namespaced": true,
                    "kind": "Service",
                    "shortNames": ["svc"],
                    "verbs": ["create", "delete", "get", "list", "update", "watch"]
                },
                {
                    "name": "endpoints",
                    "singularName": "endpoints",
                    "namespaced": true,
                    "kind": "Endpoints",
                    "shortNames": ["ep"],
                    "verbs": ["create", "delete", "get", "list", "update", "watch"]
                },
                {
                    "name": "serviceaccounts",
                    "singularName": "serviceaccount",
                    "namespaced": true,
                    "kind": "ServiceAccount",
                    "verbs": ["create", "delete", "get", "list", "watch"]
                },
                {
                    "name": "nodes",
                    "singularName": "node",
                    "namespaced": false,
                    "kind": "Node",
                    "verbs": ["create", "delete", "get", "list", "update", "watch"]
                },
                {
                    "name": "persistentvolumeclaims",
                    "singularName": "persistentvolumeclaim",
                    "namespaced": true,
                    "kind": "PersistentVolumeClaim",
                    "shortNames": ["pvc"],
                    "verbs": ["create", "delete", "get", "list", "update", "watch"]
                },
                {
                    "name": "persistentvolumes",
                    "singularName": "persistentvolume",
                    "namespaced": false,
                    "kind": "PersistentVolume",
                    "shortNames": ["pv"],
                    "verbs": ["create", "delete", "get", "list", "update", "watch"]
                }
            ]
        }))
    }

    pub fn discover_apis(&self) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "", "discovery", None, None)?;
        let mut groups = vec![
            json!({
                "name": "apps",
                "versions": [
                    { "groupVersion": "apps/v1", "version": "v1" }
                ],
                "preferredVersion": { "groupVersion": "apps/v1", "version": "v1" }
            }),
            json!({
                "name": "apiextensions.k8s.io",
                "versions": [
                    { "groupVersion": "apiextensions.k8s.io/v1", "version": "v1" }
                ],
                "preferredVersion": { "groupVersion": "apiextensions.k8s.io/v1", "version": "v1" }
            }),
            json!({
                "name": "rbac.authorization.k8s.io",
                "versions": [
                    { "groupVersion": "rbac.authorization.k8s.io/v1", "version": "v1" }
                ],
                "preferredVersion": { "groupVersion": "rbac.authorization.k8s.io/v1", "version": "v1" }
            }),
            json!({
                "name": "admissionregistration.k8s.io",
                "versions": [
                    { "groupVersion": "admissionregistration.k8s.io/v1", "version": "v1" }
                ],
                "preferredVersion": { "groupVersion": "admissionregistration.k8s.io/v1", "version": "v1" }
            }),
            json!({
                "name": "apiregistration.k8s.io",
                "versions": [
                    { "groupVersion": "apiregistration.k8s.io/v1", "version": "v1" }
                ],
                "preferredVersion": { "groupVersion": "apiregistration.k8s.io/v1", "version": "v1" }
            }),
            json!({
                "name": "discovery.k8s.io",
                "versions": [
                    { "groupVersion": "discovery.k8s.io/v1", "version": "v1" }
                ],
                "preferredVersion": { "groupVersion": "discovery.k8s.io/v1", "version": "v1" }
            }),
            json!({
                "name": "storage.k8s.io",
                "versions": [
                    { "groupVersion": "storage.k8s.io/v1", "version": "v1" }
                ],
                "preferredVersion": { "groupVersion": "storage.k8s.io/v1", "version": "v1" }
            }),
        ];

        // Dynamically add CRD groups
        let crd_guard = self.crd_registry.read().unwrap();
        for crd in crd_guard.values() {
            if let Some(spec) = crd.get("spec")
                && let Some(group) = spec.get("group").and_then(Value::as_str)
            {
                if groups
                    .iter()
                    .any(|g| g.get("name").and_then(Value::as_str) == Some(group))
                {
                    continue;
                }

                let versions = Self::extract_crd_versions(spec, group);
                let pref = versions.first().cloned().unwrap_or(json!({}));
                groups.push(json!({
                    "name": group,
                    "versions": versions,
                    "preferredVersion": pref
                }));
            }
        }

        // Dynamically add APIService groups
        for api_service in self.aggregation.list_api_services() {
            let group = &api_service.spec.group;
            let version = &api_service.spec.version;
            if !groups
                .iter()
                .any(|g| g.get("name").and_then(Value::as_str) == Some(group.as_str()))
            {
                groups.push(json!({
                    "name": group,
                    "versions": [
                        { "groupVersion": format!("{group}/{version}"), "version": version }
                    ],
                    "preferredVersion": { "groupVersion": format!("{group}/{version}"), "version": version }
                }));
            }
        }

        Ok(json!({
            "kind": "APIGroupList",
            "apiVersion": "v1",
            "groups": groups
        }))
    }

    fn namespaced_resource(name: &str, singular: &str, kind: &str) -> Value {
        let short_names: &[&str] = match name {
            "deployments" => &["deploy"],
            "replicasets" => &["rs"],
            "statefulsets" => &["sts"],
            "daemonsets" => &["ds"],
            "endpoints" => &["ep"],
            "endpointslices" => &["es"],
            _ => &[],
        };
        json!({
            "name": name,
            "singularName": singular,
            "namespaced": true,
            "kind": kind,
            "shortNames": short_names,
            "verbs": ["create", "delete", "get", "list", "update", "watch"]
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn discover_group_resources(
        &self,
        group: &str,
        version: &str,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "", "discovery", None, None)?;

        let gv = format!("{group}/{version}");
        let mut resources = Vec::new();

        match (group, version) {
            ("apiextensions.k8s.io", "v1") => {
                resources.push(json!({
                    "name": "customresourcedefinitions",
                    "singularName": "customresourcedefinition",
                    "namespaced": false,
                    "kind": "CustomResourceDefinition",
                    "verbs": ["create", "delete", "get", "list", "watch"]
                }));
            },
            ("admissionregistration.k8s.io", "v1") => {
                resources.push(json!({
                    "name": "validatingwebhookconfigurations",
                    "singularName": "validatingwebhookconfiguration",
                    "namespaced": false,
                    "kind": "ValidatingWebhookConfiguration",
                    "verbs": ["create", "delete", "get", "list", "watch"]
                }));
                resources.push(json!({
                    "name": "mutatingwebhookconfigurations",
                    "singularName": "mutatingwebhookconfiguration",
                    "namespaced": false,
                    "kind": "MutatingWebhookConfiguration",
                    "verbs": ["create", "delete", "get", "list", "watch"]
                }));
            },
            ("apiregistration.k8s.io", "v1") => {
                resources.push(json!({
                    "name": "apiservices",
                    "singularName": "apiservice",
                    "namespaced": false,
                    "kind": "APIService",
                    "verbs": ["create", "delete", "get", "list", "watch"]
                }));
            },
            ("apps", "v1") => {
                for (name, singular, kind) in [
                    ("deployments", "deployment", "Deployment"),
                    ("replicasets", "replicaset", "ReplicaSet"),
                    ("statefulsets", "statefulset", "StatefulSet"),
                    ("daemonsets", "daemonset", "DaemonSet"),
                ] {
                    resources.push(Self::namespaced_resource(name, singular, kind));
                }
            },
            ("discovery.k8s.io", "v1") => {
                resources.push(Self::namespaced_resource(
                    "endpointslices",
                    "endpointslice",
                    "EndpointSlice",
                ));
            },
            ("storage.k8s.io", "v1") => {
                resources.push(json!({
                    "name": "storageclasses",
                    "singularName": "storageclass",
                    "namespaced": false,
                    "kind": "StorageClass",
                    "shortNames": ["sc"],
                    "verbs": ["create", "delete", "get", "list", "update", "watch"]
                }));
            },
            _ => {},
        }

        // Check CRDs
        let crd_guard = self.crd_registry.read().unwrap();
        for crd in crd_guard.values() {
            if let Some(spec) = crd.get("spec")
                && spec.get("group").and_then(Value::as_str) == Some(group)
            {
                let version_match = spec.get("versions").and_then(Value::as_array).map_or(
                    version == "v1",
                    |vers| {
                        vers.iter()
                            .any(|v| v.get("name").and_then(Value::as_str) == Some(version))
                    },
                );

                if version_match {
                    let plural = spec
                        .get("names")
                        .and_then(|n| n.get("plural"))
                        .and_then(Value::as_str)
                        .unwrap_or("customresources");
                    let singular = spec
                        .get("names")
                        .and_then(|n| n.get("singular"))
                        .and_then(Value::as_str)
                        .unwrap_or("customresource");
                    let kind = spec
                        .get("names")
                        .and_then(|n| n.get("kind"))
                        .and_then(Value::as_str)
                        .unwrap_or("CustomResource");
                    let scope = spec
                        .get("scope")
                        .and_then(Value::as_str)
                        .unwrap_or("Namespaced");

                    resources.push(json!({
                        "name": plural,
                        "singularName": singular,
                        "namespaced": scope == "Namespaced",
                        "kind": kind,
                        "verbs": ["create", "delete", "get", "list", "update", "watch"]
                    }));
                }
            }
        }

        Ok(json!({
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": gv,
            "resources": resources
        }))
    }

    // --- Namespace CRUD ---

    pub async fn create_namespace(&self, name: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("create", "", "namespaces", None, Some(name))?;
        let key = format!("{}/namespaces/{name}", self.storage.prefix());
        let doc = json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": name,
                "creationTimestamp": crate::time::now_rfc3339()
            },
            "status": {
                "phase": "Active"
            }
        });
        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = doc;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn get_namespace(&self, name: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "", "namespaces", None, Some(name))?;
        let key = format!("{}/namespaces/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "namespaces".to_string(),
                name: name.to_string(),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn list_namespaces(&self) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", "", "namespaces", None, None)?;
        let prefix = format!("{}/namespaces/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "v1",
            "kind": "NamespaceList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn delete_namespace(&self, name: &str) -> Result<(), ApiserverError> {
        self.check_auth_detailed("delete", "", "namespaces", None, Some(name))?;
        let key = format!("{}/namespaces/{name}", self.storage.prefix());
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "namespaces".to_string(),
                name: name.to_string(),
            });
        }
        Ok(())
    }

    // --- ConfigMap CRUD ---

    pub async fn create_configmap(
        &self,
        namespace: &str,
        name: &str,
        data: BTreeMap<String, String>,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("create", "", "configmaps", Some(namespace), Some(name))?;
        let key = format!("{}/configmaps/{namespace}/{name}", self.storage.prefix());
        let mut doc = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "creationTimestamp": crate::time::now_rfc3339()
            },
            "data": data
        });

        // Admission reviews
        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{}", self.storage.current_revision().await + 1),
            kind: GroupVersionKind {
                group: String::new(),
                version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
            },
            resource: GroupVersionResource {
                group: String::new(),
                version: "v1".to_string(),
                resource: "configmaps".to_string(),
            },
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info(),
            object: Some(doc.clone()),
            old_object: None,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            doc = obj;
        }

        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = doc;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn get_configmap(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "", "configmaps", Some(namespace), Some(name))?;
        let key = format!("{}/configmaps/{namespace}/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "configmaps".to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn update_configmap(
        &self,
        namespace: &str,
        name: &str,
        data: BTreeMap<String, String>,
        expected_version: Option<u64>,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("update", "", "configmaps", Some(namespace), Some(name))?;
        let key = format!("{}/configmaps/{namespace}/{name}", self.storage.prefix());
        let doc = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": namespace
            },
            "data": data
        });
        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        let mut result = doc;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn create_configmap_object(
        &self,
        namespace: &str,
        mut doc: Value,
    ) -> Result<Value, ApiserverError> {
        let name = doc
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: "ConfigMap missing metadata.name".to_string(),
            })?
            .to_string();

        self.check_auth_detailed("create", "", "configmaps", Some(namespace), Some(&name))?;
        let key = format!("{}/configmaps/{namespace}/{name}", self.storage.prefix());

        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{}", self.storage.current_revision().await + 1),
            kind: GroupVersionKind {
                group: String::new(),
                version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
            },
            resource: GroupVersionResource {
                group: String::new(),
                version: "v1".to_string(),
                resource: "configmaps".to_string(),
            },
            name: Some(name),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info(),
            object: Some(doc.clone()),
            old_object: None,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            doc = obj;
        }

        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = doc;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn patch_configmap(
        &self,
        namespace: &str,
        name: &str,
        patch: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("patch", "", "configmaps", Some(namespace), Some(name))?;
        let key = format!("{}/configmaps/{namespace}/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "configmaps".to_string(),
                name: format!("{namespace}/{name}"),
            })?;

        let mut configmap: Value = serde_json::from_slice(&kv.value)?;
        json_merge_patch(&mut configmap, patch);

        let bytes = serde_json::to_vec(&configmap)?;
        let updated_kv = self
            .storage
            .update(&key, bytes, Some(kv.mod_revision))
            .await?;
        if let Some(meta) = configmap.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(updated_kv.mod_revision.to_string()),
            );
        }
        Ok(configmap)
    }

    pub async fn list_configmaps(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", "", "configmaps", Some(namespace), None)?;
        let prefix = format!("{}/configmaps/{namespace}/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "v1",
            "kind": "ConfigMapList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn delete_configmap(
        &self,
        namespace: &str,
        name: &str,
        expected_version: Option<u64>,
    ) -> Result<(), ApiserverError> {
        self.check_auth_detailed("delete", "", "configmaps", Some(namespace), Some(name))?;
        let key = format!("{}/configmaps/{namespace}/{name}", self.storage.prefix());
        let res = self.storage.delete(&key, expected_version).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "configmaps".to_string(),
                name: format!("{namespace}/{name}"),
            });
        }
        Ok(())
    }

    // --- Secret CRUD ---

    pub async fn create_secret_object(
        &self,
        namespace: &str,
        mut doc: Value,
    ) -> Result<Value, ApiserverError> {
        let name = doc
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: "Secret missing metadata.name".to_string(),
            })?
            .to_string();

        self.check_auth_detailed("create", "", "secrets", Some(namespace), Some(&name))?;
        let key = format!("{}/secrets/{namespace}/{name}", self.storage.prefix());

        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{}", self.storage.current_revision().await + 1),
            kind: GroupVersionKind {
                group: String::new(),
                version: "v1".to_string(),
                kind: "Secret".to_string(),
            },
            resource: GroupVersionResource {
                group: String::new(),
                version: "v1".to_string(),
                resource: "secrets".to_string(),
            },
            name: Some(name),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info(),
            object: Some(doc.clone()),
            old_object: None,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            doc = obj;
        }

        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = doc;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn create_secret(
        &self,
        namespace: &str,
        name: &str,
        data: BTreeMap<String, String>,
        secret_type: Option<&str>,
    ) -> Result<Value, ApiserverError> {
        let doc = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "creationTimestamp": crate::time::now_rfc3339()
            },
            "type": secret_type.unwrap_or("Opaque"),
            "data": data
        });
        self.create_secret_object(namespace, doc).await
    }

    pub async fn get_secret(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "", "secrets", Some(namespace), Some(name))?;
        let key = format!("{}/secrets/{namespace}/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "secrets".to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn update_secret(
        &self,
        namespace: &str,
        name: &str,
        data: BTreeMap<String, String>,
        secret_type: Option<&str>,
        expected_version: Option<u64>,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("update", "", "secrets", Some(namespace), Some(name))?;
        let key = format!("{}/secrets/{namespace}/{name}", self.storage.prefix());
        let doc = json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "namespace": namespace
            },
            "type": secret_type.unwrap_or("Opaque"),
            "data": data
        });
        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        let mut result = doc;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn list_secrets(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", "", "secrets", Some(namespace), None)?;
        let prefix = format!("{}/secrets/{namespace}/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "v1",
            "kind": "SecretList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn delete_secret(
        &self,
        namespace: &str,
        name: &str,
        expected_version: Option<u64>,
    ) -> Result<(), ApiserverError> {
        self.check_auth_detailed("delete", "", "secrets", Some(namespace), Some(name))?;
        let key = format!("{}/secrets/{namespace}/{name}", self.storage.prefix());
        let res = self.storage.delete(&key, expected_version).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "secrets".to_string(),
                name: format!("{namespace}/{name}"),
            });
        }
        Ok(())
    }

    // --- ServiceAccount CRUD ---

    pub async fn create_service_account(
        &self,
        namespace: &str,
        doc: Value,
    ) -> Result<Value, ApiserverError> {
        let name = doc
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: "ServiceAccount missing metadata.name".to_string(),
            })?
            .to_string();

        self.check_auth_detailed(
            "create",
            "",
            "serviceaccounts",
            Some(namespace),
            Some(&name),
        )?;
        let key = format!(
            "{}/serviceaccounts/{namespace}/{name}",
            self.storage.prefix()
        );

        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = doc;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn get_service_account(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "", "serviceaccounts", Some(namespace), Some(name))?;
        let key = format!(
            "{}/serviceaccounts/{namespace}/{name}",
            self.storage.prefix()
        );
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "serviceaccounts".to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn list_service_accounts(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", "", "serviceaccounts", Some(namespace), None)?;
        let prefix = format!("{}/serviceaccounts/{namespace}/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "v1",
            "kind": "ServiceAccountList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn delete_service_account(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.check_auth_detailed("delete", "", "serviceaccounts", Some(namespace), Some(name))?;
        let key = format!(
            "{}/serviceaccounts/{namespace}/{name}",
            self.storage.prefix()
        );
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "serviceaccounts".to_string(),
                name: format!("{namespace}/{name}"),
            });
        }
        Ok(())
    }

    // --- Pod CRUD with Admission ---

    pub async fn create_pod(&self, namespace: &str, pod: Value) -> Result<Value, ApiserverError> {
        self.create_pod_options(namespace, pod, false).await
    }

    pub async fn create_pod_options(
        &self,
        namespace: &str,
        mut pod: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        let name = pod
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: "Pod requires metadata.name".to_string(),
            })?
            .to_string();

        self.check_auth_detailed("create", "", "pods", Some(namespace), Some(&name))?;

        if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("namespace".to_string(), json!(namespace));
            if !meta.contains_key("creationTimestamp") {
                meta.insert(
                    "creationTimestamp".to_string(),
                    json!(crate::time::now_rfc3339()),
                );
            }
            if !meta.contains_key("uid") {
                let cur_rev = self.storage.current_revision().await + 1;
                meta.insert(
                    "uid".to_string(),
                    json!(format!("uid-pods-{name}-{cur_rev}")),
                );
            }
        }

        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{}", self.storage.current_revision().await + 1),
            kind: GroupVersionKind {
                group: String::new(),
                version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            resource: GroupVersionResource {
                group: String::new(),
                version: "v1".to_string(),
                resource: "pods".to_string(),
            },
            name: Some(name.clone()),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info(),
            object: Some(pod.clone()),
            old_object: None,
            dry_run: if dry_run { Some(true) } else { None },
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            pod = obj;
        }

        if dry_run {
            return Ok(pod);
        }

        let key = format!("{}/pods/{namespace}/{name}", self.storage.prefix());
        let bytes = serde_json::to_vec(&pod)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = pod;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn get_pod(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "", "pods", Some(namespace), Some(name))?;
        let key = format!("{}/pods/{namespace}/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "pods".to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn list_pods(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", "", "pods", Some(namespace), None)?;
        let prefix = format!("{}/pods/{namespace}/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    /// Lists pods in every namespace; the kubelet uses this to find work for its node.
    pub async fn list_all_pods(&self) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", "", "pods", None, None)?;
        let prefix = format!("{}/pods/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": { "resourceVersion": cur_rev.to_string() },
            "items": items
        }))
    }

    pub async fn delete_pod(&self, namespace: &str, name: &str) -> Result<(), ApiserverError> {
        self.delete_pod_options(namespace, name, None)
            .await
            .map(drop)
    }

    /// Deletes a pod with Kubernetes graceful-deletion semantics.
    ///
    /// A pod that a kubelet has acknowledged (bound to a node and reported
    /// `Pending` or `Running`) is marked with `deletionTimestamp` and
    /// `deletionGracePeriodSeconds` and returned as `Some`; the kubelet stops its
    /// containers and then deletes it with a zero grace period. Unscheduled,
    /// unacknowledged and terminal pods are removed at once, as is any pod when
    /// `grace_period_seconds` is zero.
    pub async fn delete_pod_options(
        &self,
        namespace: &str,
        name: &str,
        grace_period_seconds: Option<i64>,
    ) -> Result<Option<Value>, ApiserverError> {
        self.check_auth_detailed("delete", "", "pods", Some(namespace), Some(name))?;
        let key = format!("{}/pods/{namespace}/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "pods".to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let mut pod: Value = serde_json::from_slice(&kv.value)?;
        let scheduled = pod
            .pointer("/spec/nodeName")
            .and_then(Value::as_str)
            .is_some_and(|node| !node.is_empty());
        let acknowledged = matches!(
            pod.pointer("/status/phase").and_then(Value::as_str),
            Some("Pending" | "Running")
        );
        if grace_period_seconds == Some(0) || !scheduled || !acknowledged {
            self.storage.delete(&key, None).await?;
            return Ok(None);
        }
        let requested = grace_period_seconds
            .or_else(|| {
                pod.pointer("/spec/terminationGracePeriodSeconds")
                    .and_then(Value::as_i64)
            })
            .unwrap_or(30)
            .max(0);
        let now = crate::time::now_unix();
        let deadline = now.saturating_add(u64::try_from(requested).unwrap_or(0));
        let existing_deadline = pod
            .pointer("/metadata/deletionTimestamp")
            .and_then(Value::as_str)
            .and_then(crate::time::parse_rfc3339_seconds);
        if existing_deadline.is_some_and(|existing| existing <= deadline) {
            // Already terminating with an earlier or equal deadline; nothing to shorten.
            if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            return Ok(Some(pod));
        }
        if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "deletionTimestamp".to_string(),
                json!(crate::time::rfc3339_seconds(deadline)),
            );
            meta.insert("deletionGracePeriodSeconds".to_string(), json!(requested));
        }
        let bytes = serde_json::to_vec(&pod)?;
        let updated = self
            .storage
            .update(&key, bytes, Some(kv.mod_revision))
            .await?;
        if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(updated.mod_revision.to_string()),
            );
        }
        Ok(Some(pod))
    }

    pub async fn update_pod(
        &self,
        namespace: &str,
        name: &str,
        pod: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_pod_options(namespace, name, pod, false).await
    }

    pub async fn update_pod_options(
        &self,
        namespace: &str,
        name: &str,
        mut pod: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("update", "", "pods", Some(namespace), Some(name))?;
        let key = format!("{}/pods/{namespace}/{name}", self.storage.prefix());
        let existing = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "pods".to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let old_pod: Value = serde_json::from_slice(&existing.value)?;

        if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("namespace".to_string(), json!(namespace));
            meta.insert("name".to_string(), json!(name));
            if let Some(old_uid) = old_pod.get("metadata").and_then(|m| m.get("uid")) {
                meta.insert("uid".to_string(), old_uid.clone());
            }
        }

        let expected_version = pod
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .and_then(|v| v.parse::<u64>().ok());

        let cur_rev = self.storage.current_revision().await + 1;
        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{cur_rev}"),
            kind: GroupVersionKind {
                group: String::new(),
                version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            resource: GroupVersionResource {
                group: String::new(),
                version: "v1".to_string(),
                resource: "pods".to_string(),
            },
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "UPDATE".to_string(),
            user_info: self.current_user_info(),
            object: Some(pod.clone()),
            old_object: Some(old_pod.clone()),
            dry_run: if dry_run { Some(true) } else { None },
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;

        let old_node = old_pod.pointer("/spec/nodeName").and_then(Value::as_str);
        let new_node = adm_req
            .object
            .as_ref()
            .and_then(|obj| obj.pointer("/spec/nodeName"))
            .and_then(Value::as_str);
        if let Some(old) = old_node {
            if let Some(new) = new_node {
                if old != new {
                    return Err(ApiserverError::InvalidInput {
                        field: "spec.nodeName".to_string(),
                        reason: "spec.nodeName is immutable once assigned".to_string(),
                    });
                }
            } else {
                return Err(ApiserverError::InvalidInput {
                    field: "spec.nodeName".to_string(),
                    reason: "spec.nodeName cannot be unset once assigned".to_string(),
                });
            }
        }

        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            pod = obj;
        }

        if dry_run {
            return Ok(pod);
        }

        let bytes = serde_json::to_vec(&pod)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        let mut result = pod;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn patch_pod_status(
        &self,
        namespace: &str,
        name: &str,
        status: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("patch", "", "pods/status", Some(namespace), Some(name))?;
        let key = format!("{}/pods/{namespace}/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "pods".to_string(),
                name: format!("{namespace}/{name}"),
            })?;

        let mut pod: Value = serde_json::from_slice(&kv.value)?;
        pod["status"] = status;

        let bytes = serde_json::to_vec(&pod)?;
        let updated_kv = self
            .storage
            .update(&key, bytes, Some(kv.mod_revision))
            .await?;
        if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(updated_kv.mod_revision.to_string()),
            );
        }
        Ok(pod)
    }

    // --- Workload Resources (apps/v1 & batch/v1) ---

    async fn create_workload(
        &self,
        group: &str,
        kind: &str,
        plural: &str,
        namespace: &str,
        doc: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_workload_options(group, kind, plural, namespace, doc, false)
            .await
    }

    async fn create_workload_options(
        &self,
        group: &str,
        kind: &str,
        plural: &str,
        namespace: &str,
        mut doc: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        let name = doc
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: format!("{kind} requires metadata.name"),
            })?
            .to_string();

        self.check_auth_detailed("create", group, plural, Some(namespace), Some(&name))?;

        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("namespace".to_string(), json!(namespace));
            if !meta.contains_key("creationTimestamp") {
                meta.insert(
                    "creationTimestamp".to_string(),
                    json!(crate::time::now_rfc3339()),
                );
            }
            if !meta.contains_key("uid") {
                meta.insert(
                    "uid".to_string(),
                    json!(format!("uid-{plural}-{name}-{cur_rev}")),
                );
            }
        }

        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{cur_rev}"),
            kind: GroupVersionKind {
                group: group.to_string(),
                version: "v1".to_string(),
                kind: kind.to_string(),
            },
            resource: GroupVersionResource {
                group: group.to_string(),
                version: "v1".to_string(),
                resource: plural.to_string(),
            },
            name: Some(name.clone()),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info(),
            object: Some(doc.clone()),
            old_object: None,
            dry_run: if dry_run { Some(true) } else { None },
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            doc = obj;
        }

        if dry_run {
            return Ok(doc);
        }

        let key = if group.is_empty() {
            format!("{}/{plural}/{namespace}/{name}", self.storage.prefix())
        } else {
            format!(
                "{}/{group}/{plural}/{namespace}/{name}",
                self.storage.prefix()
            )
        };
        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = doc;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    async fn get_workload(
        &self,
        group: &str,
        plural: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", group, plural, Some(namespace), Some(name))?;
        let key = if group.is_empty() {
            format!("{}/{plural}/{namespace}/{name}", self.storage.prefix())
        } else {
            format!(
                "{}/{group}/{plural}/{namespace}/{name}",
                self.storage.prefix()
            )
        };
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: plural.to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    async fn list_workload(
        &self,
        group: &str,
        kind_list: &str,
        plural: &str,
        namespace: &str,
    ) -> Result<Value, ApiserverError> {
        let authz_ns = if namespace.is_empty() {
            None
        } else {
            Some(namespace)
        };
        self.check_auth_detailed("list", group, plural, authz_ns, None)?;
        let prefix = if group.is_empty() {
            if namespace.is_empty() {
                format!("{}/{plural}/", self.storage.prefix())
            } else {
                format!("{}/{plural}/{namespace}/", self.storage.prefix())
            }
        } else if namespace.is_empty() {
            format!("{}/{group}/{plural}/", self.storage.prefix())
        } else {
            format!("{}/{group}/{plural}/{namespace}/", self.storage.prefix())
        };
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        let api_version = if group.is_empty() {
            "v1".to_string()
        } else {
            format!("{group}/v1")
        };
        Ok(json!({
            "apiVersion": api_version,
            "kind": kind_list,
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    async fn update_workload(
        &self,
        group: &str,
        kind: &str,
        plural: &str,
        namespace: &str,
        name: &str,
        doc: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_workload_options(group, kind, plural, namespace, name, doc, false)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_workload_options(
        &self,
        group: &str,
        kind: &str,
        plural: &str,
        namespace: &str,
        name: &str,
        mut doc: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("update", group, plural, Some(namespace), Some(name))?;
        let key = if group.is_empty() {
            format!("{}/{plural}/{namespace}/{name}", self.storage.prefix())
        } else {
            format!(
                "{}/{group}/{plural}/{namespace}/{name}",
                self.storage.prefix()
            )
        };
        let existing = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: plural.to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let old_doc: Value = serde_json::from_slice(&existing.value)?;

        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("namespace".to_string(), json!(namespace));
            meta.insert("name".to_string(), json!(name));
            if let Some(old_uid) = old_doc.get("metadata").and_then(|m| m.get("uid")) {
                meta.insert("uid".to_string(), old_uid.clone());
            }
        }

        if let (true, Some(old_status)) = (
            doc.get("status").is_none_or(Value::is_null),
            old_doc.get("status").filter(|s| !s.is_null()),
        ) {
            doc["status"] = old_status.clone();
        }

        let expected_version = doc
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .and_then(|v| v.parse::<u64>().ok());

        let cur_rev = self.storage.current_revision().await + 1;
        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{cur_rev}"),
            kind: GroupVersionKind {
                group: group.to_string(),
                version: "v1".to_string(),
                kind: kind.to_string(),
            },
            resource: GroupVersionResource {
                group: group.to_string(),
                version: "v1".to_string(),
                resource: plural.to_string(),
            },
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "UPDATE".to_string(),
            user_info: self.current_user_info(),
            object: Some(doc.clone()),
            old_object: Some(old_doc.clone()),
            dry_run: if dry_run { Some(true) } else { None },
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;

        if kind == "Job" {
            let old_tmpl = old_doc.pointer("/spec/template");
            let new_tmpl = adm_req
                .object
                .as_ref()
                .and_then(|obj| obj.pointer("/spec/template"));
            if old_tmpl.is_some() && old_tmpl != new_tmpl {
                return Err(ApiserverError::InvalidInput {
                    field: "spec.template".to_string(),
                    reason: "spec.template is immutable for jobs".to_string(),
                });
            }
        }

        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            doc = obj;
        }

        if dry_run {
            return Ok(doc);
        }

        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        let mut result = doc;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    async fn delete_workload(
        &self,
        group: &str,
        plural: &str,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.check_auth_detailed("delete", group, plural, Some(namespace), Some(name))?;
        let key = if group.is_empty() {
            format!("{}/{plural}/{namespace}/{name}", self.storage.prefix())
        } else {
            format!(
                "{}/{group}/{plural}/{namespace}/{name}",
                self.storage.prefix()
            )
        };
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: plural.to_string(),
                name: format!("{namespace}/{name}"),
            });
        }
        Ok(())
    }

    // Deployments
    pub async fn create_deployment(
        &self,
        namespace: &str,
        deployment: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_workload("apps", "Deployment", "deployments", namespace, deployment)
            .await
    }
    pub async fn get_deployment(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.get_workload("apps", "deployments", namespace, name)
            .await
    }
    pub async fn list_deployments(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.list_workload("apps", "DeploymentList", "deployments", namespace)
            .await
    }
    pub async fn update_deployment(
        &self,
        namespace: &str,
        name: &str,
        deployment: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_workload(
            "apps",
            "Deployment",
            "deployments",
            namespace,
            name,
            deployment,
        )
        .await
    }
    pub async fn delete_deployment(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.delete_workload("apps", "deployments", namespace, name)
            .await
    }

    // ReplicaSets
    pub async fn create_replicaset(
        &self,
        namespace: &str,
        replicaset: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_workload("apps", "ReplicaSet", "replicasets", namespace, replicaset)
            .await
    }
    pub async fn get_replicaset(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.get_workload("apps", "replicasets", namespace, name)
            .await
    }
    pub async fn list_replicasets(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.list_workload("apps", "ReplicaSetList", "replicasets", namespace)
            .await
    }
    pub async fn update_replicaset(
        &self,
        namespace: &str,
        name: &str,
        replicaset: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_workload(
            "apps",
            "ReplicaSet",
            "replicasets",
            namespace,
            name,
            replicaset,
        )
        .await
    }
    pub async fn delete_replicaset(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.delete_workload("apps", "replicasets", namespace, name)
            .await
    }

    // StatefulSets
    pub async fn create_statefulset(
        &self,
        namespace: &str,
        statefulset: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_workload(
            "apps",
            "StatefulSet",
            "statefulsets",
            namespace,
            statefulset,
        )
        .await
    }
    pub async fn get_statefulset(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.get_workload("apps", "statefulsets", namespace, name)
            .await
    }
    pub async fn list_statefulsets(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.list_workload("apps", "StatefulSetList", "statefulsets", namespace)
            .await
    }
    pub async fn update_statefulset(
        &self,
        namespace: &str,
        name: &str,
        statefulset: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_workload(
            "apps",
            "StatefulSet",
            "statefulsets",
            namespace,
            name,
            statefulset,
        )
        .await
    }
    pub async fn delete_statefulset(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.delete_workload("apps", "statefulsets", namespace, name)
            .await
    }

    // DaemonSets
    pub async fn create_daemonset(
        &self,
        namespace: &str,
        daemonset: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_workload("apps", "DaemonSet", "daemonsets", namespace, daemonset)
            .await
    }
    pub async fn get_daemonset(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.get_workload("apps", "daemonsets", namespace, name)
            .await
    }
    pub async fn list_daemonsets(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.list_workload("apps", "DaemonSetList", "daemonsets", namespace)
            .await
    }
    pub async fn update_daemonset(
        &self,
        namespace: &str,
        name: &str,
        daemonset: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_workload(
            "apps",
            "DaemonSet",
            "daemonsets",
            namespace,
            name,
            daemonset,
        )
        .await
    }
    pub async fn delete_daemonset(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.delete_workload("apps", "daemonsets", namespace, name)
            .await
    }

    // Jobs
    pub async fn create_job(&self, namespace: &str, job: Value) -> Result<Value, ApiserverError> {
        self.create_job_options(namespace, job, false).await
    }
    pub async fn create_job_options(
        &self,
        namespace: &str,
        job: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        self.create_workload_options("batch", "Job", "jobs", namespace, job, dry_run)
            .await
    }
    pub async fn get_job(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        self.get_workload("batch", "jobs", namespace, name).await
    }
    pub async fn list_jobs(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.list_workload("batch", "JobList", "jobs", namespace)
            .await
    }
    pub async fn update_job(
        &self,
        namespace: &str,
        name: &str,
        job: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_job_options(namespace, name, job, false).await
    }
    pub async fn update_job_options(
        &self,
        namespace: &str,
        name: &str,
        job: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        self.update_workload_options("batch", "Job", "jobs", namespace, name, job, dry_run)
            .await
    }
    pub async fn delete_job(&self, namespace: &str, name: &str) -> Result<(), ApiserverError> {
        self.delete_workload("batch", "jobs", namespace, name).await
    }

    // CronJobs
    pub async fn create_cronjob(
        &self,
        namespace: &str,
        cronjob: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_workload("batch", "CronJob", "cronjobs", namespace, cronjob)
            .await
    }
    pub async fn get_cronjob(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        self.get_workload("batch", "cronjobs", namespace, name)
            .await
    }
    pub async fn list_cronjobs(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.list_workload("batch", "CronJobList", "cronjobs", namespace)
            .await
    }
    pub async fn update_cronjob(
        &self,
        namespace: &str,
        name: &str,
        cronjob: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_workload("batch", "CronJob", "cronjobs", namespace, name, cronjob)
            .await
    }
    pub async fn delete_cronjob(&self, namespace: &str, name: &str) -> Result<(), ApiserverError> {
        self.delete_workload("batch", "cronjobs", namespace, name)
            .await
    }

    // PersistentVolumeClaims
    pub async fn create_pvc(&self, namespace: &str, pvc: Value) -> Result<Value, ApiserverError> {
        self.create_pvc_options(namespace, pvc, false).await
    }
    pub async fn create_pvc_options(
        &self,
        namespace: &str,
        pvc: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        self.create_workload_options(
            "",
            "PersistentVolumeClaim",
            "persistentvolumeclaims",
            namespace,
            pvc,
            dry_run,
        )
        .await
    }
    pub async fn get_pvc(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        self.get_workload("", "persistentvolumeclaims", namespace, name)
            .await
    }
    pub async fn list_pvcs(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.list_workload(
            "",
            "PersistentVolumeClaimList",
            "persistentvolumeclaims",
            namespace,
        )
        .await
    }
    pub async fn update_pvc(
        &self,
        namespace: &str,
        name: &str,
        pvc: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_pvc_options(namespace, name, pvc, false).await
    }
    pub async fn update_pvc_options(
        &self,
        namespace: &str,
        name: &str,
        pvc: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        self.update_workload_options(
            "",
            "PersistentVolumeClaim",
            "persistentvolumeclaims",
            namespace,
            name,
            pvc,
            dry_run,
        )
        .await
    }
    pub async fn delete_pvc(&self, namespace: &str, name: &str) -> Result<(), ApiserverError> {
        self.delete_workload("", "persistentvolumeclaims", namespace, name)
            .await
    }

    // --- StorageClass CRUD ---

    pub async fn create_storage_class(&self, mut sc: Value) -> Result<Value, ApiserverError> {
        let name = sc
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: "StorageClass requires metadata.name".to_string(),
            })?
            .to_string();

        self.check_auth_detailed(
            "create",
            "storage.k8s.io",
            "storageclasses",
            None,
            Some(&name),
        )?;

        if let Some(meta) = sc.get_mut("metadata").and_then(Value::as_object_mut) {
            if !meta.contains_key("creationTimestamp") {
                meta.insert(
                    "creationTimestamp".to_string(),
                    json!(crate::time::now_rfc3339()),
                );
            }
            if !meta.contains_key("uid") {
                let cur_rev = self.storage.current_revision().await + 1;
                meta.insert(
                    "uid".to_string(),
                    json!(format!("uid-storageclasses-{name}-{cur_rev}")),
                );
            }
        }

        let key = format!("{}/storageclasses/{name}", self.storage.prefix());
        let bytes = serde_json::to_vec(&sc)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = sc;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn get_storage_class(&self, name: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "storage.k8s.io", "storageclasses", None, Some(name))?;
        let key = format!("{}/storageclasses/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "storageclasses".to_string(),
                name: name.to_string(),
            })?;
        let mut val: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = val.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(val)
    }

    pub async fn list_storage_classes(&self) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", "storage.k8s.io", "storageclasses", None, None)?;
        let prefix = format!("{}/storageclasses/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            if let Ok(mut val) = serde_json::from_slice::<Value>(&kv.value) {
                if let Some(meta) = val.get_mut("metadata").and_then(Value::as_object_mut) {
                    meta.insert(
                        "resourceVersion".to_string(),
                        json!(kv.mod_revision.to_string()),
                    );
                }
                items.push(val);
            }
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClassList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn update_storage_class(
        &self,
        name: &str,
        mut sc: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "update",
            "storage.k8s.io",
            "storageclasses",
            None,
            Some(name),
        )?;
        let key = format!("{}/storageclasses/{name}", self.storage.prefix());
        let existing = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "storageclasses".to_string(),
                name: name.to_string(),
            })?;
        let old: Value = serde_json::from_slice(&existing.value)?;
        if let Some(meta) = sc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("name".to_string(), json!(name));
            for k in ["uid", "creationTimestamp"] {
                if let Some(v) = old.get("metadata").and_then(|m| m.get(k)) {
                    meta.insert(k.to_string(), v.clone());
                }
            }
        }
        let bytes = serde_json::to_vec(&sc)?;
        let kv = self.storage.update(&key, bytes, None).await?;
        if let Some(meta) = sc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(sc)
    }

    pub async fn delete_storage_class(&self, name: &str) -> Result<(), ApiserverError> {
        self.check_auth_detailed(
            "delete",
            "storage.k8s.io",
            "storageclasses",
            None,
            Some(name),
        )?;
        let key = format!("{}/storageclasses/{name}", self.storage.prefix());
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "storageclasses".to_string(),
                name: name.to_string(),
            });
        }
        Ok(())
    }

    // --- PersistentVolume CRUD ---

    pub async fn create_pv(&self, mut pv: Value) -> Result<Value, ApiserverError> {
        let name = pv
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: "PersistentVolume requires metadata.name".to_string(),
            })?
            .to_string();

        self.check_auth_detailed("create", "", "persistentvolumes", None, Some(&name))?;

        if let Some(meta) = pv.get_mut("metadata").and_then(Value::as_object_mut) {
            if !meta.contains_key("creationTimestamp") {
                meta.insert(
                    "creationTimestamp".to_string(),
                    json!(crate::time::now_rfc3339()),
                );
            }
            if !meta.contains_key("uid") {
                let cur_rev = self.storage.current_revision().await + 1;
                meta.insert(
                    "uid".to_string(),
                    json!(format!("uid-persistentvolumes-{name}-{cur_rev}")),
                );
            }
        }

        let key = format!("{}/persistentvolumes/{name}", self.storage.prefix());
        let bytes = serde_json::to_vec(&pv)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = pv;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn get_pv(&self, name: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "", "persistentvolumes", None, Some(name))?;
        let key = format!("{}/persistentvolumes/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "persistentvolumes".to_string(),
                name: name.to_string(),
            })?;
        let mut val: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = val.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(val)
    }

    pub async fn list_pvs(&self) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", "", "persistentvolumes", None, None)?;
        let prefix = format!("{}/persistentvolumes/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            if let Ok(mut val) = serde_json::from_slice::<Value>(&kv.value) {
                if let Some(meta) = val.get_mut("metadata").and_then(Value::as_object_mut) {
                    meta.insert(
                        "resourceVersion".to_string(),
                        json!(kv.mod_revision.to_string()),
                    );
                }
                items.push(val);
            }
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn update_pv(&self, name: &str, mut pv: Value) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("update", "", "persistentvolumes", None, Some(name))?;
        let key = format!("{}/persistentvolumes/{name}", self.storage.prefix());
        let existing = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "persistentvolumes".to_string(),
                name: name.to_string(),
            })?;
        let old: Value = serde_json::from_slice(&existing.value)?;
        if let Some(meta) = pv.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("name".to_string(), json!(name));
            for k in ["uid", "creationTimestamp"] {
                if let Some(v) = old.get("metadata").and_then(|m| m.get(k)) {
                    meta.insert(k.to_string(), v.clone());
                }
            }
        }
        let expected_version = pv
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .and_then(|v| v.parse::<u64>().ok());
        let bytes = serde_json::to_vec(&pv)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        if let Some(meta) = pv.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(pv)
    }

    pub async fn delete_pv(&self, name: &str) -> Result<(), ApiserverError> {
        self.check_auth_detailed("delete", "", "persistentvolumes", None, Some(name))?;
        let key = format!("{}/persistentvolumes/{name}", self.storage.prefix());
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "persistentvolumes".to_string(),
                name: name.to_string(),
            });
        }
        Ok(())
    }

    // --- Service, Endpoints & EndpointSlice CRUD ---

    pub async fn create_service(
        &self,
        namespace: &str,
        service: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_service_options(namespace, service, false).await
    }
    fn cidr_bounds(&self) -> Result<(u32, u32), ApiserverError> {
        let (base_ip, prefix_len) = parse_ipv4_cidr(&self.service_cluster_ip_range)?;
        let base = u32::from(base_ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            let shift = u32::from(32 - prefix_len);
            !((1u32.checked_shl(shift).unwrap_or(0)).wrapping_sub(1))
        };
        let network = base & mask;
        let broadcast = network | !mask;
        Ok((network, broadcast))
    }

    fn collect_doc_service_resources(
        doc: &Value,
        allocated_ips: &mut BTreeSet<Ipv4Addr>,
        allocated_ports: &mut BTreeSet<u16>,
    ) {
        if let Some(ip) = doc
            .pointer("/spec/clusterIP")
            .and_then(Value::as_str)
            .filter(|s| *s != "None" && !s.is_empty())
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
        {
            allocated_ips.insert(ip);
        }

        if let Some(ips) = doc.pointer("/spec/clusterIPs").and_then(Value::as_array) {
            for ip_val in ips {
                if let Some(ip) = ip_val
                    .as_str()
                    .filter(|s| *s != "None" && !s.is_empty())
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                {
                    allocated_ips.insert(ip);
                }
            }
        }

        if let Some(ports) = doc.pointer("/spec/ports").and_then(Value::as_array) {
            for p in ports {
                if let Some(np) = p
                    .get("nodePort")
                    .and_then(Value::as_u64)
                    .and_then(|np| u16::try_from(np).ok())
                    .filter(|&np| np > 0)
                {
                    allocated_ports.insert(np);
                }
            }
        }
    }

    async fn collect_allocated_service_resources(
        &self,
        exclude: Option<(&str, &str)>,
    ) -> Result<(BTreeSet<Ipv4Addr>, BTreeSet<u16>), ApiserverError> {
        let prefix = format!("{}/services/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut allocated_ips = BTreeSet::new();
        let mut allocated_ports = BTreeSet::new();

        for kv in kvs {
            let doc: Value = serde_json::from_slice(&kv.value)?;
            let ns = doc
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let name = doc
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or_default();

            if exclude == Some((ns, name)) {
                continue;
            }

            Self::collect_doc_service_resources(&doc, &mut allocated_ips, &mut allocated_ports);
        }

        Ok((allocated_ips, allocated_ports))
    }

    fn allocate_cluster_ip(
        &self,
        namespace: &str,
        name: &str,
        allocated_ips: &BTreeSet<Ipv4Addr>,
    ) -> Result<Ipv4Addr, ApiserverError> {
        let (network, broadcast) = self.cidr_bounds()?;
        let is_kubernetes_svc = namespace == "default" && name == "kubernetes";
        let start = if is_kubernetes_svc {
            network + 1
        } else if broadcast > network + 2 {
            network + 2
        } else {
            network
        };
        let end = if broadcast > network + 2 {
            broadcast - 1
        } else {
            broadcast
        };

        for ip_u32 in start..=end {
            if !is_kubernetes_svc && ip_u32 == network + 1 {
                // Reserve .1 for default/kubernetes
                continue;
            }
            let ip = Ipv4Addr::from(ip_u32);
            if !allocated_ips.contains(&ip) {
                return Ok(ip);
            }
        }

        Err(ApiserverError::InvalidInput {
            field: "spec.clusterIP".to_string(),
            reason: "service cluster IP range is full".to_string(),
        })
    }

    fn validate_specified_cluster_ip(
        &self,
        ip_str: &str,
        allocated_ips: &BTreeSet<Ipv4Addr>,
    ) -> Result<Ipv4Addr, ApiserverError> {
        let ip: Ipv4Addr = ip_str.parse().map_err(|_| ApiserverError::InvalidInput {
            field: "spec.clusterIP".to_string(),
            reason: format!("invalid cluster IP '{ip_str}'"),
        })?;
        let (network, broadcast) = self.cidr_bounds()?;
        let ip_u32 = u32::from(ip);
        if ip_u32 < network || ip_u32 > broadcast {
            return Err(ApiserverError::InvalidInput {
                field: "spec.clusterIP".to_string(),
                reason: format!(
                    "cluster IP {ip} is not within service CIDR {}",
                    self.service_cluster_ip_range
                ),
            });
        }
        if allocated_ips.contains(&ip) {
            return Err(ApiserverError::InvalidInput {
                field: "spec.clusterIP".to_string(),
                reason: format!("cluster IP {ip} is already allocated"),
            });
        }
        Ok(ip)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn prepare_service_for_create(
        &self,
        namespace: &str,
        service: &mut Value,
    ) -> Result<(), ApiserverError> {
        let name = service
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let (mut allocated_ips, mut allocated_ports) =
            self.collect_allocated_service_resources(None).await?;

        let spec = service
            .get_mut("spec")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "spec".to_string(),
                reason: "Service requires a spec object".to_string(),
            })?;

        // 1. Default spec.type
        if !spec.contains_key("type")
            || spec
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(str::is_empty)
        {
            spec.insert("type".to_string(), json!("ClusterIP"));
        }
        let svc_type = spec
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("ClusterIP")
            .to_string();

        // 2. Default sessionAffinity
        if !spec.contains_key("sessionAffinity") {
            spec.insert("sessionAffinity".to_string(), json!("None"));
        }

        // 3. ClusterIP allocation
        let specified_cluster_ip = spec
            .get("clusterIP")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

        if svc_type == "ExternalName" {
            // ExternalName does not allocate clusterIP
        } else if let Some(ip_str) = specified_cluster_ip {
            if ip_str == "None" {
                // Headless service
            } else {
                let validated_ip = self.validate_specified_cluster_ip(&ip_str, &allocated_ips)?;
                allocated_ips.insert(validated_ip);
                if !spec.contains_key("clusterIPs") {
                    spec.insert("clusterIPs".to_string(), json!([ip_str]));
                }
            }
        } else {
            // Allocate clusterIP
            let allocated = self.allocate_cluster_ip(namespace, &name, &allocated_ips)?;
            allocated_ips.insert(allocated);
            let ip_str = allocated.to_string();
            spec.insert("clusterIP".to_string(), json!(ip_str));
            if !spec.contains_key("clusterIPs") {
                spec.insert("clusterIPs".to_string(), json!([ip_str]));
            }
        }

        // 4. Default ports and allocate nodePort if NodePort / LoadBalancer
        let needs_node_port = matches!(svc_type.as_str(), "NodePort" | "LoadBalancer");
        let (min_port, max_port) = parse_port_range(&self.service_node_port_range)?;

        if let Some(ports) = spec.get_mut("ports").and_then(Value::as_array_mut) {
            for port in ports.iter_mut() {
                let Some(port_obj) = port.as_object_mut() else {
                    continue;
                };

                if !port_obj.contains_key("protocol") {
                    port_obj.insert("protocol".to_string(), json!("TCP"));
                }

                if !needs_node_port {
                    continue;
                }

                let requested = port_obj
                    .get("nodePort")
                    .and_then(Value::as_u64)
                    .filter(|&p| p > 0);
                let requested_u16 = if let Some(np_u64) = requested {
                    let np = u16::try_from(np_u64).map_err(|_| ApiserverError::InvalidInput {
                        field: "spec.ports[].nodePort".to_string(),
                        reason: format!(
                            "nodePort {np_u64} is outside allowed range {min_port}-{max_port}"
                        ),
                    })?;
                    Some(np)
                } else {
                    None
                };

                Self::allocate_or_validate_node_port(
                    port_obj,
                    requested_u16,
                    min_port,
                    max_port,
                    &mut allocated_ports,
                )?;
            }
        }

        Ok(())
    }

    fn allocate_or_validate_node_port(
        port_obj: &mut serde_json::Map<String, Value>,
        requested_port: Option<u16>,
        min_port: u16,
        max_port: u16,
        allocated_ports: &mut BTreeSet<u16>,
    ) -> Result<(), ApiserverError> {
        let port = if let Some(np) = requested_port {
            if np < min_port || np > max_port {
                return Err(ApiserverError::InvalidInput {
                    field: "spec.ports[].nodePort".to_string(),
                    reason: format!("nodePort {np} is outside allowed range {min_port}-{max_port}"),
                });
            }
            if allocated_ports.contains(&np) {
                return Err(ApiserverError::InvalidInput {
                    field: "spec.ports[].nodePort".to_string(),
                    reason: format!("nodePort {np} is already allocated"),
                });
            }
            np
        } else {
            (min_port..=max_port)
                .find(|cand| !allocated_ports.contains(cand))
                .ok_or_else(|| ApiserverError::InvalidInput {
                    field: "spec.ports[].nodePort".to_string(),
                    reason: "service node port range is full".to_string(),
                })?
        };

        allocated_ports.insert(port);
        port_obj.insert("nodePort".to_string(), json!(port));
        Ok(())
    }

    fn extract_old_node_ports(old_doc: &Value) -> (BTreeMap<i64, u16>, BTreeMap<String, u16>) {
        let mut by_port = BTreeMap::new();
        let mut by_name = BTreeMap::new();
        let Some(old_ports) = old_doc.pointer("/spec/ports").and_then(Value::as_array) else {
            return (by_port, by_name);
        };
        for p in old_ports {
            let Some(np) = p
                .get("nodePort")
                .and_then(Value::as_u64)
                .and_then(|np| u16::try_from(np).ok())
                .filter(|&np| np > 0)
            else {
                continue;
            };
            if let Some(port_num) = p.get("port").and_then(Value::as_i64) {
                by_port.insert(port_num, np);
            }
            if let Some(port_name) = p.get("name").and_then(Value::as_str) {
                by_name.insert(port_name.to_string(), np);
            }
        }
        (by_port, by_name)
    }

    #[allow(clippy::too_many_lines)]
    pub async fn prepare_service_for_update(
        &self,
        namespace: &str,
        name: &str,
        service: &mut Value,
    ) -> Result<(), ApiserverError> {
        let key = format!("{}/services/{namespace}/{name}", self.storage.prefix());
        let existing = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "services".to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let old_doc: Value = serde_json::from_slice(&existing.value)?;

        let (mut allocated_ips, mut allocated_ports) = self
            .collect_allocated_service_resources(Some((namespace, name)))
            .await?;

        let spec = service
            .get_mut("spec")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "spec".to_string(),
                reason: "Service requires a spec object".to_string(),
            })?;

        // 1. Default spec.type
        if !spec.contains_key("type")
            || spec
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(str::is_empty)
        {
            spec.insert("type".to_string(), json!("ClusterIP"));
        }
        let svc_type = spec
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("ClusterIP")
            .to_string();

        // 2. Default sessionAffinity
        if !spec.contains_key("sessionAffinity") {
            spec.insert("sessionAffinity".to_string(), json!("None"));
        }

        // 3. ClusterIP immutability / allocation
        let old_cluster_ip = old_doc.pointer("/spec/clusterIP").and_then(Value::as_str);
        let new_cluster_ip = spec.get("clusterIP").and_then(Value::as_str);

        match (old_cluster_ip, new_cluster_ip) {
            (Some(old_ip), None | Some("")) => {
                spec.insert("clusterIP".to_string(), json!(old_ip));
            },
            (Some(old_ip), Some(new_ip)) if old_ip != new_ip => {
                return Err(ApiserverError::InvalidInput {
                    field: "spec.clusterIP".to_string(),
                    reason: "field is immutable".to_string(),
                });
            },
            (None, None | Some("")) => {
                if svc_type != "ExternalName" {
                    let allocated = self.allocate_cluster_ip(namespace, name, &allocated_ips)?;
                    allocated_ips.insert(allocated);
                    spec.insert("clusterIP".to_string(), json!(allocated.to_string()));
                }
            },
            (None, Some(new_ip)) if new_ip != "None" => {
                let validated_ip = self.validate_specified_cluster_ip(new_ip, &allocated_ips)?;
                allocated_ips.insert(validated_ip);
            },
            _ => {},
        }

        if let Some(cip) = spec
            .get("clusterIP")
            .and_then(Value::as_str)
            .filter(|cip| *cip != "None" && !cip.is_empty() && !spec.contains_key("clusterIPs"))
        {
            spec.insert("clusterIPs".to_string(), json!([cip]));
        }

        // 4. Ports defaulting & NodePort handling
        let needs_node_port = matches!(svc_type.as_str(), "NodePort" | "LoadBalancer");
        let (min_port, max_port) = parse_port_range(&self.service_node_port_range)?;

        let (old_node_ports_by_port, old_node_ports_by_name) =
            Self::extract_old_node_ports(&old_doc);

        if let Some(ports) = spec.get_mut("ports").and_then(Value::as_array_mut) {
            for port in ports.iter_mut() {
                let Some(port_obj) = port.as_object_mut() else {
                    continue;
                };

                if !port_obj.contains_key("protocol") {
                    port_obj.insert("protocol".to_string(), json!("TCP"));
                }

                if !needs_node_port {
                    // Deallocate nodePort if changed to ClusterIP or ExternalName
                    port_obj.remove("nodePort");
                    continue;
                }

                let specified_node_port = port_obj
                    .get("nodePort")
                    .and_then(Value::as_u64)
                    .filter(|&p| p > 0)
                    .and_then(|p| u16::try_from(p).ok());

                let reused_old_node_port = if specified_node_port.is_none() {
                    let by_name = port_obj
                        .get("name")
                        .and_then(Value::as_str)
                        .and_then(|n| old_node_ports_by_name.get(n).copied());
                    let by_port = port_obj
                        .get("port")
                        .and_then(Value::as_i64)
                        .and_then(|p| old_node_ports_by_port.get(&p).copied());
                    by_name.or(by_port)
                } else {
                    None
                };

                let target_np = specified_node_port.or(reused_old_node_port);
                Self::allocate_or_validate_node_port(
                    port_obj,
                    target_np,
                    min_port,
                    max_port,
                    &mut allocated_ports,
                )?;
            }
        }

        Ok(())
    }

    pub async fn create_service_options(
        &self,
        namespace: &str,
        mut service: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        self.prepare_service_for_create(namespace, &mut service)
            .await?;
        self.create_workload_options("", "Service", "services", namespace, service, dry_run)
            .await
    }
    pub async fn get_service(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        self.get_workload("", "services", namespace, name).await
    }
    pub async fn list_services(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.list_workload("", "ServiceList", "services", namespace)
            .await
    }
    pub async fn update_service(
        &self,
        namespace: &str,
        name: &str,
        service: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_service_options(namespace, name, service, false)
            .await
    }
    pub async fn update_service_options(
        &self,
        namespace: &str,
        name: &str,
        mut service: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        self.prepare_service_for_update(namespace, name, &mut service)
            .await?;
        self.update_workload_options("", "Service", "services", namespace, name, service, dry_run)
            .await
    }
    pub async fn patch_service_status(
        &self,
        namespace: &str,
        name: &str,
        status: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("patch", "", "services/status", Some(namespace), Some(name))?;
        let key = format!("{}/services/{namespace}/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "services".to_string(),
                name: format!("{namespace}/{name}"),
            })?;

        let expected_version = status
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .and_then(|v| v.parse::<u64>().ok());

        if let Some(expected_rev) = expected_version
            && kv.mod_revision != expected_rev
        {
            return Err(ApiserverError::Conflict {
                resource: "services".to_string(),
                name: format!("{namespace}/{name}"),
            });
        }

        let mut service: Value = serde_json::from_slice(&kv.value)?;
        let status_value = status.get("status").unwrap_or(&status);
        if let Some(status_obj) = service.get_mut("status").and_then(Value::as_object_mut) {
            if let Some(new_status) = status_value.as_object() {
                for (k, v) in new_status {
                    status_obj.insert(k.clone(), v.clone());
                }
            } else {
                service["status"] = status_value.clone();
            }
        } else {
            service["status"] = status_value.clone();
        }

        let bytes = serde_json::to_vec(&service)?;
        let updated_kv = self
            .storage
            .update(&key, bytes, expected_version.or(Some(kv.mod_revision)))
            .await?;
        if let Some(meta) = service.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(updated_kv.mod_revision.to_string()),
            );
        }
        Ok(service)
    }
    pub async fn delete_service(&self, namespace: &str, name: &str) -> Result<(), ApiserverError> {
        self.delete_workload("", "services", namespace, name).await
    }

    pub async fn create_endpoints(
        &self,
        namespace: &str,
        endpoints: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_workload("", "Endpoints", "endpoints", namespace, endpoints)
            .await
    }
    pub async fn get_endpoints(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.get_workload("", "endpoints", namespace, name).await
    }
    pub async fn list_endpoints(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.list_workload("", "EndpointsList", "endpoints", namespace)
            .await
    }
    pub async fn update_endpoints(
        &self,
        namespace: &str,
        name: &str,
        endpoints: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_workload("", "Endpoints", "endpoints", namespace, name, endpoints)
            .await
    }
    pub async fn delete_endpoints(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.delete_workload("", "endpoints", namespace, name).await
    }

    pub async fn create_endpointslice(
        &self,
        namespace: &str,
        slice: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_workload(
            "discovery.k8s.io",
            "EndpointSlice",
            "endpointslices",
            namespace,
            slice,
        )
        .await
    }
    pub async fn get_endpointslice(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.get_workload("discovery.k8s.io", "endpointslices", namespace, name)
            .await
    }
    pub async fn list_endpointslices(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.list_workload(
            "discovery.k8s.io",
            "EndpointSliceList",
            "endpointslices",
            namespace,
        )
        .await
    }
    pub async fn update_endpointslice(
        &self,
        namespace: &str,
        name: &str,
        slice: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_workload(
            "discovery.k8s.io",
            "EndpointSlice",
            "endpointslices",
            namespace,
            name,
            slice,
        )
        .await
    }
    pub async fn delete_endpointslice(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.delete_workload("discovery.k8s.io", "endpointslices", namespace, name)
            .await
    }

    // --- Node CRUD ---

    pub async fn create_node(&self, mut node: Value) -> Result<Value, ApiserverError> {
        let name = node
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: "Node requires metadata.name".to_string(),
            })?
            .to_string();

        self.check_auth_detailed("create", "", "nodes", None, Some(&name))?;

        if let Some(meta) = node.get_mut("metadata").and_then(Value::as_object_mut) {
            if !meta.contains_key("creationTimestamp") {
                meta.insert(
                    "creationTimestamp".to_string(),
                    json!(crate::time::now_rfc3339()),
                );
            }
            if !meta.contains_key("uid") {
                let cur_rev = self.storage.current_revision().await + 1;
                meta.insert(
                    "uid".to_string(),
                    json!(format!("uid-nodes-{name}-{cur_rev}")),
                );
            }
        }

        let key = format!("{}/nodes/{name}", self.storage.prefix());
        let bytes = serde_json::to_vec(&node)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = node;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn get_node(&self, name: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "", "nodes", None, Some(name))?;
        let key = format!("{}/nodes/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "nodes".to_string(),
                name: name.to_string(),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn list_nodes(&self) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", "", "nodes", None, None)?;
        let prefix = format!("{}/nodes/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "v1",
            "kind": "NodeList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn update_node(&self, name: &str, mut node: Value) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("update", "", "nodes", None, Some(name))?;
        let key = format!("{}/nodes/{name}", self.storage.prefix());
        let existing_kv =
            self.storage
                .get(&key)
                .await?
                .ok_or_else(|| ApiserverError::NotFound {
                    resource: "nodes".to_string(),
                    name: name.to_string(),
                })?;

        let old: Value = serde_json::from_slice(&existing_kv.value)?;
        if let Some(meta) = node.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("name".to_string(), json!(name));
            for k in ["uid", "creationTimestamp"] {
                if let Some(v) = old.get("metadata").and_then(|m| m.get(k)) {
                    meta.insert(k.to_string(), v.clone());
                }
            }
        }

        let expected_version = node
            .get("metadata")
            .and_then(|m| m.get("resourceVersion"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok());

        let bytes = serde_json::to_vec(&node)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        if let Some(meta) = node.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(node)
    }

    pub async fn patch_node_status(
        &self,
        name: &str,
        status: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("patch", "", "nodes/status", None, Some(name))?;
        let key = format!("{}/nodes/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "nodes".to_string(),
                name: name.to_string(),
            })?;

        let mut node: Value = serde_json::from_slice(&kv.value)?;
        node["status"] = status;

        let bytes = serde_json::to_vec(&node)?;
        let updated_kv = self
            .storage
            .update(&key, bytes, Some(kv.mod_revision))
            .await?;
        if let Some(meta) = node.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(updated_kv.mod_revision.to_string()),
            );
        }
        Ok(node)
    }

    pub async fn delete_node(&self, name: &str) -> Result<(), ApiserverError> {
        self.check_auth_detailed("delete", "", "nodes", None, Some(name))?;
        let key = format!("{}/nodes/{name}", self.storage.prefix());
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "nodes".to_string(),
                name: name.to_string(),
            });
        }
        Ok(())
    }

    // --- Coordination Lease CRUD ---

    pub async fn create_lease(
        &self,
        namespace: &str,
        lease: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_workload("coordination.k8s.io", "Lease", "leases", namespace, lease)
            .await
    }

    pub async fn get_lease(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        self.get_workload("coordination.k8s.io", "leases", namespace, name)
            .await
    }

    pub async fn list_leases(&self, namespace: &str) -> Result<Value, ApiserverError> {
        self.list_workload("coordination.k8s.io", "LeaseList", "leases", namespace)
            .await
    }

    pub async fn update_lease(
        &self,
        namespace: &str,
        name: &str,
        lease: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_workload(
            "coordination.k8s.io",
            "Lease",
            "leases",
            namespace,
            name,
            lease,
        )
        .await
    }

    pub async fn delete_lease(&self, namespace: &str, name: &str) -> Result<(), ApiserverError> {
        self.delete_workload("coordination.k8s.io", "leases", namespace, name)
            .await
    }

    // --- CustomResourceDefinition CRUD ---

    pub async fn create_crd(&self, crd: Value) -> Result<Value, ApiserverError> {
        let name = crd
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: "CustomResourceDefinition requires metadata.name".to_string(),
            })?
            .to_string();

        self.check_auth_detailed(
            "create",
            "apiextensions.k8s.io",
            "customresourcedefinitions",
            None,
            Some(&name),
        )?;

        let key = format!("{}/customresourcedefinitions/{name}", self.storage.prefix());
        let bytes = serde_json::to_vec(&crd)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = crd;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        self.crd_registry
            .write()
            .unwrap()
            .insert(name.clone(), result.clone());
        Ok(result)
    }

    pub async fn get_crd(&self, name: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "get",
            "apiextensions.k8s.io",
            "customresourcedefinitions",
            None,
            Some(name),
        )?;
        let key = format!("{}/customresourcedefinitions/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "customresourcedefinitions".to_string(),
                name: name.to_string(),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn list_crds(&self) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "list",
            "apiextensions.k8s.io",
            "customresourcedefinitions",
            None,
            None,
        )?;
        let prefix = format!("{}/customresourcedefinitions/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinitionList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn delete_crd(&self, name: &str) -> Result<(), ApiserverError> {
        self.check_auth_detailed(
            "delete",
            "apiextensions.k8s.io",
            "customresourcedefinitions",
            None,
            Some(name),
        )?;
        let key = format!("{}/customresourcedefinitions/{name}", self.storage.prefix());
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "customresourcedefinitions".to_string(),
                name: name.to_string(),
            });
        }
        let crd_opt = self.crd_registry.write().unwrap().remove(name);
        if let Some(crd) = crd_opt
            && let Some(spec) = crd.get("spec")
            && let Some(group) = spec.get("group").and_then(Value::as_str)
            && let Some(plural) = spec
                .get("names")
                .and_then(|n| n.get("plural"))
                .and_then(Value::as_str)
        {
            let instances_prefix = format!("{}/{group}/{plural}/", self.storage.prefix());
            let instances = self.storage.list(&instances_prefix).await?;
            for inst in instances {
                let _ = self.storage.delete(&inst.key, None).await?;
            }
        }
        Ok(())
    }

    // --- Dynamic Custom Resources & Schema Validation ---

    fn value_type_name(v: &Value) -> &'static str {
        match v {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(n) => {
                if n.is_i64() || n.is_u64() {
                    "integer"
                } else {
                    "number"
                }
            },
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        }
    }

    pub fn validate_json_schema(
        schema: &Value,
        data: &Value,
        path: &str,
    ) -> Result<(), ApiserverError> {
        // 1. type check
        if let Some(expected_type) = schema.get("type").and_then(Value::as_str) {
            let matches = match expected_type {
                "object" => data.is_object(),
                "array" => data.is_array(),
                "string" => data.is_string(),
                "integer" => data.is_i64() || data.is_u64(),
                "number" => data.is_number(),
                "boolean" => data.is_boolean(),
                _ => true,
            };
            if !matches {
                return Err(ApiserverError::InvalidInput {
                    field: path.to_string(),
                    reason: format!(
                        "expected type '{expected_type}', found {}",
                        Self::value_type_name(data)
                    ),
                });
            }
        }

        // 2. enum check
        if let Some(enum_vals) = schema.get("enum").and_then(Value::as_array)
            && !enum_vals.contains(data)
        {
            return Err(ApiserverError::InvalidInput {
                field: path.to_string(),
                reason: format!("value '{data}' is not in allowed enum values: {enum_vals:?}"),
            });
        }

        // 3. numeric limits
        if let Some(min) = schema.get("minimum").and_then(Value::as_f64)
            && let Some(val) = data.as_f64()
            && val < min
        {
            return Err(ApiserverError::InvalidInput {
                field: path.to_string(),
                reason: format!("value {val} is less than minimum {min}"),
            });
        }
        if let Some(max) = schema.get("maximum").and_then(Value::as_f64)
            && let Some(val) = data.as_f64()
            && val > max
        {
            return Err(ApiserverError::InvalidInput {
                field: path.to_string(),
                reason: format!("value {val} is greater than maximum {max}"),
            });
        }

        // 4. object validation: required and properties
        if let Some(map) = data.as_object() {
            if let Some(required) = schema.get("required").and_then(Value::as_array) {
                Self::validate_object_required(map, required, path)?;
            }
            if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                Self::validate_object_properties(map, props, path)?;
            }
        }

        // 5. array validation: items
        if let Some(arr) = data.as_array()
            && let Some(item_schema) = schema.get("items")
        {
            Self::validate_array_items(arr, item_schema, path)?;
        }

        Ok(())
    }

    fn validate_object_required(
        map: &serde_json::Map<String, Value>,
        required: &[Value],
        path: &str,
    ) -> Result<(), ApiserverError> {
        for req in required {
            if let Some(prop_name) = req.as_str()
                && !map.contains_key(prop_name)
            {
                let field_path = if path.is_empty() {
                    prop_name.to_string()
                } else {
                    format!("{path}.{prop_name}")
                };
                return Err(ApiserverError::InvalidInput {
                    field: field_path,
                    reason: format!("missing required field '{prop_name}'"),
                });
            }
        }
        Ok(())
    }

    fn validate_object_properties(
        map: &serde_json::Map<String, Value>,
        props: &serde_json::Map<String, Value>,
        path: &str,
    ) -> Result<(), ApiserverError> {
        for (prop_name, prop_val) in map {
            let Some(prop_schema) = props.get(prop_name) else {
                continue;
            };
            let next_path = if path.is_empty() {
                prop_name.clone()
            } else {
                format!("{path}.{prop_name}")
            };
            Self::validate_json_schema(prop_schema, prop_val, &next_path)?;
        }
        Ok(())
    }

    fn validate_array_items(
        arr: &[Value],
        item_schema: &Value,
        path: &str,
    ) -> Result<(), ApiserverError> {
        for (idx, item) in arr.iter().enumerate() {
            Self::validate_json_schema(item_schema, item, &format!("{path}[{idx}]"))?;
        }
        Ok(())
    }

    fn extract_crd_versions(spec: &Value, group: &str) -> Vec<Value> {
        let mut versions = Vec::new();
        if let Some(vers) = spec.get("versions").and_then(Value::as_array) {
            for v in vers {
                let Some(v_name) = v.get("name").and_then(Value::as_str) else {
                    continue;
                };
                versions.push(json!({
                    "groupVersion": format!("{group}/{v_name}"),
                    "version": v_name
                }));
            }
        }
        if versions.is_empty() {
            versions.push(json!({
                "groupVersion": format!("{group}/v1"),
                "version": "v1"
            }));
        }
        versions
    }

    fn validate_crd_instance_schema(
        crd_registry: &Arc<RwLock<BTreeMap<String, Value>>>,
        group: &str,
        plural: &str,
        resource: &Value,
    ) -> Result<(), ApiserverError> {
        let registry = crd_registry.read().unwrap();
        for crd in registry.values() {
            let Some(spec) = crd.get("spec") else {
                continue;
            };
            let spec_group = spec.get("group").and_then(Value::as_str);
            let spec_plural = spec
                .get("names")
                .and_then(|n| n.get("plural"))
                .and_then(Value::as_str);
            if spec_group != Some(group) || spec_plural != Some(plural) {
                continue;
            }
            Self::validate_spec_schema(spec, resource)?;
            break;
        }
        Ok(())
    }

    fn validate_spec_schema(spec: &Value, resource: &Value) -> Result<(), ApiserverError> {
        let Some(versions) = spec.get("versions").and_then(Value::as_array) else {
            return Ok(());
        };
        for ver in versions {
            let Some(schema) = ver.get("schema").and_then(|s| s.get("openAPIV3Schema")) else {
                continue;
            };
            Self::validate_json_schema(schema, resource, "")?;
        }
        Ok(())
    }

    pub async fn create_custom_resource(
        &self,
        group: &str,
        plural: &str,
        namespace: &str,
        name: &str,
        mut resource: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("create", group, plural, Some(namespace), Some(name))?;

        // Admission reviews
        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{}", self.storage.current_revision().await + 1),
            kind: GroupVersionKind {
                group: group.to_string(),
                version: "v1".to_string(),
                kind: plural.to_string(),
            },
            resource: GroupVersionResource {
                group: group.to_string(),
                version: "v1".to_string(),
                resource: plural.to_string(),
            },
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info(),
            object: Some(resource.clone()),
            old_object: None,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        if let Some(obj) = adm_req.object {
            resource = obj.clone();
            adm_req.object = Some(obj);
        }

        // CRD OpenAPI v3 schema validation
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &resource)?;

        self.admission.run_validating_admission(&adm_req).await?;

        let key = format!(
            "{}/{group}/{plural}/{namespace}/{name}",
            self.storage.prefix()
        );
        let bytes = serde_json::to_vec(&resource)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = resource;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn get_custom_resource(
        &self,
        group: &str,
        plural: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", group, plural, Some(namespace), Some(name))?;
        let key = format!(
            "{}/{group}/{plural}/{namespace}/{name}",
            self.storage.prefix()
        );
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: plural.to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn update_custom_resource(
        &self,
        group: &str,
        plural: &str,
        namespace: &str,
        name: &str,
        mut resource: Value,
        expected_version: Option<u64>,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("update", group, plural, Some(namespace), Some(name))?;
        let key = format!(
            "{}/{group}/{plural}/{namespace}/{name}",
            self.storage.prefix()
        );

        let old_bytes = self.storage.get(&key).await?;
        let old_obj: Option<Value> = old_bytes.and_then(|b| serde_json::from_slice(&b.value).ok());

        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{}", self.storage.current_revision().await + 1),
            kind: GroupVersionKind {
                group: group.to_string(),
                version: "v1".to_string(),
                kind: plural.to_string(),
            },
            resource: GroupVersionResource {
                group: group.to_string(),
                version: "v1".to_string(),
                resource: plural.to_string(),
            },
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "UPDATE".to_string(),
            user_info: self.current_user_info(),
            object: Some(resource.clone()),
            old_object: old_obj,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        if let Some(obj) = adm_req.object {
            resource = obj.clone();
            adm_req.object = Some(obj);
        }

        // CRD OpenAPI v3 schema validation
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &resource)?;

        self.admission.run_validating_admission(&adm_req).await?;

        let bytes = serde_json::to_vec(&resource)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        let mut result = resource;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn list_custom_resources(
        &self,
        group: &str,
        plural: &str,
        namespace: &str,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", group, plural, Some(namespace), None)?;
        let prefix = format!("{}/{group}/{plural}/{namespace}/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": format!("{group}/v1"),
            "kind": format!("{plural}List"),
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn delete_custom_resource(
        &self,
        group: &str,
        plural: &str,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.check_auth_detailed("delete", group, plural, Some(namespace), Some(name))?;
        let key = format!(
            "{}/{group}/{plural}/{namespace}/{name}",
            self.storage.prefix()
        );
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: plural.to_string(),
                name: format!("{namespace}/{name}"),
            });
        }
        Ok(())
    }

    // --- Webhook Configurations CRUD ---

    pub async fn create_validating_webhook_configuration(
        &self,
        config: Value,
    ) -> Result<Value, ApiserverError> {
        let name = config
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: "ValidatingWebhookConfiguration requires metadata.name".to_string(),
            })?;

        self.check_auth_detailed(
            "create",
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
            None,
            Some(name),
        )?;

        let typed: crate::admission::ValidatingWebhookConfiguration =
            serde_json::from_value(config.clone())?;
        self.admission.add_validating_webhook_config(typed);

        let key = format!(
            "{}/validatingwebhookconfigurations/{name}",
            self.storage.prefix()
        );
        let bytes = serde_json::to_vec(&config)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = config;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn get_validating_webhook_configuration(
        &self,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "get",
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
            None,
            Some(name),
        )?;
        let key = format!(
            "{}/validatingwebhookconfigurations/{name}",
            self.storage.prefix()
        );
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "validatingwebhookconfigurations".to_string(),
                name: name.to_string(),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn list_validating_webhook_configurations(&self) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "list",
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
            None,
            None,
        )?;
        let prefix = format!("{}/validatingwebhookconfigurations/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingWebhookConfigurationList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn delete_validating_webhook_configuration(
        &self,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.check_auth_detailed(
            "delete",
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
            None,
            Some(name),
        )?;
        let key = format!(
            "{}/validatingwebhookconfigurations/{name}",
            self.storage.prefix()
        );
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "validatingwebhookconfigurations".to_string(),
                name: name.to_string(),
            });
        }
        Ok(())
    }

    pub async fn create_mutating_webhook_configuration(
        &self,
        config: Value,
    ) -> Result<Value, ApiserverError> {
        let name = config
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: "MutatingWebhookConfiguration requires metadata.name".to_string(),
            })?;

        self.check_auth_detailed(
            "create",
            "admissionregistration.k8s.io",
            "mutatingwebhookconfigurations",
            None,
            Some(name),
        )?;

        let typed: crate::admission::MutatingWebhookConfiguration =
            serde_json::from_value(config.clone())?;
        self.admission.add_mutating_webhook_config(typed);

        let key = format!(
            "{}/mutatingwebhookconfigurations/{name}",
            self.storage.prefix()
        );
        let bytes = serde_json::to_vec(&config)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = config;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn get_mutating_webhook_configuration(
        &self,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "get",
            "admissionregistration.k8s.io",
            "mutatingwebhookconfigurations",
            None,
            Some(name),
        )?;
        let key = format!(
            "{}/mutatingwebhookconfigurations/{name}",
            self.storage.prefix()
        );
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "mutatingwebhookconfigurations".to_string(),
                name: name.to_string(),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn update_mutating_webhook_configuration(
        &self,
        name: &str,
        config: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "update",
            "admissionregistration.k8s.io",
            "mutatingwebhookconfigurations",
            None,
            Some(name),
        )?;

        let body_name = config
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str);
        if body_name != Some(name) {
            return Err(ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: format!("body name {body_name:?} does not match '{name}'"),
            });
        }

        let typed: crate::admission::MutatingWebhookConfiguration =
            serde_json::from_value(config.clone())?;

        let key = format!(
            "{}/mutatingwebhookconfigurations/{name}",
            self.storage.prefix()
        );
        let bytes = serde_json::to_vec(&config)?;
        let kv = self.storage.update(&key, bytes, None).await?;
        self.admission.add_mutating_webhook_config(typed);
        let mut result = config;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn list_mutating_webhook_configurations(&self) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "list",
            "admissionregistration.k8s.io",
            "mutatingwebhookconfigurations",
            None,
            None,
        )?;
        let prefix = format!("{}/mutatingwebhookconfigurations/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfigurationList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn delete_mutating_webhook_configuration(
        &self,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.check_auth_detailed(
            "delete",
            "admissionregistration.k8s.io",
            "mutatingwebhookconfigurations",
            None,
            Some(name),
        )?;
        let key = format!(
            "{}/mutatingwebhookconfigurations/{name}",
            self.storage.prefix()
        );
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "mutatingwebhookconfigurations".to_string(),
                name: name.to_string(),
            });
        }
        Ok(())
    }

    // --- Aggregated APIService CRUD & Dispatch ---

    pub async fn create_api_service(&self, service: Value) -> Result<Value, ApiserverError> {
        let name = service
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: "APIService requires metadata.name".to_string(),
            })?;

        self.check_auth_detailed(
            "create",
            "apiregistration.k8s.io",
            "apiservices",
            None,
            Some(name),
        )?;

        let typed: APIService = serde_json::from_value(service.clone())?;
        self.aggregation.register_api_service(typed);

        let key = format!("{}/apiservices/{name}", self.storage.prefix());
        let bytes = serde_json::to_vec(&service)?;
        let kv = self.storage.create(&key, bytes).await?;
        let mut result = service;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
    }

    pub async fn get_api_service(&self, name: &str) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "get",
            "apiregistration.k8s.io",
            "apiservices",
            None,
            Some(name),
        )?;
        let key = format!("{}/apiservices/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "apiservices".to_string(),
                name: name.to_string(),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn list_api_services(&self) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", "apiregistration.k8s.io", "apiservices", None, None)?;
        let prefix = format!("{}/apiservices/", self.storage.prefix());
        let kvs = self.storage.list(&prefix).await?;
        let mut items = Vec::new();
        for kv in kvs {
            let mut doc: Value = serde_json::from_slice(&kv.value)?;
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(kv.mod_revision.to_string()),
                );
            }
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        Ok(json!({
            "apiVersion": "apiregistration.k8s.io/v1",
            "kind": "APIServiceList",
            "metadata": {
                "resourceVersion": cur_rev.to_string()
            },
            "items": items
        }))
    }

    pub async fn delete_api_service(&self, name: &str) -> Result<(), ApiserverError> {
        self.check_auth_detailed(
            "delete",
            "apiregistration.k8s.io",
            "apiservices",
            None,
            Some(name),
        )?;
        let key = format!("{}/apiservices/{name}", self.storage.prefix());
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "apiservices".to_string(),
                name: name.to_string(),
            });
        }
        self.aggregation.remove_api_service(name);
        Ok(())
    }

    pub async fn dispatch_aggregated_request(
        &self,
        service_name: &str,
        path: &str,
        method: &str,
        body: Option<Value>,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", "", "aggregated-apis", None, Some(service_name))?;
        let user_info = self.current_user_info();
        let ctx = AggregatedRequestContext {
            path: path.to_string(),
            method: method.to_string(),
            caller_username: user_info.username,
            caller_groups: user_info.groups,
            body,
        };
        self.aggregation.dispatch(service_name, &ctx).await
    }

    // --- RBAC API Management ---

    fn verify_caller_holds_rule(
        &self,
        rule: &PolicyRule,
        namespace: Option<&str>,
    ) -> Result<(), ApiserverError> {
        let names: Vec<Option<&str>> = if rule.resource_names.is_empty() {
            vec![None]
        } else {
            rule.resource_names
                .iter()
                .map(|n| Some(n.as_str()))
                .collect()
        };

        for verb in &rule.verbs {
            for group in &rule.api_groups {
                self.verify_caller_holds_verb_group(
                    verb,
                    group,
                    &rule.resources,
                    &names,
                    namespace,
                )?;
            }
        }
        Ok(())
    }

    fn verify_caller_holds_verb_group(
        &self,
        verb: &str,
        group: &str,
        resources: &[String],
        names: &[Option<&str>],
        namespace: Option<&str>,
    ) -> Result<(), ApiserverError> {
        for res in resources {
            for name in names {
                self.check_auth_detailed(verb, group, res, namespace, *name)?;
            }
        }
        Ok(())
    }

    fn verify_caller_holds_rules(
        &self,
        rules: &[PolicyRule],
        namespace: Option<&str>,
    ) -> Result<(), ApiserverError> {
        for rule in rules {
            self.verify_caller_holds_rule(rule, namespace)?;
        }
        Ok(())
    }

    fn verify_cluster_role_creation_privileges(
        &self,
        cr: &ClusterRole,
    ) -> Result<(), ApiserverError> {
        if self.identity == ClientIdentity::AdminCertificate {
            return Ok(());
        }

        let has_escalate = self
            .check_auth_detailed(
                "escalate",
                "rbac.authorization.k8s.io",
                "clusterroles",
                None,
                Some(&cr.name),
            )
            .is_ok();

        if has_escalate {
            return Ok(());
        }

        self.verify_caller_holds_rules(&cr.rules, None)
    }

    fn verify_cluster_role_binding_privileges(&self, role_ref: &str) -> Result<(), ApiserverError> {
        if self.identity == ClientIdentity::AdminCertificate {
            return Ok(());
        }

        let has_bind = self
            .check_auth_detailed(
                "bind",
                "rbac.authorization.k8s.io",
                "clusterroles",
                None,
                Some(role_ref),
            )
            .is_ok();

        if has_bind {
            return Ok(());
        }

        let rules = if let Some(cr) = self.rbac.get_cluster_role(role_ref) {
            cr.rules
        } else {
            return Err(ApiserverError::InvalidInput {
                field: "role_ref".to_string(),
                reason: format!("referenced ClusterRole '{role_ref}' does not exist"),
            });
        };

        self.verify_caller_holds_rules(&rules, None)
    }

    fn verify_role_creation_privileges(
        &self,
        namespace: &str,
        role: &Role,
    ) -> Result<(), ApiserverError> {
        if self.identity == ClientIdentity::AdminCertificate {
            return Ok(());
        }

        let has_escalate = self
            .check_auth_detailed(
                "escalate",
                "rbac.authorization.k8s.io",
                "roles",
                Some(namespace),
                Some(&role.name),
            )
            .is_ok();

        if has_escalate {
            return Ok(());
        }

        self.verify_caller_holds_rules(&role.rules, Some(namespace))
    }

    fn verify_role_binding_privileges(
        &self,
        namespace: &str,
        role_ref: &str,
    ) -> Result<(), ApiserverError> {
        if self.identity == ClientIdentity::AdminCertificate {
            return Ok(());
        }

        let has_bind = self
            .check_auth_detailed(
                "bind",
                "rbac.authorization.k8s.io",
                "roles",
                Some(namespace),
                Some(role_ref),
            )
            .is_ok()
            || self
                .check_auth_detailed(
                    "bind",
                    "rbac.authorization.k8s.io",
                    "clusterroles",
                    None,
                    Some(role_ref),
                )
                .is_ok();

        if has_bind {
            return Ok(());
        }

        let rules = if let Some(r) = self.rbac.get_role(namespace, role_ref) {
            r.rules
        } else if let Some(cr) = self.rbac.get_cluster_role(role_ref) {
            cr.rules
        } else {
            return Err(ApiserverError::InvalidInput {
                field: "role_ref".to_string(),
                reason: format!("referenced role '{role_ref}' does not exist"),
            });
        };

        self.verify_caller_holds_rules(&rules, Some(namespace))
    }

    pub async fn create_cluster_role(
        &self,
        role: ClusterRole,
    ) -> Result<ClusterRole, ApiserverError> {
        self.check_auth_detailed(
            "create",
            "rbac.authorization.k8s.io",
            "clusterroles",
            None,
            Some(&role.name),
        )?;
        self.verify_cluster_role_creation_privileges(&role)?;
        let key = format!("{}/clusterroles/{}", self.storage.prefix(), role.name);
        let bytes = serde_json::to_vec(&role)?;
        self.storage.create(&key, bytes).await?;
        self.rbac.add_cluster_role(role.clone());
        Ok(role)
    }

    pub async fn get_cluster_role(&self, name: &str) -> Result<ClusterRole, ApiserverError> {
        self.check_auth_detailed(
            "get",
            "rbac.authorization.k8s.io",
            "clusterroles",
            None,
            Some(name),
        )?;
        if let Some(role) = self.rbac.get_cluster_role(name) {
            return Ok(role);
        }
        let key = format!("{}/clusterroles/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "clusterroles".to_string(),
                name: name.to_string(),
            })?;
        let role: ClusterRole = serde_json::from_slice(&kv.value)?;
        self.rbac.add_cluster_role(role.clone());
        Ok(role)
    }

    pub async fn update_cluster_role(
        &self,
        role: ClusterRole,
    ) -> Result<ClusterRole, ApiserverError> {
        self.check_auth_detailed(
            "update",
            "rbac.authorization.k8s.io",
            "clusterroles",
            None,
            Some(&role.name),
        )?;
        self.verify_cluster_role_creation_privileges(&role)?;
        let key = format!("{}/clusterroles/{}", self.storage.prefix(), role.name);
        let bytes = serde_json::to_vec(&role)?;
        self.storage.update(&key, bytes, None).await?;
        self.rbac.add_cluster_role(role.clone());
        Ok(role)
    }

    pub async fn create_cluster_role_binding(
        &self,
        binding: ClusterRoleBinding,
    ) -> Result<ClusterRoleBinding, ApiserverError> {
        self.check_auth_detailed(
            "create",
            "rbac.authorization.k8s.io",
            "clusterrolebindings",
            None,
            Some(&binding.name),
        )?;
        self.verify_cluster_role_binding_privileges(&binding.role_ref)?;
        let key = format!(
            "{}/clusterrolebindings/{}",
            self.storage.prefix(),
            binding.name
        );
        let bytes = serde_json::to_vec(&binding)?;
        self.storage.create(&key, bytes).await?;
        self.rbac.add_cluster_role_binding(binding.clone());
        Ok(binding)
    }

    pub async fn get_cluster_role_binding(
        &self,
        name: &str,
    ) -> Result<ClusterRoleBinding, ApiserverError> {
        self.check_auth_detailed(
            "get",
            "rbac.authorization.k8s.io",
            "clusterrolebindings",
            None,
            Some(name),
        )?;
        if let Some(binding) = self.rbac.get_cluster_role_binding(name) {
            return Ok(binding);
        }
        let key = format!("{}/clusterrolebindings/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "clusterrolebindings".to_string(),
                name: name.to_string(),
            })?;
        let binding: ClusterRoleBinding = serde_json::from_slice(&kv.value)?;
        self.rbac.add_cluster_role_binding(binding.clone());
        Ok(binding)
    }

    pub async fn update_cluster_role_binding(
        &self,
        binding: ClusterRoleBinding,
    ) -> Result<ClusterRoleBinding, ApiserverError> {
        self.check_auth_detailed(
            "update",
            "rbac.authorization.k8s.io",
            "clusterrolebindings",
            None,
            Some(&binding.name),
        )?;
        self.verify_cluster_role_binding_privileges(&binding.role_ref)?;
        let key = format!(
            "{}/clusterrolebindings/{}",
            self.storage.prefix(),
            binding.name
        );
        let bytes = serde_json::to_vec(&binding)?;
        self.storage.update(&key, bytes, None).await?;
        self.rbac.add_cluster_role_binding(binding.clone());
        Ok(binding)
    }

    pub async fn create_role(&self, role: Role) -> Result<Role, ApiserverError> {
        self.check_auth_detailed(
            "create",
            "rbac.authorization.k8s.io",
            "roles",
            Some(&role.namespace),
            Some(&role.name),
        )?;
        self.verify_role_creation_privileges(&role.namespace, &role)?;
        let key = format!(
            "{}/roles/{}/{}",
            self.storage.prefix(),
            role.namespace,
            role.name
        );
        let bytes = serde_json::to_vec(&role)?;
        self.storage.create(&key, bytes).await?;
        self.rbac.add_role(role.clone());
        Ok(role)
    }

    pub async fn get_role(&self, namespace: &str, name: &str) -> Result<Role, ApiserverError> {
        self.check_auth_detailed(
            "get",
            "rbac.authorization.k8s.io",
            "roles",
            Some(namespace),
            Some(name),
        )?;
        if let Some(role) = self.rbac.get_role(namespace, name) {
            return Ok(role);
        }
        let key = format!("{}/roles/{namespace}/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "roles".to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let role: Role = serde_json::from_slice(&kv.value)?;
        self.rbac.add_role(role.clone());
        Ok(role)
    }

    pub async fn update_role(&self, role: Role) -> Result<Role, ApiserverError> {
        self.check_auth_detailed(
            "update",
            "rbac.authorization.k8s.io",
            "roles",
            Some(&role.namespace),
            Some(&role.name),
        )?;
        self.verify_role_creation_privileges(&role.namespace, &role)?;
        let key = format!(
            "{}/roles/{}/{}",
            self.storage.prefix(),
            role.namespace,
            role.name
        );
        let bytes = serde_json::to_vec(&role)?;
        self.storage.update(&key, bytes, None).await?;
        self.rbac.add_role(role.clone());
        Ok(role)
    }

    pub async fn create_role_binding(
        &self,
        binding: RoleBinding,
    ) -> Result<RoleBinding, ApiserverError> {
        self.check_auth_detailed(
            "create",
            "rbac.authorization.k8s.io",
            "rolebindings",
            Some(&binding.namespace),
            Some(&binding.name),
        )?;
        self.verify_role_binding_privileges(&binding.namespace, &binding.role_ref)?;
        let key = format!(
            "{}/rolebindings/{}/{}",
            self.storage.prefix(),
            binding.namespace,
            binding.name
        );
        let bytes = serde_json::to_vec(&binding)?;
        self.storage.create(&key, bytes).await?;
        self.rbac.add_role_binding(binding.clone());
        Ok(binding)
    }

    pub async fn get_role_binding(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<RoleBinding, ApiserverError> {
        self.check_auth_detailed(
            "get",
            "rbac.authorization.k8s.io",
            "rolebindings",
            Some(namespace),
            Some(name),
        )?;
        if let Some(binding) = self.rbac.get_role_binding(namespace, name) {
            return Ok(binding);
        }
        let key = format!("{}/rolebindings/{namespace}/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "rolebindings".to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let binding: RoleBinding = serde_json::from_slice(&kv.value)?;
        self.rbac.add_role_binding(binding.clone());
        Ok(binding)
    }

    pub async fn update_role_binding(
        &self,
        binding: RoleBinding,
    ) -> Result<RoleBinding, ApiserverError> {
        self.check_auth_detailed(
            "update",
            "rbac.authorization.k8s.io",
            "rolebindings",
            Some(&binding.namespace),
            Some(&binding.name),
        )?;
        self.verify_role_binding_privileges(&binding.namespace, &binding.role_ref)?;
        let key = format!(
            "{}/rolebindings/{}/{}",
            self.storage.prefix(),
            binding.namespace,
            binding.name
        );
        let bytes = serde_json::to_vec(&binding)?;
        self.storage.update(&key, bytes, None).await?;
        self.rbac.add_role_binding(binding.clone());
        Ok(binding)
    }

    // --- Watch Streaming ---

    /// Subscribes to changes of one resource collection after a `watch` authorization check.
    ///
    /// `namespace` of `None` watches a namespaced resource across all namespaces or a
    /// cluster-scoped resource. Events arrive with the raw storage key and value.
    pub async fn watch_resource(
        &self,
        group: &str,
        resource: &str,
        namespace: Option<&str>,
    ) -> Result<WatchReceiver, ApiserverError> {
        self.check_auth_detailed("watch", group, resource, namespace, None)?;
        let group_segment = if group.is_empty() {
            String::new()
        } else {
            format!("/{group}")
        };
        let namespace_segment = namespace.map_or_else(String::new, |ns| format!("{ns}/"));
        let prefix = format!(
            "{}{group_segment}/{resource}/{namespace_segment}",
            self.storage.prefix()
        );
        Ok(self.storage.watch(&prefix).await)
    }

    pub async fn watch(&self, prefix: &str) -> Result<WatchReceiver, ApiserverError> {
        self.check_auth_detailed("watch", "", prefix, None, None)?;
        let full_prefix = format!(
            "{}/{}",
            self.storage.prefix(),
            prefix.trim_start_matches('/')
        );
        Ok(self.storage.watch(&full_prefix).await)
    }
}
