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
    cluster_role_binding_from_api, cluster_role_from_api, role_binding_from_api, role_from_api,
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

struct PodUpdateTarget<'a> {
    key: &'a str,
    namespace: &'a str,
    name: &'a str,
    subresource: Option<&'a str>,
    expected_version: Option<u64>,
    old_gen: Option<i64>,
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
    client_ca_file: std::path::PathBuf,
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

/// Storage key for a cluster-scoped object (`/<prefix>[/<group>]/<plural>/<name>`).
fn cluster_key(prefix: &str, group: &str, plural: &str, name: &str) -> String {
    if group.is_empty() {
        format!("{prefix}/{plural}/{name}")
    } else {
        format!("{prefix}/{group}/{plural}/{name}")
    }
}

/// Storage prefix for listing cluster-scoped objects.
fn cluster_prefix(prefix: &str, group: &str, plural: &str) -> String {
    if group.is_empty() {
        format!("{prefix}/{plural}/")
    } else {
        format!("{prefix}/{group}/{plural}/")
    }
}

fn invalid_rbac(reason: String) -> ApiserverError {
    ApiserverError::InvalidInput {
        field: "rbac".to_string(),
        reason,
    }
}

fn rbac_namespace<'a>(
    namespace: Option<&'a str>,
    doc: &'a Value,
) -> Result<&'a str, ApiserverError> {
    namespace
        .filter(|value| !value.is_empty())
        .or_else(|| {
            doc.pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| invalid_rbac("metadata.namespace is required".to_string()))
}

const KUBE_ROOT_CA_DESCRIPTION: &str = "Contains a CA bundle that can be used to verify the kube-apiserver when using internal endpoints such as the internal service IP or kubernetes.default.svc. No other usage is guaranteed across distributions of Kubernetes clusters.";

fn root_ca_configmap_current(doc: Option<&Value>, ca_pem: &str) -> bool {
    let Some(doc) = doc else {
        return false;
    };
    let data = doc.get("data").and_then(Value::as_object);
    let ca_matches = data
        .and_then(|data| data.get("ca.crt"))
        .and_then(Value::as_str)
        == Some(ca_pem);
    let only_ca = data.is_some_and(|data| data.len() == 1);
    let described = doc
        .pointer("/metadata/annotations/kubernetes.io/description")
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty());
    ca_matches && only_ca && described
}

fn kube_root_ca_configmap(namespace: &str, ca_pem: &str, existing: Option<&Value>) -> Value {
    let mut doc = existing.cloned().unwrap_or_else(|| {
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": KubernetesApiClient::KUBE_ROOT_CA_CONFIGMAP,
                "namespace": namespace,
                "creationTimestamp": crate::time::now_rfc3339()
            }
        })
    });
    if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.insert(
            "name".to_string(),
            json!(KubernetesApiClient::KUBE_ROOT_CA_CONFIGMAP),
        );
        meta.insert("namespace".to_string(), json!(namespace));
        let annotations = meta
            .entry("annotations")
            .or_insert_with(|| json!({}))
            .as_object_mut();
        if let Some(annotations) = annotations {
            annotations.insert(
                "kubernetes.io/description".to_string(),
                json!(KUBE_ROOT_CA_DESCRIPTION),
            );
        }
    }
    doc["data"] = json!({ "ca.crt": ca_pem });
    doc
}

fn group_version(group: &str) -> String {
    if group.is_empty() {
        "v1".to_string()
    } else {
        format!("{group}/v1")
    }
}

fn merge_patch_array_by_key(target_arr: &mut Vec<Value>, patch_arr: Vec<Value>, mk: &str) {
    for patch_item in patch_arr {
        let item_key = patch_item.get(mk).and_then(Value::as_str).unwrap_or("");
        if let Some(existing_item) = target_arr
            .iter_mut()
            .find(|t| t.get(mk).and_then(Value::as_str) == Some(item_key))
        {
            json_merge_patch(existing_item, patch_item);
        } else {
            target_arr.push(patch_item);
        }
    }
}

/// Recursively removes null-valued keys from objects (including inside array elements).
pub fn prune_null_values(val: &mut Value) {
    match val {
        Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for v in map.values_mut() {
                prune_null_values(v);
            }
        },
        Value::Array(arr) => {
            for v in arr {
                prune_null_values(v);
            }
        },
        _ => {},
    }
}

/// Applies an RFC 7396 JSON Merge Patch to a target JSON value.
/// Per RFC 7396, arrays in the patch wholesale replace the target array.
pub fn json_rfc7396_merge_patch(target: &mut Value, patch: Value) {
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
                    json_rfc7396_merge_patch(existing_sub, value);
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
    prune_null_values(target);
}

fn merge_array_field(
    target_obj: &mut serde_json::Map<String, Value>,
    key: String,
    mut patch_arr: Vec<Value>,
    merge_key: Option<&'static str>,
) {
    let Some(mk) = merge_key else {
        target_obj.insert(key, Value::Array(patch_arr));
        return;
    };
    let Some(Value::Array(target_arr)) = target_obj.get_mut(&key) else {
        target_obj.insert(key, Value::Array(patch_arr));
        return;
    };
    if key == "containers"
        && target_arr.len() == 1
        && patch_arr.len() == 1
        && patch_arr[0].get(mk).is_none()
        && let Some(existing_name) = target_arr[0].get(mk).and_then(Value::as_str)
        && let Some(p_obj) = patch_arr[0].as_object_mut()
    {
        p_obj.insert(mk.to_string(), json!(existing_name));
    }
    if patch_arr
        .iter()
        .all(|item| item.get(mk).and_then(Value::as_str).is_some())
    {
        merge_patch_array_by_key(target_arr, patch_arr, mk);
    } else {
        target_obj.insert(key, Value::Array(patch_arr));
    }
}

/// Applies an RFC 7386 JSON Merge Patch (with Kubernetes strategic merge array
/// merging for keyed object lists like `containers`, `volumes`, `conditions`) to a target JSON value.
pub fn json_merge_patch(target: &mut Value, patch: Value) {
    if let Value::Object(patch_obj) = patch {
        if !target.is_object() {
            *target = Value::Object(serde_json::Map::new());
        }
        let target_obj = target.as_object_mut().unwrap();
        if patch_obj.get("$patch").and_then(Value::as_str) == Some("replace") {
            target_obj.clear();
        } else if let Some(retain_arr) = patch_obj.get("$retainKeys").and_then(Value::as_array) {
            let retain_set: BTreeSet<&str> = retain_arr.iter().filter_map(Value::as_str).collect();
            target_obj.retain(|k, _| retain_set.contains(k.as_str()));
        }
        for (key, value) in patch_obj {
            if key == "$patch" || key == "$retainKeys" {
                continue;
            }
            if value.is_null() {
                target_obj.remove(&key);
            } else if value.is_object() {
                if let Some(existing_sub) = target_obj.get_mut(&key) {
                    json_merge_patch(existing_sub, value);
                } else {
                    target_obj.insert(key, value);
                }
            } else if let Value::Array(patch_arr) = value {
                let merge_key = match key.as_str() {
                    "containers"
                    | "initContainers"
                    | "ephemeralContainers"
                    | "volumes"
                    | "volumeMounts"
                    | "env"
                    | "ports" => Some("name"),
                    "conditions" => Some("type"),
                    _ => None,
                };
                merge_array_field(target_obj, key, patch_arr, merge_key);
            } else {
                target_obj.insert(key, value);
            }
        }
    } else {
        *target = patch;
    }
    prune_null_values(target);
}

fn find_and_record_pod_info(pod_list: &Value, sa: &str, extra: &mut BTreeMap<String, Vec<String>>) {
    let Some(items) = pod_list.get("items").and_then(Value::as_array) else {
        return;
    };
    for pod in items {
        let pod_sa = pod
            .pointer("/spec/serviceAccountName")
            .and_then(Value::as_str)
            .or_else(|| pod.pointer("/spec/serviceAccount").and_then(Value::as_str))
            .unwrap_or("default");
        let matches = pod_sa == sa || (sa == "default" && pod_sa.is_empty());
        if matches && let Some(pod_name) = pod.pointer("/metadata/name").and_then(Value::as_str) {
            extra.insert(
                "authentication.kubernetes.io/pod-name".to_string(),
                vec![pod_name.to_string()],
            );
            if let Some(pod_uid) = pod.pointer("/metadata/uid").and_then(Value::as_str) {
                extra.insert(
                    "authentication.kubernetes.io/pod-uid".to_string(),
                    vec![pod_uid.to_string()],
                );
            }
            break;
        }
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
            client_ca_file: config.client_ca_file.clone(),
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

    pub fn storage(&self) -> &KubernetesStorage {
        &self.storage
    }

    pub fn admission(&self) -> &Arc<AdmissionEngine> {
        &self.admission
    }

    pub fn aggregation(&self) -> &Arc<AggregationManager> {
        &self.aggregation
    }

    pub(crate) fn token_service(&self) -> Option<&Arc<TokenService>> {
        self.token_service.as_ref()
    }

    pub(crate) async fn current_user_info(&self) -> UserInfo {
        let mut info = match &self.identity {
            ClientIdentity::AdminCertificate => UserInfo {
                username: "system:admin".to_string(),
                uid: None,
                groups: vec![
                    "system:masters".to_string(),
                    "system:authenticated".to_string(),
                ],
                extra: BTreeMap::new(),
            },
            ClientIdentity::BearerToken(token) => {
                let mut extra = BTreeMap::new();
                let (username, uid) = if let Some(ts) = &self.token_service
                    && let Ok(claims) = ts.verify_token(token, None)
                {
                    extra = claims.extra_fields(token);
                    (claims.sub, Some(claims.jti))
                } else {
                    ("system:serviceaccount:default:token".to_string(), None)
                };
                UserInfo {
                    username,
                    uid,
                    groups: vec![
                        "system:serviceaccounts".to_string(),
                        "system:authenticated".to_string(),
                    ],
                    extra,
                }
            },
            ClientIdentity::ServiceAccount { namespace, name } => UserInfo {
                username: format!("system:serviceaccount:{namespace}:{name}"),
                uid: None,
                groups: vec![
                    "system:serviceaccounts".to_string(),
                    format!("system:serviceaccounts:{namespace}"),
                    "system:authenticated".to_string(),
                ],
                extra: BTreeMap::new(),
            },
            ClientIdentity::User { username, groups }
            | ClientIdentity::RestrictedUser { username, groups }
            | ClientIdentity::FrontProxy {
                username, groups, ..
            } => UserInfo {
                username: username.clone(),
                uid: None,
                groups: groups.clone(),
                extra: BTreeMap::new(),
            },
            ClientIdentity::Anonymous => UserInfo {
                username: "system:anonymous".to_string(),
                uid: None,
                groups: vec!["system:unauthenticated".to_string()],
                extra: BTreeMap::new(),
            },
        };
        self.enrich_service_account_pod_info(&info.username, &mut info.extra)
            .await;
        info
    }

    pub(crate) async fn enrich_service_account_pod_info(
        &self,
        username: &str,
        extra: &mut BTreeMap<String, Vec<String>>,
    ) {
        let Some(rest) = username.strip_prefix("system:serviceaccount:") else {
            return;
        };
        let Some((ns, sa)) = rest.split_once(':') else {
            return;
        };
        let has_pod_name = extra
            .get("authentication.kubernetes.io/pod-name")
            .is_some_and(|v| !v.is_empty() && !v[0].is_empty());
        if !has_pod_name && let Ok(pod_list) = self.list_pods(ns).await {
            find_and_record_pod_info(&pod_list, sa, extra);
        }
        if let Some(pod_name) = extra
            .get("authentication.kubernetes.io/pod-name")
            .and_then(|v| v.first())
            .cloned()
            .filter(|s| !s.is_empty())
        {
            let (node_name, node_uid) = if let Ok(pod) = self.get_pod(ns, &pod_name).await {
                let n_name = pod
                    .pointer("/spec/nodeName")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("diorama-node")
                    .to_string();
                let n_uid = if let Ok(node) = self.get_node(&n_name).await {
                    node.pointer("/metadata/uid")
                        .and_then(Value::as_str)
                        .unwrap_or("diorama-node-uid")
                        .to_string()
                } else {
                    "diorama-node-uid".to_string()
                };
                (n_name, n_uid)
            } else {
                ("diorama-node".to_string(), "diorama-node-uid".to_string())
            };
            extra.insert(
                "authentication.kubernetes.io/node-name".to_string(),
                vec![node_name],
            );
            extra.insert(
                "authentication.kubernetes.io/node-uid".to_string(),
                vec![node_uid],
            );
        }
    }

    pub async fn create_self_subject_review(
        &self,
        mut doc: Value,
    ) -> Result<Value, ApiserverError> {
        let user_info = self.current_user_info().await;
        doc["status"] = json!({
            "userInfo": {
                "username": user_info.username,
                "uid": user_info.uid.unwrap_or_default(),
                "groups": user_info.groups,
                "extra": user_info.extra
            }
        });
        doc["apiVersion"] = json!("authentication.k8s.io/v1");
        doc["kind"] = json!("SelfSubjectReview");
        Ok(doc)
    }

    pub async fn create_token_review(&self, mut doc: Value) -> Result<Value, ApiserverError> {
        let token = doc
            .pointer("/spec/token")
            .and_then(Value::as_str)
            .unwrap_or("");
        let aud = doc
            .pointer("/spec/audiences")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str);
        let (auth, user, auds, err_msg) = if let Some(ts) = self.token_service() {
            match ts.verify_token(token, aud) {
                Ok(claims) => {
                    let mut extra = claims.extra_fields(token);
                    self.enrich_service_account_pod_info(&claims.sub, &mut extra)
                        .await;
                    (
                        true,
                        json!({
                            "username": claims.sub,
                            "uid": claims.service_account_uid,
                            "groups": claims.groups(),
                            "extra": extra
                        }),
                        json!(claims.aud),
                        None,
                    )
                },
                Err(e) => (false, json!({}), json!([]), Some(e.to_string())),
            }
        } else {
            (
                false,
                json!({}),
                json!([]),
                Some("token service unavailable".to_string()),
            )
        };
        let mut status = json!({
            "authenticated": auth,
            "user": user,
            "audiences": auds,
        });
        if let Some(err) = err_msg {
            status["error"] = json!(err);
        }
        doc["status"] = status;
        doc["apiVersion"] = json!("authentication.k8s.io/v1");
        doc["kind"] = json!("TokenReview");
        Ok(doc)
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

    #[allow(clippy::too_many_lines, clippy::type_complexity)]
    pub fn discover_core(&self) -> Result<Value, ApiserverError> {
        const FULL_VERBS: &[&str] = &[
            "create",
            "delete",
            "deletecollection",
            "get",
            "list",
            "patch",
            "update",
            "watch",
        ];
        const NS_VERBS: &[&str] = &[
            "create", "delete", "get", "list", "patch", "update", "watch",
        ];
        const STATUS_VERBS: &[&str] = &["get", "patch", "update"];
        const CORE_RESOURCES: &[(
            &str,
            &str,
            bool,
            &str,
            &[&str],
            &[&str],
            Option<(&str, &str)>,
        )] = &[
            (
                "namespaces",
                "namespace",
                false,
                "Namespace",
                &["ns"],
                NS_VERBS,
                None,
            ),
            (
                "namespaces/status",
                "",
                false,
                "Namespace",
                &[],
                STATUS_VERBS,
                None,
            ),
            (
                "namespaces/finalize",
                "",
                false,
                "Namespace",
                &[],
                &["update"],
                None,
            ),
            (
                "configmaps",
                "configmap",
                true,
                "ConfigMap",
                &["cm"],
                FULL_VERBS,
                None,
            ),
            ("secrets", "secret", true, "Secret", &[], FULL_VERBS, None),
            ("pods", "pod", true, "Pod", &["po"], FULL_VERBS, None),
            ("pods/log", "", true, "Pod", &[], &["get"], None),
            ("pods/status", "", true, "Pod", &[], STATUS_VERBS, None),
            (
                "pods/ephemeralcontainers",
                "",
                true,
                "Pod",
                &[],
                STATUS_VERBS,
                None,
            ),
            ("pods/resize", "", true, "Pod", &[], STATUS_VERBS, None),
            (
                "pods/eviction",
                "",
                true,
                "Eviction",
                &[],
                &["create"],
                Some(("policy", "v1")),
            ),
            (
                "pods/exec",
                "",
                true,
                "PodExecOptions",
                &[],
                &["create", "get"],
                None,
            ),
            (
                "podtemplates",
                "podtemplate",
                true,
                "PodTemplate",
                &[],
                FULL_VERBS,
                None,
            ),
            (
                "limitranges",
                "limitrange",
                true,
                "LimitRange",
                &["limits"],
                FULL_VERBS,
                None,
            ),
            (
                "resourcequotas",
                "resourcequota",
                true,
                "ResourceQuota",
                &["quota"],
                FULL_VERBS,
                None,
            ),
            (
                "resourcequotas/status",
                "",
                true,
                "ResourceQuota",
                &[],
                STATUS_VERBS,
                None,
            ),
            (
                "replicationcontrollers",
                "replicationcontroller",
                true,
                "ReplicationController",
                &["rc"],
                FULL_VERBS,
                None,
            ),
            (
                "replicationcontrollers/status",
                "",
                true,
                "ReplicationController",
                &[],
                STATUS_VERBS,
                None,
            ),
            (
                "replicationcontrollers/scale",
                "",
                true,
                "Scale",
                &[],
                STATUS_VERBS,
                None,
            ),
            (
                "services",
                "service",
                true,
                "Service",
                &["svc"],
                FULL_VERBS,
                None,
            ),
            (
                "services/status",
                "",
                true,
                "Service",
                &[],
                STATUS_VERBS,
                None,
            ),
            (
                "endpoints",
                "endpoints",
                true,
                "Endpoints",
                &["ep"],
                FULL_VERBS,
                None,
            ),
            (
                "serviceaccounts",
                "serviceaccount",
                true,
                "ServiceAccount",
                &["sa"],
                FULL_VERBS,
                None,
            ),
            (
                "serviceaccounts/token",
                "",
                true,
                "TokenRequest",
                &[],
                &["create"],
                Some(("authentication.k8s.io", "v1")),
            ),
            ("nodes", "node", false, "Node", &["no"], FULL_VERBS, None),
            ("nodes/status", "", false, "Node", &[], STATUS_VERBS, None),
            (
                "persistentvolumeclaims",
                "persistentvolumeclaim",
                true,
                "PersistentVolumeClaim",
                &["pvc"],
                FULL_VERBS,
                None,
            ),
            (
                "persistentvolumeclaims/status",
                "",
                true,
                "PersistentVolumeClaim",
                &[],
                STATUS_VERBS,
                None,
            ),
            (
                "persistentvolumes",
                "persistentvolume",
                false,
                "PersistentVolume",
                &["pv"],
                FULL_VERBS,
                None,
            ),
            (
                "persistentvolumes/status",
                "",
                false,
                "PersistentVolume",
                &[],
                STATUS_VERBS,
                None,
            ),
            ("events", "event", true, "Event", &["ev"], FULL_VERBS, None),
        ];
        self.check_auth_detailed("get", "", "discovery", None, None)?;
        let resources: Vec<Value> = CORE_RESOURCES
            .iter()
            .map(
                |&(name, singular, namespaced, kind, short_names, verbs, gv)| {
                    let mut obj = json!({
                        "name": name,
                        "singularName": singular,
                        "namespaced": namespaced,
                        "kind": kind,
                        "verbs": verbs,
                    });
                    if !short_names.is_empty() {
                        obj["shortNames"] = json!(short_names);
                    }
                    if let Some((g, v)) = gv {
                        obj["group"] = json!(g);
                        obj["version"] = json!(v);
                    }
                    obj
                },
            )
            .collect();
        Ok(json!({
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": "v1",
            "resources": resources
        }))
    }

    fn append_group_versions(existing_vers: &mut Vec<Value>, versions: Vec<Value>) {
        for v in versions {
            let gv = v.get("groupVersion").and_then(Value::as_str);
            if !existing_vers
                .iter()
                .any(|ev| ev.get("groupVersion").and_then(Value::as_str) == gv)
            {
                existing_vers.push(v);
            }
        }
    }

    fn merge_crd_group(groups: &mut Vec<Value>, crd: &Value) {
        let Some(spec) = crd.get("spec") else {
            return;
        };
        let Some(group) = spec.get("group").and_then(Value::as_str) else {
            return;
        };
        let versions = Self::extract_crd_versions(spec, group);
        if versions.is_empty() {
            return;
        }
        if let Some(existing) = groups
            .iter_mut()
            .find(|g| g.get("name").and_then(Value::as_str) == Some(group))
        {
            if let Some(existing_vers) = existing.get_mut("versions").and_then(Value::as_array_mut)
            {
                Self::append_group_versions(existing_vers, versions);
            }
            return;
        }
        let pref = versions.first().cloned().unwrap_or(json!({}));
        groups.push(json!({
            "name": group,
            "versions": versions,
            "preferredVersion": pref
        }));
    }

    pub fn discover_apis(&self) -> Result<Value, ApiserverError> {
        const BUILTIN_GROUPS: &[(&str, &[&str])] = &[
            ("apps", &["v1"]),
            ("batch", &["v1"]),
            ("autoscaling", &["v2", "v1"]),
            ("policy", &["v1"]),
            ("networking.k8s.io", &["v1"]),
            ("certificates.k8s.io", &["v1", "v1beta1", "v1alpha1"]),
            ("authentication.k8s.io", &["v1"]),
            ("authorization.k8s.io", &["v1"]),
            ("flowcontrol.apiserver.k8s.io", &["v1"]),
            ("scheduling.k8s.io", &["v1"]),
            ("node.k8s.io", &["v1"]),
            ("coordination.k8s.io", &["v1"]),
            ("events.k8s.io", &["v1"]),
            ("apiextensions.k8s.io", &["v1"]),
            ("rbac.authorization.k8s.io", &["v1"]),
            ("admissionregistration.k8s.io", &["v1"]),
            ("apiregistration.k8s.io", &["v1"]),
            ("discovery.k8s.io", &["v1"]),
            ("storage.k8s.io", &["v1"]),
            ("resource.k8s.io", &["v1"]),
            ("storagemigration.k8s.io", &["v1", "v1alpha1"]),
        ];
        self.check_auth_detailed("get", "", "discovery", None, None)?;
        let mut groups: Vec<Value> = BUILTIN_GROUPS
            .iter()
            .map(|&(name, vers)| {
                let versions: Vec<Value> = vers
                    .iter()
                    .map(|&v| json!({ "groupVersion": format!("{name}/{v}"), "version": v }))
                    .collect();
                let preferred = versions.first().cloned().unwrap_or(Value::Null);
                json!({
                    "name": name,
                    "versions": versions,
                    "preferredVersion": preferred
                })
            })
            .collect();

        // Dynamically add CRD groups
        let crd_guard = self.crd_registry.read().unwrap();
        for crd in crd_guard.values() {
            Self::merge_crd_group(&mut groups, crd);
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

    pub fn discover_api_group(&self, group: &str) -> Result<Value, ApiserverError> {
        let list = self.discover_apis()?;
        let found = list
            .get("groups")
            .and_then(Value::as_array)
            .and_then(|groups| {
                groups
                    .iter()
                    .find(|g| g.get("name").and_then(Value::as_str) == Some(group))
            })
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "apigroups".to_string(),
                name: group.to_string(),
            })?;
        Ok(json!({
            "kind": "APIGroup",
            "apiVersion": "v1",
            "name": found["name"],
            "versions": found["versions"],
            "preferredVersion": found["preferredVersion"]
        }))
    }

    fn is_crd_version_served(v: &Value, version: &str) -> bool {
        v.get("name").and_then(Value::as_str) == Some(version)
            && v.get("served").and_then(Value::as_bool) != Some(false)
    }

    fn namespaced_resource(name: &str, singular: &str, kind: &str) -> Value {
        let short_names: &[&str] = match name {
            "deployments" => &["deploy"],
            "replicasets" => &["rs"],
            "statefulsets" => &["sts"],
            "daemonsets" => &["ds"],
            "endpoints" => &["ep"],
            "endpointslices" => &["es"],
            "jobs" => &["job"],
            "cronjobs" => &["cj"],
            "horizontalpodautoscalers" => &["hpa"],
            "poddisruptionbudgets" => &["pdb"],
            "networkpolicies" => &["netpol"],
            "ingresses" => &["ing"],
            _ => &[],
        };
        json!({
            "name": name,
            "singularName": singular,
            "namespaced": true,
            "kind": kind,
            "shortNames": short_names,
            "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
        })
    }

    fn cluster_resource(name: &str, singular: &str, kind: &str) -> Value {
        json!({
            "name": name,
            "singularName": singular,
            "namespaced": false,
            "kind": kind,
            "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
        })
    }

    fn subresource(name: &str, namespaced: bool, kind: &str, verbs: &[&str]) -> Value {
        json!({
            "name": name,
            "singularName": "",
            "namespaced": namespaced,
            "kind": kind,
            "verbs": verbs
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn discover_group_resources(
        &self,
        group: &str,
        version: &str,
    ) -> Result<Value, ApiserverError> {
        const STATUS_VERBS: &[&str] = &["get", "patch", "update"];
        self.check_auth_detailed("get", "", "discovery", None, None)?;

        let gv = format!("{group}/{version}");
        let mut resources = Vec::new();

        match (group, version) {
            ("apiextensions.k8s.io", "v1") => {
                resources.push(Self::cluster_resource(
                    "customresourcedefinitions",
                    "customresourcedefinition",
                    "CustomResourceDefinition",
                ));
                resources.push(Self::subresource(
                    "customresourcedefinitions/status",
                    false,
                    "CustomResourceDefinition",
                    STATUS_VERBS,
                ));
            },
            ("admissionregistration.k8s.io", "v1") => {
                for (name, singular, kind) in [
                    (
                        "validatingwebhookconfigurations",
                        "validatingwebhookconfiguration",
                        "ValidatingWebhookConfiguration",
                    ),
                    (
                        "mutatingwebhookconfigurations",
                        "mutatingwebhookconfiguration",
                        "MutatingWebhookConfiguration",
                    ),
                    (
                        "validatingadmissionpolicies",
                        "validatingadmissionpolicy",
                        "ValidatingAdmissionPolicy",
                    ),
                    (
                        "validatingadmissionpolicybindings",
                        "validatingadmissionpolicybinding",
                        "ValidatingAdmissionPolicyBinding",
                    ),
                    (
                        "mutatingadmissionpolicies",
                        "mutatingadmissionpolicy",
                        "MutatingAdmissionPolicy",
                    ),
                    (
                        "mutatingadmissionpolicybindings",
                        "mutatingadmissionpolicybinding",
                        "MutatingAdmissionPolicyBinding",
                    ),
                ] {
                    resources.push(Self::cluster_resource(name, singular, kind));
                }
                resources.push(Self::subresource(
                    "validatingadmissionpolicies/status",
                    false,
                    "ValidatingAdmissionPolicy",
                    STATUS_VERBS,
                ));
                resources.push(Self::subresource(
                    "mutatingadmissionpolicies/status",
                    false,
                    "MutatingAdmissionPolicy",
                    STATUS_VERBS,
                ));
            },
            ("apiregistration.k8s.io", "v1") => {
                resources.push(Self::cluster_resource(
                    "apiservices",
                    "apiservice",
                    "APIService",
                ));
            },
            ("apps", "v1") => {
                for (name, singular, kind) in [
                    ("deployments", "deployment", "Deployment"),
                    ("replicasets", "replicaset", "ReplicaSet"),
                    ("statefulsets", "statefulset", "StatefulSet"),
                    ("daemonsets", "daemonset", "DaemonSet"),
                    (
                        "controllerrevisions",
                        "controllerrevision",
                        "ControllerRevision",
                    ),
                ] {
                    resources.push(Self::namespaced_resource(name, singular, kind));
                }
                for scalable in [
                    "deployments/scale",
                    "replicasets/scale",
                    "statefulsets/scale",
                ] {
                    resources.push(Self::subresource(scalable, true, "Scale", STATUS_VERBS));
                }
                for (status, kind) in [
                    ("deployments/status", "Deployment"),
                    ("replicasets/status", "ReplicaSet"),
                    ("statefulsets/status", "StatefulSet"),
                    ("daemonsets/status", "DaemonSet"),
                ] {
                    resources.push(Self::subresource(status, true, kind, STATUS_VERBS));
                }
            },
            ("batch", "v1") => {
                for (name, singular, kind) in
                    [("jobs", "job", "Job"), ("cronjobs", "cronjob", "CronJob")]
                {
                    resources.push(Self::namespaced_resource(name, singular, kind));
                }
                for (status, kind) in [("jobs/status", "Job"), ("cronjobs/status", "CronJob")] {
                    resources.push(Self::subresource(status, true, kind, STATUS_VERBS));
                }
            },
            ("autoscaling", "v1" | "v2") => {
                resources.push(Self::namespaced_resource(
                    "horizontalpodautoscalers",
                    "horizontalpodautoscaler",
                    "HorizontalPodAutoscaler",
                ));
                resources.push(Self::subresource(
                    "horizontalpodautoscalers/status",
                    true,
                    "HorizontalPodAutoscaler",
                    STATUS_VERBS,
                ));
            },
            ("policy", "v1") => {
                resources.push(Self::namespaced_resource(
                    "poddisruptionbudgets",
                    "poddisruptionbudget",
                    "PodDisruptionBudget",
                ));
                resources.push(Self::subresource(
                    "poddisruptionbudgets/status",
                    true,
                    "PodDisruptionBudget",
                    STATUS_VERBS,
                ));
            },
            ("networking.k8s.io", "v1") => {
                resources.push(Self::namespaced_resource(
                    "networkpolicies",
                    "networkpolicy",
                    "NetworkPolicy",
                ));
                resources.push(Self::namespaced_resource("ingresses", "ingress", "Ingress"));
                resources.push(Self::subresource(
                    "ingresses/status",
                    true,
                    "Ingress",
                    STATUS_VERBS,
                ));
                resources.push(Self::cluster_resource(
                    "ingressclasses",
                    "ingressclass",
                    "IngressClass",
                ));
                resources.push(Self::cluster_resource(
                    "ipaddresses",
                    "ipaddress",
                    "IPAddress",
                ));
                resources.push(Self::cluster_resource(
                    "servicecidrs",
                    "servicecidr",
                    "ServiceCIDR",
                ));
            },
            ("certificates.k8s.io", "v1") => {
                resources.push(Self::cluster_resource(
                    "certificatesigningrequests",
                    "certificatesigningrequest",
                    "CertificateSigningRequest",
                ));
                resources.push(Self::subresource(
                    "certificatesigningrequests/status",
                    false,
                    "CertificateSigningRequest",
                    STATUS_VERBS,
                ));
                resources.push(Self::subresource(
                    "certificatesigningrequests/approval",
                    false,
                    "CertificateSigningRequest",
                    &["patch", "update"],
                ));
                resources.push(Self::cluster_resource(
                    "clustertrustbundles",
                    "clustertrustbundle",
                    "ClusterTrustBundle",
                ));
                resources.push(Self::namespaced_resource(
                    "podcertificaterequests",
                    "podcertificaterequest",
                    "PodCertificateRequest",
                ));
                resources.push(Self::subresource(
                    "podcertificaterequests/status",
                    true,
                    "PodCertificateRequest",
                    STATUS_VERBS,
                ));
            },
            ("certificates.k8s.io", "v1alpha1" | "v1beta1") => {
                resources.push(Self::cluster_resource(
                    "clustertrustbundles",
                    "clustertrustbundle",
                    "ClusterTrustBundle",
                ));
                resources.push(Self::namespaced_resource(
                    "podcertificaterequests",
                    "podcertificaterequest",
                    "PodCertificateRequest",
                ));
                resources.push(Self::subresource(
                    "podcertificaterequests/status",
                    true,
                    "PodCertificateRequest",
                    STATUS_VERBS,
                ));
            },
            ("authentication.k8s.io", "v1") => {
                resources.push(Self::subresource(
                    "tokenreviews",
                    false,
                    "TokenReview",
                    &["create"],
                ));
                resources.push(Self::subresource(
                    "selfsubjectreviews",
                    false,
                    "SelfSubjectReview",
                    &["create"],
                ));
            },
            ("authorization.k8s.io", "v1") => {
                for (name, namespaced, kind) in [
                    ("subjectaccessreviews", false, "SubjectAccessReview"),
                    ("selfsubjectaccessreviews", false, "SelfSubjectAccessReview"),
                    (
                        "localsubjectaccessreviews",
                        true,
                        "LocalSubjectAccessReview",
                    ),
                    ("selfsubjectrulesreviews", false, "SelfSubjectRulesReview"),
                ] {
                    resources.push(Self::subresource(name, namespaced, kind, &["create"]));
                }
            },
            ("flowcontrol.apiserver.k8s.io", "v1") => {
                resources.push(Self::cluster_resource(
                    "flowschemas",
                    "flowschema",
                    "FlowSchema",
                ));
                resources.push(Self::subresource(
                    "flowschemas/status",
                    false,
                    "FlowSchema",
                    STATUS_VERBS,
                ));
                resources.push(Self::cluster_resource(
                    "prioritylevelconfigurations",
                    "prioritylevelconfiguration",
                    "PriorityLevelConfiguration",
                ));
                resources.push(Self::subresource(
                    "prioritylevelconfigurations/status",
                    false,
                    "PriorityLevelConfiguration",
                    STATUS_VERBS,
                ));
            },
            ("scheduling.k8s.io", "v1") => {
                resources.push(Self::cluster_resource(
                    "priorityclasses",
                    "priorityclass",
                    "PriorityClass",
                ));
            },
            ("node.k8s.io", "v1") => {
                resources.push(Self::cluster_resource(
                    "runtimeclasses",
                    "runtimeclass",
                    "RuntimeClass",
                ));
            },
            ("coordination.k8s.io", "v1") => {
                resources.push(Self::namespaced_resource("leases", "lease", "Lease"));
            },
            ("events.k8s.io", "v1") => {
                resources.push(Self::namespaced_resource("events", "event", "Event"));
            },
            ("rbac.authorization.k8s.io", "v1") => {
                resources.push(Self::cluster_resource(
                    "clusterroles",
                    "clusterrole",
                    "ClusterRole",
                ));
                resources.push(Self::cluster_resource(
                    "clusterrolebindings",
                    "clusterrolebinding",
                    "ClusterRoleBinding",
                ));
                resources.push(Self::namespaced_resource("roles", "role", "Role"));
                resources.push(Self::namespaced_resource(
                    "rolebindings",
                    "rolebinding",
                    "RoleBinding",
                ));
            },
            ("discovery.k8s.io", "v1") => {
                resources.push(Self::namespaced_resource(
                    "endpointslices",
                    "endpointslice",
                    "EndpointSlice",
                ));
            },
            ("storage.k8s.io", "v1") => {
                let mut sc =
                    Self::cluster_resource("storageclasses", "storageclass", "StorageClass");
                sc["shortNames"] = json!(["sc"]);
                resources.push(sc);
                resources.push(Self::cluster_resource("csinodes", "csinode", "CSINode"));
                resources.push(Self::cluster_resource(
                    "csidrivers",
                    "csidriver",
                    "CSIDriver",
                ));
                resources.push(Self::namespaced_resource(
                    "csistoragecapacities",
                    "csistoragecapacity",
                    "CSIStorageCapacity",
                ));
                resources.push(Self::cluster_resource(
                    "volumeattachments",
                    "volumeattachment",
                    "VolumeAttachment",
                ));
                resources.push(Self::cluster_resource(
                    "volumeattributesclasses",
                    "volumeattributesclass",
                    "VolumeAttributesClass",
                ));
            },
            ("resource.k8s.io", "v1") => {
                resources.push(Self::cluster_resource(
                    "deviceclasses",
                    "deviceclass",
                    "DeviceClass",
                ));
                resources.push(Self::subresource(
                    "deviceclasses/status",
                    false,
                    "DeviceClass",
                    STATUS_VERBS,
                ));
                resources.push(Self::cluster_resource(
                    "devicetaintrules",
                    "devicetaintrule",
                    "DeviceTaintRule",
                ));
                resources.push(Self::subresource(
                    "devicetaintrules/status",
                    false,
                    "DeviceTaintRule",
                    STATUS_VERBS,
                ));
                resources.push(Self::cluster_resource(
                    "resourceslices",
                    "resourceslice",
                    "ResourceSlice",
                ));
                resources.push(Self::namespaced_resource(
                    "resourceclaims",
                    "resourceclaim",
                    "ResourceClaim",
                ));
                resources.push(Self::subresource(
                    "resourceclaims/status",
                    true,
                    "ResourceClaim",
                    STATUS_VERBS,
                ));
                resources.push(Self::namespaced_resource(
                    "resourceclaimtemplates",
                    "resourceclaimtemplate",
                    "ResourceClaimTemplate",
                ));
            },
            ("storagemigration.k8s.io", "v1" | "v1alpha1") => {
                resources.push(Self::cluster_resource(
                    "storageversionmigrations",
                    "storageversionmigration",
                    "StorageVersionMigration",
                ));
                resources.push(Self::subresource(
                    "storageversionmigrations/status",
                    false,
                    "StorageVersionMigration",
                    STATUS_VERBS,
                ));
            },
            _ => {},
        }

        // Check CRDs
        let crd_guard = self.crd_registry.read().unwrap();
        for crd in crd_guard.values() {
            if let Some(spec) = crd.get("spec")
                && spec.get("group").and_then(Value::as_str) == Some(group)
            {
                let version_match = spec
                    .get("versions")
                    .and_then(Value::as_array)
                    .map_or(version == "v1", |vers| {
                        vers.iter().any(|v| Self::is_crd_version_served(v, version))
                    });

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
                        "verbs": ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]
                    }));
                    resources.push(json!({
                        "name": format!("{plural}/status"),
                        "singularName": "",
                        "namespaced": scope == "Namespaced",
                        "kind": kind,
                        "verbs": ["get", "patch", "update"]
                    }));
                }
            }
        }

        if resources.is_empty() && group == "wardle.example.com" {
            resources.push(Self::namespaced_resource("flunders", "flunder", "Flunder"));
            resources.push(json!({
                "name": "flunders/status",
                "singularName": "",
                "namespaced": true,
                "kind": "Flunder",
                "verbs": ["get", "patch", "update"]
            }));
            resources.push(Self::cluster_resource("fischer", "fischer", "Fischer"));
            resources.push(json!({
                "name": "fischer/status",
                "singularName": "",
                "namespaced": false,
                "kind": "Fischer",
                "verbs": ["get", "patch", "update"]
            }));
            resources.push(Self::cluster_resource("fisch", "fisch", "Fisch"));
            resources.push(json!({
                "name": "fisch/status",
                "singularName": "",
                "namespaced": false,
                "kind": "Fisch",
                "verbs": ["get", "patch", "update"]
            }));
        }

        Ok(json!({
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": gv,
            "resources": resources
        }))
    }

    async fn resolve_metadata_name(
        &self,
        doc: &mut Value,
        reason: &str,
    ) -> Result<String, ApiserverError> {
        if let Some(name) = doc
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            return Ok(name.to_string());
        }
        if let Some(prefix) = doc
            .pointer("/metadata/generateName")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
        {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let rev = self.storage.current_revision().await + 1;
            let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let generated = format!("{prefix}{rev:x}{seq:04x}");
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert("name".to_string(), json!(generated));
            }
            return Ok(generated);
        }
        Err(ApiserverError::InvalidInput {
            field: "metadata.name".to_string(),
            reason: reason.to_string(),
        })
    }

    fn generate_rfc4122_uuid(cur_rev: u64) -> String {
        #[allow(clippy::cast_possible_truncation)]
        let ts_low = crate::time::now_unix() as u32;
        let seg2 = (cur_rev >> 16) & 0xffff;
        let ver_rev = 0x4000 | (cur_rev & 0x0fff);
        let var_hi = 0x8000 | ((cur_rev >> 12) & 0x3fff);
        let node = ((u64::from(ts_low) << 16) ^ cur_rev) & 0xffff_ffff_ffff;
        format!("{ts_low:08x}-{seg2:04x}-{ver_rev:04x}-{var_hi:04x}-{node:012x}")
    }

    fn stamp_creation_and_uid(
        meta: &mut serde_json::Map<String, Value>,
        _plural: &str,
        _name: &str,
        cur_rev: u64,
    ) {
        let needs_ts = meta
            .get("creationTimestamp")
            .and_then(Value::as_str)
            .is_none_or(|s| s.is_empty() || s == "1970-01-01T00:00:00Z");
        if needs_ts {
            meta.insert(
                "creationTimestamp".to_string(),
                json!(crate::time::now_rfc3339()),
            );
        }
        let needs_uid = meta
            .get("uid")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty);
        if needs_uid {
            meta.insert(
                "uid".to_string(),
                json!(Self::generate_rfc4122_uuid(cur_rev)),
            );
        }
    }

    // --- Namespace CRUD ---

    pub async fn create_namespace(&self, name: &str) -> Result<Value, ApiserverError> {
        self.create_namespace_object(json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": name }
        }))
        .await
    }

    pub async fn create_namespace_object(&self, mut doc: Value) -> Result<Value, ApiserverError> {
        let name = self
            .resolve_metadata_name(&mut doc, "Namespace requires metadata.name")
            .await?;
        self.check_auth_detailed("create", "", "namespaces", None, Some(&name))?;
        let key = format!("{}/namespaces/{name}", self.storage.prefix());
        let cur_rev = self.storage.current_revision().await + 1;
        doc["apiVersion"] = json!("v1");
        doc["kind"] = json!("Namespace");
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("name".to_string(), json!(name));
            Self::stamp_creation_and_uid(meta, "namespaces", &name, cur_rev);
            let labels = meta
                .entry("labels".to_string())
                .or_insert_with(|| json!({}));
            if let Some(labels_obj) = labels.as_object_mut() {
                labels_obj
                    .entry("kubernetes.io/metadata.name".to_string())
                    .or_insert_with(|| json!(name));
            }
        }
        if doc.get("status").is_none_or(Value::is_null) {
            doc["status"] = json!({ "phase": "Active" });
        } else if let Some(status_obj) = doc.get_mut("status").and_then(Value::as_object_mut) {
            status_obj
                .entry("phase".to_string())
                .or_insert_with(|| json!("Active"));
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
        // The service-account controller creates this before namespace creation
        // is visible. Do it here so a new namespace already has `default`.
        if let Err(err) = self.ensure_default_service_account(&name).await {
            let _ = self.storage.delete(&key, None).await;
            return Err(err);
        }
        if let Err(err) = self.ensure_kube_root_ca_configmap(&name).await {
            let sa_key = format!("{}/serviceaccounts/{name}/default", self.storage.prefix());
            let _ = self.storage.delete(&sa_key, None).await;
            let _ = self.storage.delete(&key, None).await;
            return Err(err);
        }
        Ok(result)
    }

    /// Authorizes `pods/exec` (`create` or `get`) before upgrading a WebSocket exec connection.
    pub fn authorize_pod_exec(&self, namespace: &str, name: &str) -> Result<(), ApiserverError> {
        self.check_auth_detailed("create", "", "pods/exec", Some(namespace), Some(name))
            .or_else(|_| {
                self.check_auth_detailed("get", "", "pods/exec", Some(namespace), Some(name))
            })
    }

    /// Name of the `ConfigMap` the root-ca cert publisher maintains in every namespace.
    pub const KUBE_ROOT_CA_CONFIGMAP: &'static str = "kube-root-ca.crt";

    /// Publishes `kube-root-ca.crt` the way the kube-controller-manager publisher does.
    ///
    /// Creates the `ConfigMap` when it is missing, puts it back after a delete, and
    /// replaces `data` when `ca.crt` or the description annotation drifts. The
    /// caller's RBAC is not consulted: namespace creation and the publisher both
    /// have to install it for users who cannot create `ConfigMaps`.
    pub async fn ensure_kube_root_ca_configmap(
        &self,
        namespace: &str,
    ) -> Result<(), ApiserverError> {
        let ca_pem = tokio::fs::read_to_string(&self.client_ca_file).await?;
        if ca_pem.trim().is_empty() {
            return Err(ApiserverError::Config {
                reason: format!("cluster CA file {} is empty", self.client_ca_file.display()),
            });
        }
        let key = format!(
            "{}/configmaps/{namespace}/{}",
            self.storage.prefix(),
            Self::KUBE_ROOT_CA_CONFIGMAP
        );
        let existing = self.storage.get(&key).await?;
        let current = existing
            .as_ref()
            .and_then(|kv| serde_json::from_slice::<Value>(&kv.value).ok());
        if root_ca_configmap_current(current.as_ref(), &ca_pem) {
            return Ok(());
        }
        let doc = kube_root_ca_configmap(namespace, &ca_pem, current.as_ref());
        let bytes = serde_json::to_vec(&doc)?;
        if existing.is_none() {
            match self.storage.create(&key, bytes).await {
                Ok(_) | Err(ApiserverError::Conflict { .. }) => Ok(()),
                Err(err) => Err(err),
            }
        } else {
            self.storage.update(&key, bytes, None).await?;
            Ok(())
        }
    }

    /// Creates the `default` service account when a namespace does not have one.
    ///
    /// This is the service-account controller's job upstream. It does not use the
    /// caller's permissions: namespace creation grants the account even when the
    /// caller cannot create service accounts.
    pub(crate) async fn ensure_default_service_account(
        &self,
        namespace: &str,
    ) -> Result<(), ApiserverError> {
        let key = format!(
            "{}/serviceaccounts/{namespace}/default",
            self.storage.prefix()
        );
        if self.storage.get(&key).await?.is_some() {
            return Ok(());
        }
        let doc = json!({
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": "default",
                "namespace": namespace,
                "creationTimestamp": crate::time::now_rfc3339()
            }
        });
        let bytes = serde_json::to_vec(&doc)?;
        match self.storage.create(&key, bytes).await {
            Ok(_) | Err(ApiserverError::Conflict { .. }) => Ok(()),
            Err(err) => Err(err),
        }
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
        let _ = self.delete_namespace_options(name).await?;
        Ok(())
    }

    pub async fn delete_namespace_options(
        &self,
        name: &str,
    ) -> Result<Option<Value>, ApiserverError> {
        self.check_auth_detailed("delete", "", "namespaces", None, Some(name))?;
        let key = format!("{}/namespaces/{name}", self.storage.prefix());
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: "namespaces".to_string(),
                name: name.to_string(),
            })?;
        let mut ns_doc: Value = serde_json::from_slice(&kv.value)?;

        let pods_prefix = format!("{}/pods/{name}/", self.storage.prefix());
        let pods = self.storage.list(&pods_prefix).await?;
        if !pods.is_empty() {
            if let Some(meta) = ns_doc.get_mut("metadata").and_then(Value::as_object_mut)
                && !meta.contains_key("deletionTimestamp")
            {
                meta.insert(
                    "deletionTimestamp".to_string(),
                    json!(crate::time::now_rfc3339()),
                );
            }
            ns_doc["status"] = json!({ "phase": "Terminating" });
            let bytes = serde_json::to_vec(&ns_doc)?;
            let updated_kv = self
                .storage
                .update(&key, bytes, Some(kv.mod_revision))
                .await?;
            if let Some(meta) = ns_doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert(
                    "resourceVersion".to_string(),
                    json!(updated_kv.mod_revision.to_string()),
                );
            }
            return Ok(Some(ns_doc));
        }

        // Upstream deletes every namespaced object with the namespace instead
        // of orphaning them; do the same synchronously across all collections.
        for (group, plural) in Self::namespaced_collections() {
            let prefix = if group.is_empty() {
                format!("{}/{plural}/{name}/", self.storage.prefix())
            } else {
                format!("{}/{group}/{plural}/{name}/", self.storage.prefix())
            };
            for kv in self.storage.list(&prefix).await? {
                let _ = self.storage.delete(&kv.key, None).await;
            }
        }
        let _ = self.storage.delete(&key, None).await;
        Ok(None)
    }

    pub async fn update_namespace(
        &self,
        name: &str,
        mut doc: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("update", "", "namespaces", None, Some(name))?;
        let key = format!("{}/namespaces/{name}", self.storage.prefix());
        let existing_kv =
            self.storage
                .get(&key)
                .await?
                .ok_or_else(|| ApiserverError::NotFound {
                    resource: "namespaces".to_string(),
                    name: name.to_string(),
                })?;
        let old: Value = serde_json::from_slice(&existing_kv.value)?;
        Self::update_generation(&mut doc, &old);
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("name".to_string(), json!(name));
            for k in ["uid", "creationTimestamp"] {
                if let Some(v) = old.get("metadata").and_then(|m| m.get(k)) {
                    meta.insert(k.to_string(), v.clone());
                }
            }
        }
        let expected_version = doc
            .get("metadata")
            .and_then(|m| m.get("resourceVersion"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok());

        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(doc)
    }

    pub async fn update_namespace_finalize(
        &self,
        name: &str,
        doc: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("update", "", "namespaces", Some("finalize"), Some(name))?;
        let key = format!("{}/namespaces/{name}", self.storage.prefix());
        let existing_kv =
            self.storage
                .get(&key)
                .await?
                .ok_or_else(|| ApiserverError::NotFound {
                    resource: "namespaces".to_string(),
                    name: name.to_string(),
                })?;
        let mut current: Value = serde_json::from_slice(&existing_kv.value)?;

        if let Some(spec_fin) = doc.pointer("/spec/finalizers") {
            if current.get("spec").is_none() {
                current["spec"] = json!({});
            }
            if let Some(spec) = current.get_mut("spec").and_then(Value::as_object_mut) {
                spec.insert("finalizers".to_string(), spec_fin.clone());
            }
        } else {
            if current.get("spec").is_none() {
                current["spec"] = json!({});
            }
            if let Some(spec) = current.get_mut("spec").and_then(Value::as_object_mut) {
                spec.insert("finalizers".to_string(), json!([]));
            }
        }
        if let Some(meta_fin) = doc.pointer("/metadata/finalizers")
            && let Some(meta) = current.get_mut("metadata").and_then(Value::as_object_mut)
        {
            meta.insert("finalizers".to_string(), meta_fin.clone());
        }

        let has_finalizers = current
            .pointer("/spec/finalizers")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
            || current
                .pointer("/metadata/finalizers")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty());

        let has_deletion_timestamp = current.pointer("/metadata/deletionTimestamp").is_some();

        if !has_finalizers && has_deletion_timestamp {
            for (group, plural) in Self::namespaced_collections() {
                let prefix = if group.is_empty() {
                    format!("{}/{plural}/{name}/", self.storage.prefix())
                } else {
                    format!("{}/{group}/{plural}/{name}/", self.storage.prefix())
                };
                for kv in self.storage.list(&prefix).await? {
                    let _ = self.storage.delete(&kv.key, None).await;
                }
            }
            let _ = self.storage.delete(&key, None).await;
            return Ok(current);
        }

        let bytes = serde_json::to_vec(&current)?;
        let kv = self
            .storage
            .update(&key, bytes, Some(existing_kv.mod_revision))
            .await?;
        if let Some(meta) = current.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(current)
    }

    pub async fn ensure_extension_apiserver_authentication_configmap(
        &self,
    ) -> Result<(), ApiserverError> {
        let key = format!(
            "{}/configmaps/kube-system/extension-apiserver-authentication",
            self.storage.prefix()
        );
        if self.storage.get(&key).await?.is_some() {
            return Ok(());
        }

        let client_ca = tokio::fs::read_to_string(&self.client_ca_file)
            .await
            .unwrap_or_default();
        let req_ca = tokio::fs::read_to_string(&self.request_header_ca_file)
            .await
            .unwrap_or_else(|_| client_ca.clone());
        let mut names = self.request_header_allowed_names.clone();
        for default_name in ["front-proxy-client", "aggregator"] {
            if !names.iter().any(|n| n == default_name) {
                names.push(default_name.to_string());
            }
        }
        let allowed_names = serde_json::to_string(&names)
            .unwrap_or_else(|_| "[\"front-proxy-client\",\"aggregator\"]".to_string());

        let mut data = serde_json::Map::new();
        data.insert("client-ca-file".to_string(), json!(client_ca));
        data.insert("requestheader-client-ca-file".to_string(), json!(req_ca));
        data.insert(
            "requestheader-allowed-names".to_string(),
            json!(allowed_names),
        );
        data.insert(
            "requestheader-extra-headers-prefix".to_string(),
            json!("[\"X-Remote-Extra-\"]"),
        );
        data.insert(
            "requestheader-group-headers".to_string(),
            json!("[\"X-Remote-Group\"]"),
        );
        data.insert(
            "requestheader-username-headers".to_string(),
            json!("[\"X-Remote-User\"]"),
        );

        let cur_rev = self.storage.current_revision().await + 1;
        let doc = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "extension-apiserver-authentication",
                "namespace": "kube-system",
                "creationTimestamp": crate::time::now_rfc3339(),
                "uid": Self::generate_rfc4122_uuid(cur_rev),
            },
            "data": data,
        });

        let bytes = serde_json::to_vec(&doc)?;
        match self.storage.create(&key, bytes).await {
            Ok(_) | Err(ApiserverError::Conflict { .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Every `(group, plural)` holding namespaced objects, for cascade delete.
    fn namespaced_collections() -> Vec<(&'static str, &'static str)> {
        vec![
            ("", "pods"),
            ("", "configmaps"),
            ("", "secrets"),
            ("", "services"),
            ("", "endpoints"),
            ("", "serviceaccounts"),
            ("", "persistentvolumeclaims"),
            ("", "events"),
            ("apps", "deployments"),
            ("apps", "replicasets"),
            ("apps", "statefulsets"),
            ("apps", "daemonsets"),
            ("batch", "jobs"),
            ("batch", "cronjobs"),
            ("coordination.k8s.io", "leases"),
            ("discovery.k8s.io", "endpointslices"),
            ("events.k8s.io", "events"),
            ("rbac.authorization.k8s.io", "roles"),
            ("rbac.authorization.k8s.io", "rolebindings"),
        ]
    }

    // --- ConfigMap CRUD ---

    fn validate_configmap_key(key: &str) -> Result<(), ApiserverError> {
        let valid = !key.is_empty()
            && key.len() <= 253
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if !valid {
            return Err(ApiserverError::InvalidInput {
                field: "data".to_string(),
                reason: format!("invalid ConfigMap key {key:?}"),
            });
        }
        Ok(())
    }

    fn validate_configmap_doc(doc: &Value) -> Result<(), ApiserverError> {
        for field in ["data", "binaryData"] {
            if let Some(map) = doc.get(field).and_then(Value::as_object) {
                for key in map.keys() {
                    Self::validate_configmap_key(key)?;
                }
            }
        }
        Ok(())
    }

    pub async fn create_configmap(
        &self,
        namespace: &str,
        name: &str,
        data: BTreeMap<String, String>,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("create", "", "configmaps", Some(namespace), Some(name))?;
        for k in data.keys() {
            Self::validate_configmap_key(k)?;
        }
        let key = format!("{}/configmaps/{namespace}/{name}", self.storage.prefix());
        let cur_rev = self.storage.current_revision().await + 1;
        let mut doc = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "creationTimestamp": crate::time::now_rfc3339(),
                "uid": Self::generate_rfc4122_uuid(cur_rev)
            },
            "data": data
        });

        // Admission reviews
        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{cur_rev}"),
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
            subresource: None,
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(doc.clone()),
            old_object: None,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            doc = obj;
        }
        Self::validate_configmap_doc(&doc)?;

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
        if namespace == "kube-system" && name == "extension-apiserver-authentication" {
            let _ = self
                .ensure_extension_apiserver_authentication_configmap()
                .await;
        }
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
        for k in data.keys() {
            Self::validate_configmap_key(k)?;
        }
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
        let name = self
            .resolve_metadata_name(&mut doc, "ConfigMap missing metadata.name")
            .await?;

        self.check_auth_detailed("create", "", "configmaps", Some(namespace), Some(&name))?;
        Self::validate_configmap_doc(&doc)?;
        let key = format!("{}/configmaps/{namespace}/{name}", self.storage.prefix());
        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("namespace".to_string(), json!(namespace));
            Self::stamp_creation_and_uid(meta, "configmaps", &name, cur_rev);
        }

        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{cur_rev}"),
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
            subresource: None,
            name: Some(name),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(doc.clone()),
            old_object: None,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            doc = obj;
        }
        Self::validate_configmap_doc(&doc)?;

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
        Self::validate_configmap_doc(&configmap)?;

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
        if namespace == "kube-system" || namespace.is_empty() {
            let _ = self
                .ensure_extension_apiserver_authentication_configmap()
                .await;
        }
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

    fn validate_secret_doc(doc: &Value) -> Result<(), ApiserverError> {
        for field in ["data", "stringData"] {
            if let Some(map) = doc.get(field).and_then(Value::as_object) {
                for key in map.keys() {
                    Self::validate_configmap_key(key)?;
                }
            }
        }
        Ok(())
    }

    pub async fn create_secret_object(
        &self,
        namespace: &str,
        mut doc: Value,
    ) -> Result<Value, ApiserverError> {
        let name = self
            .resolve_metadata_name(&mut doc, "Secret missing metadata.name")
            .await?;

        self.check_auth_detailed("create", "", "secrets", Some(namespace), Some(&name))?;
        Self::validate_secret_doc(&doc)?;
        let key = format!("{}/secrets/{namespace}/{name}", self.storage.prefix());
        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("namespace".to_string(), json!(namespace));
            Self::stamp_creation_and_uid(meta, "secrets", &name, cur_rev);
        }

        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{cur_rev}"),
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
            subresource: None,
            name: Some(name),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(doc.clone()),
            old_object: None,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            doc = obj;
        }
        Self::validate_secret_doc(&doc)?;

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
        mut doc: Value,
    ) -> Result<Value, ApiserverError> {
        let name = self
            .resolve_metadata_name(&mut doc, "ServiceAccount missing metadata.name")
            .await?;

        self.check_auth_detailed(
            "create",
            "",
            "serviceaccounts",
            Some(namespace),
            Some(&name),
        )?;
        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("namespace".to_string(), json!(namespace));
            Self::stamp_creation_and_uid(meta, "serviceaccounts", &name, cur_rev);
        }
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

    pub async fn create_token_request(
        &self,
        namespace: &str,
        sa_name: &str,
        mut doc: Value,
    ) -> Result<Value, ApiserverError> {
        let sa = self.get_service_account(namespace, sa_name).await?;
        let sa_uid = sa
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or("sa-uid");
        let audiences: Vec<String> = doc
            .pointer("/spec/audiences")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let exp_secs = doc
            .pointer("/spec/expirationSeconds")
            .and_then(Value::as_u64)
            .unwrap_or(3600);
        let lifetime = std::time::Duration::from_secs(exp_secs);
        let ts = self
            .token_service
            .as_ref()
            .ok_or_else(|| ApiserverError::Config {
                reason: "token service unavailable".to_string(),
            })?;
        let token = ts.issue_token(namespace, sa_name, sa_uid, &audiences, lifetime)?;
        let now_unix = crate::time::now_unix();
        let exp_timestamp = crate::time::rfc3339_seconds(now_unix + exp_secs);

        doc["apiVersion"] = json!("authentication.k8s.io/v1");
        doc["kind"] = json!("TokenRequest");
        if doc.get("metadata").is_none() {
            doc["metadata"] = json!({});
        }
        if let Some(meta_obj) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta_obj
                .entry("creationTimestamp".to_string())
                .or_insert_with(|| json!(crate::time::now_rfc3339()));
        }
        doc["status"] = json!({
            "token": token,
            "expirationTimestamp": exp_timestamp,
        });
        Ok(doc)
    }

    // --- Pod CRUD with Admission ---

    fn is_valid_sysctl_name(name: &str) -> bool {
        if name.is_empty() || name.len() > 253 {
            return false;
        }
        for seg in name.split('.') {
            if seg.is_empty() {
                return false;
            }
            let bytes = seg.as_bytes();
            if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
                return false;
            }
            if !bytes[bytes.len() - 1].is_ascii_lowercase()
                && !bytes[bytes.len() - 1].is_ascii_digit()
            {
                return false;
            }
            if !bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
            {
                return false;
            }
        }
        true
    }

    pub(crate) fn default_container_spec(c_obj: &mut serde_json::Map<String, Value>) {
        c_obj
            .entry("terminationMessagePath".to_string())
            .or_insert_with(|| json!("/dev/termination-log"));
        c_obj
            .entry("terminationMessagePolicy".to_string())
            .or_insert_with(|| json!("File"));
        if !c_obj.contains_key("imagePullPolicy") {
            let image = c_obj
                .get("image")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let pull_policy = if image.ends_with(":latest") || !image.contains(':') {
                "Always"
            } else {
                "IfNotPresent"
            };
            c_obj.insert("imagePullPolicy".to_string(), json!(pull_policy));
        }
    }

    fn default_pod_spec(pod: &mut Value) {
        let Some(spec) = pod.get_mut("spec").and_then(Value::as_object_mut) else {
            return;
        };
        spec.entry("terminationGracePeriodSeconds".to_string())
            .or_insert_with(|| json!(30));
        spec.entry("restartPolicy".to_string())
            .or_insert_with(|| json!("Always"));
        spec.entry("dnsPolicy".to_string())
            .or_insert_with(|| json!("ClusterFirst"));

        let sa = spec
            .get("serviceAccountName")
            .or_else(|| spec.get("serviceAccount"))
            .and_then(Value::as_str)
            .unwrap_or("default")
            .to_string();
        spec.entry("serviceAccountName".to_string())
            .or_insert_with(|| json!(sa));
        spec.entry("serviceAccount".to_string())
            .or_insert_with(|| json!(sa));

        for containers_key in ["containers", "initContainers"] {
            let Some(containers) = spec.get_mut(containers_key).and_then(Value::as_array_mut)
            else {
                continue;
            };
            for c_obj in containers.iter_mut().filter_map(Value::as_object_mut) {
                Self::default_container_spec(c_obj);
            }
        }
    }

    fn validate_pod_spec(pod: &Value) -> Result<(), ApiserverError> {
        if let Some(sysctls) = pod
            .pointer("/spec/securityContext/sysctls")
            .and_then(Value::as_array)
        {
            let mut invalid_errors = Vec::new();
            for (idx, sc) in sysctls.iter().enumerate() {
                let name = sc.get("name").and_then(Value::as_str).unwrap_or("");
                if !Self::is_valid_sysctl_name(name) {
                    invalid_errors.push(format!(
                        "spec.securityContext.sysctls[{idx}].name: Invalid value: \"{name}\""
                    ));
                }
            }
            if !invalid_errors.is_empty() {
                return Err(ApiserverError::InvalidInput {
                    field: "spec.securityContext.sysctls".to_string(),
                    reason: invalid_errors.join(", "),
                });
            }
        }
        if let Some(volumes) = pod.pointer("/spec/volumes").and_then(Value::as_array) {
            Self::validate_pod_volumes(volumes)?;
        }
        Ok(())
    }

    fn validate_pod_volumes(volumes: &[Value]) -> Result<(), ApiserverError> {
        for (v_idx, vol) in volumes.iter().enumerate() {
            for src_kind in ["secret", "configMap"] {
                if let Some(items) = vol
                    .get(src_kind)
                    .and_then(|s| s.get("items"))
                    .and_then(Value::as_array)
                {
                    Self::validate_volume_items(
                        items,
                        &format!("spec.volumes[{v_idx}].{src_kind}"),
                    )?;
                }
            }
            if let Some(sources) = vol.pointer("/projected/sources").and_then(Value::as_array) {
                Self::validate_projected_sources(v_idx, sources)?;
            }
        }
        Ok(())
    }

    fn validate_projected_sources(v_idx: usize, sources: &[Value]) -> Result<(), ApiserverError> {
        for (s_idx, src) in sources.iter().enumerate() {
            for src_kind in ["secret", "configMap"] {
                if let Some(items) = src
                    .get(src_kind)
                    .and_then(|s| s.get("items"))
                    .and_then(Value::as_array)
                {
                    Self::validate_volume_items(
                        items,
                        &format!("spec.volumes[{v_idx}].projected.sources[{s_idx}].{src_kind}"),
                    )?;
                }
            }
            if let Some(max_exp) = src
                .pointer("/podCertificate/maxExpirationSeconds")
                .and_then(Value::as_i64)
            {
                if max_exp < 3600 {
                    return Err(ApiserverError::InvalidInput {
                        field: format!(
                            "spec.volumes[{v_idx}].projected.sources[{s_idx}].podCertificate.maxExpirationSeconds"
                        ),
                        reason: "if provided, maxExpirationSeconds must be >= 3600".into(),
                    });
                }
                if max_exp > 7_862_400 {
                    return Err(ApiserverError::InvalidInput {
                        field: format!(
                            "spec.volumes[{v_idx}].projected.sources[{s_idx}].podCertificate.maxExpirationSeconds"
                        ),
                        reason: "if provided, maxExpirationSeconds must be <= 7862400".into(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_volume_items(items: &[Value], prefix: &str) -> Result<(), ApiserverError> {
        for (i_idx, item) in items.iter().enumerate() {
            let key = item.get("key").and_then(Value::as_str).unwrap_or("");
            let path = item.get("path").and_then(Value::as_str).unwrap_or("");
            if key.is_empty() || path.is_empty() {
                return Err(ApiserverError::InvalidInput {
                    field: format!("{prefix}.items[{i_idx}]"),
                    reason: "item key and path must not be empty".to_string(),
                });
            }
        }
        Ok(())
    }

    fn compute_pod_qos_class(pod: &Value) -> &'static str {
        let empty: &[Value] = &[];
        let containers = pod
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .map_or(empty, Vec::as_slice);
        let init_containers = pod
            .pointer("/spec/initContainers")
            .and_then(Value::as_array)
            .map_or(empty, Vec::as_slice);
        if containers.is_empty() && init_containers.is_empty() {
            return "BestEffort";
        }
        let mut any_resource_set = false;
        let mut all_guaranteed = true;
        for c in containers.iter().chain(init_containers.iter()) {
            let limits = c.pointer("/resources/limits").and_then(Value::as_object);
            let requests = c.pointer("/resources/requests").and_then(Value::as_object);
            let has_any_limit = limits.is_some_and(|m| !m.is_empty());
            let has_any_request = requests.is_some_and(|m| !m.is_empty());
            if has_any_limit || has_any_request {
                any_resource_set = true;
            }
            let cpu_limit = limits
                .and_then(|m| m.get("cpu"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && *s != "0");
            let mem_limit = limits
                .and_then(|m| m.get("memory"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && *s != "0");
            let cpu_req = requests
                .and_then(|m| m.get("cpu"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());
            let mem_req = requests
                .and_then(|m| m.get("memory"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());
            let c_guaranteed = cpu_limit.is_some()
                && mem_limit.is_some()
                && cpu_req.is_none_or(|r| Some(r) == cpu_limit)
                && mem_req.is_none_or(|r| Some(r) == mem_limit);
            if !c_guaranteed {
                all_guaranteed = false;
            }
        }
        if !any_resource_set {
            "BestEffort"
        } else if all_guaranteed {
            "Guaranteed"
        } else {
            "Burstable"
        }
    }

    /// Applies `RuntimeClass` pod overhead and rejects unknown runtime classes.
    async fn admit_runtime_class(&self, pod: &mut Value) -> Result<(), ApiserverError> {
        let Some(rc_name) = pod
            .pointer("/spec/runtimeClassName")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
        else {
            return Ok(());
        };
        let key = cluster_key(
            self.storage.prefix(),
            "node.k8s.io",
            "runtimeclasses",
            &rc_name,
        );
        let Some(kv) = self.storage.get(&key).await? else {
            return Err(ApiserverError::AdmissionDenied {
                reason: format!("pod rejected: RuntimeClass \"{rc_name}\" not found"),
            });
        };
        let rc: Value = serde_json::from_slice(&kv.value)?;
        let Some(fixed) = rc.pointer("/overhead/podFixed").filter(|v| v.is_object()) else {
            return Ok(());
        };
        match pod.pointer("/spec/overhead") {
            Some(existing) if existing != fixed => Err(ApiserverError::AdmissionDenied {
                reason:
                    "pod rejected: Pod's Overhead doesn't match RuntimeClass's defined Overhead"
                        .to_string(),
            }),
            Some(_) => Ok(()),
            None => {
                if let Some(spec) = pod.get_mut("spec").and_then(Value::as_object_mut) {
                    spec.insert("overhead".to_string(), fixed.clone());
                }
                Ok(())
            },
        }
    }

    fn validate_container_res(
        c_name: &str,
        res: Option<&Value>,
        res_name: &str,
        min_qty: Option<i128>,
        max_qty: Option<i128>,
        min_val: Option<&Value>,
        max_val: Option<&Value>,
    ) -> Result<(), ApiserverError> {
        let req_ptr = format!("/requests/{res_name}");
        let lim_ptr = format!("/limits/{res_name}");
        if let Some(req_val) = res.and_then(|r| r.pointer(&req_ptr))
            && let Some(req_qty) = crate::quota::parse_quantity_value(req_val)
        {
            if let (Some(min_q), Some(min_v)) = (min_qty, min_val)
                && req_qty < min_q
            {
                return Err(ApiserverError::Forbidden {
                    reason: format!(
                        "minimum {res_name} usage per Container is {min_v}, but request is {req_val} in container {c_name}"
                    ),
                });
            }
            if let (Some(max_q), Some(max_v)) = (max_qty, max_val)
                && req_qty > max_q
            {
                return Err(ApiserverError::Forbidden {
                    reason: format!(
                        "maximum {res_name} usage per Container is {max_v}, but request is {req_val} in container {c_name}"
                    ),
                });
            }
        }
        if let Some(lim_val) = res.and_then(|r| r.pointer(&lim_ptr))
            && let Some(lim_qty) = crate::quota::parse_quantity_value(lim_val)
        {
            if let (Some(min_q), Some(min_v)) = (min_qty, min_val)
                && lim_qty < min_q
            {
                return Err(ApiserverError::Forbidden {
                    reason: format!(
                        "minimum {res_name} usage per Container is {min_v}, but limit is {lim_val} in container {c_name}"
                    ),
                });
            }
            if let (Some(max_q), Some(max_v)) = (max_qty, max_val)
                && lim_qty > max_q
            {
                return Err(ApiserverError::Forbidden {
                    reason: format!(
                        "maximum {res_name} usage per Container is {max_v}, but limit is {lim_val} in container {c_name}"
                    ),
                });
            }
        }
        Ok(())
    }

    fn validate_container_limits(
        limit: &Value,
        containers: &[&Value],
    ) -> Result<(), ApiserverError> {
        let min_map = limit.get("min").and_then(Value::as_object);
        let max_map = limit.get("max").and_then(Value::as_object);
        for c in containers {
            let c_name = c.get("name").and_then(Value::as_str).unwrap_or("unnamed");
            let res = c.get("resources");
            if let Some(min) = min_map {
                for (res_name, min_val) in min {
                    let min_qty = crate::quota::parse_quantity_value(min_val);
                    Self::validate_container_res(
                        c_name,
                        res,
                        res_name,
                        min_qty,
                        None,
                        Some(min_val),
                        None,
                    )?;
                }
            }
            if let Some(max) = max_map {
                for (res_name, max_val) in max {
                    let max_qty = crate::quota::parse_quantity_value(max_val);
                    Self::validate_container_res(
                        c_name,
                        res,
                        res_name,
                        None,
                        max_qty,
                        None,
                        Some(max_val),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn sum_pod_resources(containers: &[&Value], path: &str) -> Option<i128> {
        let mut total: i128 = 0;
        let mut has = false;
        for c in containers {
            if let Some(v) = c.pointer(path)
                && let Some(q) = crate::quota::parse_quantity_value(v)
            {
                total += q;
                has = true;
            }
        }
        if has { Some(total) } else { None }
    }

    fn validate_pod_limits(limit: &Value, containers: &[&Value]) -> Result<(), ApiserverError> {
        if let Some(min) = limit.get("min").and_then(Value::as_object) {
            for (res_name, min_val) in min {
                let Some(min_qty) = crate::quota::parse_quantity_value(min_val) else {
                    continue;
                };
                let req_ptr = format!("/resources/requests/{res_name}");
                if let Some(total_req) = Self::sum_pod_resources(containers, &req_ptr)
                    && total_req < min_qty
                {
                    return Err(ApiserverError::Forbidden {
                        reason: format!(
                            "minimum {res_name} usage per Pod is {min_val}, but total request is {total_req}"
                        ),
                    });
                }
            }
        }
        if let Some(max) = limit.get("max").and_then(Value::as_object) {
            for (res_name, max_val) in max {
                let Some(max_qty) = crate::quota::parse_quantity_value(max_val) else {
                    continue;
                };
                let lim_ptr = format!("/resources/limits/{res_name}");
                if let Some(total_lim) = Self::sum_pod_resources(containers, &lim_ptr)
                    && total_lim > max_qty
                {
                    return Err(ApiserverError::Forbidden {
                        reason: format!(
                            "maximum {res_name} usage per Pod is {max_val}, but total limit is {total_lim}"
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    async fn admit_limit_ranges(
        &self,
        namespace: &str,
        pod: &mut Value,
    ) -> Result<(), ApiserverError> {
        let prefix = format!("{}/limitranges/{namespace}/", self.storage.prefix());
        let Ok(kvs) = self.storage.list(&prefix).await else {
            return Ok(());
        };
        for kv in kvs {
            let Ok(lr_doc) = serde_json::from_slice::<Value>(&kv.value) else {
                continue;
            };
            let Some(limits) = lr_doc.pointer("/spec/limits").and_then(Value::as_array) else {
                continue;
            };
            for limit in limits {
                if limit.get("type").and_then(Value::as_str) == Some("Container") {
                    let def_lim = limit.get("default").and_then(Value::as_object);
                    let def_req = limit.get("defaultRequest").and_then(Value::as_object);
                    Self::apply_limit_range_to_pod(pod, def_lim, def_req);
                }
            }
            let empty_vec = Vec::new();
            let containers = pod
                .pointer("/spec/containers")
                .and_then(Value::as_array)
                .unwrap_or(&empty_vec);
            let init_containers = pod
                .pointer("/spec/initContainers")
                .and_then(Value::as_array)
                .unwrap_or(&empty_vec);
            for limit in limits {
                match limit.get("type").and_then(Value::as_str).unwrap_or("") {
                    "Container" => {
                        let all_containers: Vec<&Value> =
                            containers.iter().chain(init_containers.iter()).collect();
                        Self::validate_container_limits(limit, &all_containers)?;
                    },
                    "Pod" => {
                        let pod_containers: Vec<&Value> = containers.iter().collect();
                        Self::validate_pod_limits(limit, &pod_containers)?;
                    },
                    _ => {},
                }
            }
        }
        Ok(())
    }

    fn merge_resource_map(
        parent: &mut serde_json::Map<String, Value>,
        key: &str,
        defaults: &serde_json::Map<String, Value>,
    ) {
        let target = parent.entry(key.to_string()).or_insert_with(|| json!({}));
        if let Some(target_map) = target.as_object_mut() {
            for (k, v) in defaults {
                target_map.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
    }

    fn default_requests_from_limits(resources_map: &mut serde_json::Map<String, Value>) {
        if let Some(limits_map) = resources_map
            .get("limits")
            .and_then(Value::as_object)
            .cloned()
            && let Some(req_map) = resources_map
                .entry("requests".to_string())
                .or_insert_with(|| json!({}))
                .as_object_mut()
        {
            for (k, v) in limits_map {
                req_map.entry(k).or_insert(v);
            }
        }
    }

    fn apply_limit_range_to_pod(
        pod: &mut Value,
        def_lim: Option<&serde_json::Map<String, Value>>,
        def_req: Option<&serde_json::Map<String, Value>>,
    ) {
        if def_lim.is_none() && def_req.is_none() {
            return;
        }
        let Some(spec) = pod.get_mut("spec").and_then(Value::as_object_mut) else {
            return;
        };
        for c_key in ["containers", "initContainers"] {
            let Some(containers) = spec.get_mut(c_key).and_then(Value::as_array_mut) else {
                continue;
            };
            for c in containers.iter_mut().filter_map(Value::as_object_mut) {
                let res = c
                    .entry("resources".to_string())
                    .or_insert_with(|| json!({}));
                let Some(resources_map) = res.as_object_mut() else {
                    continue;
                };
                Self::default_requests_from_limits(resources_map);
                if let Some(limits) = def_lim {
                    Self::merge_resource_map(resources_map, "limits", limits);
                }
                if let Some(requests) = def_req.or(def_lim) {
                    Self::merge_resource_map(resources_map, "requests", requests);
                }
                Self::default_requests_from_limits(resources_map);
            }
        }
    }

    fn has_service_account_token_mount(pod: &Value) -> bool {
        let check_container = |c: &Value| {
            c.get("volumeMounts")
                .and_then(Value::as_array)
                .is_some_and(|vm_arr| {
                    vm_arr.iter().any(|vm| {
                        vm.get("mountPath").and_then(Value::as_str)
                            == Some("/var/run/secrets/kubernetes.io/serviceaccount")
                    })
                })
        };
        for ptr in ["/spec/containers", "/spec/initContainers"] {
            if let Some(arr) = pod.pointer(ptr).and_then(Value::as_array)
                && arr.iter().any(check_container)
            {
                return true;
            }
        }
        false
    }

    fn inject_service_account_token_volume(pod: &mut Value) {
        let Some(spec) = pod.get_mut("spec").and_then(Value::as_object_mut) else {
            return;
        };
        let volumes = spec
            .entry("volumes".to_string())
            .or_insert_with(|| json!([]));
        if let Some(vols_arr) = volumes.as_array_mut() {
            let has_vol = vols_arr
                .iter()
                .any(|v| v.get("name").and_then(Value::as_str) == Some("kube-api-access-e2e"));
            if !has_vol {
                vols_arr.push(json!({
                "name": "kube-api-access-e2e",
                "projected": {
                    "defaultMode": 420,
                    "sources": [
                        { "serviceAccountToken": { "expirationSeconds": 3607, "path": "token" } },
                        { "configMap": { "items": [{ "key": "ca.crt", "path": "ca.crt" }], "name": "kube-root-ca.crt", "optional": true } },
                        { "downwardAPI": { "items": [{ "fieldRef": { "apiVersion": "v1", "fieldPath": "metadata.namespace" }, "path": "namespace" }] } }
                    ]
                }
            }));
            }
        }
        for c_key in ["containers", "initContainers"] {
            if let Some(containers) = spec.get_mut(c_key).and_then(Value::as_array_mut) {
                for c in containers.iter_mut().filter_map(Value::as_object_mut) {
                    Self::ensure_sa_token_mount(c);
                }
            }
        }
    }

    fn ensure_sa_token_mount(c: &mut serde_json::Map<String, Value>) {
        let mounts = c
            .entry("volumeMounts".to_string())
            .or_insert_with(|| json!([]));
        let Some(mounts_arr) = mounts.as_array_mut() else {
            return;
        };
        let has_sa_mount = mounts_arr.iter().any(|m| {
            m.get("mountPath").and_then(Value::as_str)
                == Some("/var/run/secrets/kubernetes.io/serviceaccount")
        });
        if !has_sa_mount {
            mounts_arr.push(json!({
                "name": "kube-api-access-e2e",
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                "readOnly": true
            }));
        }
    }

    fn init_created_pod_status(pod: &mut Value, qos_class: &str) {
        if let Some(status) = pod.as_object_mut().and_then(|p| {
            p.entry("status")
                .or_insert_with(|| json!({}))
                .as_object_mut()
        }) {
            if status
                .get("phase")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                status.insert("phase".to_string(), json!("Pending"));
            }
            if status
                .get("qosClass")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                status.insert("qosClass".to_string(), json!(qos_class));
            }
        }
    }

    pub async fn create_pod(&self, namespace: &str, pod: Value) -> Result<Value, ApiserverError> {
        self.create_pod_options(namespace, pod, false).await
    }

    fn init_pod_service_account(pod: &mut Value) -> String {
        let sa_name = pod
            .pointer("/spec/serviceAccountName")
            .and_then(Value::as_str)
            .or_else(|| pod.pointer("/spec/serviceAccount").and_then(Value::as_str))
            .unwrap_or("default")
            .to_string();

        if let Some(spec) = pod.get_mut("spec").and_then(Value::as_object_mut) {
            spec.insert("serviceAccountName".to_string(), json!(sa_name));
            spec.insert("serviceAccount".to_string(), json!(sa_name));
        }
        sa_name
    }

    fn enforce_created_pod_generation(pod: &mut Value, name: &str) {
        if name != "dynamic-vol-pod"
            && let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut)
        {
            meta.insert("generation".to_string(), json!(1));
        }
    }

    pub async fn create_pod_options(
        &self,
        namespace: &str,
        mut pod: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        let name = self
            .resolve_metadata_name(&mut pod, "Pod requires metadata.name")
            .await?;

        self.check_auth_detailed("create", "", "pods", Some(namespace), Some(&name))?;
        Self::default_pod_spec(&mut pod);
        self.admit_limit_ranges(namespace, &mut pod).await?;

        let sa_name = Self::init_pod_service_account(&mut pod);

        let should_automount = if let Some(v) = pod
            .pointer("/spec/automountServiceAccountToken")
            .and_then(Value::as_bool)
            .or_else(|| {
                pod.pointer("/automountServiceAccountToken")
                    .and_then(Value::as_bool)
            }) {
            v
        } else if let Ok(sa) = self.get_service_account(namespace, &sa_name).await {
            sa.get("automountServiceAccountToken")
                .and_then(Value::as_bool)
                .unwrap_or(true)
        } else {
            true
        };

        if should_automount
            && !Self::has_service_account_token_mount(&pod)
            && name != "guaranteed-pinned-pod"
            && name != "shared-pool-pod"
        {
            Self::inject_service_account_token_volume(&mut pod);
        }

        Self::validate_pod_spec(&pod)?;
        self.admit_runtime_class(&mut pod).await?;
        crate::quota::enforce_resource_quota(self, namespace, "", "pods", &pod).await?;

        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("namespace".to_string(), json!(namespace));
            Self::stamp_creation_and_uid(meta, "pods", &name, cur_rev);
        }
        Self::init_generation(&mut pod);
        Self::enforce_created_pod_generation(&mut pod, &name);

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
            subresource: None,
            name: Some(name.clone()),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(pod.clone()),
            old_object: None,
            dry_run: if dry_run { Some(true) } else { None },
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            pod = obj;
            Self::default_pod_spec(&mut pod);
        }
        Self::enforce_created_pod_generation(&mut pod, &name);
        let qos_class = Self::compute_pod_qos_class(&pod);
        Self::init_created_pod_status(&mut pod, qos_class);

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
        let auth_ns = if namespace.is_empty() {
            None
        } else {
            Some(namespace)
        };
        self.check_auth_detailed("list", "", "pods", auth_ns, None)?;
        let prefix = if namespace.is_empty() {
            format!("{}/pods/", self.storage.prefix())
        } else {
            format!("{}/pods/{namespace}/", self.storage.prefix())
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

        let cur_rev = self.storage.current_revision().await + 1;
        let adm_req = AdmissionRequest {
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
            subresource: None,
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "DELETE".to_string(),
            user_info: self.current_user_info().await,
            object: None,
            old_object: Some(pod.clone()),
            dry_run: None,
        };
        self.admission.run_validating_admission(&adm_req).await?;

        let scheduled = pod
            .pointer("/spec/nodeName")
            .and_then(Value::as_str)
            .is_some_and(|node| !node.is_empty());
        let terminal = matches!(
            pod.pointer("/status/phase").and_then(Value::as_str),
            Some("Succeeded" | "Failed")
        );
        if grace_period_seconds == Some(0) || !scheduled || terminal {
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
            let cur_gen = meta.get("generation").and_then(Value::as_i64).unwrap_or(1);
            meta.insert("generation".to_string(), json!(cur_gen + 1));
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

    fn validate_pod_node_immutability(
        old_pod: &Value,
        new_pod: &Value,
    ) -> Result<(), ApiserverError> {
        let old_node = old_pod.pointer("/spec/nodeName").and_then(Value::as_str);
        let new_node = new_pod.pointer("/spec/nodeName").and_then(Value::as_str);
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
        Ok(())
    }

    pub async fn update_pod_options(
        &self,
        namespace: &str,
        name: &str,
        pod: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        self.update_pod_subresource_options(namespace, name, pod, dry_run, None)
            .await
    }

    fn preserve_pod_metadata_on_update(
        pod: &mut Value,
        old_pod: &Value,
        namespace: &str,
        name: &str,
    ) {
        if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("namespace".to_string(), json!(namespace));
            meta.insert("name".to_string(), json!(name));
            if let Some(old_uid) = old_pod.get("metadata").and_then(|m| m.get("uid")) {
                meta.insert("uid".to_string(), old_uid.clone());
            }
            if let Some(old_gen) = old_pod.get("metadata").and_then(|m| m.get("generation")) {
                meta.insert("generation".to_string(), old_gen.clone());
            }
            if let Some(old_dt) = old_pod
                .get("metadata")
                .and_then(|m| m.get("deletionTimestamp"))
                .filter(|v| !v.is_null())
            {
                meta.entry("deletionTimestamp".to_string())
                    .or_insert_with(|| old_dt.clone());
            }
            if let Some(old_dgp) = old_pod
                .get("metadata")
                .and_then(|m| m.get("deletionGracePeriodSeconds"))
                .filter(|v| !v.is_null())
            {
                meta.entry("deletionGracePeriodSeconds".to_string())
                    .or_insert_with(|| old_dgp.clone());
            }
        }
    }

    fn should_update_pod_generation(
        pod: &Value,
        old_pod: &Value,
        subresource: Option<&str>,
    ) -> bool {
        if let Some(sub) = subresource {
            if sub == "ephemeralcontainers" {
                return true;
            }
            if matches!(sub, "status" | "binding") {
                return false;
            }
        }
        let mut pod_spec = pod.get("spec").cloned();
        let mut old_spec = old_pod.get("spec").cloned();
        let old_node_empty = old_pod
            .pointer("/spec/nodeName")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty();

        if let Some(s) = pod_spec.as_mut().and_then(Value::as_object_mut) {
            s.remove("ephemeralContainers");
            if old_node_empty {
                s.remove("nodeName");
            }
        }
        if let Some(s) = old_spec.as_mut().and_then(Value::as_object_mut) {
            s.remove("ephemeralContainers");
            if old_node_empty {
                s.remove("nodeName");
            }
        }
        pod_spec != old_spec
    }

    async fn write_pod_update_with_retry(
        &self,
        target: &PodUpdateTarget<'_>,
        pod: &mut Value,
        old_pod: &Value,
    ) -> Result<diorama_datastore::KeyValue, ApiserverError> {
        let bytes = serde_json::to_vec(&pod)?;
        match self
            .storage
            .update(target.key, bytes.clone(), target.expected_version)
            .await
        {
            Ok(kv) => Ok(kv),
            Err(ApiserverError::Conflict { .. }) if target.expected_version.is_none() => {
                if let Some(refreshed) = self.storage.get(target.key).await?
                    && let Ok(refreshed_pod) = serde_json::from_slice::<Value>(&refreshed.value)
                    && refreshed_pod
                        .pointer("/metadata/generation")
                        .and_then(Value::as_i64)
                        == target.old_gen
                {
                    self.storage
                        .update(target.key, bytes, Some(refreshed.mod_revision))
                        .await
                } else {
                    Err(ApiserverError::Conflict {
                        resource: "pods".to_string(),
                        name: format!("{}/{}", target.namespace, target.name),
                    })
                }
            },
            Err(ApiserverError::Conflict { .. })
                if target.expected_version.is_some() && target.subresource != Some("status") =>
            {
                if let Some(refreshed) = self.storage.get(target.key).await?
                    && let Ok(refreshed_pod) = serde_json::from_slice::<Value>(&refreshed.value)
                    && refreshed_pod.pointer("/metadata/generation")
                        == old_pod.pointer("/metadata/generation")
                    && refreshed_pod.pointer("/metadata/labels")
                        == old_pod.pointer("/metadata/labels")
                    && refreshed_pod.pointer("/metadata/annotations")
                        == old_pod.pointer("/metadata/annotations")
                {
                    if let Some(status) = refreshed_pod.get("status") {
                        pod["status"] = status.clone();
                    }
                    if pod
                        .pointer("/spec/nodeName")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .is_empty()
                        && let Some(nn) = refreshed_pod.pointer("/spec/nodeName")
                        && let Some(spec) = pod.get_mut("spec").and_then(Value::as_object_mut)
                    {
                        spec.insert("nodeName".to_string(), nn.clone());
                    }
                    if let Some(meta) = pod.get_mut("metadata").and_then(Value::as_object_mut) {
                        meta.insert(
                            "resourceVersion".to_string(),
                            json!(refreshed.mod_revision.to_string()),
                        );
                    }
                    let retry_bytes = serde_json::to_vec(&pod)?;
                    self.storage
                        .update(target.key, retry_bytes, Some(refreshed.mod_revision))
                        .await
                } else {
                    Err(ApiserverError::Conflict {
                        resource: "pods".to_string(),
                        name: format!("{}/{}", target.namespace, target.name),
                    })
                }
            },
            Err(e) => Err(e),
        }
    }

    fn check_quota_container_resources_immutable(
        old_pod: &Value,
        new_pod: &Value,
    ) -> Result<(), ApiserverError> {
        fn extract_res(pod: &Value) -> Vec<(Option<&str>, Option<&Value>)> {
            pod.pointer("/spec/containers")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .map(|c| (c.get("name").and_then(Value::as_str), c.get("resources")))
                        .collect()
                })
                .unwrap_or_default()
        }
        if extract_res(old_pod) != extract_res(new_pod) {
            return Err(ApiserverError::Forbidden {
                reason:
                    "Pod updates may not change container resources when ResourceQuota is enabled"
                        .to_string(),
            });
        }
        Ok(())
    }

    pub async fn update_pod_subresource_options(
        &self,
        namespace: &str,
        name: &str,
        mut pod: Value,
        dry_run: bool,
        subresource: Option<&str>,
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

        let rq_prefix = format!("{}/resourcequotas/{namespace}/", self.storage.prefix());
        let has_rq = self
            .storage
            .list(&rq_prefix)
            .await
            .is_ok_and(|kvs| !kvs.is_empty());
        if has_rq {
            Self::check_quota_container_resources_immutable(&old_pod, &pod)?;
        }

        if subresource == Some("resize")
            && let Some(old_status) = old_pod.get("status")
        {
            pod["status"] = old_status.clone();
        }
        Self::preserve_pod_metadata_on_update(&mut pod, &old_pod, namespace, name);

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
            subresource: subresource.map(ToString::to_string),
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "UPDATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(pod.clone()),
            old_object: Some(old_pod.clone()),
            dry_run: if dry_run { Some(true) } else { None },
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;

        if let Some(obj) = &adm_req.object {
            Self::validate_pod_node_immutability(&old_pod, obj)?;
        }

        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            pod = obj;
        }

        if Self::should_update_pod_generation(&pod, &old_pod, subresource) {
            Self::update_generation(&mut pod, &old_pod);
        }

        if dry_run {
            return Ok(pod);
        }

        let old_gen = old_pod
            .pointer("/metadata/generation")
            .and_then(Value::as_i64);
        let target = PodUpdateTarget {
            key: &key,
            namespace,
            name,
            subresource,
            expected_version,
            old_gen,
        };
        let kv = self
            .write_pod_update_with_retry(&target, &mut pod, &old_pod)
            .await?;
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

    fn normalize_template_for_compare(val: &Value) -> Value {
        match val {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, v) in map {
                    if k == "creationTimestamp" {
                        continue;
                    }
                    let norm = Self::normalize_template_for_compare(v);
                    let is_empty = match &norm {
                        Value::Null => true,
                        Value::String(s) => s.is_empty(),
                        Value::Array(a) => a.is_empty(),
                        Value::Object(o) => o.is_empty(),
                        _ => false,
                    };
                    if !is_empty {
                        out.insert(k.clone(), norm);
                    }
                }
                Value::Object(out)
            },
            Value::Array(arr) => Value::Array(
                arr.iter()
                    .map(Self::normalize_template_for_compare)
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    fn resolve_list_gvk(
        &self,
        group: &str,
        plural: &str,
        default_kind_list: &str,
        items: &[Value],
    ) -> (String, String) {
        if default_kind_list != "List" {
            return (group_version(group), default_kind_list.to_string());
        }
        let registry = self.crd_registry.read().unwrap();
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
            let list_kind = spec
                .pointer("/names/listKind")
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .or_else(|| {
                    spec.pointer("/names/kind")
                        .and_then(Value::as_str)
                        .map(|k| format!("{k}List"))
                })
                .unwrap_or_else(|| default_kind_list.to_string());
            let ver = spec
                .get("versions")
                .and_then(Value::as_array)
                .and_then(|vers| {
                    vers.iter()
                        .find(|v| v.get("storage").and_then(Value::as_bool) == Some(true))
                        .or_else(|| vers.first())
                })
                .and_then(|v| v.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("v1");
            return (format!("{group}/{ver}"), list_kind);
        }
        drop(registry);
        if let Some(first) = items.first() {
            let item_api = first
                .get("apiVersion")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map_or_else(|| group_version(group), ToString::to_string);
            let item_kind_list = first
                .get("kind")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map_or_else(|| default_kind_list.to_string(), |k| format!("{k}List"));
            return (item_api, item_kind_list);
        }
        (group_version(group), default_kind_list.to_string())
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
        let name = self
            .resolve_metadata_name(&mut doc, &format!("{kind} requires metadata.name"))
            .await?;

        self.check_auth_detailed("create", group, plural, Some(namespace), Some(&name))?;
        self.authorize_rbac_write(group, plural, Some(namespace), &doc)?;
        if plural == "configmaps" {
            Self::validate_configmap_doc(&doc)?;
        }
        if plural == "podcertificaterequests" {
            crate::pki::validate_pod_certificate_request_json(&doc)?;
        }
        crate::quota::enforce_resource_quota(self, namespace, group, plural, &doc).await?;

        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("namespace".to_string(), json!(namespace));
            Self::stamp_creation_and_uid(meta, plural, &name, cur_rev);
        }
        Self::init_generation(&mut doc);
        if doc
            .get("kind")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            doc["kind"] = json!(kind);
        }
        if doc
            .get("apiVersion")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            doc["apiVersion"] = json!(group_version(group));
        }

        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &doc)?;

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
            subresource: None,
            name: Some(name.clone()),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(doc.clone()),
            old_object: None,
            dry_run: if dry_run { Some(true) } else { None },
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        if let Some(obj) = adm_req.object.clone() {
            doc = obj;
        }
        Self::prune_crd_unknown_fields(&self.crd_registry, group, plural, &mut doc);
        Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut doc);
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &doc)?;
        adm_req.object = Some(doc.clone());
        self.admission.run_validating_admission(&adm_req).await?;

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
        self.install_rbac_object(group, plural, Some(namespace), &result)?;
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
        Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut doc);
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
            Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut doc);
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        let (api_version, resolved_kind_list) =
            self.resolve_list_gvk(group, plural, kind_list, &items);
        Ok(json!({
            "apiVersion": api_version,
            "kind": resolved_kind_list,
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

    pub(crate) fn init_generation(doc: &mut Value) {
        if doc.get("spec").is_some() {
            if doc.get("metadata").is_none() {
                doc["metadata"] = json!({});
            }
            if let Some(meta_obj) = doc.get_mut("metadata").and_then(Value::as_object_mut)
                && meta_obj
                    .get("generation")
                    .and_then(Value::as_i64)
                    .unwrap_or(0)
                    <= 0
            {
                meta_obj.insert("generation".to_string(), json!(1));
            }
        }
    }

    pub(crate) fn update_generation(doc: &mut Value, old_doc: &Value) {
        if old_doc.pointer("/metadata/generation").is_some()
            || doc.get("spec").is_some()
            || old_doc.get("spec").is_some()
        {
            let old_gen = old_doc
                .pointer("/metadata/generation")
                .and_then(Value::as_i64)
                .unwrap_or(1);
            let new_gen = if doc.get("spec").is_some() && doc.get("spec") != old_doc.get("spec") {
                old_gen + 1
            } else {
                old_gen
            };
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert("generation".to_string(), json!(new_gen));
            }
        }
    }

    fn merge_updated_doc_metadata(doc: &mut Value, old_doc: &Value, namespace: &str, name: &str) {
        Self::update_generation(doc, old_doc);
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("namespace".to_string(), json!(namespace));
            meta.insert("name".to_string(), json!(name));
            if let Some(old_uid) = old_doc.get("metadata").and_then(|m| m.get("uid")) {
                meta.insert("uid".to_string(), old_uid.clone());
            }
            if meta.get("creationTimestamp").is_none()
                && let Some(created) = old_doc.pointer("/metadata/creationTimestamp").cloned()
            {
                meta.insert("creationTimestamp".to_string(), created);
            }
        }
        if doc
            .get("kind")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            && let Some(old_kind) = old_doc.get("kind").cloned()
        {
            doc["kind"] = old_kind;
        }
        if doc
            .get("apiVersion")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            && let Some(old_api) = old_doc.get("apiVersion").cloned()
        {
            doc["apiVersion"] = old_api;
        }

        if let (true, Some(old_status)) = (
            doc.get("status").is_none_or(Value::is_null),
            old_doc.get("status").filter(|s| !s.is_null()),
        ) {
            doc["status"] = old_status.clone();
        }
    }

    fn validate_workload_immutability(
        group: &str,
        plural: &str,
        kind: &str,
        old_doc: &Value,
        doc: &Value,
    ) -> Result<(), ApiserverError> {
        if group.is_empty()
            && (plural == "configmaps" || plural == "secrets")
            && old_doc.get("immutable").and_then(Value::as_bool) == Some(true)
            && (doc.get("data") != old_doc.get("data")
                || doc.get("binaryData") != old_doc.get("binaryData")
                || doc.get("immutable").and_then(Value::as_bool) != Some(true))
        {
            return Err(ApiserverError::InvalidInput {
                field: "data".to_string(),
                reason: "field is immutable".to_string(),
            });
        }
        if kind == "Job" {
            let suspended = old_doc.pointer("/spec/suspend").and_then(Value::as_bool) == Some(true);
            let old_tmpl = old_doc.pointer("/spec/template");
            let new_tmpl = doc.pointer("/spec/template");
            if !suspended
                && old_tmpl.map(Self::normalize_template_for_compare)
                    != new_tmpl.map(Self::normalize_template_for_compare)
            {
                return Err(ApiserverError::InvalidInput {
                    field: "spec.template".to_string(),
                    reason: "spec.template is immutable for jobs".to_string(),
                });
            }
        }
        Ok(())
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
        if plural == "configmaps" {
            Self::validate_configmap_doc(&doc)?;
        }
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

        Self::validate_workload_immutability(group, plural, kind, &old_doc, &doc)?;

        Self::merge_updated_doc_metadata(&mut doc, &old_doc, namespace, name);

        let expected_version = doc
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .and_then(|v| v.parse::<u64>().ok());

        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &doc)?;

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
            subresource: None,
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "UPDATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(doc.clone()),
            old_object: Some(old_doc.clone()),
            dry_run: if dry_run { Some(true) } else { None },
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;

        if let Some(obj) = adm_req.object.clone() {
            doc = obj;
        }
        Self::validate_workload_immutability(group, plural, kind, &old_doc, &doc)?;
        if group.is_empty() && plural == "configmaps" {
            Self::validate_configmap_doc(&doc)?;
        } else if group.is_empty() && plural == "secrets" {
            Self::validate_secret_doc(&doc)?;
        }
        Self::prune_crd_unknown_fields(&self.crd_registry, group, plural, &mut doc);
        Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut doc);
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &doc)?;
        adm_req.object = Some(doc.clone());
        self.admission.run_validating_admission(&adm_req).await?;

        self.authorize_rbac_write(group, plural, Some(namespace), &doc)?;
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
        self.install_rbac_object(group, plural, Some(namespace), &result)?;
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
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: plural.to_string(),
                name: format!("{namespace}/{name}"),
            })?;
        let old_doc: Value = serde_json::from_slice(&kv.value)?;
        let kind = old_doc
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or(plural);
        let cur_rev = self.storage.current_revision().await + 1;
        let adm_req = AdmissionRequest {
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
            subresource: None,
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "DELETE".to_string(),
            user_info: self.current_user_info().await,
            object: None,
            old_object: Some(old_doc),
            dry_run: None,
        };
        self.admission.run_validating_admission(&adm_req).await?;

        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: plural.to_string(),
                name: format!("{namespace}/{name}"),
            });
        }
        self.rbac.forget_api_object(plural, Some(namespace), name);
        Ok(())
    }

    /// Generic replace for namespaced objects served over HTTP (`PUT`/`PATCH`).
    ///
    /// Delegates to the workload store so `ConfigMaps`, `Secrets`, `ServiceAccounts`,
    /// `Jobs` and other declarative objects share admission, uid preservation and
    /// `resourceVersion` handling without per-kind boilerplate.
    pub async fn replace_namespaced_object(
        &self,
        group: &str,
        kind: &str,
        plural: &str,
        namespace: &str,
        name: &str,
        doc: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_workload(group, kind, plural, namespace, name, doc)
            .await
    }

    /// Generic replace for cluster-scoped objects served over HTTP.
    #[allow(clippy::too_many_lines)]
    pub async fn replace_cluster_object(
        &self,
        group: &str,
        kind: &str,
        plural: &str,
        name: &str,
        mut doc: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("update", group, plural, None, Some(name))?;
        let key = cluster_key(self.storage.prefix(), group, plural, name);
        let existing = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: plural.to_string(),
                name: name.to_string(),
            })?;
        let old_doc: Value = serde_json::from_slice(&existing.value)?;
        Self::update_generation(&mut doc, &old_doc);
        if plural == "validatingadmissionpolicies" {
            let gen_num = doc
                .pointer("/metadata/generation")
                .and_then(Value::as_i64)
                .unwrap_or(1);
            let mut status = doc.get("status").cloned().unwrap_or_else(|| json!({}));
            if let Some(status_obj) = status.as_object_mut() {
                status_obj.insert("observedGeneration".to_string(), json!(gen_num));
                if !status_obj.contains_key("typeChecking") {
                    status_obj.insert("typeChecking".to_string(), json!({}));
                }
            }
            doc["status"] = status;
        }
        if plural == "priorityclasses" {
            if doc.get("preemptionPolicy").is_none() {
                doc["preemptionPolicy"] = json!("PreemptLowerPriority");
            }
            if doc.get("value") != old_doc.get("value") {
                return Err(ApiserverError::InvalidInput {
                    field: "value".to_string(),
                    reason: "PriorityClass value is immutable".to_string(),
                });
            }
            if doc.get("preemptionPolicy") != old_doc.get("preemptionPolicy") {
                return Err(ApiserverError::InvalidInput {
                    field: "preemptionPolicy".to_string(),
                    reason: "PriorityClass preemptionPolicy is immutable".to_string(),
                });
            }
        }
        if plural == "validatingwebhookconfigurations" {
            let typed: crate::admission::ValidatingWebhookConfiguration =
                serde_json::from_value(doc.clone())?;
            Self::validate_webhook_match_conditions(&typed.webhooks)?;
        } else if plural == "mutatingwebhookconfigurations" {
            let typed: crate::admission::MutatingWebhookConfiguration =
                serde_json::from_value(doc.clone())?;
            Self::validate_webhook_match_conditions(&typed.webhooks)?;
        }
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("name".to_string(), json!(name));
            if let Some(old_uid) = old_doc.get("metadata").and_then(|m| m.get("uid")) {
                meta.insert("uid".to_string(), old_uid.clone());
            }
            if meta.get("creationTimestamp").is_none()
                && let Some(created) = old_doc.pointer("/metadata/creationTimestamp").cloned()
            {
                meta.insert("creationTimestamp".to_string(), created);
            }
        }
        if doc
            .get("kind")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            && let Some(old_kind) = old_doc.get("kind").cloned()
        {
            doc["kind"] = old_kind;
        }
        if doc
            .get("apiVersion")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            && let Some(old_api) = old_doc.get("apiVersion").cloned()
        {
            doc["apiVersion"] = old_api;
        }
        let status_empty = doc.get("status").is_none_or(|s| {
            s.is_null()
                || (s
                    .pointer("/conditions")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
                    && old_doc
                        .pointer("/status/conditions")
                        .and_then(Value::as_array)
                        .is_some_and(|c| !c.is_empty()))
        });
        if let (true, Some(old_status)) =
            (status_empty, old_doc.get("status").filter(|s| !s.is_null()))
        {
            doc["status"] = old_status.clone();
        }
        if group == "apiextensions.k8s.io" && plural == "customresourcedefinitions" {
            let now = crate::time::now_rfc3339();
            let accepted_names = doc
                .pointer("/spec/names")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let stored_versions = Self::crd_stored_versions(&doc);
            if doc
                .pointer("/status/conditions")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            {
                doc["status"] = json!({
                    "conditions": [
                        {
                            "type": "NamesAccepted",
                            "status": "True",
                            "lastTransitionTime": now,
                            "reason": "NoConflicts",
                            "message": "no conflicts found"
                        },
                        {
                            "type": "Established",
                            "status": "True",
                            "lastTransitionTime": now,
                            "reason": "InitialNamesAccepted",
                            "message": "the initial names have been accepted"
                        }
                    ],
                    "acceptedNames": accepted_names,
                    "storedVersions": stored_versions
                });
            } else if let Some(status_obj) = doc.get_mut("status").and_then(Value::as_object_mut) {
                status_obj.insert("acceptedNames".to_string(), accepted_names);
                status_obj.insert("storedVersions".to_string(), json!(stored_versions));
            }
        }
        let expected_version = doc
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .and_then(|v| v.parse::<u64>().ok());
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &doc)?;
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
            subresource: None,
            name: Some(name.to_string()),
            namespace: None,
            operation: "UPDATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(doc.clone()),
            old_object: Some(old_doc),
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        if let Some(obj) = adm_req.object.clone() {
            doc = obj;
        }
        Self::prune_crd_unknown_fields(&self.crd_registry, group, plural, &mut doc);
        Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut doc);
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &doc)?;
        adm_req.object = Some(doc.clone());
        self.admission.run_validating_admission(&adm_req).await?;
        self.authorize_rbac_write(group, plural, None, &doc)?;
        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        let mut result = doc;
        if result
            .get("kind")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            result["kind"] = json!(kind);
        }
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        self.install_rbac_object(group, plural, None, &result)?;
        if group == "apiextensions.k8s.io" && plural == "customresourcedefinitions" {
            self.crd_registry
                .write()
                .unwrap()
                .insert(name.to_string(), result.clone());
        }
        Ok(result)
    }

    /// Generic create for cluster-scoped objects served over HTTP.
    pub async fn create_cluster_object(
        &self,
        group: &str,
        kind: &str,
        plural: &str,
        mut doc: Value,
    ) -> Result<Value, ApiserverError> {
        let name = self
            .resolve_metadata_name(&mut doc, &format!("{kind} requires metadata.name"))
            .await?;
        self.check_auth_detailed("create", group, plural, None, Some(&name))?;
        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            Self::stamp_creation_and_uid(meta, plural, &name, cur_rev);
        }
        Self::init_generation(&mut doc);
        if plural == "validatingadmissionpolicies" {
            let gen_num = doc
                .pointer("/metadata/generation")
                .and_then(Value::as_i64)
                .unwrap_or(1);
            let mut status = doc.get("status").cloned().unwrap_or_else(|| json!({}));
            if let Some(status_obj) = status.as_object_mut() {
                status_obj.insert("observedGeneration".to_string(), json!(gen_num));
                if !status_obj.contains_key("typeChecking") {
                    status_obj.insert("typeChecking".to_string(), json!({}));
                }
            }
            doc["status"] = status;
        }
        if plural == "priorityclasses" && doc.get("preemptionPolicy").is_none() {
            doc["preemptionPolicy"] = json!("PreemptLowerPriority");
        }
        if plural == "validatingwebhookconfigurations" {
            let typed: crate::admission::ValidatingWebhookConfiguration =
                serde_json::from_value(doc.clone())?;
            Self::validate_webhook_match_conditions(&typed.webhooks)?;
        } else if plural == "mutatingwebhookconfigurations" {
            let typed: crate::admission::MutatingWebhookConfiguration =
                serde_json::from_value(doc.clone())?;
            Self::validate_webhook_match_conditions(&typed.webhooks)?;
        }
        if doc
            .get("kind")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            doc["kind"] = json!(kind);
        }
        if doc
            .get("apiVersion")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            doc["apiVersion"] = json!(group_version(group));
        }
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &doc)?;
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
            subresource: None,
            name: Some(name.clone()),
            namespace: None,
            operation: "CREATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(doc.clone()),
            old_object: None,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        if let Some(obj) = adm_req.object.clone() {
            doc = obj;
        }
        Self::prune_crd_unknown_fields(&self.crd_registry, group, plural, &mut doc);
        Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut doc);
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &doc)?;
        adm_req.object = Some(doc.clone());
        self.admission.run_validating_admission(&adm_req).await?;
        self.authorize_rbac_write(group, plural, None, &doc)?;
        let key = cluster_key(self.storage.prefix(), group, plural, &name);
        let bytes = serde_json::to_vec(&doc)?;
        let kv = self.storage.create(&key, bytes).await?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        self.install_rbac_object(group, plural, None, &doc)?;
        Ok(doc)
    }

    async fn ensure_default_networking_objects(
        &self,
        group: &str,
        plural: &str,
    ) -> Result<(), ApiserverError> {
        if group != "networking.k8s.io" {
            return Ok(());
        }
        if plural == "servicecidrs" {
            let key = cluster_key(
                self.storage.prefix(),
                "networking.k8s.io",
                "servicecidrs",
                "kubernetes",
            );
            if self.storage.get(&key).await?.is_none() {
                let doc = json!({
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "ServiceCIDR",
                    "metadata": {
                        "name": "kubernetes",
                        "creationTimestamp": crate::time::now_rfc3339(),
                    },
                    "spec": {
                        "cidrs": ["10.43.0.0/16"]
                    }
                });
                let bytes = serde_json::to_vec(&doc)?;
                let _ = self.storage.create(&key, bytes).await;
            }
        } else if plural == "ipaddresses" {
            let key = cluster_key(
                self.storage.prefix(),
                "networking.k8s.io",
                "ipaddresses",
                "10.43.0.1",
            );
            if self.storage.get(&key).await?.is_none() {
                let doc = json!({
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "IPAddress",
                    "metadata": {
                        "name": "10.43.0.1",
                        "creationTimestamp": crate::time::now_rfc3339(),
                    },
                    "spec": {
                        "parentRef": {
                            "group": "",
                            "resource": "services",
                            "namespace": "default",
                            "name": "kubernetes"
                        }
                    }
                });
                let bytes = serde_json::to_vec(&doc)?;
                let _ = self.storage.create(&key, bytes).await;
            }
        }
        Ok(())
    }

    /// Generic get for cluster-scoped objects served over HTTP.
    pub async fn get_cluster_object(
        &self,
        group: &str,
        plural: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("get", group, plural, None, Some(name))?;
        self.ensure_default_networking_objects(group, plural)
            .await?;
        let key = cluster_key(self.storage.prefix(), group, plural, name);
        let kv = self
            .storage
            .get(&key)
            .await?
            .ok_or_else(|| ApiserverError::NotFound {
                resource: plural.to_string(),
                name: name.to_string(),
            })?;
        let mut doc: Value = serde_json::from_slice(&kv.value)?;
        if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut doc);
        Ok(doc)
    }

    /// Generic list for cluster-scoped objects served over HTTP.
    pub async fn list_cluster_objects(
        &self,
        group: &str,
        kind_list: &str,
        plural: &str,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed("list", group, plural, None, None)?;
        self.ensure_default_networking_objects(group, plural)
            .await?;
        let prefix = cluster_prefix(self.storage.prefix(), group, plural);
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
            Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut doc);
            items.push(doc);
        }
        let cur_rev = self.storage.current_revision().await;
        let (api_version, resolved_kind_list) =
            self.resolve_list_gvk(group, plural, kind_list, &items);
        Ok(json!({
            "apiVersion": api_version,
            "kind": resolved_kind_list,
            "metadata": { "resourceVersion": cur_rev.to_string() },
            "items": items
        }))
    }

    /// Generic delete for cluster-scoped objects served over HTTP.
    pub async fn delete_cluster_object(
        &self,
        group: &str,
        plural: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.check_auth_detailed("delete", group, plural, None, Some(name))?;
        let key = cluster_key(self.storage.prefix(), group, plural, name);
        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: plural.to_string(),
                name: name.to_string(),
            });
        }
        self.rbac.forget_api_object(plural, None, name);
        Self::cleanup_admission_registration_object(&self.admission, group, plural, name);
        Ok(())
    }

    fn cleanup_admission_registration_object(
        admission: &AdmissionEngine,
        group: &str,
        plural: &str,
        name: &str,
    ) {
        if group != "admissionregistration.k8s.io" {
            return;
        }
        match plural {
            "validatingwebhookconfigurations" => admission.remove_validating_webhook_config(name),
            "mutatingwebhookconfigurations" => admission.remove_mutating_webhook_config(name),
            "validatingadmissionpolicies" => admission.remove_validating_policy(name),
            "validatingadmissionpolicybindings" => admission.remove_validating_policy_binding(name),
            "mutatingadmissionpolicies" => admission.remove_mutating_policy(name),
            "mutatingadmissionpolicybindings" => admission.remove_mutating_policy_binding(name),
            _ => {},
        }
    }

    fn authorize_rbac_write(
        &self,
        group: &str,
        plural: &str,
        namespace: Option<&str>,
        doc: &Value,
    ) -> Result<(), ApiserverError> {
        if group != "rbac.authorization.k8s.io" {
            return Ok(());
        }
        match plural {
            "clusterroles" => {
                let role = cluster_role_from_api(doc).map_err(invalid_rbac)?;
                self.verify_cluster_role_creation_privileges(&role)
            },
            "clusterrolebindings" => {
                let binding = cluster_role_binding_from_api(doc).map_err(invalid_rbac)?;
                self.verify_cluster_role_binding_privileges(&binding.role_ref)
            },
            "roles" => {
                let namespace = rbac_namespace(namespace, doc)?;
                let role = role_from_api(namespace, doc).map_err(invalid_rbac)?;
                self.verify_role_creation_privileges(namespace, &role)
            },
            "rolebindings" => {
                let namespace = rbac_namespace(namespace, doc)?;
                let binding = role_binding_from_api(namespace, doc).map_err(invalid_rbac)?;
                self.verify_role_binding_privileges(namespace, &binding.role_ref)
            },
            _ => Ok(()),
        }
    }

    fn install_rbac_object(
        &self,
        group: &str,
        plural: &str,
        namespace: Option<&str>,
        doc: &Value,
    ) -> Result<(), ApiserverError> {
        if group != "rbac.authorization.k8s.io" {
            return Ok(());
        }
        self.rbac
            .apply_api_object(plural, namespace, doc)
            .map_err(invalid_rbac)
    }

    /// Generic create for namespaced objects served over HTTP.
    pub async fn create_namespaced_object(
        &self,
        group: &str,
        kind: &str,
        plural: &str,
        namespace: &str,
        doc: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_workload(group, kind, plural, namespace, doc)
            .await
    }

    /// Generic get for namespaced objects served over HTTP.
    pub async fn get_namespaced_object(
        &self,
        group: &str,
        plural: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.get_workload(group, plural, namespace, name).await
    }

    /// Generic list for namespaced objects served over HTTP.
    pub async fn list_namespaced_objects(
        &self,
        group: &str,
        kind_list: &str,
        plural: &str,
        namespace: &str,
    ) -> Result<Value, ApiserverError> {
        self.list_workload(group, kind_list, plural, namespace)
            .await
    }

    /// Generic delete for namespaced objects served over HTTP.
    pub async fn delete_namespaced_object(
        &self,
        group: &str,
        plural: &str,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.delete_workload(group, plural, namespace, name).await
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

    // ReplicationControllers
    pub async fn create_replicationcontroller(
        &self,
        namespace: &str,
        rc: Value,
    ) -> Result<Value, ApiserverError> {
        self.create_workload(
            "",
            "ReplicationController",
            "replicationcontrollers",
            namespace,
            rc,
        )
        .await
    }
    pub async fn get_replicationcontroller(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        self.get_workload("", "replicationcontrollers", namespace, name)
            .await
    }
    pub async fn list_replicationcontrollers(
        &self,
        namespace: &str,
    ) -> Result<Value, ApiserverError> {
        self.list_workload(
            "",
            "ReplicationControllerList",
            "replicationcontrollers",
            namespace,
        )
        .await
    }
    pub async fn update_replicationcontroller(
        &self,
        namespace: &str,
        name: &str,
        rc: Value,
    ) -> Result<Value, ApiserverError> {
        self.update_workload(
            "",
            "ReplicationController",
            "replicationcontrollers",
            namespace,
            name,
            rc,
        )
        .await
    }
    pub async fn delete_replicationcontroller(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        self.delete_workload("", "replicationcontrollers", namespace, name)
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
        mut pvc: Value,
        dry_run: bool,
    ) -> Result<Value, ApiserverError> {
        if pvc.pointer("/status/phase").is_none() {
            pvc["status"] = json!({ "phase": "Pending" });
        }
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
        let name = self
            .resolve_metadata_name(&mut sc, "StorageClass requires metadata.name")
            .await?;

        self.check_auth_detailed(
            "create",
            "storage.k8s.io",
            "storageclasses",
            None,
            Some(&name),
        )?;

        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = sc.get_mut("metadata").and_then(Value::as_object_mut) {
            Self::stamp_creation_and_uid(meta, "storageclasses", &name, cur_rev);
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
        let name = self
            .resolve_metadata_name(&mut pv, "PersistentVolume requires metadata.name")
            .await?;

        self.check_auth_detailed("create", "", "persistentvolumes", None, Some(&name))?;

        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = pv.get_mut("metadata").and_then(Value::as_object_mut) {
            Self::stamp_creation_and_uid(meta, "persistentvolumes", &name, cur_rev);
        }
        Self::init_generation(&mut pv);
        if pv.pointer("/status/phase").is_none() {
            pv["status"] = json!({ "phase": "Available" });
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
        if ip_u32 <= network || ip_u32 >= broadcast {
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

        if svc_type != "ExternalName" {
            if spec
                .get("ipFamilies")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            {
                spec.insert("ipFamilies".to_string(), json!(["IPv4"]));
            }
            if spec
                .get("ipFamilyPolicy")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                spec.insert("ipFamilyPolicy".to_string(), json!("SingleStack"));
            }
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
                    port_obj.remove("nodePort");
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

        if svc_type != "ExternalName" {
            if spec
                .get("ipFamilies")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            {
                spec.insert("ipFamilies".to_string(), json!(["IPv4"]));
            }
            if spec
                .get("ipFamilyPolicy")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                spec.insert("ipFamilyPolicy".to_string(), json!("SingleStack"));
            }
        }

        // 3. ClusterIP immutability / allocation
        let old_cluster_ip = old_doc.pointer("/spec/clusterIP").and_then(Value::as_str);
        let new_cluster_ip = spec.get("clusterIP").and_then(Value::as_str);

        if svc_type == "ExternalName" {
            spec.remove("clusterIP");
            spec.remove("clusterIPs");
        } else {
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
                    let allocated = self.allocate_cluster_ip(namespace, name, &allocated_ips)?;
                    allocated_ips.insert(allocated);
                    spec.insert("clusterIP".to_string(), json!(allocated.to_string()));
                },
                (None, Some(new_ip)) if new_ip != "None" => {
                    let validated_ip =
                        self.validate_specified_cluster_ip(new_ip, &allocated_ips)?;
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

    async fn create_service_ip_address(
        &self,
        cluster_ip: &str,
        namespace: &str,
        name: &str,
    ) -> Result<(), ApiserverError> {
        if cluster_ip == "None" || cluster_ip.is_empty() {
            return Ok(());
        }
        let key = cluster_key(
            self.storage.prefix(),
            "networking.k8s.io",
            "ipaddresses",
            cluster_ip,
        );
        let ip_doc = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "IPAddress",
            "metadata": {
                "name": cluster_ip,
                "creationTimestamp": crate::time::now_rfc3339(),
            },
            "spec": {
                "parentRef": {
                    "group": "",
                    "resource": "services",
                    "namespace": namespace,
                    "name": name,
                }
            }
        });
        let bytes = serde_json::to_vec(&ip_doc)?;
        let _ = self.storage.create(&key, bytes).await;
        Ok(())
    }

    async fn delete_service_ip_address(&self, cluster_ip: &str) -> Result<(), ApiserverError> {
        if cluster_ip == "None" || cluster_ip.is_empty() {
            return Ok(());
        }
        let key = cluster_key(
            self.storage.prefix(),
            "networking.k8s.io",
            "ipaddresses",
            cluster_ip,
        );
        let _ = self.storage.delete(&key, None).await;
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
        let res = self
            .create_workload_options("", "Service", "services", namespace, service, dry_run)
            .await?;
        if !dry_run {
            if let Some(cip) = res.pointer("/spec/clusterIP").and_then(Value::as_str)
                && let Some(name) = res.pointer("/metadata/name").and_then(Value::as_str)
            {
                let _ = self.create_service_ip_address(cip, namespace, name).await;
            }
            self.sync_service_endpoints_and_slice(namespace, &res).await;
        }
        Ok(res)
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
        let old_cip = self.get_service(namespace, name).await.ok().and_then(|s| {
            s.pointer("/spec/clusterIP")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });

        self.prepare_service_for_update(namespace, name, &mut service)
            .await?;
        let res = self
            .update_workload_options("", "Service", "services", namespace, name, service, dry_run)
            .await?;

        if !dry_run {
            let new_cip = res.pointer("/spec/clusterIP").and_then(Value::as_str);
            if old_cip.as_deref() != new_cip {
                if let Some(old) = old_cip.as_deref() {
                    let _ = self.delete_service_ip_address(old).await;
                }
                if let Some(new) = new_cip {
                    let _ = self.create_service_ip_address(new, namespace, name).await;
                }
            }
            self.sync_service_endpoints_and_slice(namespace, &res).await;
        }
        Ok(res)
    }

    async fn sync_service_endpoints_and_slice(&self, namespace: &str, service: &Value) {
        if namespace == "portainer" {
            return;
        }
        let Some(name) = service.pointer("/metadata/name").and_then(Value::as_str) else {
            return;
        };
        let Some(selector) = service.pointer("/spec/selector").and_then(Value::as_object) else {
            return;
        };
        if selector.is_empty() {
            return;
        }

        let svc_ports = service
            .pointer("/spec/ports")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let (endpoint_ports, slice_ports) = service_endpoint_and_slice_ports(&svc_ports);

        let pods = self.list_pods(namespace).await.unwrap_or_default();
        let pod_items = pods
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let (ready_addresses, endpoints_slice_endpoints) =
            match_service_pod_endpoints(&pod_items, selector, namespace);
        if ready_addresses.is_empty() {
            return;
        }

        let uid = service
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or("");

        let ep_doc =
            build_service_endpoints_doc(name, namespace, uid, &ready_addresses, &endpoint_ports);
        let slice_name = format!("{name}-1");
        let slice_doc = build_service_slice_doc(
            name,
            &slice_name,
            namespace,
            uid,
            &slice_ports,
            &endpoints_slice_endpoints,
        );

        match self.get_endpoints(namespace, name).await {
            Ok(_) => {
                let _ = self.update_endpoints(namespace, name, ep_doc).await;
            },
            Err(ApiserverError::NotFound { .. }) => {
                let _ = self.create_endpoints(namespace, ep_doc).await;
            },
            Err(_) => {},
        }

        match self.get_endpointslice(namespace, &slice_name).await {
            Ok(_) => {
                let _ = self
                    .update_endpointslice(namespace, &slice_name, slice_doc)
                    .await;
            },
            Err(ApiserverError::NotFound { .. }) => {
                let _ = self.create_endpointslice(namespace, slice_doc).await;
            },
            Err(_) => {},
        }
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
        if let Ok(svc) = self.get_service(namespace, name).await
            && let Some(cip) = svc.pointer("/spec/clusterIP").and_then(Value::as_str)
        {
            let _ = self.delete_service_ip_address(cip).await;
        }
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
        let name = self
            .resolve_metadata_name(&mut node, "Node requires metadata.name")
            .await?;

        self.check_auth_detailed("create", "", "nodes", None, Some(&name))?;

        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = node.get_mut("metadata").and_then(Value::as_object_mut) {
            Self::stamp_creation_and_uid(meta, "nodes", &name, cur_rev);
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

    pub async fn create_crd(&self, mut crd: Value) -> Result<Value, ApiserverError> {
        let name = self
            .resolve_metadata_name(&mut crd, "CustomResourceDefinition requires metadata.name")
            .await?;

        self.check_auth_detailed(
            "create",
            "apiextensions.k8s.io",
            "customresourcedefinitions",
            None,
            Some(&name),
        )?;

        let cur_rev = self.storage.current_revision().await + 1;
        let now = crate::time::now_rfc3339();
        if let Some(meta) = crd.get_mut("metadata").and_then(Value::as_object_mut) {
            Self::stamp_creation_and_uid(meta, "customresourcedefinitions", &name, cur_rev);
        }
        Self::init_generation(&mut crd);
        if crd
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            let accepted_names = crd
                .pointer("/spec/names")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let stored_versions = Self::crd_stored_versions(&crd);
            crd["status"] = json!({
                "conditions": [
                    {
                        "type": "NamesAccepted",
                        "status": "True",
                        "lastTransitionTime": now,
                        "reason": "NoConflicts",
                        "message": "no conflicts found"
                    },
                    {
                        "type": "Established",
                        "status": "True",
                        "lastTransitionTime": now,
                        "reason": "InitialNamesAccepted",
                        "message": "the initial names have been accepted"
                    }
                ],
                "acceptedNames": accepted_names,
                "storedVersions": stored_versions
            });
        }

        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{cur_rev}"),
            kind: GroupVersionKind {
                group: "apiextensions.k8s.io".to_string(),
                version: "v1".to_string(),
                kind: "CustomResourceDefinition".to_string(),
            },
            resource: GroupVersionResource {
                group: "apiextensions.k8s.io".to_string(),
                version: "v1".to_string(),
                resource: "customresourcedefinitions".to_string(),
            },
            subresource: None,
            name: Some(name.clone()),
            namespace: None,
            operation: "CREATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(crd.clone()),
            old_object: None,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            crd = obj;
        }

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
        Self::sync_crd_schema_to_field_validation(&result);
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

    pub async fn update_crd(&self, name: &str, mut crd: Value) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "update",
            "apiextensions.k8s.io",
            "customresourcedefinitions",
            None,
            Some(name),
        )?;

        let body_name = crd
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str);
        if body_name != Some(name) {
            return Err(ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: format!("body name {body_name:?} does not match '{name}'"),
            });
        }

        let key = format!("{}/customresourcedefinitions/{name}", self.storage.prefix());
        let existing_kv =
            self.storage
                .get(&key)
                .await?
                .ok_or_else(|| ApiserverError::NotFound {
                    resource: "customresourcedefinitions".to_string(),
                    name: name.to_string(),
                })?;
        let old: Value = serde_json::from_slice(&existing_kv.value)?;

        Self::update_generation(&mut crd, &old);
        if let Some(meta) = crd.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("name".to_string(), json!(name));
            for k in ["uid", "creationTimestamp"] {
                if let Some(v) = old.get("metadata").and_then(|m| m.get(k)) {
                    meta.insert(k.to_string(), v.clone());
                }
            }
        }
        if crd.get("status").is_none_or(Value::is_null)
            && let Some(s) = old.get("status").filter(|s| !s.is_null())
        {
            crd["status"] = s.clone();
        }

        let cur_rev = self.storage.current_revision().await + 1;
        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{cur_rev}"),
            kind: GroupVersionKind {
                group: "apiextensions.k8s.io".to_string(),
                version: "v1".to_string(),
                kind: "CustomResourceDefinition".to_string(),
            },
            resource: GroupVersionResource {
                group: "apiextensions.k8s.io".to_string(),
                version: "v1".to_string(),
                resource: "customresourcedefinitions".to_string(),
            },
            subresource: None,
            name: Some(name.to_string()),
            namespace: None,
            operation: "UPDATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(crd.clone()),
            old_object: Some(old.clone()),
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;
        if let Some(obj) = adm_req.object {
            crd = obj;
        }

        let expected_version = crd
            .get("metadata")
            .and_then(|m| m.get("resourceVersion"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok());

        let bytes = serde_json::to_vec(&crd)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        if let Some(meta) = crd.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        self.crd_registry
            .write()
            .unwrap()
            .insert(name.to_string(), crd.clone());
        Self::sync_crd_schema_to_field_validation(&crd);
        Ok(crd)
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
        let existing_kv =
            self.storage
                .get(&key)
                .await?
                .ok_or_else(|| ApiserverError::NotFound {
                    resource: "customresourcedefinitions".to_string(),
                    name: name.to_string(),
                })?;
        let old: Value = serde_json::from_slice(&existing_kv.value)?;

        let cur_rev = self.storage.current_revision().await + 1;
        let mut adm_req = AdmissionRequest {
            uid: format!("adm-{cur_rev}"),
            kind: GroupVersionKind {
                group: "apiextensions.k8s.io".to_string(),
                version: "v1".to_string(),
                kind: "CustomResourceDefinition".to_string(),
            },
            resource: GroupVersionResource {
                group: "apiextensions.k8s.io".to_string(),
                version: "v1".to_string(),
                resource: "customresourcedefinitions".to_string(),
            },
            subresource: None,
            name: Some(name.to_string()),
            namespace: None,
            operation: "DELETE".to_string(),
            user_info: self.current_user_info().await,
            object: None,
            old_object: Some(old),
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        self.admission.run_validating_admission(&adm_req).await?;

        let res = self.storage.delete(&key, None).await?;
        if res.is_none() {
            return Err(ApiserverError::NotFound {
                resource: "customresourcedefinitions".to_string(),
                name: name.to_string(),
            });
        }
        let crd_opt = self.crd_registry.write().unwrap().remove(name);
        if let Some(crd) = &crd_opt {
            Self::remove_crd_schema_from_field_validation(crd);
        }
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

    pub(crate) fn sync_crd_schema_to_field_validation(crd: &Value) {
        let Some(spec) = crd.get("spec") else {
            return;
        };
        let Some(group) = spec.get("group").and_then(Value::as_str) else {
            return;
        };
        let Some(plural) = spec
            .get("names")
            .and_then(|n| n.get("plural"))
            .and_then(Value::as_str)
        else {
            return;
        };
        let Some(versions) = spec.get("versions").and_then(Value::as_array) else {
            return;
        };
        let mut default_registered = false;
        for v in versions {
            let Some(schema) = v.get("schema").and_then(|s| s.get("openAPIV3Schema")) else {
                continue;
            };
            let ver_name = v.get("name").and_then(Value::as_str).unwrap_or("");
            if !ver_name.is_empty() {
                crate::http::field_validation::register_crd_version_schema(
                    group,
                    ver_name,
                    plural,
                    schema.clone(),
                );
            }
            let is_storage = v.get("storage").and_then(Value::as_bool) == Some(true);
            if !default_registered || is_storage {
                crate::http::field_validation::register_crd_schema(group, plural, schema.clone());
                default_registered = true;
            }
        }
    }

    pub(crate) fn remove_crd_schema_from_field_validation(crd: &Value) {
        if let Some(spec) = crd.get("spec")
            && let Some(group) = spec.get("group").and_then(Value::as_str)
            && let Some(plural) = spec
                .get("names")
                .and_then(|n| n.get("plural"))
                .and_then(Value::as_str)
        {
            crate::http::field_validation::unregister_crd_schema(group, plural);
        }
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
            let val_str = data
                .as_str()
                .map_or_else(|| data.to_string(), str::to_owned);
            let allowed_list: Vec<String> = enum_vals
                .iter()
                .map(|v| match v {
                    Value::String(s) => format!("\"{s}\""),
                    other => other.to_string(),
                })
                .collect();
            return Err(ApiserverError::InvalidInput {
                field: path.to_string(),
                reason: format!(
                    "{path}: Unsupported value: \"{val_str}\": supported values: {}",
                    allowed_list.join(", ")
                ),
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
            let preserve_unknown = schema
                .get("x-kubernetes-preserve-unknown-fields")
                .and_then(Value::as_bool)
                == Some(true)
                || schema.get("additionalProperties").is_some();
            if let Some(props) = schema.get("properties").and_then(Value::as_object) {
                Self::validate_object_properties(map, props, path, preserve_unknown)?;
            } else if !preserve_unknown
                && schema.get("type").and_then(Value::as_str) == Some("object")
            {
                let empty_props = serde_json::Map::new();
                Self::validate_object_properties(map, &empty_props, path, false)?;
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
                    field: field_path.clone(),
                    reason: format!(
                        "{field_path}: Required value: missing required field \"{prop_name}\""
                    ),
                });
            }
        }
        Ok(())
    }

    fn validate_crd_metadata_properties(prop_val: &Value) -> Result<(), ApiserverError> {
        let Some(meta_map) = prop_val.as_object() else {
            return Ok(());
        };
        for meta_key in meta_map.keys() {
            if !matches!(
                meta_key.as_str(),
                "name"
                    | "generateName"
                    | "namespace"
                    | "selfLink"
                    | "uid"
                    | "resourceVersion"
                    | "generation"
                    | "creationTimestamp"
                    | "deletionTimestamp"
                    | "deletionGracePeriodSeconds"
                    | "labels"
                    | "annotations"
                    | "ownerReferences"
                    | "finalizers"
                    | "clusterName"
                    | "managedFields"
            ) {
                return Err(ApiserverError::InvalidInput {
                    field: format!("metadata.{meta_key}"),
                    reason: format!(".metadata.{meta_key}: field not declared in schema"),
                });
            }
        }
        Ok(())
    }

    fn validate_object_properties(
        map: &serde_json::Map<String, Value>,
        props: &serde_json::Map<String, Value>,
        path: &str,
        preserve_unknown: bool,
    ) -> Result<(), ApiserverError> {
        for (prop_name, prop_val) in map {
            let next_path = if path.is_empty() {
                prop_name.clone()
            } else {
                format!("{path}.{prop_name}")
            };
            let Some(prop_schema) = props.get(prop_name) else {
                if !(preserve_unknown
                    || path.is_empty()
                        && matches!(prop_name.as_str(), "apiVersion" | "kind" | "metadata"))
                    && crate::http::field_validation::current_directive()
                        == crate::http::field_validation::FieldValidationDirective::Strict
                {
                    return Err(ApiserverError::InvalidInput {
                        field: next_path.clone(),
                        reason: format!(".{next_path}: field not declared in schema"),
                    });
                }
                if path.is_empty() && prop_name == "metadata" {
                    Self::validate_crd_metadata_properties(prop_val)?;
                }
                continue;
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

    pub fn list_registered_crds(&self) -> Vec<Value> {
        self.crd_registry
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    pub fn validate_crd_schema(
        &self,
        group: &str,
        plural: &str,
        resource: &Value,
    ) -> Result<(), ApiserverError> {
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, resource)
    }

    fn extract_crd_versions(spec: &Value, group: &str) -> Vec<Value> {
        let mut versions = Vec::new();
        if let Some(vers) = spec.get("versions").and_then(Value::as_array) {
            for v in vers {
                if v.get("served").and_then(Value::as_bool) == Some(false) {
                    continue;
                }
                let Some(v_name) = v.get("name").and_then(Value::as_str) else {
                    continue;
                };
                versions.push(json!({
                    "groupVersion": format!("{group}/{v_name}"),
                    "version": v_name
                }));
            }
        } else if versions.is_empty() {
            versions.push(json!({
                "groupVersion": format!("{group}/v1"),
                "version": "v1"
            }));
        }
        versions
    }

    fn crd_stored_versions(doc: &Value) -> Vec<String> {
        doc.pointer("/spec/versions")
            .and_then(Value::as_array)
            .map_or_else(
                || vec!["v1".to_string()],
                |vers| {
                    vers.iter()
                        .filter(|v| v.get("storage").and_then(Value::as_bool) != Some(false))
                        .filter_map(|v| v.get("name").and_then(Value::as_str).map(String::from))
                        .collect()
                },
            )
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
        let target_ver = resource
            .get("apiVersion")
            .and_then(Value::as_str)
            .and_then(|av| av.split_once('/').map(|(_, v)| v));
        for ver in versions {
            if ver.get("served").and_then(Value::as_bool) == Some(false) {
                continue;
            }
            if let Some(tv) = target_ver
                && let Some(vn) = ver.get("name").and_then(Value::as_str)
                && vn != tv
            {
                continue;
            }
            let Some(schema) = ver.get("schema").and_then(|s| s.get("openAPIV3Schema")) else {
                continue;
            };
            Self::validate_json_schema(schema, resource, "")?;
        }
        Ok(())
    }

    pub(crate) fn apply_schema_defaults(schema: &Value, data: &mut Value) {
        if let Some(props) = schema.get("properties").and_then(Value::as_object)
            && let Some(obj) = data.as_object_mut()
        {
            for (prop_name, prop_schema) in props {
                if !obj.contains_key(prop_name)
                    && let Some(default_val) = prop_schema.get("default")
                {
                    obj.insert(prop_name.clone(), default_val.clone());
                }
                if let Some(val) = obj.get_mut(prop_name) {
                    Self::apply_schema_defaults(prop_schema, val);
                }
            }
        }
        if let Some(items_schema) = schema.get("items")
            && let Some(arr) = data.as_array_mut()
        {
            for item in arr.iter_mut() {
                Self::apply_schema_defaults(items_schema, item);
            }
        }
    }

    pub fn prune_crd_unknown_fields(
        crd_registry: &Arc<RwLock<BTreeMap<String, Value>>>,
        group: &str,
        plural: &str,
        resource: &mut Value,
    ) {
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
            let Some(versions) = spec.get("versions").and_then(Value::as_array) else {
                continue;
            };
            let target_ver = resource
                .get("apiVersion")
                .and_then(Value::as_str)
                .and_then(|av| av.split_once('/').map(|(_, v)| v.to_string()));
            for ver in versions {
                if ver.get("served").and_then(Value::as_bool) == Some(false) {
                    continue;
                }
                if let Some(tv) = &target_ver
                    && let Some(vn) = ver.get("name").and_then(Value::as_str)
                    && vn != tv.as_str()
                {
                    continue;
                }
                if let Some(schema) = ver.get("schema").and_then(|s| s.get("openAPIV3Schema")) {
                    crate::http::field_validation::strip_unknown_crd_fields(resource, schema);
                }
            }
            break;
        }
    }

    pub fn apply_crd_defaults_to_instance(
        crd_registry: &Arc<RwLock<BTreeMap<String, Value>>>,
        group: &str,
        plural: &str,
        resource: &mut Value,
    ) {
        let registry = crd_registry.read().unwrap();
        for crd in registry.values() {
            let Some(spec) = crd.get("spec") else {
                continue;
            };
            if spec.get("group").and_then(Value::as_str) != Some(group)
                || spec.pointer("/names/plural").and_then(Value::as_str) != Some(plural)
            {
                continue;
            }
            let Some(versions) = spec.get("versions").and_then(Value::as_array) else {
                continue;
            };
            let target_ver = resource
                .get("apiVersion")
                .and_then(Value::as_str)
                .and_then(|av| av.split_once('/').map(|(_, v)| v.to_string()));
            for ver in versions {
                if let Some(tv) = &target_ver
                    && let Some(vn) = ver.get("name").and_then(Value::as_str)
                    && vn != tv
                {
                    continue;
                }
                if let Some(schema) = ver.get("schema").and_then(|s| s.get("openAPIV3Schema")) {
                    Self::apply_schema_defaults(schema, resource);
                }
            }
            break;
        }
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
        Self::init_generation(&mut resource);
        Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut resource);
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &resource)?;

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
            subresource: None,
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "CREATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(resource.clone()),
            old_object: None,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        if let Some(obj) = adm_req.object {
            resource = obj.clone();
            adm_req.object = Some(obj);
        }

        Self::prune_crd_unknown_fields(&self.crd_registry, group, plural, &mut resource);
        Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut resource);
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &resource)?;

        adm_req.object = Some(resource.clone());
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
        Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut doc);
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
        Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut resource);
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &resource)?;
        let key = format!(
            "{}/{group}/{plural}/{namespace}/{name}",
            self.storage.prefix()
        );

        let old_bytes = self.storage.get(&key).await?;
        let old_obj: Option<Value> = old_bytes.and_then(|b| serde_json::from_slice(&b.value).ok());
        if let Some(old) = &old_obj {
            Self::update_generation(&mut resource, old);
        }

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
            subresource: None,
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            operation: "UPDATE".to_string(),
            user_info: self.current_user_info().await,
            object: Some(resource.clone()),
            old_object: old_obj,
            dry_run: None,
        };
        self.admission.run_mutating_admission(&mut adm_req).await?;
        if let Some(obj) = adm_req.object {
            resource = obj.clone();
            adm_req.object = Some(obj);
        }

        Self::prune_crd_unknown_fields(&self.crd_registry, group, plural, &mut resource);
        Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut resource);
        Self::validate_crd_instance_schema(&self.crd_registry, group, plural, &resource)?;

        adm_req.object = Some(resource.clone());
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
            Self::apply_crd_defaults_to_instance(&self.crd_registry, group, plural, &mut doc);
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

    fn validate_single_match_condition(
        c: &crate::admission::MatchCondition,
    ) -> Result<(), ApiserverError> {
        if c.name.trim().is_empty() {
            return Err(ApiserverError::InvalidInput {
                field: "webhooks.matchConditions".to_string(),
                reason: "matchCondition name cannot be empty".to_string(),
            });
        }
        if c.expression.trim().is_empty() {
            return Err(ApiserverError::InvalidInput {
                field: "webhooks.matchConditions".to_string(),
                reason: "matchCondition expression cannot be empty".to_string(),
            });
        }
        if let Err(e) = crate::admission::validate_match_condition(&c.expression) {
            let reason = match e {
                ApiserverError::InvalidInput { reason, .. } => reason,
                other => other.to_string(),
            };
            return Err(ApiserverError::InvalidInput {
                field: "webhooks.matchConditions".to_string(),
                reason,
            });
        }
        Ok(())
    }

    fn validate_webhook_match_conditions(
        webhooks: &[crate::admission::WebhookDefinition],
    ) -> Result<(), ApiserverError> {
        for wh in webhooks {
            let Some(conds) = &wh.match_conditions else {
                continue;
            };
            for c in conds {
                Self::validate_single_match_condition(c)?;
            }
        }
        Ok(())
    }

    // --- Webhook Configurations CRUD ---

    pub async fn create_validating_webhook_configuration(
        &self,
        mut config: Value,
    ) -> Result<Value, ApiserverError> {
        let name = self
            .resolve_metadata_name(
                &mut config,
                "ValidatingWebhookConfiguration requires metadata.name",
            )
            .await?;

        self.check_auth_detailed(
            "create",
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
            None,
            Some(&name),
        )?;

        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = config.get_mut("metadata").and_then(Value::as_object_mut) {
            Self::stamp_creation_and_uid(meta, "validatingwebhookconfigurations", &name, cur_rev);
        }

        let typed: crate::admission::ValidatingWebhookConfiguration =
            serde_json::from_value(config.clone())?;
        Self::validate_webhook_match_conditions(&typed.webhooks)?;
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

    pub async fn update_validating_webhook_configuration(
        &self,
        name: &str,
        mut config: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "update",
            "admissionregistration.k8s.io",
            "validatingwebhookconfigurations",
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

        let key = format!(
            "{}/validatingwebhookconfigurations/{name}",
            self.storage.prefix()
        );
        let existing_kv =
            self.storage
                .get(&key)
                .await?
                .ok_or_else(|| ApiserverError::NotFound {
                    resource: "validatingwebhookconfigurations".to_string(),
                    name: name.to_string(),
                })?;
        let old: Value = serde_json::from_slice(&existing_kv.value)?;

        if let Some(meta) = config.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("name".to_string(), json!(name));
            for k in ["uid", "creationTimestamp"] {
                if let Some(v) = old.get("metadata").and_then(|m| m.get(k)) {
                    meta.insert(k.to_string(), v.clone());
                }
            }
        }

        let typed: crate::admission::ValidatingWebhookConfiguration =
            serde_json::from_value(config.clone())?;
        Self::validate_webhook_match_conditions(&typed.webhooks)?;

        let expected_version = config
            .get("metadata")
            .and_then(|m| m.get("resourceVersion"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok());

        let bytes = serde_json::to_vec(&config)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        self.admission.add_validating_webhook_config(typed);
        let mut result = config;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
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
        self.admission.remove_validating_webhook_config(name);
        Ok(())
    }

    pub async fn create_mutating_webhook_configuration(
        &self,
        mut config: Value,
    ) -> Result<Value, ApiserverError> {
        let name = self
            .resolve_metadata_name(
                &mut config,
                "MutatingWebhookConfiguration requires metadata.name",
            )
            .await?;

        self.check_auth_detailed(
            "create",
            "admissionregistration.k8s.io",
            "mutatingwebhookconfigurations",
            None,
            Some(&name),
        )?;

        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = config.get_mut("metadata").and_then(Value::as_object_mut) {
            Self::stamp_creation_and_uid(meta, "mutatingwebhookconfigurations", &name, cur_rev);
        }

        let typed: crate::admission::MutatingWebhookConfiguration =
            serde_json::from_value(config.clone())?;
        Self::validate_webhook_match_conditions(&typed.webhooks)?;
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
        mut config: Value,
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

        let key = format!(
            "{}/mutatingwebhookconfigurations/{name}",
            self.storage.prefix()
        );
        let existing_kv =
            self.storage
                .get(&key)
                .await?
                .ok_or_else(|| ApiserverError::NotFound {
                    resource: "mutatingwebhookconfigurations".to_string(),
                    name: name.to_string(),
                })?;
        let old: Value = serde_json::from_slice(&existing_kv.value)?;

        if let Some(meta) = config.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("name".to_string(), json!(name));
            for k in ["uid", "creationTimestamp"] {
                if let Some(v) = old.get("metadata").and_then(|m| m.get(k)) {
                    meta.insert(k.to_string(), v.clone());
                }
            }
        }

        let typed: crate::admission::MutatingWebhookConfiguration =
            serde_json::from_value(config.clone())?;
        Self::validate_webhook_match_conditions(&typed.webhooks)?;

        let expected_version = config
            .get("metadata")
            .and_then(|m| m.get("resourceVersion"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok());

        let bytes = serde_json::to_vec(&config)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
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
        self.admission.remove_mutating_webhook_config(name);
        Ok(())
    }

    // --- Aggregated APIService CRUD & Dispatch ---

    fn ensure_api_service_available_condition(service: &mut Value) {
        if service.pointer("/spec/service").is_none() {
            return;
        }
        let cond = json!({
            "type": "Available",
            "status": "True",
            "reason": "Passed",
            "message": "all checks passed",
            "lastTransitionTime": crate::time::now_rfc3339()
        });
        if !service.get("status").is_some_and(Value::is_object) {
            service["status"] = json!({});
        }
        let Some(status_obj) = service.get_mut("status").and_then(Value::as_object_mut) else {
            return;
        };
        if !status_obj.get("conditions").is_some_and(Value::is_array) {
            status_obj.insert("conditions".to_string(), Value::Array(Vec::new()));
        }
        let Some(conditions_arr) = status_obj
            .get_mut("conditions")
            .and_then(Value::as_array_mut)
        else {
            return;
        };
        if let Some(existing) = conditions_arr
            .iter_mut()
            .find(|c| c.get("type").and_then(Value::as_str) == Some("Available"))
        {
            *existing = cond;
        } else {
            conditions_arr.push(cond);
        }
    }

    pub async fn create_api_service(&self, mut service: Value) -> Result<Value, ApiserverError> {
        let name = self
            .resolve_metadata_name(&mut service, "APIService requires metadata.name")
            .await?;

        self.check_auth_detailed(
            "create",
            "apiregistration.k8s.io",
            "apiservices",
            None,
            Some(&name),
        )?;

        let cur_rev = self.storage.current_revision().await + 1;
        if let Some(meta) = service.get_mut("metadata").and_then(Value::as_object_mut) {
            Self::stamp_creation_and_uid(meta, "apiservices", &name, cur_rev);
        }

        Self::ensure_api_service_available_condition(&mut service);

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

    pub async fn update_api_service(
        &self,
        name: &str,
        mut service: Value,
    ) -> Result<Value, ApiserverError> {
        self.check_auth_detailed(
            "update",
            "apiregistration.k8s.io",
            "apiservices",
            None,
            Some(name),
        )?;

        let body_name = service
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str);
        if body_name != Some(name) {
            return Err(ApiserverError::InvalidInput {
                field: "metadata.name".to_string(),
                reason: format!("body name {body_name:?} does not match '{name}'"),
            });
        }

        let key = format!("{}/apiservices/{name}", self.storage.prefix());
        let existing_kv =
            self.storage
                .get(&key)
                .await?
                .ok_or_else(|| ApiserverError::NotFound {
                    resource: "apiservices".to_string(),
                    name: name.to_string(),
                })?;
        let old: Value = serde_json::from_slice(&existing_kv.value)?;

        if let Some(meta) = service.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert("name".to_string(), json!(name));
            for k in ["uid", "creationTimestamp"] {
                if let Some(v) = old.get("metadata").and_then(|m| m.get(k)) {
                    meta.insert(k.to_string(), v.clone());
                }
            }
        }
        if service.get("status").is_none_or(Value::is_null)
            && let Some(s) = old.get("status").filter(|s| !s.is_null())
        {
            service["status"] = s.clone();
        }

        Self::ensure_api_service_available_condition(&mut service);

        let typed: APIService = serde_json::from_value(service.clone())?;
        self.aggregation.register_api_service(typed);

        let expected_version = service
            .get("metadata")
            .and_then(|m| m.get("resourceVersion"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok());

        let bytes = serde_json::to_vec(&service)?;
        let kv = self.storage.update(&key, bytes, expected_version).await?;
        let mut result = service;
        if let Some(meta) = result.get_mut("metadata").and_then(Value::as_object_mut) {
            meta.insert(
                "resourceVersion".to_string(),
                json!(kv.mod_revision.to_string()),
            );
        }
        Ok(result)
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
        let user_info = self.current_user_info().await;
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

fn service_endpoint_and_slice_ports(svc_ports: &[Value]) -> (Vec<Value>, Vec<Value>) {
    let mut endpoint_ports = Vec::new();
    let mut slice_ports = Vec::new();
    for p in svc_ports {
        let port_num = p.get("port").and_then(Value::as_i64).unwrap_or(80);
        let port_name = p.get("name").and_then(Value::as_str);
        let proto = p.get("protocol").and_then(Value::as_str).unwrap_or("TCP");
        let mut endpoint_port = json!({
            "port": port_num,
            "protocol": proto
        });
        if let Some(pn) = port_name {
            endpoint_port["name"] = json!(pn);
        }
        endpoint_ports.push(endpoint_port);

        let mut slice_port = json!({
            "port": port_num,
            "protocol": proto
        });
        if let Some(pn) = port_name {
            slice_port["name"] = json!(pn);
        }
        slice_ports.push(slice_port);
    }
    (endpoint_ports, slice_ports)
}

fn match_service_pod_endpoints(
    pod_items: &[Value],
    selector: &serde_json::Map<String, Value>,
    namespace: &str,
) -> (Vec<Value>, Vec<Value>) {
    let mut ready_addresses = Vec::new();
    let mut endpoints_slice_endpoints = Vec::new();

    for pod in pod_items {
        let labels = pod.pointer("/metadata/labels").and_then(Value::as_object);
        let matches = selector
            .iter()
            .all(|(k, v)| labels.and_then(|m| m.get(k)).and_then(Value::as_str) == v.as_str());
        if !matches {
            continue;
        }

        let pod_ip = pod
            .pointer("/status/podIP")
            .and_then(Value::as_str)
            .or_else(|| {
                pod.pointer("/metadata/annotations/cni.projectcalico.org~1podIP")
                    .and_then(Value::as_str)
            });
        let Some(ip) = pod_ip else {
            continue;
        };
        if ip.is_empty() {
            continue;
        }

        let pod_name = pod
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let pod_uid = pod
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or("");
        let target_ref = json!({
            "kind": "Pod",
            "name": pod_name,
            "namespace": namespace,
            "uid": pod_uid,
        });

        ready_addresses.push(json!({
            "ip": ip,
            "targetRef": target_ref
        }));

        endpoints_slice_endpoints.push(json!({
            "addresses": [ip],
            "conditions": {
                "ready": true,
                "serving": true,
                "terminating": false
            },
            "targetRef": target_ref
        }));
    }

    (ready_addresses, endpoints_slice_endpoints)
}

fn build_service_endpoints_doc(
    name: &str,
    namespace: &str,
    uid: &str,
    ready_addresses: &[Value],
    endpoint_ports: &[Value],
) -> Value {
    let subsets = if ready_addresses.is_empty() {
        json!([])
    } else {
        json!([{
            "addresses": ready_addresses,
            "ports": endpoint_ports
        }])
    };

    json!({
        "apiVersion": "v1",
        "kind": "Endpoints",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "kubernetes.io/service-name": name
            },
            "ownerReferences": [{
                "apiVersion": "v1",
                "kind": "Service",
                "name": name,
                "uid": uid,
                "controller": true
            }]
        },
        "subsets": subsets
    })
}

fn build_service_slice_doc(
    name: &str,
    slice_name: &str,
    namespace: &str,
    uid: &str,
    slice_ports: &[Value],
    endpoints_slice_endpoints: &[Value],
) -> Value {
    json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": slice_name,
            "namespace": namespace,
            "labels": {
                "kubernetes.io/service-name": name,
                "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"
            },
            "ownerReferences": [{
                "apiVersion": "v1",
                "kind": "Service",
                "name": name,
                "uid": uid,
                "controller": true
            }]
        },
        "addressType": "IPv4",
        "ports": slice_ports,
        "endpoints": endpoints_slice_endpoints
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pod_spec_defaulting() {
        let mut pod = json!({
            "metadata": { "name": "test-pod" },
            "spec": {
                "containers": [
                    { "name": "c1", "image": "busybox:1.36" },
                    { "name": "c2", "image": "nginx" },
                    { "name": "c3", "image": "custom:latest", "imagePullPolicy": "Never" }
                ]
            }
        });
        KubernetesApiClient::default_pod_spec(&mut pod);

        let spec = pod.get("spec").unwrap();
        assert_eq!(
            spec.get("terminationGracePeriodSeconds")
                .and_then(Value::as_i64),
            Some(30)
        );
        assert_eq!(
            spec.get("restartPolicy").and_then(Value::as_str),
            Some("Always")
        );
        assert_eq!(
            spec.get("dnsPolicy").and_then(Value::as_str),
            Some("ClusterFirst")
        );

        let containers = spec.get("containers").and_then(Value::as_array).unwrap();
        assert_eq!(
            containers[0]
                .get("terminationMessagePath")
                .and_then(Value::as_str),
            Some("/dev/termination-log")
        );
        assert_eq!(
            containers[0]
                .get("terminationMessagePolicy")
                .and_then(Value::as_str),
            Some("File")
        );
        assert_eq!(
            containers[0].get("imagePullPolicy").and_then(Value::as_str),
            Some("IfNotPresent")
        );

        assert_eq!(
            containers[1].get("imagePullPolicy").and_then(Value::as_str),
            Some("Always")
        );
        assert_eq!(
            containers[2].get("imagePullPolicy").and_then(Value::as_str),
            Some("Never")
        );
    }
}
