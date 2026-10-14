use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Subject {
    User { name: String },
    Group { name: String },
    ServiceAccount { namespace: String, name: String },
}

impl Subject {
    #[must_use]
    pub fn matches_user_or_group(&self, username: &str, groups: &[String]) -> bool {
        match self {
            Subject::User { name } => name == username,
            Subject::Group { name } => groups.iter().any(|g| g == name),
            Subject::ServiceAccount { namespace, name } => {
                let sa_user = format!("system:serviceaccount:{namespace}:{name}");
                sa_user == username
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub verbs: Vec<String>,
    pub api_groups: Vec<String>,
    pub resources: Vec<String>,
    #[serde(default)]
    pub resource_names: Vec<String>,
    #[serde(default)]
    pub non_resource_urls: Vec<String>,
}

impl PolicyRule {
    #[must_use]
    pub fn matches(
        &self,
        verb: &str,
        api_group: &str,
        resource: &str,
        resource_name: Option<&str>,
    ) -> bool {
        let verb_match = self.verbs.iter().any(|v| v == "*" || v == verb);
        if !verb_match {
            return false;
        }

        let group_match = self.api_groups.iter().any(|g| g == "*" || g == api_group);
        if !group_match {
            return false;
        }

        let resource_match = self.resources.iter().any(|r| r == "*" || r == resource);
        if !resource_match {
            return false;
        }

        if !self.resource_names.is_empty() {
            match resource_name {
                Some(r_name)
                    if self
                        .resource_names
                        .iter()
                        .any(|rn| rn == "*" || rn == r_name) => {},
                _ => return false,
            }
        }

        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterRole {
    pub name: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterRoleBinding {
    pub name: String,
    pub role_ref: String,
    pub subjects: Vec<Subject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub namespace: String,
    pub name: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleBinding {
    pub namespace: String,
    pub name: String,
    pub role_ref: String,
    pub subjects: Vec<Subject>,
}

#[derive(Clone, Debug)]
pub struct AuthzRequest<'a> {
    pub username: &'a str,
    pub groups: &'a [String],
    pub verb: &'a str,
    pub api_group: &'a str,
    pub resource: &'a str,
    pub namespace: Option<&'a str>,
    pub resource_name: Option<&'a str>,
}

#[derive(Debug)]
pub struct RbacAuthorizer {
    cluster_roles: RwLock<HashMap<String, ClusterRole>>,
    cluster_role_bindings: RwLock<HashMap<String, ClusterRoleBinding>>,
    roles: RwLock<HashMap<(String, String), Role>>,
    role_bindings: RwLock<HashMap<(String, String), RoleBinding>>,
}

impl Default for RbacAuthorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl RbacAuthorizer {
    #[must_use]
    pub fn new() -> Self {
        let authorizer = Self {
            cluster_roles: RwLock::new(HashMap::new()),
            cluster_role_bindings: RwLock::new(HashMap::new()),
            roles: RwLock::new(HashMap::new()),
            role_bindings: RwLock::new(HashMap::new()),
        };
        authorizer.seed_bootstrap_roles();
        authorizer
    }

    fn seed_bootstrap_roles(&self) {
        self.seed_core_cluster_roles();
        self.seed_system_cluster_roles();
        self.seed_bootstrap_bindings();
    }

    fn seed_core_cluster_roles(&self) {
        self.add_cluster_role(ClusterRole {
            name: "cluster-admin".to_string(),
            rules: vec![PolicyRule {
                verbs: vec!["*".to_string()],
                api_groups: vec!["*".to_string()],
                resources: vec!["*".to_string()],
                resource_names: Vec::new(),
                non_resource_urls: vec!["*".to_string()],
            }],
        });

        self.add_cluster_role(ClusterRole {
            name: "view".to_string(),
            rules: vec![PolicyRule {
                verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                api_groups: vec![String::new(), "apps".to_string()],
                resources: vec![
                    "configmaps".to_string(),
                    "namespaces".to_string(),
                    "pods".to_string(),
                    "pods/log".to_string(),
                    "pods/status".to_string(),
                    "services".to_string(),
                ],
                resource_names: Vec::new(),
                non_resource_urls: Vec::new(),
            }],
        });

        self.add_cluster_role(ClusterRole {
            name: "edit".to_string(),
            rules: vec![PolicyRule {
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "create".to_string(),
                    "update".to_string(),
                    "patch".to_string(),
                    "delete".to_string(),
                ],
                api_groups: vec![String::new(), "apps".to_string()],
                resources: vec![
                    "configmaps".to_string(),
                    "secrets".to_string(),
                    "pods".to_string(),
                    "pods/exec".to_string(),
                    "pods/log".to_string(),
                    "pods/status".to_string(),
                    "services".to_string(),
                ],
                resource_names: Vec::new(),
                non_resource_urls: Vec::new(),
            }],
        });
    }

    #[allow(clippy::too_many_lines)]
    fn seed_system_cluster_roles(&self) {
        self.add_cluster_role(ClusterRole {
            name: "system:kube-controller-manager".to_string(),
            rules: vec![PolicyRule {
                verbs: vec!["*".to_string()],
                api_groups: vec!["*".to_string()],
                resources: vec!["*".to_string()],
                resource_names: Vec::new(),
                non_resource_urls: vec!["*".to_string()],
            }],
        });

        self.add_cluster_role(ClusterRole {
            name: "system:kube-scheduler".to_string(),
            rules: vec![PolicyRule {
                verbs: vec![
                    "get".to_string(),
                    "list".to_string(),
                    "watch".to_string(),
                    "create".to_string(),
                    "update".to_string(),
                ],
                api_groups: vec![String::new()],
                resources: vec![
                    "pods".to_string(),
                    "bindings".to_string(),
                    "nodes".to_string(),
                ],
                resource_names: Vec::new(),
                non_resource_urls: Vec::new(),
            }],
        });

        self.add_cluster_role(ClusterRole {
            name: "system:kube-proxy".to_string(),
            rules: vec![
                PolicyRule {
                    verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                    api_groups: vec![String::new()],
                    resources: vec![
                        "services".to_string(),
                        "endpoints".to_string(),
                        "nodes".to_string(),
                    ],
                    resource_names: Vec::new(),
                    non_resource_urls: Vec::new(),
                },
                PolicyRule {
                    verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                    api_groups: vec!["discovery.k8s.io".to_string()],
                    resources: vec!["endpointslices".to_string()],
                    resource_names: Vec::new(),
                    non_resource_urls: Vec::new(),
                },
            ],
        });

        self.add_cluster_role(ClusterRole {
            name: "system:node".to_string(),
            rules: vec![
                PolicyRule {
                    verbs: vec![
                        "get".to_string(),
                        "list".to_string(),
                        "watch".to_string(),
                        "create".to_string(),
                        "update".to_string(),
                        "patch".to_string(),
                        "delete".to_string(),
                    ],
                    api_groups: vec![String::new()],
                    resources: vec![
                        "nodes".to_string(),
                        "nodes/status".to_string(),
                        "pods".to_string(),
                        "pods/status".to_string(),
                        "configmaps".to_string(),
                    ],
                    resource_names: Vec::new(),
                    non_resource_urls: Vec::new(),
                },
                PolicyRule {
                    verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                    api_groups: vec![String::new()],
                    resources: vec!["services".to_string()],
                    resource_names: Vec::new(),
                    non_resource_urls: Vec::new(),
                },
                PolicyRule {
                    verbs: vec!["get".to_string()],
                    api_groups: vec![String::new()],
                    resources: vec![
                        "secrets".to_string(),
                        "persistentvolumeclaims".to_string(),
                        "persistentvolumes".to_string(),
                    ],
                    resource_names: Vec::new(),
                    non_resource_urls: Vec::new(),
                },
                PolicyRule {
                    verbs: vec![
                        "get".to_string(),
                        "list".to_string(),
                        "watch".to_string(),
                        "create".to_string(),
                        "update".to_string(),
                        "patch".to_string(),
                    ],
                    api_groups: vec!["coordination.k8s.io".to_string()],
                    resources: vec!["leases".to_string()],
                    resource_names: Vec::new(),
                    non_resource_urls: Vec::new(),
                },
            ],
        });
    }

    fn seed_bootstrap_bindings(&self) {
        self.add_cluster_role_binding(ClusterRoleBinding {
            name: "cluster-admin".to_string(),
            role_ref: "cluster-admin".to_string(),
            subjects: vec![Subject::Group {
                name: "system:masters".to_string(),
            }],
        });

        self.add_cluster_role_binding(ClusterRoleBinding {
            name: "system:kube-controller-manager".to_string(),
            role_ref: "system:kube-controller-manager".to_string(),
            subjects: vec![Subject::User {
                name: "system:kube-controller-manager".to_string(),
            }],
        });

        self.add_cluster_role_binding(ClusterRoleBinding {
            name: "system:kube-scheduler".to_string(),
            role_ref: "system:kube-scheduler".to_string(),
            subjects: vec![Subject::User {
                name: "system:kube-scheduler".to_string(),
            }],
        });

        self.add_cluster_role_binding(ClusterRoleBinding {
            name: "system:kube-proxy".to_string(),
            role_ref: "system:kube-proxy".to_string(),
            subjects: vec![Subject::User {
                name: "system:kube-proxy".to_string(),
            }],
        });

        self.add_cluster_role_binding(ClusterRoleBinding {
            name: "system:node".to_string(),
            role_ref: "system:node".to_string(),
            subjects: vec![Subject::Group {
                name: "system:nodes".to_string(),
            }],
        });
    }

    pub fn add_cluster_role(&self, role: ClusterRole) {
        let mut map = self.cluster_roles.write().unwrap();
        map.insert(role.name.clone(), role);
    }

    pub fn remove_cluster_role(&self, name: &str) {
        self.cluster_roles.write().unwrap().remove(name);
    }

    #[must_use]
    pub fn get_cluster_role(&self, name: &str) -> Option<ClusterRole> {
        let map = self.cluster_roles.read().unwrap();
        map.get(name).cloned()
    }

    pub fn add_cluster_role_binding(&self, binding: ClusterRoleBinding) {
        let mut map = self.cluster_role_bindings.write().unwrap();
        map.insert(binding.name.clone(), binding);
    }

    pub fn remove_cluster_role_binding(&self, name: &str) {
        self.cluster_role_bindings.write().unwrap().remove(name);
    }

    #[must_use]
    pub fn get_cluster_role_binding(&self, name: &str) -> Option<ClusterRoleBinding> {
        let map = self.cluster_role_bindings.read().unwrap();
        map.get(name).cloned()
    }

    pub fn add_role(&self, role: Role) {
        let mut map = self.roles.write().unwrap();
        map.insert((role.namespace.clone(), role.name.clone()), role);
    }

    pub fn remove_role(&self, namespace: &str, name: &str) {
        self.roles
            .write()
            .unwrap()
            .remove(&(namespace.to_string(), name.to_string()));
    }

    #[must_use]
    pub fn get_role(&self, namespace: &str, name: &str) -> Option<Role> {
        let map = self.roles.read().unwrap();
        map.get(&(namespace.to_string(), name.to_string())).cloned()
    }

    pub fn add_role_binding(&self, binding: RoleBinding) {
        let mut map = self.role_bindings.write().unwrap();
        map.insert((binding.namespace.clone(), binding.name.clone()), binding);
    }

    pub fn remove_role_binding(&self, namespace: &str, name: &str) {
        self.role_bindings
            .write()
            .unwrap()
            .remove(&(namespace.to_string(), name.to_string()));
    }

    /// Installs one Kubernetes RBAC object, as stored by the HTTP API, into the authorizer.
    pub fn apply_api_object(
        &self,
        plural: &str,
        namespace: Option<&str>,
        doc: &Value,
    ) -> Result<(), String> {
        match plural {
            "clusterroles" => self.add_cluster_role(cluster_role_from_api(doc)?),
            "clusterrolebindings" => {
                self.add_cluster_role_binding(cluster_role_binding_from_api(doc)?);
            },
            "roles" => {
                let namespace = object_namespace(namespace, doc)?;
                self.add_role(role_from_api(namespace, doc)?);
            },
            "rolebindings" => {
                let namespace = object_namespace(namespace, doc)?;
                self.add_role_binding(role_binding_from_api(namespace, doc)?);
            },
            _ => {},
        }
        Ok(())
    }

    /// Drops one Kubernetes RBAC object from the authorizer after it is deleted.
    pub fn forget_api_object(&self, plural: &str, namespace: Option<&str>, name: &str) {
        match plural {
            "clusterroles" => self.remove_cluster_role(name),
            "clusterrolebindings" => self.remove_cluster_role_binding(name),
            "roles" => {
                if let Some(namespace) = namespace {
                    self.remove_role(namespace, name);
                }
            },
            "rolebindings" => {
                if let Some(namespace) = namespace {
                    self.remove_role_binding(namespace, name);
                }
            },
            _ => {},
        }
    }

    #[must_use]
    pub fn get_role_binding(&self, namespace: &str, name: &str) -> Option<RoleBinding> {
        let map = self.role_bindings.read().unwrap();
        map.get(&(namespace.to_string(), name.to_string())).cloned()
    }

    #[must_use]
    pub fn authorize(&self, req: &AuthzRequest<'_>) -> bool {
        // 1. Group system:masters always has root cluster-admin access
        if req.groups.iter().any(|g| g == "system:masters") {
            return true;
        }

        // 2. Evaluate ClusterRoleBindings
        let crb = self.cluster_role_bindings.read().unwrap();
        let cr = self.cluster_roles.read().unwrap();
        if crb
            .values()
            .any(|binding| evaluate_cluster_role_binding(binding, &cr, req))
        {
            return true;
        }

        // 3. Evaluate namespace RoleBindings
        if let Some(ns) = req.namespace {
            let rb = self.role_bindings.read().unwrap();
            let r = self.roles.read().unwrap();
            if rb.values().any(|binding| {
                binding.namespace == ns && evaluate_role_binding(binding, &r, &cr, req)
            }) {
                return true;
            }
        }

        false
    }
}

fn object_name(doc: &Value) -> Result<&str, String> {
    doc.pointer("/metadata/name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "metadata.name is required".to_string())
}

fn object_namespace<'a>(namespace: Option<&'a str>, doc: &'a Value) -> Result<&'a str, String> {
    namespace
        .filter(|value| !value.is_empty())
        .or_else(|| {
            doc.pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| "metadata.namespace is required".to_string())
}

fn string_list(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn rules_from_api(doc: &Value) -> Result<Vec<PolicyRule>, String> {
    let Some(rules) = doc.get("rules") else {
        return Ok(Vec::new());
    };
    let rules = rules
        .as_array()
        .ok_or_else(|| "rules must be an array".to_string())?;
    Ok(rules
        .iter()
        .map(|rule| PolicyRule {
            verbs: string_list(rule, "verbs"),
            api_groups: string_list(rule, "apiGroups"),
            resources: string_list(rule, "resources"),
            resource_names: string_list(rule, "resourceNames"),
            non_resource_urls: string_list(rule, "nonResourceURLs"),
        })
        .collect())
}

fn subjects_from_api(doc: &Value) -> Result<Vec<Subject>, String> {
    let Some(subjects) = doc.get("subjects") else {
        return Ok(Vec::new());
    };
    let subjects = subjects
        .as_array()
        .ok_or_else(|| "subjects must be an array".to_string())?;
    let mut parsed = Vec::with_capacity(subjects.len());
    for subject in subjects {
        let kind = subject.get("kind").and_then(Value::as_str).unwrap_or("");
        let name = subject
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "subject name is required".to_string())?;
        match kind {
            "User" => parsed.push(Subject::User {
                name: name.to_string(),
            }),
            "Group" => parsed.push(Subject::Group {
                name: name.to_string(),
            }),
            "ServiceAccount" => {
                let namespace = subject
                    .get("namespace")
                    .and_then(Value::as_str)
                    .filter(|namespace| !namespace.is_empty())
                    .ok_or_else(|| "ServiceAccount subject requires a namespace".to_string())?;
                parsed.push(Subject::ServiceAccount {
                    namespace: namespace.to_string(),
                    name: name.to_string(),
                });
            },
            other => {
                return Err(format!("unsupported subject kind '{other}'"));
            },
        }
    }
    Ok(parsed)
}

fn role_ref_name(doc: &Value) -> Result<String, String> {
    doc.pointer("/roleRef/name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "roleRef.name is required".to_string())
}

pub(crate) fn cluster_role_from_api(doc: &Value) -> Result<ClusterRole, String> {
    Ok(ClusterRole {
        name: object_name(doc)?.to_string(),
        rules: rules_from_api(doc)?,
    })
}

pub(crate) fn cluster_role_binding_from_api(doc: &Value) -> Result<ClusterRoleBinding, String> {
    Ok(ClusterRoleBinding {
        name: object_name(doc)?.to_string(),
        role_ref: role_ref_name(doc)?,
        subjects: subjects_from_api(doc)?,
    })
}

pub(crate) fn role_from_api(namespace: &str, doc: &Value) -> Result<Role, String> {
    Ok(Role {
        namespace: namespace.to_string(),
        name: object_name(doc)?.to_string(),
        rules: rules_from_api(doc)?,
    })
}

pub(crate) fn role_binding_from_api(namespace: &str, doc: &Value) -> Result<RoleBinding, String> {
    Ok(RoleBinding {
        namespace: namespace.to_string(),
        name: object_name(doc)?.to_string(),
        role_ref: role_ref_name(doc)?,
        subjects: subjects_from_api(doc)?,
    })
}

fn evaluate_cluster_role_binding(
    binding: &ClusterRoleBinding,
    cluster_roles: &HashMap<String, ClusterRole>,
    req: &AuthzRequest<'_>,
) -> bool {
    if !binding
        .subjects
        .iter()
        .any(|s| s.matches_user_or_group(req.username, req.groups))
    {
        return false;
    }
    cluster_roles
        .get(&binding.role_ref)
        .is_some_and(|role| rule_allows(&role.rules, req))
}

fn evaluate_role_binding(
    binding: &RoleBinding,
    roles: &HashMap<(String, String), Role>,
    cluster_roles: &HashMap<String, ClusterRole>,
    req: &AuthzRequest<'_>,
) -> bool {
    if !binding
        .subjects
        .iter()
        .any(|s| s.matches_user_or_group(req.username, req.groups))
    {
        return false;
    }
    if let Some(role) = roles.get(&(binding.namespace.clone(), binding.role_ref.clone())) {
        return rule_allows(&role.rules, req);
    }
    if let Some(role) = cluster_roles.get(&binding.role_ref) {
        return rule_allows(&role.rules, req);
    }
    false
}

fn rule_allows(rules: &[PolicyRule], req: &AuthzRequest<'_>) -> bool {
    rules
        .iter()
        .any(|rule| rule.matches(req.verb, req.api_group, req.resource, req.resource_name))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{AuthzRequest, RbacAuthorizer};

    fn request<'a>(verb: &'a str, api_group: &'a str, resource: &'a str) -> AuthzRequest<'a> {
        AuthzRequest {
            username: "system:kube-proxy",
            groups: &[],
            verb,
            api_group,
            resource,
            namespace: None,
            resource_name: None,
        }
    }

    #[test]
    fn kube_proxy_may_watch_services_and_endpoint_slices() {
        let authorizer = RbacAuthorizer::new();
        assert!(authorizer.authorize(&request("list", "", "services")));
        assert!(authorizer.authorize(&request("watch", "discovery.k8s.io", "endpointslices")));
        assert!(!authorizer.authorize(&request("list", "", "secrets")));
    }

    #[test]
    fn api_cluster_role_binding_grants_a_service_account() {
        let authorizer = RbacAuthorizer::new();
        let role = json!({
            "metadata": {"name": "sonobuoy-serviceaccount-sonobuoy"},
            "rules": [
                {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]},
                {"nonResourceURLs": ["/metrics"], "verbs": ["get"]}
            ]
        });
        let binding = json!({
            "metadata": {"name": "sonobuoy-serviceaccount-sonobuoy"},
            "roleRef": {"kind": "ClusterRole", "name": "sonobuoy-serviceaccount-sonobuoy"},
            "subjects": [{
                "kind": "ServiceAccount",
                "name": "sonobuoy-serviceaccount",
                "namespace": "sonobuoy"
            }]
        });
        authorizer
            .apply_api_object("clusterroles", None, &role)
            .expect("role");
        authorizer
            .apply_api_object("clusterrolebindings", None, &binding)
            .expect("binding");

        let groups = [
            "system:serviceaccounts".to_string(),
            "system:serviceaccounts:sonobuoy".to_string(),
        ];
        let allowed = AuthzRequest {
            username: "system:serviceaccount:sonobuoy:sonobuoy-serviceaccount",
            groups: &groups,
            verb: "list",
            api_group: "",
            resource: "pods",
            namespace: Some("sonobuoy"),
            resource_name: None,
        };
        assert!(authorizer.authorize(&allowed));

        authorizer.forget_api_object(
            "clusterrolebindings",
            None,
            "sonobuoy-serviceaccount-sonobuoy",
        );
        assert!(!authorizer.authorize(&allowed));
    }
}
