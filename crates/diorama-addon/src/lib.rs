//! Resources shared by release pack generation and the in-cluster installer.
use serde_json::{Value, json};

pub const OWNER: &str = "diorama.io/addon";
pub const MANAGER: &str = "diorama.io/managed-by";
pub const JOB_MANAGER: &str = "addon-job";
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub struct Settings {
    pub addon: String,
    pub image: String,
    pub namespace: String,
    pub node: String,
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.addon.as_str(), "portainer-agent" | "d2k") {
            return Err("unknown add-on".into());
        }
        if !dns_name(&self.namespace) || !dns_name(&self.node) {
            return Err("namespace and node must be valid DNS names".into());
        }
        if self.addon == "portainer-agent" && self.namespace != "portainer" {
            return Err("Portainer Agent uses namespace portainer".into());
        }
        let prefix = format!("ghcr.io/geoffsee/diorama-addon-{}:", self.addon);
        let version = self
            .image
            .strip_prefix(&prefix)
            .ok_or("installer requires its versioned pack image")?;
        if version.is_empty()
            || version == "latest"
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("add-on image must use an explicit release tag".into());
        }
        Ok(())
    }

    pub fn secret(&self) -> (&'static str, &'static [&'static str]) {
        if self.addon == "portainer-agent" {
            ("portainer-agent-edge-key", &["edge.id", "edge.key"])
        } else {
            ("d2k-tls", &["ca.crt", "tls.crt", "tls.key"])
        }
    }
}

fn dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part.as_bytes()[0].is_ascii_alphanumeric()
                && part.as_bytes()[part.len() - 1].is_ascii_alphanumeric()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn resource(kind: &str, name: &str, namespace: Option<&str>) -> Value {
    let api = match kind {
        "Deployment" => "apps/v1",
        "Job" => "batch/v1",
        "Role" | "RoleBinding" | "ClusterRole" | "ClusterRoleBinding" => {
            "rbac.authorization.k8s.io/v1"
        },
        _ => "v1",
    };
    let mut value = json!({"apiVersion":api,"kind":kind,"metadata":{"name":name}});
    if let Some(namespace) = namespace {
        value["metadata"]["namespace"] = json!(namespace);
    }
    value
}

fn binding(kind: &str, name: &str, role: &str, service_account: &str, namespace: &str) -> Value {
    let mut value = resource(kind, name, (kind == "RoleBinding").then_some(namespace));
    value["roleRef"] = json!({"apiGroup":"rbac.authorization.k8s.io","kind":if kind == "RoleBinding" {"Role"} else {"ClusterRole"},"name":role});
    value["subjects"] =
        json!([{"kind":"ServiceAccount","name":service_account,"namespace":namespace}]);
    value
}

/// The workload's image equals the Job image; no registry or second payload is needed.
pub fn resources(settings: &Settings) -> Result<Vec<Value>> {
    settings.validate()?;
    let ns = settings.namespace.as_str();
    let agent = settings.addon == "portainer-agent";
    let name = settings.addon.as_str();
    let account = if agent {
        "portainer-sa-clusteradmin"
    } else {
        "d2k"
    };
    let mut resources = vec![resource("ServiceAccount", account, Some(ns))];
    if agent {
        resources.push(binding(
            "ClusterRoleBinding",
            "portainer-crb-clusteradmin",
            "cluster-admin",
            account,
            ns,
        ));
        let mut config = resource("ConfigMap", "portainer-agent-edge", Some(ns));
        config["data"] = json!({"EDGE_ASYNC":"false","EDGE_INSECURE_POLL":"0"});
        resources.push(config);
    } else {
        let mut role = resource("Role", "d2k", Some(ns));
        role["rules"] = json!([
            {"apiGroups":["apps"],"resources":["deployments"],"verbs":["get","list","watch","create","update","patch","delete"]},
            {"apiGroups":[""],"resources":["pods","events","resourcequotas"],"verbs":["get","list","watch"]},
            {"apiGroups":[""],"resources":["pods/log"],"verbs":["get"]},
            {"apiGroups":[""],"resources":["pods/exec"],"verbs":["create"]},
            {"apiGroups":[""],"resources":["services","configmaps","secrets","persistentvolumeclaims"],"verbs":["get","list","watch","create","update","patch","delete"]},
            {"apiGroups":["metrics.k8s.io"],"resources":["pods"],"verbs":["get","list"]}
        ]);
        resources.push(role);
        resources.push(binding("RoleBinding", "d2k", "d2k", account, ns));
        let cluster_name = format!("d2k-node-reader-{ns}");
        let mut role = resource("ClusterRole", &cluster_name, None);
        role["rules"] = json!([
            {"apiGroups":[""],"resources":["nodes"],"verbs":["get","list","watch"]},
            {"apiGroups":[""],"resources":["namespaces"],"resourceNames":[ns],"verbs":["get"]},
            {"apiGroups":["storage.k8s.io"],"resources":["storageclasses"],"verbs":["get","list","watch"]}
        ]);
        resources.push(role);
        resources.push(binding(
            "ClusterRoleBinding",
            &cluster_name,
            &cluster_name,
            account,
            ns,
        ));
    }
    let mut service = resource("Service", name, Some(ns));
    service["spec"] = if agent {
        json!({"clusterIP":"None","publishNotReadyAddresses":true,"selector":{"app":name},"ports":[{"name":"edge","port":9001,"targetPort":9001},{"name":"http","port":80,"targetPort":80}]})
    } else {
        json!({"type":"LoadBalancer","selector":{"app":name},"ports":[{"name":"docker-api","port":2376,"targetPort":2376}]})
    };
    resources.push(service);
    let mut deployment = resource("Deployment", name, Some(ns));
    let mut container = json!({"name":name,"image":settings.image,"imagePullPolicy":"Never",
        "command":[if agent {"/app/agent"} else {"/d2k"}],
        "resources":{"requests":{"cpu":"25m","memory":"32Mi"}}});
    if agent {
        container["envFrom"] = json!([{"configMapRef":{"name":"portainer-agent-edge"}}]);
        container["env"] = json!([
            {"name":"EDGE","value":"1"}, {"name":"LOG_LEVEL","value":"INFO"},
            {"name":"AGENT_CLUSTER_ADDR","value":"portainer-agent"},
            {"name":"KUBERNETES_POD_IP","valueFrom":{"fieldRef":{"fieldPath":"status.podIP"}}},
            {"name":"EDGE_ID","valueFrom":{"secretKeyRef":{"name":"portainer-agent-edge-key","key":"edge.id"}}},
            {"name":"EDGE_KEY","valueFrom":{"secretKeyRef":{"name":"portainer-agent-edge-key","key":"edge.key"}}}
        ]);
        container["readinessProbe"] =
            json!({"exec":{"command":["/app/healthy"]},"initialDelaySeconds":5});
    } else {
        container["env"] = json!([
            {"name":"D2K_NAMESPACE","value":ns}, {"name":"D2K_PORT","value":"2376"},
            {"name":"D2K_SWARM_MODE","value":"true"}, {"name":"D2K_LOG_LEVEL","value":"info"},
            {"name":"D2K_TLS_CERT_FILE","value":"/etc/d2k/tls/tls.crt"},
            {"name":"D2K_TLS_KEY_FILE","value":"/etc/d2k/tls/tls.key"},
            {"name":"D2K_TLS_CA_FILE","value":"/etc/d2k/tls/ca.crt"}
        ]);
        container["volumeMounts"] =
            json!([{"name":"tls","mountPath":"/etc/d2k/tls","readOnly":true}]);
        container["readinessProbe"] = json!({"tcpSocket":{"port":2376},"initialDelaySeconds":2});
    }
    deployment["spec"] = json!({"replicas":1,"strategy":{"type":"Recreate"},"selector":{"matchLabels":{"app":name}},"template":{"metadata":{"labels":{"app":name}},"spec":{"nodeSelector":{"diorama.io/runtime":"ordinary","kubernetes.io/hostname":settings.node},"serviceAccountName":account,"containers":[container]}}});
    if !agent {
        deployment["spec"]["template"]["spec"]["volumes"] =
            json!([{"name":"tls","secret":{"secretName":"d2k-tls"}}]);
    }
    resources.push(deployment);
    for resource in &mut resources {
        resource["metadata"]["labels"][OWNER] = json!(name);
        resource["metadata"]["labels"][MANAGER] = json!(JOB_MANAGER);
    }
    Ok(resources)
}

/// Explicit bootstrap RBAC plus a repeatable, node-bound installation Job.
pub fn installation_job(settings: &Settings) -> Result<Value> {
    settings.validate()?;
    let ns = settings.namespace.as_str();
    let name = format!("diorama-install-{}", settings.addon);
    let mut role = resource("ClusterRole", &name, None);
    role["rules"] = json!([
        {"apiGroups":[""],"resources":["namespaces","serviceaccounts","configmaps","services"],"verbs":["get","create","update"]},
        {"apiGroups":[""],"resources":["secrets"],"verbs":["get"]},
        {"apiGroups":[""],"resources":["pods","events"],"verbs":["get","list"]},
        {"apiGroups":["apps"],"resources":["deployments"],"verbs":["get","create","update"]},
        {"apiGroups":["rbac.authorization.k8s.io"],"resources":["roles","rolebindings","clusterroles","clusterrolebindings"],"verbs":["get","create","update","bind","escalate"]}
    ]);
    // Each namespace has a separate installer identity; workload cluster roles are also unique.
    let identity = format!("{name}-{ns}");
    role["metadata"]["name"] = json!(identity);
    let mut job = resource("Job", &name, Some(ns));
    job["spec"] = json!({"backoffLimit":0,"activeDeadlineSeconds":360,"template":{"spec":{
        "nodeSelector":{"diorama.io/runtime":"ordinary","kubernetes.io/hostname":settings.node},"serviceAccountName":name,"restartPolicy":"Never",
        "containers":[{"name":"installer","image":settings.image,"imagePullPolicy":"Never",
            "command":["/diorama-addon"],"env":[
                {"name":"DIORAMA_ADDON","value":settings.addon},
                {"name":"DIORAMA_ADDON_IMAGE","value":settings.image},
                {"name":"DIORAMA_ADDON_NAMESPACE","value":ns},
                {"name":"DIORAMA_ADDON_NODE","valueFrom":{"fieldRef":{"fieldPath":"spec.nodeName"}}}
            ]}]
    }}});
    Ok(json!({"apiVersion":"v1","kind":"List","items":[
        resource("Namespace", ns, None), resource("ServiceAccount", &name, Some(ns)),
        role, binding("ClusterRoleBinding", &identity, &identity, &name, ns), job
    ]}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offline_jobs_and_workloads_share_image_and_node_without_embedded_credentials() {
        for addon in ["d2k", "portainer-agent"] {
            let settings = Settings {
                addon: addon.into(),
                image: format!("ghcr.io/geoffsee/diorama-addon-{addon}:v1.2.3"),
                namespace: if addon == "d2k" {
                    "workspace"
                } else {
                    "portainer"
                }
                .into(),
                node: "node-1".into(),
            };
            let job = installation_job(&settings).unwrap();
            let job_spec =
                &job["items"].as_array().unwrap().last().unwrap()["spec"]["template"]["spec"];
            let objects = resources(&settings).unwrap();
            let deployment = objects.iter().find(|v| v["kind"] == "Deployment").unwrap();
            let pod = &deployment["spec"]["template"]["spec"];
            assert_eq!(job_spec["nodeName"], pod["nodeName"]);
            assert_eq!(
                job_spec["containers"][0]["image"],
                pod["containers"][0]["image"]
            );
            assert_eq!(pod["containers"][0]["imagePullPolicy"], "Never");
            assert_eq!(job_spec["containers"][0]["imagePullPolicy"], "Never");
            assert!(
                !objects
                    .iter()
                    .any(|v| v["kind"] == "Secret" || v["kind"] == "Namespace")
            );
            assert!(
                objects
                    .iter()
                    .all(|v| v["metadata"]["labels"][MANAGER] == JOB_MANAGER)
            );
        }
    }
    #[test]
    fn unsafe_and_floating_installation_inputs_are_rejected() {
        let base = Settings {
            addon: "d2k".into(),
            image: "ghcr.io/geoffsee/diorama-addon-d2k:v1".into(),
            namespace: "d2k".into(),
            node: "node".into(),
        };
        for value in ["", "latest", "v1/a"] {
            let mut settings = base.clone();
            settings.image = format!("ghcr.io/geoffsee/diorama-addon-d2k:{value}");
            assert!(resources(&settings).is_err());
        }
        for value in ["", "../ns", "Bad_Name"] {
            let mut settings = base.clone();
            settings.namespace = value.into();
            assert!(resources(&settings).is_err());
        }
    }
}
