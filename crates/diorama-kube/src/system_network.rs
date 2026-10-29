//! API-only installation of Cilium and scheduled kube-proxy. Installation does not
//! depend on DNS, Service forwarding, or Node Ready conditions.
use diorama_apiserver::{ApiserverError, KubernetesApiClient};
use diorama_supervisor::{Adapter, AdapterContext, AdapterError, AdapterFuture, StopPhase};
use serde_json::Value;
use std::sync::Arc;
#[derive(Debug)]
pub(crate) struct SystemNetwork {
    pub client: Arc<KubernetesApiClient>,
    pub host: String,
    pub pool: String,
    pub mtu: i64,
}
impl SystemNetwork {
    async fn reconcile(&self) -> Result<(), ApiserverError> {
        for source in [
            include_str!("../resources/cilium.yaml"),
            include_str!("../resources/kube-proxy.yaml"),
        ] {
            let source = source
                .replace("DIORAMA_API_HOST", &self.host)
                .replace("DIORAMA_POD_POOL", &self.pool)
                .replace("10.42.0.0/16", &self.pool);
            for document in source.split("\n---") {
                let mut doc: Value =
                    serde_saphyr::from_str(document).map_err(|_| ApiserverError::Config {
                        reason: "invalid embedded network manifest".into(),
                    })?;
                if doc.is_null() {
                    continue;
                }
                if self.mtu > 0
                    && doc["kind"] == "ConfigMap"
                    && doc["metadata"]["name"] == "cilium-config"
                {
                    doc["data"]["mtu"] = Value::String(self.mtu.to_string());
                }
                apply(&self.client, doc).await?;
            }
        }
        Ok(())
    }
}
async fn apply(client: &KubernetesApiClient, mut doc: Value) -> Result<(), ApiserverError> {
    let kind = doc["kind"].as_str().unwrap_or("").to_string();
    let name = doc["metadata"]["name"].as_str().unwrap_or("").to_string();
    let namespace = doc["metadata"]["namespace"].as_str().map(String::from);
    let version = doc["apiVersion"].as_str().unwrap_or("v1");
    let group = version.split_once('/').map_or("", |v| v.0).to_string();
    if kind == "Namespace" {
        match client.get_namespace(&name).await {
            Ok(_) => {},
            Err(ApiserverError::NotFound { .. }) => {
                client.create_namespace_object(doc).await?;
            },
            Err(error) => return Err(error),
        }
        return Ok(());
    }
    let plural = match kind.as_str() {
        "ServiceAccount" => "serviceaccounts",
        "ConfigMap" => "configmaps",
        "Secret" => "secrets",
        "ClusterRole" => "clusterroles",
        "ClusterRoleBinding" => "clusterrolebindings",
        "Role" => "roles",
        "RoleBinding" => "rolebindings",
        "DaemonSet" => "daemonsets",
        "Deployment" => "deployments",
        "Service" => "services",
        "CustomResourceDefinition" => "customresourcedefinitions",
        _ => {
            return Err(ApiserverError::Config {
                reason: format!("unsupported network manifest {kind}"),
            });
        },
    };
    let existing = if kind == "CustomResourceDefinition" {
        client.get_crd(&name).await
    } else if let Some(ns) = &namespace {
        client
            .get_namespaced_object(&group, plural, ns, &name)
            .await
    } else {
        client.get_cluster_object(&group, plural, &name).await
    };
    match existing {
        Ok(old) => {
            if ["spec", "data", "rules", "roleRef", "subjects"]
                .iter()
                .all(|key| old.get(key) == doc.get(key))
            {
                return Ok(());
            }
            doc["metadata"]["resourceVersion"] = old["metadata"]["resourceVersion"].clone();
            if kind == "CustomResourceDefinition" {
                client.update_crd(&name, doc).await?;
            } else if let Some(ns) = &namespace {
                client
                    .replace_namespaced_object(&group, &kind, plural, ns, &name, doc)
                    .await?;
            } else {
                client
                    .replace_cluster_object(&group, &kind, plural, &name, doc)
                    .await?;
            }
        },
        Err(ApiserverError::NotFound { .. }) => {
            if kind == "CustomResourceDefinition" {
                client.create_crd(doc).await?;
            } else if let Some(ns) = &namespace {
                client
                    .create_namespaced_object(&group, &kind, plural, ns, doc)
                    .await?;
            } else {
                client
                    .create_cluster_object(&group, &kind, plural, doc)
                    .await?;
            }
        },
        Err(e) => return Err(e),
    }
    Ok(())
}
impl Adapter for SystemNetwork {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            self.reconcile().await.map_err(|e| {
                eprintln!("network bootstrap: {e}");
                AdapterError {
                    code: "network-bootstrap-failed",
                }
            })?;
            if !context.ready() {
                return Err(AdapterError {
                    code: "network-bootstrap-readiness-rejected",
                });
            }
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tokio::select! {
                    phase = context.changed() => { if matches!(phase, StopPhase::Graceful | StopPhase::Force) { return Ok(()); } },
                    _ = interval.tick() => { if let Err(e) = self.reconcile().await { eprintln!("network reconciliation: {e}"); } }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_bootstrap_uses_direct_api_and_ordinary_nodes_only() {
        let mut workloads = 0;
        for source in [
            include_str!("../resources/cilium.yaml"),
            include_str!("../resources/kube-proxy.yaml"),
        ] {
            assert!(source.contains("DIORAMA_API_HOST"));
            for document in source.split("\n---") {
                let doc: Value = serde_saphyr::from_str(document).unwrap();
                if !matches!(doc["kind"].as_str(), Some("DaemonSet" | "Deployment")) {
                    continue;
                }
                workloads += 1;
                let spec = &doc["spec"]["template"]["spec"];
                assert_eq!(spec["nodeSelector"]["diorama.io/runtime"], "ordinary");
                assert_eq!(spec["hostNetwork"], true);
                for mode in spec["volumes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|volume| volume.pointer("/projected/defaultMode"))
                {
                    assert_eq!(
                        mode.as_u64(),
                        Some(256),
                        "upstream clients require integer file modes"
                    );
                }
                for toleration in spec["tolerations"].as_array().unwrap() {
                    let key = toleration["key"].as_str().unwrap();
                    assert_ne!(key, "");
                    assert_ne!(key, "diorama.io/foreign-runtime");
                }
            }
        }
        assert_eq!(workloads, 3);
    }
}
