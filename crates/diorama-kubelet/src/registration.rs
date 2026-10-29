use std::sync::{Arc, RwLock};

use serde_json::{Value, json};

use crate::config::KubeletConfigOptions;
use crate::error::KubeletError;

/// Node registration manager responsible for posting Node status and Lease heartbeats.
#[derive(Clone, Debug)]
pub struct NodeRegistration {
    client: crate::api::NodeApi,
    options: KubeletConfigOptions,
    runtime_version: Arc<RwLock<String>>,
    ready: Arc<std::sync::atomic::AtomicBool>,
}

impl NodeRegistration {
    #[must_use]
    pub fn new(
        client: impl Into<crate::api::NodeApi>,
        options: KubeletConfigOptions,
        runtime_version: impl Into<String>,
    ) -> Self {
        Self {
            client: client.into(),
            options,
            runtime_version: Arc::new(RwLock::new(runtime_version.into())),
            ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn set_ready(&self, ready: bool) {
        self.ready
            .store(ready, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_runtime_version(&self, version: impl Into<String>) {
        if let Ok(mut lock) = self.runtime_version.write() {
            *lock = version.into();
        }
    }

    /// Constructs the canonical Node resource object for the primary node.
    #[must_use]
    pub fn build_node_resource(&self) -> Value {
        self.build_node_resource_for(&self.options.node_name)
    }

    /// Constructs the canonical Node resource object for a given node name.
    #[must_use]
    pub fn build_node_resource_for(&self, node_name: &str) -> Value {
        let node_ip = if self.options.node_ip.is_empty() {
            "127.0.0.1".to_string()
        } else {
            self.options.node_ip.clone()
        };

        let arch = if cfg!(target_arch = "x86_64") {
            "amd64"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            std::env::consts::ARCH
        };

        let runtime_version = self
            .runtime_version
            .read()
            .map_or_else(|_| "unknown".to_string(), |v| v.clone());

        let ready = self.ready.load(std::sync::atomic::Ordering::Relaxed);
        let cpu = std::thread::available_parallelism()
            .map_or(1, std::num::NonZero::get)
            .to_string();
        let memory = host_memory_capacity();
        json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": node_name,
                "labels": {
                    "kubernetes.io/hostname": node_name,
                    "kubernetes.io/os": "linux",
                    "kubernetes.io/arch": arch,
                    "node.kubernetes.io/instance-type": "k8s",
                    "diorama.io/runtime": "ordinary"
                }
            },
            "spec": {},
            "status": {
                "addresses": [
                    {
                        "type": "InternalIP",
                        "address": node_ip
                    },
                    {
                        "type": "Hostname",
                        "address": node_name
                    }
                ],
                "conditions": [
                    {
                        "type": "Ready",
                        "status": if ready { "True" } else { "False" },
                        "reason": if ready { "KubeletReady" } else { "KubeletNotReady" },
                        "message": if ready { "runtime and network ready" } else { "runtime or network is not ready" }
                    },
                    {
                        "type": "DiskPressure",
                        "status": "False",
                        "reason": "KubeletHasNoDiskPressure",
                        "message": "kubelet has sufficient disk space available"
                    },
                    {
                        "type": "MemoryPressure",
                        "status": "False",
                        "reason": "KubeletHasSufficientMemory",
                        "message": "kubelet has sufficient memory available"
                    },
                    {
                        "type": "PIDPressure",
                        "status": "False",
                        "reason": "KubeletHasSufficientPID",
                        "message": "kubelet has sufficient PID available"
                    }
                ],
                "capacity": {
                    "cpu": cpu,
                    "memory": memory,
                    "pods": "110"
                },
                "allocatable": {
                    "cpu": cpu,
                    "memory": memory,
                    "pods": "110"
                },
                "nodeInfo": {
                    "kubeletVersion": diorama_apiserver::KUBERNETES_VERSION,
                    "containerRuntimeVersion": runtime_version,
                    "operatingSystem": "linux",
                    "architecture": arch,
                    "osImage": "Linux"
                }
            }
        })
    }

    async fn register_node(&self, name: &str) -> Result<Value, KubeletError> {
        let node_doc = self.build_node_resource_for(name);

        match self.client.get_node(name).await {
            Ok(existing) => {
                let mut updated = node_doc;
                merge_existing_node_fields(&mut updated, &existing);
                self.client
                    .patch_node_status(name, updated["status"].clone())
                    .await
                    .map_err(|e| KubeletError::NodeRegistrationFailed {
                        reason: format!("failed to update node {name}: {e}"),
                    })
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => {
                self.client.create_node(node_doc).await.map_err(|e| {
                    KubeletError::NodeRegistrationFailed {
                        reason: format!("failed to create node {name}: {e}"),
                    }
                })
            },
            Err(e) => Err(KubeletError::NodeRegistrationFailed {
                reason: format!("failed to query node {name}: {e}"),
            }),
        }
    }

    /// Registers the Node objects (this process) in the API server.
    /// If already existing, updates their status to Ready.
    pub async fn register_or_update(&self) -> Result<Value, KubeletError> {
        self.register_node(&self.options.node_name).await
    }

    async fn update_lease_for(&self, name: &str) -> Result<Value, KubeletError> {
        let renew_time = current_rfc3339_micros();
        let lease_doc = json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": name,
                "namespace": "kube-node-lease"
            },
            "spec": {
                "holderIdentity": name,
                "leaseDurationSeconds": 40,
                "renewTime": renew_time
            }
        });

        match self.client.get_lease("kube-node-lease", name).await {
            Ok(existing) => {
                let mut updated = lease_doc;
                if let Some(rv) = existing
                    .get("metadata")
                    .and_then(|m| m.get("resourceVersion"))
                    && let Some(meta) = updated.get_mut("metadata").and_then(Value::as_object_mut)
                {
                    meta.insert("resourceVersion".to_string(), rv.clone());
                }
                self.client
                    .update_lease("kube-node-lease", name, updated)
                    .await
                    .map_err(|e| KubeletError::NodeRegistrationFailed {
                        reason: format!("failed to update lease for {name}: {e}"),
                    })
            },
            Err(diorama_apiserver::ApiserverError::NotFound { .. }) => self
                .client
                .create_lease("kube-node-lease", lease_doc)
                .await
                .map_err(|e| KubeletError::NodeRegistrationFailed {
                    reason: format!("failed to create lease for {name}: {e}"),
                }),
            Err(e) => Err(KubeletError::NodeRegistrationFailed {
                reason: format!("failed to query lease for {name}: {e}"),
            }),
        }
    }

    /// Heartbeat by creating or renewing the Leases in `kube-node-lease` for this node.
    pub async fn update_lease(&self) -> Result<Value, KubeletError> {
        self.update_lease_for(&self.options.node_name).await
    }
}

fn current_rfc3339_micros() -> String {
    let now = std::time::SystemTime::now();
    let dur = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let micros = dur.subsec_micros();

    let days = secs / 86400;
    let rem_secs = secs % 86400;
    let hours = rem_secs / 3600;
    let mins = (rem_secs % 3600) / 60;
    let s = rem_secs % 60;

    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{s:02}.{micros:06}Z")
}

#[allow(
    clippy::unreadable_literal,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]
fn days_to_ymd(days: u64) -> (i64, u32, u32) {
    let z = (days as i64) + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

const STANDARD_NODE_RESOURCES: &[&str] = &["cpu", "memory", "pods", "ephemeral-storage"];

fn merge_node_metadata(node: &mut Value, existing: &Value) {
    let Some(existing_meta) = existing.get("metadata").and_then(Value::as_object) else {
        return;
    };
    let Some(node_meta) = node.get_mut("metadata").and_then(Value::as_object_mut) else {
        return;
    };

    for field in ["uid", "creationTimestamp", "generation", "resourceVersion"] {
        if let Some(val) = existing_meta.get(field) {
            node_meta.insert(field.to_string(), val.clone());
        }
    }

    if let Some(existing_labels) = existing_meta.get("labels").and_then(Value::as_object) {
        let mut merged_labels = existing_labels.clone();
        if let Some(default_labels) = node_meta.get("labels").and_then(Value::as_object) {
            for (k, v) in default_labels {
                merged_labels.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        node_meta.insert("labels".to_string(), Value::Object(merged_labels));
    }

    if let Some(existing_annotations) = existing_meta.get("annotations").and_then(Value::as_object)
    {
        let mut merged_annotations = existing_annotations.clone();
        if let Some(default_annotations) = node_meta.get("annotations").and_then(Value::as_object) {
            for (k, v) in default_annotations {
                merged_annotations
                    .entry(k.clone())
                    .or_insert_with(|| v.clone());
            }
        }
        node_meta.insert("annotations".to_string(), Value::Object(merged_annotations));
    }
}

fn merge_node_spec(node: &mut Value, existing: &Value) {
    let Some(existing_spec) = existing.get("spec").and_then(Value::as_object) else {
        return;
    };
    let node_spec = node.as_object_mut().and_then(|obj| {
        obj.entry("spec".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
    });

    if let Some(node_spec) = node_spec {
        for (k, v) in existing_spec {
            node_spec.insert(k.clone(), v.clone());
        }
    }
}

fn merge_node_resources(node: &mut Value, existing: &Value) {
    for section in ["capacity", "allocatable"] {
        let existing_res = existing
            .pointer(&format!("/status/{section}"))
            .and_then(Value::as_object);
        let node_res = node
            .pointer_mut(&format!("/status/{section}"))
            .and_then(Value::as_object_mut);

        if let (Some(existing_res), Some(node_res)) = (existing_res, node_res) {
            for (k, v) in existing_res {
                if !STANDARD_NODE_RESOURCES.contains(&k.as_str()) {
                    node_res.insert(k.clone(), v.clone());
                }
            }
        }
    }
}

pub(crate) fn merge_existing_node_fields(node: &mut Value, existing: &Value) {
    merge_node_metadata(node, existing);
    merge_node_spec(node, existing);
    merge_node_resources(node, existing);
}

fn host_memory_capacity() -> String {
    let memory = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|contents| {
            contents
                .lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0);
    format!("{memory}Ki")
}

#[cfg(test)]
mod tests {
    use super::*;
    use diorama_apiserver::KubernetesApiClient;
    use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
    use diorama_datastore::{DatastoreConfig, DatastoreEngine};
    use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
    use std::net::IpAddr;
    use tempfile::TempDir;

    fn setup_test_client(dir: &TempDir) -> Arc<KubernetesApiClient> {
        let node_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let pki_dir = dir.path().join("pki");
        std::fs::create_dir_all(&pki_dir).unwrap();
        let datastore_dir = dir.path().join("datastore");

        let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
        let pki = ClusterPki::new(pki_config);
        pki.reconcile().expect("PKI reconcile");

        let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
        let storage = KubernetesStorage::new(engine.client(), "/registry");

        let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
        let apiserver = Arc::new(ApiserverService::new(apiserver_config, storage));
        Arc::new(apiserver.admin_client())
    }

    #[tokio::test]
    async fn registration_owns_one_node_and_lease_and_reports_readiness() {
        let temp = TempDir::new().unwrap();
        let client = setup_test_client(&temp);
        let registration = NodeRegistration::new(
            client.clone(),
            KubeletConfigOptions {
                node_name: "test-node".into(),
                ..Default::default()
            },
            "v1.35.7",
        );
        let node = registration.register_or_update().await.unwrap();
        assert_eq!(node["metadata"]["labels"]["diorama.io/runtime"], "ordinary");
        assert_eq!(node["status"]["conditions"][0]["status"], "False");
        assert!(client.get_node("test-node-worker").await.is_err());
        registration.set_ready(true);
        let ready = registration.register_or_update().await.unwrap();
        assert_eq!(ready["status"]["conditions"][0]["status"], "True");
        registration.update_lease().await.unwrap();
        assert_eq!(
            client
                .get_lease("kube-node-lease", "test-node")
                .await
                .unwrap()["spec"]["holderIdentity"],
            "test-node"
        );
        assert!(
            client
                .get_lease("kube-node-lease", "test-node-worker")
                .await
                .is_err()
        );
    }
}
