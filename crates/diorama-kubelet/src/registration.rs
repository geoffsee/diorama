use std::sync::{Arc, RwLock};

use serde_json::{Value, json};

use diorama_apiserver::KubernetesApiClient;

use crate::config::KubeletConfigOptions;
use crate::error::KubeletError;

/// Node registration manager responsible for posting Node status and Lease heartbeats.
#[derive(Clone, Debug)]
pub struct NodeRegistration {
    client: Arc<KubernetesApiClient>,
    options: KubeletConfigOptions,
    runtime_version: Arc<RwLock<String>>,
}

impl NodeRegistration {
    #[must_use]
    pub fn new(
        client: Arc<KubernetesApiClient>,
        options: KubeletConfigOptions,
        runtime_version: impl Into<String>,
    ) -> Self {
        Self {
            client,
            options,
            runtime_version: Arc::new(RwLock::new(runtime_version.into())),
        }
    }

    pub fn set_runtime_version(&self, version: impl Into<String>) {
        if let Ok(mut lock) = self.runtime_version.write() {
            *lock = version.into();
        }
    }

    /// Constructs the canonical Node resource object.
    #[must_use]
    pub fn build_node_resource(&self) -> Value {
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

        json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": self.options.node_name,
                "labels": {
                    "kubernetes.io/hostname": self.options.node_name,
                    "kubernetes.io/os": "linux",
                    "kubernetes.io/arch": arch,
                    "node.kubernetes.io/instance-type": "k8s"
                }
            },
            "status": {
                "addresses": [
                    {
                        "type": "InternalIP",
                        "address": node_ip
                    },
                    {
                        "type": "Hostname",
                        "address": self.options.node_name
                    }
                ],
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "reason": "KubeletReady",
                        "message": "kubelet is posting ready status"
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
                    "cpu": "2",
                    "memory": "4Gi",
                    "pods": "110"
                },
                "allocatable": {
                    "cpu": "2",
                    "memory": "4Gi",
                    "pods": "110"
                },
                "nodeInfo": {
                    "kubeletVersion": "v1.35.7",
                    "containerRuntimeVersion": runtime_version,
                    "operatingSystem": "linux",
                    "architecture": arch,
                    "osImage": "Linux"
                }
            }
        })
    }

    /// Registers the Node object in the API server. If already existing, updates its status to Ready.
    pub async fn register_or_update(&self) -> Result<Value, KubeletError> {
        let node_doc = self.build_node_resource();
        let name = &self.options.node_name;

        match self.client.get_node(name).await {
            Ok(existing) => {
                let mut updated = node_doc;
                if let Some(rv) = existing
                    .get("metadata")
                    .and_then(|m| m.get("resourceVersion"))
                    && let Some(meta) = updated.get_mut("metadata").and_then(Value::as_object_mut)
                {
                    meta.insert("resourceVersion".to_string(), rv.clone());
                }
                self.client.update_node(name, updated).await.map_err(|e| {
                    KubeletError::NodeRegistrationFailed {
                        reason: format!("failed to update node {name}: {e}"),
                    }
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

    /// Heartbeat by creating or renewing the Lease in `kube-node-lease`.
    pub async fn update_lease(&self) -> Result<Value, KubeletError> {
        let renew_time = current_rfc3339_micros();
        let lease_doc = json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": self.options.node_name,
                "namespace": "kube-node-lease"
            },
            "spec": {
                "holderIdentity": self.options.node_name,
                "leaseDurationSeconds": 40,
                "renewTime": renew_time
            }
        });

        let name = &self.options.node_name;
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
