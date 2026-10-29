use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const API_VERSION: &str = "kubesolo.io/v1alpha1";
pub const KIND: &str = "Config";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/diorama/config.yaml";

/// Desired configuration. Runtime discovery and precedence are separate operations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub api_version: String,
    pub kind: String,
    pub path: String,
    pub logging: Logging,
    pub network: Network,
    pub runtime: Runtime,
    pub kubernetes: Kubernetes,
    pub storage: Storage,
    pub portainer: Portainer,
    pub d2k: D2k,
    pub metrics: Metrics,
    pub api: ConfigApi,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Logging {
    pub debug: bool,
    pub pprof: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Network {
    #[serde(default = "default_pod_pool")]
    pub pod_address_pool: String,
    #[serde(rename = "nodeIP")]
    pub node_ip: String,
    pub mtu: i64,
    #[serde(rename = "disableIPv6")]
    pub disable_ipv6: bool,
    pub load_balancer: LoadBalancer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadBalancer {
    pub enabled: bool,
    pub ip: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Runtime {
    /// Empty or auto preserves automatic runtime detection.
    #[serde(default)]
    pub backend: String,
    pub endpoint: String,
    pub container_mode: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Kubernetes {
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(default)]
    pub token_file: String,
    #[serde(default)]
    pub disable_local_kubelet: bool,
    pub node_name: String,
    pub api_server: ApiServer,
    pub kubelet: Kubelet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiServer {
    #[serde(rename = "extraSANs")]
    pub extra_sans: Option<Vec<String>>,
    pub startup_timeout_seconds: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Kubelet {
    pub cpu_manager: CpuManager,
    pub system_reserved: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpuManager {
    pub policy: String,
    pub policy_options: Option<BTreeMap<String, String>>,
    #[serde(rename = "reservedCPUs")]
    pub reserved_cpus: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Storage {
    pub local_path: LocalPath,
    #[serde(rename = "dbWALRepair")]
    pub db_wal_repair: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalPath {
    pub enabled: bool,
    pub shared_path: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Portainer {
    #[serde(rename = "edgeID")]
    pub edge_id: String,
    #[serde(rename = "edgeKey")]
    pub edge_key: String,
    #[serde(rename = "async")]
    pub asynchronous: bool,
    pub image: String,
}

impl std::fmt::Debug for Portainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Portainer")
            .field("edge_id", &self.edge_id)
            .field("edge_key", &"<redacted>")
            .field("asynchronous", &self.asynchronous)
            .field("image", &self.image)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct D2k {
    pub enabled: bool,
    pub namespace: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    pub enabled: bool,
    pub bind_address: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigApi {
    pub enabled: bool,
    pub socket_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_version: API_VERSION.into(),
            kind: KIND.into(),
            path: "/var/lib/diorama".into(),
            logging: Logging::default(),
            network: Network {
                pod_address_pool: default_pod_pool(),
                node_ip: String::new(),
                mtu: 0,
                disable_ipv6: false,
                load_balancer: LoadBalancer {
                    enabled: true,
                    ip: String::new(),
                },
            },
            runtime: Runtime::default(),
            kubernetes: Kubernetes {
                role: default_role(),
                token_file: String::new(),
                disable_local_kubelet: false,
                node_name: String::new(),
                api_server: ApiServer {
                    extra_sans: None,
                    startup_timeout_seconds: 600,
                },
                kubelet: Kubelet {
                    cpu_manager: CpuManager {
                        policy: "none".into(),
                        policy_options: None,
                        reserved_cpus: String::new(),
                    },
                    system_reserved: None,
                },
            },
            storage: Storage {
                local_path: LocalPath {
                    enabled: true,
                    shared_path: String::new(),
                },
                db_wal_repair: false,
            },
            portainer: Portainer {
                edge_id: String::new(),
                edge_key: String::new(),
                asynchronous: false,
                image: "docker.io/portainer/agent:lts".into(),
            },
            d2k: D2k {
                enabled: false,
                namespace: "d2k".into(),
            },
            metrics: Metrics {
                enabled: false,
                bind_address: "127.0.0.1:9105".into(),
            },
            api: ConfigApi::default(),
        }
    }
}

fn default_role() -> String {
    "control-plane".into()
}
fn default_pod_pool() -> String {
    "10.42.0.0/16".into()
}
