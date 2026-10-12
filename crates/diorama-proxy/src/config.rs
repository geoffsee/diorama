use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::backend::ProxyMode;

pub const DEFAULT_CLUSTER_CIDR: &str = "10.42.0.0/16";
pub const DEFAULT_HEALTHZ_BIND_ADDRESS: &str = "0.0.0.0:10256";
pub const DEFAULT_HEALTHZ_PORT: u16 = 10256;
pub const DEFAULT_METRICS_BIND_ADDRESS: &str = "";
pub const DEFAULT_OOM_SCORE_ADJ: i32 = -998;

pub const DEFAULT_CONNTRACK_MAX_PER_CORE: u32 = 32_768;
pub const DEFAULT_CONNTRACK_MIN: u32 = 131_072;
pub const DEFAULT_CONNTRACK_TCP_ESTABLISHED_TIMEOUT: &str = "24h0m0s";
pub const DEFAULT_CONNTRACK_TCP_CLOSE_WAIT_TIMEOUT: &str = "1h0m0s";
pub const DEFAULT_CONNTRACK_UDP_TIMEOUT: &str = "0s";
pub const DEFAULT_CONNTRACK_UDP_STREAM_TIMEOUT: &str = "0s";

/// Conntrack configuration options for kube-proxy.
///
/// Upstream Kubernetes attempts to configure kernel sysctls for connection tracking.
/// In container mode (nested Docker, Kubernetes-in-Docker, unprivileged container),
/// writing to `/proc/sys/net/netfilter/nf_conntrack_*` fails with EROFS. Setting all
/// six conntrack values to zero instructs kube-proxy to leave kernel values alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConntrackConfiguration {
    pub max_per_core: Option<u32>,
    pub min: Option<u32>,
    pub tcp_established_timeout: Option<String>,
    pub tcp_close_wait_timeout: Option<String>,
    #[serde(default)]
    pub tcp_be_liberal: Option<bool>,
    pub udp_timeout: Option<String>,
    pub udp_stream_timeout: Option<String>,
}

impl ConntrackConfiguration {
    /// Creates a conntrack configuration with upstream Kubernetes defaults (for host mode).
    #[must_use]
    pub fn default_host() -> Self {
        Self {
            max_per_core: Some(DEFAULT_CONNTRACK_MAX_PER_CORE),
            min: Some(DEFAULT_CONNTRACK_MIN),
            tcp_established_timeout: Some(DEFAULT_CONNTRACK_TCP_ESTABLISHED_TIMEOUT.to_string()),
            tcp_close_wait_timeout: Some(DEFAULT_CONNTRACK_TCP_CLOSE_WAIT_TIMEOUT.to_string()),
            tcp_be_liberal: Some(false),
            udp_timeout: Some(DEFAULT_CONNTRACK_UDP_TIMEOUT.to_string()),
            udp_stream_timeout: Some(DEFAULT_CONNTRACK_UDP_STREAM_TIMEOUT.to_string()),
        }
    }

    /// Creates a conntrack configuration with all six settings set to zero (for container mode).
    #[must_use]
    pub fn container_mode() -> Self {
        Self {
            max_per_core: Some(0),
            min: Some(0),
            tcp_established_timeout: Some("0s".to_string()),
            tcp_close_wait_timeout: Some("0s".to_string()),
            tcp_be_liberal: Some(false),
            udp_timeout: Some("0s".to_string()),
            udp_stream_timeout: Some("0s".to_string()),
        }
    }

    /// Checks whether all six conntrack settings are set to zero.
    #[must_use]
    pub fn is_all_zero(&self) -> bool {
        let max_zero = self.max_per_core == Some(0);
        let min_zero = self.min == Some(0);
        let tcp_est_zero = self
            .tcp_established_timeout
            .as_deref()
            .is_some_and(|v| v == "0" || v == "0s");
        let tcp_close_zero = self
            .tcp_close_wait_timeout
            .as_deref()
            .is_some_and(|v| v == "0" || v == "0s");
        let udp_zero = self
            .udp_timeout
            .as_deref()
            .is_some_and(|v| v == "0" || v == "0s");
        let udp_stream_zero = self
            .udp_stream_timeout
            .as_deref()
            .is_some_and(|v| v == "0" || v == "0s");

        max_zero && min_zero && tcp_est_zero && tcp_close_zero && udp_zero && udp_stream_zero
    }

    /// Checks whether conntrack settings preserve upstream host defaults.
    #[must_use]
    pub fn is_upstream_defaults(&self) -> bool {
        self.max_per_core == Some(DEFAULT_CONNTRACK_MAX_PER_CORE)
            && self.min == Some(DEFAULT_CONNTRACK_MIN)
            && self.tcp_established_timeout.as_deref()
                == Some(DEFAULT_CONNTRACK_TCP_ESTABLISHED_TIMEOUT)
            && self.tcp_close_wait_timeout.as_deref()
                == Some(DEFAULT_CONNTRACK_TCP_CLOSE_WAIT_TIMEOUT)
            && self.udp_timeout.as_deref() == Some(DEFAULT_CONNTRACK_UDP_TIMEOUT)
            && self.udp_stream_timeout.as_deref() == Some(DEFAULT_CONNTRACK_UDP_STREAM_TIMEOUT)
    }
}

impl Default for ConntrackConfiguration {
    fn default() -> Self {
        Self::default_host()
    }
}

/// iptables backend configuration options.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IptablesConfiguration {
    #[serde(default)]
    pub masquerade_all: bool,
    #[serde(default)]
    pub masquerade_bit: Option<i32>,
    pub sync_period: String,
    pub min_sync_period: String,
    #[serde(default)]
    pub localhost_node_ports: Option<bool>,
}

impl Default for IptablesConfiguration {
    fn default() -> Self {
        Self {
            masquerade_all: false,
            masquerade_bit: Some(14),
            sync_period: "30s".to_string(),
            min_sync_period: "1s".to_string(),
            localhost_node_ports: Some(true),
        }
    }
}

/// nftables backend configuration options.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NftablesConfiguration {
    #[serde(default)]
    pub masquerade_all: bool,
    #[serde(default)]
    pub masquerade_bit: Option<i32>,
    pub sync_period: String,
    pub min_sync_period: String,
}

impl Default for NftablesConfiguration {
    fn default() -> Self {
        Self {
            masquerade_all: false,
            masquerade_bit: Some(14),
            sync_period: "30s".to_string(),
            min_sync_period: "1s".to_string(),
        }
    }
}

/// Full `KubeProxyConfiguration` representation matching `kubeproxy.config.k8s.io/v1alpha1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeProxyConfiguration {
    pub api_version: String,
    pub kind: String,
    pub mode: String,
    pub cluster_cidr: String,
    pub healthz_bind_address: String,
    pub metrics_bind_address: String,
    pub oom_score_adj: Option<i32>,
    pub iptables: IptablesConfiguration,
    pub nftables: NftablesConfiguration,
    pub conntrack: ConntrackConfiguration,
}

/// High-level options for starting and supervising kube-proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KubeProxyOptions {
    pub kubeconfig: PathBuf,
    pub cluster_cidr: String,
    pub container_mode: bool,
    pub proxy_mode: ProxyMode,
    pub healthz_port: u16,
    pub healthz_bind_address: String,
    pub metrics_bind_address: String,
    pub oom_score_adj: i32,
    pub conntrack: ConntrackConfiguration,
}

impl KubeProxyOptions {
    /// Creates options with appropriate conntrack defaults based on `container_mode`.
    #[must_use]
    pub fn new(kubeconfig: PathBuf, container_mode: bool, proxy_mode: ProxyMode) -> Self {
        let conntrack = if container_mode {
            ConntrackConfiguration::container_mode()
        } else {
            ConntrackConfiguration::default_host()
        };

        Self {
            kubeconfig,
            cluster_cidr: DEFAULT_CLUSTER_CIDR.to_string(),
            container_mode,
            proxy_mode,
            healthz_port: DEFAULT_HEALTHZ_PORT,
            healthz_bind_address: DEFAULT_HEALTHZ_BIND_ADDRESS.to_string(),
            metrics_bind_address: DEFAULT_METRICS_BIND_ADDRESS.to_string(),
            oom_score_adj: DEFAULT_OOM_SCORE_ADJ,
            conntrack,
        }
    }

    /// Generates CLI command flags matching upstream `KubeSolo` and Kubernetes flags.
    #[must_use]
    pub fn generate_flags(&self) -> Vec<String> {
        let mut flags = Vec::new();

        flags.push(format!("--kubeconfig={}", self.kubeconfig.display()));
        flags.push(format!("--cluster-cidr={}", self.cluster_cidr));
        flags.push(format!(
            "--metrics-bind-address={}",
            self.metrics_bind_address
        ));
        flags.push(format!("--oom-score-adj={}", self.oom_score_adj));
        flags.push(format!("--proxy-mode={}", self.proxy_mode.as_str()));

        if self.container_mode {
            // Container mode must always set all six conntrack settings to zero to prevent
            // kube-proxy from attempting to write to read-only /proc/sys sysctls.
            flags.push("--conntrack-max-per-core=0".to_string());
            flags.push("--conntrack-min=0".to_string());
            flags.push("--conntrack-tcp-timeout-established=0s".to_string());
            flags.push("--conntrack-tcp-timeout-close-wait=0s".to_string());
            flags.push("--conntrack-udp-timeout=0s".to_string());
            flags.push("--conntrack-udp-timeout-stream=0s".to_string());
        }

        if self.proxy_mode == ProxyMode::IpTables {
            flags.push("--masquerade-all=true".to_string());
        }

        flags
    }

    /// Returns the effective conntrack configuration, enforcing container mode zeroing
    /// when `container_mode` is enabled.
    #[must_use]
    pub fn effective_conntrack(&self) -> ConntrackConfiguration {
        if self.container_mode {
            ConntrackConfiguration::container_mode()
        } else {
            self.conntrack.clone()
        }
    }

    /// Converts these options to a structured `KubeProxyConfiguration` object.
    #[must_use]
    pub fn to_v1alpha1_config(&self) -> KubeProxyConfiguration {
        let mut iptables = IptablesConfiguration::default();
        if self.proxy_mode == ProxyMode::IpTables {
            iptables.masquerade_all = true;
        }

        let nftables = NftablesConfiguration::default();
        let conntrack = self.effective_conntrack();

        KubeProxyConfiguration {
            api_version: "kubeproxy.config.k8s.io/v1alpha1".to_string(),
            kind: "KubeProxyConfiguration".to_string(),
            mode: self.proxy_mode.as_str().to_string(),
            cluster_cidr: self.cluster_cidr.clone(),
            healthz_bind_address: self.healthz_bind_address.clone(),
            metrics_bind_address: self.metrics_bind_address.clone(),
            oom_score_adj: Some(self.oom_score_adj),
            iptables,
            nftables,
            conntrack,
        }
    }
}
