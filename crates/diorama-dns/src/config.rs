use serde::{Deserialize, Serialize};

/// Standard namespace where cluster DNS infrastructure resides.
pub const COREDNS_NAMESPACE: &str = "kube-system";

/// Standard `CoreDNS` service name expected by cluster workloads and kubelet.
pub const COREDNS_SERVICE_NAME: &str = "kube-dns";

/// Standard `CoreDNS` `ConfigMap` name holding the Corefile.
pub const COREDNS_CONFIGMAP_NAME: &str = "coredns";

/// Standard `CoreDNS` `Deployment` name.
pub const COREDNS_DEPLOYMENT_NAME: &str = "coredns";

/// Standard `CoreDNS` `ServiceAccount` name.
pub const COREDNS_SERVICE_ACCOUNT_NAME: &str = "coredns";

/// Standard `CoreDNS` `ClusterRole` and `ClusterRoleBinding` name.
pub const COREDNS_CLUSTER_ROLE_NAME: &str = "system:coredns";

/// Default cluster DNS service IPv4 address.
pub const DEFAULT_COREDNS_IP: &str = "10.43.0.10";

/// Default upstream `CoreDNS` image reference.
pub const DEFAULT_COREDNS_IMAGE: &str = "docker.io/coredns/coredns:1.14.4";

/// Default cluster domain.
pub const DEFAULT_CLUSTER_DOMAIN: &str = "cluster.local";

/// Configuration parameters for `CoreDNS` resource generation and reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreDnsConfig {
    /// Whether running in a containerized environment (e.g. docker-in-docker).
    ///
    /// In container mode:
    /// - Memory limits are omitted on the `CoreDNS` deployment to avoid OOM in constrained environments.
    /// - Public resolvers (`1.1.1.1 8.8.8.8`) are used unless `upstream_resolvers` is set.
    pub container_mode: bool,

    /// Whether IPv6 support is disabled on the cluster.
    ///
    /// When true, `CoreDNS` omits `ip6.arpa` reverse-zone forwarding, serving only `in-addr.arpa`.
    pub disable_ipv6: bool,

    /// `ClusterIP` assigned to the `kube-dns` service. Defaults to `10.43.0.10`.
    pub dns_ip: String,

    /// Container image reference for `CoreDNS`. Defaults to `docker.io/coredns/coredns:1.14.4`.
    pub image: String,

    /// Cluster domain suffix. Defaults to `cluster.local`.
    pub cluster_domain: String,

    /// Explicit upstream resolvers to forward queries to. If empty, defaults according to `container_mode`.
    pub upstream_resolvers: Vec<String>,

    /// Timeout for waiting for `CoreDNS` pods to become ready. Defaults to 90 seconds.
    pub readiness_timeout: std::time::Duration,
}

impl Default for CoreDnsConfig {
    fn default() -> Self {
        Self {
            container_mode: false,
            disable_ipv6: false,
            dns_ip: DEFAULT_COREDNS_IP.to_string(),
            image: DEFAULT_COREDNS_IMAGE.to_string(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            upstream_resolvers: Vec::new(),
            readiness_timeout: std::time::Duration::from_secs(90),
        }
    }
}

impl CoreDnsConfig {
    /// Create a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set container mode.
    #[must_use]
    pub fn with_container_mode(mut self, container_mode: bool) -> Self {
        self.container_mode = container_mode;
        self
    }

    /// Set `disable_ipv6` flag.
    #[must_use]
    pub fn with_disable_ipv6(mut self, disable_ipv6: bool) -> Self {
        self.disable_ipv6 = disable_ipv6;
        self
    }

    /// Set custom DNS `ClusterIP` address.
    #[must_use]
    pub fn with_dns_ip(mut self, dns_ip: impl Into<String>) -> Self {
        self.dns_ip = dns_ip.into();
        self
    }

    /// Set custom `CoreDNS` container image.
    #[must_use]
    pub fn with_image(mut self, image: impl Into<String>) -> Self {
        self.image = image.into();
        self
    }

    /// Set custom cluster domain.
    #[must_use]
    pub fn with_cluster_domain(mut self, cluster_domain: impl Into<String>) -> Self {
        self.cluster_domain = cluster_domain.into();
        self
    }

    /// Set explicit upstream resolvers.
    #[must_use]
    pub fn with_upstream_resolvers(mut self, resolvers: Vec<String>) -> Self {
        self.upstream_resolvers = resolvers;
        self
    }

    /// Set readiness polling timeout.
    #[must_use]
    pub fn with_readiness_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.readiness_timeout = timeout;
        self
    }

    /// Generate the exact Corefile text matching upstream `KubeSolo` contract.
    #[must_use]
    pub fn generate_corefile(&self) -> String {
        let forward = if !self.upstream_resolvers.is_empty() {
            format!("forward . {}", self.upstream_resolvers.join(" "))
        } else if self.container_mode {
            "forward . 1.1.1.1 8.8.8.8".to_string()
        } else {
            "forward . /etc/resolv.conf".to_string()
        };

        let domain = &self.cluster_domain;

        if self.disable_ipv6 {
            format!(
                ".:53 {{\n\terrors\n\tloop\n\tcache 30 {{\n\t\tdisable denial {domain}\n\t}}\n\tkubernetes {domain} in-addr.arpa {{\n\t\tpods insecure\n\t\tfallthrough in-addr.arpa\n\t\tttl 30\n\t}}\n\t{forward}\n\tminimal\n\treload\n\thealth :8080\n\tready :8181\n}}"
            )
        } else {
            format!(
                ".:53 {{\n\terrors\n\tloop\n\tcache 30 {{\n\t\tdisable denial {domain}\n\t}}\n\tkubernetes {domain} in-addr.arpa ip6.arpa {{\n\t\tpods insecure\n\t\tfallthrough in-addr.arpa ip6.arpa\n\t\tttl 30\n\t}}\n\t{forward}\n\tminimal\n\treload\n\thealth :8080\n\tready :8181\n}}"
            )
        }
    }
}
