//! Kube-proxy configuration, backend selection, and supervised lifecycle.
//!
//! Provides configuration generation matching official upstream `kubeproxy.config.k8s.io/v1alpha1`,
//! automatic detection and selection between `iptables` and native `nftables` backends,
//! conntrack zeroing in container mode to accommodate read-only `/proc/sys` environments,
//! preservation of upstream host defaults, dataplane Service routing across `ClusterIP` and `NodePort`,
//! `EndpointSlice` dynamic synchronization, TCP/UDP workload probing, and integration with `diorama-supervisor`.

pub mod backend;
pub mod config;
pub mod dataplane;
pub mod error;
pub mod firewall;
pub mod health;
pub mod prober;
pub mod routing;
pub mod service;
pub mod supervisor;

pub use backend::{
    ProxyMode, check_sysctl_conntrack_writable, detect_proxy_backend, flush_nftables_nat,
};
pub use config::{
    ConntrackConfiguration, DEFAULT_CLUSTER_CIDR, DEFAULT_CONNTRACK_MAX_PER_CORE,
    DEFAULT_CONNTRACK_MIN, DEFAULT_CONNTRACK_TCP_CLOSE_WAIT_TIMEOUT,
    DEFAULT_CONNTRACK_TCP_ESTABLISHED_TIMEOUT, DEFAULT_CONNTRACK_UDP_STREAM_TIMEOUT,
    DEFAULT_CONNTRACK_UDP_TIMEOUT, DEFAULT_HEALTHZ_BIND_ADDRESS, DEFAULT_HEALTHZ_PORT,
    DEFAULT_METRICS_BIND_ADDRESS, DEFAULT_OOM_SCORE_ADJ, IptablesConfiguration,
    KubeProxyConfiguration, KubeProxyOptions, NftablesConfiguration,
};
pub use dataplane::{
    IptablesDataplane, IptablesRule, NftablesDataplane, NftablesRule, service_chain_hash,
};
pub use error::ProxyError;
pub use firewall::{
    DIORAMA_MASQ_NFT_TABLE, DataplaneReconciler, FirewallSnapshot, KUBE_PROXY_NFT_TABLE,
    ReconciliationSummary,
};
pub use health::ProxyHealthReport;
pub use prober::{DataplaneProbeReport, DataplaneProber, ProbeResult, WorkloadProbe};
pub use routing::{
    EndpointConditions, EndpointItem, EndpointPort, EndpointSliceDefinition, HostPortDefinition,
    HostPortKey, Protocol, ServiceDefinition, ServicePort, ServiceRoutingTable, ServiceType,
    TargetEndpoint, endpoint_slice_from_value, extract_namespace_and_name_from_key,
    host_ports_from_pod_value, service_from_value,
};
pub use service::ProxyService;
pub use supervisor::{COMPONENT_PROXY, DEFAULT_STARTUP_TIMEOUT, ProxyAdapter};
