pub mod config;
pub mod error;
pub mod health;
pub mod manifests;
pub mod mock_server;
pub mod probe;
pub mod reconciler;
pub mod service;
pub mod supervisor;
pub mod wire;

pub use config::{
    COREDNS_CLUSTER_ROLE_NAME, COREDNS_CONFIGMAP_NAME, COREDNS_DEPLOYMENT_NAME, COREDNS_NAMESPACE,
    COREDNS_SERVICE_ACCOUNT_NAME, COREDNS_SERVICE_NAME, CoreDnsConfig, DEFAULT_CLUSTER_DOMAIN,
    DEFAULT_COREDNS_IMAGE, DEFAULT_COREDNS_IP,
};
pub use error::{DnsError, Result};
pub use health::CoreDnsHealthReport;
pub use manifests::{
    CoreDnsManifests, coredns_labels, coredns_selector, generate_cluster_role,
    generate_cluster_role_binding, generate_config_map, generate_config_map_patch,
    generate_deployment, generate_service, generate_service_account, should_recreate_service,
};
pub use mock_server::LocalDnsServer;
pub use probe::{
    DnsProbeResult, DnsProber, DnsProtocol, DnsResolutionProbe, DnsResolutionReport, ProbeCategory,
    ProbeTransport,
};
pub use reconciler::{DnsReconciler, ReconciliationReport};
pub use service::CoreDnsService;
pub use supervisor::{COMPONENT_COREDNS, CoreDnsAdapter, DEFAULT_STARTUP_TIMEOUT};
pub use wire::{
    DnsAnswer, DnsHeader, DnsMessage, DnsQuestion, DnsRcode, DnsRecordData, DnsRecordType,
};
