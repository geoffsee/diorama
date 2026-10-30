/// Kubernetes release reported by `/version` and the node `kubeletVersion`.
/// Sonobuoy selects `registry.k8s.io/conformance:<version>` from that value.
pub const KUBERNETES_VERSION: &str = "v1.37.1";

pub mod admission;
pub mod aggregation;
pub mod client;
pub mod config;
pub mod error;
pub mod exec;
pub mod health;
mod http;
pub mod logs;
pub mod openapi;
pub mod pdb;
pub mod peer_proxy;
pub mod pki;
pub mod quota;
pub mod rbac;
pub mod service;
pub mod storage;
pub mod supervisor;
pub mod time;
pub mod token;

pub use admission::{
    AdmissionEngine, AdmissionRequest, AdmissionResponse, AdmissionStatus, FailurePolicy,
    MutatingWebhookConfiguration, RuleWithOperations, ValidatingWebhookConfiguration,
    WebhookClientConfig, WebhookDefinition, WebhookHandler,
};
pub use aggregation::{
    APIService, APIServiceSpec, AggregatedApiHandler, AggregatedRequestContext, AggregationManager,
};
pub use client::{
    ClientIdentity, KubernetesApiClient, WatchEvent, WatchEventType, WatchReceiver,
    json_merge_patch, json_rfc7396_merge_patch,
};
pub use config::{
    ApiserverConfig, DEFAULT_ETCD_PREFIX, DEFAULT_SA_ISSUER, DEFAULT_SECURE_PORT,
    DEFAULT_SERVICE_CLUSTER_IP_RANGE, DEFAULT_SERVICE_NODE_PORT_RANGE, parse_ipv4_cidr,
    parse_port_range,
};
pub use error::ApiserverError;
pub use exec::{PodExec, PodExecOptions, PodExecResult};
pub use health::{HealthReport, check_apiserver_readiness};
pub use logs::{PodLogOptions, PodLogReader};
pub use peer_proxy::{
    ClusterPodRouter, DEFAULT_KUBELET_QUIC_PORT, RemoteExecRequest, RemoteExecResponse,
    RemoteLogRequest, RemoteLogResponse,
};
pub use pki::validate_pki_prerequisites;
pub use rbac::{
    ClusterRole, ClusterRoleBinding, PolicyRule, RbacAuthorizer, Role, RoleBinding, Subject,
};
pub use service::ApiserverService;
pub use storage::KubernetesStorage;
pub use supervisor::{ApiserverAdapter, COMPONENT_APISERVER, DEFAULT_STARTUP_TIMEOUT};
pub use token::{ServiceAccountClaims, TokenService};
