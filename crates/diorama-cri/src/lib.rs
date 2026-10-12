//! Client bindings and external runtime attachment for the official Kubernetes v1.35.7 CRI v1 protocol.
//!
//! Regenerate protocol definitions with the `diorama-upstream` maintenance CLI; ordinary builds do not fetch inputs
//! or execute a protobuf compiler.

pub mod cgroup;
pub mod client;
pub mod consumer;
pub mod endpoint;
pub mod external;
pub mod ownership;
pub mod provider;
pub mod readiness;
pub mod workload;

pub use cgroup::{
    CgroupDriverSource, ResolvedCgroupDriver, detect_host_cgroup_driver,
    evaluate_host_cgroup_driver, negotiate_cgroup_driver, query_cgroup_driver,
};
pub use client::connect_unix;
pub use consumer::{CniConsumerSettings, KubeletConsumerSettings, NegotiatedRuntime};
pub use endpoint::{CriEndpoint, EndpointError, RuntimeEndpoints};
pub use external::{COMPONENT_EXTERNAL_CRI, ExternalRuntimeOptions, ExternalRuntimeService};
pub use ownership::{
    BuildAndRuntimeMatrix, BuildProfile, OwnershipViolation, RuntimeMode, RuntimeOwnershipPolicy,
    WorkloadScoping,
};
pub use provider::{CriProvider, ProviderInfo, detect_provider};
pub use readiness::{
    DEFAULT_READINESS_TIMEOUT, DEFAULT_RETRY_INTERVAL, ReadinessError, check_image_service,
    check_runtime_version, probe_cri_readiness,
};
pub use tonic;
pub use workload::{CriClient, image_spec};

pub mod runtime {
    // Preserve upstream protocol comments/boolean fields and tonic's nested RPC templates.
    // These four style exceptions apply only to deterministic generated source.
    #[allow(
        clippy::doc_lazy_continuation,
        clippy::doc_markdown,
        clippy::excessive_nesting,
        clippy::struct_excessive_bools
    )]
    pub mod v1 {
        include!("generated/runtime.v1.rs");
    }
}
