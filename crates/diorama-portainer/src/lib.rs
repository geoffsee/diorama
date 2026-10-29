#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! diorama Portainer Edge Agent bootstrap and lifecycle management crate.
//!
//! This crate provides configuration types, Kubernetes manifest generators,
//! create-only bootstrap reconciliation, and supervisor lifecycle management
//! for the Portainer Edge Agent in `diorama`.

/// Configuration types and constants for Portainer Edge agent.
pub mod config;
/// Error types for Portainer Edge agent manifest generation and deployment.
pub mod error;
/// Kubernetes manifest generation for Portainer Edge agent.
pub mod manifests;
/// Create-only reconciliation for Portainer Edge agent resources.
pub mod reconciler;
/// Portainer service lifecycle management.
pub mod service;
/// Supervisor adapter for Portainer Edge agent.
pub mod supervisor;

pub use config::{
    CLUSTER_ADMIN_CLUSTER_ROLE_NAME, DEFAULT_EDGE_INSECURE_POLL, DEFAULT_PORTAINER_AGENT_IMAGE,
    DEFAULT_READINESS_TIMEOUT, PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME,
    PORTAINER_AGENT_CONFIGMAP_NAME, PORTAINER_AGENT_DEPLOYMENT_NAME, PORTAINER_AGENT_PORT_EDGE,
    PORTAINER_AGENT_PORT_HTTP, PORTAINER_AGENT_SECRET_NAME, PORTAINER_AGENT_SERVICE_ACCOUNT_NAME,
    PORTAINER_AGENT_SERVICE_NAME, PORTAINER_NAMESPACE, PortainerAgentConfig,
};
pub use error::{PortainerError, Result};
pub use manifests::PortainerManifests;
pub use reconciler::{PortainerReconciler, PortainerReconciliationReport};
pub use service::PortainerService;
pub use supervisor::{COMPONENT_PORTAINER, DEFAULT_STARTUP_TIMEOUT, PortainerAdapter};
