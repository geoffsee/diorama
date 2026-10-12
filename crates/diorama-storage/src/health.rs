use serde::{Deserialize, Serialize};

/// Health and readiness report for the local-path storage provisioner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPathHealthReport {
    /// True if storage is running and ready (or disabled).
    pub is_healthy: bool,

    /// Whether the `local-path-provisioner` deployment exists in the cluster.
    pub deployment_found: bool,

    /// Number of ready provisioner pod replicas.
    pub ready_replicas: i32,

    /// Desired replica count.
    pub desired_replicas: i32,

    /// Descriptive summary of provisioner health.
    pub message: String,
}
