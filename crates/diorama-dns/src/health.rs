use serde::{Deserialize, Serialize};

/// Health and readiness status report for the `CoreDNS` component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreDnsHealthReport {
    /// True if `CoreDNS` is running and at least one replica is ready.
    pub is_healthy: bool,
    /// Whether the `CoreDNS` deployment was found in the cluster.
    pub deployment_found: bool,
    /// Number of ready replicas observed.
    pub ready_replicas: i32,
    /// Desired replica count.
    pub desired_replicas: i32,
    /// Diagnostic or status message.
    pub message: String,
}
