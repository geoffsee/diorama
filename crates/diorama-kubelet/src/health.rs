use serde::{Deserialize, Serialize};

/// Health status and diagnostic report for the Kubelet service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubeletHealthReport {
    pub is_healthy: bool,
    pub node_name: String,
    pub node_ready: bool,
    pub runtime_endpoint: String,
    pub runtime_provider: String,
    pub cgroup_driver: String,
    pub active_pods: usize,
    pub message: Option<String>,
}

impl KubeletHealthReport {
    #[must_use]
    pub fn new_healthy(
        node_name: impl Into<String>,
        node_ready: bool,
        runtime_endpoint: impl Into<String>,
        runtime_provider: impl Into<String>,
        cgroup_driver: impl Into<String>,
        active_pods: usize,
    ) -> Self {
        Self {
            is_healthy: true,
            node_name: node_name.into(),
            node_ready,
            runtime_endpoint: runtime_endpoint.into(),
            runtime_provider: runtime_provider.into(),
            cgroup_driver: cgroup_driver.into(),
            active_pods,
            message: None,
        }
    }

    #[must_use]
    pub fn new_unhealthy(node_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            is_healthy: false,
            node_name: node_name.into(),
            node_ready: false,
            runtime_endpoint: String::new(),
            runtime_provider: String::new(),
            cgroup_driver: String::new(),
            active_pods: 0,
            message: Some(reason.into()),
        }
    }
}
