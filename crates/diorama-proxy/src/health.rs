use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::backend::ProxyMode;

pub const DEFAULT_HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_RETRY_COUNT: usize = 3;

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyHealthReport {
    pub is_healthy: bool,
    pub proxy_mode: ProxyMode,
    pub container_mode: bool,
    pub all_conntrack_zero: bool,
    pub snat_ready: bool,
    pub startup_ready: bool,
    pub dataplane_ready: bool,
    pub details: BTreeMap<String, String>,
}

impl ProxyHealthReport {
    #[must_use]
    pub fn new_healthy(
        proxy_mode: ProxyMode,
        container_mode: bool,
        all_conntrack_zero: bool,
        snat_ready: bool,
    ) -> Self {
        let mut details = BTreeMap::new();
        details.insert("status".to_string(), "ok".to_string());
        details.insert("mode".to_string(), proxy_mode.to_string());
        details.insert("container_mode".to_string(), container_mode.to_string());
        details.insert(
            "all_conntrack_zero".to_string(),
            all_conntrack_zero.to_string(),
        );
        details.insert("snat_ready".to_string(), snat_ready.to_string());
        details.insert("startup_ready".to_string(), "true".to_string());
        details.insert("dataplane_ready".to_string(), "false".to_string());

        Self {
            is_healthy: true,
            proxy_mode,
            container_mode,
            all_conntrack_zero,
            snat_ready,
            startup_ready: true,
            dataplane_ready: false,
            details,
        }
    }

    #[must_use]
    pub fn with_dataplane_ready(mut self, ready: bool, status_message: impl Into<String>) -> Self {
        self.dataplane_ready = ready;
        self.details
            .insert("dataplane_ready".to_string(), ready.to_string());
        self.details
            .insert("dataplane_status".to_string(), status_message.into());
        self
    }

    #[must_use]
    pub fn new_unhealthy(
        proxy_mode: ProxyMode,
        container_mode: bool,
        reason: impl Into<String>,
    ) -> Self {
        let mut details = BTreeMap::new();
        details.insert("error".to_string(), reason.into());

        Self {
            is_healthy: false,
            proxy_mode,
            container_mode,
            all_conntrack_zero: false,
            snat_ready: false,
            startup_ready: false,
            dataplane_ready: false,
            details,
        }
    }
}
