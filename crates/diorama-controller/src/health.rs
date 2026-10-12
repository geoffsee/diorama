use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerHealthReport {
    pub is_healthy: bool,
    pub authenticated: bool,
    pub apiserver_connected: bool,
    pub configured_controllers: Vec<String>,
    pub active_controllers: Vec<String>,
    pub details: BTreeMap<String, String>,
}

impl ControllerHealthReport {
    #[must_use]
    pub fn new_healthy(
        configured_controllers: Vec<String>,
        active_controllers: Vec<String>,
    ) -> Self {
        let mut details = BTreeMap::new();
        details.insert("status".to_string(), "ok".to_string());
        details.insert(
            "configured_controllers_count".to_string(),
            configured_controllers.len().to_string(),
        );
        details.insert(
            "active_controllers_count".to_string(),
            active_controllers.len().to_string(),
        );

        Self {
            is_healthy: true,
            authenticated: true,
            apiserver_connected: true,
            configured_controllers,
            active_controllers,
            details,
        }
    }

    #[must_use]
    pub fn new_unhealthy(reason: impl Into<String>) -> Self {
        let mut details = BTreeMap::new();
        details.insert("error".to_string(), reason.into());

        Self {
            is_healthy: false,
            authenticated: false,
            apiserver_connected: false,
            configured_controllers: Vec::new(),
            active_controllers: Vec::new(),
            details,
        }
    }
}
