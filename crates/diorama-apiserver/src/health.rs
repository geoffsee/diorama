use std::collections::BTreeMap;
use std::time::Duration;

use crate::config::ApiserverConfig;
use crate::error::ApiserverError;
use crate::pki::validate_pki_prerequisites;
use crate::storage::KubernetesStorage;

pub const DEFAULT_HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthReport {
    pub is_healthy: bool,
    pub checks: BTreeMap<String, String>,
}

impl HealthReport {
    #[must_use]
    pub fn ok() -> Self {
        let mut checks = BTreeMap::new();
        checks.insert("ping".to_string(), "ok".to_string());
        checks.insert("etcd".to_string(), "ok".to_string());
        checks.insert("pki".to_string(), "ok".to_string());
        checks.insert(
            "poststarthook/start-kube-apiserver-admission-initializer".to_string(),
            "ok".to_string(),
        );
        Self {
            is_healthy: true,
            checks,
        }
    }

    #[must_use]
    pub fn failed(failed_check: &str, reason: &str) -> Self {
        let mut checks = BTreeMap::new();
        checks.insert(failed_check.to_string(), format!("failed: {reason}"));
        Self {
            is_healthy: false,
            checks,
        }
    }
}

/// Evaluates API server readiness across storage and credentials.
pub async fn check_apiserver_readiness(
    config: &ApiserverConfig,
    storage: &KubernetesStorage,
) -> Result<HealthReport, ApiserverError> {
    // 1. Verify PKI prerequisites
    if let Err(e) = validate_pki_prerequisites(config) {
        return Ok(HealthReport::failed("pki", &e.to_string()));
    }

    // 2. Verify Datastore storage readiness
    if let Err(e) = storage.check_health().await {
        return Ok(HealthReport::failed("etcd", &e.to_string()));
    }

    Ok(HealthReport::ok())
}
