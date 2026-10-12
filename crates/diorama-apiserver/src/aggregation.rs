use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::admission::ServiceReference;
use crate::error::ApiserverError;
use crate::storage::KubernetesStorage;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct APIServiceSpec {
    pub group: String,
    pub version: String,
    #[serde(rename = "groupPriorityMinimum")]
    pub group_priority_minimum: i32,
    #[serde(rename = "versionPriority")]
    pub version_priority: i32,
    pub service: Option<ServiceReference>,
    #[serde(rename = "caBundle")]
    pub ca_bundle: Option<String>,
    #[serde(rename = "insecureSkipTLSVerify")]
    pub insecure_skip_tls_verify: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct APIService {
    pub metadata: BTreeMap<String, Value>,
    pub spec: APIServiceSpec,
}

#[derive(Clone, Debug)]
pub struct AggregatedRequestContext {
    pub path: String,
    pub method: String,
    pub caller_username: String,
    pub caller_groups: Vec<String>,
    pub body: Option<Value>,
}

#[async_trait]
pub trait AggregatedApiHandler: Send + Sync {
    async fn handle_request(&self, ctx: &AggregatedRequestContext)
    -> Result<Value, ApiserverError>;
}

struct RegisteredService {
    handler: Arc<dyn AggregatedApiHandler>,
    server_cert_pem: Option<String>,
}

#[derive(Clone, Default)]
pub struct AggregationManager {
    services: Arc<RwLock<BTreeMap<String, APIService>>>,
    endpoints: Arc<RwLock<BTreeMap<String, Arc<RegisteredService>>>>,
}

impl std::fmt::Debug for AggregationManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregationManager")
            .field(
                "services_count",
                &self.services.read().map_or(0, |s| s.len()),
            )
            .field(
                "endpoints_count",
                &self.endpoints.read().map_or(0, |e| e.len()),
            )
            .finish()
    }
}

/// Verifies the aggregated service TLS certificate against its `caBundle`.
fn verify_service_trust(
    service_name: &str,
    spec: &APIServiceSpec,
    endpoint: &RegisteredService,
) -> Result<(), ApiserverError> {
    if spec.insecure_skip_tls_verify == Some(true) {
        return Ok(());
    }

    let Some(ca_bundle_b64) = &spec.ca_bundle else {
        return Ok(());
    };

    let ca_bytes = diorama_pki::base64_decode(ca_bundle_b64).map_err(|e| {
        ApiserverError::InvalidCredentials {
            reason: format!("invalid base64 in APIService '{service_name}' caBundle: {e}"),
        }
    })?;

    let ca_pem =
        std::str::from_utf8(&ca_bytes).map_err(|e| ApiserverError::InvalidCredentials {
            reason: format!("invalid UTF-8 in APIService '{service_name}' caBundle: {e}"),
        })?;

    let Some(server_cert) = &endpoint.server_cert_pem else {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!(
                "APIService '{service_name}' expects TLS verification against caBundle, but endpoint provided no certificate"
            ),
        });
    };

    diorama_pki::verify_certificate_chain(server_cert, ca_pem).map_err(|e| {
        ApiserverError::InvalidCredentials {
            reason: format!(
                "APIService '{service_name}' server TLS certificate rejected by caBundle trust: {e}"
            ),
        }
    })?;

    Ok(())
}

impl AggregationManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_api_service(&self, service: APIService) {
        let name = service
            .metadata
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut guard = self.services.write().unwrap();
        guard.insert(name, service);
    }

    pub fn remove_api_service(&self, name: &str) -> Option<APIService> {
        let mut guard = self.services.write().unwrap();
        guard.remove(name)
    }

    pub fn get_api_service(&self, name: &str) -> Option<APIService> {
        let guard = self.services.read().unwrap();
        guard.get(name).cloned()
    }

    pub fn list_api_services(&self) -> Vec<APIService> {
        let guard = self.services.read().unwrap();
        guard.values().cloned().collect()
    }

    pub fn register_endpoint(
        &self,
        service_name: impl Into<String>,
        handler: Arc<dyn AggregatedApiHandler>,
        server_cert_pem: Option<String>,
    ) {
        let mut guard = self.endpoints.write().unwrap();
        guard.insert(
            service_name.into(),
            Arc::new(RegisteredService {
                handler,
                server_cert_pem,
            }),
        );
    }

    pub async fn dispatch(
        &self,
        service_name: &str,
        ctx: &AggregatedRequestContext,
    ) -> Result<Value, ApiserverError> {
        let service =
            self.get_api_service(service_name)
                .ok_or_else(|| ApiserverError::NotFound {
                    resource: "apiservices".to_string(),
                    name: service_name.to_string(),
                })?;

        let endpoint = {
            let guard = self.endpoints.read().unwrap();
            guard.get(service_name).cloned()
        };

        let Some(endpoint) = endpoint else {
            return Err(ApiserverError::AggregatedApiError {
                service: service_name.to_string(),
                reason: "no backend handler registered for aggregated service".to_string(),
            });
        };

        // Trust verification against caBundle
        verify_service_trust(service_name, &service.spec, &endpoint)?;

        // Invoke handler
        endpoint.handler.handle_request(ctx).await
    }

    /// Restores persisted `APIServices` from storage upon startup or restart.
    pub async fn restore_from_storage(
        &self,
        storage: &KubernetesStorage,
    ) -> Result<(), ApiserverError> {
        let prefix = format!("{}/apiservices", storage.prefix());
        let kvs = storage.list(&prefix).await?;
        for kv in kvs {
            let api_service: APIService = serde_json::from_slice(&kv.value)?;
            self.register_api_service(api_service);
        }
        Ok(())
    }
}
