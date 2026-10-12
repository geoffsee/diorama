use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use diorama_apiserver::{ApiserverError, KubernetesApiClient};
use serde_json::{Value, json};

use super::error::WebhookError;

#[async_trait]
pub trait LoadBalancerClient: Send + Sync {
    async fn get_service(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError>;
    async fn patch_service_status(
        &self,
        namespace: &str,
        name: &str,
        status: Value,
    ) -> Result<Value, ApiserverError>;
}

#[async_trait]
impl LoadBalancerClient for KubernetesApiClient {
    async fn get_service(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        self.get_service(namespace, name).await
    }

    async fn patch_service_status(
        &self,
        namespace: &str,
        name: &str,
        status: Value,
    ) -> Result<Value, ApiserverError> {
        self.patch_service_status(namespace, name, status).await
    }
}

#[async_trait]
impl<T: LoadBalancerClient + ?Sized> LoadBalancerClient for Arc<T> {
    async fn get_service(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        (**self).get_service(namespace, name).await
    }

    async fn patch_service_status(
        &self,
        namespace: &str,
        name: &str,
        status: Value,
    ) -> Result<Value, ApiserverError> {
        (**self).patch_service_status(namespace, name, status).await
    }
}

/// Updates the Service status with the external `LoadBalancer` IP, with exponential retry backoff.
///
/// Handles stale pre-commit reads where the type in storage hasn't yet transitioned
/// to `LoadBalancer`, transient get/patch failures, and skips redundant status updates
/// if the IP is already configured.
pub async fn update_load_balancer_status_with_retry(
    client: &dyn LoadBalancerClient,
    namespace: &str,
    name: &str,
    load_balancer_ip: &str,
    max_steps: usize,
    base_duration: Duration,
) -> Result<(), WebhookError> {
    let mut factor: u32 = 1;
    for step in 0..max_steps {
        let step_backoff = base_duration.saturating_mul(factor);
        factor = factor.saturating_mul(2);

        let svc_res = client.get_service(namespace, name).await;
        let Ok(svc) = svc_res else {
            if step + 1 < max_steps {
                tokio::time::sleep(step_backoff).await;
                continue;
            }
            return Err(WebhookError::StatusUpdateFailed {
                reason: "timed out waiting for the condition".to_string(),
            });
        };

        let svc_type = svc
            .pointer("/spec/type")
            .and_then(Value::as_str)
            .unwrap_or("");

        if svc_type != "LoadBalancer" {
            if step + 1 < max_steps {
                tokio::time::sleep(step_backoff).await;
                continue;
            }
            return Err(WebhookError::StatusUpdateFailed {
                reason: "timed out waiting for the condition".to_string(),
            });
        }

        let already_correct = svc
            .pointer("/status/loadBalancer/ingress")
            .and_then(Value::as_array)
            .is_some_and(|arr| {
                arr.iter()
                    .any(|entry| entry.get("ip").and_then(Value::as_str) == Some(load_balancer_ip))
            });

        if already_correct {
            return Ok(());
        }

        let resource_version = svc
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str);

        let mut patch_obj = json!({
            "status": {
                "loadBalancer": {
                    "ingress": [
                        {
                            "ip": load_balancer_ip
                        }
                    ]
                }
            }
        });
        if let Some(rv) = resource_version {
            patch_obj["metadata"] = json!({
                "resourceVersion": rv
            });
        }

        if client
            .patch_service_status(namespace, name, patch_obj)
            .await
            .is_ok()
        {
            return Ok(());
        }

        if step + 1 < max_steps {
            tokio::time::sleep(step_backoff).await;
        } else {
            return Err(WebhookError::StatusUpdateFailed {
                reason: "timed out waiting for the condition".to_string(),
            });
        }
    }

    Err(WebhookError::StatusUpdateFailed {
        reason: "timed out waiting for the condition".to_string(),
    })
}
