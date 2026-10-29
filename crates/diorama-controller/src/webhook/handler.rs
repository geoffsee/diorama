use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use diorama_apiserver::{AdmissionRequest, AdmissionResponse, ApiserverError, WebhookHandler};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use super::loadbalancer::{LoadBalancerClient, update_load_balancer_status_with_retry};

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub scheduled_status_update: bool,
}

#[derive(Clone)]
pub struct NodeSetterHandler {
    node_name: String,
    load_balancer_ip: String,
    load_balancer: bool,
    load_balancer_update_locks: Arc<Mutex<HashSet<String>>>,
    client: Arc<tokio::sync::RwLock<Option<Arc<dyn LoadBalancerClient>>>>,
    max_steps: usize,
    base_duration: std::time::Duration,
    lock_release_delay: std::time::Duration,
}

impl std::fmt::Debug for NodeSetterHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeSetterHandler")
            .field("node_name", &self.node_name)
            .field("load_balancer_ip", &self.load_balancer_ip)
            .field("load_balancer", &self.load_balancer)
            .field("max_steps", &self.max_steps)
            .field("base_duration", &self.base_duration)
            .field("lock_release_delay", &self.lock_release_delay)
            .finish_non_exhaustive()
    }
}

impl NodeSetterHandler {
    #[must_use]
    pub fn new(node_name: &str, load_balancer_ip: &str, load_balancer: bool) -> Self {
        Self {
            node_name: node_name.to_string(),
            load_balancer_ip: load_balancer_ip.to_string(),
            load_balancer,
            load_balancer_update_locks: Arc::new(Mutex::new(HashSet::new())),
            client: Arc::new(tokio::sync::RwLock::new(None)),
            max_steps: 5,
            base_duration: std::time::Duration::from_millis(50),
            lock_release_delay: std::time::Duration::from_millis(100),
        }
    }

    #[must_use]
    pub fn with_client(self, client: Arc<dyn LoadBalancerClient>) -> Self {
        Self {
            client: Arc::new(tokio::sync::RwLock::new(Some(client))),
            ..self
        }
    }

    #[must_use]
    pub fn with_retry_params(
        mut self,
        max_steps: usize,
        base_duration: std::time::Duration,
        lock_release_delay: std::time::Duration,
    ) -> Self {
        self.max_steps = max_steps;
        self.base_duration = base_duration;
        self.lock_release_delay = lock_release_delay;
        self
    }

    #[must_use]
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    #[must_use]
    pub fn load_balancer_ip(&self) -> &str {
        &self.load_balancer_ip
    }

    #[must_use]
    pub fn load_balancer(&self) -> bool {
        self.load_balancer
    }

    #[must_use]
    pub fn locks(&self) -> &Arc<Mutex<HashSet<String>>> {
        &self.load_balancer_update_locks
    }

    /// Evaluates mutation patches for a given `AdmissionReview` request object.
    #[allow(clippy::too_many_lines)]
    pub async fn evaluate_mutation(
        &self,
        request: &Value,
    ) -> Result<(Option<String>, bool), String> {
        let kind = request
            .get("kind")
            .and_then(|k| k.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let object = request.get("object");

        match kind {
            "Service" => {
                let dry_run = request
                    .get("dryRun")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

                if dry_run || !self.load_balancer || self.load_balancer_ip.is_empty() {
                    return Ok((None, false));
                }

                let Some(obj) = object else {
                    return Ok((None, false));
                };

                let svc_type = obj
                    .get("spec")
                    .and_then(|s| s.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("");

                if svc_type != "LoadBalancer" {
                    return Ok((None, false));
                }

                let name = obj
                    .get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let namespace = obj
                    .get("metadata")
                    .and_then(|m| m.get("namespace"))
                    .and_then(Value::as_str)
                    .unwrap_or("default");

                let key = format!("{namespace}/{name}");
                let mut locks = self.load_balancer_update_locks.lock().await;
                let scheduled = locks.insert(key.clone());
                drop(locks);

                if scheduled {
                    let client_opt = self.client.read().await.clone();
                    if let Some(client) = client_opt {
                        self.spawn_load_balancer_update(client, namespace, name, key);
                    }
                }

                Ok((None, scheduled))
            },
            _ => Ok((None, false)),
        }
    }

    fn spawn_load_balancer_update(
        &self,
        client: Arc<dyn LoadBalancerClient>,
        namespace: &str,
        name: &str,
        lock_key: String,
    ) {
        let handler = self.clone();
        let ns = namespace.to_string();
        let n = name.to_string();
        tokio::spawn(async move {
            if let Err(e) = update_load_balancer_status_with_retry(
                &*client,
                &ns,
                &n,
                &handler.load_balancer_ip,
                handler.max_steps,
                handler.base_duration,
            )
            .await
            {
                eprintln!("[{}] {ns}/{n}: {e}", e.diagnostic_code());
            }

            if !handler.lock_release_delay.is_zero() {
                tokio::time::sleep(handler.lock_release_delay).await;
            }
            handler
                .load_balancer_update_locks
                .lock()
                .await
                .remove(&lock_key);
        });
    }

    /// Handles an incoming HTTP request and returns an `HttpResponse`.
    pub async fn handle_http_request(&self, method: &str, path: &str, body: &[u8]) -> HttpResponse {
        if path == "/healthz" || path == "/readyz" {
            return HttpResponse {
                status: 200,
                content_type: "text/plain; charset=utf-8",
                body: b"ok\n".to_vec(),
                scheduled_status_update: false,
            };
        }

        if method != "POST" {
            return HttpResponse {
                status: 405,
                content_type: "text/plain; charset=utf-8",
                body: b"method not allowed\n".to_vec(),
                scheduled_status_update: false,
            };
        }

        if path != "/mutate" {
            return HttpResponse {
                status: 404,
                content_type: "text/plain; charset=utf-8",
                body: b"not found\n".to_vec(),
                scheduled_status_update: false,
            };
        }

        let review_json: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                return HttpResponse {
                    status: 400,
                    content_type: "text/plain; charset=utf-8",
                    body: b"error decoding admission review: couldn't get version/kind; json parse error: unexpected end of JSON input\n".to_vec(),
                    scheduled_status_update: false,
                };
            },
        };

        let Some(request) = review_json.get("request") else {
            return HttpResponse {
                status: 400,
                content_type: "text/plain; charset=utf-8",
                body: b"admission review with no request\n".to_vec(),
                scheduled_status_update: false,
            };
        };

        let uid = request
            .get("uid")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let (patch_opt, scheduled) = match self.evaluate_mutation(request).await {
            Ok(res) => res,
            Err(e) => {
                let err_review = json!({
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": uid,
                        "allowed": false,
                        "result": {
                            "message": e,
                        }
                    }
                });
                let resp_body = serde_json::to_vec(&err_review).unwrap_or_default();
                return HttpResponse {
                    status: 200,
                    content_type: "application/json",
                    body: resp_body,
                    scheduled_status_update: false,
                };
            },
        };

        let mut response_obj = json!({
            "uid": uid,
            "allowed": true,
        });

        if let Some(patch_b64) = patch_opt {
            response_obj["patch"] = json!(patch_b64);
            response_obj["patchType"] = json!("JSONPatch");
        }

        let resp_review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": request,
            "response": response_obj,
        });

        let resp_body = serde_json::to_vec(&resp_review).unwrap_or_default();
        HttpResponse {
            status: 200,
            content_type: "application/json",
            body: resp_body,
            scheduled_status_update: scheduled,
        }
    }
}

#[async_trait]
impl WebhookHandler for NodeSetterHandler {
    async fn handle(&self, req: &AdmissionRequest) -> Result<AdmissionResponse, ApiserverError> {
        let req_json = serde_json::to_value(req).map_err(|e| ApiserverError::Internal {
            reason: format!("failed to serialize admission request: {e}"),
        })?;

        let (patch_opt, _) = self.evaluate_mutation(&req_json).await.map_err(|reason| {
            ApiserverError::WebhookFailure {
                webhook: "webhook.kubesolo.io".to_string(),
                reason,
            }
        })?;

        if let Some(patch_b64) = patch_opt {
            Ok(AdmissionResponse {
                uid: req.uid.clone(),
                allowed: true,
                status: None,
                patch: Some(patch_b64),
                patch_type: Some("JSONPatch".to_string()),
            })
        } else {
            Ok(AdmissionResponse::allow(req.uid.clone()))
        }
    }
}
