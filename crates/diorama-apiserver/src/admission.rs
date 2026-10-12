use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ApiserverError;
use crate::storage::KubernetesStorage;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailurePolicy {
    #[serde(rename = "Fail")]
    #[default]
    Fail,
    #[serde(rename = "Ignore")]
    Ignore,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceReference {
    pub namespace: String,
    pub name: String,
    pub path: Option<String>,
    pub port: Option<i32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebhookClientConfig {
    pub url: Option<String>,
    pub service: Option<ServiceReference>,
    #[serde(rename = "caBundle")]
    pub ca_bundle: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleWithOperations {
    pub operations: Vec<String>,
    #[serde(rename = "apiGroups")]
    pub api_groups: Vec<String>,
    #[serde(rename = "apiVersions")]
    pub api_versions: Vec<String>,
    pub resources: Vec<String>,
    pub scope: Option<String>,
}

impl RuleWithOperations {
    #[must_use]
    pub fn matches(&self, op: &str, group: &str, version: &str, resource: &str) -> bool {
        let op_match = self
            .operations
            .iter()
            .any(|o| o == "*" || o.eq_ignore_ascii_case(op));
        let group_match = self.api_groups.iter().any(|g| g == "*" || g == group);
        let version_match = self.api_versions.iter().any(|v| v == "*" || v == version);
        let res_match = self.resources.iter().any(|r| r == "*" || r == resource);

        op_match && group_match && version_match && res_match
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookDefinition {
    pub name: String,
    pub rules: Vec<RuleWithOperations>,
    #[serde(rename = "clientConfig")]
    pub client_config: WebhookClientConfig,
    #[serde(default, rename = "failurePolicy")]
    pub failure_policy: FailurePolicy,
    #[serde(
        default,
        rename = "sideEffects",
        skip_serializing_if = "Option::is_none"
    )]
    pub side_effects: Option<String>,
    #[serde(rename = "timeoutSeconds")]
    pub timeout_seconds: Option<u32>,
    #[serde(default, rename = "admissionReviewVersions")]
    pub admission_review_versions: Vec<String>,
    #[serde(
        default,
        rename = "reinvocationPolicy",
        skip_serializing_if = "Option::is_none"
    )]
    pub reinvocation_policy: Option<String>,
}

impl WebhookDefinition {
    #[must_use]
    pub fn matches_request(&self, req: &AdmissionRequest) -> bool {
        self.rules.iter().any(|r| {
            r.matches(
                &req.operation,
                &req.resource.group,
                &req.resource.version,
                &req.resource.resource,
            )
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatingWebhookConfiguration {
    pub metadata: BTreeMap<String, Value>,
    pub webhooks: Vec<WebhookDefinition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutatingWebhookConfiguration {
    pub metadata: BTreeMap<String, Value>,
    pub webhooks: Vec<WebhookDefinition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupVersionKind {
    pub group: String,
    pub version: String,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupVersionResource {
    pub group: String,
    pub version: String,
    pub resource: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub uid: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionRequest {
    pub uid: String,
    pub kind: GroupVersionKind,
    pub resource: GroupVersionResource,
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub operation: String,
    #[serde(rename = "userInfo")]
    pub user_info: UserInfo,
    pub object: Option<Value>,
    #[serde(rename = "oldObject")]
    pub old_object: Option<Value>,
    #[serde(rename = "dryRun")]
    pub dry_run: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionStatus {
    pub code: Option<u16>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionResponse {
    pub uid: String,
    pub allowed: bool,
    pub status: Option<AdmissionStatus>,
    pub patch: Option<String>,
    #[serde(rename = "patchType")]
    pub patch_type: Option<String>,
}

impl AdmissionResponse {
    #[must_use]
    pub fn allow(uid: impl Into<String>) -> Self {
        Self {
            uid: uid.into(),
            allowed: true,
            status: None,
            patch: None,
            patch_type: None,
        }
    }

    #[must_use]
    pub fn deny(uid: impl Into<String>, code: u16, message: impl Into<String>) -> Self {
        Self {
            uid: uid.into(),
            allowed: false,
            status: Some(AdmissionStatus {
                code: Some(code),
                message: Some(message.into()),
            }),
            patch: None,
            patch_type: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdmissionReview {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub request: Option<AdmissionRequest>,
    pub response: Option<AdmissionResponse>,
}

#[async_trait]
pub trait WebhookHandler: Send + Sync {
    async fn handle(&self, req: &AdmissionRequest) -> Result<AdmissionResponse, ApiserverError>;
}

struct RegisteredEndpoint {
    handler: Arc<dyn WebhookHandler>,
    server_cert_pem: Option<String>,
}

#[derive(Clone, Default)]
pub struct AdmissionEngine {
    mutating_configs: Arc<RwLock<Vec<MutatingWebhookConfiguration>>>,
    validating_configs: Arc<RwLock<Vec<ValidatingWebhookConfiguration>>>,
    endpoints: Arc<RwLock<BTreeMap<String, Arc<RegisteredEndpoint>>>>,
}

impl std::fmt::Debug for AdmissionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionEngine")
            .field(
                "mutating_configs_count",
                &self.mutating_configs.read().map_or(0, |c| c.len()),
            )
            .field(
                "validating_configs_count",
                &self.validating_configs.read().map_or(0, |c| c.len()),
            )
            .field(
                "endpoints_count",
                &self.endpoints.read().map_or(0, |e| e.len()),
            )
            .finish()
    }
}

fn find_endpoint(
    endpoints: &BTreeMap<String, Arc<RegisteredEndpoint>>,
    webhook: &WebhookDefinition,
) -> Option<Arc<RegisteredEndpoint>> {
    if let Some(ep) = endpoints.get(&webhook.name) {
        return Some(ep.clone());
    }
    if let Some(svc) = &webhook.client_config.service
        && let Some(ep) = endpoints.get(&svc.name)
    {
        return Some(ep.clone());
    }
    if let Some(url_str) = &webhook.client_config.url {
        if let Some(ep) = endpoints.get(url_str) {
            return Some(ep.clone());
        }
        let stripped = url_str
            .strip_prefix("https://")
            .or_else(|| url_str.strip_prefix("http://"));
        if let Some(host_part) = stripped {
            let host_name = host_part.split(['/', ':']).next().unwrap_or(host_part);
            if let Some(ep) = endpoints.get(host_name) {
                return Some(ep.clone());
            }
        }
    }
    None
}

/// Verifies the webhook endpoint's TLS certificate against the `ca_bundle` if present.
fn verify_webhook_trust(
    webhook_name: &str,
    client_config: &WebhookClientConfig,
    endpoint: &RegisteredEndpoint,
) -> Result<(), ApiserverError> {
    let Some(ca_bundle_b64) = &client_config.ca_bundle else {
        return Ok(());
    };

    let ca_bytes = diorama_pki::base64_decode(ca_bundle_b64).map_err(|e| {
        ApiserverError::InvalidCredentials {
            reason: format!("invalid base64 in webhook '{webhook_name}' caBundle: {e}"),
        }
    })?;

    let ca_pem =
        std::str::from_utf8(&ca_bytes).map_err(|e| ApiserverError::InvalidCredentials {
            reason: format!("invalid UTF-8 in webhook '{webhook_name}' caBundle: {e}"),
        })?;

    let Some(server_cert) = &endpoint.server_cert_pem else {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!(
                "webhook '{webhook_name}' expects TLS verification against caBundle, but endpoint provided no certificate"
            ),
        });
    };

    diorama_pki::verify_certificate_chain(server_cert, ca_pem).map_err(|e| {
        ApiserverError::InvalidCredentials {
            reason: format!(
                "webhook '{webhook_name}' server TLS certificate rejected by caBundle trust: {e}"
            ),
        }
    })?;

    Ok(())
}

async fn dispatch_single_webhook(
    webhook: &WebhookDefinition,
    endpoint: &RegisteredEndpoint,
    req: &AdmissionRequest,
) -> Result<AdmissionResponse, ApiserverError> {
    verify_webhook_trust(&webhook.name, &webhook.client_config, endpoint).map_err(|err| {
        ApiserverError::WebhookFailure {
            webhook: webhook.name.clone(),
            reason: format!("TLS certificate chain verification failed: {err}"),
        }
    })?;

    endpoint.handler.handle(req).await.map_err(|err| match err {
        ApiserverError::WebhookFailure { .. } => err,
        other => ApiserverError::WebhookFailure {
            webhook: webhook.name.clone(),
            reason: other.to_string(),
        },
    })
}

async fn apply_mutating_webhook(
    webhook: &WebhookDefinition,
    endpoint: Option<&RegisteredEndpoint>,
    req: &mut AdmissionRequest,
) -> Result<(), ApiserverError> {
    let Some(endpoint) = endpoint else {
        if webhook.failure_policy == FailurePolicy::Fail {
            return Err(ApiserverError::WebhookFailure {
                webhook: webhook.name.clone(),
                reason: "webhook endpoint handler not registered".to_string(),
            });
        }
        return Ok(());
    };

    let response = match dispatch_single_webhook(webhook, endpoint, req).await {
        Ok(resp) => resp,
        Err(err) => {
            if webhook.failure_policy == FailurePolicy::Fail {
                return Err(err);
            }
            return Ok(());
        },
    };

    if !response.allowed {
        let msg = response
            .status
            .and_then(|s| s.message)
            .unwrap_or_else(|| format!("admission denied by webhook '{}'", webhook.name));
        return Err(ApiserverError::AdmissionDenied { reason: msg });
    }

    if let Some(patch_b64) = response.patch
        && let Some(obj) = &mut req.object
    {
        let patch_bytes =
            diorama_pki::base64_decode(&patch_b64).map_err(|e| ApiserverError::InvalidInput {
                field: "patch".to_string(),
                reason: format!(
                    "failed to decode base64 JSON patch from {}: {e}",
                    webhook.name
                ),
            })?;
        apply_json_patch(obj, &patch_bytes)?;
    }

    Ok(())
}

async fn apply_validating_webhook(
    webhook: &WebhookDefinition,
    endpoint: Option<&RegisteredEndpoint>,
    req: &AdmissionRequest,
) -> Result<(), ApiserverError> {
    let Some(endpoint) = endpoint else {
        if webhook.failure_policy == FailurePolicy::Fail {
            return Err(ApiserverError::WebhookFailure {
                webhook: webhook.name.clone(),
                reason: "webhook endpoint handler not registered".to_string(),
            });
        }
        return Ok(());
    };

    let response = match dispatch_single_webhook(webhook, endpoint, req).await {
        Ok(resp) => resp,
        Err(err) => {
            if webhook.failure_policy == FailurePolicy::Fail {
                return Err(err);
            }
            return Ok(());
        },
    };

    if !response.allowed {
        let msg = response
            .status
            .and_then(|s| s.message)
            .unwrap_or_else(|| format!("admission denied by webhook '{}'", webhook.name));
        return Err(ApiserverError::AdmissionDenied { reason: msg });
    }

    Ok(())
}

impl AdmissionEngine {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_webhook_endpoint(
        &self,
        name: impl Into<String>,
        handler: Arc<dyn WebhookHandler>,
        server_cert_pem: Option<String>,
    ) {
        let mut guard = self.endpoints.write().unwrap();
        guard.insert(
            name.into(),
            Arc::new(RegisteredEndpoint {
                handler,
                server_cert_pem,
            }),
        );
    }

    pub fn add_mutating_webhook_config(&self, config: MutatingWebhookConfiguration) {
        let mut guard = self.mutating_configs.write().unwrap();
        if let Some(name) = config.metadata.get("name").and_then(Value::as_str) {
            guard.retain(|c| c.metadata.get("name").and_then(Value::as_str) != Some(name));
        }
        guard.push(config);
    }

    pub fn add_validating_webhook_config(&self, config: ValidatingWebhookConfiguration) {
        let mut guard = self.validating_configs.write().unwrap();
        if let Some(name) = config.metadata.get("name").and_then(Value::as_str) {
            guard.retain(|c| c.metadata.get("name").and_then(Value::as_str) != Some(name));
        }
        guard.push(config);
    }

    pub fn clear_configs(&self) {
        self.mutating_configs.write().unwrap().clear();
        self.validating_configs.write().unwrap().clear();
    }

    /// Runs all matching mutating webhooks against the admission request.
    /// Modifies `req.object` in place if patches are returned.
    pub async fn run_mutating_admission(
        &self,
        req: &mut AdmissionRequest,
    ) -> Result<(), ApiserverError> {
        let configs = self.mutating_configs.read().unwrap().clone();

        for config in configs {
            for webhook in &config.webhooks {
                if !webhook.matches_request(req) {
                    continue;
                }

                let endpoint = {
                    let guard = self.endpoints.read().unwrap();
                    find_endpoint(&guard, webhook)
                };

                apply_mutating_webhook(webhook, endpoint.as_deref(), req).await?;
            }
        }

        Ok(())
    }

    /// Runs all matching validating webhooks against the admission request.
    pub async fn run_validating_admission(
        &self,
        req: &AdmissionRequest,
    ) -> Result<(), ApiserverError> {
        let configs = self.validating_configs.read().unwrap().clone();

        for config in configs {
            for webhook in &config.webhooks {
                if !webhook.matches_request(req) {
                    continue;
                }

                let endpoint = {
                    let guard = self.endpoints.read().unwrap();
                    find_endpoint(&guard, webhook)
                };

                apply_validating_webhook(webhook, endpoint.as_deref(), req).await?;
            }
        }

        Ok(())
    }

    /// Restores persisted webhook configurations from storage.
    pub async fn restore_from_storage(
        &self,
        storage: &KubernetesStorage,
    ) -> Result<(), ApiserverError> {
        self.clear_configs();

        let mutating_prefix = format!("{}/mutatingwebhookconfigurations/", storage.prefix());
        let mutating_kvs = storage.list(&mutating_prefix).await?;
        for kv in mutating_kvs {
            let config: MutatingWebhookConfiguration =
                serde_json::from_slice(&kv.value).map_err(|e| ApiserverError::StorageUnusable {
                    reason: format!(
                        "failed to deserialize MutatingWebhookConfiguration at {}: {e}",
                        kv.key
                    ),
                })?;
            self.add_mutating_webhook_config(config);
        }

        let validating_prefix = format!("{}/validatingwebhookconfigurations/", storage.prefix());
        let validating_kvs = storage.list(&validating_prefix).await?;
        for kv in validating_kvs {
            let config: ValidatingWebhookConfiguration = serde_json::from_slice(&kv.value)
                .map_err(|e| ApiserverError::StorageUnusable {
                    reason: format!(
                        "failed to deserialize ValidatingWebhookConfiguration at {}: {e}",
                        kv.key
                    ),
                })?;
            self.add_validating_webhook_config(config);
        }

        Ok(())
    }
}

// --- RFC 6902 JSONPatch Engine ---

#[derive(Deserialize)]
struct PatchOperation {
    op: String,
    path: String,
    value: Option<Value>,
}

/// Applies an RFC 6902 `JSONPatch` document to a JSON value.
pub fn apply_json_patch(target: &mut Value, patch_bytes: &[u8]) -> Result<(), ApiserverError> {
    let operations: Vec<PatchOperation> =
        serde_json::from_slice(patch_bytes).map_err(|e| ApiserverError::InvalidInput {
            field: "patch".to_string(),
            reason: format!("invalid JSONPatch document: {e}"),
        })?;

    for op in operations {
        match op.op.as_str() {
            "add" => {
                let value = op.value.ok_or_else(|| ApiserverError::InvalidInput {
                    field: op.path.clone(),
                    reason: "add operation missing 'value'".to_string(),
                })?;
                patch_add(target, &op.path, value)?;
            },
            "replace" => {
                let value = op.value.ok_or_else(|| ApiserverError::InvalidInput {
                    field: op.path.clone(),
                    reason: "replace operation missing 'value'".to_string(),
                })?;
                patch_replace(target, &op.path, value)?;
            },
            "remove" => {
                patch_remove(target, &op.path)?;
            },
            other => {
                return Err(ApiserverError::InvalidInput {
                    field: "op".to_string(),
                    reason: format!("unsupported patch operation '{other}'"),
                });
            },
        }
    }
    Ok(())
}

fn split_pointer(path: &str) -> Vec<String> {
    if path.is_empty() || path == "/" {
        return Vec::new();
    }
    path.strip_prefix('/')
        .unwrap_or(path)
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect()
}

fn patch_add(target: &mut Value, path: &str, value: Value) -> Result<(), ApiserverError> {
    let tokens = split_pointer(path);
    if tokens.is_empty() {
        *target = value;
        return Ok(());
    }

    let mut current = target;
    for (i, token) in tokens.iter().enumerate() {
        let is_last = i == tokens.len() - 1;
        if is_last {
            match current {
                Value::Object(map) => {
                    map.insert(token.clone(), value);
                    return Ok(());
                },
                Value::Array(arr) => {
                    if token == "-" {
                        arr.push(value);
                        return Ok(());
                    }
                    if let Ok(idx) = token.parse::<usize>()
                        && idx <= arr.len()
                    {
                        arr.insert(idx, value);
                        return Ok(());
                    }
                    return Err(ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("array index {token} out of bounds"),
                    });
                },
                _ => {
                    return Err(ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: "cannot add property to non-object/non-array".to_string(),
                    });
                },
            }
        }

        // Navigate or create intermediate object
        if current.is_null() {
            *current = Value::Object(serde_json::Map::new());
        }
        match current {
            Value::Object(map) => {
                current = map
                    .entry(token.clone())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
            },
            Value::Array(arr) => {
                let idx = token
                    .parse::<usize>()
                    .map_err(|_| ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("invalid array index {token}"),
                    })?;
                if idx < arr.len() {
                    current = &mut arr[idx];
                } else {
                    return Err(ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("array index {idx} out of bounds"),
                    });
                }
            },
            _ => {
                return Err(ApiserverError::InvalidInput {
                    field: path.to_string(),
                    reason: "cannot navigate into non-container".to_string(),
                });
            },
        }
    }
    Ok(())
}

fn patch_replace(target: &mut Value, path: &str, value: Value) -> Result<(), ApiserverError> {
    let tokens = split_pointer(path);
    if tokens.is_empty() {
        *target = value;
        return Ok(());
    }

    let mut current = target;
    for (i, token) in tokens.iter().enumerate() {
        let is_last = i == tokens.len() - 1;
        if is_last {
            match current {
                Value::Object(map) => {
                    if let Some(entry) = map.get_mut(token) {
                        *entry = value;
                        return Ok(());
                    }
                    return Err(ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("property '{token}' does not exist for replace"),
                    });
                },
                Value::Array(arr) => {
                    let idx = token
                        .parse::<usize>()
                        .map_err(|_| ApiserverError::InvalidInput {
                            field: path.to_string(),
                            reason: format!("invalid array index {token}"),
                        })?;
                    if idx < arr.len() {
                        arr[idx] = value;
                        return Ok(());
                    }
                    return Err(ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("array index {idx} out of bounds for replace"),
                    });
                },
                _ => {
                    return Err(ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: "cannot replace on non-container".to_string(),
                    });
                },
            }
        }

        match current {
            Value::Object(map) => {
                current = map
                    .get_mut(token)
                    .ok_or_else(|| ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("path component '{token}' not found"),
                    })?;
            },
            Value::Array(arr) => {
                let idx = token
                    .parse::<usize>()
                    .map_err(|_| ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("invalid array index {token}"),
                    })?;
                if idx < arr.len() {
                    current = &mut arr[idx];
                } else {
                    return Err(ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("array index {idx} out of bounds"),
                    });
                }
            },
            _ => {
                return Err(ApiserverError::InvalidInput {
                    field: path.to_string(),
                    reason: "cannot navigate into non-container".to_string(),
                });
            },
        }
    }
    Ok(())
}

fn patch_remove(target: &mut Value, path: &str) -> Result<(), ApiserverError> {
    let tokens = split_pointer(path);
    if tokens.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: path.to_string(),
            reason: "cannot remove root document".to_string(),
        });
    }

    let mut current = target;
    for (i, token) in tokens.iter().enumerate() {
        let is_last = i == tokens.len() - 1;
        if is_last {
            match current {
                Value::Object(map) => {
                    if map.remove(token).is_some() {
                        return Ok(());
                    }
                    return Err(ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("property '{token}' does not exist for remove"),
                    });
                },
                Value::Array(arr) => {
                    let idx = token
                        .parse::<usize>()
                        .map_err(|_| ApiserverError::InvalidInput {
                            field: path.to_string(),
                            reason: format!("invalid array index {token}"),
                        })?;
                    if idx < arr.len() {
                        arr.remove(idx);
                        return Ok(());
                    }
                    return Err(ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("array index {idx} out of bounds for remove"),
                    });
                },
                _ => {
                    return Err(ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: "cannot remove on non-container".to_string(),
                    });
                },
            }
        }

        match current {
            Value::Object(map) => {
                current = map
                    .get_mut(token)
                    .ok_or_else(|| ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("path component '{token}' not found"),
                    })?;
            },
            Value::Array(arr) => {
                let idx = token
                    .parse::<usize>()
                    .map_err(|_| ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("invalid array index {token}"),
                    })?;
                if idx < arr.len() {
                    current = &mut arr[idx];
                } else {
                    return Err(ApiserverError::InvalidInput {
                        field: path.to_string(),
                        reason: format!("array index {idx} out of bounds"),
                    });
                }
            },
            _ => {
                return Err(ApiserverError::InvalidInput {
                    field: path.to_string(),
                    reason: "cannot navigate into non-container".to_string(),
                });
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_json_patch_operations() {
        let mut doc = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "test-pod",
                "labels": {
                    "env": "dev"
                }
            }
        });

        // Add
        let patch_add = json!([
            { "op": "add", "path": "/metadata/labels/team", "value": "core" },
            { "op": "add", "path": "/spec", "value": { "nodeName": "node-1" } }
        ]);
        apply_json_patch(&mut doc, serde_json::to_vec(&patch_add).unwrap().as_slice()).unwrap();
        assert_eq!(doc["metadata"]["labels"]["team"], "core");
        assert_eq!(doc["spec"]["nodeName"], "node-1");

        // Replace
        let patch_replace = json!([
            { "op": "replace", "path": "/metadata/labels/env", "value": "prod" }
        ]);
        apply_json_patch(
            &mut doc,
            serde_json::to_vec(&patch_replace).unwrap().as_slice(),
        )
        .unwrap();
        assert_eq!(doc["metadata"]["labels"]["env"], "prod");

        // Remove
        let patch_remove = json!([
            { "op": "remove", "path": "/metadata/labels/team" }
        ]);
        apply_json_patch(
            &mut doc,
            serde_json::to_vec(&patch_remove).unwrap().as_slice(),
        )
        .unwrap();
        assert!(doc["metadata"]["labels"].get("team").is_none());
    }
}
