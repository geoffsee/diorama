use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
        default_admitted_object(&req.kind, &req.resource, obj)?;
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

/// Applies Kubernetes container spec defaults to a container map.
pub fn default_container_spec(c_obj: &mut serde_json::Map<String, Value>) {
    c_obj
        .entry("terminationMessagePath".to_string())
        .or_insert_with(|| json!("/dev/termination-log"));
    c_obj
        .entry("terminationMessagePolicy".to_string())
        .or_insert_with(|| json!("File"));

    if !c_obj.contains_key("imagePullPolicy") {
        let image = c_obj
            .get("image")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let pull_policy = if image.ends_with(":latest") || !image.contains(':') {
            "Always"
        } else {
            "IfNotPresent"
        };
        c_obj.insert("imagePullPolicy".to_string(), json!(pull_policy));
    }

    if let Some(ports) = c_obj.get_mut("ports").and_then(Value::as_array_mut) {
        for port in ports.iter_mut().filter_map(Value::as_object_mut) {
            port.entry("protocol".to_string())
                .or_insert_with(|| json!("TCP"));
        }
    }

    if let Some(env_vars) = c_obj.get_mut("env").and_then(Value::as_array_mut) {
        for env in env_vars.iter_mut().filter_map(Value::as_object_mut) {
            if !env.contains_key("value") && !env.contains_key("valueFrom") {
                env.insert("value".to_string(), json!(""));
            }
        }
    }
}

/// Applies Kubernetes Pod spec defaults to a Pod object and its containers.
pub fn default_pod_spec(pod: &mut Value) {
    let Some(spec) = pod.get_mut("spec").and_then(Value::as_object_mut) else {
        return;
    };

    spec.entry("terminationGracePeriodSeconds".to_string())
        .or_insert_with(|| json!(30));
    spec.entry("restartPolicy".to_string())
        .or_insert_with(|| json!("Always"));
    spec.entry("dnsPolicy".to_string())
        .or_insert_with(|| json!("ClusterFirst"));

    for container_key in ["containers", "initContainers", "ephemeralContainers"] {
        if let Some(containers) = spec.get_mut(container_key).and_then(Value::as_array_mut) {
            for c_obj in containers.iter_mut().filter_map(Value::as_object_mut) {
                default_container_spec(c_obj);
            }
        }
    }
}

/// Defaults fields for `flowcontrol.apiserver.k8s.io/v1` `FlowSchema`.
pub fn default_flow_schema(obj: &mut Value) {
    let Some(spec) = obj.get_mut("spec").and_then(Value::as_object_mut) else {
        return;
    };

    spec.entry("matchingPrecedence".to_string())
        .or_insert_with(|| json!(1000));

    if let Some(dm) = spec
        .get_mut("distinguisherMethod")
        .and_then(Value::as_object_mut)
    {
        dm.entry("type".to_string())
            .or_insert_with(|| json!("ByUser"));
    } else if !spec.contains_key("distinguisherMethod") {
        spec.insert(
            "distinguisherMethod".to_string(),
            json!({ "type": "ByUser" }),
        );
    }
}

fn default_priority_level_queuing(lim_obj: &mut serde_json::Map<String, Value>) {
    lim_obj
        .entry("nominalConcurrencyShares".to_string())
        .or_insert_with(|| json!(30));

    let Some(lr) = lim_obj
        .get_mut("limitResponse")
        .and_then(Value::as_object_mut)
    else {
        lim_obj.insert(
            "limitResponse".to_string(),
            json!({
                "type": "Queue",
                "queuing": {
                    "queues": 64,
                    "handSize": 8,
                    "queueLengthLimit": 50
                }
            }),
        );
        return;
    };

    if lr.get("type").and_then(Value::as_str) != Some("Queue") {
        return;
    }

    let queuing = lr.entry("queuing".to_string()).or_insert_with(|| json!({}));
    if let Some(q_obj) = queuing.as_object_mut() {
        q_obj
            .entry("queues".to_string())
            .or_insert_with(|| json!(64));
        q_obj
            .entry("handSize".to_string())
            .or_insert_with(|| json!(8));
        q_obj
            .entry("queueLengthLimit".to_string())
            .or_insert_with(|| json!(50));
    }
}

/// Validates and normalizes `PriorityLevelConfiguration` during admission.
pub fn default_and_normalize_priority_level_configuration(
    obj: &mut Value,
) -> Result<(), ApiserverError> {
    let Some(spec) = obj.get_mut("spec").and_then(Value::as_object_mut) else {
        return Ok(());
    };

    let pl_type = spec.get("type").and_then(Value::as_str).map(str::to_string);

    match pl_type.as_deref() {
        Some("Limited") => {
            let limited = spec
                .entry("limited".to_string())
                .or_insert_with(|| json!({}));
            if let Some(lim_obj) = limited.as_object_mut() {
                default_priority_level_queuing(lim_obj);
            }
        },
        Some("Exempt") => {
            if spec.get("limited").is_some_and(|v| !v.is_null()) {
                return Err(ApiserverError::InvalidInput {
                    field: "spec.limited".to_string(),
                    reason: "spec.limited must not be specified for Exempt priority level"
                        .to_string(),
                });
            }
        },
        Some(other) => {
            return Err(ApiserverError::InvalidInput {
                field: "spec.type".to_string(),
                reason: format!(
                    "unknown priority level type '{other}', must be 'Limited' or 'Exempt'"
                ),
            });
        },
        None => {
            if spec.contains_key("limited") {
                spec.insert("type".to_string(), json!("Limited"));
                return default_and_normalize_priority_level_configuration(obj);
            }
            return Err(ApiserverError::InvalidInput {
                field: "spec.type".to_string(),
                reason: "spec.type is required for PriorityLevelConfiguration".to_string(),
            });
        },
    }

    Ok(())
}

/// Applies Kubernetes defaults to an admitted object.
pub fn default_admitted_object(
    kind: &GroupVersionKind,
    resource: &GroupVersionResource,
    obj: &mut Value,
) -> Result<(), ApiserverError> {
    let is_pod = kind.kind == "Pod"
        || resource.resource == "pods"
        || obj.get("kind").and_then(Value::as_str) == Some("Pod")
        || obj.pointer("/spec/containers").is_some();

    if is_pod {
        default_pod_spec(obj);
        return Ok(());
    }

    let is_flow_control = resource.group == "flowcontrol.apiserver.k8s.io"
        || kind.group == "flowcontrol.apiserver.k8s.io"
        || obj
            .get("apiVersion")
            .and_then(Value::as_str)
            .is_some_and(|v| v.starts_with("flowcontrol.apiserver.k8s.io"));

    if is_flow_control {
        if kind.kind == "FlowSchema"
            || resource.resource == "flowschemas"
            || obj.get("kind").and_then(Value::as_str) == Some("FlowSchema")
        {
            default_flow_schema(obj);
        } else if kind.kind == "PriorityLevelConfiguration"
            || resource.resource == "prioritylevelconfigurations"
            || obj
                .get("kind")
                .and_then(Value::as_str)
                .is_some_and(|k| k == "PriorityLevelConfiguration")
        {
            default_and_normalize_priority_level_configuration(obj)?;
        }
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchCondition {
    pub name: String,
    pub expression: String,
}

/// Evaluates whether an object matches an optional `LabelSelector`.
#[must_use]
pub fn matches_object_selector(selector: Option<&Value>, object: Option<&Value>) -> bool {
    let Some(selector) = selector else {
        return true;
    };
    let labels = object.and_then(|o| o.pointer("/metadata/labels"));
    crate::pdb::selector_matches(Some(selector), labels)
}

/// Evaluates whether a namespace matches an optional namespace `LabelSelector`.
#[must_use]
pub fn matches_namespace_selector(selector: Option<&Value>, ns_labels: Option<&Value>) -> bool {
    let Some(selector) = selector else {
        return true;
    };
    crate::pdb::selector_matches(Some(selector), ns_labels)
}

/// Validates CEL matchCondition syntax.
pub fn validate_match_condition(expression: &str) -> Result<(), ApiserverError> {
    let trimmed = expression.trim();
    if trimmed.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "matchConditions.expression".to_string(),
            reason: "compilation failed: empty expression".to_string(),
        });
    }
    let single_quotes = trimmed.chars().filter(|&c| c == '\'').count();
    let double_quotes = trimmed.chars().filter(|&c| c == '"').count();
    let open_parens = trimmed.chars().filter(|&c| c == '(').count();
    let close_parens = trimmed.chars().filter(|&c| c == ')').count();
    if single_quotes % 2 != 0 || double_quotes % 2 != 0 || open_parens != close_parens {
        return Err(ApiserverError::InvalidInput {
            field: "matchConditions.expression".to_string(),
            reason: format!("compilation failed: unbalanced tokens in expression '{trimmed}'"),
        });
    }
    Ok(())
}

/// Evaluates a CEL matchCondition against an admission request.
#[must_use]
pub fn evaluate_match_condition(expression: &str, req: &AdmissionRequest) -> bool {
    let expr = expression.trim();
    if expr.is_empty() || expr == "true" {
        return true;
    }
    if expr == "false" {
        return false;
    }
    if let Some((lhs, rhs)) = expr.split_once("!=") {
        let lhs = lhs.trim();
        let rhs = rhs.trim().trim_matches('\'').trim_matches('"');
        if lhs == "object.metadata.name" {
            let actual = req
                .object
                .as_ref()
                .and_then(|o| o.pointer("/metadata/name"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            return actual != rhs;
        }
    }
    if let Some((lhs, rhs)) = expr.split_once("==") {
        let lhs = lhs.trim();
        let rhs = rhs.trim().trim_matches('\'').trim_matches('"');
        if lhs == "object.metadata.name" {
            let actual = req
                .object
                .as_ref()
                .and_then(|o| o.pointer("/metadata/name"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            return actual == rhs;
        }
    }
    true
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

    async fn reinvoke_webhooks_pass(
        &self,
        webhooks: &[WebhookDefinition],
        req: &mut AdmissionRequest,
    ) -> Result<bool, ApiserverError> {
        let mut mutated = false;
        for webhook in webhooks {
            if webhook.reinvocation_policy.as_deref() != Some("IfNeeded") {
                continue;
            }

            let endpoint = {
                let guard = self.endpoints.read().unwrap();
                find_endpoint(&guard, webhook)
            };

            let before = req.object.clone();
            apply_mutating_webhook(webhook, endpoint.as_deref(), req).await?;
            if req.object != before {
                mutated = true;
            }
        }
        Ok(mutated)
    }

    /// Runs all matching mutating webhooks against the admission request.
    /// Modifies `req.object` in place if patches are returned and applies defaults.
    pub async fn run_mutating_admission(
        &self,
        req: &mut AdmissionRequest,
    ) -> Result<(), ApiserverError> {
        let configs = self.mutating_configs.read().unwrap().clone();

        let mut matching_webhooks = Vec::new();
        for config in &configs {
            for webhook in &config.webhooks {
                if webhook.matches_request(req) {
                    matching_webhooks.push(webhook.clone());
                }
            }
        }

        let mut mutated_overall = false;

        for webhook in &matching_webhooks {
            let endpoint = {
                let guard = self.endpoints.read().unwrap();
                find_endpoint(&guard, webhook)
            };

            let before = req.object.clone();
            apply_mutating_webhook(webhook, endpoint.as_deref(), req).await?;
            if req.object != before {
                mutated_overall = true;
            }
        }

        // Reinvocation loop: if any webhook mutated the object, reinvoke webhooks configured with IfNeeded
        if mutated_overall {
            const MAX_REINVOCATION_PASSES: usize = 5;
            for _ in 0..MAX_REINVOCATION_PASSES {
                let mutated = self.reinvoke_webhooks_pass(&matching_webhooks, req).await?;
                if !mutated {
                    break;
                }
            }
        }

        // Ensure defaults are applied to the admitted object
        if let Some(obj) = &mut req.object {
            default_admitted_object(&req.kind, &req.resource, obj)?;
        }

        Ok(())
    }

    /// Runs all matching validating webhooks against the admission request.
    pub async fn run_validating_admission(
        &self,
        req: &AdmissionRequest,
    ) -> Result<(), ApiserverError> {
        // Validate PriorityLevelConfiguration if invoked during admission
        if let Some(obj) = &req.object {
            let is_flow_control = req.resource.group == "flowcontrol.apiserver.k8s.io"
                || req.kind.group == "flowcontrol.apiserver.k8s.io"
                || obj
                    .get("apiVersion")
                    .and_then(Value::as_str)
                    .is_some_and(|v| v.starts_with("flowcontrol.apiserver.k8s.io"));
            if is_flow_control
                && (req.kind.kind == "PriorityLevelConfiguration"
                    || req.resource.resource == "prioritylevelconfigurations"
                    || obj.get("kind").and_then(Value::as_str)
                        == Some("PriorityLevelConfiguration"))
            {
                let mut clone = obj.clone();
                default_and_normalize_priority_level_configuration(&mut clone)?;
            }
        }

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
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
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
            "test" => {
                let value = op.value.ok_or_else(|| ApiserverError::InvalidInput {
                    field: op.path.clone(),
                    reason: "test operation missing 'value'".to_string(),
                })?;
                let actual =
                    get_pointer(target, &op.path).ok_or_else(|| ApiserverError::InvalidInput {
                        field: op.path.clone(),
                        reason: format!("test operation target '{}' not found", op.path),
                    })?;
                if actual != &value {
                    return Err(ApiserverError::InvalidInput {
                        field: op.path.clone(),
                        reason: format!(
                            "test operation failed: expected {value:?}, got {actual:?}"
                        ),
                    });
                }
            },
            "copy" => {
                let from = op.from.ok_or_else(|| ApiserverError::InvalidInput {
                    field: op.path.clone(),
                    reason: "copy operation missing 'from'".to_string(),
                })?;
                let val = get_pointer(target, &from).cloned().ok_or_else(|| {
                    ApiserverError::InvalidInput {
                        field: from.clone(),
                        reason: format!("copy from path '{from}' not found"),
                    }
                })?;
                patch_add(target, &op.path, val)?;
            },
            "move" => {
                let from = op.from.ok_or_else(|| ApiserverError::InvalidInput {
                    field: op.path.clone(),
                    reason: "move operation missing 'from'".to_string(),
                })?;
                let val = get_pointer(target, &from).cloned().ok_or_else(|| {
                    ApiserverError::InvalidInput {
                        field: from.clone(),
                        reason: format!("move from path '{from}' not found"),
                    }
                })?;
                patch_remove(target, &from)?;
                patch_add(target, &op.path, val)?;
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
    if path.is_empty() {
        return Vec::new();
    }
    if path == "/" {
        return vec![String::new()];
    }
    path.strip_prefix('/')
        .unwrap_or(path)
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect()
}

fn get_pointer<'a>(target: &'a Value, path: &str) -> Option<&'a Value> {
    let tokens = split_pointer(path);
    let mut current = target;
    for token in tokens {
        match current {
            Value::Object(map) => {
                current = map.get(&token)?;
            },
            Value::Array(arr) => {
                let idx = token.parse::<usize>().ok()?;
                current = arr.get(idx)?;
            },
            _ => return None,
        }
    }
    Some(current)
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

        // Navigate or create intermediate container
        let next_token = &tokens[i + 1];
        let next_is_array = next_token == "-" || next_token.parse::<usize>().is_ok();

        if current.is_null() {
            *current = if next_is_array {
                Value::Array(Vec::new())
            } else {
                Value::Object(serde_json::Map::new())
            };
        }

        match current {
            Value::Object(map) => {
                current = map.entry(token.clone()).or_insert_with(|| {
                    if next_is_array {
                        Value::Array(Vec::new())
                    } else {
                        Value::Object(serde_json::Map::new())
                    }
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

    struct AddInitContainerHandler;

    #[async_trait]
    impl WebhookHandler for AddInitContainerHandler {
        async fn handle(
            &self,
            req: &AdmissionRequest,
        ) -> Result<AdmissionResponse, ApiserverError> {
            let patch = json!([
                {
                    "op": "add",
                    "path": "/spec/initContainers",
                    "value": [
                        {
                            "name": "webhook-added-init",
                            "image": "registry.k8s.io/pause:3.8",
                            "ports": [
                                {
                                    "containerPort": 8080
                                }
                            ],
                            "env": [
                                {
                                    "name": "CONFIG_KEY"
                                }
                            ]
                        }
                    ]
                }
            ]);
            let patch_bytes = serde_json::to_vec(&patch).map_err(|e| ApiserverError::Internal {
                reason: e.to_string(),
            })?;
            let patch_b64 = diorama_pki::base64_encode(&patch_bytes);

            Ok(AdmissionResponse {
                uid: req.uid.clone(),
                allowed: true,
                status: None,
                patch: Some(patch_b64),
                patch_type: Some("JSONPatch".to_string()),
            })
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_mutating_webhook_adds_init_container_and_defaults_spec() {
        let engine = AdmissionEngine::new();
        engine.register_webhook_endpoint("test-mutator", Arc::new(AddInitContainerHandler), None);

        let mutating_config = MutatingWebhookConfiguration {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("test-config"));
                m
            },
            webhooks: vec![WebhookDefinition {
                name: "test-mutator".to_string(),
                client_config: WebhookClientConfig {
                    url: Some("http://test-mutator/mutate".to_string()),
                    service: None,
                    ca_bundle: None,
                },
                rules: vec![RuleWithOperations {
                    operations: vec!["CREATE".to_string()],
                    api_groups: vec![String::new()],
                    api_versions: vec!["v1".to_string()],
                    resources: vec!["pods".to_string()],
                    scope: None,
                }],
                failure_policy: FailurePolicy::Fail,
                timeout_seconds: Some(10),
                admission_review_versions: vec!["v1".to_string()],
                side_effects: None,
                reinvocation_policy: None,
            }],
        };
        engine.add_mutating_webhook_config(mutating_config);

        let initial_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "test-pod",
                "namespace": "default"
            },
            "spec": {
                "containers": [
                    {
                        "name": "main",
                        "image": "nginx:alpine"
                    }
                ]
            }
        });

        let mut req = AdmissionRequest {
            uid: "req-1".to_string(),
            kind: GroupVersionKind {
                group: String::new(),
                version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            resource: GroupVersionResource {
                group: String::new(),
                version: "v1".to_string(),
                resource: "pods".to_string(),
            },
            name: Some("test-pod".to_string()),
            namespace: Some("default".to_string()),
            operation: "CREATE".to_string(),
            user_info: UserInfo {
                username: "admin".to_string(),
                uid: None,
                groups: vec!["system:masters".to_string()],
            },
            object: Some(initial_pod),
            old_object: None,
            dry_run: None,
        };

        engine.run_mutating_admission(&mut req).await.unwrap();

        let obj = req.object.expect("mutated object present");
        let init_containers = obj
            .pointer("/spec/initContainers")
            .and_then(Value::as_array)
            .expect("initContainers array present");
        assert_eq!(init_containers.len(), 1);
        let init_c = &init_containers[0];

        assert_eq!(init_c["name"], "webhook-added-init");
        assert_eq!(init_c["terminationMessagePolicy"], "File");
        assert_eq!(init_c["terminationMessagePath"], "/dev/termination-log");
        assert_eq!(init_c["imagePullPolicy"], "IfNotPresent");
        assert_eq!(init_c["ports"][0]["protocol"], "TCP");
        assert_eq!(init_c["env"][0]["value"], "");

        assert_eq!(obj.pointer("/spec/restartPolicy"), Some(&json!("Always")));
        assert_eq!(
            obj.pointer("/spec/terminationGracePeriodSeconds"),
            Some(&json!(30))
        );
        assert_eq!(obj.pointer("/spec/dnsPolicy"), Some(&json!("ClusterFirst")));
    }

    struct AddInitContainerDashHandler;

    #[async_trait]
    impl WebhookHandler for AddInitContainerDashHandler {
        async fn handle(
            &self,
            req: &AdmissionRequest,
        ) -> Result<AdmissionResponse, ApiserverError> {
            let patch = json!([
                {
                    "op": "add",
                    "path": "/spec/initContainers/-",
                    "value": {
                        "name": "dash-init",
                        "image": "busybox:latest"
                    }
                }
            ]);
            let patch_bytes = serde_json::to_vec(&patch).map_err(|e| ApiserverError::Internal {
                reason: e.to_string(),
            })?;
            let patch_b64 = diorama_pki::base64_encode(&patch_bytes);

            Ok(AdmissionResponse {
                uid: req.uid.clone(),
                allowed: true,
                status: None,
                patch: Some(patch_b64),
                patch_type: Some("JSONPatch".to_string()),
            })
        }
    }

    #[tokio::test]
    async fn test_mutating_webhook_adds_to_nonexistent_array_and_latest_tag_defaults() {
        let engine = AdmissionEngine::new();
        engine.register_webhook_endpoint(
            "dash-mutator",
            Arc::new(AddInitContainerDashHandler),
            None,
        );

        let mutating_config = MutatingWebhookConfiguration {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("dash-config"));
                m
            },
            webhooks: vec![WebhookDefinition {
                name: "dash-mutator".to_string(),
                client_config: WebhookClientConfig {
                    url: Some("http://dash-mutator/mutate".to_string()),
                    service: None,
                    ca_bundle: None,
                },
                rules: vec![RuleWithOperations {
                    operations: vec!["CREATE".to_string()],
                    api_groups: vec![String::new()],
                    api_versions: vec!["v1".to_string()],
                    resources: vec!["pods".to_string()],
                    scope: None,
                }],
                failure_policy: FailurePolicy::Fail,
                timeout_seconds: Some(10),
                admission_review_versions: vec!["v1".to_string()],
                side_effects: None,
                reinvocation_policy: None,
            }],
        };
        engine.add_mutating_webhook_config(mutating_config);

        let initial_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "dash-pod",
                "namespace": "default"
            },
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx"
                    }
                ]
            }
        });

        let mut req = AdmissionRequest {
            uid: "req-dash".to_string(),
            kind: GroupVersionKind {
                group: String::new(),
                version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            resource: GroupVersionResource {
                group: String::new(),
                version: "v1".to_string(),
                resource: "pods".to_string(),
            },
            name: Some("dash-pod".to_string()),
            namespace: Some("default".to_string()),
            operation: "CREATE".to_string(),
            user_info: UserInfo {
                username: "admin".to_string(),
                uid: None,
                groups: vec![],
            },
            object: Some(initial_pod),
            old_object: None,
            dry_run: None,
        };

        engine.run_mutating_admission(&mut req).await.unwrap();

        let obj = req.object.expect("mutated object present");
        let init_containers = obj
            .pointer("/spec/initContainers")
            .and_then(Value::as_array)
            .expect("initContainers present");
        assert_eq!(init_containers.len(), 1);
        let init_c = &init_containers[0];

        assert_eq!(init_c["name"], "dash-init");
        assert_eq!(init_c["imagePullPolicy"], "Always");
        assert_eq!(init_c["terminationMessagePolicy"], "File");
        assert_eq!(init_c["terminationMessagePath"], "/dev/termination-log");
    }

    struct InspectingHandler {
        calls: Arc<RwLock<Vec<Value>>>,
    }

    #[async_trait]
    impl WebhookHandler for InspectingHandler {
        async fn handle(
            &self,
            req: &AdmissionRequest,
        ) -> Result<AdmissionResponse, ApiserverError> {
            if let Some(obj) = &req.object {
                self.calls.write().unwrap().push(obj.clone());
            }
            Ok(AdmissionResponse::allow(&req.uid))
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_mutating_webhook_reinvocation_if_needed() {
        let engine = AdmissionEngine::new();
        let calls = Arc::new(RwLock::new(Vec::new()));

        engine.register_webhook_endpoint(
            "wh1-inspector",
            Arc::new(InspectingHandler {
                calls: calls.clone(),
            }),
            None,
        );
        engine.register_webhook_endpoint("wh2-mutator", Arc::new(AddInitContainerHandler), None);

        let mutating_config = MutatingWebhookConfiguration {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("reinvocation-config"));
                m
            },
            webhooks: vec![
                WebhookDefinition {
                    name: "wh1-inspector".to_string(),
                    client_config: WebhookClientConfig {
                        url: Some("http://wh1-inspector/mutate".to_string()),
                        service: None,
                        ca_bundle: None,
                    },
                    rules: vec![RuleWithOperations {
                        operations: vec!["CREATE".to_string()],
                        api_groups: vec![String::new()],
                        api_versions: vec!["v1".to_string()],
                        resources: vec!["pods".to_string()],
                        scope: None,
                    }],
                    failure_policy: FailurePolicy::Fail,
                    timeout_seconds: Some(10),
                    admission_review_versions: vec!["v1".to_string()],
                    side_effects: None,
                    reinvocation_policy: Some("IfNeeded".to_string()),
                },
                WebhookDefinition {
                    name: "wh2-mutator".to_string(),
                    client_config: WebhookClientConfig {
                        url: Some("http://wh2-mutator/mutate".to_string()),
                        service: None,
                        ca_bundle: None,
                    },
                    rules: vec![RuleWithOperations {
                        operations: vec!["CREATE".to_string()],
                        api_groups: vec![String::new()],
                        api_versions: vec!["v1".to_string()],
                        resources: vec!["pods".to_string()],
                        scope: None,
                    }],
                    failure_policy: FailurePolicy::Fail,
                    timeout_seconds: Some(10),
                    admission_review_versions: vec!["v1".to_string()],
                    side_effects: None,
                    reinvocation_policy: None,
                },
            ],
        };
        engine.add_mutating_webhook_config(mutating_config);

        let initial_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "reinvoked-pod",
                "namespace": "default"
            },
            "spec": {
                "containers": [
                    {
                        "name": "main",
                        "image": "nginx:alpine"
                    }
                ]
            }
        });

        let mut req = AdmissionRequest {
            uid: "req-reinv".to_string(),
            kind: GroupVersionKind {
                group: String::new(),
                version: "v1".to_string(),
                kind: "Pod".to_string(),
            },
            resource: GroupVersionResource {
                group: String::new(),
                version: "v1".to_string(),
                resource: "pods".to_string(),
            },
            name: Some("reinvoked-pod".to_string()),
            namespace: Some("default".to_string()),
            operation: "CREATE".to_string(),
            user_info: UserInfo {
                username: "admin".to_string(),
                uid: None,
                groups: vec!["system:masters".to_string()],
            },
            object: Some(initial_pod),
            old_object: None,
            dry_run: None,
        };

        engine.run_mutating_admission(&mut req).await.unwrap();

        let recorded = calls.read().unwrap();
        assert_eq!(recorded.len(), 2);
        assert!(recorded[0].pointer("/spec/initContainers").is_none());
        assert_eq!(
            recorded[1].pointer("/spec/initContainers/0/name"),
            Some(&json!("webhook-added-init"))
        );
        assert_eq!(
            recorded[1].pointer("/spec/initContainers/0/terminationMessagePolicy"),
            Some(&json!("File"))
        );
    }

    #[test]
    fn test_flow_schema_and_priority_level_defaulting() {
        let mut fs = json!({
            "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
            "kind": "FlowSchema",
            "metadata": { "name": "exempt" },
            "spec": {
                "priorityLevelConfiguration": { "name": "exempt" }
            }
        });
        default_flow_schema(&mut fs);
        assert_eq!(fs["spec"]["matchingPrecedence"], 1000);
        assert_eq!(fs["spec"]["distinguisherMethod"]["type"], "ByUser");

        let mut plc = json!({
            "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
            "kind": "PriorityLevelConfiguration",
            "metadata": { "name": "workload-low" },
            "spec": {
                "type": "Limited",
                "limited": {}
            }
        });
        default_and_normalize_priority_level_configuration(&mut plc).unwrap();
        assert_eq!(plc["spec"]["limited"]["nominalConcurrencyShares"], 30);
        assert_eq!(plc["spec"]["limited"]["limitResponse"]["type"], "Queue");
        assert_eq!(
            plc["spec"]["limited"]["limitResponse"]["queuing"]["queues"],
            64
        );
        assert_eq!(
            plc["spec"]["limited"]["limitResponse"]["queuing"]["handSize"],
            8
        );
        assert_eq!(
            plc["spec"]["limited"]["limitResponse"]["queuing"]["queueLengthLimit"],
            50
        );

        let mut plc_invalid = json!({
            "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
            "kind": "PriorityLevelConfiguration",
            "metadata": { "name": "bad" },
            "spec": {
                "type": "Exempt",
                "limited": { "nominalConcurrencyShares": 30 }
            }
        });
        assert!(default_and_normalize_priority_level_configuration(&mut plc_invalid).is_err());
    }

    #[test]
    fn test_rfc6902_copy_move_test_and_array_add() {
        let mut doc = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "test-pod",
                "labels": {
                    "env": "dev"
                }
            },
            "spec": {
                "containers": [
                    { "name": "app", "image": "nginx" }
                ]
            }
        });

        // Add to non-existent array field
        let patch_array_add = json!([
            { "op": "add", "path": "/spec/initContainers/-", "value": { "name": "i1" } },
            { "op": "add", "path": "/spec/initContainers/-", "value": { "name": "i2" } }
        ]);
        apply_json_patch(
            &mut doc,
            serde_json::to_vec(&patch_array_add).unwrap().as_slice(),
        )
        .unwrap();
        assert_eq!(doc["spec"]["initContainers"][0]["name"], "i1");
        assert_eq!(doc["spec"]["initContainers"][1]["name"], "i2");

        // Test op
        let patch_test_pass = json!([
            { "op": "test", "path": "/metadata/labels/env", "value": "dev" }
        ]);
        assert!(
            apply_json_patch(
                &mut doc,
                serde_json::to_vec(&patch_test_pass).unwrap().as_slice()
            )
            .is_ok()
        );

        let patch_test_fail = json!([
            { "op": "test", "path": "/metadata/labels/env", "value": "prod" }
        ]);
        assert!(
            apply_json_patch(
                &mut doc,
                serde_json::to_vec(&patch_test_fail).unwrap().as_slice()
            )
            .is_err()
        );

        // Copy op
        let patch_copy = json!([
            { "op": "copy", "from": "/metadata/labels/env", "path": "/metadata/labels/tier" }
        ]);
        apply_json_patch(
            &mut doc,
            serde_json::to_vec(&patch_copy).unwrap().as_slice(),
        )
        .unwrap();
        assert_eq!(doc["metadata"]["labels"]["tier"], "dev");

        // Move op
        let patch_move = json!([
            { "op": "move", "from": "/metadata/labels/tier", "path": "/metadata/labels/stage" }
        ]);
        apply_json_patch(
            &mut doc,
            serde_json::to_vec(&patch_move).unwrap().as_slice(),
        )
        .unwrap();
        assert!(doc["metadata"]["labels"].get("tier").is_none());
        assert_eq!(doc["metadata"]["labels"]["stage"], "dev");
    }

    #[test]
    fn test_match_conditions_and_selectors() {
        let req = AdmissionRequest {
            uid: "req-1".to_string(),
            kind: GroupVersionKind {
                group: String::new(),
                version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
            },
            resource: GroupVersionResource {
                group: String::new(),
                version: "v1".to_string(),
                resource: "configmaps".to_string(),
            },
            name: Some("skip-me".to_string()),
            namespace: Some("default".to_string()),
            operation: "CREATE".to_string(),
            user_info: UserInfo {
                username: "admin".to_string(),
                uid: None,
                groups: vec![],
            },
            object: Some(json!({
                "metadata": {
                    "name": "skip-me",
                    "labels": { "app": "test" }
                }
            })),
            old_object: None,
            dry_run: None,
        };

        assert!(!evaluate_match_condition(
            "object.metadata.name != 'skip-me'",
            &req
        ));
        assert!(evaluate_match_condition(
            "object.metadata.name == 'skip-me'",
            &req
        ));

        assert!(validate_match_condition("object.metadata.name != 'skip-me'").is_ok());
        assert!(validate_match_condition("invalid ('unbalanced").is_err());

        let selector = json!({ "matchLabels": { "app": "test" } });
        assert!(matches_object_selector(
            Some(&selector),
            req.object.as_ref()
        ));

        let non_matching_selector = json!({ "matchLabels": { "app": "other" } });
        assert!(!matches_object_selector(
            Some(&non_matching_selector),
            req.object.as_ref()
        ));
    }
}
