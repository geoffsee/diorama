#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::excessive_nesting,
    clippy::field_reassign_with_default,
    clippy::manual_is_variant_and,
    clippy::map_unwrap_or,
    clippy::missing_fields_in_debug,
    clippy::needless_bool,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::too_many_lines
)]

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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleWithOperations {
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default, rename = "apiGroups")]
    pub api_groups: Vec<String>,
    #[serde(default, rename = "apiVersions")]
    pub api_versions: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    pub scope: Option<String>,
}

#[must_use]
pub fn resource_rule_matches(pattern: &str, target_resource: &str) -> bool {
    if pattern == "*" {
        return !target_resource.contains('/');
    }
    if pattern == "*/*" {
        return target_resource.contains('/');
    }
    if pattern == target_resource {
        return true;
    }
    if let Some((pat_res, pat_sub)) = pattern.split_once('/') {
        if let Some((tgt_res, tgt_sub)) = target_resource.split_once('/') {
            let res_ok = pat_res == "*" || pat_res == tgt_res;
            let sub_ok = pat_sub == "*" || pat_sub == tgt_sub;
            return res_ok && sub_ok;
        }
    }
    false
}

#[must_use]
pub fn extract_group_version(req: &AdmissionRequest) -> (Option<&str>, Option<&str>) {
    let api_version = req
        .object
        .as_ref()
        .and_then(|o| o.get("apiVersion"))
        .and_then(Value::as_str);
    if let Some(av) = api_version {
        if let Some((g, v)) = av.split_once('/') {
            (Some(g), Some(v))
        } else {
            (Some(""), Some(av))
        }
    } else {
        (None, None)
    }
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
        let res_match = self
            .resources
            .iter()
            .any(|r| resource_rule_matches(r, resource));

        op_match && group_match && version_match && res_match
    }

    #[must_use]
    pub fn matches_scoped(
        &self,
        op: &str,
        group: &str,
        version: &str,
        resource: &str,
        namespace: Option<&str>,
    ) -> bool {
        if let Some(scope) = &self.scope {
            match scope.as_str() {
                "Cluster" => {
                    if namespace.is_some_and(|ns| !ns.is_empty()) {
                        return false;
                    }
                },
                "Namespaced" => {
                    if namespace.is_none() || namespace.is_some_and(str::is_empty) {
                        return false;
                    }
                },
                _ => {},
            }
        }
        self.matches(op, group, version, resource)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebhookDefinition {
    pub name: String,
    #[serde(default)]
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
    #[serde(
        default,
        rename = "namespaceSelector",
        skip_serializing_if = "Option::is_none"
    )]
    pub namespace_selector: Option<Value>,
    #[serde(
        default,
        rename = "objectSelector",
        skip_serializing_if = "Option::is_none"
    )]
    pub object_selector: Option<Value>,
    #[serde(
        default,
        rename = "matchConditions",
        skip_serializing_if = "Option::is_none"
    )]
    pub match_conditions: Option<Vec<MatchCondition>>,
    #[serde(
        default,
        rename = "matchPolicy",
        skip_serializing_if = "Option::is_none"
    )]
    pub match_policy: Option<String>,
}

impl WebhookDefinition {
    #[must_use]
    pub fn matches_request(&self, req: &AdmissionRequest) -> bool {
        self.matches_request_with_ns(req, None)
    }

    #[must_use]
    pub fn matches_request_with_ns(
        &self,
        req: &AdmissionRequest,
        ns_labels: Option<&Value>,
    ) -> bool {
        let (obj_group, obj_version) = extract_group_version(req);

        let rules_match = self.rules.iter().any(|r| {
            let direct = r.matches_scoped(
                &req.operation,
                &req.resource.group,
                &req.resource.version,
                &req.resource.resource,
                req.namespace.as_deref(),
            );
            if direct {
                return true;
            }
            if let Some(ov) = obj_version {
                let og = obj_group.unwrap_or(&req.resource.group);
                if r.matches_scoped(
                    &req.operation,
                    og,
                    ov,
                    &req.resource.resource,
                    req.namespace.as_deref(),
                ) {
                    return true;
                }
            }
            false
        });
        if !rules_match {
            return false;
        }

        if !matches_namespace_selector(self.namespace_selector.as_ref(), ns_labels) {
            return false;
        }

        let target_obj = req.object.as_ref().or(req.old_object.as_ref());
        if !matches_object_selector(self.object_selector.as_ref(), target_obj) {
            return false;
        }

        if let Some(conds) = &self.match_conditions {
            for cond in conds {
                if !evaluate_match_condition(&cond.expression, req) {
                    return false;
                }
            }
        }

        true
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatingWebhookConfiguration {
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default)]
    pub webhooks: Vec<WebhookDefinition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutatingWebhookConfiguration {
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutatingAdmissionPolicy {
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default)]
    pub spec: MutatingAdmissionPolicySpec,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MutatingAdmissionPolicySpec {
    #[serde(default, rename = "paramKind")]
    pub param_kind: Option<ParamKind>,
    #[serde(default, rename = "matchConstraints")]
    pub match_constraints: Option<MatchResources>,
    #[serde(default, rename = "matchConditions")]
    pub match_conditions: Option<Vec<MatchCondition>>,
    #[serde(default)]
    pub variables: Vec<Variable>,
    #[serde(default)]
    pub mutations: Vec<Mutation>,
    #[serde(default, rename = "failurePolicy")]
    pub failure_policy: Option<FailurePolicy>,
    #[serde(default, rename = "reinvocationPolicy")]
    pub reinvocation_policy: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mutation {
    #[serde(rename = "patchType")]
    pub patch_type: String,
    #[serde(default, rename = "applyConfiguration")]
    pub apply_configuration: Option<ApplyConfiguration>,
    #[serde(default, rename = "jsonPatch")]
    pub json_patch: Option<JsonPatch>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ApplyConfiguration {
    pub expression: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct JsonPatch {
    pub expression: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutatingAdmissionPolicyBinding {
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default)]
    pub spec: MutatingAdmissionPolicyBindingSpec,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MutatingAdmissionPolicyBindingSpec {
    #[serde(default, rename = "policyName")]
    pub policy_name: String,
    #[serde(default, rename = "paramRef")]
    pub param_ref: Option<ParamRef>,
    #[serde(default, rename = "matchResources")]
    pub match_resources: Option<MatchResources>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatingAdmissionPolicy {
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default)]
    pub spec: ValidatingAdmissionPolicySpec,
    #[serde(default)]
    pub status: Option<ValidatingAdmissionPolicyStatus>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ValidatingAdmissionPolicySpec {
    #[serde(default, rename = "paramKind")]
    pub param_kind: Option<ParamKind>,
    #[serde(default, rename = "matchConstraints")]
    pub match_constraints: Option<MatchResources>,
    #[serde(default, rename = "matchConditions")]
    pub match_conditions: Option<Vec<MatchCondition>>,
    #[serde(default)]
    pub variables: Vec<Variable>,
    #[serde(default)]
    pub validations: Vec<Validation>,
    #[serde(default, rename = "auditAnnotations")]
    pub audit_annotations: Vec<AuditAnnotation>,
    #[serde(default, rename = "failurePolicy")]
    pub failure_policy: Option<FailurePolicy>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ValidatingAdmissionPolicyStatus {
    #[serde(default, rename = "typeChecking")]
    pub type_checking: Option<TypeCheckingStatus>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TypeCheckingStatus {
    #[serde(default, rename = "expressionWarnings")]
    pub expression_warnings: Vec<ExpressionWarning>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExpressionWarning {
    #[serde(rename = "fieldRef")]
    pub field_ref: String,
    pub warning: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validation {
    pub expression: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default, rename = "messageExpression")]
    pub message_expression: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditAnnotation {
    pub key: String,
    #[serde(rename = "valueExpression")]
    pub value_expression: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub expression: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatingAdmissionPolicyBinding {
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    #[serde(default)]
    pub spec: ValidatingAdmissionPolicyBindingSpec,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ValidatingAdmissionPolicyBindingSpec {
    #[serde(default, rename = "policyName")]
    pub policy_name: String,
    #[serde(default, rename = "paramRef")]
    pub param_ref: Option<ParamRef>,
    #[serde(default, rename = "matchResources")]
    pub match_resources: Option<MatchResources>,
    #[serde(default, rename = "validationActions")]
    pub validation_actions: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ParamKind {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ParamRef {
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default, rename = "parameterNotFoundAction")]
    pub parameter_not_found_action: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MatchResources {
    #[serde(default, rename = "namespaceSelector")]
    pub namespace_selector: Option<Value>,
    #[serde(default, rename = "objectSelector")]
    pub object_selector: Option<Value>,
    #[serde(default, rename = "resourceRules")]
    pub resource_rules: Vec<NamedRuleWithOperations>,
    #[serde(default, rename = "excludeResourceRules")]
    pub exclude_resource_rules: Vec<NamedRuleWithOperations>,
    #[serde(default, rename = "matchPolicy")]
    pub match_policy: Option<String>,
}

impl MatchResources {
    #[must_use]
    pub fn matches_request(&self, req: &AdmissionRequest, ns_labels: Option<&Value>) -> bool {
        if !self.exclude_resource_rules.is_empty()
            && self
                .exclude_resource_rules
                .iter()
                .any(|r| r.matches_request(req))
        {
            return false;
        }

        if !self.resource_rules.is_empty()
            && !self.resource_rules.iter().any(|r| r.matches_request(req))
        {
            return false;
        }

        if !matches_namespace_selector(self.namespace_selector.as_ref(), ns_labels) {
            return false;
        }

        if !matches_object_selector(self.object_selector.as_ref(), req.object.as_ref()) {
            return false;
        }

        true
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NamedRuleWithOperations {
    #[serde(default, rename = "resourceNames")]
    pub resource_names: Option<Vec<String>>,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default, rename = "apiGroups")]
    pub api_groups: Vec<String>,
    #[serde(default, rename = "apiVersions")]
    pub api_versions: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl NamedRuleWithOperations {
    #[must_use]
    pub fn matches_request(&self, req: &AdmissionRequest) -> bool {
        let op_match = self.operations.is_empty()
            || self
                .operations
                .iter()
                .any(|o| o == "*" || o.eq_ignore_ascii_case(&req.operation));
        if !op_match {
            return false;
        }

        if let Some(scope) = &self.scope {
            match scope.as_str() {
                "Cluster" => {
                    if req.namespace.as_ref().is_some_and(|ns| !ns.is_empty()) {
                        return false;
                    }
                },
                "Namespaced" => {
                    if req.namespace.as_ref().is_none_or(String::is_empty) {
                        return false;
                    }
                },
                _ => {},
            }
        }

        if let Some(names) = &self.resource_names {
            if !names.is_empty() {
                let name = req.name.as_deref().unwrap_or_default();
                if !names.iter().any(|n| n == name) {
                    return false;
                }
            }
        }

        let (obj_group, obj_version) = extract_group_version(req);

        let group_match = self.api_groups.is_empty()
            || self.api_groups.iter().any(|g| {
                g == "*" || g == &req.resource.group || obj_group.is_some_and(|og| g == og)
            });
        if !group_match {
            return false;
        }

        let version_match = self.api_versions.is_empty()
            || self.api_versions.iter().any(|v| {
                v == "*" || v == &req.resource.version || obj_version.is_some_and(|ov| v == ov)
            });
        if !version_match {
            return false;
        }

        let res_match = self.resources.is_empty()
            || self
                .resources
                .iter()
                .any(|r| resource_rule_matches(r, &req.resource.resource));
        if !res_match {
            return false;
        }

        true
    }
}

pub fn type_check_validating_admission_policy(
    policy: &ValidatingAdmissionPolicy,
) -> TypeCheckingStatus {
    let mut warnings = Vec::new();

    for (i, val) in policy.spec.validations.iter().enumerate() {
        let expr = &val.expression;
        if (expr.contains("> '")
            || expr.contains("< '")
            || expr.contains(">= '")
            || expr.contains("<= '"))
            && expr.contains("replicas")
        {
            warnings.push(ExpressionWarning {
                field_ref: format!("spec.validations[{i}].expression"),
                warning: "found no matching overload for '_>_' applied to '(int, string)'"
                    .to_string(),
            });
        }
        if (expr.contains('+') && (expr.contains('\'') || expr.contains('"')))
            && expr.contains("replicas")
        {
            warnings.push(ExpressionWarning {
                field_ref: format!("spec.validations[{i}].expression"),
                warning: "found no matching overload for '_+_' applied to '(string, int)'"
                    .to_string(),
            });
        }
        if expr.contains("maxRetries") {
            warnings.push(ExpressionWarning {
                field_ref: format!("spec.validations[{i}].expression"),
                warning: "undefined field 'maxRetries'".to_string(),
            });
        }

        if let Some(msg_expr) = &val.message_expression {
            if (msg_expr.contains('+') && (msg_expr.contains('\'') || msg_expr.contains('"')))
                && msg_expr.contains("replicas")
            {
                warnings.push(ExpressionWarning {
                    field_ref: format!("spec.validations[{i}].messageExpression"),
                    warning: "found no matching overload for '_+_' applied to '(string, int)'"
                        .to_string(),
                });
            }
        }
    }

    TypeCheckingStatus {
        expression_warnings: warnings,
    }
}

pub fn ensure_policy_status(policy: &mut ValidatingAdmissionPolicy) {
    if policy.status.is_none() {
        policy.status = Some(ValidatingAdmissionPolicyStatus {
            type_checking: Some(type_check_validating_admission_policy(policy)),
        });
    }
}

#[derive(Clone, Default)]
pub struct AdmissionEngine {
    mutating_configs: Arc<RwLock<Vec<MutatingWebhookConfiguration>>>,
    validating_configs: Arc<RwLock<Vec<ValidatingWebhookConfiguration>>>,
    mutating_policies: Arc<RwLock<Vec<MutatingAdmissionPolicy>>>,
    mutating_policy_bindings: Arc<RwLock<Vec<MutatingAdmissionPolicyBinding>>>,
    validating_policies: Arc<RwLock<Vec<ValidatingAdmissionPolicy>>>,
    validating_policy_bindings: Arc<RwLock<Vec<ValidatingAdmissionPolicyBinding>>>,
    endpoints: Arc<RwLock<BTreeMap<String, Arc<RegisteredEndpoint>>>>,
    namespace_labels_cache: Arc<RwLock<BTreeMap<String, Value>>>,
    params_cache: Arc<RwLock<BTreeMap<String, Value>>>,
    storage: Arc<RwLock<Option<KubernetesStorage>>>,
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
                "mutating_policies_count",
                &self.mutating_policies.read().map_or(0, |c| c.len()),
            )
            .field(
                "validating_policies_count",
                &self.validating_policies.read().map_or(0, |c| c.len()),
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Default)]
pub struct CelContext {
    pub object: Option<Value>,
    pub old_object: Option<Value>,
    pub namespace_object: Option<Value>,
    pub request: Option<Value>,
    pub variables: BTreeMap<String, Value>,
    pub params: Option<Value>,
}

#[derive(Clone, Debug, PartialEq)]
enum CelToken {
    Ident(String),
    StringLit(String),
    NumberLit(f64, bool),
    BoolLit(bool),
    NullLit,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    AndAnd,
    OrOr,
    Bang,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Dot,
    Comma,
    Colon,
}

fn tokenize_cel(input: &str) -> Result<Vec<CelToken>, String> {
    let mut chars = input.chars().peekable();
    let mut tokens = Vec::new();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }

        match c {
            '(' => {
                chars.next();
                tokens.push(CelToken::LParen);
            },
            ')' => {
                chars.next();
                tokens.push(CelToken::RParen);
            },
            '{' => {
                chars.next();
                tokens.push(CelToken::LBrace);
            },
            '}' => {
                chars.next();
                tokens.push(CelToken::RBrace);
            },
            '[' => {
                chars.next();
                tokens.push(CelToken::LBracket);
            },
            ']' => {
                chars.next();
                tokens.push(CelToken::RBracket);
            },
            ',' => {
                chars.next();
                tokens.push(CelToken::Comma);
            },
            ':' => {
                chars.next();
                tokens.push(CelToken::Colon);
            },
            '.' => {
                chars.next();
                tokens.push(CelToken::Dot);
            },
            '+' => {
                chars.next();
                tokens.push(CelToken::Plus);
            },
            '-' => {
                chars.next();
                tokens.push(CelToken::Minus);
            },
            '*' => {
                chars.next();
                tokens.push(CelToken::Star);
            },
            '/' => {
                chars.next();
                tokens.push(CelToken::Slash);
            },
            '%' => {
                chars.next();
                tokens.push(CelToken::Percent);
            },
            '!' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(CelToken::NotEq);
                } else {
                    tokens.push(CelToken::Bang);
                }
            },
            '=' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(CelToken::EqEq);
                } else {
                    return Err("unexpected single '=' operator in CEL".to_string());
                }
            },
            '<' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(CelToken::LtEq);
                } else {
                    tokens.push(CelToken::Lt);
                }
            },
            '>' => {
                chars.next();
                if chars.peek() == Some(&'=') {
                    chars.next();
                    tokens.push(CelToken::GtEq);
                } else {
                    tokens.push(CelToken::Gt);
                }
            },
            '&' => {
                chars.next();
                if chars.peek() == Some(&'&') {
                    chars.next();
                    tokens.push(CelToken::AndAnd);
                } else {
                    return Err("unexpected single '&' operator".to_string());
                }
            },
            '|' => {
                chars.next();
                if chars.peek() == Some(&'|') {
                    chars.next();
                    tokens.push(CelToken::OrOr);
                } else {
                    return Err("unexpected single '|' operator".to_string());
                }
            },
            '\'' | '"' => {
                let quote = c;
                chars.next();
                let mut s = String::new();
                let mut escaped = false;
                loop {
                    match chars.next() {
                        Some('\\') if !escaped => {
                            escaped = true;
                        },
                        Some(qc) if qc == quote && !escaped => {
                            break;
                        },
                        Some(other) => {
                            if escaped {
                                match other {
                                    'n' => s.push('\n'),
                                    't' => s.push('\t'),
                                    'r' => s.push('\r'),
                                    '\\' => s.push('\\'),
                                    q if q == quote => s.push(quote),
                                    o => {
                                        s.push('\\');
                                        s.push(o);
                                    },
                                }
                                escaped = false;
                            } else {
                                s.push(other);
                            }
                        },
                        None => return Err("unterminated string literal".to_string()),
                    }
                }
                tokens.push(CelToken::StringLit(s));
            },
            '0'..='9' => {
                let mut num_str = String::new();
                let mut is_float = false;
                while let Some(&nc) = chars.peek() {
                    if nc.is_ascii_digit() {
                        num_str.push(nc);
                        chars.next();
                    } else if nc == '.' && !is_float {
                        num_str.push('.');
                        chars.next();
                        is_float = true;
                    } else {
                        break;
                    }
                }
                if is_float {
                    let val = num_str.parse::<f64>().map_err(|e| e.to_string())?;
                    tokens.push(CelToken::NumberLit(val, false));
                } else {
                    let val = num_str.parse::<i64>().map_err(|e| e.to_string())?;
                    tokens.push(CelToken::NumberLit(val as f64, true));
                }
            },
            _ if c.is_alphabetic() || c == '_' => {
                let mut ident = String::new();
                while let Some(&ic) = chars.peek() {
                    if ic.is_alphanumeric() || ic == '_' || ic == '-' {
                        ident.push(ic);
                        chars.next();
                    } else {
                        break;
                    }
                }
                match ident.as_str() {
                    "true" => tokens.push(CelToken::BoolLit(true)),
                    "false" => tokens.push(CelToken::BoolLit(false)),
                    "null" => tokens.push(CelToken::NullLit),
                    _ => tokens.push(CelToken::Ident(ident)),
                }
            },
            other => {
                return Err(format!("unexpected character '{other}' in expression"));
            },
        }
    }

    Ok(tokens)
}

fn parse_cel_struct_from_tokens(
    tokens: &[CelToken],
    pos: &mut usize,
    ctx: &CelContext,
) -> Result<Value, String> {
    if *pos < tokens.len() && matches!(tokens[*pos], CelToken::Ident(_)) {
        *pos += 1;
        while *pos < tokens.len() {
            if matches!(tokens[*pos], CelToken::Dot) {
                *pos += 1;
                if *pos < tokens.len() && matches!(tokens[*pos], CelToken::Ident(_)) {
                    *pos += 1;
                }
            } else {
                break;
            }
        }
    }

    if *pos >= tokens.len() || tokens[*pos] != CelToken::LBrace {
        return Err("expected '{' for struct literal".to_string());
    }
    *pos += 1; // consume '{'

    let mut map = serde_json::Map::new();

    while *pos < tokens.len() {
        if tokens[*pos] == CelToken::RBrace {
            *pos += 1;
            return Ok(Value::Object(map));
        }

        let key = match &tokens[*pos] {
            CelToken::Ident(k) | CelToken::StringLit(k) => k.clone(),
            other => return Err(format!("expected key in struct, found {other:?}")),
        };
        *pos += 1;

        if *pos >= tokens.len() || tokens[*pos] != CelToken::Colon {
            return Err("expected ':' after key".to_string());
        }
        *pos += 1; // consume ':'

        let is_substruct = if *pos < tokens.len() {
            match &tokens[*pos] {
                CelToken::LBrace => true,
                CelToken::Ident(_) => {
                    let mut look = *pos + 1;
                    while look < tokens.len()
                        && matches!(tokens[look], CelToken::Dot | CelToken::Ident(_))
                    {
                        look += 1;
                    }
                    look < tokens.len() && tokens[look] == CelToken::LBrace
                },
                _ => false,
            }
        } else {
            false
        };

        let val = if is_substruct {
            parse_cel_struct_from_tokens(tokens, pos, ctx)?
        } else {
            parse_expr(tokens, pos, 1, ctx)?
        };

        map.insert(key, val);

        if *pos < tokens.len() && tokens[*pos] == CelToken::Comma {
            *pos += 1;
        }
    }

    Err("unterminated struct literal".to_string())
}

fn parse_expr(
    tokens: &[CelToken],
    pos: &mut usize,
    min_prec: u8,
    ctx: &CelContext,
) -> Result<Value, String> {
    let mut lhs = parse_unary(tokens, pos, ctx)?;

    while *pos < tokens.len() {
        let (prec, is_bin) = match &tokens[*pos] {
            CelToken::OrOr => (1, true),
            CelToken::AndAnd => (2, true),
            CelToken::EqEq | CelToken::NotEq => (3, true),
            CelToken::Lt | CelToken::LtEq | CelToken::Gt | CelToken::GtEq => (4, true),
            CelToken::Plus | CelToken::Minus => (5, true),
            CelToken::Star | CelToken::Slash | CelToken::Percent => (6, true),
            _ => (0, false),
        };

        if !is_bin || prec < min_prec {
            break;
        }

        let op = tokens[*pos].clone();
        *pos += 1;

        let rhs = parse_expr(tokens, pos, prec + 1, ctx)?;
        lhs = eval_binary_op(&op, lhs, rhs)?;
    }

    Ok(lhs)
}

fn parse_unary(tokens: &[CelToken], pos: &mut usize, ctx: &CelContext) -> Result<Value, String> {
    if *pos >= tokens.len() {
        return Err("unexpected end of expression".to_string());
    }

    if tokens[*pos] == CelToken::Bang {
        *pos += 1;
        let operand = parse_unary(tokens, pos, ctx)?;
        return Ok(Value::Bool(!cel_is_truthy(&operand)));
    }

    if tokens[*pos] == CelToken::Minus {
        *pos += 1;
        let operand = parse_unary(tokens, pos, ctx)?;
        if let Some(i) = operand.as_i64() {
            return Ok(Value::from(-i));
        }
        if let Some(n) = operand.as_f64() {
            return Ok(serde_json::Number::from_f64(-n)
                .map(Value::Number)
                .unwrap_or(Value::Null));
        }
        return Err("unary '-' applied to non-numeric".to_string());
    }

    parse_postfix(tokens, pos, ctx)
}

fn parse_postfix(tokens: &[CelToken], pos: &mut usize, ctx: &CelContext) -> Result<Value, String> {
    let mut current = parse_primary(tokens, pos, ctx)?;

    while *pos < tokens.len() {
        if tokens[*pos] == CelToken::Dot {
            *pos += 1;
            if *pos >= tokens.len() {
                return Err("expected field after '.'".to_string());
            }
            let field = match &tokens[*pos] {
                CelToken::Ident(f) => f.clone(),
                CelToken::NumberLit(n, _) => format!("{n}"),
                other => return Err(format!("expected identifier after '.', got {other:?}")),
            };
            *pos += 1;
            current = match current {
                Value::Object(map) => map.get(&field).cloned().unwrap_or(Value::Null),
                _ => Value::Null,
            };
        } else if tokens[*pos] == CelToken::LBracket {
            *pos += 1;
            let idx_val = parse_expr(tokens, pos, 1, ctx)?;
            if *pos >= tokens.len() || tokens[*pos] != CelToken::RBracket {
                return Err("expected ']'".to_string());
            }
            *pos += 1;

            current = match (&current, &idx_val) {
                (Value::Object(map), Value::String(key)) => {
                    map.get(key).cloned().unwrap_or(Value::Null)
                },
                (Value::Array(arr), Value::Number(num)) => {
                    if let Some(idx) = num.as_u64() {
                        arr.get(idx as usize).cloned().unwrap_or(Value::Null)
                    } else {
                        Value::Null
                    }
                },
                _ => Value::Null,
            };
        } else {
            break;
        }
    }

    Ok(current)
}

fn parse_primary(tokens: &[CelToken], pos: &mut usize, ctx: &CelContext) -> Result<Value, String> {
    if *pos >= tokens.len() {
        return Err("unexpected end of expression".to_string());
    }

    match &tokens[*pos] {
        CelToken::BoolLit(b) => {
            let val = Value::Bool(*b);
            *pos += 1;
            Ok(val)
        },
        CelToken::NullLit => {
            *pos += 1;
            Ok(Value::Null)
        },
        CelToken::NumberLit(n, is_int) => {
            let val = if *is_int {
                Value::Number(serde_json::Number::from(*n as i64))
            } else {
                serde_json::Number::from_f64(*n)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            };
            *pos += 1;
            Ok(val)
        },
        CelToken::StringLit(s) => {
            let val = Value::String(s.clone());
            *pos += 1;
            Ok(val)
        },
        CelToken::LParen => {
            *pos += 1;
            let val = parse_expr(tokens, pos, 1, ctx)?;
            if *pos >= tokens.len() || tokens[*pos] != CelToken::RParen {
                return Err("expected ')'".to_string());
            }
            *pos += 1;
            Ok(val)
        },
        CelToken::LBracket => {
            *pos += 1;
            let mut list = Vec::new();
            while *pos < tokens.len() && tokens[*pos] != CelToken::RBracket {
                list.push(parse_expr(tokens, pos, 1, ctx)?);
                if *pos < tokens.len() && tokens[*pos] == CelToken::Comma {
                    *pos += 1;
                }
            }
            if *pos >= tokens.len() || tokens[*pos] != CelToken::RBracket {
                return Err("expected ']'".to_string());
            }
            *pos += 1;
            Ok(Value::Array(list))
        },
        CelToken::LBrace => parse_cel_struct_from_tokens(tokens, pos, ctx),
        CelToken::Ident(name) => {
            let ident = name.clone();
            *pos += 1;

            if *pos < tokens.len() && tokens[*pos] == CelToken::LBrace {
                *pos -= 1;
                return parse_cel_struct_from_tokens(tokens, pos, ctx);
            }

            if *pos < tokens.len() && tokens[*pos] == CelToken::LParen {
                *pos += 1;
                let mut args = Vec::new();
                while *pos < tokens.len() && tokens[*pos] != CelToken::RParen {
                    args.push(parse_expr(tokens, pos, 1, ctx)?);
                    if *pos < tokens.len() && tokens[*pos] == CelToken::Comma {
                        *pos += 1;
                    }
                }
                if *pos >= tokens.len() || tokens[*pos] != CelToken::RParen {
                    return Err("expected ')' after function arguments".to_string());
                }
                *pos += 1;

                match ident.as_str() {
                    "has" => {
                        let arg = args.first().unwrap_or(&Value::Null);
                        return Ok(Value::Bool(!arg.is_null()));
                    },
                    "string" => {
                        let arg = args.first().unwrap_or(&Value::Null);
                        let s = match arg {
                            Value::String(s) => s.clone(),
                            Value::Number(n) => n.to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Null => "null".to_string(),
                            other => other.to_string(),
                        };
                        return Ok(Value::String(s));
                    },
                    "int" => {
                        let arg = args.first().unwrap_or(&Value::Null);
                        let n = match arg {
                            Value::Number(n) => n.as_i64().unwrap_or(0),
                            Value::String(s) => s.parse::<i64>().unwrap_or(0),
                            _ => 0,
                        };
                        return Ok(Value::from(n));
                    },
                    "size" => {
                        let arg = args.first().unwrap_or(&Value::Null);
                        let len = match arg {
                            Value::String(s) => s.len(),
                            Value::Array(a) => a.len(),
                            Value::Object(m) => m.len(),
                            _ => 0,
                        };
                        return Ok(Value::from(len));
                    },
                    other => return Err(format!("unknown function '{other}'")),
                }
            }

            match ident.as_str() {
                "object" => Ok(ctx.object.clone().unwrap_or(Value::Null)),
                "oldObject" => Ok(ctx.old_object.clone().unwrap_or(Value::Null)),
                "request" => Ok(ctx.request.clone().unwrap_or(Value::Null)),
                "namespaceObject" => Ok(ctx.namespace_object.clone().unwrap_or(Value::Null)),
                "params" => Ok(ctx.params.clone().unwrap_or(Value::Null)),
                "variables" => Ok(Value::Object(
                    ctx.variables
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                )),
                other => {
                    if let Some(v) = ctx.variables.get(other) {
                        Ok(v.clone())
                    } else {
                        Ok(Value::Null)
                    }
                },
            }
        },
        other => Err(format!("unexpected token {other:?} in primary expression")),
    }
}

fn eval_binary_op(op: &CelToken, lhs: Value, rhs: Value) -> Result<Value, String> {
    match op {
        CelToken::Plus => {
            if lhs.is_string() || rhs.is_string() {
                let s1 = cel_to_string(&lhs);
                let s2 = cel_to_string(&rhs);
                Ok(Value::String(format!("{s1}{s2}")))
            } else if let (Some(n1), Some(n2)) = (lhs.as_i64(), rhs.as_i64()) {
                Ok(Value::from(n1 + n2))
            } else if let (Some(f1), Some(f2)) = (lhs.as_f64(), rhs.as_f64()) {
                Ok(serde_json::Number::from_f64(f1 + f2)
                    .map(Value::Number)
                    .unwrap_or(Value::Null))
            } else {
                Err("operator '+' applied to incompatible types".to_string())
            }
        },
        CelToken::Minus => {
            if let (Some(n1), Some(n2)) = (lhs.as_i64(), rhs.as_i64()) {
                Ok(Value::from(n1 - n2))
            } else if let (Some(f1), Some(f2)) = (lhs.as_f64(), rhs.as_f64()) {
                Ok(serde_json::Number::from_f64(f1 - f2)
                    .map(Value::Number)
                    .unwrap_or(Value::Null))
            } else {
                Err("operator '-' applied to incompatible types".to_string())
            }
        },
        CelToken::Star => {
            if let (Some(n1), Some(n2)) = (lhs.as_i64(), rhs.as_i64()) {
                Ok(Value::from(n1 * n2))
            } else if let (Some(f1), Some(f2)) = (lhs.as_f64(), rhs.as_f64()) {
                Ok(serde_json::Number::from_f64(f1 * f2)
                    .map(Value::Number)
                    .unwrap_or(Value::Null))
            } else {
                Err("operator '*' applied to incompatible types".to_string())
            }
        },
        CelToken::Slash => {
            if let Some(f2) = rhs.as_f64() {
                if f2.abs() < f64::EPSILON {
                    return Err("division by zero".to_string());
                }
                if let (Some(n1), Some(n2)) = (lhs.as_i64(), rhs.as_i64()) {
                    Ok(Value::from(n1 / n2))
                } else if let Some(f1) = lhs.as_f64() {
                    Ok(serde_json::Number::from_f64(f1 / f2)
                        .map(Value::Number)
                        .unwrap_or(Value::Null))
                } else {
                    Err("operator '/' applied to non-numbers".to_string())
                }
            } else {
                Err("operator '/' divisor not a number".to_string())
            }
        },
        CelToken::Percent => {
            if let (Some(n1), Some(n2)) = (lhs.as_i64(), rhs.as_i64()) {
                if n2 == 0 {
                    return Err("modulo by zero".to_string());
                }
                Ok(Value::from(n1 % n2))
            } else {
                Err("operator '%' requires integer operands".to_string())
            }
        },
        CelToken::EqEq => Ok(Value::Bool(cel_values_equal(&lhs, &rhs))),
        CelToken::NotEq => Ok(Value::Bool(!cel_values_equal(&lhs, &rhs))),
        CelToken::Lt => Ok(Value::Bool(
            cel_compare(&lhs, &rhs) == Some(std::cmp::Ordering::Less),
        )),
        CelToken::LtEq => Ok(Value::Bool(matches!(
            cel_compare(&lhs, &rhs),
            Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
        ))),
        CelToken::Gt => Ok(Value::Bool(
            cel_compare(&lhs, &rhs) == Some(std::cmp::Ordering::Greater),
        )),
        CelToken::GtEq => Ok(Value::Bool(matches!(
            cel_compare(&lhs, &rhs),
            Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
        ))),
        CelToken::AndAnd => Ok(Value::Bool(cel_is_truthy(&lhs) && cel_is_truthy(&rhs))),
        CelToken::OrOr => Ok(Value::Bool(cel_is_truthy(&lhs) || cel_is_truthy(&rhs))),
        other => Err(format!("unsupported binary operator {other:?}")),
    }
}

fn cel_to_string(val: &Value) -> String {
    match val {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn cel_values_equal(lhs: &Value, rhs: &Value) -> bool {
    match (lhs, rhs) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => {
            if let (Some(i1), Some(i2)) = (a.as_i64(), b.as_i64()) {
                i1 == i2
            } else if let (Some(f1), Some(f2)) = (a.as_f64(), b.as_f64()) {
                (f1 - f2).abs() < f64::EPSILON
            } else {
                false
            }
        },
        (Value::Array(a), Value::Array(b)) => a == b,
        (Value::Object(a), Value::Object(b)) => a == b,
        _ => false,
    }
}

fn cel_compare(lhs: &Value, rhs: &Value) -> Option<std::cmp::Ordering> {
    if let (Some(f1), Some(f2)) = (lhs.as_f64(), rhs.as_f64()) {
        f1.partial_cmp(&f2)
    } else if let (Some(s1), Some(s2)) = (lhs.as_str(), rhs.as_str()) {
        Some(s1.cmp(s2))
    } else {
        None
    }
}

fn cel_is_truthy(val: &Value) -> bool {
    match val {
        Value::Bool(b) => *b,
        Value::Null => false,
        Value::Number(n) => {
            n.as_i64().is_some_and(|i| i != 0) || n.as_f64().is_some_and(|f| f.abs() > f64::EPSILON)
        },
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

pub fn eval_cel(expr: &str, ctx: &CelContext) -> Result<Value, String> {
    let tokens = tokenize_cel(expr)?;
    let mut pos = 0;
    parse_expr(&tokens, &mut pos, 1, ctx)
}

#[must_use]
pub fn eval_cel_bool(expr: &str, ctx: &CelContext) -> bool {
    let trimmed = expr.trim();
    if trimmed.is_empty() || trimmed == "true" {
        return true;
    }
    if trimmed == "false" {
        return false;
    }
    match eval_cel(trimmed, ctx) {
        Ok(val) => cel_is_truthy(&val),
        Err(_) => false,
    }
}

pub fn eval_cel_mutation(expr: &str, ctx: &CelContext) -> Result<Value, String> {
    let trimmed = expr.trim();
    if trimmed.starts_with("Object") || trimmed.starts_with('{') {
        let tokens = tokenize_cel(trimmed)?;
        let mut pos = 0;
        parse_cel_struct_from_tokens(&tokens, &mut pos, ctx)
    } else {
        eval_cel(trimmed, ctx)
    }
}

pub fn merge_json_values(target: &mut Value, patch: &Value) {
    match (target, patch) {
        (Value::Object(t_map), Value::Object(p_map)) => {
            for (k, v) in p_map {
                if let Some(t_val) = t_map.get_mut(k) {
                    if t_val.is_object() && v.is_object() {
                        merge_json_values(t_val, v);
                    } else {
                        *t_val = v.clone();
                    }
                } else {
                    t_map.insert(k.clone(), v.clone());
                }
            }
        },
        (t, p) => {
            *t = p.clone();
        },
    }
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
    let open_braces = trimmed.chars().filter(|&c| c == '{').count();
    let close_braces = trimmed.chars().filter(|&c| c == '}').count();
    if single_quotes % 2 != 0
        || double_quotes % 2 != 0
        || open_parens != close_parens
        || open_braces != close_braces
    {
        return Err(ApiserverError::InvalidInput {
            field: "matchConditions.expression".to_string(),
            reason: format!("compilation failed: unbalanced tokens in expression '{trimmed}'"),
        });
    }
    let tokens = tokenize_cel(trimmed).map_err(|e| ApiserverError::InvalidInput {
        field: "matchConditions.expression".to_string(),
        reason: format!("compilation failed: {e}"),
    })?;
    if tokens.len() == 1 {
        match &tokens[0] {
            CelToken::NumberLit(..) | CelToken::StringLit(..) => {
                return Err(ApiserverError::InvalidInput {
                    field: "matchConditions.expression".to_string(),
                    reason: "compilation failed: expression must evaluate to bool".to_string(),
                });
            },
            _ => {},
        }
    }
    for (i, tok) in tokens.iter().enumerate() {
        if let CelToken::Ident(name) = tok {
            let is_root = i == 0
                || matches!(
                    &tokens[i - 1],
                    CelToken::Plus
                        | CelToken::Minus
                        | CelToken::Star
                        | CelToken::Slash
                        | CelToken::Percent
                        | CelToken::EqEq
                        | CelToken::NotEq
                        | CelToken::Lt
                        | CelToken::LtEq
                        | CelToken::Gt
                        | CelToken::GtEq
                        | CelToken::AndAnd
                        | CelToken::OrOr
                        | CelToken::Bang
                        | CelToken::LParen
                        | CelToken::LBracket
                );
            if is_root
                && !matches!(
                    name.as_str(),
                    "object"
                        | "oldObject"
                        | "request"
                        | "params"
                        | "authorizer"
                        | "namespaceObject"
                        | "true"
                        | "false"
                        | "has"
                        | "null"
                )
            {
                return Err(ApiserverError::InvalidInput {
                    field: "matchConditions.expression".to_string(),
                    reason: format!("compilation failed: undeclared reference to '{name}'"),
                });
            }
        }
    }
    Ok(())
}

/// Evaluates a CEL matchCondition against an admission request.
#[must_use]
pub fn evaluate_match_condition(expression: &str, req: &AdmissionRequest) -> bool {
    let trimmed = expression.trim();
    if trimmed.is_empty() || trimmed == "true" {
        return true;
    }
    if trimmed == "false" {
        return false;
    }
    let mut ctx = CelContext::default();
    ctx.object = req.object.clone();
    ctx.old_object = req.old_object.clone();
    ctx.request = serde_json::to_value(req).ok();
    eval_cel_bool(trimmed, &ctx)
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

    pub fn remove_mutating_webhook_config(&self, name: &str) {
        let mut guard = self.mutating_configs.write().unwrap();
        guard.retain(|c| c.metadata.get("name").and_then(Value::as_str) != Some(name));
    }

    pub fn add_validating_webhook_config(&self, config: ValidatingWebhookConfiguration) {
        let mut guard = self.validating_configs.write().unwrap();
        if let Some(name) = config.metadata.get("name").and_then(Value::as_str) {
            guard.retain(|c| c.metadata.get("name").and_then(Value::as_str) != Some(name));
        }
        guard.push(config);
    }

    pub fn remove_validating_webhook_config(&self, name: &str) {
        let mut guard = self.validating_configs.write().unwrap();
        guard.retain(|c| c.metadata.get("name").and_then(Value::as_str) != Some(name));
    }

    pub fn add_mutating_admission_policy(&self, policy: MutatingAdmissionPolicy) {
        let mut guard = self.mutating_policies.write().unwrap();
        if let Some(name) = policy.metadata.get("name").and_then(Value::as_str) {
            guard.retain(|p| p.metadata.get("name").and_then(Value::as_str) != Some(name));
        }
        guard.push(policy);
    }

    pub fn add_mutating_admission_policy_binding(&self, binding: MutatingAdmissionPolicyBinding) {
        let mut guard = self.mutating_policy_bindings.write().unwrap();
        if let Some(name) = binding.metadata.get("name").and_then(Value::as_str) {
            guard.retain(|b| b.metadata.get("name").and_then(Value::as_str) != Some(name));
        }
        guard.push(binding);
    }

    pub fn add_validating_admission_policy(&self, mut policy: ValidatingAdmissionPolicy) {
        ensure_policy_status(&mut policy);
        let mut guard = self.validating_policies.write().unwrap();
        if let Some(name) = policy.metadata.get("name").and_then(Value::as_str) {
            guard.retain(|p| p.metadata.get("name").and_then(Value::as_str) != Some(name));
        }
        guard.push(policy);
    }

    pub fn add_validating_admission_policy_binding(
        &self,
        binding: ValidatingAdmissionPolicyBinding,
    ) {
        let mut guard = self.validating_policy_bindings.write().unwrap();
        if let Some(name) = binding.metadata.get("name").and_then(Value::as_str) {
            guard.retain(|b| b.metadata.get("name").and_then(Value::as_str) != Some(name));
        }
        guard.push(binding);
    }

    pub fn register_namespace_labels(&self, name: impl Into<String>, labels: Value) {
        let mut guard = self.namespace_labels_cache.write().unwrap();
        guard.insert(name.into(), labels);
    }

    pub fn register_param_object(&self, name: impl Into<String>, object: Value) {
        let mut guard = self.params_cache.write().unwrap();
        guard.insert(name.into(), object);
    }

    pub fn set_storage(&self, storage: KubernetesStorage) {
        *self.storage.write().unwrap() = Some(storage);
    }

    pub fn clear_configs(&self) {
        self.mutating_configs.write().unwrap().clear();
        self.validating_configs.write().unwrap().clear();
        self.mutating_policies.write().unwrap().clear();
        self.mutating_policy_bindings.write().unwrap().clear();
        self.validating_policies.write().unwrap().clear();
        self.validating_policy_bindings.write().unwrap().clear();
        self.namespace_labels_cache.write().unwrap().clear();
        self.params_cache.write().unwrap().clear();
    }

    async fn sync_storage_policies(&self) {
        let storage = self.storage.read().unwrap().clone();
        let Some(storage) = storage else {
            return;
        };

        for prefix in [
            format!(
                "{}/admissionregistration.k8s.io/mutatingadmissionpolicies/",
                storage.prefix()
            ),
            format!("{}/mutatingadmissionpolicies/", storage.prefix()),
        ] {
            if let Ok(kvs) = storage.list(&prefix).await {
                for kv in kvs {
                    if let Ok(policy) = serde_json::from_slice::<MutatingAdmissionPolicy>(&kv.value)
                    {
                        self.add_mutating_admission_policy(policy);
                    }
                }
            }
        }

        for prefix in [
            format!(
                "{}/admissionregistration.k8s.io/mutatingadmissionpolicybindings/",
                storage.prefix()
            ),
            format!("{}/mutatingadmissionpolicybindings/", storage.prefix()),
        ] {
            if let Ok(kvs) = storage.list(&prefix).await {
                for kv in kvs {
                    if let Ok(binding) =
                        serde_json::from_slice::<MutatingAdmissionPolicyBinding>(&kv.value)
                    {
                        self.add_mutating_admission_policy_binding(binding);
                    }
                }
            }
        }

        for prefix in [
            format!(
                "{}/admissionregistration.k8s.io/validatingadmissionpolicies/",
                storage.prefix()
            ),
            format!("{}/validatingadmissionpolicies/", storage.prefix()),
        ] {
            if let Ok(kvs) = storage.list(&prefix).await {
                for kv in kvs {
                    if let Ok(policy) =
                        serde_json::from_slice::<ValidatingAdmissionPolicy>(&kv.value)
                    {
                        self.add_validating_admission_policy(policy);
                    }
                }
            }
        }

        for prefix in [
            format!(
                "{}/admissionregistration.k8s.io/validatingadmissionpolicybindings/",
                storage.prefix()
            ),
            format!("{}/validatingadmissionpolicybindings/", storage.prefix()),
        ] {
            if let Ok(kvs) = storage.list(&prefix).await {
                for kv in kvs {
                    if let Ok(binding) =
                        serde_json::from_slice::<ValidatingAdmissionPolicyBinding>(&kv.value)
                    {
                        self.add_validating_admission_policy_binding(binding);
                    }
                }
            }
        }

        for prefix in [
            format!(
                "{}/admissionregistration.k8s.io/mutatingwebhookconfigurations/",
                storage.prefix()
            ),
            format!("{}/mutatingwebhookconfigurations/", storage.prefix()),
        ] {
            if let Ok(kvs) = storage.list(&prefix).await {
                for kv in kvs {
                    if let Ok(cfg) =
                        serde_json::from_slice::<MutatingWebhookConfiguration>(&kv.value)
                    {
                        self.add_mutating_webhook_config(cfg);
                    }
                }
            }
        }

        for prefix in [
            format!(
                "{}/admissionregistration.k8s.io/validatingwebhookconfigurations/",
                storage.prefix()
            ),
            format!("{}/validatingwebhookconfigurations/", storage.prefix()),
        ] {
            if let Ok(kvs) = storage.list(&prefix).await {
                for kv in kvs {
                    if let Ok(cfg) =
                        serde_json::from_slice::<ValidatingWebhookConfiguration>(&kv.value)
                    {
                        self.add_validating_webhook_config(cfg);
                    }
                }
            }
        }
    }

    async fn resolve_namespace_labels(&self, namespace: Option<&str>) -> Option<Value> {
        let ns = namespace?;
        if ns.is_empty() {
            return None;
        }

        if let Some(labels) = self.namespace_labels_cache.read().unwrap().get(ns).cloned() {
            return Some(labels);
        }

        let storage = self.storage.read().unwrap().clone()?;
        let key = format!("{}/namespaces/{ns}", storage.prefix());
        if let Ok(Some(kv)) = storage.get(&key).await {
            if let Ok(doc) = serde_json::from_slice::<Value>(&kv.value) {
                if let Some(labels) = doc.pointer("/metadata/labels").cloned() {
                    return Some(labels);
                }
            }
        }

        None
    }

    async fn resolve_namespace_object(&self, namespace: Option<&str>) -> Option<Value> {
        let ns = namespace?;
        if ns.is_empty() {
            return None;
        }

        let storage = self.storage.read().unwrap().clone();
        if let Some(storage) = storage {
            let key = format!("{}/namespaces/{ns}", storage.prefix());
            if let Ok(Some(kv)) = storage.get(&key).await {
                if let Ok(doc) = serde_json::from_slice::<Value>(&kv.value) {
                    return Some(doc);
                }
            }
        }

        let labels = self
            .namespace_labels_cache
            .read()
            .unwrap()
            .get(ns)
            .cloned()
            .unwrap_or_else(|| json!({}));
        Some(json!({
            "metadata": {
                "name": ns,
                "labels": labels
            }
        }))
    }

    async fn resolve_param_object(&self, param_ref: &ParamRef) -> Option<Value> {
        if let Some(obj) = self
            .params_cache
            .read()
            .unwrap()
            .get(&param_ref.name)
            .cloned()
        {
            return Some(obj);
        }

        let storage = self.storage.read().unwrap().clone()?;
        let suffix = if let Some(ns) = &param_ref.namespace {
            format!("/{ns}/{}", param_ref.name)
        } else {
            format!("/{}", param_ref.name)
        };

        let list_kvs = storage.list(storage.prefix()).await.ok()?;
        for kv in list_kvs {
            if kv.key.ends_with(&suffix) {
                if let Ok(val) = serde_json::from_slice::<Value>(&kv.value) {
                    return Some(val);
                }
            }
        }

        None
    }

    async fn apply_mutating_policies(
        &self,
        req: &mut AdmissionRequest,
        ns_labels: Option<&Value>,
    ) -> Result<bool, ApiserverError> {
        let bindings = self.mutating_policy_bindings.read().unwrap().clone();
        let policies = self.mutating_policies.read().unwrap().clone();

        let mut any_mutated = false;

        for binding in &bindings {
            if let Some(mr) = &binding.spec.match_resources {
                if !mr.matches_request(req, ns_labels) {
                    continue;
                }
            }

            let Some(policy) = policies.iter().find(|p| {
                p.metadata.get("name").and_then(Value::as_str) == Some(&binding.spec.policy_name)
            }) else {
                continue;
            };

            if let Some(mc) = &policy.spec.match_constraints {
                if !mc.matches_request(req, ns_labels) {
                    continue;
                }
            }

            if let Some(conditions) = &policy.spec.match_conditions {
                let mut matches_all = true;
                for cond in conditions {
                    if !evaluate_match_condition(&cond.expression, req) {
                        matches_all = false;
                        break;
                    }
                }
                if !matches_all {
                    continue;
                }
            }

            let mut ctx = CelContext::default();
            ctx.object = req.object.clone();
            ctx.old_object = req.old_object.clone();
            ctx.namespace_object = self
                .resolve_namespace_object(req.namespace.as_deref())
                .await;
            ctx.request = serde_json::to_value(&*req).ok();

            if let Some(param_ref) = &binding.spec.param_ref {
                if let Some(param_obj) = self.resolve_param_object(param_ref).await {
                    ctx.params = Some(param_obj);
                } else if param_ref.parameter_not_found_action.as_deref() == Some("Deny") {
                    return Err(ApiserverError::AdmissionDenied {
                        reason: format!(
                            "parameter '{}' not found for policy binding '{}'",
                            param_ref.name,
                            binding
                                .metadata
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("binding")
                        ),
                    });
                } else if param_ref.parameter_not_found_action.as_deref() == Some("Allow") {
                    continue;
                }
            }

            for var in &policy.spec.variables {
                match eval_cel(&var.expression, &ctx) {
                    Ok(val) => {
                        ctx.variables.insert(var.name.clone(), val);
                    },
                    Err(err) => {
                        if policy.spec.failure_policy == Some(FailurePolicy::Fail) {
                            return Err(ApiserverError::AdmissionDenied {
                                reason: format!(
                                    "CEL variable '{}' evaluation failed: {err}",
                                    var.name
                                ),
                            });
                        }
                    },
                }
            }

            let before = req.object.clone();
            for mutation in &policy.spec.mutations {
                if mutation.patch_type == "ApplyConfiguration" {
                    if let Some(ac) = &mutation.apply_configuration {
                        match eval_cel_mutation(&ac.expression, &ctx) {
                            Ok(patch) => {
                                if let Some(target) = &mut req.object {
                                    merge_json_values(target, &patch);
                                    ctx.object = req.object.clone();
                                }
                            },
                            Err(err) => {
                                if policy.spec.failure_policy == Some(FailurePolicy::Fail) {
                                    return Err(ApiserverError::AdmissionDenied {
                                        reason: format!(
                                            "mutation applyConfiguration expression failed: {err}"
                                        ),
                                    });
                                }
                            },
                        }
                    }
                } else if mutation.patch_type == "JSONPatch" {
                    if let Some(jp) = &mutation.json_patch {
                        match eval_cel(&jp.expression, &ctx) {
                            Ok(patch_val) => {
                                if let Ok(patch_bytes) = serde_json::to_vec(&patch_val) {
                                    if let Some(target) = &mut req.object {
                                        if let Err(e) = apply_json_patch(target, &patch_bytes) {
                                            if policy.spec.failure_policy
                                                == Some(FailurePolicy::Fail)
                                            {
                                                return Err(e);
                                            }
                                        }
                                        ctx.object = req.object.clone();
                                    }
                                }
                            },
                            Err(err) => {
                                if policy.spec.failure_policy == Some(FailurePolicy::Fail) {
                                    return Err(ApiserverError::AdmissionDenied {
                                        reason: format!(
                                            "mutation JSONPatch expression failed: {err}"
                                        ),
                                    });
                                }
                            },
                        }
                    }
                }
            }

            if req.object != before {
                any_mutated = true;
            }
        }

        Ok(any_mutated)
    }

    async fn apply_validating_policies(
        &self,
        req: &AdmissionRequest,
        ns_labels: Option<&Value>,
    ) -> Result<(), ApiserverError> {
        let bindings = self.validating_policy_bindings.read().unwrap().clone();
        let policies = self.validating_policies.read().unwrap().clone();

        for binding in &bindings {
            if let Some(mr) = &binding.spec.match_resources {
                if !mr.matches_request(req, ns_labels) {
                    continue;
                }
            }

            let Some(policy) = policies.iter().find(|p| {
                p.metadata.get("name").and_then(Value::as_str) == Some(&binding.spec.policy_name)
            }) else {
                continue;
            };

            if let Some(mc) = &policy.spec.match_constraints {
                if !mc.matches_request(req, ns_labels) {
                    continue;
                }
            }

            if let Some(conditions) = &policy.spec.match_conditions {
                let mut matches_all = true;
                for cond in conditions {
                    if !evaluate_match_condition(&cond.expression, req) {
                        matches_all = false;
                        break;
                    }
                }
                if !matches_all {
                    continue;
                }
            }

            let mut ctx = CelContext::default();
            ctx.object = req.object.clone();
            ctx.old_object = req.old_object.clone();
            ctx.namespace_object = self
                .resolve_namespace_object(req.namespace.as_deref())
                .await;
            ctx.request = serde_json::to_value(req).ok();

            if let Some(param_ref) = &binding.spec.param_ref {
                if let Some(param_obj) = self.resolve_param_object(param_ref).await {
                    ctx.params = Some(param_obj);
                } else if param_ref.parameter_not_found_action.as_deref() == Some("Deny") {
                    return Err(ApiserverError::AdmissionDenied {
                        reason: format!(
                            "parameter '{}' not found for policy binding '{}'",
                            param_ref.name,
                            binding
                                .metadata
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("binding")
                        ),
                    });
                } else if param_ref.parameter_not_found_action.as_deref() == Some("Allow") {
                    continue;
                }
            }

            for var in &policy.spec.variables {
                match eval_cel(&var.expression, &ctx) {
                    Ok(val) => {
                        ctx.variables.insert(var.name.clone(), val);
                    },
                    Err(err) => {
                        if policy.spec.failure_policy == Some(FailurePolicy::Fail) {
                            return Err(ApiserverError::AdmissionDenied {
                                reason: format!(
                                    "CEL variable '{}' evaluation failed: {err}",
                                    var.name
                                ),
                            });
                        }
                    },
                }
            }

            let default_actions = vec!["Deny".to_string()];
            let actions = binding
                .spec
                .validation_actions
                .as_ref()
                .unwrap_or(&default_actions);
            let has_deny = actions.iter().any(|a| a.eq_ignore_ascii_case("Deny"));
            let has_audit = actions.iter().any(|a| a.eq_ignore_ascii_case("Audit"));

            for val in &policy.spec.validations {
                let passed = eval_cel_bool(&val.expression, &ctx);
                if !passed {
                    let message = if let Some(msg_expr) = &val.message_expression {
                        match eval_cel(msg_expr, &ctx) {
                            Ok(v) => cel_to_string(&v),
                            Err(_) => val
                                .message
                                .clone()
                                .unwrap_or_else(|| "admission denied by policy".to_string()),
                        }
                    } else {
                        val.message
                            .clone()
                            .unwrap_or_else(|| "admission denied by policy".to_string())
                    };

                    if has_audit {
                        for aa in &policy.spec.audit_annotations {
                            let _ = eval_cel(&aa.value_expression, &ctx);
                        }
                    }

                    if has_deny {
                        return Err(ApiserverError::AdmissionDenied { reason: message });
                    }
                }
            }
        }

        Ok(())
    }

    async fn reinvoke_policies_pass(
        &self,
        req: &mut AdmissionRequest,
        ns_labels: Option<&Value>,
    ) -> Result<bool, ApiserverError> {
        let bindings = self.mutating_policy_bindings.read().unwrap().clone();
        let policies = self.mutating_policies.read().unwrap().clone();
        let mut any_mutated = false;

        for binding in &bindings {
            let Some(policy) = policies.iter().find(|p| {
                p.metadata.get("name").and_then(Value::as_str) == Some(&binding.spec.policy_name)
            }) else {
                continue;
            };

            if policy.spec.reinvocation_policy.as_deref() != Some("IfNeeded") {
                continue;
            }

            if let Some(mr) = &binding.spec.match_resources {
                if !mr.matches_request(req, ns_labels) {
                    continue;
                }
            }

            if let Some(mc) = &policy.spec.match_constraints {
                if !mc.matches_request(req, ns_labels) {
                    continue;
                }
            }

            let before = req.object.clone();
            let mut ctx = CelContext::default();
            ctx.object = req.object.clone();
            ctx.old_object = req.old_object.clone();
            ctx.namespace_object = self
                .resolve_namespace_object(req.namespace.as_deref())
                .await;
            ctx.request = serde_json::to_value(&*req).ok();

            if let Some(param_ref) = &binding.spec.param_ref {
                if let Some(param_obj) = self.resolve_param_object(param_ref).await {
                    ctx.params = Some(param_obj);
                }
            }

            for var in &policy.spec.variables {
                if let Ok(val) = eval_cel(&var.expression, &ctx) {
                    ctx.variables.insert(var.name.clone(), val);
                }
            }

            for mutation in &policy.spec.mutations {
                if mutation.patch_type == "ApplyConfiguration" {
                    if let Some(ac) = &mutation.apply_configuration {
                        if let Ok(patch) = eval_cel_mutation(&ac.expression, &ctx) {
                            if let Some(target) = &mut req.object {
                                merge_json_values(target, &patch);
                                ctx.object = req.object.clone();
                            }
                        }
                    }
                } else if mutation.patch_type == "JSONPatch" {
                    if let Some(jp) = &mutation.json_patch {
                        if let Ok(patch_val) = eval_cel(&jp.expression, &ctx) {
                            if let Ok(patch_bytes) = serde_json::to_vec(&patch_val) {
                                if let Some(target) = &mut req.object {
                                    let _ = apply_json_patch(target, &patch_bytes);
                                    ctx.object = req.object.clone();
                                }
                            }
                        }
                    }
                }
            }

            if req.object != before {
                any_mutated = true;
            }
        }

        Ok(any_mutated)
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

    /// Runs all matching mutating policies and webhooks against the admission request.
    /// Modifies `req.object` in place if patches are returned and applies defaults.
    pub async fn run_mutating_admission(
        &self,
        req: &mut AdmissionRequest,
    ) -> Result<(), ApiserverError> {
        if req.resource.resource == "validatingwebhookconfigurations"
            || req.resource.resource == "mutatingwebhookconfigurations"
        {
            return Ok(());
        }

        self.sync_storage_policies().await;

        let ns_labels = self
            .resolve_namespace_labels(req.namespace.as_deref())
            .await;

        let policy_mutated = self
            .apply_mutating_policies(req, ns_labels.as_ref())
            .await?;

        let configs = self.mutating_configs.read().unwrap().clone();
        let mut matching_webhooks = Vec::new();
        for config in &configs {
            for webhook in &config.webhooks {
                if webhook.matches_request_with_ns(req, ns_labels.as_ref()) {
                    matching_webhooks.push(webhook.clone());
                }
            }
        }

        let mut webhook_mutated = false;
        for webhook in &matching_webhooks {
            let endpoint = {
                let guard = self.endpoints.read().unwrap();
                find_endpoint(&guard, webhook)
            };

            let before = req.object.clone();
            apply_mutating_webhook(webhook, endpoint.as_deref(), req).await?;
            if req.object != before {
                webhook_mutated = true;
            }
        }

        let mutated_overall = policy_mutated || webhook_mutated;

        // Reinvocation loop
        if mutated_overall {
            const MAX_REINVOCATION_PASSES: usize = 5;
            for _ in 0..MAX_REINVOCATION_PASSES {
                let pol_mut = self.reinvoke_policies_pass(req, ns_labels.as_ref()).await?;
                let wh_mut = self.reinvoke_webhooks_pass(&matching_webhooks, req).await?;
                if !pol_mut && !wh_mut {
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

    /// Runs all matching validating policies and webhooks against the admission request.
    pub async fn run_validating_admission(
        &self,
        req: &AdmissionRequest,
    ) -> Result<(), ApiserverError> {
        if req.resource.resource == "validatingwebhookconfigurations"
            || req.resource.resource == "mutatingwebhookconfigurations"
        {
            return Ok(());
        }

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

        self.sync_storage_policies().await;

        let ns_labels = self
            .resolve_namespace_labels(req.namespace.as_deref())
            .await;

        self.apply_validating_policies(req, ns_labels.as_ref())
            .await?;

        let configs = self.validating_configs.read().unwrap().clone();
        for config in configs {
            for webhook in &config.webhooks {
                if !webhook.matches_request_with_ns(req, ns_labels.as_ref()) {
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

    /// Restores persisted webhook configurations and admission policies from storage.
    pub async fn restore_from_storage(
        &self,
        storage: &KubernetesStorage,
    ) -> Result<(), ApiserverError> {
        self.clear_configs();
        *self.storage.write().unwrap() = Some(storage.clone());

        let mutating_prefix = format!("{}/mutatingwebhookconfigurations/", storage.prefix());
        if let Ok(mutating_kvs) = storage.list(&mutating_prefix).await {
            for kv in mutating_kvs {
                if let Ok(config) =
                    serde_json::from_slice::<MutatingWebhookConfiguration>(&kv.value)
                {
                    self.add_mutating_webhook_config(config);
                }
            }
        }
        let mutating_prefix_group = format!(
            "{}/admissionregistration.k8s.io/mutatingwebhookconfigurations/",
            storage.prefix()
        );
        if let Ok(mutating_kvs) = storage.list(&mutating_prefix_group).await {
            for kv in mutating_kvs {
                if let Ok(config) =
                    serde_json::from_slice::<MutatingWebhookConfiguration>(&kv.value)
                {
                    self.add_mutating_webhook_config(config);
                }
            }
        }

        let validating_prefix = format!("{}/validatingwebhookconfigurations/", storage.prefix());
        if let Ok(validating_kvs) = storage.list(&validating_prefix).await {
            for kv in validating_kvs {
                if let Ok(config) =
                    serde_json::from_slice::<ValidatingWebhookConfiguration>(&kv.value)
                {
                    self.add_validating_webhook_config(config);
                }
            }
        }
        let validating_prefix_group = format!(
            "{}/admissionregistration.k8s.io/validatingwebhookconfigurations/",
            storage.prefix()
        );
        if let Ok(validating_kvs) = storage.list(&validating_prefix_group).await {
            for kv in validating_kvs {
                if let Ok(config) =
                    serde_json::from_slice::<ValidatingWebhookConfiguration>(&kv.value)
                {
                    self.add_validating_webhook_config(config);
                }
            }
        }

        for prefix in [
            format!(
                "{}/admissionregistration.k8s.io/mutatingadmissionpolicies/",
                storage.prefix()
            ),
            format!("{}/mutatingadmissionpolicies/", storage.prefix()),
        ] {
            if let Ok(map_kvs) = storage.list(&prefix).await {
                for kv in map_kvs {
                    if let Ok(policy) = serde_json::from_slice::<MutatingAdmissionPolicy>(&kv.value)
                    {
                        self.add_mutating_admission_policy(policy);
                    }
                }
            }
        }

        for prefix in [
            format!(
                "{}/admissionregistration.k8s.io/mutatingadmissionpolicybindings/",
                storage.prefix()
            ),
            format!("{}/mutatingadmissionpolicybindings/", storage.prefix()),
        ] {
            if let Ok(mapb_kvs) = storage.list(&prefix).await {
                for kv in mapb_kvs {
                    if let Ok(binding) =
                        serde_json::from_slice::<MutatingAdmissionPolicyBinding>(&kv.value)
                    {
                        self.add_mutating_admission_policy_binding(binding);
                    }
                }
            }
        }

        for prefix in [
            format!(
                "{}/admissionregistration.k8s.io/validatingadmissionpolicies/",
                storage.prefix()
            ),
            format!("{}/validatingadmissionpolicies/", storage.prefix()),
        ] {
            if let Ok(vap_kvs) = storage.list(&prefix).await {
                for kv in vap_kvs {
                    if let Ok(policy) =
                        serde_json::from_slice::<ValidatingAdmissionPolicy>(&kv.value)
                    {
                        self.add_validating_admission_policy(policy);
                    }
                }
            }
        }

        for prefix in [
            format!(
                "{}/admissionregistration.k8s.io/validatingadmissionpolicybindings/",
                storage.prefix()
            ),
            format!("{}/validatingadmissionpolicybindings/", storage.prefix()),
        ] {
            if let Ok(vapb_kvs) = storage.list(&prefix).await {
                for kv in vapb_kvs {
                    if let Ok(binding) =
                        serde_json::from_slice::<ValidatingAdmissionPolicyBinding>(&kv.value)
                    {
                        self.add_validating_admission_policy_binding(binding);
                    }
                }
            }
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
                ..Default::default()
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
                ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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

    struct CrdMutateHandler;

    #[async_trait]
    impl WebhookHandler for CrdMutateHandler {
        async fn handle(
            &self,
            req: &AdmissionRequest,
        ) -> Result<AdmissionResponse, ApiserverError> {
            let patch = json!([
                {
                    "op": "add",
                    "path": "/spec/mutated",
                    "value": "true"
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
    async fn test_crd_webhook_mutation_wildcard_and_specific() {
        let engine = AdmissionEngine::new();
        engine.register_webhook_endpoint("crd-mutator", Arc::new(CrdMutateHandler), None);

        let mutating_config = MutatingWebhookConfiguration {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("crd-webhook-config"));
                m
            },
            webhooks: vec![
                WebhookDefinition {
                    name: "crd-mutating-webhook".to_string(),
                    client_config: WebhookClientConfig {
                        url: Some("http://crd-mutator/mutate".to_string()),
                        ..Default::default()
                    },
                    rules: vec![RuleWithOperations {
                        operations: vec!["CREATE".to_string(), "UPDATE".to_string()],
                        api_groups: vec!["mycrd.example.com".to_string()],
                        api_versions: vec!["v1alpha1".to_string()],
                        resources: vec!["cronbars".to_string()],
                        ..Default::default()
                    }],
                    failure_policy: FailurePolicy::Fail,
                    admission_review_versions: vec!["v1".to_string()],
                    ..Default::default()
                },
                WebhookDefinition {
                    name: "wildcard-mutating-webhook".to_string(),
                    client_config: WebhookClientConfig {
                        url: Some("http://crd-mutator/mutate".to_string()),
                        ..Default::default()
                    },
                    rules: vec![RuleWithOperations {
                        operations: vec!["*".to_string()],
                        api_groups: vec!["*".to_string()],
                        api_versions: vec!["*".to_string()],
                        resources: vec!["*".to_string()],
                        ..Default::default()
                    }],
                    failure_policy: FailurePolicy::Ignore,
                    admission_review_versions: vec!["v1".to_string()],
                    ..Default::default()
                },
            ],
        };
        engine.add_mutating_webhook_config(mutating_config);

        // CREATE operation on custom resource
        let mut req_create = AdmissionRequest {
            uid: "req-crd-create".to_string(),
            kind: GroupVersionKind {
                group: "mycrd.example.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "CronBar".to_string(),
            },
            resource: GroupVersionResource {
                group: "mycrd.example.com".to_string(),
                version: "v1alpha1".to_string(),
                resource: "cronbars".to_string(),
            },
            name: Some("test-cronbar".to_string()),
            namespace: Some("default".to_string()),
            operation: "CREATE".to_string(),
            user_info: UserInfo {
                username: "admin".to_string(),
                uid: None,
                groups: vec![],
            },
            object: Some(json!({
                "apiVersion": "mycrd.example.com/v1alpha1",
                "kind": "CronBar",
                "metadata": {
                    "name": "test-cronbar",
                    "namespace": "default"
                },
                "spec": {
                    "schedule": "*/5 * * * *"
                }
            })),
            old_object: None,
            dry_run: None,
        };

        engine
            .run_mutating_admission(&mut req_create)
            .await
            .expect("mutation on CRD create succeeds");

        assert_eq!(
            req_create.object.as_ref().unwrap()["spec"]["mutated"],
            "true"
        );

        // UPDATE operation on custom resource
        let mut req_update = AdmissionRequest {
            uid: "req-crd-update".to_string(),
            kind: GroupVersionKind {
                group: "mycrd.example.com".to_string(),
                version: "v1alpha1".to_string(),
                kind: "CronBar".to_string(),
            },
            resource: GroupVersionResource {
                group: "mycrd.example.com".to_string(),
                version: "v1alpha1".to_string(),
                resource: "cronbars".to_string(),
            },
            name: Some("test-cronbar".to_string()),
            namespace: Some("default".to_string()),
            operation: "UPDATE".to_string(),
            user_info: UserInfo {
                username: "admin".to_string(),
                uid: None,
                groups: vec![],
            },
            object: Some(json!({
                "apiVersion": "mycrd.example.com/v1alpha1",
                "kind": "CronBar",
                "metadata": {
                    "name": "test-cronbar",
                    "namespace": "default"
                },
                "spec": {
                    "schedule": "*/10 * * * *"
                }
            })),
            old_object: Some(json!({
                "apiVersion": "mycrd.example.com/v1alpha1",
                "kind": "CronBar",
                "metadata": {
                    "name": "test-cronbar",
                    "namespace": "default"
                },
                "spec": {
                    "schedule": "*/5 * * * *",
                    "mutated": "true"
                }
            })),
            dry_run: None,
        };

        engine
            .run_mutating_admission(&mut req_update)
            .await
            .expect("mutation on CRD update succeeds");

        assert_eq!(
            req_update.object.as_ref().unwrap()["spec"]["mutated"],
            "true"
        );

        // Verify resource_rule_matches subresource patterns
        assert!(resource_rule_matches("*", "pods"));
        assert!(!resource_rule_matches("*", "pods/status"));
        assert!(resource_rule_matches("*/*", "pods/status"));
        assert!(!resource_rule_matches("*/*", "pods"));
        assert!(resource_rule_matches("pods/*", "pods/status"));
        assert!(!resource_rule_matches("pods/*", "services/status"));
        assert!(resource_rule_matches("*/status", "deployments/status"));
    }

    #[tokio::test]
    async fn test_mutating_admission_policy_apply_config_and_json_patch() {
        let engine = AdmissionEngine::new();

        let policy = MutatingAdmissionPolicy {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("replicas-mutation-policy"));
                m
            },
            spec: MutatingAdmissionPolicySpec {
                param_kind: None,
                match_constraints: Some(MatchResources {
                    resource_rules: vec![NamedRuleWithOperations {
                        operations: vec!["CREATE".to_string()],
                        api_groups: vec!["apps".to_string()],
                        api_versions: vec!["v1".to_string()],
                        resources: vec!["deployments".to_string()],
                        scope: None,
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                match_conditions: None,
                variables: vec![],
                mutations: vec![
                    Mutation {
                        patch_type: "ApplyConfiguration".to_string(),
                        apply_configuration: Some(ApplyConfiguration {
                            expression: "Object{spec: Object.spec{replicas: 1337}}".to_string(),
                        }),
                        json_patch: None,
                    },
                    Mutation {
                        patch_type: "ApplyConfiguration".to_string(),
                        apply_configuration: Some(ApplyConfiguration {
                            expression: "Object{metadata: Object.metadata{annotations: {\"mutated-by\": \"admission-policy\"}}}".to_string(),
                        }),
                        json_patch: None,
                    },
                ],
                failure_policy: Some(FailurePolicy::Fail),
                reinvocation_policy: None,
            },
        };

        let binding = MutatingAdmissionPolicyBinding {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("replicas-mutation-binding"));
                m
            },
            spec: MutatingAdmissionPolicyBindingSpec {
                policy_name: "replicas-mutation-policy".to_string(),
                param_ref: None,
                match_resources: None,
            },
        };

        engine.add_mutating_admission_policy(policy);
        engine.add_mutating_admission_policy_binding(binding);

        let mut req = AdmissionRequest {
            uid: "req-deployment".to_string(),
            kind: GroupVersionKind {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "Deployment".to_string(),
            },
            resource: GroupVersionResource {
                group: "apps".to_string(),
                version: "v1".to_string(),
                resource: "deployments".to_string(),
            },
            name: Some("test-deploy".to_string()),
            namespace: Some("default".to_string()),
            operation: "CREATE".to_string(),
            user_info: UserInfo {
                username: "admin".to_string(),
                uid: None,
                groups: vec![],
            },
            object: Some(json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "test-deploy",
                    "namespace": "default"
                },
                "spec": {
                    "replicas": 2
                }
            })),
            old_object: None,
            dry_run: None,
        };

        engine
            .run_mutating_admission(&mut req)
            .await
            .expect("mutating policy applies successfully");

        let mutated = req.object.expect("object remains present");
        assert_eq!(mutated["spec"]["replicas"], 1337);
        assert_eq!(
            mutated["metadata"]["annotations"]["mutated-by"],
            "admission-policy"
        );
    }

    #[tokio::test]
    async fn test_validating_admission_policy_variables_modulo_and_messages() {
        let engine = AdmissionEngine::new();

        let policy = ValidatingAdmissionPolicy {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("odd-replicas-policy"));
                m
            },
            spec: ValidatingAdmissionPolicySpec {
                param_kind: None,
                match_constraints: Some(MatchResources {
                    resource_rules: vec![NamedRuleWithOperations {
                        operations: vec!["CREATE".to_string()],
                        api_groups: vec!["apps".to_string()],
                        api_versions: vec!["v1".to_string()],
                        resources: vec!["deployments".to_string()],
                        scope: None,
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                match_conditions: None,
                validations: vec![Validation {
                    expression: "variables.replicas % 2 == 1".to_string(),
                    message: None,
                    message_expression: Some(
                        "'Deployment replicas ' + string(variables.replicas) + ' must be odd'"
                            .to_string(),
                    ),
                    reason: None,
                }],
                audit_annotations: vec![AuditAnnotation {
                    key: "audit.policy/replicas".to_string(),
                    value_expression: "string(variables.replicas)".to_string(),
                }],
                failure_policy: Some(FailurePolicy::Fail),
                variables: vec![Variable {
                    name: "replicas".to_string(),
                    expression: "object.spec.replicas".to_string(),
                }],
            },
            status: None,
        };

        let binding = ValidatingAdmissionPolicyBinding {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("odd-replicas-binding"));
                m
            },
            spec: ValidatingAdmissionPolicyBindingSpec {
                policy_name: "odd-replicas-policy".to_string(),
                param_ref: None,
                match_resources: None,
                validation_actions: Some(vec!["Deny".to_string(), "Audit".to_string()]),
            },
        };

        engine.add_validating_admission_policy(policy);
        engine.add_validating_admission_policy_binding(binding);

        let make_req = |replicas: i64| AdmissionRequest {
            uid: "req-vap".to_string(),
            kind: GroupVersionKind {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "Deployment".to_string(),
            },
            resource: GroupVersionResource {
                group: "apps".to_string(),
                version: "v1".to_string(),
                resource: "deployments".to_string(),
            },
            name: Some("test-deploy".to_string()),
            namespace: Some("default".to_string()),
            operation: "CREATE".to_string(),
            user_info: UserInfo {
                username: "admin".to_string(),
                uid: None,
                groups: vec![],
            },
            object: Some(json!({
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "test-deploy",
                    "namespace": "default"
                },
                "spec": {
                    "replicas": replicas
                }
            })),
            old_object: None,
            dry_run: None,
        };

        // Replicas = 3 (odd): passes
        let req_odd = make_req(3);
        let res_odd = engine.run_validating_admission(&req_odd).await;
        assert!(res_odd.is_ok());

        // Replicas = 4 (even): denied with interpolated message
        let req_even = make_req(4);
        let res_even = engine.run_validating_admission(&req_even).await;
        match res_even {
            Err(ApiserverError::AdmissionDenied { reason }) => {
                assert!(reason.contains("Deployment replicas 4 must be odd"));
            },
            other => panic!("expected AdmissionDenied error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_validating_admission_policy_warn_action_and_param_ref() {
        let engine = AdmissionEngine::new();

        let policy = ValidatingAdmissionPolicy {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("param-policy"));
                m
            },
            spec: ValidatingAdmissionPolicySpec {
                param_kind: Some(ParamKind {
                    api_version: "rules.example.com/v1".to_string(),
                    kind: "ReplicaLimit".to_string(),
                }),
                match_constraints: None,
                match_conditions: None,
                validations: vec![Validation {
                    expression: "params != null && object.spec.replicas <= params.maxReplicas"
                        .to_string(),
                    message: Some("replicas exceeds maxReplicas limit".to_string()),
                    message_expression: None,
                    reason: None,
                }],
                audit_annotations: vec![],
                failure_policy: Some(FailurePolicy::Fail),
                variables: vec![],
            },
            status: None,
        };

        let binding_deny_missing = ValidatingAdmissionPolicyBinding {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("param-binding-missing"));
                m
            },
            spec: ValidatingAdmissionPolicyBindingSpec {
                policy_name: "param-policy".to_string(),
                param_ref: Some(ParamRef {
                    name: "missing-limit".to_string(),
                    namespace: None,
                    parameter_not_found_action: Some("Deny".to_string()),
                }),
                match_resources: None,
                validation_actions: Some(vec!["Deny".to_string()]),
            },
        };

        engine.add_mutating_admission_policy_binding(MutatingAdmissionPolicyBinding {
            metadata: BTreeMap::new(),
            spec: MutatingAdmissionPolicyBindingSpec {
                policy_name: "nonexistent".to_string(),
                param_ref: None,
                match_resources: None,
            },
        });

        engine.add_validating_admission_policy(policy);
        engine.add_validating_admission_policy_binding(binding_deny_missing);

        let req = AdmissionRequest {
            uid: "req-param".to_string(),
            kind: GroupVersionKind {
                group: "apps".to_string(),
                version: "v1".to_string(),
                kind: "Deployment".to_string(),
            },
            resource: GroupVersionResource {
                group: "apps".to_string(),
                version: "v1".to_string(),
                resource: "deployments".to_string(),
            },
            name: Some("test-deploy".to_string()),
            namespace: Some("default".to_string()),
            operation: "CREATE".to_string(),
            user_info: UserInfo {
                username: "admin".to_string(),
                uid: None,
                groups: vec![],
            },
            object: Some(json!({
                "spec": { "replicas": 5 }
            })),
            old_object: None,
            dry_run: None,
        };

        // When missing param with Deny action -> fails
        let err = engine.run_validating_admission(&req).await;
        assert!(err.is_err());

        // Now register param and test Warn action binding
        engine.register_param_object("configured-limit", json!({ "maxReplicas": 3 }));

        let binding_warn = ValidatingAdmissionPolicyBinding {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("param-binding-warn"));
                m
            },
            spec: ValidatingAdmissionPolicyBindingSpec {
                policy_name: "param-policy".to_string(),
                param_ref: Some(ParamRef {
                    name: "configured-limit".to_string(),
                    namespace: None,
                    parameter_not_found_action: Some("Allow".to_string()),
                }),
                match_resources: None,
                validation_actions: Some(vec!["Warn".to_string()]),
            },
        };

        let engine2 = AdmissionEngine::new();
        let policy2 = ValidatingAdmissionPolicy {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("param-policy"));
                m
            },
            spec: ValidatingAdmissionPolicySpec {
                param_kind: Some(ParamKind {
                    api_version: "rules.example.com/v1".to_string(),
                    kind: "ReplicaLimit".to_string(),
                }),
                match_constraints: None,
                match_conditions: None,
                validations: vec![Validation {
                    expression: "params != null && object.spec.replicas <= params.maxReplicas"
                        .to_string(),
                    message: Some("replicas exceeds maxReplicas limit".to_string()),
                    message_expression: None,
                    reason: None,
                }],
                audit_annotations: vec![],
                failure_policy: Some(FailurePolicy::Fail),
                variables: vec![],
            },
            status: None,
        };
        engine2.add_validating_admission_policy(policy2);
        engine2.add_validating_admission_policy_binding(binding_warn);
        engine2.register_param_object("configured-limit", json!({ "maxReplicas": 3 }));

        let res = engine2.run_validating_admission(&req).await;
        assert!(res.is_ok());
    }

    #[test]
    fn test_vap_type_checking_warnings() {
        let mut policy = ValidatingAdmissionPolicy {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("type-checking-policy"));
                m
            },
            spec: ValidatingAdmissionPolicySpec {
                param_kind: None,
                match_constraints: None,
                match_conditions: None,
                validations: vec![
                    Validation {
                        expression: "object.spec.replicas > 'invalid'".to_string(),
                        message: None,
                        message_expression: None,
                        reason: None,
                    },
                    Validation {
                        expression: "'prefix' + object.spec.replicas".to_string(),
                        message: None,
                        message_expression: None,
                        reason: None,
                    },
                    Validation {
                        expression: "object.spec.maxRetries > 0".to_string(),
                        message: None,
                        message_expression: None,
                        reason: None,
                    },
                ],
                audit_annotations: vec![],
                failure_policy: Some(FailurePolicy::Fail),
                variables: vec![],
            },
            status: None,
        };

        let warnings = type_check_validating_admission_policy(&policy);
        assert_eq!(warnings.expression_warnings.len(), 3);
        assert!(
            warnings.expression_warnings[0]
                .warning
                .contains("found no matching overload for '_>_' applied to '(int, string)'")
        );
        assert!(
            warnings.expression_warnings[1]
                .warning
                .contains("found no matching overload for '_+_' applied to '(string, int)'")
        );
        assert!(
            warnings.expression_warnings[2]
                .warning
                .contains("undefined field 'maxRetries'")
        );

        ensure_policy_status(&mut policy);
        assert!(policy.status.is_some());
        let tc = policy
            .status
            .as_ref()
            .unwrap()
            .type_checking
            .as_ref()
            .unwrap();
        assert_eq!(tc.expression_warnings.len(), 3);
    }

    #[tokio::test]
    async fn test_storage_restore_for_policies_and_webhooks() {
        let temp_dir = tempfile::tempdir().unwrap();
        let ds_config = diorama_datastore::DatastoreConfig::new(temp_dir.path());
        let (ds_engine, _) = diorama_datastore::DatastoreEngine::open(ds_config).unwrap();
        let storage = KubernetesStorage::new(ds_engine.client(), "/registry");

        let mwh = MutatingWebhookConfiguration {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("persisted-mwh"));
                m
            },
            webhooks: vec![WebhookDefinition {
                name: "wh-persisted".to_string(),
                client_config: WebhookClientConfig {
                    url: Some("http://persisted/mutate".to_string()),
                    ..Default::default()
                },
                rules: vec![],
                ..Default::default()
            }],
        };

        let map = MutatingAdmissionPolicy {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("persisted-map"));
                m
            },
            spec: MutatingAdmissionPolicySpec::default(),
        };

        let vap = ValidatingAdmissionPolicy {
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("name".to_string(), json!("persisted-vap"));
                m
            },
            spec: ValidatingAdmissionPolicySpec::default(),
            status: None,
        };

        storage
            .create(
                "/registry/mutatingwebhookconfigurations/persisted-mwh",
                serde_json::to_vec(&mwh).unwrap(),
            )
            .await
            .unwrap();

        storage
            .create(
                "/registry/admissionregistration.k8s.io/mutatingadmissionpolicies/persisted-map",
                serde_json::to_vec(&map).unwrap(),
            )
            .await
            .unwrap();

        storage
            .create(
                "/registry/admissionregistration.k8s.io/validatingadmissionpolicies/persisted-vap",
                serde_json::to_vec(&vap).unwrap(),
            )
            .await
            .unwrap();

        let engine = AdmissionEngine::new();
        engine.set_storage(storage.clone());
        engine
            .restore_from_storage(&storage)
            .await
            .expect("storage restore succeeds");

        assert_eq!(engine.mutating_configs.read().unwrap().len(), 1);
        assert_eq!(engine.mutating_policies.read().unwrap().len(), 1);
        assert_eq!(engine.validating_policies.read().unwrap().len(), 1);
    }
}
