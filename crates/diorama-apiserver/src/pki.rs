use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use diorama_pki::{validate_certificate_pem, validate_private_key_pem};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256, RsaKeySize, SanType,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x509_parser::prelude::FromDer;

use crate::config::ApiserverConfig;
use crate::error::ApiserverError;

/// Validates that all required PKI credentials and keys exist, are non-empty,
/// and contain valid PEM formatted certificates or keys.
pub fn validate_pki_prerequisites(config: &ApiserverConfig) -> Result<(), ApiserverError> {
    // 1. Client CA
    validate_cert_file(&config.client_ca_file, "client CA")?;

    // 2. Apiserver TLS Cert and Key
    validate_cert_file(&config.tls_cert_file, "API server certificate")?;
    validate_key_file(&config.tls_private_key_file, "API server private key")?;

    // 3. Service Account signing key
    validate_key_file(
        &config.service_account_signing_key_file,
        "service account signing key",
    )?;

    // 4. Request header CA
    validate_cert_file(&config.request_header_ca_file, "request-header CA")?;

    Ok(())
}

fn validate_cert_file(path: &Path, name: &str) -> Result<(), ApiserverError> {
    if !path.exists() {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!("{name} file not found at {}", path.display()),
        });
    }

    let bytes = fs::read(path).map_err(|e| ApiserverError::InvalidCredentials {
        reason: format!("failed to read {name} at {}: {e}", path.display()),
    })?;

    if bytes.is_empty() {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!("{name} file at {} is empty", path.display()),
        });
    }

    validate_certificate_pem(&bytes).map_err(|e| ApiserverError::InvalidCredentials {
        reason: format!(
            "{name} at {} is not a valid PEM certificate: {e}",
            path.display()
        ),
    })?;

    Ok(())
}

fn validate_key_file(path: &Path, name: &str) -> Result<(), ApiserverError> {
    if !path.exists() {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!("{name} file not found at {}", path.display()),
        });
    }

    let bytes = fs::read(path).map_err(|e| ApiserverError::InvalidCredentials {
        reason: format!("failed to read {name} at {}: {e}", path.display()),
    })?;

    if bytes.is_empty() {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!("{name} file at {} is empty", path.display()),
        });
    }

    validate_private_key_pem(&bytes).map_err(|e| ApiserverError::InvalidCredentials {
        reason: format!(
            "{name} at {} is not a valid PEM private key: {e}",
            path.display()
        ),
    })?;

    Ok(())
}

// =============================================================================
// PEM Encoding and Decoding Helpers
// =============================================================================

/// Encodes raw DER bytes into a formatted PEM block.
#[must_use]
pub fn encode_pem(label: &str, der: &[u8]) -> String {
    let b64 = diorama_pki::base64_encode(der);
    let mut lines = Vec::new();
    lines.push(format!("-----BEGIN {label}-----"));
    for chunk in b64.as_bytes().chunks(64) {
        if let Ok(s) = std::str::from_utf8(chunk) {
            lines.push(s.to_string());
        }
    }
    lines.push(format!("-----END {label}-----"));
    lines.join("\n")
}

/// Parses PEM-encoded bytes into a list of (label, DER contents) pairs.
pub fn parse_pem_entries(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ApiserverError> {
    let text = std::str::from_utf8(data).map_err(|e| ApiserverError::InvalidInput {
        field: "spec.trustBundle".into(),
        reason: format!("PEM must be valid UTF-8: {e}"),
    })?;
    let begin_count = text
        .lines()
        .filter(|l| l.starts_with("-----BEGIN "))
        .count();
    let end_count = text.lines().filter(|l| l.starts_with("-----END ")).count();
    if begin_count == 0 || begin_count != end_count {
        return Err(ApiserverError::InvalidInput {
            field: "spec.trustBundle".into(),
            reason: "malformed PEM headers".into(),
        });
    }

    let mut entries = Vec::new();
    for item in x509_parser::pem::Pem::iter_from_buffer(data) {
        let pem = item.map_err(|e| ApiserverError::InvalidInput {
            field: "spec.trustBundle".into(),
            reason: format!("failed to decode PEM block: {e}"),
        })?;
        entries.push((pem.label, pem.contents));
    }

    if entries.len() != begin_count {
        return Err(ApiserverError::InvalidInput {
            field: "spec.trustBundle".into(),
            reason: "mismatched PEM block count".into(),
        });
    }

    Ok(entries)
}

// =============================================================================
// ClusterTrustBundle (certificates.k8s.io/v1, v1beta1, v1alpha1)
// =============================================================================

fn default_ctb_api_version() -> String {
    "certificates.k8s.io/v1".to_string()
}

fn default_ctb_kind() -> String {
    "ClusterTrustBundle".to_string()
}

/// Generic Kubernetes `ObjectMeta` representation for PKI resources.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(
        rename = "resourceVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resource_version: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

/// A cluster-scoped trust anchor collection distributing X.509 CA roots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterTrustBundle {
    #[serde(rename = "apiVersion", default = "default_ctb_api_version")]
    pub api_version: String,
    #[serde(default = "default_ctb_kind")]
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: ClusterTrustBundleSpec,
}

/// Specification for a `ClusterTrustBundle`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterTrustBundleSpec {
    #[serde(
        rename = "signerName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub signer_name: Option<String>,
    #[serde(rename = "trustBundle")]
    pub trust_bundle: String,
}

/// A projection volume source targeting `ClusterTrustBundle` resources.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClusterTrustBundleProjection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        rename = "signerName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub signer_name: Option<String>,
    #[serde(
        rename = "labelSelector",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub label_selector: Option<LabelSelector>,
    #[serde(default)]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Label selector matching `matchLabels` and `matchExpressions`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LabelSelector {
    #[serde(
        rename = "matchLabels",
        default,
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub match_labels: HashMap<String, String>,
    #[serde(
        rename = "matchExpressions",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

/// A requirement in a `LabelSelector`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelSelectorRequirement {
    pub key: String,
    pub operator: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

impl LabelSelector {
    #[must_use]
    pub fn matches(&self, labels: &HashMap<String, String>) -> bool {
        for (k, v) in &self.match_labels {
            if labels.get(k) != Some(v) {
                return false;
            }
        }
        for expr in &self.match_expressions {
            let actual = labels.get(&expr.key);
            let ok = match expr.operator.as_str() {
                "In" => actual.is_some_and(|val| expr.values.iter().any(|v| v == val)),
                "NotIn" => actual.is_none_or(|val| !expr.values.iter().any(|v| v == val)),
                "Exists" => actual.is_some(),
                "DoesNotExist" => actual.is_none(),
                _ => false,
            };
            if !ok {
                return false;
            }
        }
        true
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.match_labels.is_empty() && self.match_expressions.is_empty()
    }
}

/// Validates syntax of a signer name (domain/path format).
#[must_use]
pub fn is_valid_signer_name(signer: &str) -> bool {
    if signer.is_empty() || signer.len() > 571 {
        return false;
    }
    let Some((domain, path)) = signer.split_once('/') else {
        return false;
    };
    if domain.is_empty() || path.is_empty() {
        return false;
    }
    for part in domain.split('.') {
        if part.is_empty() || part.len() > 63 {
            return false;
        }
        if !part
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return false;
        }
        if part.starts_with('-') || part.ends_with('-') {
            return false;
        }
    }
    for c in path.chars() {
        if !c.is_ascii_lowercase()
            && !c.is_ascii_digit()
            && c != '-'
            && c != '.'
            && c != '_'
            && c != '/'
        {
            return false;
        }
    }
    true
}

/// Validates the PEM trust bundle: must contain at least one valid X.509
/// certificate, all certificates must be CAs (`basicConstraints CA:true`),
/// no duplicate certificates allowed, and no non-certificate PEM blocks.
pub fn validate_trust_bundle_pem(pem_str: &str) -> Result<Vec<Vec<u8>>, ApiserverError> {
    let trimmed = pem_str.trim();
    if trimmed.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "spec.trustBundle".into(),
            reason: "trustBundle must not be empty".into(),
        });
    }

    let entries = parse_pem_entries(trimmed.as_bytes())?;
    if entries.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "spec.trustBundle".into(),
            reason: "trustBundle must contain at least one certificate".into(),
        });
    }

    let mut seen_der = HashSet::new();
    let mut der_list = Vec::new();

    for (idx, (label, der)) in entries.iter().enumerate() {
        if label != "CERTIFICATE" {
            return Err(ApiserverError::InvalidInput {
                field: "spec.trustBundle".into(),
                reason: format!(
                    "PEM entry {idx} has tag '{label}', only 'CERTIFICATE' is allowed in trustBundle"
                ),
            });
        }
        if seen_der.contains(der) {
            return Err(ApiserverError::InvalidInput {
                field: "spec.trustBundle".into(),
                reason: format!("trustBundle contains duplicate certificate at entry {idx}"),
            });
        }
        seen_der.insert(der.clone());

        let (_, cert) =
            x509_parser::parse_x509_certificate(der).map_err(|e| ApiserverError::InvalidInput {
                field: "spec.trustBundle".into(),
                reason: format!("entry {idx} is not a valid X.509 certificate: {e}"),
            })?;

        if !cert.is_ca() {
            return Err(ApiserverError::InvalidInput {
                field: "spec.trustBundle".into(),
                reason: format!(
                    "certificate at entry {idx} is not a CA (must have basicConstraints CA:true)"
                ),
            });
        }

        der_list.push(der.clone());
    }

    Ok(der_list)
}

/// Validates a `ClusterTrustBundle` object including signerName syntax, naming
/// convention prefix/colon rules, and trustBundle PEM certificates.
pub fn validate_cluster_trust_bundle(bundle: &ClusterTrustBundle) -> Result<(), ApiserverError> {
    if bundle.metadata.name.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "metadata.name".into(),
            reason: "metadata.name must not be empty".into(),
        });
    }

    if let Some(signer) = &bundle.spec.signer_name {
        if !signer.is_empty() {
            if !is_valid_signer_name(signer) {
                return Err(ApiserverError::InvalidInput {
                    field: "spec.signerName".into(),
                    reason: format!("invalid signerName format: '{signer}'"),
                });
            }
            let expected_prefix = format!("{}:", signer.replace('/', ":"));
            if !bundle.metadata.name.starts_with(&expected_prefix) {
                return Err(ApiserverError::InvalidInput {
                    field: "metadata.name".into(),
                    reason: format!(
                        "metadata.name must start with '{expected_prefix}' when signerName is '{signer}'"
                    ),
                });
            }
            let suffix = &bundle.metadata.name[expected_prefix.len()..];
            if suffix.is_empty() {
                return Err(ApiserverError::InvalidInput {
                    field: "metadata.name".into(),
                    reason: "metadata.name must have a non-empty suffix after signer prefix".into(),
                });
            }
        } else if bundle.metadata.name.contains(':') {
            return Err(ApiserverError::InvalidInput {
                field: "metadata.name".into(),
                reason: "metadata.name must not contain ':' when signerName is empty".into(),
            });
        }
    } else if bundle.metadata.name.contains(':') {
        return Err(ApiserverError::InvalidInput {
            field: "metadata.name".into(),
            reason: "metadata.name must not contain ':' when signerName is not specified".into(),
        });
    }

    validate_trust_bundle_pem(&bundle.spec.trust_bundle)?;

    Ok(())
}

/// Validates that an update to `ClusterTrustBundle` preserves immutability
/// invariants (spec.signerName cannot be changed).
pub fn validate_cluster_trust_bundle_update(
    new_bundle: &ClusterTrustBundle,
    old_bundle: &ClusterTrustBundle,
) -> Result<(), ApiserverError> {
    if new_bundle.spec.signer_name != old_bundle.spec.signer_name {
        return Err(ApiserverError::InvalidInput {
            field: "spec.signerName".into(),
            reason: "field is immutable".into(),
        });
    }
    validate_cluster_trust_bundle(new_bundle)
}

/// Resolves a `ClusterTrustBundleProjection` against a set of `ClusterTrustBundle`
/// resources, combining and deduplicating matching certificates into a consolidated PEM bundle.
pub fn resolve_cluster_trust_bundles(
    projection: &ClusterTrustBundleProjection,
    bundles: &[ClusterTrustBundle],
) -> Result<Option<String>, ApiserverError> {
    if projection.name.is_some() && projection.signer_name.is_some() {
        return Err(ApiserverError::InvalidInput {
            field: "name".into(),
            reason: "name and signerName are mutually exclusive in ClusterTrustBundle projection"
                .into(),
        });
    }
    if projection.name.is_none() && projection.signer_name.is_none() {
        return Err(ApiserverError::InvalidInput {
            field: "name".into(),
            reason: "either name or signerName must be specified in ClusterTrustBundle projection"
                .into(),
        });
    }
    if projection.name.is_some() && projection.label_selector.is_some() {
        return Err(ApiserverError::InvalidInput {
            field: "labelSelector".into(),
            reason:
                "labelSelector is not allowed when name is specified in ClusterTrustBundle projection"
                    .into(),
        });
    }

    let is_optional = projection.optional.unwrap_or(false);

    if let Some(name) = &projection.name {
        if let Some(ctb) = bundles.iter().find(|b| &b.metadata.name == name) {
            return Ok(Some(ctb.spec.trust_bundle.clone()));
        }
        if is_optional {
            return Ok(None);
        }
        return Err(ApiserverError::NotFound {
            resource: "clustertrustbundles".into(),
            name: name.clone(),
        });
    }

    if let Some(signer) = &projection.signer_name {
        let matching: Vec<&ClusterTrustBundle> = bundles
            .iter()
            .filter(|b| b.spec.signer_name.as_deref() == Some(signer))
            .filter(|b| {
                if let Some(sel) = &projection.label_selector {
                    sel.matches(&b.metadata.labels)
                } else {
                    true
                }
            })
            .collect();

        if matching.is_empty() {
            if is_optional {
                return Ok(None);
            }
            return Err(ApiserverError::NotFound {
                resource: "clustertrustbundles".into(),
                name: format!("matching signerName '{signer}'"),
            });
        }

        let mut seen = HashSet::new();
        let mut combined_pems = Vec::new();

        for b in matching {
            let entries = parse_pem_entries(b.spec.trust_bundle.as_bytes())?;
            for (label, der) in entries {
                if label == "CERTIFICATE" && seen.insert(der.clone()) {
                    let encoded = encode_pem("CERTIFICATE", &der);
                    combined_pems.push(encoded);
                }
            }
        }

        return Ok(Some(combined_pems.join("\n")));
    }

    Ok(None)
}

/// An indexed cache of `ClusterTrustBundle` resources for high-scale resolution
/// (>100 CTBs) with sub-millisecond lookup latency.
#[derive(Clone, Debug, Default)]
pub struct ClusterTrustBundleIndex {
    by_name: HashMap<String, ClusterTrustBundle>,
    by_signer: HashMap<String, Vec<ClusterTrustBundle>>,
}

impl ClusterTrustBundleIndex {
    #[must_use]
    pub fn new(bundles: Vec<ClusterTrustBundle>) -> Self {
        let mut index = Self::default();
        for b in bundles {
            index.insert(b);
        }
        index
    }

    pub fn insert(&mut self, bundle: ClusterTrustBundle) {
        if let Some(signer) = &bundle.spec.signer_name
            && !signer.is_empty()
        {
            self.by_signer
                .entry(signer.clone())
                .or_default()
                .push(bundle.clone());
        }
        self.by_name.insert(bundle.metadata.name.clone(), bundle);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    pub fn resolve(
        &self,
        projection: &ClusterTrustBundleProjection,
    ) -> Result<Option<String>, ApiserverError> {
        let is_optional = projection.optional.unwrap_or(false);

        if projection.name.is_some() && projection.signer_name.is_some() {
            return Err(ApiserverError::InvalidInput {
                field: "name".into(),
                reason: "name and signerName are mutually exclusive".into(),
            });
        }
        if projection.name.is_none() && projection.signer_name.is_none() {
            return Err(ApiserverError::InvalidInput {
                field: "name".into(),
                reason: "either name or signerName must be specified".into(),
            });
        }
        if projection.name.is_some() && projection.label_selector.is_some() {
            return Err(ApiserverError::InvalidInput {
                field: "labelSelector".into(),
                reason: "labelSelector is not allowed when name is specified".into(),
            });
        }

        if let Some(name) = &projection.name {
            if let Some(ctb) = self.by_name.get(name) {
                return Ok(Some(ctb.spec.trust_bundle.clone()));
            }
            if is_optional {
                return Ok(None);
            }
            return Err(ApiserverError::NotFound {
                resource: "clustertrustbundles".into(),
                name: name.clone(),
            });
        }

        if let Some(signer) = &projection.signer_name {
            let Some(bundles) = self.by_signer.get(signer) else {
                if is_optional {
                    return Ok(None);
                }
                return Err(ApiserverError::NotFound {
                    resource: "clustertrustbundles".into(),
                    name: format!("matching signerName '{signer}'"),
                });
            };

            let matching: Vec<&ClusterTrustBundle> = bundles
                .iter()
                .filter(|b| {
                    if let Some(sel) = &projection.label_selector {
                        sel.matches(&b.metadata.labels)
                    } else {
                        true
                    }
                })
                .collect();

            if matching.is_empty() {
                if is_optional {
                    return Ok(None);
                }
                return Err(ApiserverError::NotFound {
                    resource: "clustertrustbundles".into(),
                    name: format!("matching signerName '{signer}'"),
                });
            }

            let combined = combine_unique_bundle_pems(matching)?;
            return Ok(Some(combined));
        }

        Ok(None)
    }
}

fn combine_unique_bundle_pems<'a>(
    bundles: impl IntoIterator<Item = &'a ClusterTrustBundle>,
) -> Result<String, ApiserverError> {
    let mut seen = HashSet::new();
    let mut combined_pems = Vec::new();
    for b in bundles {
        let entries = parse_pem_entries(b.spec.trust_bundle.as_bytes())?;
        for (label, der) in entries {
            if label == "CERTIFICATE" && seen.insert(der.clone()) {
                let encoded = encode_pem("CERTIFICATE", &der);
                combined_pems.push(encoded);
            }
        }
    }
    Ok(combined_pems.join("\n"))
}

// =============================================================================
// PodCertificateRequest (certificates.k8s.io/v1alpha1, v1beta1, v1)
// =============================================================================

fn default_pcr_api_version() -> String {
    "certificates.k8s.io/v1".to_string()
}

fn default_pcr_kind() -> String {
    "PodCertificateRequest".to_string()
}

/// Represents a request for an X.509 certificate for a pod.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodCertificateRequest {
    #[serde(rename = "apiVersion", default = "default_pcr_api_version")]
    pub api_version: String,
    #[serde(default = "default_pcr_kind")]
    pub kind: String,
    pub metadata: ObjectMeta,
    pub spec: PodCertificateRequestSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<PodCertificateRequestStatus>,
}

/// Specification for a `PodCertificateRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodCertificateRequestSpec {
    #[serde(rename = "signerName")]
    pub signer_name: String,
    #[serde(rename = "podName")]
    pub pod_name: String,
    #[serde(rename = "podUID")]
    pub pod_uid: String,
    #[serde(rename = "serviceAccountName")]
    pub service_account_name: String,
    #[serde(rename = "serviceAccountUID")]
    pub service_account_uid: String,
    #[serde(rename = "nodeName")]
    pub node_name: String,
    #[serde(rename = "nodeUID")]
    pub node_uid: String,
    #[serde(
        rename = "maxExpirationSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_expiration_seconds: Option<i32>,
    #[serde(
        rename = "unverifiedUserAnnotations",
        default,
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub unverified_user_annotations: HashMap<String, String>,
    #[serde(
        rename = "stubPKCS10Request",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stub_pkcs10_request: Option<Vec<u8>>,
    #[serde(
        rename = "pkixPublicKey",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pkix_public_key: Option<Vec<u8>>,
    #[serde(
        rename = "proofOfPossession",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub proof_of_possession: Option<Vec<u8>>,
}

/// Status of a `PodCertificateRequest`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodCertificateRequestStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<PodCertificateRequestCondition>,
    #[serde(
        rename = "certificateChain",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_chain: Option<String>,
    #[serde(rename = "notBefore", default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(
        rename = "beginRefreshAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub begin_refresh_at: Option<String>,
    #[serde(rename = "notAfter", default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

/// Condition of a `PodCertificateRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodCertificateRequestCondition {
    #[serde(rename = "type")]
    pub condition_type: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(
        rename = "lastTransitionTime",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_transition_time: Option<String>,
}

/// Validates a `PodCertificateRequest` object.
pub fn validate_pod_certificate_request(pcr: &PodCertificateRequest) -> Result<(), ApiserverError> {
    if pcr.metadata.name.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "metadata.name".into(),
            reason: "metadata.name must not be empty".into(),
        });
    }
    validate_pod_certificate_request_spec(&pcr.spec)
}

/// Validates `PodCertificateRequestSpec`: bounds for `maxExpirationSeconds` (1h..=91d),
/// non-empty identity fields, and proof-of-possession or stub CSR.
pub fn validate_pod_certificate_request_spec(
    spec: &PodCertificateRequestSpec,
) -> Result<(), ApiserverError> {
    if spec.signer_name.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "spec.signerName".into(),
            reason: "signerName must not be empty".into(),
        });
    }
    if spec.pod_name.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "spec.podName".into(),
            reason: "podName must not be empty".into(),
        });
    }
    if spec.pod_uid.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "spec.podUID".into(),
            reason: "podUID must not be empty".into(),
        });
    }
    if spec.service_account_name.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "spec.serviceAccountName".into(),
            reason: "serviceAccountName must not be empty".into(),
        });
    }
    if spec.service_account_uid.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "spec.serviceAccountUID".into(),
            reason: "serviceAccountUID must not be empty".into(),
        });
    }
    if spec.node_name.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "spec.nodeName".into(),
            reason: "nodeName must not be empty".into(),
        });
    }
    if spec.node_uid.is_empty() {
        return Err(ApiserverError::InvalidInput {
            field: "spec.nodeUID".into(),
            reason: "nodeUID must not be empty".into(),
        });
    }

    if let Some(exp) = spec.max_expiration_seconds {
        if exp < 3600 {
            return Err(ApiserverError::InvalidInput {
                field: "spec.maxExpirationSeconds".into(),
                reason: format!("maxExpirationSeconds ({exp}) must be at least 3600 (1h)"),
            });
        }
        if exp > 91 * 86_400 {
            return Err(ApiserverError::InvalidInput {
                field: "spec.maxExpirationSeconds".into(),
                reason: format!("maxExpirationSeconds ({exp}) must not exceed 7862400 (91d)"),
            });
        }
    }

    validate_key_and_proof_of_possession(spec)?;

    Ok(())
}

fn validate_key_and_proof_of_possession(
    spec: &PodCertificateRequestSpec,
) -> Result<(), ApiserverError> {
    if let Some(csr_bytes) = &spec.stub_pkcs10_request {
        if csr_bytes.is_empty() {
            return Err(ApiserverError::InvalidInput {
                field: "spec.stubPKCS10Request".into(),
                reason: "stubPKCS10Request must not be empty".into(),
            });
        }
        let csr_der =
            if x509_parser::certification_request::X509CertificationRequest::from_der(csr_bytes)
                .is_ok()
            {
                csr_bytes.clone()
            } else {
                let entries = parse_pem_entries(csr_bytes)?;
                let (_, der) = entries
                    .first()
                    .ok_or_else(|| ApiserverError::InvalidInput {
                        field: "spec.stubPKCS10Request".into(),
                        reason: "empty CSR PEM".into(),
                    })?;
                der.clone()
            };

        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&csr_der)
                .map_err(|e| ApiserverError::InvalidInput {
                    field: "spec.stubPKCS10Request".into(),
                    reason: format!("failed to parse stubPKCS10Request as X.509 CSR: {e}"),
                })?;

        csr.verify_signature()
            .map_err(|e| ApiserverError::InvalidInput {
                field: "spec.stubPKCS10Request".into(),
                reason: format!("CSR self-signature verification failed: {e}"),
            })?;

        return Ok(());
    }

    if let (Some(pkix_bytes), Some(pop_bytes)) = (&spec.pkix_public_key, &spec.proof_of_possession)
    {
        if pkix_bytes.is_empty() || pop_bytes.is_empty() {
            return Err(ApiserverError::InvalidInput {
                field: "spec.pkixPublicKey".into(),
                reason: "pkixPublicKey and proofOfPossession must not be empty".into(),
            });
        }

        let pkix_der = if x509_parser::x509::SubjectPublicKeyInfo::from_der(pkix_bytes).is_ok() {
            pkix_bytes.clone()
        } else {
            let entries = parse_pem_entries(pkix_bytes)?;
            let (_, der) = entries
                .first()
                .ok_or_else(|| ApiserverError::InvalidInput {
                    field: "spec.pkixPublicKey".into(),
                    reason: "empty pkixPublicKey PEM".into(),
                })?;
            der.clone()
        };

        let (_, spki) =
            x509_parser::x509::SubjectPublicKeyInfo::from_der(&pkix_der).map_err(|e| {
                ApiserverError::InvalidInput {
                    field: "spec.pkixPublicKey".into(),
                    reason: format!("failed to parse pkixPublicKey as SubjectPublicKeyInfo: {e}"),
                }
            })?;

        let sig_alg = if spki.algorithm.algorithm
            == x509_parser::oid_registry::OID_PKCS1_RSAENCRYPTION
        {
            x509_parser::x509::AlgorithmIdentifier {
                algorithm: x509_parser::oid_registry::OID_PKCS1_SHA256WITHRSA,
                parameters: None,
            }
        } else if spki.algorithm.algorithm == x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY
        {
            x509_parser::x509::AlgorithmIdentifier {
                algorithm: x509_parser::oid_registry::OID_SIG_ECDSA_WITH_SHA256,
                parameters: None,
            }
        } else {
            spki.algorithm.clone()
        };

        let bit_string = x509_parser::asn1_rs::BitString::new(0, pop_bytes);
        x509_parser::verify::verify_signature(
            &spki,
            &sig_alg,
            &bit_string,
            spec.pod_uid.as_bytes(),
        )
        .map_err(|e| ApiserverError::InvalidInput {
            field: "spec.proofOfPossession".into(),
            reason: format!("proof-of-possession signature verification failed: {e}"),
        })?;

        return Ok(());
    }

    Err(ApiserverError::InvalidInput {
        field: "spec".into(),
        reason: "must provide either stubPKCS10Request or (pkixPublicKey and proofOfPossession)"
            .into(),
    })
}

/// Validates that an update to `PodCertificateRequest` preserves spec immutability.
pub fn validate_pod_certificate_request_update(
    new_pcr: &PodCertificateRequest,
    old_pcr: &PodCertificateRequest,
) -> Result<(), ApiserverError> {
    if new_pcr.spec != old_pcr.spec {
        return Err(ApiserverError::InvalidInput {
            field: "spec".into(),
            reason: "spec is immutable".into(),
        });
    }
    validate_pod_certificate_request(new_pcr)
}

fn resolve_spiffe_uri(pcr: &PodCertificateRequest, td: &str, ns: &str) -> String {
    for (k, v) in &pcr.spec.unverified_user_annotations {
        if v.starts_with("spiffe://") {
            return v.clone();
        }
        let k_lower = k.to_ascii_lowercase();
        if k_lower.ends_with("spiffe-id")
            || k_lower.ends_with("spiffe-uri")
            || k_lower.ends_with("spiffe_id")
            || k_lower.ends_with("spiffe_uri")
        {
            return if v.starts_with('/') {
                format!("spiffe://{td}{v}")
            } else {
                format!("spiffe://{td}/{v}")
            };
        }
        if k_lower.ends_with("spiffe-path")
            || k_lower.ends_with("/path")
            || k_lower == "spiffe.io/path"
        {
            let path = v.strip_prefix('/').unwrap_or(v);
            return format!("spiffe://{td}/{path}");
        }
    }

    format!("spiffe://{td}/ns/{ns}/sa/{}", pcr.spec.service_account_name)
}

fn build_leaf_cert_params(
    pcr: &PodCertificateRequest,
    td: &str,
    ns: &str,
    not_before: u64,
    not_after: u64,
) -> CertificateParams {
    let final_spiffe_uri = resolve_spiffe_uri(pcr, td, ns);
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        format!("system:pod:{}", pcr.spec.pod_name),
    );
    params.distinguished_name = dn;

    if let Ok(ia5) = final_spiffe_uri.try_into() {
        params.subject_alt_names.push(SanType::URI(ia5));
    }
    let dns_name = format!("{}.{ns}.pod.{td}", pcr.spec.pod_name);
    if let Ok(ia5) = dns_name.try_into() {
        params.subject_alt_names.push(SanType::DnsName(ia5));
    }
    if let Ok(ia5) = pcr.spec.pod_name.clone().try_into() {
        params.subject_alt_names.push(SanType::DnsName(ia5));
    }

    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    params.not_before =
        rcgen::date_time_ymd(1970, 1, 1) + std::time::Duration::from_secs(not_before);
    params.not_after = rcgen::date_time_ymd(1970, 1, 1) + std::time::Duration::from_secs(not_after);
    params.is_ca = IsCa::ExplicitNoCa;
    params
}

fn sign_leaf_certificate(
    pcr: &PodCertificateRequest,
    params: &CertificateParams,
    issuer: &Issuer<'_, KeyPair>,
) -> Result<rcgen::Certificate, ApiserverError> {
    if let Some(csr_bytes) = &pcr.spec.stub_pkcs10_request {
        let csr_der =
            if x509_parser::certification_request::X509CertificationRequest::from_der(csr_bytes)
                .is_ok()
            {
                csr_bytes.clone()
            } else {
                let entries = parse_pem_entries(csr_bytes)?;
                let (_, der) = entries
                    .first()
                    .ok_or_else(|| ApiserverError::InvalidInput {
                        field: "spec.stubPKCS10Request".into(),
                        reason: "empty CSR PEM".into(),
                    })?;
                der.clone()
            };

        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&csr_der)
                .map_err(|e| ApiserverError::InvalidInput {
                    field: "spec.stubPKCS10Request".into(),
                    reason: format!("invalid CSR: {e}"),
                })?;

        let raw_spki = csr.certification_request_info.subject_pki.raw;
        let spki = rcgen::SubjectPublicKeyInfo::from_der(raw_spki).map_err(|e| {
            ApiserverError::InvalidInput {
                field: "spec.stubPKCS10Request".into(),
                reason: format!("invalid public key in CSR: {e}"),
            }
        })?;
        params
            .signed_by(&spki, issuer)
            .map_err(|e| ApiserverError::Internal {
                reason: format!("failed to sign leaf certificate: {e}"),
            })
    } else if let Some(pkix_bytes) = &pcr.spec.pkix_public_key {
        let spki = rcgen::SubjectPublicKeyInfo::from_der(pkix_bytes).map_err(|e| {
            ApiserverError::InvalidInput {
                field: "spec.pkixPublicKey".into(),
                reason: format!("invalid pkixPublicKey: {e}"),
            }
        })?;
        params
            .signed_by(&spki, issuer)
            .map_err(|e| ApiserverError::Internal {
                reason: format!("failed to sign leaf certificate: {e}"),
            })
    } else {
        let key_pair =
            KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).map_err(|e| {
                ApiserverError::Internal {
                    reason: format!("failed to generate leaf key pair: {e}"),
                }
            })?;
        params
            .signed_by(&key_pair, issuer)
            .map_err(|e| ApiserverError::Internal {
                reason: format!("failed to sign leaf certificate: {e}"),
            })
    }
}

/// Issues an X.509 leaf certificate for a `PodCertificateRequest`, honoring:
/// - Default expiration (24h) if `maxExpirationSeconds` is omitted.
/// - Custom expiration when specified.
/// - `UserAnnotations` for SPIFFE URI path override.
/// - SANs (SPIFFE URI + DNS) and key usages for mTLS communication.
pub fn issue_pod_certificate(
    pcr: &mut PodCertificateRequest,
    signer_ca_cert_pem: &str,
    signer_ca_key_pem: &str,
    trust_domain: Option<&str>,
) -> Result<(), ApiserverError> {
    validate_pod_certificate_request(pcr)?;

    let duration_secs =
        u64::try_from(pcr.spec.max_expiration_seconds.unwrap_or(86400)).unwrap_or(86400);
    let now = crate::time::now_unix();
    let not_before = now;
    let not_after = now + duration_secs;
    let refresh_at = now + (duration_secs * 2 / 3);

    let td = trust_domain.unwrap_or("cluster.local");
    let ns = pcr.metadata.namespace.as_deref().unwrap_or("default");

    let params = build_leaf_cert_params(pcr, td, ns, not_before, not_after);

    let ca_key_pair =
        KeyPair::from_pem(signer_ca_key_pem).map_err(|e| ApiserverError::InvalidCredentials {
            reason: format!("failed to parse signer CA key: {e}"),
        })?;
    let issuer = Issuer::from_ca_cert_pem(signer_ca_cert_pem, ca_key_pair).map_err(|e| {
        ApiserverError::InvalidCredentials {
            reason: format!("failed to parse signer CA certificate: {e}"),
        }
    })?;

    let cert = sign_leaf_certificate(pcr, &params, &issuer)?;
    let leaf_pem = cert.pem();
    let chain = format!("{}\n{}", leaf_pem.trim(), signer_ca_cert_pem.trim());

    pcr.status = Some(PodCertificateRequestStatus {
        conditions: vec![PodCertificateRequestCondition {
            condition_type: "Issued".to_string(),
            status: "True".to_string(),
            reason: Some("Issued".to_string()),
            message: Some("Pod certificate issued successfully".to_string()),
            last_transition_time: Some(crate::time::now_rfc3339()),
        }],
        certificate_chain: Some(chain),
        not_before: Some(crate::time::rfc3339_seconds(not_before)),
        begin_refresh_at: Some(crate::time::rfc3339_seconds(refresh_at)),
        not_after: Some(crate::time::rfc3339_seconds(not_after)),
    });

    Ok(())
}

// =============================================================================
// JSON Serde Helpers for HTTP Dispatch and Storage
// =============================================================================

/// Validates a raw JSON `ClusterTrustBundle` value.
pub fn validate_cluster_trust_bundle_json(val: &Value) -> Result<(), ApiserverError> {
    let ctb: ClusterTrustBundle =
        serde_json::from_value(val.clone()).map_err(|e| ApiserverError::InvalidInput {
            field: "clusterTrustBundle".into(),
            reason: format!("invalid ClusterTrustBundle JSON: {e}"),
        })?;
    validate_cluster_trust_bundle(&ctb)
}

/// Validates a raw JSON `PodCertificateRequest` value.
pub fn validate_pod_certificate_request_json(val: &Value) -> Result<(), ApiserverError> {
    let pcr: PodCertificateRequest =
        serde_json::from_value(val.clone()).map_err(|e| ApiserverError::InvalidInput {
            field: "podCertificateRequest".into(),
            reason: format!("invalid PodCertificateRequest JSON: {e}"),
        })?;
    validate_pod_certificate_request(&pcr)
}

/// Resolves a JSON `ClusterTrustBundleProjection` against a list of JSON `ClusterTrustBundle`s.
pub fn resolve_cluster_trust_bundle_projection_json(
    proj_val: &Value,
    bundles_val: &[Value],
) -> Result<Option<String>, ApiserverError> {
    let proj: ClusterTrustBundleProjection =
        serde_json::from_value(proj_val.clone()).map_err(|e| ApiserverError::InvalidInput {
            field: "clusterTrustBundle".into(),
            reason: format!("invalid ClusterTrustBundleProjection JSON: {e}"),
        })?;
    let mut bundles = Vec::with_capacity(bundles_val.len());
    for b in bundles_val {
        let ctb: ClusterTrustBundle =
            serde_json::from_value(b.clone()).map_err(|e| ApiserverError::InvalidInput {
                field: "clusterTrustBundle".into(),
                reason: format!("invalid ClusterTrustBundle item: {e}"),
            })?;
        bundles.push(ctb);
    }
    resolve_cluster_trust_bundles(&proj, &bundles)
}

// =============================================================================
// Unit & Scale Regression Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use diorama_pki::verify_certificate_chain;
    use tempfile::tempdir;

    fn generate_ca(common_name: &str) -> (String, String) {
        let mut params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name.to_string());
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    fn generate_non_ca_cert(name: &str) -> String {
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.is_ca = IsCa::ExplicitNoCa;
        let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        cert.pem()
    }

    #[test]
    fn test_pki_prerequisites_validation() {
        let temp = tempdir().unwrap();
        let pki_dir = temp.path().join("pki");
        fs::create_dir_all(&pki_dir).unwrap();

        let client_ca = pki_dir.join("ca.crt");
        let tls_cert = pki_dir.join("apiserver.crt");
        let tls_key = pki_dir.join("apiserver.key");
        let sa_key = pki_dir.join("sa.key");
        let req_ca = pki_dir.join("request-header-ca.crt");

        let (ca_pem, ca_key) = generate_ca("root-ca");
        fs::write(&client_ca, &ca_pem).unwrap();
        fs::write(&tls_cert, &ca_pem).unwrap();
        fs::write(&tls_key, &ca_key).unwrap();
        fs::write(&sa_key, &ca_key).unwrap();
        fs::write(&req_ca, &ca_pem).unwrap();

        let mut config = ApiserverConfig::default_for_pki(&pki_dir, "127.0.0.1".parse().unwrap());
        config.client_ca_file = client_ca.clone();
        config.tls_cert_file = tls_cert;
        config.tls_private_key_file = tls_key;
        config.service_account_signing_key_file = sa_key;
        config.request_header_ca_file = req_ca;

        assert!(validate_pki_prerequisites(&config).is_ok());

        // Test missing file
        config.client_ca_file = pki_dir.join("missing.crt");
        assert!(validate_pki_prerequisites(&config).is_err());
    }

    #[test]
    fn test_ctb_validation_valid_with_signer() {
        let (ca_pem, _) = generate_ca("signer-ca");
        let ctb = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "example.com:signer-a:root-anchor".into(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: Some("example.com/signer-a".into()),
                trust_bundle: ca_pem,
            },
        };
        assert!(validate_cluster_trust_bundle(&ctb).is_ok());
    }

    #[test]
    fn test_ctb_validation_invalid_signer_name() {
        let (ca_pem, _) = generate_ca("signer-ca");
        let ctb = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "invalid:bundle".into(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: Some("invalid_signer_without_slash".into()),
                trust_bundle: ca_pem,
            },
        };
        assert!(validate_cluster_trust_bundle(&ctb).is_err());
    }

    #[test]
    fn test_ctb_validation_name_prefix_mismatch() {
        let (ca_pem, _) = generate_ca("signer-ca");
        let ctb = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "wrong.prefix:bundle-1".into(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: Some("example.com/signer-a".into()),
                trust_bundle: ca_pem,
            },
        };
        let err = validate_cluster_trust_bundle(&ctb).unwrap_err();
        assert!(matches!(err, ApiserverError::InvalidInput { .. }));
    }

    #[test]
    fn test_ctb_validation_unlinked_bundle_colon_rejected() {
        let (ca_pem, _) = generate_ca("signer-ca");
        let ctb = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "unlinked:with-colon".into(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: None,
                trust_bundle: ca_pem,
            },
        };
        let err = validate_cluster_trust_bundle(&ctb).unwrap_err();
        assert!(matches!(err, ApiserverError::InvalidInput { .. }));
    }

    #[test]
    fn test_ctb_validation_unlinked_bundle_valid() {
        let (ca_pem, _) = generate_ca("signer-ca");
        let ctb = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "global-root-ca".into(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: None,
                trust_bundle: ca_pem,
            },
        };
        assert!(validate_cluster_trust_bundle(&ctb).is_ok());
    }

    #[test]
    fn test_ctb_validation_non_ca_rejected() {
        let non_ca_pem = generate_non_ca_cert("not-a-ca");
        let ctb = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "invalid-non-ca".into(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: None,
                trust_bundle: non_ca_pem,
            },
        };
        let err = validate_cluster_trust_bundle(&ctb).unwrap_err();
        assert!(matches!(err, ApiserverError::InvalidInput { .. }));
    }

    #[test]
    fn test_ctb_validation_duplicate_certificates_rejected() {
        let (ca_pem, _) = generate_ca("signer-ca");
        let duplicate_bundle = format!("{ca_pem}\n{ca_pem}");
        let ctb = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "duplicate-certs".into(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: None,
                trust_bundle: duplicate_bundle,
            },
        };
        let err = validate_cluster_trust_bundle(&ctb).unwrap_err();
        assert!(matches!(err, ApiserverError::InvalidInput { .. }));
    }

    #[test]
    fn test_ctb_validation_invalid_pem_rejected() {
        let ctb = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "bad-pem".into(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: None,
                trust_bundle: "not a pem certificate block".into(),
            },
        };
        assert!(validate_cluster_trust_bundle(&ctb).is_err());
    }

    #[test]
    fn test_ctb_immutability_on_update() {
        let (ca_pem, _) = generate_ca("signer-ca");
        let old_ctb = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "example.com:signer-a:root".into(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: Some("example.com/signer-a".into()),
                trust_bundle: ca_pem.clone(),
            },
        };
        let mut new_ctb = old_ctb.clone();
        new_ctb.spec.signer_name = Some("example.com/signer-b".into());
        let err = validate_cluster_trust_bundle_update(&new_ctb, &old_ctb).unwrap_err();
        assert!(matches!(err, ApiserverError::InvalidInput { .. }));
    }

    #[test]
    fn test_ctb_projection_resolution_by_name() {
        let (ca_pem, _) = generate_ca("signer-ca");
        let ctb = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "my-ctb".into(),
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: None,
                trust_bundle: ca_pem.clone(),
            },
        };
        let bundles = vec![ctb];

        let proj = ClusterTrustBundleProjection {
            name: Some("my-ctb".into()),
            path: "certs.pem".into(),
            ..Default::default()
        };
        let res = resolve_cluster_trust_bundles(&proj, &bundles).unwrap();
        assert_eq!(res, Some(ca_pem));

        // Missing bundle with optional: false
        let proj_missing = ClusterTrustBundleProjection {
            name: Some("non-existent".into()),
            path: "certs.pem".into(),
            optional: Some(false),
            ..Default::default()
        };
        assert!(resolve_cluster_trust_bundles(&proj_missing, &bundles).is_err());

        // Missing bundle with optional: true
        let proj_opt = ClusterTrustBundleProjection {
            name: Some("non-existent".into()),
            path: "certs.pem".into(),
            optional: Some(true),
            ..Default::default()
        };
        assert_eq!(
            resolve_cluster_trust_bundles(&proj_opt, &bundles).unwrap(),
            None
        );
    }

    #[test]
    fn test_ctb_projection_resolution_by_signer_and_selector() {
        let (ca1, _) = generate_ca("ca-1");
        let (ca2, _) = generate_ca("ca-2");
        let (ca3, _) = generate_ca("ca-3");

        let mut labels1 = HashMap::new();
        labels1.insert("env".into(), "prod".into());
        labels1.insert("tier".into(), "backend".into());

        let mut labels2 = HashMap::new();
        labels2.insert("env".into(), "prod".into());
        labels2.insert("tier".into(), "frontend".into());

        let mut labels3 = HashMap::new();
        labels3.insert("env".into(), "staging".into());

        let ctb1 = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "example.com:signer-a:ctb1".into(),
                labels: labels1,
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: Some("example.com/signer-a".into()),
                trust_bundle: ca1,
            },
        };
        let ctb2 = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "example.com:signer-a:ctb2".into(),
                labels: labels2,
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: Some("example.com/signer-a".into()),
                trust_bundle: ca2,
            },
        };
        let ctb3 = ClusterTrustBundle {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "ClusterTrustBundle".into(),
            metadata: ObjectMeta {
                name: "example.com:signer-a:ctb3".into(),
                labels: labels3,
                ..Default::default()
            },
            spec: ClusterTrustBundleSpec {
                signer_name: Some("example.com/signer-a".into()),
                trust_bundle: ca3,
            },
        };

        let bundles = vec![ctb1, ctb2, ctb3];

        // 1. Empty selector combines ALL signer CTBs
        let proj_all = ClusterTrustBundleProjection {
            signer_name: Some("example.com/signer-a".into()),
            label_selector: None,
            path: "all-roots.pem".into(),
            ..Default::default()
        };
        let all_res = resolve_cluster_trust_bundles(&proj_all, &bundles)
            .unwrap()
            .unwrap();
        let entries = parse_pem_entries(all_res.as_bytes()).unwrap();
        assert_eq!(entries.len(), 3);

        // 2. Filter with matchLabels: env=prod
        let mut match_labels = HashMap::new();
        match_labels.insert("env".into(), "prod".into());
        let proj_prod = ClusterTrustBundleProjection {
            signer_name: Some("example.com/signer-a".into()),
            label_selector: Some(LabelSelector {
                match_labels,
                match_expressions: Vec::new(),
            }),
            path: "prod-roots.pem".into(),
            ..Default::default()
        };
        let prod_res = resolve_cluster_trust_bundles(&proj_prod, &bundles)
            .unwrap()
            .unwrap();
        let prod_entries = parse_pem_entries(prod_res.as_bytes()).unwrap();
        assert_eq!(prod_entries.len(), 2);

        // 3. Filter matching nothing + optional=true returns Ok(None)
        let mut match_none = HashMap::new();
        match_none.insert("env".into(), "non-existent".into());
        let proj_opt = ClusterTrustBundleProjection {
            signer_name: Some("example.com/signer-a".into()),
            label_selector: Some(LabelSelector {
                match_labels: match_none,
                match_expressions: Vec::new(),
            }),
            path: "opt.pem".into(),
            optional: Some(true),
            ..Default::default()
        };
        assert_eq!(
            resolve_cluster_trust_bundles(&proj_opt, &bundles).unwrap(),
            None
        );
    }

    #[test]
    fn test_ctb_scale_handling_over_100_bundles() {
        // Issue #221 & #220..#229: Mount big number (>100) of CTBs
        const BUNDLE_COUNT: usize = 120;
        let mut bundles = Vec::with_capacity(BUNDLE_COUNT);

        let (shared_ca_pem, _) = generate_ca("scale-root-shared");

        for i in 0..BUNDLE_COUNT {
            let mut labels = HashMap::new();
            labels.insert("bundle-index".into(), i.to_string());
            labels.insert(
                "group".into(),
                if i < 60 {
                    "primary".into()
                } else {
                    "secondary".into()
                },
            );

            // Generate unique CA for each to test high volume of distinct certificates
            let (unique_ca, _) = generate_ca(&format!("scale-ca-{i}"));
            // Combine unique CA with shared root to test deduplication across 120 bundles
            let trust_bundle = format!("{}\n{}", unique_ca.trim(), shared_ca_pem.trim());

            bundles.push(ClusterTrustBundle {
                api_version: "certificates.k8s.io/v1".into(),
                kind: "ClusterTrustBundle".into(),
                metadata: ObjectMeta {
                    name: format!("scale.example.com:k8s-signer:bundle-{i:03}"),
                    labels,
                    ..Default::default()
                },
                spec: ClusterTrustBundleSpec {
                    signer_name: Some("scale.example.com/k8s-signer".into()),
                    trust_bundle,
                },
            });
        }

        // Test building ClusterTrustBundleIndex
        let index = ClusterTrustBundleIndex::new(bundles.clone());
        assert_eq!(index.len(), BUNDLE_COUNT);

        // Benchmark / verify sub-millisecond bundle resolution across >100 CTBs
        let start = std::time::Instant::now();

        // Resolve projection with empty selector (combines all 120 CTBs + deduplicates shared root)
        let proj = ClusterTrustBundleProjection {
            signer_name: Some("scale.example.com/k8s-signer".into()),
            label_selector: None,
            path: "scale-bundle.pem".into(),
            optional: Some(false),
            ..Default::default()
        };
        let resolved = index.resolve(&proj).unwrap().unwrap();
        let elapsed = start.elapsed();

        // 120 unique CAs + 1 deduplicated shared CA = 121 certificates total
        let entries = parse_pem_entries(resolved.as_bytes()).unwrap();
        assert_eq!(entries.len(), BUNDLE_COUNT + 1);
        assert!(
            elapsed.as_millis() < 50,
            "Resolution across >100 CTBs took too long: {elapsed:?}"
        );

        // Resolve subset via labelSelector
        let mut match_labels = HashMap::new();
        match_labels.insert("group".into(), "primary".into());
        let subset_proj = ClusterTrustBundleProjection {
            signer_name: Some("scale.example.com/k8s-signer".into()),
            label_selector: Some(LabelSelector {
                match_labels,
                match_expressions: Vec::new(),
            }),
            path: "primary-group.pem".into(),
            ..Default::default()
        };
        let subset_res = index.resolve(&subset_proj).unwrap().unwrap();
        let subset_entries = parse_pem_entries(subset_res.as_bytes()).unwrap();
        assert_eq!(subset_entries.len(), 61); // 60 unique + 1 shared
    }

    #[test]
    fn test_pcr_validation_and_expiration_bounds() {
        let (ca_pem, ca_key) = generate_ca("pcr-signer-ca");
        let client_key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let csr_params = CertificateParams::new(vec!["test-pod".into()]).unwrap();
        let csr = csr_params.serialize_request(&client_key).unwrap();
        let csr_der = csr.der().to_vec();

        let mut pcr = PodCertificateRequest {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "PodCertificateRequest".into(),
            metadata: ObjectMeta {
                name: "test-pcr".into(),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: PodCertificateRequestSpec {
                signer_name: "example.com/pod-signer".into(),
                pod_name: "nginx-pod".into(),
                pod_uid: "abc-123".into(),
                service_account_name: "default".into(),
                service_account_uid: "sa-456".into(),
                node_name: "node-1".into(),
                node_uid: "node-789".into(),
                max_expiration_seconds: Some(86400),
                unverified_user_annotations: HashMap::new(),
                stub_pkcs10_request: Some(csr_der.clone()),
                pkix_public_key: None,
                proof_of_possession: None,
            },
            status: None,
        };

        // Valid PCR
        assert!(validate_pod_certificate_request(&pcr).is_ok());

        // Issue #208: maxExpirationSeconds < 3600 rejected
        pcr.spec.max_expiration_seconds = Some(1800);
        let err_min = validate_pod_certificate_request(&pcr).unwrap_err();
        assert!(matches!(err_min, ApiserverError::InvalidInput { .. }));

        // Issue #207: maxExpirationSeconds > 91 days rejected
        pcr.spec.max_expiration_seconds = Some(92 * 86400);
        let err_max = validate_pod_certificate_request(&pcr).unwrap_err();
        assert!(matches!(err_max, ApiserverError::InvalidInput { .. }));

        // Valid bounds: 3600s
        pcr.spec.max_expiration_seconds = Some(3600);
        assert!(validate_pod_certificate_request(&pcr).is_ok());

        // Spec immutability
        let mut updated = pcr.clone();
        updated.spec.pod_name = "mutated-pod".into();
        assert!(validate_pod_certificate_request_update(&updated, &pcr).is_err());

        // Ensure issuance works
        issue_pod_certificate(&mut pcr, &ca_pem, &ca_key, None).unwrap();
        let status = pcr.status.unwrap();
        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].condition_type, "Issued");
        assert!(status.certificate_chain.is_some());
    }

    #[test]
    fn test_pcr_issuance_default_and_custom_expiration() {
        // Issue #205: Default 24h expiration
        let (ca_pem, ca_key) = generate_ca("expiration-ca");
        let client_key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let csr_params = CertificateParams::new(vec!["pod".into()]).unwrap();
        let csr = csr_params.serialize_request(&client_key).unwrap();

        let mut pcr_default = PodCertificateRequest {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "PodCertificateRequest".into(),
            metadata: ObjectMeta {
                name: "pcr-default".into(),
                namespace: Some("test-ns".into()),
                ..Default::default()
            },
            spec: PodCertificateRequestSpec {
                signer_name: "example.com/signer".into(),
                pod_name: "default-pod".into(),
                pod_uid: "uid-default".into(),
                service_account_name: "app-sa".into(),
                service_account_uid: "sa-uid".into(),
                node_name: "node-1".into(),
                node_uid: "node-uid".into(),
                max_expiration_seconds: None, // Omitted! Must default to 24h (86400s)
                unverified_user_annotations: HashMap::new(),
                stub_pkcs10_request: Some(csr.der().to_vec()),
                pkix_public_key: None,
                proof_of_possession: None,
            },
            status: None,
        };

        issue_pod_certificate(&mut pcr_default, &ca_pem, &ca_key, None).unwrap();
        let status = pcr_default.status.clone().unwrap();
        let nb = crate::time::parse_rfc3339_seconds(&status.not_before.unwrap()).unwrap();
        let na = crate::time::parse_rfc3339_seconds(&status.not_after.unwrap()).unwrap();
        assert_eq!(na - nb, 86400, "Must have default 24h lifetime");

        // Issue #206: Custom 1h expiration
        let mut pcr_custom = pcr_default.clone();
        pcr_custom.metadata.name = "pcr-custom".into();
        pcr_custom.spec.max_expiration_seconds = Some(3600); // 1h
        pcr_custom.status = None;

        issue_pod_certificate(&mut pcr_custom, &ca_pem, &ca_key, None).unwrap();
        let custom_status = pcr_custom.status.unwrap();
        let custom_start_secs =
            crate::time::parse_rfc3339_seconds(&custom_status.not_before.unwrap()).unwrap();
        let custom_end_secs =
            crate::time::parse_rfc3339_seconds(&custom_status.not_after.unwrap()).unwrap();
        assert_eq!(
            custom_end_secs - custom_start_secs,
            3600,
            "Must have custom 1h lifetime"
        );
    }

    fn cert_has_spiffe_uri(cert_pem: &str, target_uri: &str) -> bool {
        let entries = parse_pem_entries(cert_pem.as_bytes()).unwrap();
        let (_, x509) = x509_parser::parse_x509_certificate(&entries[0].1).unwrap();
        for ext in x509.iter_extensions() {
            let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                ext.parsed_extension()
            else {
                continue;
            };
            let matched = san.general_names.iter().any(|gn| {
                matches!(gn, x509_parser::extensions::GeneralName::URI(uri) if *uri == target_uri)
            });
            if matched {
                return true;
            }
        }
        false
    }

    fn create_test_pcr(
        pod_name: &str,
        sa_name: &str,
        node_name: &str,
        annotations: HashMap<String, String>,
    ) -> PodCertificateRequest {
        let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let csr_params = CertificateParams::new(vec![pod_name.to_string()]).unwrap();
        let csr = csr_params.serialize_request(&key).unwrap();

        PodCertificateRequest {
            api_version: "certificates.k8s.io/v1".into(),
            kind: "PodCertificateRequest".into(),
            metadata: ObjectMeta {
                name: format!("{pod_name}-cert"),
                namespace: Some("workloads".into()),
                ..Default::default()
            },
            spec: PodCertificateRequestSpec {
                signer_name: "example.com/signer".into(),
                pod_name: pod_name.to_string(),
                pod_uid: format!("uid-{pod_name}"),
                service_account_name: sa_name.to_string(),
                service_account_uid: format!("sa-{sa_name}"),
                node_name: node_name.to_string(),
                node_uid: format!("uid-{node_name}"),
                max_expiration_seconds: Some(7200),
                unverified_user_annotations: annotations,
                stub_pkcs10_request: Some(csr.der().to_vec()),
                pkix_public_key: None,
                proof_of_possession: None,
            },
            status: None,
        }
    }

    #[test]
    fn test_pcr_user_annotations_and_mtls_between_two_pods() {
        // Issue #209: mTLS between client and server pods
        // Issue #210: UserAnnotations for SPIFFE URI path
        let (ca_pem, ca_key) = generate_ca("mtls-trust-anchor");

        let mut server_annotations = HashMap::new();
        server_annotations.insert(
            "experimental.certificates.k8s.io/spiffe-id".into(),
            "spiffe://cluster.local/ns/workloads/sa/server-sa/custom-svc".into(),
        );

        let mut server_pcr =
            create_test_pcr("server-pod", "server-sa", "node-1", server_annotations);
        issue_pod_certificate(&mut server_pcr, &ca_pem, &ca_key, None).unwrap();
        let server_chain = server_pcr
            .status
            .as_ref()
            .unwrap()
            .certificate_chain
            .as_ref()
            .unwrap();

        let mut client_pcr = create_test_pcr("client-pod", "client-sa", "node-2", HashMap::new());
        issue_pod_certificate(&mut client_pcr, &ca_pem, &ca_key, None).unwrap();
        let client_chain = client_pcr
            .status
            .as_ref()
            .unwrap()
            .certificate_chain
            .as_ref()
            .unwrap();

        // Extract leaf certs
        let server_entries = parse_pem_entries(server_chain.as_bytes()).unwrap();
        let server_leaf_pem = encode_pem("CERTIFICATE", &server_entries[0].1);
        let client_entries = parse_pem_entries(client_chain.as_bytes()).unwrap();
        let client_leaf_pem = encode_pem("CERTIFICATE", &client_entries[0].1);

        // Verify both authenticate mutually against the CA trust anchor
        assert!(verify_certificate_chain(&server_leaf_pem, &ca_pem).is_ok());
        assert!(verify_certificate_chain(&client_leaf_pem, &ca_pem).is_ok());

        // Verify server leaf has overridden SPIFFE URI from UserAnnotations
        assert!(
            cert_has_spiffe_uri(
                &server_leaf_pem,
                "spiffe://cluster.local/ns/workloads/sa/server-sa/custom-svc"
            ),
            "UserAnnotations SPIFFE URI must be present in SAN"
        );
    }
}
