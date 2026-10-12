//! PKI trust root preservation and kubeconfig format verification.
//!
//! Enforces:
//! 1. Root CA (`ca.crt`, `ca.key`) and `ServiceAccount` (`service-account.key`) preservation.
//! 2. Accommodation and verification of **both YAML and JSON** kubeconfig formats.
//! 3. Cryptographic consistency: client certificates in kubeconfig authenticate against CA root.
//! 4. Non-invalidation of existing client trust across the Go-to-Rust transition.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use x509_parser::pem::parse_x509_pem;

/// Format of a kubeconfig file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KubeconfigFormat {
    Yaml,
    Json,
}

impl fmt::Display for KubeconfigFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yaml => write!(f, "YAML"),
            Self::Json => write!(f, "JSON"),
        }
    }
}

/// Extracted fields from a parsed kubeconfig document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedKubeconfig {
    pub format: KubeconfigFormat,
    pub server: String,
    pub cluster_name: String,
    pub user_name: String,
    pub current_context: String,
    pub ca_cert_bytes: Vec<u8>,
    pub client_cert_bytes: Vec<u8>,
    pub client_key_bytes: Vec<u8>,
}

/// Parses YAML or JSON kubeconfig and resolves the current context's exact credentials.
pub fn parse_kubeconfig(bytes: &[u8]) -> Result<ParsedKubeconfig, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("invalid UTF-8: {e}"))?;
    let raw = dioramactl::kubeconfig::parse_kubeconfig_content(text).map_err(|e| e.to_string())?;
    let current = required_string(&raw, "current-context")?;
    let context = named_entry(&raw, "contexts", current)?;
    let context = &context["context"];
    let cluster_name = required_string(context, "cluster")?;
    let user_name = required_string(context, "user")?;
    let cluster = &named_entry(&raw, "clusters", cluster_name)?["cluster"];
    let user = &named_entry(&raw, "users", user_name)?["user"];
    Ok(ParsedKubeconfig {
        format: if text.trim_start().starts_with('{') {
            KubeconfigFormat::Json
        } else {
            KubeconfigFormat::Yaml
        },
        server: required_string(cluster, "server")?.into(),
        cluster_name: cluster_name.into(),
        user_name: user_name.into(),
        current_context: current.into(),
        ca_cert_bytes: decode_field(cluster, "certificate-authority-data")?,
        client_cert_bytes: decode_field(user, "client-certificate-data")?,
        client_key_bytes: decode_field(user, "client-key-data")?,
    })
}

fn required_string<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, String> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing or invalid {key}"))
}

fn named_entry<'a>(
    raw: &'a serde_json::Value,
    list: &str,
    name: &str,
) -> Result<&'a serde_json::Value, String> {
    let entries = raw[list]
        .as_array()
        .ok_or_else(|| format!("missing {list}"))?;
    let mut names = std::collections::BTreeSet::new();
    let mut selected = None;
    for entry in entries {
        let entry_name = required_string(entry, "name")?;
        if !names.insert(entry_name) {
            return Err(format!("duplicate {list} name: {entry_name}"));
        }
        if entry_name == name {
            selected = Some(entry);
        }
    }
    selected.ok_or_else(|| format!("missing {list} reference: {name}"))
}

fn decode_field(value: &serde_json::Value, key: &str) -> Result<Vec<u8>, String> {
    BASE64_STANDARD
        .decode(required_string(value, key)?)
        .map_err(|e| format!("invalid base64 in {key}: {e}"))
}

/// Result of PKI transition assertion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Independent preservation checks in a serialized evidence record, not mutually exclusive states.
#[allow(clippy::struct_excessive_bools)]
pub struct PkiTransitionAssertion {
    pub ca_sha256_before: String,
    pub ca_sha256_after: String,
    pub ca_preserved: bool,
    pub ca_key_preserved: bool,
    pub sa_key_sha256_before: String,
    pub sa_key_sha256_after: String,
    pub sa_key_preserved: bool,
    pub client_cert_verified: bool,
    pub kubeconfig_format: KubeconfigFormat,
}

/// Computes SHA-256 hex digest of a byte slice.
fn digest_bytes(b: &[u8]) -> String {
    crate::sha256(b)
}

/// Asserts PKI state before and after transition.
pub fn assert_pki_transition(
    pki_dir_before: &Path,
    pki_dir_after: &Path,
    kubeconfig_file: &Path,
) -> io::Result<PkiTransitionAssertion> {
    // 1. Locate CA cert
    let ca_path_before = find_file(pki_dir_before, "ca.crt")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ca.crt not found before"))?;
    let ca_path_after = find_file(pki_dir_after, "ca.crt")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ca.crt not found after"))?;

    let ca_bytes_before = fs::read(&ca_path_before)?;
    let ca_bytes_after = fs::read(&ca_path_after)?;

    let ca_sha_before = digest_bytes(&ca_bytes_before);
    let ca_sha_after = digest_bytes(&ca_bytes_after);
    let ca_preserved = ca_sha_before == ca_sha_after;

    // 2. Service account key
    let sa_key_before = read_signing_key(pki_dir_before, "service-account.key")?;
    let sa_key_after = read_signing_key(pki_dir_after, "service-account.key")?;
    let ca_key_before = read_signing_key(pki_dir_before, "ca.key")?;
    let ca_key_after = read_signing_key(pki_dir_after, "ca.key")?;
    let ca_key_preserved = ca_key_before == ca_key_after
        && signing_key_matches_cert(&ca_key_before, &ca_bytes_before)?
        && signing_key_matches_cert(&ca_key_after, &ca_bytes_after)?;

    let sa_sha_before = digest_bytes(&sa_key_before);
    let sa_sha_after = digest_bytes(&sa_key_after);
    let sa_key_preserved = sa_sha_before == sa_sha_after;

    // 3. Verify kubeconfig
    let kcfg_bytes = fs::read(kubeconfig_file)?;
    let parsed_kcfg =
        parse_kubeconfig(&kcfg_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Verify client cert is signed by CA cert
    let client_verified = parsed_kcfg.ca_cert_bytes == ca_bytes_after
        && verify_cert_chain(&ca_bytes_after, &parsed_kcfg.client_cert_bytes).unwrap_or(false);

    Ok(PkiTransitionAssertion {
        ca_sha256_before: ca_sha_before,
        ca_sha256_after: ca_sha_after,
        ca_preserved,
        ca_key_preserved,
        sa_key_sha256_before: sa_sha_before,
        sa_key_sha256_after: sa_sha_after,
        sa_key_preserved,
        client_cert_verified: client_verified,
        kubeconfig_format: parsed_kcfg.format,
    })
}

fn read_signing_key(root: &Path, name: &str) -> io::Result<Vec<u8>> {
    let path = find_file(root, name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("missing {name}")))?;
    let bytes = fs::read(path)?;
    let pem = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid signing key"))?;
    rcgen::KeyPair::from_pem(pem)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid signing key"))?;
    Ok(bytes)
}

fn signing_key_matches_cert(key: &[u8], cert: &[u8]) -> io::Result<bool> {
    let text = std::str::from_utf8(key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid signing key"))?;
    let key = rcgen::KeyPair::from_pem(text)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid signing key"))?;
    let (_, pem) = parse_x509_pem(cert)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid CA certificate"))?;
    let cert = pem
        .parse_x509()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid CA certificate"))?;
    Ok(cert.public_key().subject_public_key.data.as_ref() == key.public_key_raw())
}

/// Finds a file by name recursively within a directory.
fn find_file(root: &Path, filename: &str) -> Option<std::path::PathBuf> {
    if !root.is_dir() {
        return None;
    }
    for entry in fs::read_dir(root).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        if path.is_file() && path.file_name().and_then(|n| n.to_str()) == Some(filename) {
            return Some(path);
        }
        if path.is_dir()
            && let Some(found) = find_file(&path, filename)
        {
            return Some(found);
        }
    }
    None
}

/// Validates a directly signed client certificate against the preserved CA.
pub fn verify_cert_chain(ca_pem: &[u8], client_pem: &[u8]) -> Result<bool, String> {
    let (_, ca_pem_obj) =
        parse_x509_pem(ca_pem).map_err(|e| format!("failed to parse CA PEM: {e}"))?;
    let ca_cert = ca_pem_obj
        .parse_x509()
        .map_err(|e| format!("failed to parse CA X.509 cert: {e}"))?;

    let (_, client_pem_obj) =
        parse_x509_pem(client_pem).map_err(|e| format!("failed to parse client PEM: {e}"))?;
    let client_cert = client_pem_obj
        .parse_x509()
        .map_err(|e| format!("failed to parse client X.509 cert: {e}"))?;

    let ca_text = std::str::from_utf8(ca_pem).map_err(|_| "invalid CA PEM".to_string())?;
    let client_text =
        std::str::from_utf8(client_pem).map_err(|_| "invalid client PEM".to_string())?;
    if diorama_pki::verify_certificate_chain(client_text, ca_text).is_err()
        || client_cert.issuer() != ca_cert.subject()
        || !ca_cert.is_ca()
        || client_cert.is_ca()
    {
        return Ok(false);
    }
    if ca_cert
        .key_usage()
        .map_err(|e| e.to_string())?
        .is_some_and(|usage| !usage.value.key_cert_sign())
        || client_cert
            .key_usage()
            .map_err(|e| e.to_string())?
            .is_some_and(|usage| !usage.value.digital_signature())
        || client_cert
            .extended_key_usage()
            .map_err(|e| e.to_string())?
            .is_some_and(|usage| !usage.value.client_auth && !usage.value.any)
    {
        return Ok(false);
    }
    Ok(true)
}
