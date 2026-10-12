//! Dual-format kubeconfig loader and validator accommodating both YAML and JSON representations.

use diorama_config::decode_yaml_value;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum KubeconfigError {
    Io(String),
    Parse(String),
    MissingField(String),
    InvalidFormat(String),
}

impl fmt::Display for KubeconfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "kubeconfig IO error: {msg}"),
            Self::Parse(msg) => write!(f, "kubeconfig parse error: {msg}"),
            Self::MissingField(msg) => write!(f, "kubeconfig missing required field: {msg}"),
            Self::InvalidFormat(msg) => write!(f, "kubeconfig invalid format: {msg}"),
        }
    }
}

impl std::error::Error for KubeconfigError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterData {
    pub server: String,
    #[serde(
        rename = "certificate-authority-data",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_authority_data: Option<String>,
    #[serde(
        rename = "certificate-authority",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub certificate_authority: Option<String>,
    #[serde(
        rename = "insecure-skip-tls-verify",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub insecure_skip_tls_verify: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedCluster {
    pub name: String,
    pub cluster: ClusterData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextData {
    pub cluster: String,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedContext {
    pub name: String,
    pub context: ContextData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserData {
    #[serde(
        rename = "client-certificate-data",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub client_certificate_data: Option<String>,
    #[serde(
        rename = "client-certificate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub client_certificate: Option<String>,
    #[serde(
        rename = "client-key-data",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub client_key_data: Option<String>,
    #[serde(
        rename = "client-key",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub client_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedUser {
    pub name: String,
    pub user: UserData,
}

/// Represents a parsed Kubernetes kubeconfig file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kubeconfig {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    #[serde(rename = "current-context")]
    pub current_context: String,
    pub clusters: Vec<NamedCluster>,
    pub contexts: Vec<NamedContext>,
    pub users: Vec<NamedUser>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub preferences: serde_json::Map<String, Value>,
}

impl Kubeconfig {
    /// Parse kubeconfig text from either JSON or YAML format.
    pub fn parse(content: &str) -> Result<Self, KubeconfigError> {
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Err(KubeconfigError::Parse("empty kubeconfig".to_string()));
        }

        // Try direct JSON deserialization first
        if let Some(config) = trimmed
            .strip_prefix('{')
            .and_then(|_| serde_json::from_str::<Self>(trimmed).ok())
        {
            config.validate()?;
            return Ok(config);
        }

        // Fallback to YAML decoder which produces a serde_json::Value
        let value = decode_yaml_value(trimmed)
            .map_err(|e| KubeconfigError::Parse(format!("YAML decode error: {e}")))?;

        let config: Self = serde_json::from_value(value)
            .map_err(|e| KubeconfigError::Parse(format!("schema error: {e}")))?;

        config.validate()?;
        Ok(config)
    }

    /// Read and parse kubeconfig from a file path.
    pub fn from_file(path: &Path) -> Result<Self, KubeconfigError> {
        let content = fs::read_to_string(path)
            .map_err(|e| KubeconfigError::Io(format!("{}: {e}", path.display())))?;
        Self::parse(&content)
    }

    /// Validate the internal consistency of the kubeconfig.
    pub fn validate(&self) -> Result<(), KubeconfigError> {
        if self.api_version != "v1" {
            return Err(KubeconfigError::InvalidFormat(format!(
                "expected apiVersion v1, got {}",
                self.api_version
            )));
        }
        if self.kind != "Config" {
            return Err(KubeconfigError::InvalidFormat(format!(
                "expected kind Config, got {}",
                self.kind
            )));
        }
        if self.current_context.is_empty() {
            return Err(KubeconfigError::MissingField("current-context".to_string()));
        }
        if self.clusters.is_empty() {
            return Err(KubeconfigError::MissingField("clusters".to_string()));
        }
        if self.contexts.is_empty() {
            return Err(KubeconfigError::MissingField("contexts".to_string()));
        }
        if self.users.is_empty() {
            return Err(KubeconfigError::MissingField("users".to_string()));
        }

        // Validate current context references an existing context
        let current_ctx = self
            .contexts
            .iter()
            .find(|c| c.name == self.current_context)
            .ok_or_else(|| {
                KubeconfigError::InvalidFormat(format!(
                    "current-context '{}' not found in contexts list",
                    self.current_context
                ))
            })?;

        // Validate context references an existing cluster
        let current_cluster = self
            .clusters
            .iter()
            .find(|c| c.name == current_ctx.context.cluster)
            .ok_or_else(|| {
                KubeconfigError::InvalidFormat(format!(
                    "cluster '{}' referenced by current context not found in clusters list",
                    current_ctx.context.cluster
                ))
            })?;

        if current_cluster.cluster.server.is_empty() {
            return Err(KubeconfigError::MissingField(
                "cluster server url".to_string(),
            ));
        }

        // Validate context references an existing user
        self.users
            .iter()
            .find(|u| u.name == current_ctx.context.user)
            .ok_or_else(|| {
                KubeconfigError::InvalidFormat(format!(
                    "user '{}' referenced by current context not found in users list",
                    current_ctx.context.user
                ))
            })?;

        Ok(())
    }

    /// Serialize to standard JSON format.
    pub fn to_json(&self) -> Result<String, KubeconfigError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| KubeconfigError::Parse(format!("JSON serialization error: {e}")))
    }

    /// Serialize YAML using JSON-escaped scalar values (valid YAML 1.2).
    pub fn to_yaml(&self) -> String {
        fn quoted(value: &str) -> String {
            Value::String(value.to_owned()).to_string()
        }
        let mut yaml = format!(
            "apiVersion: {}\nkind: {}\ncurrent-context: {}\npreferences: {}\n",
            quoted(&self.api_version),
            quoted(&self.kind),
            quoted(&self.current_context),
            Value::Object(self.preferences.clone()),
        );
        yaml.push_str("clusters:\n");
        for c in &self.clusters {
            yaml.push_str(&format!(
                "- name: {}\n  cluster:\n    server: {}\n",
                quoted(&c.name),
                quoted(&c.cluster.server)
            ));
            for (key, value) in [
                (
                    "certificate-authority-data",
                    &c.cluster.certificate_authority_data,
                ),
                ("certificate-authority", &c.cluster.certificate_authority),
            ] {
                if let Some(value) = value {
                    yaml.push_str(&format!("    {key}: {}\n", quoted(value)));
                }
            }
            if let Some(skip) = c.cluster.insecure_skip_tls_verify {
                yaml.push_str(&format!("    insecure-skip-tls-verify: {skip}\n"));
            }
        }
        yaml.push_str("contexts:\n");
        for c in &self.contexts {
            yaml.push_str(&format!(
                "- name: {}\n  context:\n    cluster: {}\n    user: {}\n",
                quoted(&c.name),
                quoted(&c.context.cluster),
                quoted(&c.context.user)
            ));
            if let Some(ns) = &c.context.namespace {
                yaml.push_str(&format!("    namespace: {}\n", quoted(ns)));
            }
        }
        yaml.push_str("users:\n");
        for u in &self.users {
            yaml.push_str(&format!("- name: {}\n  user: {{", quoted(&u.name)));
            let mut fields = Vec::new();
            for (key, value) in [
                ("client-certificate-data", &u.user.client_certificate_data),
                ("client-key-data", &u.user.client_key_data),
                ("client-certificate", &u.user.client_certificate),
                ("client-key", &u.user.client_key),
                ("token", &u.user.token),
            ] {
                if let Some(value) = value {
                    fields.push(format!("{}: {}", quoted(key), quoted(value)));
                }
            }
            yaml.push_str(&fields.join(", "));
            yaml.push_str("}\n");
        }
        yaml
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_yaml_and_json_interchangeably() {
        let yaml_text = r#"apiVersion: v1
kind: Config
current-context: admin@diorama
clusters:
- cluster:
    certificate-authority-data: dGVzdC1jYQ==
    server: https://127.0.0.1:6443
  name: diorama
contexts:
- context:
    cluster: diorama
    user: admin
  name: admin@diorama
users:
- name: admin
  user:
    client-certificate-data: dGVzdC1jZXJ0
    client-key-data: dGVzdC1rZXk=
"#;

        let from_yaml = Kubeconfig::parse(yaml_text).expect("parse YAML");
        assert_eq!(from_yaml.current_context, "admin@diorama");
        assert_eq!(from_yaml.clusters.len(), 1);
        assert_eq!(
            from_yaml.clusters[0].cluster.server,
            "https://127.0.0.1:6443"
        );

        let json_text = from_yaml.to_json().expect("to json");
        let from_json = Kubeconfig::parse(&json_text).expect("parse JSON");
        assert_eq!(from_yaml, from_json);

        // Check round-trip through to_yaml
        let rendered_yaml = from_json.to_yaml();
        let from_rendered_yaml = Kubeconfig::parse(&rendered_yaml).expect("parse rendered YAML");
        assert_eq!(from_yaml, from_rendered_yaml);
    }

    #[test]
    fn reject_invalid_kubeconfigs() {
        assert!(Kubeconfig::parse("").is_err());
        assert!(Kubeconfig::parse("apiVersion: v2\nkind: Config").is_err());
        assert!(Kubeconfig::parse(r#"{"apiVersion":"v1","kind":"WrongKind"}"#).is_err());
        assert!(
            Kubeconfig::parse(r#"{"apiVersion":"v1","kind":"Config","current-context":"missing"}"#)
                .is_err()
        );
    }
}
