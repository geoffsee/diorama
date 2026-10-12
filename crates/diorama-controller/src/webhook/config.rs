use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use diorama_apiserver::{
    FailurePolicy, MutatingWebhookConfiguration, RuleWithOperations, WebhookClientConfig,
    WebhookDefinition,
};
use serde_json::json;

use super::error::WebhookError;

pub const DEFAULT_WEBHOOK_NAME: &str = "webhook.kubesolo.io";
pub const DEFAULT_WEBHOOK_PORT: u16 = 10443;
pub const DEFAULT_MUTATE_URL: &str = "https://127.0.0.1:10443/mutate";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookConfig {
    /// Node name to assign unassigned pods, PVCs and jobs to.
    pub node_name: String,
    /// Static IP assigned to Services of type `LoadBalancer`.
    pub load_balancer_ip: String,
    /// Whether `LoadBalancer` status allocation is enabled.
    pub load_balancer: bool,
    /// PKI directory path containing certificates.
    pub pki_path: PathBuf,
    /// Webhook server TLS certificate.
    pub cert_file: PathBuf,
    /// Webhook server TLS private key.
    pub key_file: PathBuf,
    /// CA certificate bundle used to verify trust.
    pub ca_file: PathBuf,
    /// Address to bind the webhook HTTPS listener to.
    pub bind_address: IpAddr,
    /// Port to listen on (default 10443).
    pub port: u16,
    /// Webhook endpoint URL registered in `MutatingWebhookConfiguration`.
    pub url: String,
}

impl WebhookConfig {
    #[must_use]
    pub fn default_for_pki(
        pki_dir: impl AsRef<Path>,
        node_name: &str,
        load_balancer_ip: &str,
        load_balancer: bool,
    ) -> Self {
        let pki = pki_dir.as_ref().to_path_buf();
        let cert_file = if pki.join("webhook/webhook.crt").exists() {
            pki.join("webhook/webhook.crt")
        } else {
            pki.join("webhook.crt")
        };
        let key_file = if pki.join("webhook/webhook.key").exists() {
            pki.join("webhook/webhook.key")
        } else {
            pki.join("webhook.key")
        };
        let ca_file = if pki.join("ca.crt").exists() {
            pki.join("ca.crt")
        } else if pki.join("webhook/webhook.crt").exists() {
            pki.join("webhook/webhook.crt")
        } else {
            pki.join("webhook.crt")
        };

        Self {
            node_name: node_name.to_string(),
            load_balancer_ip: load_balancer_ip.to_string(),
            load_balancer,
            pki_path: pki,
            cert_file,
            key_file,
            ca_file,
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_WEBHOOK_PORT,
            url: DEFAULT_MUTATE_URL.to_string(),
        }
    }

    /// Creates the standard `MutatingWebhookConfiguration` object for `NodeSetter` admission.
    pub fn create_configuration(&self) -> Result<MutatingWebhookConfiguration, WebhookError> {
        let ca_cert_path = if self.ca_file.exists() {
            &self.ca_file
        } else if self.pki_path.join("ca.crt").exists() {
            &self.pki_path.join("ca.crt")
        } else if self.pki_path.join("webhook/webhook.crt").exists() {
            &self.pki_path.join("webhook/webhook.crt")
        } else if self.cert_file.exists() {
            &self.cert_file
        } else {
            return Err(WebhookError::MissingCredential {
                path: self.cert_file.clone(),
                component: "webhook-cert",
            });
        };

        let ca_bytes =
            std::fs::read(ca_cert_path).map_err(|_e| WebhookError::MissingCredential {
                path: ca_cert_path.clone(),
                component: "webhook-ca",
            })?;

        let ca_bundle = diorama_pki::base64_encode(&ca_bytes);

        let mut rules = vec![RuleWithOperations {
            operations: vec!["CREATE".to_string()],
            api_groups: vec![String::new(), "apps".to_string(), "batch".to_string()],
            api_versions: vec!["v1".to_string()],
            resources: vec![
                "pods".to_string(),
                "persistentvolumeclaims".to_string(),
                "jobs".to_string(),
            ],
            scope: None,
        }];

        if self.load_balancer {
            rules.push(RuleWithOperations {
                operations: vec!["CREATE".to_string(), "UPDATE".to_string()],
                api_groups: vec![String::new()],
                api_versions: vec!["v1".to_string()],
                resources: vec!["services".to_string()],
                scope: None,
            });
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("name".to_string(), json!(DEFAULT_WEBHOOK_NAME));

        let webhook_def = WebhookDefinition {
            name: DEFAULT_WEBHOOK_NAME.to_string(),
            rules,
            client_config: WebhookClientConfig {
                url: Some(self.url.clone()),
                service: None,
                ca_bundle: Some(ca_bundle),
            },
            failure_policy: FailurePolicy::Ignore,
            side_effects: Some("NoneOnDryRun".to_string()),
            timeout_seconds: Some(30),
            admission_review_versions: vec!["v1".to_string()],
            reinvocation_policy: Some("IfNeeded".to_string()),
        };

        Ok(MutatingWebhookConfiguration {
            metadata,
            webhooks: vec![webhook_def],
        })
    }
}
