use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use crate::error::ApiserverError;

pub const DEFAULT_SECURE_PORT: u16 = 6443;
pub const DEFAULT_SERVICE_CLUSTER_IP_RANGE: &str = "10.43.0.0/16";
pub const DEFAULT_ETCD_PREFIX: &str = "/registry";
pub const DEFAULT_SA_ISSUER: &str = "https://kubernetes.default.svc";

/// Official Kubernetes v1.35.7 API Server configuration options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiserverConfig {
    pub bind_address: IpAddr,
    pub secure_port: u16,
    pub advertise_address: IpAddr,
    pub service_cluster_ip_range: String,
    pub pki_dir: PathBuf,
    pub etcd_servers: Vec<String>,
    pub etcd_prefix: String,
    pub etcd_ca_file: Option<PathBuf>,
    pub etcd_cert_file: Option<PathBuf>,
    pub etcd_key_file: Option<PathBuf>,
    pub authorization_modes: Vec<String>,
    pub anonymous_auth: bool,
    pub allow_privileged: bool,
    pub service_account_issuer: String,
    pub api_audiences: Vec<String>,
    pub feature_gates: BTreeMap<String, bool>,

    // PKI certificate paths
    pub client_ca_file: PathBuf,
    pub tls_cert_file: PathBuf,
    pub tls_private_key_file: PathBuf,
    pub service_account_key_file: PathBuf,
    pub service_account_signing_key_file: PathBuf,
    pub request_header_ca_file: PathBuf,
    pub request_header_client_cert: PathBuf,
    pub request_header_client_key: PathBuf,
    pub kubelet_client_certificate: PathBuf,
    pub kubelet_client_key: PathBuf,
}

impl ApiserverConfig {
    pub fn default_for_pki(pki_dir: impl AsRef<Path>, node_ip: IpAddr) -> Self {
        let pki = pki_dir.as_ref();
        Self {
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            secure_port: DEFAULT_SECURE_PORT,
            advertise_address: node_ip,
            service_cluster_ip_range: DEFAULT_SERVICE_CLUSTER_IP_RANGE.to_string(),
            pki_dir: pki.to_path_buf(),
            etcd_servers: vec!["http://127.0.0.1:2379".to_string()],
            etcd_prefix: DEFAULT_ETCD_PREFIX.to_string(),
            etcd_ca_file: None,
            etcd_cert_file: None,
            etcd_key_file: None,
            authorization_modes: vec!["Node".to_string(), "RBAC".to_string()],
            anonymous_auth: false,
            allow_privileged: true,
            service_account_issuer: DEFAULT_SA_ISSUER.to_string(),
            api_audiences: vec![DEFAULT_SA_ISSUER.to_string()],
            feature_gates: BTreeMap::new(),

            client_ca_file: pki.join("ca.crt"),
            tls_cert_file: pki.join("kube-apiserver.crt"),
            tls_private_key_file: pki.join("kube-apiserver.key"),
            service_account_key_file: pki.join("service-account.key"),
            service_account_signing_key_file: pki.join("service-account.key"),
            request_header_ca_file: pki.join("request-header-ca.crt"),
            request_header_client_cert: pki.join("admin.crt"),
            request_header_client_key: pki.join("admin.key"),
            kubelet_client_certificate: pki.join("kube-apiserver.crt"),
            kubelet_client_key: pki.join("kube-apiserver.key"),
        }
    }

    pub fn validate(&self) -> Result<(), ApiserverError> {
        if self.service_cluster_ip_range.is_empty() {
            return Err(ApiserverError::Config {
                reason: "service_cluster_ip_range must not be empty".to_string(),
            });
        }
        if self.etcd_servers.is_empty() {
            return Err(ApiserverError::Config {
                reason: "at least one etcd server must be configured".to_string(),
            });
        }
        if self.secure_port == 0 {
            return Err(ApiserverError::Config {
                reason: "secure_port must be non-zero".to_string(),
            });
        }
        Ok(())
    }

    /// Format standard official kube-apiserver v1.35.7 CLI arguments.
    #[must_use]
    pub fn to_command_args(&self) -> Vec<String> {
        let mut args = vec![
            format!("--bind-address={}", self.bind_address),
            format!("--advertise-address={}", self.advertise_address),
            format!("--secure-port={}", self.secure_port),
            format!(
                "--service-cluster-ip-range={}",
                self.service_cluster_ip_range
            ),
            format!("--cert-dir={}", self.pki_dir.display()),
            format!("--client-ca-file={}", self.client_ca_file.display()),
            format!("--tls-cert-file={}", self.tls_cert_file.display()),
            format!(
                "--tls-private-key-file={}",
                self.tls_private_key_file.display()
            ),
            format!(
                "--service-account-key-file={}",
                self.service_account_key_file.display()
            ),
            format!(
                "--service-account-signing-key-file={}",
                self.service_account_signing_key_file.display()
            ),
            format!("--service-account-issuer={}", self.service_account_issuer),
            format!("--api-audiences={}", self.api_audiences.join(",")),
            format!(
                "--authorization-mode={}",
                self.authorization_modes.join(",")
            ),
            format!("--anonymous-auth={}", self.anonymous_auth),
            format!("--allow-privileged={}", self.allow_privileged),
            format!("--etcd-servers={}", self.etcd_servers.join(",")),
            format!("--etcd-prefix={}", self.etcd_prefix),
            format!(
                "--requestheader-client-ca-file={}",
                self.request_header_ca_file.display()
            ),
            "--requestheader-allowed-names=system:auth-proxy".to_string(),
            "--requestheader-extra-headers-prefix=X-Remote-Extra-".to_string(),
            "--requestheader-group-headers=X-Remote-Group".to_string(),
            "--requestheader-username-headers=X-Remote-User".to_string(),
            format!(
                "--proxy-client-cert-file={}",
                self.request_header_client_cert.display()
            ),
            format!(
                "--proxy-client-key-file={}",
                self.request_header_client_key.display()
            ),
            format!(
                "--kubelet-client-certificate={}",
                self.kubelet_client_certificate.display()
            ),
            format!("--kubelet-client-key={}", self.kubelet_client_key.display()),
        ];

        if let Some(ca) = &self.etcd_ca_file {
            args.push(format!("--etcd-cafile={}", ca.display()));
        }
        if let Some(cert) = &self.etcd_cert_file {
            args.push(format!("--etcd-certfile={}", cert.display()));
        }
        if let Some(key) = &self.etcd_key_file {
            args.push(format!("--etcd-keyfile={}", key.display()));
        }

        if !self.feature_gates.is_empty() {
            let gates = self
                .feature_gates
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(",");
            args.push(format!("--feature-gates={gates}"));
        }

        args
    }
}
