use base64::prelude::*;
use rcgen::SanType;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::kubeconfig::write_kubeconfig;
use crate::profile::{Component, profile};
use crate::rotate::{rotate_leaf_if_needed, validate_pki_dir};
use crate::{PkiError, ensure_ca, ensure_service_account_key};

#[derive(Debug, Clone)]
pub struct ClusterPkiConfig {
    pub pki_dir: PathBuf,
    pub node_name: String,
    pub node_ip: IpAddr,
    pub service_ip: IpAddr,
    pub extra_sans: Vec<String>,
}

impl ClusterPkiConfig {
    pub fn new(pki_dir: PathBuf, node_name: String, node_ip: IpAddr) -> Self {
        Self {
            pki_dir,
            node_name,
            node_ip,
            service_ip: "10.43.0.1".parse().unwrap(),
            extra_sans: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct PkiReport {
    pub rotated: Vec<String>,
    pub preserved: Vec<String>,
}

#[derive(Debug)]
pub struct ClusterPki {
    config: ClusterPkiConfig,
}

impl ClusterPki {
    pub fn new(config: ClusterPkiConfig) -> Self {
        Self { config }
    }

    #[allow(clippy::too_many_lines)]
    pub fn reconcile(&self) -> Result<PkiReport, PkiError> {
        validate_pki_dir(&self.config.pki_dir)?;

        let mut report = PkiReport::default();
        let dir = &self.config.pki_dir;

        // 1. CAs
        let ca_crt = dir.join("ca.crt");
        let ca_key = dir.join("ca.key");
        ensure_ca(&ca_crt, &ca_key, "kubernetes-ca")?;

        let req_ca_crt = dir.join("request-header-ca.crt");
        let req_ca_key = dir.join("request-header-ca.key");
        ensure_ca(&req_ca_crt, &req_ca_key, "request-header-ca")?;

        let ds_ca_crt = dir.join("datastore-ca.crt");
        let ds_ca_key = dir.join("datastore-ca.key");
        ensure_ca(&ds_ca_crt, &ds_ca_key, "datastore-ca")?;

        // 2. Service Account Key
        let sa_key = dir.join("service-account.key");
        ensure_service_account_key(&sa_key)?;

        // 3. Leaf certificates
        // Helper closure to manage leaf rotation
        let mut handle_leaf = |name: &str,
                               component: Component,
                               signer_crt: &Path,
                               signer_key: &Path,
                               dns: &[String],
                               ips: &[IpAddr]|
         -> Result<(), PkiError> {
            let cert_path = dir.join(format!("{name}.crt"));
            let key_path = dir.join(format!("{name}.key"));

            let mut params = profile(component);
            let mut san_types = Vec::new();
            for d in dns {
                if let Ok(ia5) = d.clone().try_into() {
                    san_types.push(SanType::DnsName(ia5));
                }
            }
            for ip in ips {
                san_types.push(SanType::IpAddress(*ip));
            }
            params.subject_alt_names = san_types;

            let expected_cn = match component {
                Component::Kubelet => format!("system:node:{}", self.config.node_name),
                _ => String::new(),
            };
            if !expected_cn.is_empty() {
                params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, expected_cn.clone());
            }

            let rotated = rotate_leaf_if_needed(
                &cert_path,
                &key_path,
                signer_crt,
                signer_key,
                &params,
                &expected_cn,
                dns,
                ips,
            )?;

            if rotated {
                report.rotated.push(name.to_string());
            } else {
                report.preserved.push(name.to_string());
            }
            Ok(())
        };

        // Kubelet
        let kubelet_dns = vec![self.config.node_name.clone(), "localhost".to_string()];
        let kubelet_ips = vec!["127.0.0.1".parse().unwrap(), self.config.node_ip];
        handle_leaf(
            "kubelet",
            Component::Kubelet,
            &ca_crt,
            &ca_key,
            &kubelet_dns,
            &kubelet_ips,
        )?;

        // Apiserver
        let mut apiserver_dns = vec![
            "kubernetes".to_string(),
            "kubernetes.default".to_string(),
            "kubernetes.default.svc".to_string(),
            "kubernetes.default.svc.cluster".to_string(),
            "kubernetes.default.svc.cluster.local".to_string(),
            "localhost".to_string(),
        ];
        let mut apiserver_ips = vec![
            self.config.service_ip,
            "127.0.0.1".parse().unwrap(),
            self.config.node_ip,
        ];
        // Parse extra SANs
        for san in &self.config.extra_sans {
            if san.is_empty() {
                continue;
            }
            if let Ok(ip) = san.parse::<IpAddr>() {
                if !apiserver_ips.contains(&ip) {
                    apiserver_ips.push(ip);
                }
            } else if !apiserver_dns.contains(san) {
                apiserver_dns.push(san.clone());
            }
        }
        handle_leaf(
            "kube-apiserver",
            Component::Apiserver,
            &ca_crt,
            &ca_key,
            &apiserver_dns,
            &apiserver_ips,
        )?;

        // Controller Manager
        handle_leaf(
            "kube-controller-manager",
            Component::ControllerManager,
            &ca_crt,
            &ca_key,
            &[],
            &[],
        )?;

        // Kube Proxy
        handle_leaf(
            "kube-proxy",
            Component::KubeProxy,
            &ca_crt,
            &ca_key,
            &[],
            &[],
        )?;

        // Admin
        let admin_dns = vec!["localhost".to_string()];
        let admin_ips = vec!["127.0.0.1".parse().unwrap()];
        handle_leaf(
            "admin",
            Component::Admin,
            &ca_crt,
            &ca_key,
            &admin_dns,
            &admin_ips,
        )?;

        // Webhook
        let webhook_dns = vec![
            "localhost".to_string(),
            "diorama-webhook".to_string(),
            "diorama-webhook.default".to_string(),
            "diorama-webhook.default.svc".to_string(),
        ];
        let webhook_ips = vec!["127.0.0.1".parse().unwrap()];
        handle_leaf(
            "webhook",
            Component::Webhook,
            &ca_crt,
            &ca_key,
            &webhook_dns,
            &webhook_ips,
        )?;

        // Request Header Client (signed by request-header-ca)
        handle_leaf(
            "request-header-client",
            Component::RequestHeaderClient,
            &req_ca_crt,
            &req_ca_key,
            &[],
            &[],
        )?;

        // D2K Server
        let d2k_dns = vec![
            "d2k".to_string(),
            "d2k.fixture-d2k".to_string(),
            "d2k.fixture-d2k.svc".to_string(),
            "d2k.fixture-d2k.svc.cluster.local".to_string(),
            "localhost".to_string(),
        ];
        let d2k_ips = vec!["127.0.0.1".parse().unwrap()];
        handle_leaf(
            "d2k-server",
            Component::D2kServer,
            &ca_crt,
            &ca_key,
            &d2k_dns,
            &d2k_ips,
        )?;

        // D2K Client
        handle_leaf(
            "d2k-client",
            Component::D2kClient,
            &ca_crt,
            &ca_key,
            &[],
            &[],
        )?;

        // Datastore Server
        let mut ds_server_dns = vec!["localhost".to_string()];
        let mut ds_server_ips = vec!["127.0.0.1".parse().unwrap()];
        if !ds_server_ips.contains(&self.config.node_ip) {
            ds_server_ips.push(self.config.node_ip);
        }
        for san in &self.config.extra_sans {
            if let Ok(ip) = san.parse::<IpAddr>() {
                if !ds_server_ips.contains(&ip) {
                    ds_server_ips.push(ip);
                }
            } else if !ds_server_dns.contains(san) {
                ds_server_dns.push(san.clone());
            }
        }
        handle_leaf(
            "datastore-server",
            Component::DatastoreServer,
            &ds_ca_crt,
            &ds_ca_key,
            &ds_server_dns,
            &ds_server_ips,
        )?;

        // Datastore Client
        let ds_client_dns = ds_server_dns;
        let ds_client_ips = ds_server_ips;
        handle_leaf(
            "datastore-client",
            Component::DatastoreClient,
            &ds_ca_crt,
            &ds_ca_key,
            &ds_client_dns,
            &ds_client_ips,
        )?;

        // 4. Kubeconfigs
        let server_url = format!(
            "https://{}",
            std::net::SocketAddr::new(self.config.node_ip, 6443)
        );
        let ca_data = std::fs::read(&ca_crt)?;
        let ca_b64 = BASE64_STANDARD.encode(&ca_data);

        for (name, user) in [
            ("admin", "admin"),
            ("kubelet", "kubelet"),
            ("kube-controller-manager", "kube-controller-manager"),
            ("kube-proxy", "system:kube-proxy"),
        ] {
            let kubeconfig_path = dir.join(format!("{name}.kubeconfig"));
            let client_cert = std::fs::read(dir.join(format!("{name}.crt")))?;
            let client_key = std::fs::read(dir.join(format!("{name}.key")))?;

            write_kubeconfig(
                &kubeconfig_path,
                &server_url,
                "diorama",
                user,
                &ca_b64,
                &BASE64_STANDARD.encode(&client_cert),
                &BASE64_STANDARD.encode(&client_key),
            )?;
        }

        Ok(report)
    }

    pub fn ca_fingerprint(&self) -> Result<String, PkiError> {
        let ca_crt = self.config.pki_dir.join("ca.crt");
        let bytes = std::fs::read(ca_crt)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let res = hasher.finalize();
        let mut hex = String::with_capacity(res.len() * 2);
        for b in res {
            let _ = write!(hex, "{b:02x}");
        }
        Ok(hex)
    }

    /// Exports shared CA and service-account signing keys for a joining `controller` node.
    pub fn export_controller_join_material(
        pki_dir: &Path,
        assigned_node_id: u64,
        peers: std::collections::BTreeMap<u64, std::net::SocketAddr>,
    ) -> Result<crate::token::ControllerJoinMaterial, PkiError> {
        Ok(crate::token::ControllerJoinMaterial {
            assigned_node_id,
            peers,
            ca_cert_pem: std::fs::read_to_string(pki_dir.join("ca.crt"))?,
            ca_key_pem: std::fs::read_to_string(pki_dir.join("ca.key"))?,
            request_header_ca_cert_pem: std::fs::read_to_string(
                pki_dir.join("request-header-ca.crt"),
            )?,
            request_header_ca_key_pem: std::fs::read_to_string(
                pki_dir.join("request-header-ca.key"),
            )?,
            datastore_ca_cert_pem: std::fs::read_to_string(pki_dir.join("datastore-ca.crt"))?,
            datastore_ca_key_pem: std::fs::read_to_string(pki_dir.join("datastore-ca.key"))?,
            service_account_key_pem: std::fs::read_to_string(pki_dir.join("service-account.key"))?,
        })
    }

    /// Installs shared CA and service-account keys into `pki_dir` before `reconcile()` runs
    /// on a joining `controller` node.
    pub fn install_controller_join_material(
        pki_dir: &Path,
        material: &crate::token::ControllerJoinMaterial,
    ) -> Result<(), PkiError> {
        std::fs::create_dir_all(pki_dir)?;
        validate_pki_dir(pki_dir)?;
        crate::atomic_write(
            &pki_dir.join("ca.crt"),
            material.ca_cert_pem.as_bytes(),
            0o644,
        )?;
        crate::atomic_write(
            &pki_dir.join("ca.key"),
            material.ca_key_pem.as_bytes(),
            0o600,
        )?;
        crate::atomic_write(
            &pki_dir.join("request-header-ca.crt"),
            material.request_header_ca_cert_pem.as_bytes(),
            0o644,
        )?;
        crate::atomic_write(
            &pki_dir.join("request-header-ca.key"),
            material.request_header_ca_key_pem.as_bytes(),
            0o600,
        )?;
        crate::atomic_write(
            &pki_dir.join("datastore-ca.crt"),
            material.datastore_ca_cert_pem.as_bytes(),
            0o644,
        )?;
        crate::atomic_write(
            &pki_dir.join("datastore-ca.key"),
            material.datastore_ca_key_pem.as_bytes(),
            0o600,
        )?;
        crate::atomic_write(
            &pki_dir.join("service-account.key"),
            material.service_account_key_pem.as_bytes(),
            0o600,
        )?;
        Ok(())
    }

    /// Issues least-privilege worker credentials signed by the seed controller's CA without
    /// exposing any CA private keys to the worker node.
    pub fn issue_worker_join_material(
        seed_pki_dir: &Path,
        worker_node_name: &str,
        worker_node_ip: IpAddr,
        api_endpoint: &str,
    ) -> Result<crate::token::WorkerJoinMaterial, PkiError> {
        let scratch = tempfile::tempdir()?;
        for file in [
            "ca.crt",
            "ca.key",
            "request-header-ca.crt",
            "request-header-ca.key",
            "datastore-ca.crt",
            "datastore-ca.key",
            "service-account.key",
        ] {
            std::fs::copy(seed_pki_dir.join(file), scratch.path().join(file))?;
        }
        let worker_pki = ClusterPki::new(ClusterPkiConfig::new(
            scratch.path().to_path_buf(),
            worker_node_name.to_string(),
            worker_node_ip,
        ));
        worker_pki.reconcile()?;

        Ok(crate::token::WorkerJoinMaterial {
            assigned_node_id: 2,
            peer_addr: None,
            api_endpoint: api_endpoint.to_string(),
            ca_cert_pem: std::fs::read_to_string(scratch.path().join("ca.crt"))?,
            kubelet_cert_pem: std::fs::read_to_string(scratch.path().join("kubelet.crt"))?,
            kubelet_key_pem: std::fs::read_to_string(scratch.path().join("kubelet.key"))?,
            kube_proxy_cert_pem: std::fs::read_to_string(scratch.path().join("kube-proxy.crt"))?,
            kube_proxy_key_pem: std::fs::read_to_string(scratch.path().join("kube-proxy.key"))?,
            datastore_ca_cert_pem: std::fs::read_to_string(
                scratch.path().join("datastore-ca.crt"),
            )?,
            datastore_server_cert_pem: std::fs::read_to_string(
                scratch.path().join("datastore-server.crt"),
            )?,
            datastore_server_key_pem: std::fs::read_to_string(
                scratch.path().join("datastore-server.key"),
            )?,
        })
    }

    /// Installs signed worker certificates and kubeconfigs pointing at the controller API server.
    pub fn install_worker_join_material(
        pki_dir: &Path,
        material: &crate::token::WorkerJoinMaterial,
    ) -> Result<(), PkiError> {
        std::fs::create_dir_all(pki_dir)?;
        validate_pki_dir(pki_dir)?;
        crate::atomic_write(
            &pki_dir.join("ca.crt"),
            material.ca_cert_pem.as_bytes(),
            0o644,
        )?;
        crate::atomic_write(
            &pki_dir.join("kubelet.crt"),
            material.kubelet_cert_pem.as_bytes(),
            0o644,
        )?;
        crate::atomic_write(
            &pki_dir.join("kubelet.key"),
            material.kubelet_key_pem.as_bytes(),
            0o600,
        )?;
        crate::atomic_write(
            &pki_dir.join("kube-proxy.crt"),
            material.kube_proxy_cert_pem.as_bytes(),
            0o644,
        )?;
        crate::atomic_write(
            &pki_dir.join("kube-proxy.key"),
            material.kube_proxy_key_pem.as_bytes(),
            0o600,
        )?;
        crate::atomic_write(
            &pki_dir.join("datastore-ca.crt"),
            material.datastore_ca_cert_pem.as_bytes(),
            0o644,
        )?;
        crate::atomic_write(
            &pki_dir.join("datastore-server.crt"),
            material.datastore_server_cert_pem.as_bytes(),
            0o644,
        )?;
        crate::atomic_write(
            &pki_dir.join("datastore-server.key"),
            material.datastore_server_key_pem.as_bytes(),
            0o600,
        )?;

        let ca_b64 = BASE64_STANDARD.encode(material.ca_cert_pem.as_bytes());
        write_kubeconfig(
            &pki_dir.join("kubelet.kubeconfig"),
            &material.api_endpoint,
            "diorama",
            "kubelet",
            &ca_b64,
            &BASE64_STANDARD.encode(material.kubelet_cert_pem.as_bytes()),
            &BASE64_STANDARD.encode(material.kubelet_key_pem.as_bytes()),
        )?;
        write_kubeconfig(
            &pki_dir.join("kube-proxy.kubeconfig"),
            &material.api_endpoint,
            "diorama",
            "system:kube-proxy",
            &ca_b64,
            &BASE64_STANDARD.encode(material.kube_proxy_cert_pem.as_bytes()),
            &BASE64_STANDARD.encode(material.kube_proxy_key_pem.as_bytes()),
        )?;
        Ok(())
    }
}
