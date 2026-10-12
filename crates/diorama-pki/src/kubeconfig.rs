use crate::{PkiError, atomic_write};
use std::path::Path;

pub fn write_kubeconfig(
    path: &Path,
    server_url: &str,
    cluster_name: &str,
    user_name: &str,
    ca_b64: &str,
    cert_b64: &str,
    key_b64: &str,
) -> Result<(), PkiError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let yaml = format!(
        "apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {ca_b64}
    server: {server_url}
  name: {cluster_name}
contexts:
- context:
    cluster: {cluster_name}
    user: {user_name}
  name: {user_name}@{cluster_name}
current-context: {user_name}@{cluster_name}
kind: Config
preferences: {{}}
users:
- name: {user_name}
  user:
    client-certificate-data: {cert_b64}
    client-key-data: {key_b64}
"
    );

    atomic_write(path, yaml.as_bytes(), 0o600)?;
    Ok(())
}

pub fn ensure_kubeconfig(
    path: &Path,
    server_url: &str,
    cluster_name: &str,
    user_name: &str,
    ca_b64: &str,
    cert_b64: &str,
    key_b64: &str,
) -> Result<(), PkiError> {
    if path.exists() {
        return Ok(());
    }
    write_kubeconfig(
        path,
        server_url,
        cluster_name,
        user_name,
        ca_b64,
        cert_b64,
        key_b64,
    )
}

pub fn write_kubeconfig_path(
    path: &Path,
    server_url: &str,
    cluster_name: &str,
    user_name: &str,
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<(), PkiError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let yaml = format!(
        "apiVersion: v1
clusters:
- cluster:
    certificate-authority: {ca_path}
    server: {server_url}
  name: {cluster_name}
contexts:
- context:
    cluster: {cluster_name}
    user: {user_name}
  name: {user_name}@{cluster_name}
current-context: {user_name}@{cluster_name}
kind: Config
preferences: {{}}
users:
- name: {user_name}
  user:
    client-certificate: {cert_path}
    client-key: {key_path}
"
    );

    atomic_write(path, yaml.as_bytes(), 0o600)?;
    Ok(())
}

pub fn ensure_kubeconfig_path(
    path: &Path,
    server_url: &str,
    cluster_name: &str,
    user_name: &str,
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<(), PkiError> {
    if path.exists() {
        return Ok(());
    }
    write_kubeconfig_path(
        path,
        server_url,
        cluster_name,
        user_name,
        ca_path,
        cert_path,
        key_path,
    )
}
