use diorama_pki::PkiError;
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_pki::rotate::validate_pki_dir;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_fresh_reconcile_generates_all() {
    let dir = tempdir().unwrap();
    let config = ClusterPkiConfig::new(
        dir.path().to_path_buf(),
        "fixture-node".to_string(),
        "192.0.2.10".parse().unwrap(),
    );
    let pki = ClusterPki::new(config);
    let report = pki.reconcile().unwrap();

    assert_eq!(report.rotated.len(), 12);
    assert_eq!(report.preserved.len(), 0);

    // Verify files on disk
    for name in [
        "ca.crt",
        "ca.key",
        "request-header-ca.crt",
        "request-header-ca.key",
        "datastore-ca.crt",
        "datastore-ca.key",
        "service-account.key",
        "kube-apiserver.crt",
        "kube-apiserver.key",
        "kubelet.crt",
        "kubelet.key",
        "kube-controller-manager.crt",
        "kube-controller-manager.key",
        "admin.crt",
        "admin.key",
        "webhook.crt",
        "webhook.key",
        "request-header-client.crt",
        "request-header-client.key",
        "d2k-server.crt",
        "d2k-server.key",
        "d2k-client.crt",
        "d2k-client.key",
        "datastore-server.crt",
        "datastore-server.key",
        "datastore-client.crt",
        "datastore-client.key",
        "admin.kubeconfig",
        "kubelet.kubeconfig",
        "kube-controller-manager.kubeconfig",
        "kube-proxy.crt",
        "kube-proxy.key",
        "kube-proxy.kubeconfig",
    ] {
        assert!(dir.path().join(name).exists(), "missing file: {name}");
    }
}

#[test]
fn test_unchanged_restart_preserves_all() {
    let dir = tempdir().unwrap();
    let config = ClusterPkiConfig::new(
        dir.path().to_path_buf(),
        "fixture-node".to_string(),
        "192.0.2.10".parse().unwrap(),
    );
    let pki = ClusterPki::new(config);
    pki.reconcile().unwrap();

    let ca_fp_before = pki.ca_fingerprint().unwrap();
    let apiserver_cert_before = fs::read(dir.path().join("kube-apiserver.crt")).unwrap();

    // Reconcile again with same config
    let report = pki.reconcile().unwrap();
    assert_eq!(report.rotated.len(), 0);
    assert_eq!(report.preserved.len(), 12);

    let ca_fp_after = pki.ca_fingerprint().unwrap();
    assert_eq!(ca_fp_before, ca_fp_after);

    let apiserver_cert_after = fs::read(dir.path().join("kube-apiserver.crt")).unwrap();
    assert_eq!(apiserver_cert_before, apiserver_cert_after);
}

#[test]
fn test_node_ip_change_rotates_affected_leaves() {
    let dir = tempdir().unwrap();
    let config = ClusterPkiConfig::new(
        dir.path().to_path_buf(),
        "fixture-node".to_string(),
        "192.0.2.10".parse().unwrap(),
    );
    let pki = ClusterPki::new(config);
    pki.reconcile().unwrap();

    let ca_fp_before = pki.ca_fingerprint().unwrap();
    let admin_cert_before = fs::read(dir.path().join("admin.crt")).unwrap();

    // Change node IP to 192.0.2.11
    let mut config2 = ClusterPkiConfig::new(
        dir.path().to_path_buf(),
        "fixture-node".to_string(),
        "192.0.2.11".parse().unwrap(),
    );
    config2.service_ip = "10.43.0.1".parse().unwrap();
    let pki2 = ClusterPki::new(config2);
    let report = pki2.reconcile().unwrap();

    // Apiserver and kubelet have node_ip in SANs, so they must rotate
    assert!(report.rotated.contains(&"kube-apiserver".to_string()));
    assert!(report.rotated.contains(&"kubelet".to_string()));

    // Admin, webhook, controller-manager, request-header-client, d2k, datastore do not have node IP in SANs
    assert!(report.preserved.contains(&"admin".to_string()));
    assert!(report.preserved.contains(&"webhook".to_string()));
    assert!(
        report
            .preserved
            .contains(&"kube-controller-manager".to_string())
    );
    assert!(
        report
            .preserved
            .contains(&"request-header-client".to_string())
    );
    assert!(report.preserved.contains(&"datastore-server".to_string()));
    assert!(report.preserved.contains(&"datastore-client".to_string()));

    // CA fingerprint and existing admin cert survive
    let ca_fp_after = pki2.ca_fingerprint().unwrap();
    assert_eq!(ca_fp_before, ca_fp_after);
    let admin_cert_after = fs::read(dir.path().join("admin.crt")).unwrap();
    assert_eq!(admin_cert_before, admin_cert_after);
}

#[test]
fn test_extra_sans_rotates_apiserver() {
    let dir = tempdir().unwrap();
    let config = ClusterPkiConfig::new(
        dir.path().to_path_buf(),
        "fixture-node".to_string(),
        "192.0.2.10".parse().unwrap(),
    );
    let pki = ClusterPki::new(config);
    pki.reconcile().unwrap();

    // Add extra SAN
    let mut config2 = ClusterPkiConfig::new(
        dir.path().to_path_buf(),
        "fixture-node".to_string(),
        "192.0.2.10".parse().unwrap(),
    );
    config2.extra_sans = vec!["new.fixture.test".to_string(), "192.0.2.20".to_string()];
    let pki2 = ClusterPki::new(config2);
    let report = pki2.reconcile().unwrap();

    assert!(report.rotated.contains(&"kube-apiserver".to_string()));
    assert!(report.preserved.contains(&"kubelet".to_string()));
    assert!(report.preserved.contains(&"admin".to_string()));
}

#[test]
fn test_corrupt_leaf_triggers_rotation() {
    let dir = tempdir().unwrap();
    let config = ClusterPkiConfig::new(
        dir.path().to_path_buf(),
        "fixture-node".to_string(),
        "192.0.2.10".parse().unwrap(),
    );
    let pki = ClusterPki::new(config);
    pki.reconcile().unwrap();

    // Corrupt kube-apiserver.crt
    fs::write(dir.path().join("kube-apiserver.crt"), b"corrupted pem data").unwrap();

    let report = pki.reconcile().unwrap();
    assert!(report.rotated.contains(&"kube-apiserver".to_string()));
    assert!(report.preserved.contains(&"admin".to_string()));

    // Ensure it is now valid
    let cert_bytes = fs::read(dir.path().join("kube-apiserver.crt")).unwrap();
    assert!(cert_bytes.starts_with(b"-----BEGIN CERTIFICATE-----"));
}

#[test]
fn test_unsafe_roots_rejected() {
    assert!(matches!(
        validate_pki_dir(std::path::Path::new("")),
        Err(PkiError::UnsafePath(_))
    ));
    assert!(matches!(
        validate_pki_dir(std::path::Path::new("/")),
        Err(PkiError::UnsafePath(_))
    ));
    assert!(matches!(
        validate_pki_dir(std::path::Path::new(".")),
        Err(PkiError::UnsafePath(_))
    ));

    let dir = tempdir().unwrap();
    let symlink_path = dir.path().join("symlink_pki");
    let target_dir = dir.path().join("target");
    fs::create_dir(&target_dir).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target_dir, &symlink_path).unwrap();

    #[cfg(unix)]
    assert!(matches!(
        validate_pki_dir(&symlink_path),
        Err(PkiError::UnsafePath(_))
    ));
}

#[test]
fn test_leaf_key_mismatch_rotates() {
    let dir = tempdir().unwrap();
    let config = ClusterPkiConfig::new(
        dir.path().to_path_buf(),
        "fixture-node".to_string(),
        "192.0.2.10".parse().unwrap(),
    );
    let pki = ClusterPki::new(config);
    pki.reconcile().unwrap();

    // Replace admin.key with a freshly generated different key (causing cert/key mismatch)
    let alt_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
    fs::write(dir.path().join("admin.key"), alt_key.serialize_pem()).unwrap();

    let report = pki.reconcile().unwrap();
    assert!(report.rotated.contains(&"admin".to_string()));
    assert!(report.preserved.contains(&"kubelet".to_string()));
}

#[test]
fn test_ipv6_kubeconfig_server_url_is_bracketed() {
    let dir = tempdir().unwrap();
    let config = ClusterPkiConfig::new(
        dir.path().to_path_buf(),
        "fixture-node".to_string(),
        "2001:db8::1".parse().unwrap(),
    );
    let pki = ClusterPki::new(config);
    pki.reconcile().unwrap();

    let admin_cfg = fs::read_to_string(dir.path().join("admin.kubeconfig")).unwrap();
    assert!(admin_cfg.contains("server: https://[2001:db8::1]:6443"));

    let proxy_cfg = fs::read_to_string(dir.path().join("kube-proxy.kubeconfig")).unwrap();
    assert!(proxy_cfg.contains("server: https://[2001:db8::1]:6443"));
    assert!(proxy_cfg.contains("certificate-authority-data:"));
    assert!(proxy_cfg.contains("name: system:kube-proxy"));
    assert!(proxy_cfg.contains("client-certificate-data:"));
}
