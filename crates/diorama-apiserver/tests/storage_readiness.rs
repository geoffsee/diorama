use std::net::IpAddr;
use std::time::Duration;
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverAdapter, ApiserverConfig, ApiserverService, COMPONENT_APISERVER, KubernetesStorage,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_supervisor::{StopCause, Supervisor};

fn setup_pki(dir: &TempDir, node_ip: IpAddr) -> ApiserverConfig {
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let config = ClusterPkiConfig::new(pki_dir.clone(), "node-1".to_string(), node_ip);
    let pki = ClusterPki::new(config);
    pki.reconcile().expect("PKI reconcile");
    ApiserverConfig::default_for_pki(&pki_dir, node_ip)
}

fn setup_storage(dir: &TempDir) -> KubernetesStorage {
    let data_dir = dir.path().join("datastore");
    let ds_config = DatastoreConfig::new(data_dir);
    let (engine, _) = DatastoreEngine::open(ds_config).expect("datastore open");
    KubernetesStorage::new(engine.client(), "/registry")
}

#[tokio::test]
async fn readiness_succeeds_when_storage_and_credentials_are_healthy() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let config = setup_pki(&temp, node_ip);
    let storage = setup_storage(&temp);

    let service = ApiserverService::new(config, storage);
    let report = service
        .check_readiness()
        .await
        .expect("readiness evaluation succeeds");

    assert!(report.is_healthy);
    assert_eq!(report.checks.get("etcd").map(String::as_str), Some("ok"));
    assert_eq!(report.checks.get("pki").map(String::as_str), Some("ok"));
}

#[tokio::test]
async fn readiness_fails_when_pki_credentials_are_missing() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.2".parse().unwrap();
    let mut config = setup_pki(&temp, node_ip);
    let storage = setup_storage(&temp);

    // Point cert file to non-existent path
    config.tls_cert_file = temp.path().join("pki/non_existent.crt");

    let service = ApiserverService::new(config, storage);
    let report = service
        .check_readiness()
        .await
        .expect("readiness evaluation completes");

    assert!(!report.is_healthy);
    assert!(
        report
            .checks
            .get("pki")
            .unwrap()
            .contains("file not found at"),
        "Missing certificate must cause pki check failure"
    );

    // Prerequisite check must fail
    let prereq_err = service.check_prerequisites().await;
    assert!(prereq_err.is_err());
    assert_eq!(
        prereq_err.unwrap_err().diagnostic_code(),
        "apiserver-credentials-invalid"
    );
}

#[tokio::test]
async fn readiness_fails_when_pki_private_key_is_corrupt() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.3".parse().unwrap();
    let config = setup_pki(&temp, node_ip);
    let storage = setup_storage(&temp);

    // Corrupt service-account signing key
    std::fs::write(
        &config.service_account_signing_key_file,
        b"NOT_A_VALID_PEM_KEY",
    )
    .unwrap();

    let service = ApiserverService::new(config, storage);
    let report = service
        .check_readiness()
        .await
        .expect("readiness evaluation completes");

    assert!(!report.is_healthy);
    assert!(
        report
            .checks
            .get("pki")
            .unwrap()
            .contains("not a valid PEM private key"),
        "Corrupted key must cause pki check failure"
    );
}

#[tokio::test]
async fn supervisor_rejects_startup_when_credentials_are_unusable() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.4".parse().unwrap();
    let config = setup_pki(&temp, node_ip);
    let storage = setup_storage(&temp);

    // Corrupt TLS private key
    std::fs::write(&config.tls_private_key_file, b"corrupted").unwrap();

    let service = ApiserverService::new(config, storage);

    let registration = ApiserverAdapter::registration(
        COMPONENT_APISERVER,
        service,
        Vec::new(),
        Duration::from_secs(5),
    );

    let supervisor = Supervisor::new(vec![registration]).expect("register succeeds");
    let (stop_handle, stop_receiver) = diorama_supervisor::stop_channel();

    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // The supervisor will run the adapter, fail the prerequisite check, and terminate
    let report = sup_handle.await.expect("supervisor task joins");
    assert!(
        matches!(report.cause, StopCause::Fatal { .. }),
        "Supervisor must stop with Fatal when prerequisites are unusable"
    );
    drop(stop_handle);
}

#[tokio::test]
async fn readiness_fails_when_certificate_is_truncated() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.5".parse().unwrap();
    let config = setup_pki(&temp, node_ip);
    let storage = setup_storage(&temp);

    // Read valid cert and truncate its base64 body
    let valid_cert = std::fs::read_to_string(&config.tls_cert_file).unwrap();
    let truncated_cert = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        &valid_cert[30..60] // Truncated DER body
    );
    std::fs::write(&config.tls_cert_file, truncated_cert).unwrap();

    let service = ApiserverService::new(config, storage);
    let report = service
        .check_readiness()
        .await
        .expect("readiness evaluation completes");

    assert!(!report.is_healthy);
    assert!(
        report
            .checks
            .get("pki")
            .unwrap()
            .contains("not a valid PEM certificate"),
        "Truncated certificate must fail validation"
    );

    let prereq_err = service.check_prerequisites().await;
    assert!(prereq_err.is_err());
}

#[tokio::test]
async fn readiness_fails_when_private_key_is_truncated() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.6".parse().unwrap();
    let config = setup_pki(&temp, node_ip);
    let storage = setup_storage(&temp);

    // Write a key PEM with truncated payload
    let truncated_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0123456789\n-----END RSA PRIVATE KEY-----\n";
    std::fs::write(&config.tls_private_key_file, truncated_key).unwrap();

    let service = ApiserverService::new(config, storage);
    let report = service
        .check_readiness()
        .await
        .expect("readiness evaluation completes");

    assert!(!report.is_healthy);
    assert!(
        report
            .checks
            .get("pki")
            .unwrap()
            .contains("not a valid PEM private key"),
        "Truncated private key must fail validation"
    );

    let prereq_err = service.check_prerequisites().await;
    assert!(prereq_err.is_err());
}
