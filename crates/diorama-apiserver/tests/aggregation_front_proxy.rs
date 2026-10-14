use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;

use async_trait::async_trait;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
use serde_json::{Value, json};

use diorama_apiserver::{
    AggregatedApiHandler, AggregatedRequestContext, ApiserverConfig, ApiserverError,
    ApiserverService, ClusterRoleBinding, KubernetesStorage, Subject,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};

fn setup_service(dir: &TempDir) -> ApiserverService {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "node-1".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);

    let data_dir = dir.path().join("datastore");
    let ds_config = DatastoreConfig::new(data_dir);
    let (engine, _) = DatastoreEngine::open(ds_config).expect("datastore open");
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    ApiserverService::new(apiserver_config, storage)
}

fn sign_client_cert_with_ca(ca_crt_path: &Path, ca_key_path: &Path, common_name: &str) -> String {
    let ca_crt_pem = std::fs::read_to_string(ca_crt_path).expect("read CA crt");
    let ca_key_pem = std::fs::read_to_string(ca_key_path).expect("read CA key");
    let ca_key_pair = KeyPair::from_pem(&ca_key_pem).expect("parse CA key");
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_crt_pem, ca_key_pair).expect("parse issuer");

    let leaf_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let leaf_params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_pair, &issuer).unwrap();
    leaf_cert.pem()
}

fn generate_untrusted_client_cert(common_name: &str) -> String {
    let ca_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let mut ca_params = CertificateParams::new(vec!["rogue-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let rogue_ca = ca_params.self_signed(&ca_pair).unwrap();
    let issuer = rcgen::Issuer::from_ca_cert_pem(&rogue_ca.pem(), ca_pair).unwrap();

    let leaf_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let leaf_params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_pair, &issuer).unwrap();
    leaf_cert.pem()
}

fn generate_custom_ca_and_server_cert(common_name: &str) -> (String, String) {
    let ca_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let mut ca_params = CertificateParams::new(vec!["aggregated-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_pair).unwrap();

    let leaf_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let leaf_params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_pair).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_pair, &issuer).unwrap();

    (ca_cert.pem(), leaf_cert.pem())
}

struct MockMetricsAggregatedHandler;

#[async_trait]
impl AggregatedApiHandler for MockMetricsAggregatedHandler {
    async fn handle_request(
        &self,
        ctx: &AggregatedRequestContext,
    ) -> Result<Value, ApiserverError> {
        // Verify caller context forwarded correctly from front-proxy
        assert!(
            !ctx.caller_username.is_empty(),
            "Caller username must be forwarded"
        );
        assert!(
            !ctx.caller_groups.is_empty(),
            "Caller groups must be forwarded"
        );

        if ctx.path == "/apis/metrics.k8s.io/v1beta1/nodes" && ctx.method == "GET" {
            Ok(json!({
                "kind": "NodeMetricsList",
                "apiVersion": "metrics.k8s.io/v1beta1",
                "metadata": { "resourceVersion": "100" },
                "items": [
                    {
                        "metadata": { "name": "node-1" },
                        "timestamp": "2026-09-30T12:00:00Z",
                        "window": "1m",
                        "usage": {
                            "cpu": "150m",
                            "memory": "512Mi"
                        }
                    }
                ]
            }))
        } else {
            Err(ApiserverError::NotFound {
                resource: "aggregated".to_string(),
                name: ctx.path.clone(),
            })
        }
    }
}

#[tokio::test]
async fn test_front_proxy_header_authentication_success_and_rejection() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();

    let pki_dir = temp.path().join("pki");
    let req_ca_crt = pki_dir.join("request-header-ca.crt");
    let req_ca_key = pki_dir.join("request-header-ca.key");

    // Case 1: Valid front-proxy client certificate with CN "system:auth-proxy"
    let valid_proxy_cert = sign_client_cert_with_ca(&req_ca_crt, &req_ca_key, "system:auth-proxy");

    let admin = service.admin_client();
    // Grant "alice" cluster-admin permission to test operation
    admin
        .create_cluster_role_binding(ClusterRoleBinding {
            name: "alice-admin".to_string(),
            role_ref: "cluster-admin".to_string(),
            subjects: vec![Subject::User {
                name: "alice".to_string(),
            }],
        })
        .await
        .expect("bind cluster-admin to alice");

    // Connect via FrontProxy identity impersonating alice
    let alice_proxy = service.front_proxy_client(
        valid_proxy_cert,
        "alice",
        vec!["system:authenticated".to_string()],
    );

    let ns = alice_proxy
        .create_namespace("alice-project")
        .await
        .expect("alice authenticated via front-proxy can create namespace");
    assert_eq!(ns["metadata"]["name"], "alice-project");

    // Case 2: Untrusted front-proxy client certificate (signed by rogue CA)
    let untrusted_proxy_cert = generate_untrusted_client_cert("system:auth-proxy");
    let untrusted_proxy = service.front_proxy_client(
        untrusted_proxy_cert,
        "alice",
        vec!["system:authenticated".to_string()],
    );

    let res_untrusted = untrusted_proxy.get_namespace("alice-project").await;
    match res_untrusted {
        Err(ApiserverError::Unauthenticated { reason }) => {
            assert!(
                reason.contains("front-proxy client certificate rejected by request-header CA"),
                "Expected rejection by request-header CA, got: {reason}"
            );
        },
        other => panic!("Expected Unauthenticated error, got: {other:?}"),
    }

    // Case 3: Front-proxy client certificate signed by request-header-ca, but with unauthorized CN
    let unauthorized_name_cert =
        sign_client_cert_with_ca(&req_ca_crt, &req_ca_key, "unauthorized-proxy");
    let unauthorized_proxy = service.front_proxy_client(
        unauthorized_name_cert,
        "alice",
        vec!["system:authenticated".to_string()],
    );

    let res_unauthorized_name = unauthorized_proxy.get_namespace("alice-project").await;
    match res_unauthorized_name {
        Err(ApiserverError::Unauthenticated { reason }) => {
            assert!(
                reason.contains("not in allowed names"),
                "Expected allowed names check failure, got: {reason}"
            );
        },
        other => panic!("Expected Unauthenticated error, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_aggregated_api_service_routing_discovery_and_tls_trust() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();

    let (trusted_ca_pem, trusted_server_pem) = generate_custom_ca_and_server_cert("metrics.k8s.io");
    let trusted_ca_bundle = diorama_pki::base64_encode(trusted_ca_pem.as_bytes());

    let (untrusted_ca_pem, _) = generate_custom_ca_and_server_cert("metrics.k8s.io");
    let untrusted_ca_bundle = diorama_pki::base64_encode(untrusted_ca_pem.as_bytes());

    // Register APIService
    let api_service_doc = json!({
        "apiVersion": "apiregistration.k8s.io/v1",
        "kind": "APIService",
        "metadata": {
            "name": "v1beta1.metrics.k8s.io"
        },
        "spec": {
            "group": "metrics.k8s.io",
            "version": "v1beta1",
            "groupPriorityMinimum": 100,
            "versionPriority": 100,
            "caBundle": trusted_ca_bundle
        }
    });

    admin
        .create_api_service(api_service_doc)
        .await
        .expect("create APIService");

    // Register endpoint handler
    service.aggregation().register_endpoint(
        "v1beta1.metrics.k8s.io",
        Arc::new(MockMetricsAggregatedHandler),
        Some(trusted_server_pem.clone()),
    );

    // 1. Discovery includes aggregated APIService
    let apis = admin.discover_apis().expect("discover_apis succeeds");
    let groups = apis["groups"].as_array().expect("groups array");
    let has_metrics = groups.iter().any(|g| g["name"] == "metrics.k8s.io");
    assert!(
        has_metrics,
        "Aggregated group metrics.k8s.io must be in APIGroupList"
    );

    let resources = admin
        .discover_group_resources("metrics.k8s.io", "v1beta1")
        .expect("discover_group_resources for aggregated API succeeds");
    assert_eq!(resources["groupVersion"], "metrics.k8s.io/v1beta1");

    // 2. Dispatch request to aggregated API server succeeds
    let metrics_result = admin
        .dispatch_aggregated_request(
            "v1beta1.metrics.k8s.io",
            "/apis/metrics.k8s.io/v1beta1/nodes",
            "GET",
            None,
        )
        .await
        .expect("dispatch to aggregated API succeeds");
    assert_eq!(metrics_result["kind"], "NodeMetricsList");
    assert_eq!(metrics_result["items"][0]["metadata"]["name"], "node-1");
    assert_eq!(metrics_result["items"][0]["usage"]["cpu"], "150m");

    // 3. TLS verification failure when APIService caBundle does not trust server cert
    let untrusted_api_service = json!({
        "apiVersion": "apiregistration.k8s.io/v1",
        "kind": "APIService",
        "metadata": {
            "name": "v1beta1.untrusted.metrics.k8s.io"
        },
        "spec": {
            "group": "untrusted.metrics.k8s.io",
            "version": "v1beta1",
            "groupPriorityMinimum": 100,
            "versionPriority": 100,
            "caBundle": untrusted_ca_bundle
        }
    });
    admin
        .create_api_service(untrusted_api_service)
        .await
        .expect("create untrusted APIService");

    service.aggregation().register_endpoint(
        "v1beta1.untrusted.metrics.k8s.io",
        Arc::new(MockMetricsAggregatedHandler),
        Some(trusted_server_pem),
    );

    let untrusted_res = admin
        .dispatch_aggregated_request(
            "v1beta1.untrusted.metrics.k8s.io",
            "/apis/untrusted.metrics.k8s.io/v1beta1/nodes",
            "GET",
            None,
        )
        .await;

    match untrusted_res {
        Err(ApiserverError::InvalidCredentials { reason }) => {
            assert!(
                reason.contains("server TLS certificate rejected by caBundle trust"),
                "Expected caBundle trust rejection, got: {reason}"
            );
        },
        other => panic!("Expected InvalidCredentials error, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_aggregated_apiservice_persistence_and_restore() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();

    let doc = json!({
        "apiVersion": "apiregistration.k8s.io/v1",
        "kind": "APIService",
        "metadata": {
            "name": "v1alpha1.custom.metrics.k8s.io"
        },
        "spec": {
            "group": "custom.metrics.k8s.io",
            "version": "v1alpha1",
            "groupPriorityMinimum": 100,
            "versionPriority": 100
        }
    });

    admin
        .create_api_service(doc)
        .await
        .expect("create APIService");

    let fetched = admin
        .get_api_service("v1alpha1.custom.metrics.k8s.io")
        .await
        .expect("get APIService");
    assert_eq!(fetched["spec"]["group"], "custom.metrics.k8s.io");

    let list = admin.list_api_services().await.expect("list APIServices");
    assert_ne!(
        list["items"].as_array().unwrap().as_slice(),
        <[serde_json::Value; 0]>::default().as_slice()
    );

    // Drop service and admin to release lock
    drop(admin);
    drop(service);

    // Reopen and restore
    let (engine, _) =
        DatastoreEngine::open(DatastoreConfig::new(temp.path().join("datastore"))).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let restarted = ApiserverService::new(
        ApiserverConfig::default_for_pki(temp.path().join("pki"), node_ip),
        storage,
    );
    restarted.check_prerequisites().await.unwrap();

    let restarted_admin = restarted.admin_client();
    let restored = restarted_admin
        .get_api_service("v1alpha1.custom.metrics.k8s.io")
        .await
        .expect("get restored APIService");
    assert_eq!(restored["spec"]["group"], "custom.metrics.k8s.io");

    // Delete APIService
    restarted_admin
        .delete_api_service("v1alpha1.custom.metrics.k8s.io")
        .await
        .expect("delete APIService");
    assert!(
        restarted_admin
            .get_api_service("v1alpha1.custom.metrics.k8s.io")
            .await
            .is_err(),
        "APIService should be deleted"
    );
}
