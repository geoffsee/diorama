use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use tempfile::TempDir;

use async_trait::async_trait;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
use serde_json::{Value, json};

use diorama_apiserver::{
    AdmissionRequest, AdmissionResponse, ApiserverConfig, ApiserverError, ApiserverService,
    FailurePolicy, KubernetesStorage, MutatingWebhookConfiguration, RuleWithOperations,
    ValidatingWebhookConfiguration, WebhookClientConfig, WebhookDefinition, WebhookHandler,
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

fn generate_webhook_ca_and_server_cert(common_name: &str) -> (String, String) {
    let ca_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let mut ca_params = CertificateParams::new(vec!["webhook-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_pair).unwrap();

    let leaf_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let leaf_params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_pair).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_pair, &issuer).unwrap();

    (ca_cert.pem(), leaf_cert.pem())
}

struct MutatingPodInjector;

#[async_trait]
impl WebhookHandler for MutatingPodInjector {
    async fn handle(&self, req: &AdmissionRequest) -> Result<AdmissionResponse, ApiserverError> {
        // Mutate pod: inject label "injected-by": "mutating-webhook"
        let patch = json!([
            {
                "op": "add",
                "path": "/metadata/labels/injected-by",
                "value": "mutating-webhook"
            },
            {
                "op": "add",
                "path": "/metadata/annotations/sidecar-injected",
                "value": "true"
            }
        ]);
        let patch_bytes = serde_json::to_vec(&patch).map_err(|e| ApiserverError::Internal {
            reason: e.to_string(),
        })?;
        let patch_b64 = diorama_pki::base64_encode(&patch_bytes);

        Ok(AdmissionResponse {
            uid: req.uid.clone(),
            allowed: true,
            status: None,
            patch: Some(patch_b64),
            patch_type: Some("JSONPatch".to_string()),
        })
    }
}

struct ValidatingPodInspector {
    require_injected: bool,
}

#[async_trait]
impl WebhookHandler for ValidatingPodInspector {
    async fn handle(&self, req: &AdmissionRequest) -> Result<AdmissionResponse, ApiserverError> {
        if self.require_injected {
            // Verify that the mutating webhook already executed and injected the label
            let injected = req
                .object
                .as_ref()
                .and_then(|obj| obj.get("metadata"))
                .and_then(|m| m.get("labels"))
                .and_then(|l| l.get("injected-by"))
                .and_then(Value::as_str);

            if injected != Some("mutating-webhook") {
                return Ok(AdmissionResponse::deny(
                    req.uid.clone(),
                    403,
                    "Mutating webhook was not executed before validating webhook",
                ));
            }
        }

        // Check if pod has forbidden name
        let name = req
            .object
            .as_ref()
            .and_then(|obj| obj.get("metadata"))
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");

        if name.starts_with("forbidden-") {
            Ok(AdmissionResponse::deny(
                req.uid.clone(),
                403,
                format!("Pod name '{name}' is forbidden by policy"),
            ))
        } else {
            Ok(AdmissionResponse::allow(req.uid.clone()))
        }
    }
}

struct FailingWebhookHandler;

#[async_trait]
impl WebhookHandler for FailingWebhookHandler {
    async fn handle(&self, _req: &AdmissionRequest) -> Result<AdmissionResponse, ApiserverError> {
        Err(ApiserverError::WebhookFailure {
            webhook: "failing-backend".to_string(),
            reason: "Webhook backend is currently unavailable (503 Service Unavailable)"
                .to_string(),
        })
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_mutating_webhook_runs_before_validating_webhook_and_applies_patch() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();

    let (ca_pem, server_pem) = generate_webhook_ca_and_server_cert("mutating.webhook.local");
    let ca_bundle = diorama_pki::base64_encode(ca_pem.as_bytes());

    // Register webhook endpoints
    service.admission().register_webhook_endpoint(
        "mutator.example.com",
        Arc::new(MutatingPodInjector),
        Some(server_pem.clone()),
    );
    service.admission().register_webhook_endpoint(
        "validator.example.com",
        Arc::new(ValidatingPodInspector {
            require_injected: true,
        }),
        Some(server_pem),
    );

    // Register MutatingWebhookConfiguration
    let mutating_config = MutatingWebhookConfiguration {
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("name".to_string(), json!("inject-pod-sidecar"));
            m
        },
        webhooks: vec![WebhookDefinition {
            name: "mutator.example.com".to_string(),
            client_config: WebhookClientConfig {
                url: Some("https://mutating.webhook.local/mutate".to_string()),
                service: None,
                ca_bundle: Some(ca_bundle.clone()),
            },
            rules: vec![RuleWithOperations {
                operations: vec!["CREATE".to_string()],
                api_groups: vec![String::new()],
                api_versions: vec!["v1".to_string()],
                resources: vec!["pods".to_string()],
                scope: None,
            }],
            failure_policy: FailurePolicy::Fail,
            timeout_seconds: Some(10),
            admission_review_versions: vec!["v1".to_string()],
            side_effects: None,
            reinvocation_policy: None,
            ..Default::default()
        }],
    };
    service
        .admission()
        .add_mutating_webhook_config(mutating_config);

    // Register ValidatingWebhookConfiguration
    let validating_config = ValidatingWebhookConfiguration {
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("name".to_string(), json!("validate-pod"));
            m
        },
        webhooks: vec![WebhookDefinition {
            name: "validator.example.com".to_string(),
            client_config: WebhookClientConfig {
                url: Some("https://mutating.webhook.local/validate".to_string()),
                service: None,
                ca_bundle: Some(ca_bundle),
            },
            rules: vec![RuleWithOperations {
                operations: vec!["CREATE".to_string()],
                api_groups: vec![String::new()],
                api_versions: vec!["v1".to_string()],
                resources: vec!["pods".to_string()],
                scope: None,
            }],
            failure_policy: FailurePolicy::Fail,
            timeout_seconds: Some(10),
            admission_review_versions: vec!["v1".to_string()],
            side_effects: None,
            reinvocation_policy: None,
            ..Default::default()
        }],
    };
    service
        .admission()
        .add_validating_webhook_config(validating_config);

    // Create a pod without injected labels
    let pod_spec = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "app-server",
            "namespace": "default",
            "labels": {
                "app": "frontend"
            }
        },
        "spec": {
            "containers": [
                {
                    "name": "web",
                    "image": "nginx:alpine"
                }
            ]
        }
    });

    let created_pod = admin
        .create_pod("default", pod_spec)
        .await
        .expect("pod creation succeeds with mutating and validating admission");

    // Assert that the pod was mutated: labels and annotations injected
    assert_eq!(
        created_pod["metadata"]["labels"]["injected-by"], "mutating-webhook",
        "Mutating webhook injected label must be present in created pod"
    );
    assert_eq!(
        created_pod["metadata"]["annotations"]["sidecar-injected"], "true",
        "Mutating webhook injected annotation must be present"
    );
    assert_eq!(
        created_pod["metadata"]["labels"]["app"], "frontend",
        "Original labels must be preserved"
    );

    // Verify stored pod
    let stored_pod = admin
        .get_pod("default", "app-server")
        .await
        .expect("pod exists in storage");
    assert_eq!(
        stored_pod["metadata"]["labels"]["injected-by"],
        "mutating-webhook"
    );
}

#[tokio::test]
async fn test_validating_webhook_admission_denial() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();

    let (ca_pem, server_pem) = generate_webhook_ca_and_server_cert("policy.validator.local");
    let ca_bundle = diorama_pki::base64_encode(ca_pem.as_bytes());

    service.admission().register_webhook_endpoint(
        "policy.example.com",
        Arc::new(ValidatingPodInspector {
            require_injected: false,
        }),
        Some(server_pem),
    );

    let validating_config = ValidatingWebhookConfiguration {
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("name".to_string(), json!("pod-policy"));
            m
        },
        webhooks: vec![WebhookDefinition {
            name: "policy.example.com".to_string(),
            client_config: WebhookClientConfig {
                url: Some("https://policy.validator.local/validate".to_string()),
                service: None,
                ca_bundle: Some(ca_bundle),
            },
            rules: vec![RuleWithOperations {
                operations: vec!["CREATE".to_string()],
                api_groups: vec![String::new()],
                api_versions: vec!["v1".to_string()],
                resources: vec!["pods".to_string()],
                scope: None,
            }],
            failure_policy: FailurePolicy::Fail,
            timeout_seconds: Some(10),
            admission_review_versions: vec!["v1".to_string()],
            side_effects: None,
            reinvocation_policy: None,
            ..Default::default()
        }],
    };
    service
        .admission()
        .add_validating_webhook_config(validating_config);

    // Attempt to create a forbidden pod
    let forbidden_pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "forbidden-app",
            "namespace": "default"
        },
        "spec": {
            "containers": [{ "name": "c1", "image": "nginx" }]
        }
    });

    let res = admin.create_pod("default", forbidden_pod).await;
    match res {
        Err(ApiserverError::AdmissionDenied { reason }) => {
            assert!(
                reason.contains("forbidden by policy"),
                "Expected denial message, got: {reason}"
            );
        },
        other => panic!("Expected AdmissionDenied error, got: {other:?}"),
    }

    // Verify forbidden pod was NOT stored
    assert!(
        admin.get_pod("default", "forbidden-app").await.is_err(),
        "Denied pod must not exist in storage"
    );

    // Creating an allowed pod succeeds
    let allowed_pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "allowed-app",
            "namespace": "default"
        },
        "spec": {
            "containers": [{ "name": "c1", "image": "nginx" }]
        }
    });
    let ok_pod = admin
        .create_pod("default", allowed_pod)
        .await
        .expect("Allowed pod creation succeeds");
    assert_eq!(ok_pod["metadata"]["name"], "allowed-app");
}

#[tokio::test]
async fn test_webhook_failure_policy_fail_vs_ignore() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();

    let (ca_pem, server_pem) = generate_webhook_ca_and_server_cert("failing.webhook.local");
    let ca_bundle = diorama_pki::base64_encode(ca_pem.as_bytes());

    service.admission().register_webhook_endpoint(
        "failing.webhook.local",
        Arc::new(FailingWebhookHandler),
        Some(server_pem),
    );

    // Case 1: FailurePolicy::Fail
    let config_fail = ValidatingWebhookConfiguration {
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("name".to_string(), json!("fail-policy-webhook"));
            m
        },
        webhooks: vec![WebhookDefinition {
            name: "failing.fail.example.com".to_string(),
            client_config: WebhookClientConfig {
                url: Some("https://failing.webhook.local/check".to_string()),
                service: None,
                ca_bundle: Some(ca_bundle.clone()),
            },
            rules: vec![RuleWithOperations {
                operations: vec!["CREATE".to_string()],
                api_groups: vec![String::new()],
                api_versions: vec!["v1".to_string()],
                resources: vec!["pods".to_string()],
                scope: None,
            }],
            failure_policy: FailurePolicy::Fail,
            timeout_seconds: None,
            admission_review_versions: vec!["v1".to_string()],
            side_effects: None,
            reinvocation_policy: None,
            ..Default::default()
        }],
    };
    service
        .admission()
        .add_validating_webhook_config(config_fail);

    let pod_a = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "pod-fail-policy", "namespace": "default" },
        "spec": { "containers": [{ "name": "c", "image": "alpine" }] }
    });

    let res_fail = admin.create_pod("default", pod_a).await;
    match res_fail {
        Err(ApiserverError::WebhookFailure { reason, .. }) => assert!(
            reason.contains("503 Service Unavailable"),
            "expected handler failure, got: {reason}"
        ),
        other => panic!("expected WebhookFailure, got: {other:?}"),
    }

    // Case 2: FailurePolicy::Ignore
    let config_ignore = ValidatingWebhookConfiguration {
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("name".to_string(), json!("fail-policy-webhook"));
            m
        },
        webhooks: vec![WebhookDefinition {
            name: "failing.ignore.example.com".to_string(),
            client_config: WebhookClientConfig {
                url: Some("https://failing.webhook.local/check".to_string()),
                service: None,
                ca_bundle: Some(ca_bundle),
            },
            rules: vec![RuleWithOperations {
                operations: vec!["CREATE".to_string()],
                api_groups: vec![String::new()],
                api_versions: vec!["v1".to_string()],
                resources: vec!["pods".to_string()],
                scope: None,
            }],
            failure_policy: FailurePolicy::Ignore,
            timeout_seconds: None,
            admission_review_versions: vec!["v1".to_string()],
            side_effects: None,
            reinvocation_policy: None,
            ..Default::default()
        }],
    };
    service
        .admission()
        .add_validating_webhook_config(config_ignore);

    let pod_b = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "pod-ignore-policy", "namespace": "default" },
        "spec": { "containers": [{ "name": "c", "image": "alpine" }] }
    });

    let res_ignore = admin.create_pod("default", pod_b).await;
    assert!(
        res_ignore.is_ok(),
        "Webhook failure under FailurePolicy::Ignore must allow request to proceed"
    );
}

#[tokio::test]
async fn test_webhook_ca_bundle_verification() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();

    let (_trusted_ca_pem, trusted_server_pem) =
        generate_webhook_ca_and_server_cert("secure.webhook.local");

    let (untrusted_ca_pem, _) = generate_webhook_ca_and_server_cert("untrusted.webhook.local");
    let untrusted_ca_bundle = diorama_pki::base64_encode(untrusted_ca_pem.as_bytes());

    // Register endpoint with trusted server cert
    service.admission().register_webhook_endpoint(
        "verify.example.com",
        Arc::new(MutatingPodInjector),
        Some(trusted_server_pem),
    );

    // Webhook configuration supplies untrusted CA bundle
    let config = MutatingWebhookConfiguration {
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("name".to_string(), json!("ca-verify-test"));
            m
        },
        webhooks: vec![WebhookDefinition {
            name: "verify.example.com".to_string(),
            client_config: WebhookClientConfig {
                url: Some("https://secure.webhook.local/mutate".to_string()),
                service: None,
                ca_bundle: Some(untrusted_ca_bundle),
            },
            rules: vec![RuleWithOperations {
                operations: vec!["CREATE".to_string()],
                api_groups: vec![String::new()],
                api_versions: vec!["v1".to_string()],
                resources: vec!["pods".to_string()],
                scope: None,
            }],
            failure_policy: FailurePolicy::Fail,
            timeout_seconds: None,
            admission_review_versions: vec!["v1".to_string()],
            side_effects: None,
            reinvocation_policy: None,
            ..Default::default()
        }],
    };
    service.admission().add_mutating_webhook_config(config);

    let pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "pod-untrusted-ca", "namespace": "default" },
        "spec": { "containers": [{ "name": "c", "image": "alpine" }] }
    });

    let res = admin.create_pod("default", pod).await;
    match res {
        Err(ApiserverError::WebhookFailure { reason, .. }) => {
            assert!(
                reason.contains("TLS certificate chain verification failed"),
                "Expected TLS verification failure reason, got: {reason}"
            );
        },
        other => panic!("Expected WebhookFailure due to CA mismatch, got: {other:?}"),
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_crd_schema_validation_and_lifecycle() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();

    let crd = json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {
            "name": "databases.infra.example.com"
        },
        "spec": {
            "group": "infra.example.com",
            "names": {
                "plural": "databases",
                "singular": "database",
                "kind": "Database"
            },
            "scope": "Namespaced",
            "versions": [
                {
                    "name": "v1",
                    "served": true,
                    "storage": true,
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": {
                                "spec": {
                                    "type": "object",
                                    "required": ["engine", "replicas"],
                                    "properties": {
                                        "engine": {
                                            "type": "string",
                                            "enum": ["postgres", "mysql"]
                                        },
                                        "replicas": {
                                            "type": "integer",
                                            "minimum": 1.0,
                                            "maximum": 5.0
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            ]
        }
    });

    admin.create_crd(crd).await.expect("create CRD");

    // Case 1: Missing required field "replicas"
    let invalid_missing_field = json!({
        "apiVersion": "infra.example.com/v1",
        "kind": "Database",
        "metadata": { "name": "db-1", "namespace": "default" },
        "spec": {
            "engine": "postgres"
        }
    });
    let err_missing = admin
        .create_custom_resource(
            "infra.example.com",
            "databases",
            "default",
            "db-1",
            invalid_missing_field,
        )
        .await;
    assert!(
        matches!(err_missing, Err(ApiserverError::InvalidInput { .. })),
        "Resource missing required field must fail schema validation"
    );

    // Case 2: Value not in enum
    let invalid_enum = json!({
        "apiVersion": "infra.example.com/v1",
        "kind": "Database",
        "metadata": { "name": "db-2", "namespace": "default" },
        "spec": {
            "engine": "sqlite",
            "replicas": 1
        }
    });
    let err_enum = admin
        .create_custom_resource(
            "infra.example.com",
            "databases",
            "default",
            "db-2",
            invalid_enum,
        )
        .await;
    assert!(
        matches!(err_enum, Err(ApiserverError::InvalidInput { .. })),
        "Resource with invalid enum must fail schema validation"
    );

    // Case 3: Replicas exceeds maximum limit
    let invalid_max = json!({
        "apiVersion": "infra.example.com/v1",
        "kind": "Database",
        "metadata": { "name": "db-3", "namespace": "default" },
        "spec": {
            "engine": "postgres",
            "replicas": 10
        }
    });
    let err_max = admin
        .create_custom_resource(
            "infra.example.com",
            "databases",
            "default",
            "db-3",
            invalid_max,
        )
        .await;
    assert!(
        matches!(err_max, Err(ApiserverError::InvalidInput { .. })),
        "Resource exceeding maximum limit must fail schema validation"
    );

    // Case 4: Valid custom resource creation succeeds
    let valid_resource = json!({
        "apiVersion": "infra.example.com/v1",
        "kind": "Database",
        "metadata": { "name": "prod-db", "namespace": "default" },
        "spec": {
            "engine": "postgres",
            "replicas": 3
        }
    });
    let created = admin
        .create_custom_resource(
            "infra.example.com",
            "databases",
            "default",
            "prod-db",
            valid_resource,
        )
        .await
        .expect("Valid custom resource creation succeeds");
    assert_eq!(created["spec"]["engine"], "postgres");
    assert_eq!(created["spec"]["replicas"], 3);

    // Delete CRD cleans up instances
    admin
        .delete_crd("databases.infra.example.com")
        .await
        .expect("delete CRD");
    assert!(
        admin
            .get_custom_resource("infra.example.com", "databases", "default", "prod-db")
            .await
            .is_err(),
        "Custom resource instances must be cleaned up when CRD is deleted"
    );
}

#[tokio::test]
async fn test_webhook_configurations_crud_and_persistence() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();

    let mut_cfg = json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "MutatingWebhookConfiguration",
        "metadata": { "name": "persist-mutating" },
        "webhooks": [
            {
                "name": "mut.k8s.io",
                "clientConfig": { "url": "https://localhost:8443/mutate" },
                "rules": [{
                    "operations": ["CREATE"],
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "resources": ["pods"]
                }]
            }
        ]
    });

    let val_cfg = json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": { "name": "persist-validating" },
        "webhooks": [
            {
                "name": "val.k8s.io",
                "clientConfig": { "url": "https://localhost:8443/validate" },
                "rules": [{
                    "operations": ["CREATE"],
                    "apiGroups": [""],
                    "apiVersions": ["v1"],
                    "resources": ["pods"]
                }]
            }
        ]
    });

    admin
        .create_mutating_webhook_configuration(mut_cfg)
        .await
        .expect("create mutating webhook configuration");
    admin
        .create_validating_webhook_configuration(val_cfg)
        .await
        .expect("create validating webhook configuration");

    let fetched_mut = admin
        .get_mutating_webhook_configuration("persist-mutating")
        .await
        .expect("fetch mutating webhook config");
    assert_eq!(fetched_mut["metadata"]["name"], "persist-mutating");

    let fetched_val = admin
        .get_validating_webhook_configuration("persist-validating")
        .await
        .expect("fetch validating webhook config");
    assert_eq!(fetched_val["metadata"]["name"], "persist-validating");

    // Test persistence across restart
    drop(admin);
    drop(service);
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
    let restored_mut = restarted_admin
        .get_mutating_webhook_configuration("persist-mutating")
        .await
        .expect("restored mutating webhook config");
    assert_eq!(restored_mut["metadata"]["name"], "persist-mutating");
}
