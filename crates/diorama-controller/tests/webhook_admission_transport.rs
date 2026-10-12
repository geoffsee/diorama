#![allow(clippy::too_many_lines)]

use std::net::IpAddr;
use std::sync::Arc;
use tempfile::TempDir;

use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_controller::webhook::{
    DEFAULT_WEBHOOK_NAME, HttpResponse, NodeSetterHandler, WebhookAdapter, WebhookConfig,
    WebhookError, WebhookService,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_supervisor::{StopCause, Supervisor, stop_channel};
use serde_json::json;

fn setup_test_environment(
    dir: &TempDir,
) -> (Arc<ApiserverService>, WebhookConfig, std::path::PathBuf) {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");

    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_service = ApiserverService::new(apiserver_config, storage);

    let webhook_config = WebhookConfig::default_for_pki(&pki_dir, "test-node", "192.0.2.9", true);

    (Arc::new(apiserver_service), webhook_config, pki_dir)
}

#[tokio::test]
async fn test_webhook_configuration_generation_and_pki_trust() {
    let temp = TempDir::new().unwrap();
    let (_apiserver, webhook_config, pki_dir) = setup_test_environment(&temp);

    // 1. Valid configuration with LoadBalancer enabled
    let config = webhook_config.create_configuration().unwrap();
    assert_eq!(
        config.metadata.get("name").unwrap(),
        &json!(DEFAULT_WEBHOOK_NAME)
    );
    assert_eq!(config.webhooks.len(), 1);
    let wh = &config.webhooks[0];
    assert_eq!(wh.name, DEFAULT_WEBHOOK_NAME);
    assert_eq!(
        wh.client_config.url.as_deref(),
        Some("https://127.0.0.1:10443/mutate")
    );
    assert!(wh.client_config.ca_bundle.is_some());
    assert_eq!(wh.rules.len(), 2);
    assert_eq!(wh.rules[0].operations, vec!["CREATE"]);
    assert_eq!(
        wh.rules[0].resources,
        vec!["pods", "persistentvolumeclaims", "jobs"]
    );
    assert_eq!(wh.rules[1].operations, vec!["CREATE", "UPDATE"]);
    assert_eq!(wh.rules[1].resources, vec!["services"]);
    assert_eq!(wh.side_effects.as_deref(), Some("NoneOnDryRun"));
    assert_eq!(wh.reinvocation_policy.as_deref(), Some("IfNeeded"));

    // 2. Configuration with LoadBalancer disabled
    let mut config_disabled = webhook_config.clone();
    config_disabled.load_balancer = false;
    let wh_disabled = config_disabled.create_configuration().unwrap();
    assert_eq!(wh_disabled.webhooks[0].rules.len(), 1);

    // 3. Missing certificate fails with MissingCredential
    let mut config_missing = webhook_config.clone();
    config_missing.pki_path = pki_dir.join("nonexistent");
    config_missing.cert_file = pki_dir.join("nonexistent/webhook.crt");
    config_missing.ca_file = pki_dir.join("nonexistent/ca.crt");
    let err = config_missing.create_configuration().unwrap_err();
    assert!(matches!(err, WebhookError::MissingCredential { .. }));
}

#[tokio::test]
async fn test_handler_protocol_correctness_and_parity_cases() {
    let handler = NodeSetterHandler::new("test-node", "192.0.2.9", true);

    // Case 1: Unassigned Pod receives nodeName patch
    let unassigned_pod_req = json!({
        "uid": "req-pod-1",
        "kind": { "group": "", "version": "v1", "kind": "Pod" },
        "operation": "CREATE",
        "object": {
            "metadata": { "name": "web" },
            "spec": {}
        }
    });
    let (patch1, scheduled1) = handler
        .evaluate_mutation(&unassigned_pod_req)
        .await
        .unwrap();
    assert!(!scheduled1);
    let patch_json1: serde_json::Value =
        serde_json::from_slice(&diorama_pki::base64_decode(&patch1.unwrap()).unwrap()).unwrap();
    assert_eq!(
        patch_json1,
        json!([{"op": "add", "path": "/spec/nodeName", "value": "test-node"}])
    );

    // Case 2: Already assigned Pod receives no patch
    let assigned_pod_req = json!({
        "uid": "req-pod-2",
        "kind": { "group": "", "version": "v1", "kind": "Pod" },
        "operation": "CREATE",
        "object": {
            "spec": { "nodeName": "other-node" }
        }
    });
    let (patch2, _) = handler.evaluate_mutation(&assigned_pod_req).await.unwrap();
    assert!(patch2.is_none());

    // Case 3: Pod direct UPDATE still receives nodeName patch if unassigned
    let update_pod_req = json!({
        "uid": "req-pod-3",
        "kind": { "group": "", "version": "v1", "kind": "Pod" },
        "operation": "UPDATE",
        "object": { "spec": {} }
    });
    let (patch3, _) = handler.evaluate_mutation(&update_pod_req).await.unwrap();
    assert!(patch3.is_some());

    // Case 4: PVC empty receives selected-node annotation patch
    let pvc_empty_req = json!({
        "uid": "req-pvc-1",
        "kind": { "group": "", "version": "v1", "kind": "PersistentVolumeClaim" },
        "operation": "CREATE",
        "object": { "metadata": {} }
    });
    let (patch4, _) = handler.evaluate_mutation(&pvc_empty_req).await.unwrap();
    let patch_json4: serde_json::Value =
        serde_json::from_slice(&diorama_pki::base64_decode(&patch4.unwrap()).unwrap()).unwrap();
    assert_eq!(
        patch_json4,
        json!([{"op": "add", "path": "/metadata/annotations", "value": {"volume.kubernetes.io/selected-node": "test-node"}}])
    );

    // Case 5: PVC already assigned receives no patch
    let pvc_assigned_req = json!({
        "uid": "req-pvc-2",
        "kind": { "group": "", "version": "v1", "kind": "PersistentVolumeClaim" },
        "operation": "CREATE",
        "object": {
            "metadata": {
                "annotations": {
                    "volume.kubernetes.io/selected-node": "other-node"
                }
            }
        }
    });
    let (patch5, _) = handler.evaluate_mutation(&pvc_assigned_req).await.unwrap();
    assert!(patch5.is_none());

    // Case 6: Job empty receives nodeSelector hostname patch
    let job_empty_req = json!({
        "uid": "req-job-1",
        "kind": { "group": "batch", "version": "v1", "kind": "Job" },
        "operation": "CREATE",
        "object": {
            "spec": { "template": { "spec": {} } }
        }
    });
    let (patch6, _) = handler.evaluate_mutation(&job_empty_req).await.unwrap();
    let patch_json6: serde_json::Value =
        serde_json::from_slice(&diorama_pki::base64_decode(&patch6.unwrap()).unwrap()).unwrap();
    assert_eq!(
        patch_json6,
        json!([{"op": "add", "path": "/spec/template/spec/nodeSelector", "value": {"kubernetes.io/hostname": "test-node"}}])
    );

    // Case 7: Job existing selector receives no patch if hostname is present
    let job_assigned_req = json!({
        "uid": "req-job-2",
        "kind": { "group": "batch", "version": "v1", "kind": "Job" },
        "operation": "CREATE",
        "object": {
            "spec": {
                "template": {
                    "spec": {
                        "nodeSelector": {
                            "kubernetes.io/hostname": "other-node"
                        }
                    }
                }
            }
        }
    });
    let (patch7, _) = handler.evaluate_mutation(&job_assigned_req).await.unwrap();
    assert!(patch7.is_none());

    // Case 8: Unknown kind receives no patch
    let unknown_req = json!({
        "uid": "req-unk",
        "kind": { "group": "custom.io", "version": "v1", "kind": "CustomResource" },
        "operation": "CREATE",
        "object": {}
    });
    let (patch8, _) = handler.evaluate_mutation(&unknown_req).await.unwrap();
    assert!(patch8.is_none());

    // Case 9: Malformed typed object (spec is string) receives no patch
    let malformed_pod = json!({
        "uid": "req-malformed",
        "kind": { "group": "", "version": "v1", "kind": "Pod" },
        "operation": "CREATE",
        "object": { "spec": "invalid" }
    });
    let (patch9, _) = handler.evaluate_mutation(&malformed_pod).await.unwrap();
    assert!(patch9.is_none());

    // Case 10: Service LoadBalancer triggers status update scheduling under lock
    let svc_req = json!({
        "uid": "req-svc-1",
        "kind": { "group": "", "version": "v1", "kind": "Service" },
        "operation": "CREATE",
        "dryRun": false,
        "object": {
            "metadata": { "name": "my-lb", "namespace": "default" },
            "spec": { "type": "LoadBalancer" }
        }
    });
    let (patch10, scheduled10) = handler.evaluate_mutation(&svc_req).await.unwrap();
    assert!(patch10.is_none());
    assert!(scheduled10);

    // Duplicate event while lock is held skips scheduling
    let (_, scheduled_dup) = handler.evaluate_mutation(&svc_req).await.unwrap();
    assert!(!scheduled_dup);

    // Dry-run Service never schedules status update
    let svc_dry_req = json!({
        "uid": "req-svc-dry",
        "kind": { "group": "", "version": "v1", "kind": "Service" },
        "operation": "CREATE",
        "dryRun": true,
        "object": {
            "metadata": { "name": "my-dry", "namespace": "default" },
            "spec": { "type": "LoadBalancer" }
        }
    });
    let (_, scheduled_dry) = handler.evaluate_mutation(&svc_dry_req).await.unwrap();
    assert!(!scheduled_dry);
}

#[tokio::test]
async fn test_http_transport_status_codes_and_errors() {
    let handler = NodeSetterHandler::new("test-node", "192.0.2.9", true);

    // 1. Healthz probe
    let resp = handler.handle_http_request("GET", "/healthz", b"").await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"ok\n");

    // 2. Readyz probe
    let resp = handler.handle_http_request("GET", "/readyz", b"").await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"ok\n");

    // 3. Method Not Allowed (GET on /mutate)
    let resp = handler.handle_http_request("GET", "/mutate", b"{}").await;
    assert_eq!(resp.status, 405);
    assert_eq!(resp.body, b"method not allowed\n");

    // 4. Not Found
    let resp = handler.handle_http_request("POST", "/other", b"{}").await;
    assert_eq!(resp.status, 404);

    // 5. Malformed JSON Body -> 400 Bad Request
    let resp = handler.handle_http_request("POST", "/mutate", b"{").await;
    assert_eq!(resp.status, 400);
    assert!(resp.body.starts_with(b"error decoding admission review"));

    // 6. Missing Request in AdmissionReview -> 400 Bad Request
    let review_no_req = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview"
    });
    let resp = handler
        .handle_http_request(
            "POST",
            "/mutate",
            &serde_json::to_vec(&review_no_req).unwrap(),
        )
        .await;
    assert_eq!(resp.status, 400);
    assert_eq!(resp.body, b"admission review with no request\n");

    // 7. Valid AdmissionReview -> 200 OK with correct JSON envelope
    let valid_review = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "rev-uid-123",
            "kind": { "group": "", "version": "v1", "kind": "Pod" },
            "operation": "CREATE",
            "object": {
                "metadata": { "name": "pod-1" },
                "spec": {}
            }
        }
    });
    let resp = handler
        .handle_http_request(
            "POST",
            "/mutate",
            &serde_json::to_vec(&valid_review).unwrap(),
        )
        .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.content_type, "application/json");

    let resp_val: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(resp_val["apiVersion"], "admission.k8s.io/v1");
    assert_eq!(resp_val["kind"], "AdmissionReview");
    assert_eq!(resp_val["response"]["uid"], "rev-uid-123");
    assert_eq!(resp_val["response"]["allowed"], true);
    assert_eq!(resp_val["response"]["patchType"], "JSONPatch");
    assert!(resp_val["response"]["patch"].is_string());
}

#[tokio::test]
async fn test_webhook_service_lifecycle_and_live_api_admission() {
    let temp = TempDir::new().unwrap();
    let (apiserver, mut webhook_config, _pki_dir) = setup_test_environment(&temp);

    // Use ephemeral port 0 for test network isolation
    webhook_config.port = 0;

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    let webhook_service = WebhookService::new(webhook_config, apiserver.clone());
    webhook_service.check_prerequisites().await.unwrap();
    webhook_service.start().await.unwrap();
    assert!(webhook_service.is_running());

    let readiness = webhook_service.check_readiness().await.unwrap();
    assert!(readiness.is_healthy);

    let admin = apiserver.admin_client();

    // Verify registration on API server
    let registered_cfg = admin
        .get_mutating_webhook_configuration(DEFAULT_WEBHOOK_NAME)
        .await
        .unwrap();
    assert_eq!(registered_cfg["metadata"]["name"], DEFAULT_WEBHOOK_NAME);

    // 1. Submit unassigned Pod to Apiserver and verify it is mutated to nodeName: test-node
    let pod_spec = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "auto-scheduled-pod",
            "namespace": "default"
        },
        "spec": {
            "containers": [
                {
                    "name": "nginx",
                    "image": "docker.io/library/nginx:1.27"
                }
            ]
        }
    });
    let created_pod = admin.create_pod("default", pod_spec).await.unwrap();
    assert_eq!(created_pod["spec"]["nodeName"], "test-node");

    // 2. Submit unassigned PVC and verify it is mutated with volume.kubernetes.io/selected-node annotation
    let pvc_spec = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": "auto-scheduled-pvc",
            "namespace": "default"
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {
                "requests": {
                    "storage": "1Gi"
                }
            }
        }
    });
    let created_pvc = admin.create_pvc("default", pvc_spec).await.unwrap();
    assert_eq!(
        created_pvc["metadata"]["annotations"]["volume.kubernetes.io/selected-node"],
        "test-node"
    );

    // 3. Submit unassigned Job and verify it is mutated with kubernetes.io/hostname selector
    let job_spec = json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "auto-scheduled-job",
            "namespace": "default"
        },
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "task",
                            "image": "docker.io/library/busybox:1.36"
                        }
                    ],
                    "restartPolicy": "Never"
                }
            }
        }
    });
    let created_job = admin.create_job("default", job_spec).await.unwrap();
    assert_eq!(
        created_job["spec"]["template"]["spec"]["nodeSelector"]["kubernetes.io/hostname"],
        "test-node"
    );

    // 4. Test shutdown
    webhook_service.stop().await;
    assert!(!webhook_service.is_running());

    let unready = webhook_service.check_readiness().await.unwrap();
    assert!(!unready.is_healthy);
}

#[tokio::test]
async fn test_concurrency_and_shutdown_safety() {
    let handler = Arc::new(NodeSetterHandler::new("test-node", "192.0.2.9", true));
    let mut join_handles = Vec::new();

    // Spawn 50 concurrent requests simultaneously across threads
    for i in 0..50 {
        let h = handler.clone();
        join_handles.push(tokio::spawn(async move {
            let req = json!({
                "uid": format!("concurrent-uid-{i}"),
                "kind": { "group": "", "version": "v1", "kind": "Pod" },
                "operation": "CREATE",
                "object": {
                    "metadata": { "name": format!("concurrent-pod-{i}") },
                    "spec": {}
                }
            });
            let body = serde_json::to_vec(&json!({
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "request": req
            }))
            .unwrap();

            let resp: HttpResponse = h.handle_http_request("POST", "/mutate", &body).await;
            assert_eq!(resp.status, 200);
            assert_eq!(resp.content_type, "application/json");

            let parsed: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
            assert_eq!(parsed["response"]["allowed"], true);
            assert!(parsed["response"]["patch"].is_string());
        }));
    }

    for handle in join_handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_supervisor_adapter_lifecycle() {
    let temp = TempDir::new().unwrap();
    let (apiserver, mut webhook_config, _pki_dir) = setup_test_environment(&temp);
    webhook_config.port = 0;

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    let webhook_service = Arc::new(WebhookService::new(webhook_config, apiserver));

    let reg = WebhookAdapter::registration(
        "webhook",
        webhook_service.clone(),
        Vec::new(),
        std::time::Duration::from_secs(5),
    );

    let supervisor = Supervisor::new(vec![reg]).expect("supervisor creation");
    let (stop_handle, stop_receiver) = stop_channel();
    let sup_handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });

    // Wait until webhook service becomes running
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !webhook_service.is_running() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(webhook_service.is_running());

    // Stop service
    stop_handle.stop();
    let report = sup_handle.await.expect("supervisor task joins");
    assert!(matches!(report.cause, StopCause::Requested));
    assert!(!webhook_service.is_running());
}
