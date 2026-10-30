use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use rustls::pki_types::pem::PemObject;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use diorama_apiserver::{ApiserverAdapter, ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};

struct TestEnv {
    service: ApiserverService,
    _dir: TempDir,
}

impl TestEnv {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let node_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let pki_dir = dir.path().join("pki");
        std::fs::create_dir_all(&pki_dir).unwrap();
        ClusterPki::new(ClusterPkiConfig::new(
            pki_dir.clone(),
            "test-node".to_string(),
            node_ip,
        ))
        .reconcile()
        .expect("pki reconcile");
        let config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
        let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(dir.path().join("datastore")))
            .expect("datastore engine");
        let storage = KubernetesStorage::new(engine.client(), "/registry");
        let service = ApiserverService::new(config, storage);
        Self { service, _dir: dir }
    }

    fn client(&self) -> diorama_apiserver::KubernetesApiClient {
        self.service.admin_client()
    }
}

struct TestServer {
    addr: std::net::SocketAddr,
    pki_dir: std::path::PathBuf,
    stop_handle: diorama_supervisor::StopHandle,
    join_handle: tokio::task::JoinHandle<diorama_supervisor::SupervisorReport>,
    _dir: TempDir,
}

impl TestServer {
    async fn start() -> Self {
        let dir = TempDir::new().unwrap();
        let node_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let pki_dir = dir.path().join("pki");
        std::fs::create_dir_all(&pki_dir).unwrap();
        ClusterPki::new(ClusterPkiConfig::new(
            pki_dir.clone(),
            "test-node".to_string(),
            node_ip,
        ))
        .reconcile()
        .expect("pki reconcile");

        let config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
        let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(dir.path().join("datastore")))
            .expect("datastore");
        let storage = KubernetesStorage::new(engine.client(), "/registry");
        let service = ApiserverService::new(config, storage);

        let reg = ApiserverAdapter::registration(
            "apiserver",
            service.clone(),
            Vec::new(),
            Duration::from_secs(10),
        );
        let supervisor = diorama_supervisor::Supervisor::new(vec![reg]).unwrap();
        let (stop_handle, stop_rx) = diorama_supervisor::stop_channel();
        let join_handle = tokio::spawn(async move { supervisor.run(stop_rx).await });
        let addr = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(addr) = service.bound_addr() {
                    return addr;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("server bound addr");

        Self {
            addr,
            pki_dir,
            stop_handle,
            join_handle,
            _dir: dir,
        }
    }

    async fn request_raw(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: &str,
    ) -> (u16, String) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut roots = RootCertStore::empty();
        let ca_bytes = std::fs::read(self.pki_dir.join("ca.crt")).unwrap();
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&ca_bytes) {
            roots.add(cert.unwrap()).unwrap();
        }
        let admin_cert_bytes = std::fs::read(self.pki_dir.join("admin.crt")).unwrap();
        let admin_certs = rustls::pki_types::CertificateDer::pem_slice_iter(&admin_cert_bytes)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let admin_key_bytes = std::fs::read(self.pki_dir.join("admin.key")).unwrap();
        let admin_key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&admin_key_bytes).unwrap();

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(admin_certs, admin_key)
            .unwrap();
        let connector = TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(self.addr).await.unwrap();
        let server_name = ServerName::try_from("127.0.0.1").unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();
        let ct = content_type.unwrap_or("application/json");
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: application/json\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tls.write_all(req.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).to_string();
        let status = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let body_start = text.find("\r\n\r\n").map_or(0, |i| i + 4);
        (status, text[body_start..].to_string())
    }

    async fn stop(self) {
        self.stop_handle.stop();
        let _ = self.join_handle.await;
    }
}

// ---------------------------------------------------------------------------
// Item 1: Ephemeral and Init Container Resolution
// ---------------------------------------------------------------------------
#[test]
fn container_resolution_finds_ephemeral_and_init_containers() {
    let pod = json!({
        "spec": {
            "containers": [{ "name": "main-worker" }],
            "initContainers": [{ "name": "setup-step" }],
            "ephemeralContainers": [{ "name": "debugger" }]
        }
    });

    let exec_opts =
        diorama_apiserver::PodExecOptions::from_query(Some("command=sh&container=setup-step"))
            .unwrap();
    assert_eq!(exec_opts.resolve_container(&pod).unwrap(), "setup-step");

    let exec_debug =
        diorama_apiserver::PodExecOptions::from_query(Some("command=sh&container=debugger"))
            .unwrap();
    assert_eq!(exec_debug.resolve_container(&pod).unwrap(), "debugger");

    let attach_opts =
        diorama_apiserver::exec::PodAttachOptions::from_query(Some("container=setup-step"));
    assert_eq!(attach_opts.resolve_container(&pod).unwrap(), "setup-step");
}

// ---------------------------------------------------------------------------
// Item 4: YAML Duplicate Key Error Message
// ---------------------------------------------------------------------------
#[tokio::test]
async fn yaml_duplicate_key_returns_detailed_strict_error() {
    let server = TestServer::start().await;
    let yaml_body = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm-dup\ndata:\n  key: val1\n  key: val2\n";
    let (status, resp) = server
        .request_raw(
            "POST",
            "/api/v1/namespaces/default/configmaps?fieldValidation=Strict",
            Some("application/yaml"),
            yaml_body,
        )
        .await;
    assert_eq!(status, 422);
    assert!(
        resp.contains("already set in map"),
        "expected duplicate key message in response: {resp}"
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// Item 7: Namespace /finalize Clearing Finalizers
// ---------------------------------------------------------------------------
#[tokio::test]
async fn namespace_finalize_clears_finalizers_when_omitted() {
    let env = TestEnv::new();
    let client = env.client();

    let ns = json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": "test-fin-ns"
        },
        "spec": {
            "finalizers": ["kubernetes"]
        }
    });
    client.create_namespace_object(ns).await.unwrap();

    let finalize_doc = json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": "test-fin-ns"
        },
        "spec": {}
    });
    let updated = client
        .update_namespace_finalize("test-fin-ns", finalize_doc)
        .await
        .unwrap();

    let finalizers = updated
        .pointer("/spec/finalizers")
        .and_then(Value::as_array);
    assert_eq!(finalizers, Some(&Vec::new()));
}

// ---------------------------------------------------------------------------
// Item 8: Immediate Endpoints & EndpointSlice Population
// ---------------------------------------------------------------------------
#[tokio::test]
async fn immediate_endpoints_and_slice_population_on_service_create() {
    let env = TestEnv::new();
    let client = env.client();

    let pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "backend-pod",
            "labels": { "app": "backend" }
        },
        "status": {
            "podIP": "10.244.0.42",
            "phase": "Running"
        }
    });
    client.create_pod("default", pod).await.unwrap();

    let svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "backend-svc"
        },
        "spec": {
            "selector": { "app": "backend" },
            "ports": [{
                "name": "http",
                "port": 8080,
                "protocol": "TCP"
            }]
        }
    });
    client.create_service("default", svc).await.unwrap();

    let endpoints = client
        .get_endpoints("default", "backend-svc")
        .await
        .unwrap();
    let addresses = endpoints
        .pointer("/subsets/0/addresses")
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(addresses[0]["ip"], "10.244.0.42");

    let slice = client
        .get_endpointslice("default", "backend-svc-1")
        .await
        .unwrap();
    let slice_endpoints = slice.get("endpoints").and_then(Value::as_array).unwrap();
    assert_eq!(slice_endpoints[0]["addresses"][0], "10.244.0.42");
    assert_eq!(slice_endpoints[0]["conditions"]["ready"], true);
}

// ---------------------------------------------------------------------------
// Item 6: Events API Unification & Normalization
// ---------------------------------------------------------------------------
#[tokio::test]
async fn events_api_unification_between_core_and_events_group() {
    let server = TestServer::start().await;

    let event_v1 = json!({
        "apiVersion": "events.k8s.io/v1",
        "kind": "Event",
        "metadata": {
            "name": "test-event-unify",
            "namespace": "default"
        },
        "regarding": {
            "kind": "Pod",
            "name": "some-pod",
            "namespace": "default"
        },
        "note": "Pod started successfully",
        "reason": "Started",
        "reportingController": "kubelet",
        "reportingInstance": "node-1",
        "type": "Normal",
        "eventTime": diorama_apiserver::time::now_rfc3339()
    });

    let (s, _) = server
        .request_raw(
            "POST",
            "/apis/events.k8s.io/v1/namespaces/default/events",
            None,
            &event_v1.to_string(),
        )
        .await;
    assert_eq!(s, 201);

    // Read back via core /api/v1/namespaces/default/events
    let (s_core, body_core) = server
        .request_raw(
            "GET",
            "/api/v1/namespaces/default/events/test-event-unify",
            None,
            "",
        )
        .await;
    assert_eq!(s_core, 200);
    let core_val: Value = serde_json::from_str(&body_core).unwrap();
    assert_eq!(core_val["apiVersion"], "v1");
    assert_eq!(core_val["message"], "Pod started successfully");
    assert_eq!(core_val["involvedObject"]["name"], "some-pod");
    assert_eq!(core_val["source"]["component"], "kubelet");

    // Read back via events.k8s.io
    let (s_ev, body_ev) = server
        .request_raw(
            "GET",
            "/apis/events.k8s.io/v1/namespaces/default/events/test-event-unify",
            None,
            "",
        )
        .await;
    assert_eq!(s_ev, 200);
    let ev_val: Value = serde_json::from_str(&body_ev).unwrap();
    assert_eq!(ev_val["apiVersion"], "events.k8s.io/v1");
    assert_eq!(ev_val["note"], "Pod started successfully");
    assert_eq!(ev_val["regarding"]["name"], "some-pod");
    assert_eq!(ev_val["reportingController"], "kubelet");

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Item 9: Multi-Owner Pod Preservation During Workload Cascade Deletion
// ---------------------------------------------------------------------------
async fn create_test_replicaset(server: &TestServer, name: &str, uid: &str) -> u16 {
    let rs = json!({
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": name,
            "uid": uid
        },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "tier": "shared" } },
            "template": {
                "metadata": { "labels": { "tier": "shared" } },
                "spec": { "containers": [{ "name": "app", "image": "nginx" }] }
            }
        }
    });
    let (s, _) = server
        .request_raw(
            "POST",
            "/apis/apps/v1/namespaces/default/replicasets",
            None,
            &rs.to_string(),
        )
        .await;
    s
}

#[tokio::test]
async fn multi_owner_pod_is_preserved_when_first_owner_deleted() {
    let server = TestServer::start().await;

    assert_eq!(
        create_test_replicaset(&server, "rs-primary", "rs-primary-uid-111").await,
        201
    );
    assert_eq!(
        create_test_replicaset(&server, "rs-secondary", "rs-secondary-uid-222").await,
        201
    );

    // Create a Pod owned by both RS-1 and RS-2
    let pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "multi-owned-pod",
            "ownerReferences": [
                {
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "name": "rs-primary",
                    "uid": "rs-primary-uid-111"
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "name": "rs-secondary",
                    "uid": "rs-secondary-uid-222"
                }
            ]
        },
        "spec": {
            "containers": [{ "name": "c", "image": "busybox" }]
        }
    });
    let (sp, _) = server
        .request_raw(
            "POST",
            "/api/v1/namespaces/default/pods",
            None,
            &pod.to_string(),
        )
        .await;
    assert_eq!(sp, 201);

    // Delete RS-1
    let (del_s, _) = server
        .request_raw(
            "DELETE",
            "/apis/apps/v1/namespaces/default/replicasets/rs-primary",
            None,
            "",
        )
        .await;
    assert_eq!(del_s, 200);

    // Verify Pod still exists because RS-2 is still live!
    let (s_pod, body_pod) = server
        .request_raw(
            "GET",
            "/api/v1/namespaces/default/pods/multi-owned-pod",
            None,
            "",
        )
        .await;
    assert_eq!(
        s_pod, 200,
        "Pod must be preserved because RS-2 is still live"
    );
    let pod_val: Value = serde_json::from_str(&body_pod).unwrap();
    let orefs = pod_val
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(orefs.len(), 1);
    assert_eq!(orefs[0]["name"], "rs-secondary");

    // Now delete RS-2
    let (del_s2, _) = server
        .request_raw(
            "DELETE",
            "/apis/apps/v1/namespaces/default/replicasets/rs-secondary",
            None,
            "",
        )
        .await;
    assert_eq!(del_s2, 200);

    // Pod should now be deleted because no live owners remain
    let (s_pod_gone, _) = server
        .request_raw(
            "GET",
            "/api/v1/namespaces/default/pods/multi-owned-pod",
            None,
            "",
        )
        .await;
    assert_eq!(
        s_pod_gone, 404,
        "Pod should be cascade deleted once all owners are gone"
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Item 3: Admission Webhook Timeout Error Format
// ---------------------------------------------------------------------------
#[tokio::test]
async fn webhook_timeout_error_matches_k8s_context_deadline_exceeded() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        }
    });

    let ca_pair =
        rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
            .unwrap();
    let mut ca_params =
        rcgen::CertificateParams::new(vec!["timeout.webhook.local".to_string()]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_pair).unwrap();
    let ca_bundle = diorama_pki::base64_encode(ca_cert.pem().as_bytes());

    let env = TestEnv::new();
    let client = env.client();
    let webhook_cfg = diorama_apiserver::MutatingWebhookConfiguration {
        metadata: {
            let mut m = std::collections::BTreeMap::new();
            m.insert("name".to_string(), json!("timeout-hook"));
            m
        },
        webhooks: vec![diorama_apiserver::WebhookDefinition {
            name: "timeout.webhook.local".to_string(),
            client_config: diorama_apiserver::WebhookClientConfig {
                url: Some(format!("https://127.0.0.1:{port}/mutate")),
                service: None,
                ca_bundle: Some(ca_bundle),
            },
            rules: vec![diorama_apiserver::RuleWithOperations {
                operations: vec!["CREATE".to_string()],
                api_groups: vec![String::new()],
                api_versions: vec!["v1".to_string()],
                resources: vec!["pods".to_string()],
                scope: None,
            }],
            failure_policy: diorama_apiserver::FailurePolicy::Fail,
            timeout_seconds: Some(1),
            admission_review_versions: vec!["v1".to_string()],
            ..Default::default()
        }],
    };
    env.service
        .admission()
        .add_mutating_webhook_config(webhook_cfg);

    let pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "timeout-test-pod", "namespace": "default" },
        "spec": { "containers": [{ "name": "c", "image": "alpine" }] }
    });

    let res = client.create_pod("default", pod).await;
    match res {
        Err(diorama_apiserver::ApiserverError::WebhookFailure { reason, .. }) => {
            assert!(
                reason.contains("context deadline exceeded")
                    || reason.contains("Client.Timeout exceeded")
                    || reason.contains("timeout=1s"),
                "expected context deadline exceeded in reason: {reason}"
            );
        },
        other => panic!("expected WebhookFailure timeout, got: {other:?}"),
    }
}
