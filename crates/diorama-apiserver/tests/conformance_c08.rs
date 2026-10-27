use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use diorama_apiserver::{ApiserverAdapter, ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};

fn setup_pki(dir: &TempDir) -> (ApiserverConfig, std::path::PathBuf) {
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
    (ApiserverConfig::default_for_pki(&pki_dir, node_ip), pki_dir)
}

fn setup_storage(dir: &TempDir) -> KubernetesStorage {
    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(dir.path().join("datastore")))
        .expect("datastore");
    KubernetesStorage::new(engine.client(), "/registry")
}

fn load_certs(path: &std::path::Path) -> Vec<CertificateDer<'static>> {
    let bytes = std::fs::read(path).unwrap();
    CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn load_key(path: &std::path::Path) -> PrivateKeyDer<'static> {
    let bytes = std::fs::read(path).unwrap();
    PrivateKeyDer::from_pem_slice(&bytes).unwrap()
}

async fn tls_request(
    addr: std::net::SocketAddr,
    pki: &std::path::Path,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: &str,
) -> (u16, String) {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(&pki.join("ca.crt")) {
        roots.add(cert).unwrap();
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            load_certs(&pki.join("admin.crt")),
            load_key(&pki.join("admin.key")),
        )
        .unwrap();
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await.unwrap();
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
    let text = String::from_utf8(response).unwrap();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body_start = text.find("\r\n\r\n").map_or(0, |i| i + 4);
    (status, text[body_start..].to_string())
}

fn parse_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::Null)
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
        let (config, pki_dir) = setup_pki(&dir);
        let service = ApiserverService::new(config, setup_storage(&dir));
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

    async fn request(&self, method: &str, path: &str, body: &str) -> (u16, Value) {
        let (status, text) = tls_request(self.addr, &self.pki_dir, method, path, None, body).await;
        (status, parse_json(&text))
    }

    async fn stop(self) {
        self.stop_handle.stop();
        let _ = self.join_handle.await;
    }
}

#[tokio::test]
async fn conformance_token_request_and_token_review() {
    let server = TestServer::start().await;

    // Create namespace
    let (s, _) = server
        .request(
            "POST",
            "/api/v1/namespaces",
            r#"{"metadata":{"name":"auth-test"}}"#,
        )
        .await;
    assert_eq!(s, 201);

    // Issue TokenRequest for default SA
    let tr_body = json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": {
            "audiences": ["https://kubernetes.default.svc"],
            "expirationSeconds": 3600
        }
    });
    let (s, tr_resp) = server
        .request(
            "POST",
            "/api/v1/namespaces/auth-test/serviceaccounts/default/token",
            &tr_body.to_string(),
        )
        .await;
    assert_eq!(s, 201);
    assert_eq!(tr_resp["kind"], "TokenRequest");
    let token = tr_resp["status"]["token"].as_str().expect("issued token");
    assert_ne!(token, "");
    assert!(tr_resp["status"]["expirationTimestamp"].is_string());

    // Validate token via TokenReview endpoint
    let review_body = json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "spec": {
            "token": token,
            "audiences": ["https://kubernetes.default.svc"]
        }
    });
    let (s, review_resp) = server
        .request(
            "POST",
            "/apis/authentication.k8s.io/v1/tokenreviews",
            &review_body.to_string(),
        )
        .await;
    assert_eq!(s, 201);
    assert_eq!(review_resp["status"]["authenticated"], true);
    let username = review_resp["status"]["user"]["username"]
        .as_str()
        .unwrap_or("");
    assert!(username.contains("system:serviceaccount:auth-test:default"));

    server.stop().await;
}

#[tokio::test]
async fn conformance_subject_reviews() {
    let server = TestServer::start().await;

    // SelfSubjectReview
    let self_review_payload = json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "SelfSubjectReview"
    });
    let (s, self_review_result) = server
        .request(
            "POST",
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            &self_review_payload.to_string(),
        )
        .await;
    assert_eq!(s, 201);
    let username = self_review_result["status"]["userInfo"]["username"]
        .as_str()
        .unwrap_or("");
    assert_ne!(username, "");
    let groups = self_review_result["status"]["userInfo"]["groups"]
        .as_array()
        .unwrap();
    assert!(groups.iter().any(|g| g == "system:masters"));

    // SubjectAccessReview
    let access_review_payload = json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SubjectAccessReview",
        "spec": {
            "resourceAttributes": {
                "namespace": "default",
                "verb": "get",
                "resource": "pods"
            }
        }
    });
    let (s, access_review_result) = server
        .request(
            "POST",
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            &access_review_payload.to_string(),
        )
        .await;
    assert_eq!(s, 201);
    assert_eq!(access_review_result["status"]["allowed"], true);

    // SelfSubjectRulesReview
    let rules_review_payload = json!({
        "apiVersion": "authorization.k8s.io/v1",
        "kind": "SelfSubjectRulesReview",
        "spec": {
            "namespace": "default"
        }
    });
    let (s, rules_review_result) = server
        .request(
            "POST",
            "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
            &rules_review_payload.to_string(),
        )
        .await;
    assert_eq!(s, 201);
    assert_eq!(rules_review_result["kind"], "SelfSubjectRulesReview");
    assert_ne!(
        rules_review_result["status"]["resourceRules"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    server.stop().await;
}

#[tokio::test]
async fn conformance_priority_class_immutability() {
    let server = TestServer::start().await;

    let pc = json!({
        "apiVersion": "scheduling.k8s.io/v1",
        "kind": "PriorityClass",
        "metadata": { "name": "high-prio" },
        "value": 1000
    });
    let (s, created) = server
        .request(
            "POST",
            "/apis/scheduling.k8s.io/v1/priorityclasses",
            &pc.to_string(),
        )
        .await;
    assert_eq!(s, 201);
    assert_eq!(created["preemptionPolicy"], "PreemptLowerPriority");

    // Attempt to update value: must return 422 Unprocessable Entity
    let mut updated_val = created.clone();
    updated_val["value"] = json!(2000);
    let (s, resp) = server
        .request(
            "PUT",
            "/apis/scheduling.k8s.io/v1/priorityclasses/high-prio",
            &updated_val.to_string(),
        )
        .await;
    assert_eq!(s, 422, "PriorityClass value must be immutable");
    assert_eq!(resp["reason"], "Invalid");

    // Attempt to update preemptionPolicy: must return 422 Unprocessable Entity
    let mut updated_policy = created.clone();
    updated_policy["preemptionPolicy"] = json!("Never");
    let (s, resp2) = server
        .request(
            "PUT",
            "/apis/scheduling.k8s.io/v1/priorityclasses/high-prio",
            &updated_policy.to_string(),
        )
        .await;
    assert_eq!(s, 422, "PriorityClass preemptionPolicy must be immutable");
    assert_eq!(resp2["reason"], "Invalid");

    server.stop().await;
}

#[tokio::test]
async fn conformance_validating_admission_policy_generation() {
    let server = TestServer::start().await;

    let vap = json!({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": { "name": "test-vap" },
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "resourceRules": [
                    {
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE"],
                        "resources": ["pods"]
                    }
                ]
            },
            "validations": [
                {
                    "expression": "object.metadata.name != 'forbidden'"
                }
            ]
        }
    });
    let (s, created) = server
        .request(
            "POST",
            "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies",
            &vap.to_string(),
        )
        .await;
    assert_eq!(s, 201);
    assert_eq!(created["metadata"]["generation"], 1);
    assert_eq!(created["status"]["observedGeneration"], 1);

    // Update spec -> generation becomes 2
    let mut updated = created.clone();
    updated["spec"]["failurePolicy"] = json!("Ignore");
    let (s, updated_resp) = server
        .request(
            "PUT",
            "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/test-vap",
            &updated.to_string(),
        )
        .await;
    assert_eq!(s, 200);
    assert_eq!(updated_resp["metadata"]["generation"], 2);
    assert_eq!(updated_resp["status"]["observedGeneration"], 2);

    server.stop().await;
}

#[tokio::test]
async fn conformance_limit_range_defaulting() {
    let server = TestServer::start().await;

    // Create namespace
    let (s, _) = server
        .request(
            "POST",
            "/api/v1/namespaces",
            r#"{"metadata":{"name":"lr-test"}}"#,
        )
        .await;
    assert_eq!(s, 201);

    // Create LimitRange
    let lr = json!({
        "apiVersion": "v1",
        "kind": "LimitRange",
        "metadata": { "name": "limits" },
        "spec": {
            "limits": [
                {
                    "type": "Container",
                    "default": { "cpu": "400m", "memory": "256Mi" },
                    "defaultRequest": { "cpu": "200m", "memory": "128Mi" }
                }
            ]
        }
    });
    let (s, _) = server
        .request(
            "POST",
            "/api/v1/namespaces/lr-test/limitranges",
            &lr.to_string(),
        )
        .await;
    assert_eq!(s, 201);

    // Create Pod without resources or volumes
    let pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "workload" },
        "spec": {
            "containers": [
                { "name": "main", "image": "registry.k8s.io/pause:3.9" }
            ]
        }
    });
    let (s, created_pod) = server
        .request("POST", "/api/v1/namespaces/lr-test/pods", &pod.to_string())
        .await;
    assert_eq!(s, 201);

    // Verify limit range defaults applied
    let c = &created_pod["spec"]["containers"][0];
    assert_eq!(c["resources"]["limits"]["cpu"], "400m");
    assert_eq!(c["resources"]["limits"]["memory"], "256Mi");
    assert_eq!(c["resources"]["requests"]["cpu"], "200m");
    assert_eq!(c["resources"]["requests"]["memory"], "128Mi");

    server.stop().await;
}

#[tokio::test]
async fn conformance_apis_discovery_groups() {
    let server = TestServer::start().await;

    let (s, apis_resp) = server.request("GET", "/apis", "").await;
    assert_eq!(s, 200);
    let groups = apis_resp["groups"].as_array().expect("apis groups");
    let group_names: Vec<&str> = groups.iter().filter_map(|g| g["name"].as_str()).collect();
    assert!(group_names.contains(&"authentication.k8s.io"));
    assert!(group_names.contains(&"authorization.k8s.io"));
    assert!(group_names.contains(&"flowcontrol.apiserver.k8s.io"));
    assert!(group_names.contains(&"scheduling.k8s.io"));
    assert!(group_names.contains(&"admissionregistration.k8s.io"));

    server.stop().await;
}

#[tokio::test]
async fn conformance_csr_approval_preserves_spec() {
    let server = TestServer::start().await;

    let csr = json!({
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": { "name": "my-csr" },
        "spec": {
            "request": "dGVzdC1yZXF1ZXN0",
            "signerName": "example.com/signer",
            "usages": ["digital signature"]
        }
    });
    let (s, created) = server
        .request(
            "POST",
            "/apis/certificates.k8s.io/v1/certificatesigningrequests",
            &csr.to_string(),
        )
        .await;
    assert_eq!(s, 201);
    assert_eq!(created["spec"]["signerName"], "example.com/signer");

    // Approve the CSR via /approval subresource
    let approval = json!({
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": { "name": "my-csr" },
        "status": {
            "conditions": [
                {
                    "type": "Approved",
                    "status": "True",
                    "reason": "ApprovedForTesting",
                    "message": "Approved by test"
                }
            ]
        }
    });
    let (s, approved) = server
        .request(
            "PUT",
            "/apis/certificates.k8s.io/v1/certificatesigningrequests/my-csr/approval",
            &approval.to_string(),
        )
        .await;
    assert_eq!(s, 200);
    assert_eq!(approved["spec"]["signerName"], "example.com/signer");
    assert_eq!(approved["status"]["conditions"][0]["type"], "Approved");

    server.stop().await;
}
