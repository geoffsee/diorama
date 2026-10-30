//! HTTPS coverage for `PUT`/`PATCH` (merge, JSON, apply), `scale`, label
//! selectors, and the `batch`/`rbac`/`coordination`/`events` collections.
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use diorama_apiserver::{ApiserverAdapter, ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};

fn setup(dir: &TempDir) -> (ApiserverConfig, std::path::PathBuf) {
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

fn storage(dir: &TempDir) -> KubernetesStorage {
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

async fn request(
    addr: std::net::SocketAddr,
    pki: &std::path::Path,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: &str,
) -> (u16, String) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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

fn body_json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn verify_patch_put_batch_rbac_events() {
    let dir = TempDir::new().unwrap();
    let (config, pki_dir) = setup(&dir);
    let service = ApiserverService::new(config, storage(&dir));
    let registration = ApiserverAdapter::registration(
        "apiserver",
        service.clone(),
        Vec::new(),
        Duration::from_secs(10),
    );
    let supervisor = diorama_supervisor::Supervisor::new(vec![registration]).unwrap();
    let (stop_handle, stop_receiver) = diorama_supervisor::stop_channel();
    let handle = tokio::spawn(async move { supervisor.run(stop_receiver).await });
    let addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(addr) = service.bound_addr() {
                return addr;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("listener bound");
    let pki = pki_dir.clone();

    // namespace
    let (s, _) = request(
        addr,
        &pki,
        "POST",
        "/api/v1/namespaces",
        None,
        r#"{"metadata":{"name":"gaps"}}"#,
    )
    .await;
    assert_eq!(s, 201, "create ns");

    // deployment create
    let (s, _) = request(addr, &pki, "POST", "/apis/apps/v1/namespaces/gaps/deployments",
        None, r#"{"metadata":{"name":"board"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"board"}},"template":{"metadata":{"labels":{"app":"board"}},"spec":{"containers":[{"name":"app","image":"busybox:1.36"}]}}}}"#).await;
    assert_eq!(s, 201, "create deploy: ");

    // merge patch replicas=2
    let (s, b) = request(
        addr,
        &pki,
        "PATCH",
        "/apis/apps/v1/namespaces/gaps/deployments/board",
        Some("application/merge-patch+json"),
        r#"{"spec":{"replicas":2}}"#,
    )
    .await;
    assert_eq!(s, 200, "merge patch: {b}");
    assert_eq!(body_json(&b)["spec"]["replicas"], 2);

    // json patch replicas=3
    let (s, b) = request(
        addr,
        &pki,
        "PATCH",
        "/apis/apps/v1/namespaces/gaps/deployments/board",
        Some("application/json-patch+json"),
        r#"[{"op":"replace","path":"/spec/replicas","value":3}]"#,
    )
    .await;
    assert_eq!(s, 200, "json patch: {b}");
    assert_eq!(body_json(&b)["spec"]["replicas"], 3);

    // PUT replace
    let (s, b) = request(
        addr,
        &pki,
        "GET",
        "/apis/apps/v1/namespaces/gaps/deployments/board",
        None,
        "",
    )
    .await;
    assert_eq!(s, 200);
    let mut doc = body_json(&b);
    doc["spec"]["replicas"] = serde_json::json!(1);
    let put_body = serde_json::to_string(&doc).unwrap();
    let (s, b) = request(
        addr,
        &pki,
        "PUT",
        "/apis/apps/v1/namespaces/gaps/deployments/board",
        None,
        &put_body,
    )
    .await;
    assert_eq!(s, 200, "put: {b}");

    // scale subresource GET + PUT
    let (s, b) = request(
        addr,
        &pki,
        "GET",
        "/apis/apps/v1/namespaces/gaps/deployments/board/scale",
        None,
        "",
    )
    .await;
    assert_eq!(s, 200, "get scale: {b}");
    assert_eq!(body_json(&b)["spec"]["replicas"], 1);
    let (s, b) = request(
        addr,
        &pki,
        "PUT",
        "/apis/apps/v1/namespaces/gaps/deployments/board/scale",
        None,
        r#"{"spec":{"replicas":5}}"#,
    )
    .await;
    assert_eq!(s, 200, "put scale: {b}");
    assert_eq!(body_json(&b)["spec"]["replicas"], 5);
    let (_s, b) = request(
        addr,
        &pki,
        "GET",
        "/apis/apps/v1/namespaces/gaps/deployments/board",
        None,
        "",
    )
    .await;
    assert_eq!(body_json(&b)["spec"]["replicas"], 5);

    // SSA create configmap (200 or 201 both mean created)
    let (s, b) = request(addr, &pki, "PATCH", "/api/v1/namespaces/gaps/configmaps/applied?fieldManager=test&force=true",
        Some("application/apply-patch+yaml"), r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"applied"},"data":{"k":"applied"}}"#).await;
    assert!(s == 200 || s == 201, "ssa create: {s} {b}");
    // SSA update
    let (s, b) = request(
        addr,
        &pki,
        "PATCH",
        "/api/v1/namespaces/gaps/configmaps/applied?fieldManager=test",
        Some("application/apply-patch+yaml"),
        r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"applied"},"data":{"k":"v2"}}"#,
    )
    .await;
    assert_eq!(s, 200, "ssa update: {b}");
    assert_eq!(body_json(&b)["data"]["k"], "v2");

    // label selector
    let (s, _) = request(
        addr,
        &pki,
        "POST",
        "/api/v1/namespaces/gaps/configmaps",
        None,
        r#"{"metadata":{"name":"labeled","labels":{"app":"board"}},"data":{"k":"v"}}"#,
    )
    .await;
    assert_eq!(s, 201);
    let (s, _) = request(
        addr,
        &pki,
        "POST",
        "/api/v1/namespaces/gaps/configmaps",
        None,
        r#"{"metadata":{"name":"unlabeled"},"data":{"k":"v"}}"#,
    )
    .await;
    assert_eq!(s, 201);
    let (s, b) = request(
        addr,
        &pki,
        "GET",
        "/api/v1/namespaces/gaps/configmaps?labelSelector=app%3Dboard",
        None,
        "",
    )
    .await;
    assert_eq!(s, 200);
    let items = body_json(&b)["items"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(items.len(), 1, "label selector: {b}");
    assert_eq!(items[0]["metadata"]["name"], "labeled");

    // collection delete honours the label selector
    let (s, b) = request(
        addr,
        &pki,
        "DELETE",
        "/api/v1/namespaces/gaps/configmaps?labelSelector=app%3Dboard",
        None,
        "",
    )
    .await;
    assert_eq!(s, 200, "collection delete: {b}");
    let (s, b) = request(
        addr,
        &pki,
        "GET",
        "/api/v1/namespaces/gaps/configmaps",
        None,
        "",
    )
    .await;
    assert_eq!(s, 200);
    let remaining: Vec<String> = body_json(&b)["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|item| {
            item.pointer("/metadata/name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .collect();
    assert!(
        !remaining.contains(&"labeled".to_string()),
        "labeled should be deleted: {remaining:?}"
    );
    assert!(
        remaining.contains(&"unlabeled".to_string()),
        "unlabeled should survive: {remaining:?}"
    );

    // batch job
    let (s, b) = request(addr, &pki, "POST", "/apis/batch/v1/namespaces/gaps/jobs",
        None, r#"{"metadata":{"name":"once"},"spec":{"template":{"spec":{"restartPolicy":"Never","containers":[{"name":"once","image":"busybox:1.36"}]}}}}"#).await;
    assert_eq!(s, 201, "create job: {b}");
    let (s, _) = request(
        addr,
        &pki,
        "GET",
        "/apis/batch/v1/namespaces/gaps/jobs/once",
        None,
        "",
    )
    .await;
    assert_eq!(s, 200);
    let (s, b) = request(addr, &pki, "GET", "/apis/batch/v1", None, "").await;
    assert_eq!(s, 200);
    assert!(b.contains("\"jobs\""), "batch discovery: {b}");

    // rbac
    let (s, b) = request(addr, &pki, "POST", "/apis/rbac.authorization.k8s.io/v1/clusterroles",
        None, r#"{"metadata":{"name":"reader"},"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]}"#).await;
    assert_eq!(s, 201, "create clusterrole: {b}");
    let (s, b) = request(addr, &pki, "POST", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        None, r#"{"metadata":{"name":"reader-binding"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"reader"},"subjects":[{"kind":"ServiceAccount","name":"default","namespace":"gaps"}]}"#).await;
    assert_eq!(s, 201, "create crb: {b}");
    let (s, _) = request(
        addr,
        &pki,
        "GET",
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/reader-binding",
        None,
        "",
    )
    .await;
    assert_eq!(s, 200);
    let (s, b) = request(addr, &pki, "POST", "/apis/rbac.authorization.k8s.io/v1/namespaces/gaps/roles",
        None, r#"{"metadata":{"name":"r"},"rules":[{"apiGroups":[""],"resources":["configmaps"],"verbs":["get"]}]}"#).await;
    assert_eq!(s, 201, "create role: {b}");
    let (s, b) = request(
        addr,
        &pki,
        "GET",
        "/apis/rbac.authorization.k8s.io/v1",
        None,
        "",
    )
    .await;
    assert_eq!(s, 200);
    assert!(b.contains("clusterrolebindings"), "rbac discovery: {b}");

    // events
    let (s, b) = request(
        addr,
        &pki,
        "GET",
        "/api/v1/namespaces/gaps/events",
        None,
        "",
    )
    .await;
    assert_eq!(s, 200, "list events: {b}");
    let (s, b) = request(
        addr,
        &pki,
        "POST",
        "/api/v1/namespaces/gaps/events",
        None,
        r#"{"metadata":{"name":"test-ev"},"reason":"Test","message":"hi"}"#,
    )
    .await;
    assert_eq!(s, 201, "create event: {b}");

    // leases
    let (s, b) = request(
        addr,
        &pki,
        "POST",
        "/apis/coordination.k8s.io/v1/namespaces/gaps/leases",
        None,
        r#"{"metadata":{"name":"l1"}}"#,
    )
    .await;
    assert_eq!(s, 201, "create lease: {b}");

    // openapi apps
    let (s, b) = request(addr, &pki, "GET", "/openapi/v3/apis/apps/v1", None, "").await;
    assert_eq!(s, 200, "openapi apps: {b}");
    assert!(b.contains("Deployment"), "openapi has deployment: {b}");
    let (s, _) = request(addr, &pki, "GET", "/openapi/v3/apis/batch/v1", None, "").await;
    assert_eq!(s, 200);

    // dryRun create pod should return 201 and not persist
    let (s, b) = request(
        addr,
        &pki,
        "POST",
        "/api/v1/namespaces/gaps/pods?dryRun=All",
        None,
        r#"{"metadata":{"name":"dry-run-pod"},"spec":{"containers":[{"name":"app","image":"busybox:1.36"}]}}"#,
    )
    .await;
    assert_eq!(s, 201, "dryRun create pod: {b}");
    assert_eq!(body_json(&b)["metadata"]["name"], "dry-run-pod");
    let (s, _) = request(
        addr,
        &pki,
        "GET",
        "/api/v1/namespaces/gaps/pods/dry-run-pod",
        None,
        "",
    )
    .await;
    assert_eq!(s, 404, "dryRun create pod must not persist");

    // dryRun patch should not persist
    let (s, _) = request(
        addr,
        &pki,
        "PATCH",
        "/apis/apps/v1/namespaces/gaps/deployments/board?dryRun=All",
        Some("application/merge-patch+json"),
        r#"{"spec":{"replicas":9}}"#,
    )
    .await;
    assert_eq!(s, 200);
    let (s, b) = request(
        addr,
        &pki,
        "GET",
        "/apis/apps/v1/namespaces/gaps/deployments/board",
        None,
        "",
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(
        body_json(&b)["spec"]["replicas"],
        5,
        "dryRun must not persist"
    );

    // namespace deletion cascades to namespaced objects
    let (s, _) = request(
        addr,
        &pki,
        "POST",
        "/api/v1/namespaces",
        None,
        r#"{"metadata":{"name":"cascade"}}"#,
    )
    .await;
    assert_eq!(s, 201);
    let (s, _) = request(
        addr,
        &pki,
        "POST",
        "/api/v1/namespaces/cascade/configmaps",
        None,
        r#"{"metadata":{"name":"inner"},"data":{"k":"v"}}"#,
    )
    .await;
    assert_eq!(s, 201);
    let (s, _) = request(addr, &pki, "DELETE", "/api/v1/namespaces/cascade", None, "").await;
    assert_eq!(s, 200);
    let (s, _) = request(
        addr,
        &pki,
        "GET",
        "/api/v1/namespaces/cascade/configmaps/inner",
        None,
        "",
    )
    .await;
    assert_eq!(s, 404, "cascaded object should be gone");

    stop_handle.stop();
    let _ = handle.await;
}
