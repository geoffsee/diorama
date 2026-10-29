use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use diorama::config_api::{ConfigApiServer, clear_stale_socket};
use diorama_config::{Config, HostContext, write_document};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::watch;

#[allow(clippy::duplicate_mod)]
#[path = "support/metrics_startup.rs"]
mod metrics_startup;

#[tokio::test]
async fn runtime_metrics_and_config_api_preserve_selected_context_and_degrade_independently() {
    for _ in 0..3 {
        if combined_runtime_attempt(false).await {
            assert!(combined_runtime_attempt(true).await);
            return;
        }
    }
    panic!("metrics failed to bind three fresh ephemeral addresses");
}

async fn combined_runtime_attempt(collision: bool) -> bool {
    let tmp = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics_addr = listener.local_addr().unwrap();
    let _blocker = collision.then_some(listener);
    let socket_path = tmp.path().join("config.sock");
    let config_path = tmp.path().join("selected.yaml");
    let host = HostContext {
        cpu_count: 1,
        architecture: "riscv64".into(),
        detected_container_mode: false,
    };
    let mut config = Config {
        path: tmp.path().join("state").display().to_string(),
        ..Config::default()
    };
    config.network.node_ip = "127.0.0.1".into();
    config.kubernetes.node_name = "runtime-node".into();
    config.storage.local_path.enabled = false;
    config.metrics.enabled = true;
    config.metrics.bind_address = metrics_addr.to_string();
    config.api.enabled = true;
    config.api.socket_path = socket_path.display().to_string();
    let mut stored = config.clone();
    stored.kubernetes.node_name = "selected-file-node".into();
    write_document(&config_path, &stored).unwrap();
    let validated = config.validate(&host).unwrap();
    crate::install_scheduler_process_fixture(&validated);
    let runtime =
        diorama::runtime::NodeRuntime::from_config_with_context(validated, config_path, host)
            .unwrap();
    assert!(runtime.metrics_registry().is_some());
    let mut observer = runtime.observer();
    let (stop, receiver) = diorama_supervisor::stop_channel();
    let task = tokio::spawn(runtime.run_with_sink(
        receiver,
        std::io::sink(),
        diorama::lifecycle_sink::FlushPolicy::EachFrame,
    ));
    let bound = metrics_startup::metrics_bound(&mut observer).await;
    if collision {
        assert!(
            !bound,
            "retained collision listener must make metrics bind fail"
        );
    } else if !bound {
        stop.stop();
        let (report, _, _) = task.await.unwrap();
        metrics_startup::assert_retryable_bind_failure(&report);
        assert!(!socket_path.exists());
        return false;
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while UnixStream::connect(&socket_path).await.is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let (status, _, _, body) =
            request_json(&socket_path, "GET", "/api/v1/config", "", &[]).await;
        assert_eq!(status, 200);
        assert_eq!(
            body["config"]["kubernetes"]["nodeName"],
            "selected-file-node"
        );
        let (status, _, _, _) = request_json(
            &socket_path,
            "POST",
            "/api/v1/config:validate",
            r#"{"kubernetes":{"kubelet":{"systemReserved":{"cpu":"1000m"}}}}"#,
            &[],
        )
        .await;
        assert_eq!(
            status, 422,
            "validation must retain the supplied one-CPU host"
        );
        if collision {
            wait_for_degraded(&mut observer).await;
        } else {
            assert_metrics_health(metrics_addr).await;
        }
    })
    .await
    .expect("both optional endpoints start without losing selected context");
    stop.stop();
    let (report, _, _) = task.await.unwrap();
    assert_combined_report(&report, collision);
    assert!(!socket_path.exists());
    true
}

fn assert_combined_report(report: &diorama_supervisor::SupervisorReport, collision: bool) {
    assert_eq!(report.cause, diorama_supervisor::StopCause::Requested);
    assert!(
        report
            .outcomes
            .iter()
            .any(|outcome| outcome.component == "configapi")
    );
    if collision {
        metrics_startup::assert_retryable_bind_failure(report);
    } else {
        assert_eq!(
            report.failures,
            <[diorama_supervisor::ComponentFailure; 0]>::default()
        );
    }
}

async fn wait_for_degraded(observer: &mut diorama_supervisor::LifecycleObserver) {
    while !observer.snapshot().degraded {
        observer.changed().await.unwrap();
    }
}

async fn assert_metrics_health(addr: std::net::SocketAddr) {
    let mut stream = loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => break stream,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
        }
    };
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with("ok\n"));
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

async fn do_http_request(
    socket_path: &Path,
    method: &str,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (u16, HashMap<String, String>, String) {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .expect("connect to socket");
    let mut req = format!("{method} {uri} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (k, v) in headers {
        let _ = write!(req, "{k}: {v}\r\n");
    }
    let _ = write!(req, "Content-Length: {}\r\n\r\n", body.len());
    req.push_str(body);

    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");

    let mut response_bytes = Vec::new();
    stream
        .read_to_end(&mut response_bytes)
        .await
        .expect("read response");

    let header_end = response_bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("valid http response header end");
    let header_str = std::str::from_utf8(&response_bytes[..header_end]).expect("utf8 headers");
    let raw_body = std::str::from_utf8(&response_bytes[header_end + 4..])
        .expect("utf8 body")
        .to_string();

    let mut lines = header_str.lines();
    let status_line = lines.next().expect("status line");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse::<u16>()
        .expect("numeric status");

    let mut parsed_headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            parsed_headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    (status, parsed_headers, raw_body)
}

async fn request_json(
    socket_path: &Path,
    method: &str,
    url: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (u16, String, String, Value) {
    let (status, resp_headers, raw_body) =
        do_http_request(socket_path, method, url, body, headers).await;
    let etag = resp_headers.get("etag").cloned().unwrap_or_default();
    let parsed: Value =
        serde_json::from_str(&raw_body).unwrap_or_else(|_| Value::String(raw_body.clone()));
    (status, etag, raw_body, parsed)
}

struct TestServerHarness {
    _tmp: tempfile::TempDir,
    config_path: PathBuf,
    socket_path: PathBuf,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl TestServerHarness {
    fn start(initial_config: &Config) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.yaml");
        let socket_path = tmp.path().join("s.sock");
        write_document(&config_path, initial_config).unwrap();

        let server = ConfigApiServer::new(
            socket_path.clone(),
            config_path.clone(),
            HostContext::default(),
        );
        let listener = server.bind().expect("bind socket");
        assert_eq!(format!("{:04o}", mode(&socket_path)), "0600");

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task =
            tokio::spawn(async move { server.run_with_listener(listener, shutdown_rx).await });

        Self {
            _tmp: tmp,
            config_path,
            socket_path,
            shutdown_tx,
            task,
        }
    }

    async fn shutdown(&mut self) {
        let _ = self.shutdown_tx.send(true);
        let _ = (&mut self.task).await;
    }
}

#[tokio::test]
async fn test_config_api_reads_and_schema() {
    let mut initial_config = Config::default();
    initial_config.network.node_ip = "192.0.2.10".into();
    initial_config.d2k.namespace = "workloads".into();
    initial_config.portainer.edge_key = "fixture-synthetic-key".into();

    let mut harness = TestServerHarness::start(&initial_config);
    let sp = &harness.socket_path;

    // 1. GET /api/v1/config (redacted secrets)
    let (status, initial_etag, _raw, body) =
        request_json(sp, "GET", "/api/v1/config", "", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(body["config"]["network"]["nodeIP"], "192.0.2.10");
    assert_eq!(body["config"]["portainer"]["edgeKey"], "***");
    assert_eq!(body["restartRequired"], false);

    // 2. GET /api/v1/config?showSecrets=true
    let (status, show_etag, _raw, show_body) =
        request_json(sp, "GET", "/api/v1/config?showSecrets=true", "", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(
        show_body["config"]["portainer"]["edgeKey"],
        "fixture-synthetic-key"
    );
    assert_eq!(
        show_etag, initial_etag,
        "ETag must be identical for redacted and revealed reads"
    );

    // 3. GET /api/v1/config/schema
    let (status, _, _raw, schema_body) =
        request_json(sp, "GET", "/api/v1/config/schema", "", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(schema_body["apiVersion"], diorama_config::API_VERSION);
    let settings = schema_body["settings"].as_array().expect("settings array");
    assert_eq!(settings.len(), 35);
    assert!(
        settings
            .iter()
            .any(|s| s["path"] == "path" && s["mutability"] == "immutable")
    );
    assert!(
        settings
            .iter()
            .any(|s| s["path"] == "portainer.edgeKey" && s["secret"] == true)
    );

    // 4. GET /healthz
    let (status, _, health_body, _) = request_json(sp, "GET", "/healthz", "", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(health_body, "ok\n");

    harness.shutdown().await;
}

#[tokio::test]
async fn test_config_api_patches_and_validations() {
    let mut initial_config = Config::default();
    initial_config.network.node_ip = "192.0.2.10".into();
    initial_config.d2k.namespace = "workloads".into();

    let mut harness = TestServerHarness::start(&initial_config);
    let sp = &harness.socket_path;

    let (_, initial_etag, _, _) = request_json(sp, "GET", "/api/v1/config", "", &[]).await;

    // PATCH with current etag
    let (status, patch_etag, _, patch_res) = request_json(
        sp,
        "PATCH",
        "/api/v1/config",
        r#"{"network":{"mtu":1400}}"#,
        &[("If-Match", &initial_etag)],
    )
    .await;
    assert_eq!(status, 200);
    assert_ne!(patch_etag, initial_etag);
    assert_eq!(patch_res["changed"], json!(["network.mtu"]));
    assert_eq!(patch_res["requiresRestart"], json!(["network.mtu"]));
    assert_eq!(patch_res["restartRequired"], true);
    assert_eq!(patch_res["config"]["network"]["mtu"], 1400);

    // PATCH with stale etag -> 412
    let (status, _, _, _) = request_json(
        sp,
        "PATCH",
        "/api/v1/config",
        r#"{"network":{"mtu":1500}}"#,
        &[("If-Match", &initial_etag)],
    )
    .await;
    assert_eq!(status, 412);

    // PATCH with null restoring default
    let (status, _, _, null_res) = request_json(
        sp,
        "PATCH",
        "/api/v1/config",
        r#"{"d2k":{"namespace":null}}"#,
        &[],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(null_res["config"]["d2k"]["namespace"], "d2k");

    // POST /api/v1/config:validate valid
    let file_before = fs::read(&harness.config_path).unwrap();
    let (status, _, _, val_res) = request_json(
        sp,
        "POST",
        "/api/v1/config:validate",
        r#"{"network":{"nodeIP":"192.0.2.30"}}"#,
        &[],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(val_res["config"]["network"]["nodeIP"], "192.0.2.30");
    assert_eq!(fs::read(&harness.config_path).unwrap(), file_before);

    // POST /api/v1/config:validate invalid -> 422
    let (status, _, _, _) = request_json(
        sp,
        "POST",
        "/api/v1/config:validate",
        r#"{"d2k":{"enabled":true},"network":{"loadBalancer":{"enabled":false}}}"#,
        &[],
    )
    .await;
    assert_eq!(status, 422);
    assert_eq!(fs::read(&harness.config_path).unwrap(), file_before);

    harness.shutdown().await;
}

#[tokio::test]
async fn test_config_api_rejected_requests_preserve_disk() {
    let mut harness = TestServerHarness::start(&Config::default());
    let sp = &harness.socket_path;
    let file_before = fs::read(&harness.config_path).unwrap();

    let oversized = "x".repeat(diorama::config_api::MAX_BODY_BYTES + 1);
    let rejected = [
        (
            "immutable",
            "PATCH",
            r#"{"path":"/elsewhere"}"#,
            vec![],
            409,
        ),
        (
            "invalid",
            "PATCH",
            r#"{"d2k":{"enabled":true},"network":{"loadBalancer":{"enabled":false}}}"#,
            vec![],
            422,
        ),
        ("malformed-patch", "PATCH", "{not json", vec![], 400),
        ("malformed-put", "PUT", "{not json", vec![], 400),
        (
            "wrong-type",
            "PUT",
            r#"{"network":{"mtu":"tall"}}"#,
            vec![],
            400,
        ),
        (
            "wrong-content",
            "PATCH",
            "{}",
            vec![("Content-Type", "application/xml")],
            415,
        ),
        (
            "redacted-write",
            "PATCH",
            r#"{"portainer":{"edgeKey":"***"}}"#,
            vec![],
            400,
        ),
        ("oversized", "PATCH", oversized.as_str(), vec![], 400),
    ];

    for (name, method, body, hdrs, expected_status) in rejected {
        let (st, _, _, res) = request_json(sp, method, "/api/v1/config", body, &hdrs).await;
        assert_eq!(
            st, expected_status,
            "request {name} expected status {expected_status}"
        );
        if name == "immutable" {
            assert_eq!(res["field"], "path");
        }
        if name == "redacted-write" {
            assert_eq!(res["field"], "portainer.edgeKey");
        }
    }

    assert_eq!(
        fs::read(&harness.config_path).unwrap(),
        file_before,
        "rejected requests must preserve valid file bytes on disk"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn test_config_api_replacements_and_concurrent_patches() {
    let mut harness = TestServerHarness::start(&Config::default());
    let sp = &harness.socket_path;

    // PUT replacement
    let (status, _, _, put_res) = request_json(
        sp,
        "PUT",
        "/api/v1/config",
        r#"{"network":{"mtu":1450}}"#,
        &[],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(put_res["config"]["network"]["mtu"], 1450);

    // DELETE resets to defaults
    let (status, _, _, del_res) = request_json(sp, "DELETE", "/api/v1/config", "", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(del_res["config"]["network"]["mtu"], 0);

    // Concurrent PATCH requests modifying disjoint fields
    let p1 = {
        let sp = sp.clone();
        tokio::spawn(async move {
            do_http_request(
                &sp,
                "PATCH",
                "/api/v1/config",
                r#"{"network":{"mtu":1400}}"#,
                &[],
            )
            .await
        })
    };
    let p2 = {
        let sp = sp.clone();
        tokio::spawn(async move {
            do_http_request(
                &sp,
                "PATCH",
                "/api/v1/config",
                r#"{"logging":{"debug":true}}"#,
                &[],
            )
            .await
        })
    };
    let (r1, r2) = tokio::join!(p1, p2);
    assert_eq!(r1.unwrap().0, 200);
    assert_eq!(r2.unwrap().0, 200);

    // Verify after concurrent patches
    let (status, _, _, after_res) = request_json(sp, "GET", "/api/v1/config", "", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(after_res["config"]["network"]["mtu"], 1400);
    assert_eq!(after_res["config"]["logging"]["debug"], true);

    // No-op PATCH
    let (status, _, _, noop_res) = request_json(
        sp,
        "PATCH",
        "/api/v1/config",
        r#"{"network":{"mtu":1400}}"#,
        &[],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(noop_res["restartRequired"], false);

    harness.shutdown().await;
}

#[tokio::test]
async fn test_config_api_socket_lifecycle_and_reclamation() {
    let mut harness = TestServerHarness::start(&Config::default());
    let sp = harness.socket_path.clone();

    // Live socket cannot be cleared
    assert!(
        clear_stale_socket(&sp).is_err(),
        "live socket must be refused"
    );

    // Clean shutdown removes socket file
    harness.shutdown().await;
    assert!(!sp.exists(), "clean shutdown must remove the socket file");

    // Stale socket reclamation
    {
        let std_listener = std::os::unix::net::UnixListener::bind(&sp).unwrap();
        drop(std_listener);
    }
    assert!(sp.exists());
    assert!(
        clear_stale_socket(&sp).is_ok(),
        "stale socket must be reclaimed"
    );
    assert!(!sp.exists(), "reclaimed socket must be removed");

    // Regular file refusal and preservation
    fs::write(&sp, b"keep").unwrap();
    assert!(
        clear_stale_socket(&sp).is_err(),
        "regular file must be refused"
    );
    assert_eq!(
        fs::read(&sp).unwrap(),
        b"keep",
        "regular file must be preserved"
    );
}

#[test]
fn test_restrictive_umask_socket_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("restrictive.sock");
    let status = std::process::Command::new("sh")
        .args([
            "-c",
            "umask 0777; exec \"$1\" --exact config_api::restrictive_umask_socket_child --nocapture",
            "diorama-socket-test",
        ])
        .arg(std::env::current_exe().unwrap())
        .env("diorama_SOCKET_TEST_PATH", &socket)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn restrictive_umask_socket_child() {
    let Some(socket_path) = std::env::var_os("diorama_SOCKET_TEST_PATH") else {
        return;
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(async {
        let socket_path = PathBuf::from(socket_path);
        let config_path = socket_path.parent().unwrap().join("config.yaml");
        let server = ConfigApiServer::new(socket_path.clone(), config_path, HostContext::default());
        let _listener = server.bind().expect("bind socket");
        assert_eq!(mode(&socket_path), 0o600);
    });
}

async fn incomplete_patch(harness: &TestServerHarness) -> UnixStream {
    let mut stream = UnixStream::connect(&harness.socket_path).await.unwrap();
    let body = r#"{"logging":{"debug":true}}"#;
    stream.write_all(format!(
        "PATCH /api/v1/config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", body.len()
    ).as_bytes()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    stream
}

async fn assert_connection_closed_without_write(mut stream: UnixStream, config_path: &Path) {
    let _ = stream.write_all(br#"{"logging":{"debug":true}}"#).await;
    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        stream.read_to_end(&mut response),
    )
    .await
    .expect("connection closed within deadline");
    assert!(!String::from_utf8_lossy(&response).contains("200 OK"));
    assert!(
        !diorama_config::read_file(config_path)
            .unwrap()
            .unwrap()
            .config
            .logging
            .debug
    );
}

#[tokio::test]
async fn shutdown_closes_incomplete_requests_before_reporting_stopped() {
    let mut harness = TestServerHarness::start(&Config::default());
    let stream = incomplete_patch(&harness).await;
    tokio::time::timeout(std::time::Duration::from_secs(1), harness.shutdown())
        .await
        .unwrap();
    assert!(!harness.socket_path.exists());
    assert_connection_closed_without_write(stream, &harness.config_path).await;
}

#[tokio::test]
async fn cancellation_aborts_connections_and_unlinks_owned_socket() {
    let harness = TestServerHarness::start(&Config::default());
    let stream = incomplete_patch(&harness).await;
    harness.task.abort();
    assert!(harness.task.await.unwrap_err().is_cancelled());
    assert!(!harness.socket_path.exists());
    assert_connection_closed_without_write(stream, &harness.config_path).await;
}

#[tokio::test]
async fn dropped_shutdown_sender_stops_server_and_connections() {
    let harness = TestServerHarness::start(&Config::default());
    let stream = incomplete_patch(&harness).await;
    drop(harness.shutdown_tx);
    tokio::time::timeout(std::time::Duration::from_secs(1), harness.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!harness.socket_path.exists());
    assert_connection_closed_without_write(stream, &harness.config_path).await;
}

#[tokio::test]
async fn unpolled_future_and_listener_drop_preserve_replacement_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("s.sock");
    let server = ConfigApiServer::new(
        socket_path.clone(),
        tmp.path().join("config.yaml"),
        HostContext::default(),
    );
    let listener = server.bind().unwrap();
    let (_tx, rx) = watch::channel(false);
    drop(server.clone().run_with_listener(listener, rx));
    assert!(!socket_path.exists());

    let listener = server.bind().unwrap();
    fs::remove_file(&socket_path).unwrap();
    fs::write(&socket_path, b"unrelated replacement").unwrap();
    drop(listener);
    assert_eq!(fs::read(&socket_path).unwrap(), b"unrelated replacement");
}

#[tokio::test]
async fn validation_redacts_keys_and_optional_map_edits_reach_all_handlers() {
    let mut harness = TestServerHarness::start(&Config::default());
    let body = r#"{"portainer":{"edgeKey":"review-synthetic-secret"},"kubernetes":{"kubelet":{"systemReserved":{"cpu":"100m"}}}}"#;
    for (method, uri) in [
        ("POST", "/api/v1/config:validate"),
        ("PUT", "/api/v1/config"),
        ("PATCH", "/api/v1/config"),
    ] {
        let (status, _, raw, parsed) =
            request_json(&harness.socket_path, method, uri, body, &[]).await;
        assert_eq!(status, 200, "{raw}");
        assert_eq!(parsed["config"]["portainer"]["edgeKey"], "***");
        assert!(!raw.contains("review-synthetic-secret"));
        assert_eq!(
            parsed["config"]["kubernetes"]["kubelet"]["systemReserved"]["cpu"],
            "100m"
        );
        if method == "POST" {
            let stored = diorama_config::read_file(&harness.config_path)
                .unwrap()
                .unwrap()
                .config;
            assert_eq!(stored.portainer.edge_key, "");
            assert!(stored.kubernetes.kubelet.system_reserved.is_none());
        } else {
            request_json(&harness.socket_path, "DELETE", "/api/v1/config", "", &[]).await;
        }
    }
    harness.shutdown().await;
}
