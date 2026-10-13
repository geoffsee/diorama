//! Integration tests for operational metrics HTTP serving, scrape parsing, and health checks.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use diorama::lifecycle_sink::FlushPolicy;
use diorama::metrics::{
    BuildInfoCollector, MetricsRegistry, MetricsServer, UptimeCollector, parse_scrape,
};
use diorama::runtime::NodeRuntime;
use diorama_config::{
    EnvironmentMode, ExplicitFlags, HostContext, ValidatedConfig, decode, resolve_layers,
};
use diorama_supervisor::{FailureKind, stop_channel};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[allow(clippy::duplicate_mod)]
#[path = "support/metrics_startup.rs"]
mod metrics_startup;

#[derive(Clone, Default)]
struct LogProbe(Arc<Mutex<Vec<u8>>>);

impl LogProbe {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("lock").clone()).expect("utf8")
    }
}

impl Write for LogProbe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn test_config_metrics(
    dir: &Path,
    metrics_enabled: bool,
    metrics_bind_address: &str,
) -> ValidatedConfig {
    let yaml = format!(
        r#"
path: "{}"
network:
  node_ip: "127.0.0.1"
kubernetes:
  node_name: "test-node"
  apiServer:
    startupTimeoutSeconds: 5
logging:
  debug: false
metrics:
  enabled: {}
  bindAddress: "{}"
storage:
  local_path:
    enabled: false
"#,
        dir.display(),
        metrics_enabled,
        metrics_bind_address
    );
    resolve_layers(
        Some(decode(&yaml).expect("decode")),
        &BTreeMap::new(),
        &ExplicitFlags::default(),
        EnvironmentMode::Include,
        &HostContext {
            cpu_count: 4,
            architecture: "arm64".into(),
            detected_container_mode: false,
        },
    )
    .expect("resolve")
    .validated
}

async fn http_get(addr: SocketAddr, path: &str, headers: &[(&str, &str)]) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect to server");
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read response");
    let resp = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = resp.split_once("\r\n\r\n").unwrap_or(("", &resp));
    let status_line = head.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    (status_code, head.to_string(), body.to_string())
}

#[tokio::test]
async fn test_standalone_metrics_server_endpoints_and_shutdown() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind free port");
    let addr = listener.local_addr().expect("local addr");

    let registry = Arc::new(MetricsRegistry::new());
    registry.register(BuildInfoCollector::default());
    registry.register(UptimeCollector::with_start_time(1_700_000_000));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let reg_clone = registry.clone();
    let server_task = tokio::spawn(async move {
        MetricsServer::run_with_listener(listener, reg_clone, shutdown_rx).await
    });

    // 1. Plain HTTP /healthz, /livez, /readyz checks
    let (status, _headers, body) = http_get(addr, "/healthz", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok\n");

    let (status, _headers, body) = http_get(addr, "/livez", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok\n");

    let (status, _headers, body) = http_get(addr, "/readyz", &[]).await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok\n");

    // 2. Root HTML landing page
    let (status, headers, body) = http_get(addr, "/", &[]).await;
    assert_eq!(status, 200);
    assert!(headers.contains("text/html"));
    assert!(body.contains("kubesolo metrics"));
    assert!(body.contains("/metrics"));

    // 3. Prometheus plain exposition scrape without TLS
    let (status, headers, body) = http_get(addr, "/metrics", &[]).await;
    assert_eq!(status, 200);
    assert!(headers.contains("text/plain"));
    assert!(!body.contains("# EOF"));
    let scrape = parse_scrape(&body).expect("parse Prometheus scrape");
    assert_eq!(
        scrape.get_first_value("kubesolo_start_time_seconds"),
        Some(1_700_000_000.0)
    );
    let build_sample = scrape
        .get_sample(
            "kubesolo_build_info",
            "rust_version",
            env!("diorama_RUSTC_VERSION"),
        )
        .expect("build info present");
    assert!((build_sample.value - 1.0).abs() < f64::EPSILON);

    // 4. OpenMetrics exposition scrape with Accept header
    let (status, headers, body) = http_get(
        addr,
        "/metrics",
        &[("Accept", "application/openmetrics-text; version=1.0.0")],
    )
    .await;
    assert_eq!(status, 200);
    assert!(headers.contains("application/openmetrics-text"));
    assert!(body.ends_with("# EOF\n"));
    let om_scrape = parse_scrape(&body).expect("parse OpenMetrics scrape");
    assert_eq!(
        om_scrape.get_first_value("kubesolo_start_time_seconds"),
        Some(1_700_000_000.0)
    );

    // 5. 404 for unknown routes
    let (status, _headers, _body) = http_get(addr, "/nonexistent", &[]).await;
    assert_eq!(status, 404);

    // 6. Graceful shutdown
    let _ = shutdown_tx.send(true);
    let server_res = tokio::time::timeout(Duration::from_secs(3), server_task)
        .await
        .expect("shutdown timeout");
    assert!(server_res.is_ok());

    // Connecting after shutdown fails
    let conn_after = TcpStream::connect(addr).await;
    assert!(
        conn_after.is_err(),
        "Server should no longer accept connections"
    );
}

#[tokio::test]
async fn test_node_runtime_disabled_mode_opens_no_listener() {
    let temp = TempDir::new().unwrap();
    // Default metrics.enabled is false, default bind address is 127.0.0.1:9105
    let config = test_config_metrics(temp.path(), false, "127.0.0.1:9105");
    assert!(!config.config().metrics.enabled);
    assert_eq!(config.config().metrics.bind_address, "127.0.0.1:9105");

    let runtime = NodeRuntime::from_config(config).expect("assemble runtime");
    assert!(!runtime.is_metrics_enabled());
    assert_eq!(runtime.metrics_bind_address(), "127.0.0.1:9105");
    assert!(runtime.metrics_registry().is_none());

    let client = runtime.client().expect("client present").clone();

    // Disabled mode registers no metrics listener
    let (stop_handle, stop_receiver) = stop_channel();
    let probe = LogProbe::default();
    let run_handle =
        tokio::spawn(runtime.run_with_sink(stop_receiver, probe, FlushPolicy::EachFrame));

    // Wait until apiserver is ready and serving
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client.list_namespaces().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("apiserver becomes reachable");

    stop_handle.stop();
    let (report, _, _) = run_handle.await.expect("runtime run");
    assert_eq!(
        report.failures,
        <[diorama_supervisor::ComponentFailure; 0]>::default()
    );
    assert!(
        report
            .outcomes
            .iter()
            .all(|outcome| outcome.component != "metrics")
    );
}

#[tokio::test]
async fn disabled_metrics_does_not_touch_an_existing_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let temp = TempDir::new().unwrap();
    let runtime =
        NodeRuntime::from_config(test_config_metrics(temp.path(), false, &addr.to_string()))
            .expect("assemble disabled metrics runtime");
    assert!(runtime.metrics_registry().is_none());
    let client = runtime.client().unwrap().clone();
    let (stop_handle, stop_receiver) = stop_channel();
    let run_handle = tokio::spawn(runtime.run_with_sink(
        stop_receiver,
        LogProbe::default(),
        FlushPolicy::EachFrame,
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        while client.list_namespaces().await.is_err() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut peer = TcpStream::connect(addr).await.unwrap();
        let (mut owned, _) = listener.accept().await.unwrap();
        owned.write_all(b"owner").await.unwrap();
        let mut response = [0; 5];
        peer.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"owner");
    })
    .await
    .expect("the original listener remains owned and usable");
    stop_handle.stop();
    let (report, _, _) = run_handle.await.unwrap();
    assert!(
        report.failures.is_empty(),
        "disabled metrics must not attempt a colliding bind"
    );
    assert!(
        report
            .outcomes
            .iter()
            .all(|outcome| outcome.component != "metrics")
    );
}

#[tokio::test]
async fn test_node_runtime_metrics_serving_scrape_and_certificates_without_tls() {
    for _ in 0..3 {
        if metrics_serving_attempt(false).await {
            return;
        }
    }
    panic!("metrics failed to bind three fresh ephemeral addresses");
}

#[tokio::test]
async fn reclaimed_metrics_port_is_retried_after_the_failed_runtime_is_joined() {
    assert!(!metrics_serving_attempt(true).await);
    assert!(metrics_serving_attempt(false).await);
}

async fn metrics_serving_attempt(reclaim_before_bind: bool) -> bool {
    let temp = TempDir::new().unwrap();

    // Find an unused local port
    let dummy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = dummy.local_addr().unwrap();
    let _reclaimed = reclaim_before_bind.then_some(dummy);

    let config = test_config_metrics(temp.path(), true, &addr.to_string());
    assert!(config.config().metrics.enabled);

    let runtime = NodeRuntime::from_config(config).expect("assemble runtime");
    assert!(runtime.is_metrics_enabled());
    assert!(runtime.metrics_registry().is_some());
    let mut observer = runtime.observer();

    let client = runtime.client().expect("client present").clone();
    let (stop_handle, stop_receiver) = stop_channel();
    let probe = LogProbe::default();
    let run_handle =
        tokio::spawn(runtime.run_with_sink(stop_receiver, probe, FlushPolicy::EachFrame));

    if !metrics_startup::metrics_bound(&mut observer).await {
        stop_handle.stop();
        let (report, _, _) = run_handle.await.expect("failed bind attempt joins");
        metrics_startup::assert_retryable_bind_failure(&report);
        return false;
    }

    // Wait until apiserver is ready and serving
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client.list_namespaces().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("apiserver becomes reachable");

    // Wait for the metrics endpoint to become ready
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(mut stream) = TcpStream::connect(addr).await {
            let req = format!("GET /healthz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(req.as_bytes()).await;
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf).await;
            if String::from_utf8_lossy(&buf).contains("ok") {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "Metrics endpoint did not become ready in time");

    // 1. Scrape metrics over plain HTTP (demonstrating that certificate metrics do not imply TLS)
    let (status, _headers, body) = http_get(addr, "/metrics", &[]).await;
    assert_eq!(status, 200);

    // 2. Parse scrape response
    let scrape = parse_scrape(&body).expect("parse Prometheus scrape");
    assert!(
        !body.contains("kubesolo_component_up"),
        "unwired lifecycle state must not masquerade as health"
    );
    let datastore_size: f64 = body
        .lines()
        .find_map(|line| line.strip_prefix("kubesolo_kine_db_size_bytes "))
        .expect("datastore size series")
        .parse()
        .unwrap();
    assert!(
        datastore_size > 0.0,
        "scrape must measure actual managed datastore files"
    );

    // Assert build info is present
    let build_sample = scrape
        .get_sample(
            "kubesolo_build_info",
            "rust_version",
            env!("diorama_RUSTC_VERSION"),
        )
        .expect("kubesolo_build_info");
    assert!((build_sample.value - 1.0).abs() < f64::EPSILON);

    // Assert certificate metrics are reported (e.g. apiserver, ca, kubelet)
    let apiserver_cert_valid = scrape
        .get_sample("kubesolo_certificate_valid", "name", "apiserver")
        .expect("apiserver cert valid metric");
    assert!((apiserver_cert_valid.value - 1.0).abs() < f64::EPSILON);

    let ca_cert_valid = scrape
        .get_sample("kubesolo_certificate_valid", "name", "ca")
        .expect("ca cert valid metric");
    assert!((ca_cert_valid.value - 1.0).abs() < f64::EPSILON);

    let apiserver_expiry = scrape
        .get_sample(
            "kubesolo_certificate_expiry_timestamp_seconds",
            "name",
            "apiserver",
        )
        .expect("apiserver cert expiry metric");
    assert!(apiserver_expiry.value > 1_700_000_000.0);

    // 3. Graceful shutdown
    stop_handle.stop();
    let (report, _, _) = run_handle.await.expect("runtime join");
    assert_eq!(
        report.failures,
        <[diorama_supervisor::ComponentFailure; 0]>::default()
    );

    // Verify endpoint is closed
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(TcpStream::connect(addr).await.is_err());
    true
}

#[tokio::test]
async fn test_node_runtime_metrics_bind_failure_is_observable_and_nonfatal() {
    let temp = TempDir::new().unwrap();

    // Intentionally occupy a port before starting runtime
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blocked_addr = blocker.local_addr().unwrap();

    let config = test_config_metrics(temp.path(), true, &blocked_addr.to_string());

    // NodeRuntime assembly succeeds (bind is deferred to adapter run)
    let runtime =
        NodeRuntime::from_config(config).expect("assemble runtime succeeds despite conflict");

    let client = runtime.client().expect("client present").clone();
    let probe = LogProbe::default();
    let (stop_handle, stop_receiver) = stop_channel();

    let run_handle =
        tokio::spawn(runtime.run_with_sink(stop_receiver, probe.clone(), FlushPolicy::EachFrame));

    // Wait until degradation is recorded in the structured logs
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let text = probe.text();
            if text.contains("\"event\":\"component_failure\"")
                && text.contains("\"component\":\"metrics\"")
                && text.contains("\"detail_code\":\"metrics_bind_failed\"")
                && text.contains("\"event\":\"supervisor_degraded\"")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("metrics bind failure is logged as component failure and supervisor degraded");

    // Nonfatal: Assert KubernetesApiClient remains fully operational
    client
        .create_namespace("nonfatal-metrics-ns")
        .await
        .expect("core Kubernetes API server remains operational despite metrics bind failure");

    // Clean shutdown
    stop_handle.stop();
    let (report, _, _) = run_handle.await.expect("runtime join");

    // Observable in supervisor report
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.component == "metrics"
                && f.kind == FailureKind::Adapter("metrics_bind_failed")),
        "Metrics component must be listed in failures with metrics_bind_failed"
    );

    // Free blocker
    drop(blocker);
}

async fn read_keep_alive_response(stream: &mut TcpStream) {
    let mut response = Vec::new();
    loop {
        response.push(stream.read_u8().await.expect("response byte"));
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let mut body = [0; 3];
    stream.read_exact(&mut body).await.expect("health body");
    assert_eq!(&body, b"ok\n");
}

#[tokio::test]
async fn metrics_shutdown_and_cancellation_close_existing_connections() {
    // Explicit stop, loss of the owner's channel, cancellation, and an initial
    // stopped channel all settle the listener and accepted connections.
    for mode in 0..4 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = watch::channel(mode == 3);
        let server = tokio::spawn(MetricsServer::run_with_listener(
            listener,
            Arc::new(MetricsRegistry::new()),
            rx,
        ));
        if mode == 3 {
            tokio::time::timeout(Duration::from_secs(1), server)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(TcpStream::connect(addr).await.is_err());
            continue;
        }
        let mut keep_alive = TcpStream::connect(addr).await.unwrap();
        keep_alive
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        read_keep_alive_response(&mut keep_alive).await;
        // An incomplete header must not delay bounded shutdown either.
        let mut partial = TcpStream::connect(addr).await.unwrap();
        partial
            .write_all(b"GET /metrics HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        match mode {
            0 => {
                tx.send(true).unwrap();
            },
            1 => drop(tx),
            2 => server.abort(),
            _ => unreachable!(),
        }
        let result = tokio::time::timeout(Duration::from_secs(6), server)
            .await
            .unwrap();
        if mode == 2 {
            assert!(result.unwrap_err().is_cancelled());
        } else {
            result.unwrap().unwrap();
        }
        for stream in [&mut keep_alive, &mut partial] {
            let mut buf = Vec::new();
            let result = tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut buf))
                .await
                .expect("existing socket must close");
            assert!(result.is_ok() || result.unwrap_err().kind() == io::ErrorKind::ConnectionReset);
            assert!(
                buf.is_empty(),
                "stopped server must not send a new response"
            );
        }
        assert!(TcpStream::connect(addr).await.is_err());
    }
}

#[tokio::test]
async fn metrics_accept_negotiates_quality_versions_and_wildcards() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let server = tokio::spawn(MetricsServer::run_with_listener(
        listener,
        Arc::new(MetricsRegistry::new()),
        rx,
    ));
    let cases = [
        (
            "application/openmetrics-text;version=1.0.0;q=0,text/plain;version=0.0.4;q=1",
            200,
            false,
        ),
        (
            "application/openmetrics-text;version=1.0.0;q=0.2,text/plain;q=0.8",
            200,
            false,
        ),
        (
            "text/plain;q=0.1,application/openmetrics-text;version=1.0.0;q=0.9",
            200,
            true,
        ),
        (
            "application/openmetrics-text;version=9.0.0,text/plain;version=0.0.4;q=0.1",
            200,
            false,
        ),
        ("application/openmetrics-text;version=9.0.0", 406, false),
        (
            "application/openmetrics-text;q=0,text/plain;q=0",
            406,
            false,
        ),
        ("*/*", 200, false),
        ("application/*", 200, true),
        ("application/openmetrics-text;q=0,*/*;q=0.5", 200, false),
        ("text/plain;q=0,*/*;q=0.5", 200, true),
        (
            "APPLICATION/OPENMETRICS-TEXT;version=\"1.0.0\";charset=UTF-8",
            200,
            true,
        ),
        (
            "application/openmetrics-text;q=1.001,text/plain",
            200,
            false,
        ),
        (
            "application/openmetrics-text;q=0.9999,text/plain",
            200,
            false,
        ),
        ("application/json", 406, false),
    ];
    for (accept, expected_status, openmetrics) in cases {
        let (status, headers, body) = http_get(addr, "/metrics", &[("Accept", accept)]).await;
        assert_eq!(status, expected_status, "Accept: {accept}");
        if status == 200 {
            assert_eq!(
                headers.contains("application/openmetrics-text"),
                openmetrics,
                "Accept: {accept}"
            );
            assert_eq!(body.ends_with("# EOF\n"), openmetrics, "Accept: {accept}");
        }
    }
    let (status, headers, _) = http_get(
        addr,
        "/metrics",
        &[
            ("Accept", "application/openmetrics-text;q=0.1"),
            ("Accept", "text/plain;version=0.0.4;q=0.9"),
        ],
    )
    .await;
    assert_eq!(status, 200);
    assert!(headers.contains("text/plain; version=0.0.4"));
    tx.send(true).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn incomplete_metrics_headers_expire() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let server = tokio::spawn(MetricsServer::run_with_listener(
        listener,
        Arc::new(MetricsRegistry::new()),
        rx,
    ));
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost:")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(7), stream.read_to_end(&mut buf))
        .await
        .expect("partial request must expire");
    assert!(result.is_ok() || result.unwrap_err().kind() == io::ErrorKind::ConnectionReset);
    assert_eq!(buf, <[u8; 0]>::default());
    tx.send(true).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn header_deadline_is_not_extended_by_slow_trickle() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let server = tokio::spawn(MetricsServer::run_with_listener(
        listener,
        Arc::new(MetricsRegistry::new()),
        rx,
    ));
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost:")
        .await
        .unwrap();
    // Further bytes before each idle interval must not replenish the total
    // five-second request-header budget.
    for _ in 0..2 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        stream.write_all(b"x").await.unwrap();
    }
    let mut buf = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf))
        .await
        .expect("total header deadline must close trickling peer");
    assert!(result.is_ok() || result.unwrap_err().kind() == io::ErrorKind::ConnectionReset);
    tx.send(true).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn incomplete_metrics_request_bodies_do_not_retain_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let server = tokio::spawn(MetricsServer::run_with_listener(
        listener,
        Arc::new(MetricsRegistry::new()),
        rx,
    ));
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\nx")
        .await
        .unwrap();
    // GET handlers do not consume bodies. Hyper closes rather than indefinitely
    // draining an unread, incomplete body, so body trickle cannot retain a task.
    let mut buf = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf))
        .await
        .expect("incomplete body must not retain socket");
    assert!(result.is_ok() || result.unwrap_err().kind() == io::ErrorKind::ConnectionReset);
    tx.send(true).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn saturated_metrics_connections_resume_after_owned_tasks_finish() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = watch::channel(false);
    let server = tokio::spawn(MetricsServer::run_with_listener(
        listener,
        Arc::new(MetricsRegistry::new()),
        rx,
    ));
    let mut stalled = Vec::new();
    for _ in 0..64 {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        stalled.push(stream);
    }
    let mut next = TcpStream::connect(addr).await.unwrap();
    next.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), next.read_to_end(&mut response))
            .await
            .is_err(),
        "excess connection must wait for a bounded slot"
    );
    drop(stalled);
    tokio::time::timeout(Duration::from_secs(2), next.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    tx.send(true).unwrap();
    server.await.unwrap().unwrap();
}
