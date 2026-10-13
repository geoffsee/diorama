use std::collections::BTreeMap;
use std::future::Future;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use diorama::lifecycle_logs::{
    LifecycleRenderer, LogLevel, PublisherStatus, consume_lifecycle, log_channel,
};
use diorama::lifecycle_sink::{FlushPolicy, SinkOutcome, configured_log_level, deliver_logs};
use diorama_config::{
    EnvironmentMode, ExplicitFlags, HostContext, ValidatedConfig, decode, resolve_layers,
};
use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopCause, Supervisor, stop_channel,
};
use serde_json::Value;
use tokio::sync::oneshot;

#[derive(Clone)]
struct Probe(Arc<Mutex<ProbeState>>);
struct ProbeState {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    fail_write_at: Option<usize>,
    fail_flush_at: Option<usize>,
}
impl Probe {
    fn new(fail_write_at: Option<usize>, fail_flush_at: Option<usize>) -> Self {
        Self(Arc::new(Mutex::new(ProbeState {
            bytes: Vec::new(),
            writes: 0,
            flushes: 0,
            fail_write_at,
            fail_flush_at,
        })))
    }
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("probe lock").bytes.clone()).expect("utf-8 frames")
    }
    fn counts(&self) -> (usize, usize) {
        let state = self.0.lock().expect("probe lock");
        (state.writes, state.flushes)
    }
}
impl Write for Probe {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut state = self.0.lock().expect("probe lock");
        let attempt = state.writes + 1;
        if state.fail_write_at == Some(attempt) {
            state.writes = attempt;
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "write failed"));
        }
        state.bytes.extend_from_slice(buffer);
        state.writes = attempt;
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.0.lock().expect("probe lock");
        let attempt = state.flushes + 1;
        if state.fail_flush_at == Some(attempt) {
            state.flushes = attempt;
            return Err(io::Error::new(io::ErrorKind::Interrupted, "flush failed"));
        }
        state.flushes = attempt;
        Ok(())
    }
}

fn config(debug: bool) -> ValidatedConfig {
    resolve_layers(
        Some(decode(&format!("logging:\n  debug: {debug}\n")).expect("decode")),
        &BTreeMap::new(),
        &ExplicitFlags::default(),
        EnvironmentMode::Include,
        &HostContext {
            cpu_count: 8,
            architecture: "arm64".into(),
            detected_container_mode: false,
        },
    )
    .expect("resolve")
    .validated
}

struct Worker<F>(F);
impl<F, Fut> Adapter for Worker<F>
where
    F: FnOnce(AdapterContext) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), AdapterError>> + Send + 'static,
{
    fn run(self: Box<Self>, context: AdapterContext) -> AdapterFuture {
        Box::pin((self.0)(context))
    }
}
fn registration<F, Fut>(id: &str, policy: FailurePolicy, run: F) -> Registration
where
    F: FnOnce(AdapterContext) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), AdapterError>> + Send + 'static,
{
    Registration::new(
        ComponentSpec {
            id: id.into(),
            prerequisites: vec![],
            kind: ComponentKind::LongRunning,
            failure_policy: policy,
            startup_timeout: Duration::from_mins(1),
        },
        Worker(run),
    )
}

async fn deliver_empty(
    level: LogLevel,
    policy: FlushPolicy,
    probe: Probe,
) -> diorama::lifecycle_sink::SinkReport {
    let (supervisor, observer) = Supervisor::new(vec![]).expect("register").with_observer();
    let (sender, receiver) = log_channel(8).expect("channel");
    let logging = tokio::spawn(consume_lifecycle(
        observer,
        LifecycleRenderer::new(level),
        sender,
    ));
    let delivery = tokio::spawn(deliver_logs(receiver, probe, policy));
    let (_stop, control) = stop_channel();
    supervisor.run(control).await;
    let delivered = logging.await.expect("consumer");
    assert_eq!(delivered.publisher, PublisherStatus::Finished);
    assert_eq!(delivered.dropped_full, 0);
    assert_eq!(delivered.render_error, None);
    delivery.await.expect("sink worker")
}

#[tokio::test]
async fn on_close_flushes_an_empty_stream_and_each_frame_does_not() {
    let (sender, receiver) = log_channel(1).expect("channel");
    drop(sender);
    let probe = Probe::new(None, None);
    let report = deliver_logs(receiver, probe.clone(), FlushPolicy::OnClose).await;
    assert_eq!(report.written, 0);
    assert_eq!(report.flushed_frames, 0);
    assert_eq!(report.outcome, SinkOutcome::Closed);
    assert_eq!(probe.counts(), (0, 1));

    let (sender, receiver) = log_channel(1).expect("channel");
    drop(sender);
    let failed = Probe::new(None, Some(1));
    let report = deliver_logs(receiver, failed.clone(), FlushPolicy::OnClose).await;
    assert_eq!(report.written, 0);
    assert_eq!(report.flushed_frames, 0);
    assert_eq!(
        report.outcome,
        SinkOutcome::Flush(io::ErrorKind::Interrupted)
    );
    assert_eq!(failed.counts(), (0, 1));

    let (sender, receiver) = log_channel(1).expect("channel");
    drop(sender);
    let each = Probe::new(None, None);
    let report = deliver_logs(receiver, each.clone(), FlushPolicy::EachFrame).await;
    assert_eq!(report.outcome, SinkOutcome::Closed);
    assert_eq!(each.counts(), (0, 0));
}

#[test]
fn resolved_debug_setting_selects_the_renderer_level() {
    assert_eq!(configured_log_level(&config(false)), LogLevel::Info);
    assert_eq!(configured_log_level(&config(true)), LogLevel::Debug);
}

#[tokio::test]
async fn each_frame_flush_preserves_exact_frames_and_on_close_flushes_once() {
    let each = Probe::new(None, None);
    let each_report = deliver_empty(LogLevel::Info, FlushPolicy::EachFrame, each.clone()).await;
    let text = each.text();
    let frames: Vec<_> = text.lines().collect();
    assert!(frames.len() > 1, "{text}");
    assert!(text.ends_with('\n'));
    let frame_count = u64::try_from(frames.len()).expect("frame count");
    assert_eq!(each_report.written, frame_count);
    assert_eq!(each_report.flushed_frames, frame_count);
    assert_eq!(each_report.outcome, SinkOutcome::Closed);
    assert_eq!(each.counts(), (frames.len(), frames.len()));
    for frame in &frames {
        let value: Value = serde_json::from_str(frame).expect("json");
        assert_ne!(value["level"], "debug");
    }

    let on_close = Probe::new(None, None);
    let on_close_report =
        deliver_empty(LogLevel::Info, FlushPolicy::OnClose, on_close.clone()).await;
    assert_eq!(on_close_report.written, each_report.written);
    assert_eq!(on_close_report.flushed_frames, each_report.written);
    assert_eq!(on_close_report.outcome, SinkOutcome::Closed);
    assert_eq!(on_close.counts().1, 1);
}

#[tokio::test]
async fn write_and_flush_failures_stop_without_attempting_later_frames() {
    let write_probe = Probe::new(Some(2), None);
    let write_report =
        deliver_empty(LogLevel::Info, FlushPolicy::EachFrame, write_probe.clone()).await;
    assert_eq!(write_report.written, 1);
    assert_eq!(write_report.flushed_frames, 1);
    assert_eq!(
        write_report.outcome,
        SinkOutcome::Write(io::ErrorKind::BrokenPipe)
    );
    assert_eq!(write_probe.text().lines().count(), 1);

    let flush_probe = Probe::new(None, Some(1));
    let flush_report =
        deliver_empty(LogLevel::Info, FlushPolicy::EachFrame, flush_probe.clone()).await;
    assert_eq!(flush_report.written, 1);
    assert_eq!(flush_report.flushed_frames, 0);
    assert_eq!(
        flush_report.outcome,
        SinkOutcome::Flush(io::ErrorKind::Interrupted)
    );
    assert_eq!(flush_probe.text().lines().count(), 1);

    let close_probe = Probe::new(None, Some(1));
    let close_report =
        deliver_empty(LogLevel::Info, FlushPolicy::OnClose, close_probe.clone()).await;
    assert!(close_report.written > 1);
    assert_eq!(close_report.flushed_frames, 0);
    assert_eq!(
        close_report.outcome,
        SinkOutcome::Flush(io::ErrorKind::Interrupted)
    );
    assert_eq!(
        u64::try_from(close_probe.text().lines().count()).expect("line count"),
        close_report.written
    );
}

fn setup_test_cluster(
    dir: &tempfile::TempDir,
) -> (
    diorama_apiserver::ApiserverService,
    diorama_apiserver::client::KubernetesApiClient,
) {
    let node_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");
    std::fs::create_dir_all(&datastore_dir).unwrap();

    let pki_config = diorama_pki::cluster::ClusterPkiConfig::new(
        pki_dir.clone(),
        "test-node".to_string(),
        node_ip,
    );
    let pki = diorama_pki::cluster::ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let (engine, _) = diorama_datastore::DatastoreEngine::open(
        diorama_datastore::DatastoreConfig::new(datastore_dir),
    )
    .unwrap();
    let storage = diorama_apiserver::KubernetesStorage::new(engine.client(), "/registry");

    let apiserver_config = diorama_apiserver::ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_service = diorama_apiserver::ApiserverService::new(apiserver_config, storage);
    let client = apiserver_service.admin_client();

    (apiserver_service, client)
}

#[tokio::test]
async fn optional_failure_reaches_the_sink_while_the_healthy_worker_answers() {
    let temp = tempfile::TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let (fail, failed) = oneshot::channel();
    let secret = "private-adapter-token".to_string();
    let (supervisor, observer) = Supervisor::new(vec![
        registration("optional", FailurePolicy::Degrade, move |_| async move {
            failed.await.expect("failure signal");
            assert_ne!(secret, "");
            Err(AdapterError {
                code: "optional_failed",
            })
        }),
        diorama_apiserver::ApiserverAdapter::registration(
            "apiserver",
            apiserver,
            vec![],
            Duration::from_secs(5),
        ),
    ])
    .expect("register")
    .with_observer();
    let probe = Probe::new(None, None);
    let (sender, receiver) = log_channel(64).expect("channel");
    let logging = tokio::spawn(consume_lifecycle(
        observer,
        LifecycleRenderer::new(configured_log_level(&config(false))),
        sender,
    ));
    let delivery = tokio::spawn(deliver_logs(
        receiver,
        probe.clone(),
        FlushPolicy::EachFrame,
    ));
    let (stop, control) = stop_channel();
    let running = tokio::spawn(supervisor.run(control));
    fail.send(()).expect("signal failure");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if probe.text().contains("\"event\":\"component_failure\"") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("failure frame");

    // Live Kubernetes API operations succeed while optional component is degraded:
    client
        .create_namespace("probe-ns")
        .await
        .expect("create namespace");
    let mut data = BTreeMap::new();
    data.insert("key".to_string(), "value".to_string());
    client
        .create_configmap("probe-ns", "probe-cm", data)
        .await
        .expect("create configmap");
    let cm = client
        .get_configmap("probe-ns", "probe-cm")
        .await
        .expect("get configmap");
    assert_eq!(cm["data"]["key"], "value");

    stop.stop();
    let report = running.await.expect("supervisor");
    assert_eq!(report.cause, StopCause::Requested);
    let delivered = logging.await.expect("consumer");
    let sink = delivery.await.expect("sink");
    assert_eq!(delivered.publisher, PublisherStatus::Finished);
    assert_eq!(delivered.dropped_full, 0);
    assert_eq!(sink.outcome, SinkOutcome::Closed);
    assert_eq!(sink.written, sink.flushed_frames);
    let text = probe.text();
    assert!(!text.contains("private-adapter-token"));
    assert!(text.contains("\"detail_code\":\"optional_failed\""));
    assert!(text.contains("\"event\":\"supervisor_degraded\""));
    assert!(!text.contains("\"level\":\"debug\""));
}
