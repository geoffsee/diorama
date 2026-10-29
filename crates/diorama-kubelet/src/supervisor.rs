use std::io::Write;
use std::time::Duration;

use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};

use crate::service::KubeletService;

pub const COMPONENT_KUBELET: &str = "kubelet";
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_mins(1);
/// How often the kubelet lists pods and compares them with the runtime.
pub const DEFAULT_RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
/// How often the node lease is renewed.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct KubeletAdapter {
    service: KubeletService,
    reconcile_interval: Duration,
    heartbeat_interval: Duration,
}

impl KubeletAdapter {
    #[must_use]
    pub fn new(service: KubeletService) -> Self {
        Self {
            service,
            reconcile_interval: DEFAULT_RECONCILE_INTERVAL,
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
        }
    }

    #[must_use]
    pub fn with_reconcile_interval(mut self, interval: Duration) -> Self {
        self.reconcile_interval = interval;
        self
    }

    #[must_use]
    pub fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    pub fn registration(
        id: impl Into<String>,
        service: KubeletService,
        prerequisites: Vec<String>,
        timeout: Duration,
    ) -> Registration {
        let spec = ComponentSpec {
            id: id.into(),
            prerequisites,
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout: timeout,
        };
        Registration::new(spec, Self::new(service))
    }
}

impl Adapter for KubeletAdapter {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            // 1. Start service (runs prerequisites check and performs registration)
            if let Err(err) = self.service.start().await {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // Registration is live before CNI becomes ready. Host-network bootstrap
            // workloads and heartbeats must continue while Node Ready is false.
            // 3. Signal readiness to supervisor coordinator
            if !context.ready() {
                return Err(AdapterError {
                    code: "kubelet-readiness-rejected",
                });
            }

            // 4. Reconcile pods and heartbeat until the supervisor stops us.
            let mut reconcile = tokio::time::interval(self.reconcile_interval);
            reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            let heartbeat_handle = tokio::spawn(run_heartbeat_loop(
                self.service.clone(),
                self.heartbeat_interval,
            ));

            let changed = std::sync::Arc::new(tokio::sync::Notify::new());
            let signal = changed.clone();
            let client = self.service.client();
            let watch_handle = tokio::spawn(run_watch_loop(client, signal));
            loop {
                tokio::select! {
                    biased;
                    phase = context.changed() => {
                        if matches!(phase, StopPhase::Graceful | StopPhase::Force) {
                            break;
                        }
                    }
                    () = async { tokio::select! { _ = reconcile.tick() => {}, () = changed.notified() => {} } } => {
                        match self.service.reconcile_once().await {
                            Ok(report) if report.bound + report.failed + report.orphans_stopped > 0 => {
                                log_event("kubelet_reconcile", &format!(
                                    "\"bound\":{},\"synced\":{},\"failed\":{},\"orphans_stopped\":{}",
                                    report.bound, report.synced, report.failed, report.orphans_stopped
                                ));
                            }
                            Ok(_) => {}
                            Err(err) => log_event(
                                "kubelet_reconcile_failed",
                                &format!("\"code\":\"{}\"", err.diagnostic_code()),
                            ),
                        }
                    }
                }
            }
            watch_handle.abort();
            let _ = watch_handle.await;
            heartbeat_handle.abort();
            let _ = heartbeat_handle.await;
            self.service.stop();
            Ok(())
        })
    }
}

fn log_event(event: &str, fields: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "{{\"schema\":1,\"level\":\"info\",\"component\":\"kubelet\",\"event\":\"{event}\",{fields}}}"
    );
}

async fn run_heartbeat_loop(service: KubeletService, interval: Duration) {
    let mut heartbeat = tokio::time::interval(interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.reset();
    loop {
        heartbeat.tick().await;
        if let Err(err) = service.heartbeat().await {
            log_event(
                "kubelet_heartbeat_failed",
                &format!("\"code\":\"{}\"", err.diagnostic_code()),
            );
        }
    }
}

async fn run_watch_loop(client: crate::api::NodeApi, signal: std::sync::Arc<tokio::sync::Notify>) {
    loop {
        if client.watch_pods().await.is_err() {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        signal.notify_one();
    }
}
