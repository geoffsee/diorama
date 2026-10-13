use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};

use crate::service::LocalPathService;

pub const COMPONENT_LOCAL_PATH: &str = "local-path-provisioner";

fn spawn_volume_binder(service: LocalPathService, stop: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        loop {
            interval.tick().await;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            service.bind_pending_volumes().await;
        }
    });
}
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_mins(1);

/// Supervisor adapter for the local-path storage provisioner.
///
/// Uses `FailurePolicy::Degrade` so optional storage provisioner failures
/// leave the core Kubernetes control-plane healthy while reporting diagnostic status.
#[derive(Clone, Debug)]
pub struct LocalPathAdapter {
    service: LocalPathService,
}

impl LocalPathAdapter {
    #[must_use]
    pub fn new(service: LocalPathService) -> Self {
        Self { service }
    }

    pub fn registration(
        id: impl Into<String>,
        service: LocalPathService,
        prerequisites: Vec<String>,
        timeout: Duration,
    ) -> Registration {
        let spec = ComponentSpec {
            id: id.into(),
            prerequisites,
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Degrade,
            startup_timeout: timeout,
        };
        Registration::new(spec, Self::new(service))
    }
}

impl Adapter for LocalPathAdapter {
    #[allow(clippy::too_many_lines)]
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            // Disabled mode: immediately ready without deploying components
            if !self.service.config().enabled {
                if !context.ready() {
                    return Err(AdapterError {
                        code: "storage-readiness-rejected",
                    });
                }

                while context.changed().await == StopPhase::Running {}
                self.service.stop();
                return Ok(());
            }

            // 1. Check prerequisites (API server connectivity)
            if let Err(err) = self.service.check_prerequisites().await {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // 2. Start service and reconcile resources
            if let Err(err) = self.service.start().await {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // Volume binding is independent of the provisioner pod becoming Ready.
            // A readiness timeout still degrades the addon, and binding continues.
            let stop = Arc::new(AtomicBool::new(false));
            spawn_volume_binder(self.service.clone(), Arc::clone(&stop));

            // 3. Wait for readiness
            let timeout = self.service.config().readiness_timeout;
            if let Err(err) = self.service.wait_for_readiness(timeout).await {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // 4. Signal readiness to supervisor coordinator
            if !context.ready() {
                stop.store(true, Ordering::Relaxed);
                return Err(AdapterError {
                    code: "storage-readiness-rejected",
                });
            }

            // 5. Await supervisor stop while the binder keeps running.
            loop {
                match context.changed().await {
                    StopPhase::Running => {},
                    StopPhase::Graceful | StopPhase::Force => {
                        stop.store(true, Ordering::Relaxed);
                        self.service.stop();
                        break;
                    },
                }
            }

            Ok(())
        })
    }
}
