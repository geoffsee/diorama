use std::time::Duration;

use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};

use crate::service::ControllerManagerService;

pub const COMPONENT_CONTROLLER_MANAGER: &str = "controller-manager";
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_mins(1);
pub const DEFAULT_RECONCILE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub struct ControllerManagerAdapter {
    service: ControllerManagerService,
    reconcile_interval: Duration,
}

impl ControllerManagerAdapter {
    #[must_use]
    pub fn new(service: ControllerManagerService) -> Self {
        Self {
            service,
            reconcile_interval: DEFAULT_RECONCILE_INTERVAL,
        }
    }

    #[must_use]
    pub fn with_reconcile_interval(mut self, interval: Duration) -> Self {
        self.reconcile_interval = interval;
        self
    }

    #[must_use]
    pub fn reconcile_interval(&self) -> Duration {
        self.reconcile_interval
    }

    pub fn registration(
        id: impl Into<String>,
        service: ControllerManagerService,
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

impl Adapter for ControllerManagerAdapter {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            // 1. Check prerequisites (PKI credentials, configuration, API server readiness)
            if let Err(err) = self.service.check_prerequisites().await {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // 2. Start service
            if let Err(err) = self.service.start().await {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // 3. Check readiness
            match self.service.check_readiness().await {
                Ok(report) if report.is_healthy => {},
                Ok(_) => {
                    return Err(AdapterError {
                        code: "controller-readiness-failed",
                    });
                },
                Err(err) => {
                    return Err(AdapterError {
                        code: err.diagnostic_code(),
                    });
                },
            }

            // 4. Signal readiness to supervisor coordinator
            if !context.ready() {
                return Err(AdapterError {
                    code: "controller-readiness-rejected",
                });
            }

            // 5. Periodic reconciliation until supervisor stops us
            let mut ticker = tokio::time::interval(self.reconcile_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    biased;
                    phase = context.changed() => {
                        if matches!(phase, StopPhase::Graceful | StopPhase::Force) {
                            self.service.stop();
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        let _ = self.service.reconcile_once().await;
                    }
                }
            }

            Ok(())
        })
    }
}
