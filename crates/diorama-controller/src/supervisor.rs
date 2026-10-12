use std::time::Duration;

use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};

use crate::service::ControllerManagerService;

pub const COMPONENT_CONTROLLER_MANAGER: &str = "controller-manager";
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_mins(1);

#[derive(Clone, Debug)]
pub struct ControllerManagerAdapter {
    service: ControllerManagerService,
    sync_period: Duration,
}

impl ControllerManagerAdapter {
    #[must_use]
    pub fn new(service: ControllerManagerService) -> Self {
        Self {
            service,
            sync_period: Duration::from_millis(500),
        }
    }

    #[must_use]
    pub fn with_sync_period(mut self, sync_period: Duration) -> Self {
        self.sync_period = sync_period;
        self
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

            // Initial reconciliation pass
            let _ = self.service.reconcile_all().await;

            // 5. Periodic reconciliation loop while monitoring stop phase
            let mut ticker = tokio::time::interval(self.sync_period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let _ = self.service.reconcile_all().await;
                    }
                    phase = context.changed() => {
                        match phase {
                            StopPhase::Running => {},
                            StopPhase::Graceful | StopPhase::Force => {
                                self.service.stop();
                                break;
                            },
                        }
                    }
                }
            }

            Ok(())
        })
    }
}
