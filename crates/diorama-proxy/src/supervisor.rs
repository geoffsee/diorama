use std::time::Duration;

use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};

use crate::service::ProxyService;

pub const COMPONENT_PROXY: &str = "kube-proxy";
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_mins(1);

/// Supervisor adapter for kube-proxy service.
#[derive(Clone, Debug)]
pub struct ProxyAdapter {
    service: ProxyService,
}

impl ProxyAdapter {
    #[must_use]
    pub fn new(service: ProxyService) -> Self {
        Self { service }
    }

    pub fn registration(
        id: impl Into<String>,
        service: ProxyService,
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

impl Adapter for ProxyAdapter {
    fn run(mut self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            // 1. Check prerequisites (backend detection, /proc/sys, credentials)
            if let Err(err) = self.service.check_prerequisites() {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // 2. Start service
            if let Err(err) = self.service.start() {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // 3. Check readiness
            match self.service.check_readiness() {
                Ok(report) if report.is_healthy => {},
                Ok(_) => {
                    return Err(AdapterError {
                        code: "proxy-readiness-failed",
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
                    code: "proxy-readiness-rejected",
                });
            }

            // 5. Await supervisor stop phase
            loop {
                match context.changed().await {
                    StopPhase::Running => {},
                    StopPhase::Graceful | StopPhase::Force => {
                        self.service.stop();
                        break;
                    },
                }
            }

            Ok(())
        })
    }
}
