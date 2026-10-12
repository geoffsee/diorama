use std::time::Duration;

use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};

use crate::service::CoreDnsService;

pub const COMPONENT_COREDNS: &str = "coredns";
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(90);

/// Supervisor adapter for the `CoreDNS` service.
#[derive(Clone, Debug)]
pub struct CoreDnsAdapter {
    service: CoreDnsService,
}

impl CoreDnsAdapter {
    #[must_use]
    pub fn new(service: CoreDnsService) -> Self {
        Self { service }
    }

    pub fn registration(
        id: impl Into<String>,
        service: CoreDnsService,
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

impl Adapter for CoreDnsAdapter {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
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

            // 3. Wait for readiness
            let timeout = self.service.config().readiness_timeout;
            if let Err(err) = self.service.wait_for_readiness(timeout).await {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // 4. Signal readiness to supervisor coordinator
            if !context.ready() {
                return Err(AdapterError {
                    code: "dns-readiness-rejected",
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
