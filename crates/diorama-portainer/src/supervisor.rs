use std::time::Duration;

use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};

use crate::service::PortainerService;

/// Canonical supervisor component identifier for the Portainer Edge Agent.
pub const COMPONENT_PORTAINER: &str = "portainer-agent";

/// Default startup and readiness timeout for Portainer Edge Agent supervisor lifecycle.
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(90);

/// Supervisor adapter for the Portainer Edge Agent service.
///
/// Uses `FailurePolicy::Degrade` so optional Portainer Edge Agent failures
/// leave the core Kubernetes control-plane healthy while reporting diagnostic status.
#[derive(Clone, Debug)]
pub struct PortainerAdapter {
    service: PortainerService,
}

impl PortainerAdapter {
    /// Creates a new `PortainerAdapter` wrapping the given service.
    #[must_use]
    pub fn new(service: PortainerService) -> Self {
        Self { service }
    }

    /// Constructs a supervisor component registration with `FailurePolicy::Degrade`.
    pub fn registration(
        id: impl Into<String>,
        service: PortainerService,
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

impl Adapter for PortainerAdapter {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            // Disabled mode: immediately ready without deploying components
            if !self.service.config().is_enabled() {
                if !context.ready() {
                    return Err(AdapterError {
                        code: "portainer-readiness-rejected",
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

            // 2. Start service and reconcile resources (create-only bootstrap)
            if let Err(err) = self.service.start().await {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // 3. Wait for readiness
            let timeout = self.service.config().readiness_timeout;
            tokio::select! {
                biased;
                () = async {
                    while context.stop_phase() == StopPhase::Running {
                        context.changed().await;
                    }
                } => {
                    self.service.stop();
                    return Ok(());
                },
                result = self.service.wait_for_readiness(timeout) => {
                    result.map_err(|err| AdapterError { code: err.diagnostic_code() })?;
                },
            }

            // 4. Signal readiness to supervisor coordinator
            if !context.ready() {
                return Err(AdapterError {
                    code: "portainer-readiness-rejected",
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
