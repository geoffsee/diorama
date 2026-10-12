use std::sync::Arc;
use std::time::Duration;

use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};

use super::service::WebhookService;

pub const COMPONENT_WEBHOOK: &str = "webhook";
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_mins(1);

#[derive(Clone, Debug)]
pub struct WebhookAdapter {
    service: Arc<WebhookService>,
}

impl WebhookAdapter {
    #[must_use]
    pub fn new(service: Arc<WebhookService>) -> Self {
        Self { service }
    }

    pub fn registration(
        id: impl Into<String>,
        service: Arc<WebhookService>,
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

impl Adapter for WebhookAdapter {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            // 1. Check prerequisites (certificates, keys, apiserver connectivity)
            if let Err(err) = self.service.check_prerequisites().await {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // 2. Start service and register webhook
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
                        code: "webhook-readiness-failed",
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
                    code: "webhook-readiness-rejected",
                });
            }

            // 5. Await supervisor stop phase
            loop {
                match context.changed().await {
                    StopPhase::Running => {},
                    StopPhase::Graceful | StopPhase::Force => {
                        self.service.stop().await;
                        break;
                    },
                }
            }

            Ok(())
        })
    }
}
