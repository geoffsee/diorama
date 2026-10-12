//! Supervisor adapter for the local configuration HTTP API server.

use std::time::Duration;
use tokio::sync::watch;

use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};

use super::server::ConfigApiServer;

pub const COMPONENT_CONFIG_API: &str = "configapi";
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Supervisor adapter for the configuration HTTP API server over a local Unix domain socket.
#[derive(Clone, Debug)]
pub struct ConfigApiAdapter {
    server: ConfigApiServer,
}

impl ConfigApiAdapter {
    #[must_use]
    pub fn new(server: ConfigApiServer) -> Self {
        Self { server }
    }

    pub fn registration(
        id: impl Into<String>,
        server: ConfigApiServer,
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
        Registration::new(spec, Self::new(server))
    }
}

impl Adapter for ConfigApiAdapter {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            let listener = match self.server.bind() {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("failed to bind config api socket: {e}");
                    return Err(AdapterError {
                        code: "config_api_bind_error",
                    });
                },
            };

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            if !context.ready() {
                return Err(AdapterError {
                    code: "config_api_readiness_rejected",
                });
            }

            // Keep the server in this adapter's future. Supervisor cancellation
            // drops its listener guard and aborts its owned connection tasks.
            let server = self.server.run_with_listener(listener, shutdown_rx);
            tokio::pin!(server);
            loop {
                tokio::select! {
                    result = &mut server => {
                        return result.map_err(|_| AdapterError { code: "config_api_server_error" });
                    }
                    phase = context.changed() => {
                        if phase != StopPhase::Running {
                            let _ = shutdown_tx.send(true);
                            return server.await.map_err(|_| AdapterError { code: "config_api_server_error" });
                        }
                    }
                }
            }
        })
    }
}
