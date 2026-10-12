//! Supervisor adapter for operational metrics and health HTTP endpoint.

use std::sync::Arc;
use std::time::Duration;

use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};
use tokio::sync::watch;

use super::registry::MetricsRegistry;
use super::server::MetricsServer;

pub const COMPONENT_METRICS: &str = "metrics";
pub const DEFAULT_METRICS_TIMEOUT: Duration = Duration::from_secs(30);

/// Supervisor adapter for operational metrics HTTP endpoint.
#[derive(Clone, Debug)]
pub struct MetricsAdapter {
    bind_address: String,
    registry: Arc<MetricsRegistry>,
}

impl MetricsAdapter {
    #[must_use]
    pub fn new(bind_address: impl Into<String>, registry: Arc<MetricsRegistry>) -> Self {
        Self {
            bind_address: bind_address.into(),
            registry,
        }
    }

    #[must_use]
    pub fn bind_address(&self) -> &str {
        &self.bind_address
    }

    #[must_use]
    pub fn registry(&self) -> &Arc<MetricsRegistry> {
        &self.registry
    }

    /// Constructs a supervisor registration configured with `FailurePolicy::Degrade`
    /// so bind failures are observable and nonfatal to the rest of the node.
    pub fn registration(
        id: impl Into<String>,
        adapter: Self,
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
        Registration::new(spec, adapter)
    }
}

impl Adapter for MetricsAdapter {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            // 1. Attempt to bind to configured address synchronously inside the adapter run
            let listener = match tokio::net::TcpListener::bind(&self.bind_address).await {
                Ok(l) => l,
                Err(err) => {
                    eprintln!(
                        "metrics HTTP endpoint failed to bind to {}: {err}",
                        self.bind_address
                    );
                    return Err(AdapterError {
                        code: "metrics_bind_failed",
                    });
                },
            };

            // 2. Signal readiness to supervisor
            if !context.ready() {
                return Err(AdapterError {
                    code: "metrics_readiness_rejected",
                });
            }

            // 3. Run server until stop phase
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let registry = self.registry.clone();
            // Own the server future directly: dropping/forcing this adapter drops
            // its listener and aborts its JoinSet, rather than detaching a task.
            let server = MetricsServer::run_with_listener(listener, registry, shutdown_rx);
            tokio::pin!(server);

            loop {
                let phase = tokio::select! {
                    result = &mut server => {
                        return result.map_err(|_| AdapterError { code: "metrics_server_failed" });
                    }
                    phase = context.changed() => phase,
                };
                match phase {
                    StopPhase::Running => {},
                    StopPhase::Graceful | StopPhase::Force => {
                        let _ = shutdown_tx.send(true);
                        break;
                    },
                }
            }

            // The server bounds draining itself and joins aborted connections.
            server.await.map_err(|_| AdapterError {
                code: "metrics_server_failed",
            })
        })
    }
}
