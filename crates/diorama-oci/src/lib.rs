//! Supervised, in-process oci-cri runtime. Call [`startup`] at the executable
//! entry point before creating threads. The native engine requires Linux.

use std::sync::Arc;
use std::time::Duration;

use diorama_cri::{RuntimeEndpoints, probe_cri_readiness};
use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, StopPhase,
};

pub use oci_cri::{Config, startup};

pub const COMPONENT_OCI_CRI: &str = "oci-cri";

/// Owns the CRI and streaming listeners. Shutdown preserves workloads; kubelet
/// must finish its workload cleanup before this component is stopped.
pub struct OciCriService {
    config: Config,
    engine: Option<Arc<dyn oci_cri::engine::Engine>>,
    startup_timeout: Duration,
}

impl std::fmt::Debug for OciCriService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciCriService")
            .field("config", &self.config)
            .field("startup_timeout", &self.startup_timeout)
            .finish_non_exhaustive()
    }
}

impl OciCriService {
    pub fn new(config: Config, startup_timeout: Duration) -> Self {
        Self {
            config,
            engine: None,
            startup_timeout,
        }
    }

    /// Supply an engine for protocol testing or a custom execution backend.
    #[must_use]
    pub fn with_engine(mut self, engine: Arc<dyn oci_cri::engine::Engine>) -> Self {
        self.engine = Some(engine);
        self
    }

    async fn serve(
        self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<(), oci_cri::Error> {
        if let Some(engine) = self.engine {
            return oci_cri::server::serve_with_engine_until(self.config, engine, shutdown).await;
        }
        #[cfg(target_os = "linux")]
        {
            oci_cri::server::serve_until(self.config, shutdown).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(oci_cri::Error::new(
                oci_cri::ErrorCode::Unsupported,
                "managed oci-cri requires Linux",
                "",
            ))
        }
    }

    pub fn component_spec(startup_timeout: Duration) -> ComponentSpec {
        ComponentSpec {
            id: COMPONENT_OCI_CRI.into(),
            prerequisites: Vec::new(),
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout,
        }
    }
}

impl Adapter for OciCriService {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            if context.stop_phase() != StopPhase::Running {
                return Ok(());
            }
            let endpoint =
                diorama_cri::CriEndpoint::from_path(&self.config.socket).map_err(|_| {
                    AdapterError {
                        code: "oci_cri_invalid_socket",
                    }
                })?;
            let endpoints = RuntimeEndpoints::single(endpoint);
            let startup_timeout = self.startup_timeout;
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let shutdown = async {
                let _ = stopped.await;
            };
            let server = self.serve(shutdown);
            let readiness =
                probe_cri_readiness(&endpoints, startup_timeout, Duration::from_millis(25));
            tokio::pin!(server);
            tokio::pin!(readiness);
            let mut ready = false;
            let failure = loop {
                tokio::select! {
                    result = &mut server => {
                        return result.map_err(|_| AdapterError { code: "oci_cri_server_failed" });
                    }
                    result = &mut readiness, if !ready => {
                        if result.is_err() {
                            break Some(AdapterError { code: "oci_cri_readiness_failed" });
                        }
                        ready = true;
                        context.ready();
                    }
                    phase = context.changed() => {
                        if phase != StopPhase::Running {
                            break None;
                        }
                    }
                }
            };
            let _ = stop.send(());
            server.await.map_err(|_| AdapterError {
                code: "oci_cri_shutdown_failed",
            })?;
            failure.map_or(Ok(()), Err)
        })
    }
}
