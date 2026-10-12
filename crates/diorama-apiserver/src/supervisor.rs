use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};
use std::io::Write;
use std::time::Duration;

use crate::service::ApiserverService;

pub const COMPONENT_APISERVER: &str = "apiserver";
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_mins(1);

#[derive(Clone, Debug)]
pub struct ApiserverAdapter {
    service: ApiserverService,
}

impl ApiserverAdapter {
    pub fn new(service: ApiserverService) -> Self {
        Self { service }
    }

    pub fn registration(
        id: impl Into<String>,
        service: ApiserverService,
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

impl Adapter for ApiserverAdapter {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            // 1. Check prerequisites (PKI credentials and storage availability)
            if let Err(err) = self.service.check_prerequisites().await {
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
            match self.service.check_readiness().await {
                Ok(report) if report.is_healthy => {},
                Ok(_) => {
                    self.service.stop();
                    return Err(AdapterError {
                        code: "apiserver-readiness-failed",
                    });
                },
                Err(err) => {
                    self.service.stop();
                    return Err(AdapterError {
                        code: err.diagnostic_code(),
                    });
                },
            }

            let listener = match crate::http::bind_listener(self.service.config()).await {
                Ok(listener) => listener,
                Err(err) => {
                    self.service.stop();
                    return Err(AdapterError {
                        code: err.diagnostic_code(),
                    });
                },
            };
            if let Ok(addr) = listener.local_addr() {
                self.service.set_bound_addr(addr);
                update_admin_kubeconfig(&self.service.config().pki_dir, addr);
                let _ = writeln!(
                    std::io::stderr(),
                    "{{\"schema\":1,\"level\":\"info\",\"event\":\"apiserver_listening\",\"address\":\"https://{addr}\"}}"
                );
            }

            // 4. Signal readiness only after the HTTPS port is bound.
            if !context.ready() {
                self.service.stop();
                return Err(AdapterError {
                    code: "apiserver-readiness-rejected",
                });
            }

            // 5. Serve until shutdown.
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let service = self.service.clone();
            let serve = crate::http::serve(listener, service, shutdown_rx);
            tokio::pin!(serve);
            let result = loop {
                tokio::select! {
                    biased;
                    outcome = &mut serve => {
                        break outcome;
                    }
                    phase = context.changed() => {
                        if matches!(phase, StopPhase::Graceful | StopPhase::Force) {
                            let _ = shutdown_tx.send(true);
                            break (&mut serve).await;
                        }
                    }
                }
            };
            self.service.stop();
            result.map_err(|err| AdapterError {
                code: err.diagnostic_code(),
            })
        })
    }
}

fn update_admin_kubeconfig(pki_dir: &std::path::Path, addr: std::net::SocketAddr) {
    let admin_kubeconfig = pki_dir.join("admin.kubeconfig");
    let Ok(content) = std::fs::read_to_string(&admin_kubeconfig) else {
        return;
    };
    let updated = content
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("server:") {
                format!("    server: https://{addr}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let _ = std::fs::write(&admin_kubeconfig, format!("{updated}\n"));
}
