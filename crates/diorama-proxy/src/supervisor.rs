use std::time::Duration;

use diorama_apiserver::WatchEventType;
use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};

use crate::firewall::DataplaneReconciler;
use crate::routing::{
    endpoint_slice_from_value, extract_namespace_and_name_from_key, service_from_value,
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
    #[allow(clippy::too_many_lines, clippy::excessive_nesting)]
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

            // 4. Initial dataplane reconciliation / API synchronization
            let reconciler = DataplaneReconciler::new();
            if let Err(err) = self.service.sync_from_api(&reconciler).await {
                return Err(AdapterError {
                    code: err.diagnostic_code(),
                });
            }

            // 5. Signal readiness to supervisor coordinator
            if !context.ready() {
                return Err(AdapterError {
                    code: "proxy-readiness-rejected",
                });
            }

            // 6. Supervision loop: watch Kubernetes Services and EndpointSlices if client is available
            if let Some(client) = self.service.client().cloned() {
                let mut svc_watch = client.watch_resource("", "services", None).await.ok();
                let mut eps_watch = client
                    .watch_resource("discovery.k8s.io", "endpointslices", None)
                    .await
                    .ok();

                loop {
                    tokio::select! {
                        change = context.changed() => {
                            match change {
                                StopPhase::Running => {},
                                StopPhase::Graceful | StopPhase::Force => {
                                    self.service.stop();
                                    break;
                                },
                            }
                        }
                        evt = async {
                            if let Some(rx) = &mut svc_watch {
                                rx.recv().await
                            } else {
                                std::future::pending().await
                            }
                        } => {
                            match evt {
                                Ok(event) => {
                                    match event.event_type {
                                        WatchEventType::Put => {
                                            if let Some(svc) = serde_json::from_slice::<serde_json::Value>(&event.kv.value)
                                                .ok()
                                                .and_then(|val| service_from_value(&val).ok())
                                            {
                                                self.service.apply_service(svc).await;
                                                if let Err(err) = self.service.reconcile_dataplane(&reconciler, None).await {
                                                    tracing::warn!(
                                                        target: "kubeproxy::dataplane",
                                                        error = %err,
                                                        "failed to reconcile dataplane after service update"
                                                    );
                                                }
                                            }
                                        }
                                        WatchEventType::Delete => {
                                            if let Some((ns, name)) = extract_namespace_and_name_from_key(&event.kv.key) {
                                                self.service.remove_service(&ns, &name).await;
                                                if let Err(err) = self.service.reconcile_dataplane(&reconciler, None).await {
                                                    tracing::warn!(
                                                        target: "kubeproxy::dataplane",
                                                        error = %err,
                                                        "failed to reconcile dataplane after service delete"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                    let _ = self.service.sync_from_api(&reconciler).await;
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    svc_watch = None;
                                }
                            }
                        }
                        evt = async {
                            if let Some(rx) = &mut eps_watch {
                                rx.recv().await
                            } else {
                                std::future::pending().await
                            }
                        } => {
                            match evt {
                                Ok(event) => {
                                    match event.event_type {
                                        WatchEventType::Put => {
                                            if let Some(slice) = serde_json::from_slice::<serde_json::Value>(&event.kv.value)
                                                .ok()
                                                .and_then(|val| endpoint_slice_from_value(&val).ok())
                                            {
                                                self.service.apply_endpoint_slice(slice).await;
                                                if let Err(err) = self.service.reconcile_dataplane(&reconciler, None).await {
                                                    tracing::warn!(
                                                        target: "kubeproxy::dataplane",
                                                        error = %err,
                                                        "failed to reconcile dataplane after endpointslice update"
                                                    );
                                                }
                                            }
                                        }
                                        WatchEventType::Delete => {
                                            if let Some((ns, name)) = extract_namespace_and_name_from_key(&event.kv.key) {
                                                self.service.remove_endpoint_slice(&ns, &name).await;
                                                if let Err(err) = self.service.reconcile_dataplane(&reconciler, None).await {
                                                    tracing::warn!(
                                                        target: "kubeproxy::dataplane",
                                                        error = %err,
                                                        "failed to reconcile dataplane after endpointslice delete"
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                    let _ = self.service.sync_from_api(&reconciler).await;
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    eps_watch = None;
                                }
                            }
                        }
                    }
                }
            } else {
                loop {
                    match context.changed().await {
                        StopPhase::Running => {},
                        StopPhase::Graceful | StopPhase::Force => {
                            self.service.stop();
                            break;
                        },
                    }
                }
            }

            Ok(())
        })
    }
}
