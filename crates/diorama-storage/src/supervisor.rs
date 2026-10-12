use std::time::Duration;

use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};
use serde_json::Value;

use crate::config::LOCAL_PATH_STORAGE_CLASS_NAME;
use crate::service::LocalPathService;

pub const COMPONENT_LOCAL_PATH: &str = "local-path-provisioner";
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_mins(1);

/// Supervisor adapter for the local-path storage provisioner.
///
/// Uses `FailurePolicy::Degrade` so optional storage provisioner failures
/// leave the core Kubernetes control-plane healthy while reporting diagnostic status.
#[derive(Clone, Debug)]
pub struct LocalPathAdapter {
    service: LocalPathService,
}

impl LocalPathAdapter {
    #[must_use]
    pub fn new(service: LocalPathService) -> Self {
        Self { service }
    }

    pub fn registration(
        id: impl Into<String>,
        service: LocalPathService,
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

impl Adapter for LocalPathAdapter {
    #[allow(clippy::too_many_lines)]
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            // Disabled mode: immediately ready without deploying components
            if !self.service.config().enabled {
                if !context.ready() {
                    return Err(AdapterError {
                        code: "storage-readiness-rejected",
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
                    code: "storage-readiness-rejected",
                });
            }

            let volume_manager = self.service.volume_manager();
            let mut interval = tokio::time::interval(Duration::from_millis(250));

            // 5. Await supervisor stop phase while periodically reconciling PVCs and Pods
            loop {
                tokio::select! {
                    phase = context.changed() => {
                        match phase {
                            StopPhase::Running => {},
                            StopPhase::Graceful | StopPhase::Force => {
                                self.service.stop();
                                break;
                            },
                        }
                    }
                    _ = interval.tick() => {
                        if let Ok(ns_list) = self.service.client().list_namespaces().await {
                            let mut namespaces = Vec::new();
                            if let Some(items) = ns_list.get("items").and_then(Value::as_array) {
                                for item in items {
                                    if let Some(name) = item.get("metadata").and_then(|m| m.get("name")).and_then(Value::as_str) {
                                        namespaces.push(name.to_string());
                                    }
                                }
                            }
                            if !namespaces.iter().any(|n| n == "default") {
                                namespaces.push("default".to_string());
                            }

                            let default_node = match self.service.client().list_nodes().await {
                                Ok(nodes) => nodes
                                    .pointer("/items/0/metadata/name")
                                    .and_then(Value::as_str)
                                    .map(std::string::ToString::to_string),
                                Err(_) => None,
                            };

                            for ns in &namespaces {
                                // 1. Reconcile Pod volume bindings
                                if let Ok(pod_list) = self.service.client().list_pods(ns).await
                                    && let Some(pods) = pod_list.get("items").and_then(Value::as_array)
                                {
                                    for pod in pods {
                                        if let Some(pod_name) = pod.get("metadata").and_then(|m| m.get("name")).and_then(Value::as_str)
                                            && pod.pointer("/spec/nodeName").and_then(Value::as_str).is_some()
                                        {
                                            let has_pvc = pod
                                                .pointer("/spec/volumes")
                                                .and_then(Value::as_array)
                                                .is_some_and(|vols| {
                                                    vols.iter().any(|v| v.get("persistentVolumeClaim").is_some())
                                                });
                                            if has_pvc {
                                                let _ = volume_manager.bind_volumes_for_pod(ns, pod_name).await;
                                            }
                                        }
                                    }
                                }

                                // 2. Reconcile PVCs
                                if let Ok(pvc_list) = self.service.client().list_pvcs(ns).await
                                    && let Some(pvcs) = pvc_list.get("items").and_then(Value::as_array)
                                {
                                    for pvc in pvcs {
                                        let sc = pvc.pointer("/spec/storageClassName").and_then(Value::as_str).unwrap_or("");
                                        if sc == LOCAL_PATH_STORAGE_CLASS_NAME || sc.is_empty() {
                                            let phase = pvc.pointer("/status/phase").and_then(Value::as_str);
                                            let vol_name = pvc.pointer("/spec/volumeName").and_then(Value::as_str);
                                            if phase != Some("Bound") || vol_name.is_none() {
                                                let selected_node = pvc
                                                    .pointer("/metadata/annotations/volume.kubernetes.io~1selected-node")
                                                    .and_then(Value::as_str)
                                                    .map(std::string::ToString::to_string);
                                                let node_to_use = selected_node.or_else(|| default_node.clone());
                                                if let (Some(pvc_name), Some(node)) = (
                                                    pvc.pointer("/metadata/name").and_then(Value::as_str),
                                                    node_to_use,
                                                ) {
                                                    let _ = volume_manager.provision_volume_for_pvc(ns, pvc_name, &node).await;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Ok(())
        })
    }
}
