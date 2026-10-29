//! Supervision of the pinned upstream scheduler using its default plugin profile.
use diorama_apiserver::KubernetesApiClient;
use diorama_supervisor::{
    AdapterError,
    process::{OwnedProcessAdapter, ProcessCommand},
};
use serde_json::json;
use std::{path::Path, sync::Arc, time::Duration};

pub(crate) fn adapter(
    state: &Path,
    client: Arc<KubernetesApiClient>,
) -> std::io::Result<OwnedProcessAdapter> {
    let dir = state.join("scheduler");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("config.json");
    let config = json!({"apiVersion":"kubescheduler.config.k8s.io/v1","kind":"KubeSchedulerConfiguration", "clientConnection":{"kubeconfig":state.join("pki/kube-scheduler.kubeconfig")},"leaderElection":{"leaderElect":true,"resourceLock":"leases","resourceNamespace":"kube-system","resourceName":"kube-scheduler"},"profiles":[{"schedulerName":"default-scheduler"}]});
    std::fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    let command = ProcessCommand::new(state.join("bin/kube-scheduler"))
        .inherit_stderr()
        .arg("--bind-address=127.0.0.1")
        .arg("--config")
        .arg(path);
    let started = diorama_apiserver::time::now_unix();
    let ready = async move {
        loop {
            if client
                .get_lease("kube-system", "kube-scheduler")
                .await
                .is_ok_and(|lease| {
                    lease
                        .pointer("/spec/renewTime")
                        .and_then(serde_json::Value::as_str)
                        .and_then(diorama_apiserver::time::parse_rfc3339_seconds)
                        .is_some_and(|renewed| renewed >= started)
                })
            {
                return Ok::<_, AdapterError>(());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    };
    let (adapter, _) = OwnedProcessAdapter::new(command, ready);
    Ok(adapter)
}
