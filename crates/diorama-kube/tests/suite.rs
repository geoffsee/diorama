#[path = "config_api.rs"]
mod config_api;
#[path = "host_network.rs"]
mod host_network;
#[path = "host_preflight.rs"]
mod host_preflight;
#[path = "host_preparation.rs"]
mod host_preparation;
#[path = "iptables_probe.rs"]
mod iptables_probe;
#[path = "lifecycle_logs.rs"]
mod lifecycle_logs;
#[path = "lifecycle_policy.rs"]
mod lifecycle_policy;
#[path = "lifecycle_sink.rs"]
mod lifecycle_sink;
#[path = "metrics_server.rs"]
mod metrics_server;
#[path = "node_runtime.rs"]
mod node_runtime;
#[path = "recovery_lifecycle.rs"]
mod recovery_lifecycle;
#[path = "startup.rs"]
mod startup;

// Runtime lifecycle tests exercise the real API and datastore while substituting
// only the upstream scheduler process. The Linux fixture qualifies scheduling.
fn install_scheduler_process_fixture(config: &diorama_config::ValidatedConfig) {
    use std::os::unix::fs::PermissionsExt;
    let binary = std::path::Path::new(&config.config().path).join("bin/kube-scheduler");
    std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
    std::fs::write(&binary, "#!/bin/sh\nexec sleep 600\n").unwrap();
    std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o755)).unwrap();
}
fn runtime_fixture(
    config: diorama_config::ValidatedConfig,
) -> Result<diorama::runtime::NodeRuntime, diorama::runtime::RuntimeError> {
    install_scheduler_process_fixture(&config);
    diorama::runtime::NodeRuntime::from_config(config)
}
