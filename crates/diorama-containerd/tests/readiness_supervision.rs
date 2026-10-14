//! Integration tests for containerd readiness probing and supervisor lifecycle integration.

use diorama_config::Config;
use diorama_containerd::health::{HealthError, probe_containerd_readiness};
use diorama_containerd::image::ImageImportConfig;
use diorama_containerd::service::{
    COMPONENT_CONTAINERD, ContainerdPaths, ContainerdService, ContainerdServiceOptions,
};
use diorama_supervisor::{
    ComponentKind, FailurePolicy, Registration, StopCause, Supervisor, stop_channel,
};
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

#[tokio::test]
async fn readiness_probe_times_out_when_socket_does_not_exist() {
    let non_existent_socket = PathBuf::from("/tmp/diorama-test-nonexistent.sock");
    let timeout = Duration::from_millis(100);
    let retry = Duration::from_millis(20);

    let result = probe_containerd_readiness(&non_existent_socket, timeout, retry).await;
    match result {
        Err(HealthError::TimedOut { socket, elapsed }) => {
            assert_eq!(socket, non_existent_socket);
            assert_eq!(elapsed, timeout);
        },
        other => panic!("Expected HealthError::TimedOut, got: {other:?}"),
    }
}

#[tokio::test]
async fn failed_readiness_exits_through_supervision() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join("failing_instance");
    let paths = ContainerdPaths::from_base(&base);
    let config = Config::default();
    let image_config = ImageImportConfig::from_config(&config, &paths.images_dir);

    let mut options = ContainerdServiceOptions::new(paths, image_config);
    // Short timeout so the test executes rapidly
    options.readiness_timeout = Duration::from_millis(150);
    options.retry_interval = Duration::from_millis(30);

    let service = ContainerdService::new(options);
    let result = service.post_startup().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, "containerd_readiness_failed");
}

#[test]
fn containerd_component_spec_matches_requirements() {
    let timeout = Duration::from_secs(45);
    let spec = ContainerdService::component_spec(timeout);

    assert_eq!(spec.id, COMPONENT_CONTAINERD);
    assert_eq!(spec.kind, ComponentKind::LongRunning);
    assert_eq!(spec.failure_policy, FailurePolicy::Fatal);
    assert_eq!(spec.startup_timeout, timeout);
    assert_eq!(spec.prerequisites, <[std::string::String; 0]>::default());
}

#[tokio::test]
async fn supervisor_coordinates_containerd_service_failure() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join("supervised_instance");
    let paths = ContainerdPaths::from_base(&base);
    let config = Config::default();
    let image_config = ImageImportConfig::from_config(&config, &paths.images_dir);

    let mut options = ContainerdServiceOptions::new(paths, image_config);
    options.readiness_timeout = Duration::from_millis(100);
    options.retry_interval = Duration::from_millis(25);

    let service = ContainerdService::new(options);
    let spec = ContainerdService::component_spec(Duration::from_millis(200));
    let registration = Registration::new(spec, service);

    let (_stop_handle, stop_receiver) = stop_channel();
    let supervisor = Supervisor::new(vec![registration]).expect("graph should be valid");

    let report = supervisor.run(stop_receiver).await;
    // Readiness failure must be fatal and exit cleanly through supervisor
    assert!(
        matches!(report.cause, StopCause::Fatal(_)),
        "Supervisor cause should be Fatal on readiness failure, got {:?}",
        report.cause
    );
    assert!(!report.failures.is_empty(), "Failures should be recorded");
}
