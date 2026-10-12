use std::time::Duration;

use diorama_controller::{ControllerError, ControllerManagerConfig, REQUIRED_CONTROLLERS};

#[test]
fn test_default_config_matches_kubernetes_v1_35_7_specification() {
    let config = ControllerManagerConfig::default();

    assert_eq!(config.controllers, vec!["*".to_string()]);
    assert_eq!(config.endpointslice_updates_batch_period, Duration::ZERO);
    assert_eq!(config.endpoint_updates_batch_period, Duration::ZERO);
    assert_eq!(config.concurrent_endpoint_syncs, 5);
    assert_eq!(config.secure_port, 10257);
    assert!(!config.leader_elect);

    // Validation must pass on defaults
    assert!(config.validate_controllers().is_ok());
    assert!(config.validate_batch_periods().is_ok());

    let cli_args = config.to_cli_args();
    assert!(cli_args.contains(&"--controllers=*".to_string()));
    assert!(cli_args.contains(&"--endpointslice-updates-batch-period=0s".to_string()));
    assert!(cli_args.contains(&"--endpoint-updates-batch-period=0s".to_string()));
    assert!(cli_args.contains(&"--concurrent-endpoint-syncs=5".to_string()));
    assert!(cli_args.contains(&"--secure-port=10257".to_string()));
    assert!(cli_args.contains(&"--use-service-account-credentials=true".to_string()));
}

#[test]
fn test_historical_allowlist_omitting_job_or_cronjob_is_rejected() {
    // Upstream PR #40 (f4f5ee9) regression: ensure job and cronjob cannot be silently omitted
    let mut config = ControllerManagerConfig::default();

    // 1. Custom list omitting job
    let without_job: Vec<String> = REQUIRED_CONTROLLERS
        .iter()
        .filter(|&&c| c != "job")
        .map(|&c| c.to_string())
        .collect();
    config.controllers = without_job;
    let res_no_job = config.validate_controllers();
    assert!(matches!(
        res_no_job,
        Err(ControllerError::OmittedRequiredController { controller, .. }) if controller == "job"
    ));

    // 2. Custom list omitting cronjob
    let without_cronjob: Vec<String> = REQUIRED_CONTROLLERS
        .iter()
        .filter(|&&c| c != "cronjob")
        .map(|&c| c.to_string())
        .collect();
    config.controllers = without_cronjob;
    let res_no_cronjob = config.validate_controllers();
    assert!(matches!(
        res_no_cronjob,
        Err(ControllerError::OmittedRequiredController { controller, .. }) if controller == "cronjob"
    ));
}

#[test]
fn test_historical_allowlist_omitting_garbage_collector_is_rejected() {
    // Upstream PR #68 (ec05c2c) regression: ensure garbagecollector cannot be silently omitted
    let mut config = ControllerManagerConfig::default();
    let mut full_without_gc: Vec<String> = REQUIRED_CONTROLLERS
        .iter()
        .filter(|&&c| c != "garbagecollector")
        .map(|&c| c.to_string())
        .collect();
    config.controllers = full_without_gc.clone();

    let res = config.validate_controllers();
    assert!(matches!(
        res,
        Err(ControllerError::OmittedRequiredController { controller, .. }) if controller == "garbagecollector"
    ));

    // Adding garbagecollector makes it pass
    full_without_gc.push("garbagecollector".to_string());
    config.controllers = full_without_gc;
    assert!(config.validate_controllers().is_ok());
}

#[test]
fn test_historical_allowlist_omitting_endpointslice_is_rejected() {
    // Upstream PR #111 (790b2b0) regression: ensure endpointslice cannot be silently omitted
    let mut config = ControllerManagerConfig::default();
    let full_without_eps: Vec<String> = REQUIRED_CONTROLLERS
        .iter()
        .filter(|&&c| c != "endpointslice")
        .map(|&c| c.to_string())
        .collect();
    config.controllers = full_without_eps;

    let res = config.validate_controllers();
    assert!(matches!(
        res,
        Err(ControllerError::OmittedRequiredController { controller, .. }) if controller == "endpointslice"
    ));
}

#[test]
fn test_excessive_endpointslice_batch_period_is_rejected() {
    // Upstream PR #111 (790b2b0) regression: batch periods must not introduce long multi-second delays
    let config = ControllerManagerConfig {
        endpointslice_updates_batch_period: Duration::from_secs(10),
        ..Default::default()
    };

    let res = config.validate_batch_periods();
    assert!(matches!(
        res,
        Err(ControllerError::InvalidConfiguration { field, .. }) if field == "endpointslice_updates_batch_period"
    ));
}

#[test]
fn test_excessive_endpoints_batch_period_is_rejected() {
    let config = ControllerManagerConfig {
        endpoint_updates_batch_period: Duration::from_millis(500),
        ..Default::default()
    };

    let res = config.validate_batch_periods();
    assert!(matches!(
        res,
        Err(ControllerError::InvalidConfiguration { field, .. }) if field == "endpoint_updates_batch_period"
    ));
}

#[test]
fn test_disabled_required_controller_is_rejected() {
    // Upstream allowlist with explicit negation
    let config = ControllerManagerConfig {
        controllers: vec!["*".to_string(), "-job".to_string()],
        ..Default::default()
    };

    let res = config.validate_controllers();
    assert!(matches!(
        res,
        Err(ControllerError::OmittedRequiredController { controller, .. }) if controller == "job"
    ));
}

#[test]
fn test_empty_controller_list_is_rejected() {
    let config = ControllerManagerConfig {
        controllers: Vec::new(),
        ..Default::default()
    };

    let res = config.validate_controllers();
    assert!(matches!(
        res,
        Err(ControllerError::InvalidConfiguration { field, .. }) if field == "controllers"
    ));
}
