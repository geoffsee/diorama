use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use diorama_platform::Architecture;
use diorama_portainer::config::{
    DEFAULT_EDGE_INSECURE_POLL, DEFAULT_PORTAINER_AGENT_IMAGE,
    PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME, PORTAINER_AGENT_CONFIGMAP_NAME,
    PORTAINER_AGENT_DEPLOYMENT_NAME, PORTAINER_AGENT_PORT_EDGE, PORTAINER_AGENT_PORT_HTTP,
    PORTAINER_AGENT_SECRET_NAME, PORTAINER_AGENT_SERVICE_ACCOUNT_NAME,
    PORTAINER_AGENT_SERVICE_NAME, PORTAINER_NAMESPACE, PortainerAgentConfig,
};
use diorama_portainer::error::PortainerError;
use diorama_portainer::manifests::PortainerManifests;

fn sample_sync_config() -> PortainerAgentConfig {
    PortainerAgentConfig::new("fixture-id", "fixture-key", Architecture::Amd64)
        .with_edge_secret(Some("fixture-secret".to_string()))
        .with_edge_async(false)
        .with_edge_insecure_poll(DEFAULT_EDGE_INSECURE_POLL)
        .with_image("portainer/agent:fixture")
}

#[test]
fn test_golden_sync_manifests_generation() {
    let config = sample_sync_config();
    assert!(config.is_enabled());
    assert!(config.is_architecture_supported());
    assert_eq!(config.selected_image(), Some("portainer/agent:fixture"));

    let manifests = PortainerManifests::new(&config).expect("should generate manifests");
    verify_namespace_and_rbac(&manifests);
    verify_configmap_and_secret(&manifests);
    verify_service_and_deployment(&manifests);
    verify_against_upstream_fixture(&manifests, "sync");
}

fn verify_namespace_and_rbac(manifests: &PortainerManifests) {
    assert_eq!(
        manifests.namespace.metadata.name.as_deref(),
        Some(PORTAINER_NAMESPACE)
    );
    assert_eq!(
        manifests.service_account.metadata.name.as_deref(),
        Some(PORTAINER_AGENT_SERVICE_ACCOUNT_NAME)
    );
    assert_eq!(
        manifests.service_account.metadata.namespace.as_deref(),
        Some(PORTAINER_NAMESPACE)
    );
    assert_eq!(
        manifests.cluster_role_binding.metadata.name.as_deref(),
        Some(PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME)
    );
    assert_eq!(
        manifests.cluster_role_binding.role_ref.name,
        "cluster-admin"
    );
    assert_eq!(
        manifests.cluster_role_binding.role_ref.api_group,
        "rbac.authorization.k8s.io"
    );
    assert_eq!(manifests.cluster_role_binding.role_ref.kind, "ClusterRole");

    let subjects = manifests
        .cluster_role_binding
        .subjects
        .as_ref()
        .expect("subjects");
    assert_eq!(subjects.len(), 1);
    assert_eq!(subjects[0].kind, "ServiceAccount");
    assert_eq!(subjects[0].name, PORTAINER_AGENT_SERVICE_ACCOUNT_NAME);
    assert_eq!(subjects[0].namespace.as_deref(), Some(PORTAINER_NAMESPACE));
}

fn verify_configmap_and_secret(manifests: &PortainerManifests) {
    assert_eq!(
        manifests.config_map.metadata.name.as_deref(),
        Some(PORTAINER_AGENT_CONFIGMAP_NAME)
    );
    assert_eq!(
        manifests.config_map.metadata.namespace.as_deref(),
        Some(PORTAINER_NAMESPACE)
    );
    let cm_data = manifests.config_map.data.as_ref().expect("configmap data");
    assert_eq!(cm_data.get("EDGE_ASYNC").map(String::as_str), Some("false"));
    assert_eq!(
        cm_data.get("EDGE_ID").map(String::as_str),
        Some("fixture-id")
    );
    assert_eq!(
        cm_data.get("EDGE_INSECURE_POLL").map(String::as_str),
        Some("0")
    );
    assert_eq!(
        cm_data.get("EDGE_SECRET").map(String::as_str),
        Some("fixture-secret")
    );

    assert_eq!(
        manifests.secret.metadata.name.as_deref(),
        Some(PORTAINER_AGENT_SECRET_NAME)
    );
    assert_eq!(
        manifests.secret.metadata.namespace.as_deref(),
        Some(PORTAINER_NAMESPACE)
    );
    assert_eq!(manifests.secret.type_.as_deref(), Some("Opaque"));
    let secret_data = manifests.secret.string_data.as_ref().expect("string data");
    assert_eq!(
        secret_data.get("edge.key").map(String::as_str),
        Some("fixture-key")
    );
}

fn verify_service_and_deployment(manifests: &PortainerManifests) {
    assert_eq!(
        manifests.service.metadata.name.as_deref(),
        Some(PORTAINER_AGENT_SERVICE_NAME)
    );
    let svc_spec = manifests.service.spec.as_ref().expect("service spec");
    assert_eq!(svc_spec.cluster_ip.as_deref(), Some("None"));
    assert_eq!(svc_spec.publish_not_ready_addresses, Some(true));
    let ports = svc_spec.ports.as_ref().expect("ports");
    assert_eq!(ports.len(), 2);
    assert_eq!(ports[0].name.as_deref(), Some("edge"));
    assert_eq!(ports[0].port, PORTAINER_AGENT_PORT_EDGE);
    assert_eq!(ports[1].name.as_deref(), Some("http"));
    assert_eq!(ports[1].port, PORTAINER_AGENT_PORT_HTTP);

    assert_eq!(
        manifests.deployment.metadata.name.as_deref(),
        Some(PORTAINER_AGENT_DEPLOYMENT_NAME)
    );
    let dep_spec = manifests.deployment.spec.as_ref().expect("deployment spec");
    assert_eq!(dep_spec.replicas, Some(1));
    let pod_spec = dep_spec.template.spec.as_ref().expect("pod spec");
    assert_eq!(pod_spec.containers.len(), 1);
    let container = &pod_spec.containers[0];
    assert_eq!(container.name, "portainer-agent");
    assert_eq!(container.image.as_deref(), Some("portainer/agent:fixture"));

    let env = container.env.as_ref().expect("container env");
    let env_map: BTreeMap<String, Option<String>> = env
        .iter()
        .map(|e| (e.name.clone(), e.value.clone()))
        .collect();
    assert_eq!(
        env_map.get("LOG_LEVEL").and_then(|v| v.as_deref()),
        Some("INFO")
    );
    assert_eq!(env_map.get("EDGE").and_then(|v| v.as_deref()), Some("1"));
    assert_eq!(
        env_map.get("AGENT_CLUSTER_ADDR").and_then(|v| v.as_deref()),
        Some("portainer-agent")
    );
    assert!(env_map.contains_key("KUBERNETES_POD_IP"));
    assert!(env_map.contains_key("EDGE_KEY"));
    assert!(env_map.contains_key("AGENT_SECRET"));
}

#[test]
fn test_golden_async_manifests_generation() {
    let config = PortainerAgentConfig::new("fixture-id", "fixture-key", Architecture::Amd64)
        .with_edge_secret(Some("fixture-secret".to_string()))
        .with_edge_async(true)
        .with_edge_insecure_poll(DEFAULT_EDGE_INSECURE_POLL)
        .with_image("portainer/agent:fixture");

    assert!(config.is_enabled());
    assert!(config.edge_async);

    let manifests = PortainerManifests::new(&config).expect("should generate manifests");
    let cm_data = manifests.config_map.data.as_ref().expect("configmap data");
    assert_eq!(cm_data.get("EDGE_ASYNC").map(String::as_str), Some("true"));

    verify_against_upstream_fixture(&manifests, "async");
}

#[test]
fn test_manifests_without_optional_edge_secret() {
    let config = PortainerAgentConfig::new("my-id", "my-key", Architecture::Arm64);
    assert_eq!(config.edge_secret, None);

    let manifests = PortainerManifests::new(&config).expect("should generate manifests");
    let cm_data = manifests.config_map.data.as_ref().expect("configmap data");
    assert!(!cm_data.contains_key("EDGE_SECRET"));

    let dep_spec = manifests.deployment.spec.as_ref().expect("deployment spec");
    let pod_spec = dep_spec.template.spec.as_ref().expect("pod spec");
    let env = pod_spec.containers[0].env.as_ref().expect("env");
    assert!(!env.iter().any(|e| e.name == "AGENT_SECRET"));
}

#[test]
fn test_missing_credentials_returns_error_and_disabled() {
    let config = PortainerAgentConfig::new("", "", Architecture::Amd64);

    assert!(!config.is_enabled());
    assert!(config.has_missing_credentials());
    assert!(!config.has_partial_credentials());
    assert_eq!(config.selected_image(), None);

    let err = PortainerManifests::new(&config).unwrap_err();
    assert_eq!(err, PortainerError::MissingCredentials);
}

#[test]
fn test_partial_credentials_id_only() {
    let config = PortainerAgentConfig::new("only-id", "", Architecture::Amd64);

    assert!(!config.is_enabled());
    assert!(!config.has_missing_credentials());
    assert!(config.has_partial_credentials());
    assert_eq!(config.selected_image(), None);

    let err = PortainerManifests::new(&config).unwrap_err();
    assert_eq!(
        err,
        PortainerError::IncompleteCredentials {
            has_id: true,
            has_key: false,
        }
    );
}

#[test]
fn test_partial_credentials_key_only() {
    let config = PortainerAgentConfig::new("", "only-key", Architecture::Amd64);

    assert!(!config.is_enabled());
    assert!(!config.has_missing_credentials());
    assert!(config.has_partial_credentials());
    assert_eq!(config.selected_image(), None);

    let err = PortainerManifests::new(&config).unwrap_err();
    assert_eq!(
        err,
        PortainerError::IncompleteCredentials {
            has_id: false,
            has_key: true,
        }
    );
}

#[test]
fn test_unsupported_architecture_riscv64() {
    let config = PortainerAgentConfig::new("valid-id", "valid-key", Architecture::Riscv64);

    assert!(!config.is_architecture_supported());
    assert!(!config.is_enabled());
    // Unsupported image is NOT selected
    assert_eq!(config.selected_image(), None);

    let err = PortainerManifests::new(&config).unwrap_err();
    assert_eq!(
        err,
        PortainerError::UnsupportedArchitecture(Architecture::Riscv64)
    );
}

#[test]
fn test_supported_architectures() {
    for arch in [
        Architecture::Amd64,
        Architecture::Arm64,
        Architecture::ArmV7,
    ] {
        let config = PortainerAgentConfig::new("id", "key", arch);
        assert!(config.is_architecture_supported());
        assert!(config.is_enabled());
        assert_eq!(config.selected_image(), Some(DEFAULT_PORTAINER_AGENT_IMAGE));

        let manifests = PortainerManifests::new(&config);
        assert!(manifests.is_ok(), "Architecture {arch:?} must succeed");
    }
}

#[test]
fn test_credentials_redacted_from_debug_and_diagnostics() {
    let private_key = "super-secret-edge-key-abc-123";
    let private_token = "super-secret-token-xyz-789";

    let config = PortainerAgentConfig::new("edge-id-1", private_key, Architecture::Amd64)
        .with_edge_secret(Some(private_token.to_string()));

    let debug_output = format!("{config:?}");

    // Private key and secret must NEVER be visible in debug output
    assert!(
        !debug_output.contains(private_key),
        "debug output leaked private edge key!"
    );
    assert!(
        !debug_output.contains(private_token),
        "debug output leaked private edge secret!"
    );
    assert!(
        debug_output.contains("<redacted>"),
        "debug output should have <redacted> for credentials"
    );

    // Diagnostics / Error messages must never leak credentials
    let err_incomplete = PortainerError::IncompleteCredentials {
        has_id: true,
        has_key: false,
    };
    let err_str = format!("{err_incomplete}");
    assert!(!err_str.contains(private_key));
    assert!(!err_str.contains(private_token));
}

#[test]
fn test_custom_image_and_env_vars() {
    let mut extra_vars = BTreeMap::new();
    extra_vars.insert("CUSTOM_PARAM".to_string(), "custom_value".to_string());

    let config = PortainerAgentConfig::new("id", "key", Architecture::Amd64)
        .with_image("custom.registry/portainer/agent:custom")
        .with_env_vars(extra_vars);

    assert_eq!(
        config.selected_image(),
        Some("custom.registry/portainer/agent:custom")
    );

    let manifests = PortainerManifests::new(&config).expect("manifests");
    let cm_data = manifests.config_map.data.as_ref().expect("data");
    assert_eq!(
        cm_data.get("CUSTOM_PARAM").map(String::as_str),
        Some("custom_value")
    );

    let dep = manifests.deployment.spec.as_ref().expect("spec");
    assert_eq!(
        dep.template.spec.as_ref().unwrap().containers[0]
            .image
            .as_deref(),
        Some("custom.registry/portainer/agent:custom")
    );
}

#[test]
fn test_json_values_serialization() {
    let config = PortainerAgentConfig::new("id", "key", Architecture::Amd64);
    let manifests = PortainerManifests::new(&config).expect("manifests");
    let values = manifests.to_json_values().expect("json values");

    assert_eq!(values.len(), 7);
    for v in &values {
        assert!(v.get("metadata").is_some());
    }
}

/// Helper that loads `tools/parity/fixtures/rust-evidence/portainer.json` and verifies
/// that our generated manifest objects match the upstream reference objects.
fn verify_against_upstream_fixture(manifests: &PortainerManifests, variant: &str) {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/parity/fixtures/rust-evidence/portainer.json");
    if !fixture_path.exists() {
        return;
    }

    let content = fs::read_to_string(&fixture_path).expect("read portainer.json");
    let root: serde_json::Value = serde_json::from_str(&content).expect("parse json");
    let array = root.as_array().expect("root is array");

    let fixture = array
        .iter()
        .find(|entry| entry["variant"] == variant)
        .unwrap_or_else(|| panic!("variant {variant} not found in fixture"));

    let objects = &fixture["objects"];
    verify_fixture_meta(manifests, objects);
    verify_fixture_payload(manifests, objects);
}

fn verify_fixture_meta(manifests: &PortainerManifests, objects: &serde_json::Value) {
    let ns_list = objects["namespaces"].as_array().expect("namespaces");
    assert_eq!(
        ns_list[0]["metadata"]["name"],
        manifests.namespace.metadata.name.as_deref().unwrap()
    );

    let sa_list = objects["serviceaccounts"]
        .as_array()
        .expect("serviceaccounts");
    assert_eq!(
        sa_list[0]["metadata"]["name"],
        manifests.service_account.metadata.name.as_deref().unwrap()
    );

    let crb_list = objects["clusterrolebindings"]
        .as_array()
        .expect("clusterrolebindings");
    assert_eq!(
        crb_list[0]["metadata"]["name"],
        manifests
            .cluster_role_binding
            .metadata
            .name
            .as_deref()
            .unwrap()
    );
}

fn verify_fixture_payload(manifests: &PortainerManifests, objects: &serde_json::Value) {
    let cm_list = objects["configmaps"].as_array().expect("configmaps");
    let expected_data = cm_list[0]["data"].as_object().expect("cm data");
    let actual_data = manifests.config_map.data.as_ref().expect("actual cm data");
    for (k, v) in expected_data {
        assert_eq!(
            actual_data.get(k).map(String::as_str),
            v.as_str(),
            "mismatch on configmap key {k}"
        );
    }

    let secret_list = objects["secrets"].as_array().expect("secrets");
    let expected_secret = secret_list[0]["stringData"]
        .as_object()
        .expect("secret stringData");
    let actual_secret = manifests
        .secret
        .string_data
        .as_ref()
        .expect("actual secret string_data");
    for (k, v) in expected_secret {
        assert_eq!(
            actual_secret.get(k).map(String::as_str),
            v.as_str(),
            "mismatch on secret key {k}"
        );
    }

    let dep_list = objects["deployments"].as_array().expect("deployments");
    assert_eq!(
        dep_list[0]["metadata"]["name"],
        manifests.deployment.metadata.name.as_deref().unwrap()
    );
}
