//! Tests for registry hosts.toml management and survival across config regenerations.

use std::collections::BTreeMap;
use tempfile::TempDir;

use diorama_containerd::{
    ContainerdConfigOptions, ContainerdServicePaths, HostEndpointConfig, RegistryHostFile,
    list_configured_registries, read_registry_hosts_toml, write_containerd_config_file,
    write_registry_hosts_toml,
};

#[test]
fn registry_snippets_survive_config_regeneration() {
    let temp = TempDir::new().unwrap();
    let base_dir = temp.path().join("kubesolo_data");
    let paths = ContainerdServicePaths::from_base_dir(&base_dir);
    let options = ContainerdConfigOptions::default();

    // 1. First config generation: creates containerd directory and config.toml
    write_containerd_config_file(&paths, &options).expect("initial write succeeds");
    assert!(paths.config_file.is_file());

    // 2. Operator adds registry configurations under containerd/registry/
    let mut docker_hub = RegistryHostFile {
        server: Some("https://registry-1.docker.io".to_string()),
        host: BTreeMap::new(),
    };
    docker_hub.host.insert(
        "https://mirror.corp.internal".to_string(),
        HostEndpointConfig {
            capabilities: vec!["pull".to_string(), "resolve".to_string()],
            override_path: None,
            ca: None,
            skip_verify: None,
            header: BTreeMap::new(),
        },
    );

    let mut harbor = RegistryHostFile {
        server: Some("https://registry-1.docker.io".to_string()),
        host: BTreeMap::new(),
    };
    let mut harbor_endpoint = HostEndpointConfig {
        capabilities: vec!["pull".to_string(), "resolve".to_string()],
        override_path: Some(true),
        ca: Some("/etc/ssl/certs/harbor-ca.crt".to_string()),
        skip_verify: Some(false),
        header: BTreeMap::new(),
    };
    harbor_endpoint.header.insert(
        "Authorization".to_string(),
        vec!["Basic cm9ib3Q6dG9rZW4=".to_string()],
    );
    harbor.host.insert(
        "https://harbor.corp.internal/v2/docker.io".to_string(),
        harbor_endpoint,
    );

    let mut default_catchall = RegistryHostFile {
        server: None,
        host: BTreeMap::new(),
    };
    default_catchall.host.insert(
        "https://airgap-registry.corp.internal".to_string(),
        HostEndpointConfig {
            capabilities: vec!["pull".to_string(), "resolve".to_string()],
            override_path: None,
            ca: Some("/etc/ssl/certs/corp-ca.crt".to_string()),
            skip_verify: None,
            header: BTreeMap::new(),
        },
    );

    write_registry_hosts_toml(&paths.registry_config_dir, "docker.io", &docker_hub)
        .expect("write docker.io config");
    write_registry_hosts_toml(&paths.registry_config_dir, "ghcr.io", &harbor)
        .expect("write ghcr.io config");
    write_registry_hosts_toml(&paths.registry_config_dir, "_default", &default_catchall)
        .expect("write _default config");

    let configured = list_configured_registries(&paths.registry_config_dir).unwrap();
    assert_eq!(configured, vec!["_default", "docker.io", "ghcr.io"]);

    // 3. Repeated config regeneration (e.g. on restart or update)
    for _ in 0..5 {
        write_containerd_config_file(&paths, &options).expect("regeneration succeeds");

        // Assert registry configurations remain identical and untouched
        let docker_read = read_registry_hosts_toml(&paths.registry_config_dir, "docker.io")
            .unwrap()
            .expect("docker.io hosts.toml still present");
        assert_eq!(docker_read, docker_hub);

        let ghcr_read = read_registry_hosts_toml(&paths.registry_config_dir, "ghcr.io")
            .unwrap()
            .expect("ghcr.io hosts.toml still present");
        assert_eq!(ghcr_read, harbor);

        let default_read = read_registry_hosts_toml(&paths.registry_config_dir, "_default")
            .unwrap()
            .expect("_default hosts.toml still present");
        assert_eq!(default_read, default_catchall);
    }
}
