use dioramactl::container::{
    ContainerConfig, ContainerEngineClient, ContainerInspect, ContainerInstallParams,
    CreateNetworkRequest, CreateVolumeRequest, container_name, install_container, network_name,
    volume_name,
};
use dioramactl::container_fixtures::{
    serialize_container_create_request, serialize_network_create_request,
    serialize_volume_create_request,
};
use dioramactl::container_ports::{PortMapping, PortParseError, parse_container_ports};
use std::collections::HashMap;
use std::io;

#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct MockContainerEngine {
    networks: HashMap<String, CreateNetworkRequest>,
    volumes: HashMap<String, CreateVolumeRequest>,
    images: HashMap<String, bool>,
    containers: HashMap<String, (ContainerConfig, bool, HashMap<String, u16>)>, // (config, running, allocated_ports)

    // Injected failure flags
    fail_create_network: bool,
    fail_create_volume: bool,
    fail_pull_image: bool,
    fail_create_container: bool,
    fail_start_container: bool,
    fail_post_start_inspect: bool,
    omit_inspected_port: Option<String>,

    // Audit logs of operations
    created_networks: Vec<String>,
    removed_networks: Vec<String>,
    created_volumes: Vec<String>,
    removed_volumes: Vec<String>,
    created_containers: Vec<String>,
    started_containers: Vec<String>,
    stopped_containers: Vec<String>,
    removed_containers: Vec<String>,
}

impl ContainerEngineClient for MockContainerEngine {
    fn inspect_network(&mut self, name: &str) -> io::Result<Option<CreateNetworkRequest>> {
        Ok(self.networks.get(name).cloned())
    }

    fn create_network(&mut self, req: &CreateNetworkRequest) -> io::Result<()> {
        if self.fail_create_network {
            return Err(io::Error::other("mock fail create network"));
        }
        self.networks.insert(req.name.clone(), req.clone());
        self.created_networks.push(req.name.clone());
        Ok(())
    }

    fn remove_network(&mut self, name: &str) -> io::Result<()> {
        self.networks.remove(name);
        self.removed_networks.push(name.to_string());
        Ok(())
    }

    fn inspect_volume(&mut self, name: &str) -> io::Result<Option<()>> {
        Ok(self.volumes.get(name).map(|_| ()))
    }

    fn create_volume(&mut self, req: &CreateVolumeRequest) -> io::Result<()> {
        if self.fail_create_volume {
            return Err(io::Error::other("mock fail create volume"));
        }
        self.volumes.insert(req.name.clone(), req.clone());
        self.created_volumes.push(req.name.clone());
        Ok(())
    }

    fn remove_volume(&mut self, name: &str) -> io::Result<()> {
        self.volumes.remove(name);
        self.removed_volumes.push(name.to_string());
        Ok(())
    }

    fn inspect_image(&mut self, image: &str) -> io::Result<Option<()>> {
        Ok(self.images.get(image).map(|_| ()))
    }

    fn pull_image(&mut self, image: &str) -> io::Result<()> {
        if self.fail_pull_image {
            return Err(io::Error::other("mock fail pull image"));
        }
        self.images.insert(image.to_string(), true);
        Ok(())
    }

    fn inspect_container(&mut self, name: &str) -> io::Result<Option<ContainerInspect>> {
        if self.fail_post_start_inspect && self.started_containers.contains(&name.to_string()) {
            return Err(io::Error::other("mock fail post start inspect"));
        }
        if let Some((config, running, ports)) = self.containers.get(name) {
            let mut allocated_ports = ports.clone();
            if let Some(port) = &self.omit_inspected_port {
                allocated_ports.remove(port);
            }
            Ok(Some(ContainerInspect {
                id: format!("id-{name}"),
                name: name.to_string(),
                running: *running,
                d2k_enabled: config.env.iter().any(|value| value == "DIORAMA_D2K=true"),
                exit_code: 0,
                allocated_ports,
            }))
        } else {
            Ok(None)
        }
    }

    fn create_container(&mut self, name: &str, config: &ContainerConfig) -> io::Result<String> {
        if self.fail_create_container {
            return Err(io::Error::other("mock fail create container"));
        }
        if self.containers.contains_key(name) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "container name reserved",
            ));
        }
        let mut allocated = HashMap::new();
        // Allocate ports matching bindings
        for (port_key, bindings) in &config.port_bindings {
            for b in bindings {
                let host_p = resolve_mock_port(port_key, &b.host_port);
                allocated.insert(port_key.clone(), host_p);
            }
        }
        self.containers
            .insert(name.to_string(), (config.clone(), false, allocated));
        self.created_containers.push(name.to_string());
        Ok(name.to_string())
    }

    fn start_container(&mut self, id_or_name: &str) -> io::Result<()> {
        if self.fail_start_container {
            return Err(io::Error::other("mock fail start container"));
        }
        if let Some((_, running, _)) = self.containers.get_mut(id_or_name) {
            *running = true;
        }
        self.started_containers.push(id_or_name.to_string());
        Ok(())
    }

    fn stop_container(&mut self, id_or_name: &str, _timeout: u32) -> io::Result<()> {
        if let Some((_, running, _)) = self.containers.get_mut(id_or_name) {
            *running = false;
        }
        self.stopped_containers.push(id_or_name.to_string());
        Ok(())
    }

    fn remove_container(&mut self, id_or_name: &str, _force: bool) -> io::Result<()> {
        self.containers.remove(id_or_name);
        self.removed_containers.push(id_or_name.to_string());
        Ok(())
    }
}

fn resolve_mock_port(port_key: &str, host_port: &str) -> u16 {
    if host_port.is_empty() {
        if port_key == "6443/tcp" { 32768 } else { 32769 }
    } else {
        host_port.parse().unwrap_or(0)
    }
}

// -----------------------------------------------------------------------------
// 1. Port Parsing and Validation Tests
// -----------------------------------------------------------------------------

#[test]
fn test_port_parsing_comprehensive() {
    // Single bare port defaults to 1:1 tcp
    assert_eq!(
        parse_container_ports("80").unwrap(),
        vec![PortMapping {
            host_ip: "127.0.0.1".into(),
            host_port: 80,
            container_port: 80,
            protocol: "tcp".into(),
        }]
    );

    // Protocol uppercase converted to lowercase
    assert_eq!(
        parse_container_ports("53/UDP").unwrap(),
        vec![PortMapping {
            host_ip: "127.0.0.1".into(),
            host_port: 53,
            container_port: 53,
            protocol: "udp".into(),
        }]
    );

    // Host IP binding with explicit ports
    assert_eq!(
        parse_container_ports("127.0.0.1:8443:443/tcp").unwrap(),
        vec![PortMapping {
            host_ip: "127.0.0.1".into(),
            host_port: 8443,
            container_port: 443,
            protocol: "tcp".into(),
        }]
    );

    // Range 8000-8002
    let range_res = parse_container_ports("8000-8002").unwrap();
    assert_eq!(range_res.len(), 3);
    assert_eq!(range_res[0].host_port, 8000);
    assert_eq!(range_res[1].host_port, 8001);
    assert_eq!(range_res[2].host_port, 8002);

    // Duplicate detection
    assert!(matches!(
        parse_container_ports("80, 80").unwrap_err(),
        PortParseError::DuplicateHostPort(80, _)
    ));

    // Invalid protocols rejected
    assert!(matches!(
        parse_container_ports("80/sctp").unwrap_err(),
        PortParseError::UnsupportedProtocol(_)
    ));
}

// -----------------------------------------------------------------------------
// 2. Resource Naming Tests
// -----------------------------------------------------------------------------

#[test]
fn test_resource_naming_conventions() {
    // Default / "diorama" -> "diorama"
    assert_eq!(container_name(""), "diorama");
    assert_eq!(container_name("diorama"), "diorama");
    assert_eq!(network_name("diorama"), "diorama-net");
    assert_eq!(volume_name("diorama"), "diorama-data");

    // Named cluster "dev" -> "diorama-dev"
    assert_eq!(container_name("dev"), "diorama-dev");
    assert_eq!(network_name("dev"), "diorama-dev-net");
    assert_eq!(volume_name("dev"), "diorama-dev-data");

    // Named cluster "prod-cluster" -> "diorama-prod-cluster"
    assert_eq!(container_name("prod-cluster"), "diorama-prod-cluster");
    assert_eq!(network_name("prod-cluster"), "diorama-prod-cluster-net");
    assert_eq!(volume_name("prod-cluster"), "diorama-prod-cluster-data");
}

// -----------------------------------------------------------------------------
// 3. Multi-Cluster Coexistence Tests
// -----------------------------------------------------------------------------

#[test]
fn test_multi_cluster_coexistence() {
    let mut engine = MockContainerEngine::default();

    // Cluster A
    let params_a = ContainerInstallParams {
        instance_name: "alpha".to_string(),
        image: "portainer/diorama:latest".to_string(),
        mtu: Some(1450),
        d2k: false,
        container_ports: Some("8080:80".to_string()),
        extra_env: vec![],
        apiserver_host_port: Some(6443),
        d2k_host_port: None,
    };
    let res_a = install_container(&mut engine, &params_a).unwrap();

    // Cluster B
    let params_b = ContainerInstallParams {
        instance_name: "beta".to_string(),
        image: "portainer/diorama:latest".to_string(),
        mtu: Some(1500),
        d2k: true,
        container_ports: Some("8081:80".to_string()),
        extra_env: vec![],
        apiserver_host_port: Some(7443),
        d2k_host_port: Some(2377),
    };
    let res_b = install_container(&mut engine, &params_b).unwrap();

    // Verify distinct container names
    assert_eq!(res_a.container_name, "diorama-alpha");
    assert_eq!(res_b.container_name, "diorama-beta");

    // Verify distinct networks and MTUs
    assert_eq!(res_a.network_name, "diorama-alpha-net");
    assert_eq!(res_b.network_name, "diorama-beta-net");
    assert_eq!(
        engine
            .networks
            .get("diorama-alpha-net")
            .unwrap()
            .options
            .get("com.docker.network.driver.mtu")
            .unwrap(),
        "1450"
    );
    assert_eq!(
        engine
            .networks
            .get("diorama-beta-net")
            .unwrap()
            .options
            .get("com.docker.network.driver.mtu")
            .unwrap(),
        "1500"
    );

    // Verify distinct volumes
    assert_eq!(res_a.volume_name, "diorama-alpha-data");
    assert_eq!(res_b.volume_name, "diorama-beta-data");
    assert!(engine.volumes.contains_key("diorama-alpha-data"));
    assert!(engine.volumes.contains_key("diorama-beta-data"));

    // Verify distinct API and D2K ports
    assert_eq!(res_a.apiserver_port, 6443);
    assert_eq!(res_b.apiserver_port, 7443);
    assert_eq!(res_a.d2k_port, None);
    assert_eq!(res_b.d2k_port, Some(2377));

    // Both containers are running simultaneously
    assert_eq!(engine.containers.len(), 2);
    assert!(engine.containers.get("diorama-alpha").unwrap().1);
    assert!(engine.containers.get("diorama-beta").unwrap().1);
}

// -----------------------------------------------------------------------------
// 4. Rollback and Ownership Cleanup Tests
// -----------------------------------------------------------------------------

#[test]
fn test_rollback_cleans_only_newly_owned_resources() {
    let mut engine = MockContainerEngine::default();

    // Pre-create an existing volume (e.g. from previous run or shared)
    let pre_existing_vol = CreateVolumeRequest::new("diorama-data");
    engine.create_volume(&pre_existing_vol).unwrap();
    assert_eq!(engine.created_volumes, vec!["diorama-data"]);

    // Injected failure at container start
    engine.fail_start_container = true;

    let params = ContainerInstallParams {
        instance_name: "diorama".to_string(),
        image: "portainer/diorama:latest".to_string(),
        mtu: None,
        d2k: false,
        container_ports: None,
        extra_env: vec![],
        apiserver_host_port: None,
        d2k_host_port: None,
    };

    let result = install_container(&mut engine, &params);
    assert!(result.is_err());

    // Newly created network and container must be rolled back
    assert!(engine.removed_containers.contains(&"diorama".to_string()));
    assert!(engine.removed_networks.contains(&"diorama-net".to_string()));

    // BUT pre-existing volume must NOT be rolled back
    assert!(!engine.removed_volumes.contains(&"diorama-data".to_string()));
    assert!(engine.volumes.contains_key("diorama-data"));
}

#[test]
fn test_rollback_on_network_creation_failure() {
    let mut engine = MockContainerEngine {
        fail_create_network: true,
        ..Default::default()
    };

    let params = ContainerInstallParams {
        instance_name: "test".to_string(),
        image: "img:tag".to_string(),
        mtu: None,
        d2k: false,
        container_ports: None,
        extra_env: vec![],
        apiserver_host_port: None,
        d2k_host_port: None,
    };

    let result = install_container(&mut engine, &params);
    assert!(result.is_err());

    // Nothing was created, nothing to remove
    assert_eq!(
        engine.removed_containers,
        <[std::string::String; 0]>::default()
    );
    assert_eq!(
        engine.removed_networks,
        <[std::string::String; 0]>::default()
    );
    assert_eq!(
        engine.removed_volumes,
        <[std::string::String; 0]>::default()
    );
}

// -----------------------------------------------------------------------------
// 5. Engine Request Fixtures (Linux/macOS/WSL2)
// -----------------------------------------------------------------------------

#[test]
fn test_engine_request_fixtures_matching_api() {
    // Network create serialization
    let net_req = CreateNetworkRequest::new("diorama-net", Some(1450));
    let net_json = serialize_network_create_request(&net_req);
    assert!(net_json.contains("\"Name\":\"diorama-net\""));
    assert!(net_json.contains("\"Driver\":\"bridge\""));
    assert!(net_json.contains("\"com.docker.network.driver.mtu\":\"1450\""));

    // Volume create serialization
    let vol_req = CreateVolumeRequest::new("diorama-data");
    let vol_json = serialize_volume_create_request(&vol_req);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&vol_json).unwrap(),
        serde_json::json!({"Name":"diorama-data", "Driver":"local", "Labels":{}})
    );

    // Container create serialization
    let mut engine = MockContainerEngine::default();
    let params = ContainerInstallParams {
        instance_name: "test".to_string(),
        image: "portainer/diorama:v1.1.8".to_string(),
        mtu: Some(1500),
        d2k: true,
        container_ports: Some("8080:80".to_string()),
        extra_env: vec![("CUSTOM_VAR".into(), "val".into())],
        apiserver_host_port: Some(6443),
        d2k_host_port: Some(2376),
    };
    install_container(&mut engine, &params).unwrap();

    let (cfg, _, _) = engine.containers.get("diorama-test").unwrap();
    let container_json = serialize_container_create_request(cfg);

    // Verify key fields required by diorama container contract
    assert!(container_json.contains("\"Privileged\":true"));
    assert!(container_json.contains("\"CgroupnsMode\":\"host\""));
    assert!(container_json.contains("\"RestartPolicy\":{\"Name\":\"unless-stopped\"}"));
    assert!(container_json.contains("\"Binds\":[\"diorama-test-data:/var/lib/diorama\"]"));
    assert!(container_json.contains("\"NetworkMode\":\"diorama-test-net\""));
    assert!(
        container_json.contains("\"6443/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"6443\"}]")
    );
    assert!(
        container_json.contains("\"2376/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"2376\"}]")
    );
    assert!(
        container_json.contains("\"80/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"8080\"}]")
    );
    assert!(container_json.contains("\"DIORAMA_CONTAINER_MODE=true\""));
    assert!(container_json.contains("\"DIORAMA_NAME=test\""));
    assert!(container_json.contains("\"CUSTOM_VAR=val\""));
}

// -----------------------------------------------------------------------------
// 6. CPU Manager Policy Rejection in Container Mode
// -----------------------------------------------------------------------------

#[test]
fn test_cpu_manager_policy_rejected_in_container_mode() {
    let mut engine = MockContainerEngine::default();

    let params = ContainerInstallParams {
        instance_name: "test".to_string(),
        image: "img:tag".to_string(),
        mtu: None,
        d2k: false,
        container_ports: None,
        extra_env: vec![("DIORAMA_CPU_MANAGER_POLICY".into(), "static".into())],
        apiserver_host_port: None,
        d2k_host_port: None,
    };

    let result = install_container(&mut engine, &params);
    assert!(result.is_err());
    let err_str = result.unwrap_err().to_string();
    assert!(err_str.contains("cpu-manager-policy \"static\" is not supported in container mode"));
}

fn regression_params() -> ContainerInstallParams {
    ContainerInstallParams {
        instance_name: "review".into(),
        image: "node:old".into(),
        mtu: Some(1500),
        d2k: true,
        container_ports: None,
        extra_env: vec![],
        apiserver_host_port: Some(6443),
        d2k_host_port: Some(2376),
    }
}

#[test]
fn reinstall_pull_failure_preserves_instance_and_later_failure_reports_removal() {
    let mut engine = MockContainerEngine::default();
    let mut params = regression_params();
    install_container(&mut engine, &params).unwrap();
    let cname = container_name(&params.instance_name);
    params.image = "node:replacement".into();
    engine.fail_pull_image = true;
    assert!(install_container(&mut engine, &params).is_err());
    assert!(engine.containers[&cname].1);
    assert_eq!(
        engine.removed_containers,
        <[std::string::String; 0]>::default()
    );
    engine.fail_pull_image = false;
    engine.fail_create_container = true;
    let error = install_container(&mut engine, &params).unwrap_err();
    assert!(error.to_string().contains("previous container was removed"));
    assert_eq!(
        engine.removed_volumes,
        <[std::string::String; 0]>::default()
    );
}

#[test]
fn reinstall_replaces_running_or_stopped_instance_and_reconciles_mtu() {
    for running in [false, true] {
        let mut engine = MockContainerEngine::default();
        let mut params = regression_params();
        install_container(&mut engine, &params).unwrap();
        let cname = container_name(&params.instance_name);
        engine.containers.get_mut(&cname).unwrap().1 = running;
        params.image = "node:new".into();
        params.mtu = Some(1400);
        params.extra_env = vec![
            ("DIORAMA_D2K".into(), "false".into()),
            ("SPECIAL".into(), "a\"b\\c\n".into()),
        ];
        let result = install_container(&mut engine, &params).unwrap();
        let config = &engine.containers[&cname].0;
        assert_eq!(config.image, "node:new");
        assert!(config.env.contains(&"DIORAMA_D2K=true".into()));
        assert!(!config.env.contains(&"DIORAMA_D2K=false".into()));
        assert_eq!(engine.created_containers.len(), 2);
        assert!(engine.removed_containers.contains(&cname));
        assert_eq!(
            engine.networks[&result.network_name].options["com.docker.network.driver.mtu"],
            "1400"
        );
        assert_eq!(engine.created_volumes.len(), 1);
        assert_eq!(
            engine.removed_volumes,
            <[std::string::String; 0]>::default()
        );
        let payload: serde_json::Value =
            serde_json::from_str(&serialize_container_create_request(config)).unwrap();
        assert_eq!(payload["Env"], serde_json::json!(config.env));
        assert_eq!(payload["HostConfig"]["Privileged"], true);
    }
}

#[test]
fn reserved_port_conflicts_fail_before_engine_mutation() {
    for (api, d2k, mapping) in [
        (6443, 2376, Some("127.0.0.1:6443:80")),
        (6443, 6443, None),
        (6443, 2376, Some("8443:6443")),
        (6443, 2376, Some("8443:2376")),
    ] {
        let mut engine = MockContainerEngine::default();
        let mut params = regression_params();
        params.apiserver_host_port = Some(api);
        params.d2k_host_port = Some(d2k);
        params.container_ports = mapping.map(String::from);
        assert!(install_container(&mut engine, &params).is_err());
        assert_eq!(
            engine.created_networks,
            <[std::string::String; 0]>::default()
        );
        assert_eq!(
            engine.created_volumes,
            <[std::string::String; 0]>::default()
        );
        assert_eq!(
            engine.created_containers,
            <[std::string::String; 0]>::default()
        );
    }
}

#[test]
fn engine_json_roundtrips_special_strings_and_labels() {
    let special = "a\"b\\c\n";
    let mut network = CreateNetworkRequest::new(special, None);
    network.options.insert(special.into(), special.into());
    let value: serde_json::Value =
        serde_json::from_str(&serialize_network_create_request(&network)).unwrap();
    assert_eq!(value["Name"], special);
    assert_eq!(value["Options"][special], special);
    let mut volume = CreateVolumeRequest::new(special);
    volume.labels.insert(special.into(), special.into());
    let value: serde_json::Value =
        serde_json::from_str(&serialize_volume_create_request(&volume)).unwrap();
    assert_eq!(value["Labels"][special], special);
}

#[test]
fn omitted_workload_addresses_are_loopback_and_explicit_addresses_survive() {
    let bindings = dioramactl::container::build_port_configuration(
        None,
        false,
        None,
        Some("8080:80,81,0.0.0.0:8082:82"),
    )
    .unwrap()
    .port_bindings;
    assert_eq!(bindings["80/tcp"][0].host_ip, "127.0.0.1");
    assert_eq!(bindings["81/tcp"][0].host_ip, "127.0.0.1");
    assert_eq!(bindings["82/tcp"][0].host_ip, "0.0.0.0");
}

#[test]
fn published_endpoints_require_a_nonzero_inspected_api_port() {
    let mut inspect = ContainerInspect {
        id: "id".into(),
        name: "dev".into(),
        running: true,
        d2k_enabled: false,
        exit_code: 0,
        allocated_ports: HashMap::new(),
    };
    assert!(dioramactl::container::published_endpoints(&inspect).is_none());
    inspect.allocated_ports.insert("6443/tcp".into(), 0);
    assert!(dioramactl::container::published_endpoints(&inspect).is_none());
    inspect.allocated_ports.insert("6443/tcp".into(), 49153);
    assert_eq!(
        dioramactl::container::published_endpoints(&inspect)
            .unwrap()
            .apiserver
            .port(),
        49153
    );
}

#[test]
fn missing_inspected_api_or_enabled_d2k_binding_fails_installation() {
    for port in ["6443/tcp", "2376/tcp"] {
        let mut engine = MockContainerEngine {
            omit_inspected_port: Some(port.into()),
            ..Default::default()
        };
        let error = install_container(&mut engine, &regression_params()).unwrap_err();
        assert!(error.to_string().contains("missing allocated"));
        assert_eq!(engine.removed_containers.len(), 1);
    }
}

#[test]
fn stopped_instances_do_not_report_retained_allocations() {
    let mut engine = MockContainerEngine::default();
    let result = install_container(&mut engine, &regression_params()).unwrap();
    let running = engine
        .inspect_container(&result.container_name)
        .unwrap()
        .unwrap();
    assert!(dioramactl::container::published_endpoints(&running).is_some());
    engine.stop_container(&result.container_name, 30).unwrap();
    let stopped = engine
        .inspect_container(&result.container_name)
        .unwrap()
        .unwrap();
    assert!(!stopped.allocated_ports.is_empty());
    assert!(dioramactl::container::published_endpoints(&stopped).is_none());
}

#[test]
fn d2k_endpoint_requires_effective_enablement_not_a_workload_binding() {
    for d2k_enabled in [false, true] {
        let mut engine = MockContainerEngine::default();
        let mut params = regression_params();
        params.d2k = d2k_enabled;
        params.container_ports = (!d2k_enabled).then(|| "8237:2376".into());
        let result = install_container(&mut engine, &params).unwrap();
        let inspect = engine
            .inspect_container(&result.container_name)
            .unwrap()
            .unwrap();
        assert!(inspect.allocated_ports.contains_key("2376/tcp"));
        let endpoints = dioramactl::container::published_endpoints(&inspect).unwrap();
        assert_eq!(endpoints.d2k.is_some(), d2k_enabled);
    }
}
