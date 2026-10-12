//! Named-instance lifecycle behavior against an in-memory engine.

use dioramactl::container::{
    ContainerConfig, ContainerEngineClient, ContainerInspect, ContainerInstallParams,
    CreateNetworkRequest, CreateVolumeRequest, container_name, install_container, network_name,
    volume_name,
};
use dioramactl::container_lifecycle::{
    InstanceState, instance_status, remove_instance, restart_instance, start_instance,
    stop_instance,
};
use std::collections::{HashMap, HashSet};
use std::io;

#[derive(Default)]
struct Engine {
    networks: HashSet<String>,
    volumes: HashSet<String>,
    images: HashSet<String>,
    containers: HashMap<String, (ContainerConfig, bool, HashMap<String, u16>)>,
    fail_remove_volume: Option<String>,
    fail_inspect_network: bool,
    fail_inspect_volume: bool,
    next_port: u16,
}

impl ContainerEngineClient for Engine {
    fn inspect_network(&mut self, n: &str) -> io::Result<Option<CreateNetworkRequest>> {
        if self.fail_inspect_network {
            return Err(io::Error::other("network inspection denied"));
        }
        Ok(self
            .networks
            .contains(n)
            .then(|| CreateNetworkRequest::new(n, Some(1400))))
    }
    fn create_network(&mut self, r: &CreateNetworkRequest) -> io::Result<()> {
        self.networks.insert(r.name.clone());
        Ok(())
    }
    fn remove_network(&mut self, n: &str) -> io::Result<()> {
        self.networks.remove(n);
        Ok(())
    }
    fn inspect_volume(&mut self, n: &str) -> io::Result<Option<()>> {
        if self.fail_inspect_volume {
            return Err(io::Error::other("volume inspection denied"));
        }
        Ok(self.volumes.contains(n).then_some(()))
    }
    fn create_volume(&mut self, r: &CreateVolumeRequest) -> io::Result<()> {
        self.volumes.insert(r.name.clone());
        Ok(())
    }
    fn remove_volume(&mut self, n: &str) -> io::Result<()> {
        if self.fail_remove_volume.as_deref() == Some(n) {
            return Err(io::Error::other("volume in use"));
        }
        self.volumes.remove(n);
        Ok(())
    }
    fn inspect_image(&mut self, i: &str) -> io::Result<Option<()>> {
        Ok(self.images.contains(i).then_some(()))
    }
    fn pull_image(&mut self, i: &str) -> io::Result<()> {
        self.images.insert(i.to_string());
        Ok(())
    }
    fn inspect_container(&mut self, n: &str) -> io::Result<Option<ContainerInspect>> {
        Ok(self
            .containers
            .get(n)
            .map(|(config, running, ports)| ContainerInspect {
                id: format!("id-{n}"),
                name: n.to_string(),
                running: *running,
                d2k_enabled: config.env.iter().any(|value| value == "KUBESOLO_D2K=true"),
                exit_code: if *running { 0 } else { 137 },
                allocated_ports: ports.clone(),
            }))
    }
    fn create_container(&mut self, n: &str, c: &ContainerConfig) -> io::Result<String> {
        self.next_port += 1;
        let mut ports = HashMap::new();
        for key in c.port_bindings.keys() {
            ports.insert(key.clone(), 40000 + self.next_port);
        }
        self.containers
            .insert(n.to_string(), (c.clone(), false, ports));
        Ok(n.to_string())
    }
    fn start_container(&mut self, n: &str) -> io::Result<()> {
        if let Some(c) = self.containers.get_mut(n) {
            c.1 = true;
        }
        Ok(())
    }
    fn stop_container(&mut self, n: &str, _t: u32) -> io::Result<()> {
        if let Some(c) = self.containers.get_mut(n) {
            c.1 = false;
        }
        Ok(())
    }
    fn remove_container(&mut self, n: &str, _f: bool) -> io::Result<()> {
        self.containers.remove(n);
        Ok(())
    }
}

fn params(name: &str) -> ContainerInstallParams {
    ContainerInstallParams {
        instance_name: name.to_string(),
        image: "img:1".to_string(),
        mtu: Some(1400),
        d2k: false,
        container_ports: None,
        extra_env: vec![],
        apiserver_host_port: None,
        d2k_host_port: None,
    }
}

#[test]
fn status_stop_start_restart_preserve_config_and_volume() {
    let mut e = Engine::default();
    install_container(&mut e, &params("a")).unwrap();
    let before = e.containers[&container_name("a")].0.clone();

    let s = instance_status(&mut e, "a").unwrap();
    assert_eq!(s.state, InstanceState::Running);
    assert!(s.endpoints.is_some() && s.network_present && s.volume_present);

    let s = stop_instance(&mut e, "a").unwrap();
    assert_eq!(s.state, InstanceState::Stopped { exit_code: 137 });
    assert!(s.endpoints.is_none());

    assert_eq!(
        start_instance(&mut e, "a").unwrap().state,
        InstanceState::Running
    );
    assert_eq!(
        restart_instance(&mut e, "a").unwrap().state,
        InstanceState::Running
    );
    let after = &e.containers[&container_name("a")].0;
    assert_eq!(after.binds, before.binds);
    assert_eq!(after.image, before.image);
    assert_eq!(after.port_bindings, before.port_bindings);
}

#[test]
fn missing_instance_is_reported() {
    let mut e = Engine::default();
    assert_eq!(
        instance_status(&mut e, "x").unwrap().state,
        InstanceState::Absent
    );
    assert!(start_instance(&mut e, "x").is_err());
    assert!(stop_instance(&mut e, "x").is_err());
}

#[test]
fn remove_keeps_volume_so_recreation_retains_data() {
    let mut e = Engine::default();
    install_container(&mut e, &params("a")).unwrap();
    let r = remove_instance(&mut e, "a", false);
    assert!(r.is_complete());
    assert!(e.volumes.contains(&volume_name("a")));
    assert!(e.networks.contains(&network_name("a")));
    let again = install_container(&mut e, &params("a")).unwrap();
    assert!(!again.created_new_volume);
}

#[test]
fn purge_targets_only_selected_instance_and_reports_partial_failure() {
    let mut e = Engine::default();
    install_container(&mut e, &params("a")).unwrap();
    install_container(&mut e, &params("b")).unwrap();
    e.fail_remove_volume = Some(volume_name("a"));

    let r = remove_instance(&mut e, "a", true);
    assert!(!r.is_complete());
    assert_eq!(r.failures.len(), 1);
    assert!(r.failures[0].contains(&volume_name("a")));
    assert!(!e.containers.contains_key(&container_name("a")));
    assert!(!e.networks.contains(&network_name("a")));

    assert_eq!(
        instance_status(&mut e, "b").unwrap().state,
        InstanceState::Running
    );
    assert!(e.volumes.contains(&volume_name("b")));
    assert!(e.networks.contains(&network_name("b")));
}

#[test]
fn purge_reports_inspection_errors_and_continues_with_other_resources() {
    for (network, volume) in [(true, false), (false, true), (true, true)] {
        let mut engine = Engine::default();
        install_container(&mut engine, &params("dev")).unwrap();
        engine.fail_inspect_network = network;
        engine.fail_inspect_volume = volume;
        let report = remove_instance(&mut engine, "dev", true);
        assert!(!report.is_complete());
        assert_eq!(
            report.failures.len(),
            usize::from(network) + usize::from(volume)
        );
        assert_eq!(engine.networks.contains(&network_name("dev")), network);
        assert_eq!(engine.volumes.contains(&volume_name("dev")), volume);
        assert!(!engine.containers.contains_key(&container_name("dev")));
    }
}

#[test]
fn status_does_not_identify_disabled_d2k_workload_as_a_service() {
    let mut engine = Engine::default();
    let mut options = params("dev");
    options.container_ports = Some("8237:2376".into());
    install_container(&mut engine, &options).unwrap();
    let status = instance_status(&mut engine, "dev").unwrap();
    assert!(status.endpoints.unwrap().d2k.is_none());
    stop_instance(&mut engine, "dev").unwrap();
    assert!(
        instance_status(&mut engine, "dev")
            .unwrap()
            .endpoints
            .is_none()
    );
}
