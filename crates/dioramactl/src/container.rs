//! Container lifecycle and Docker/Podman Engine client interaction for container mode.
//!
//! Matches Portainer `KubeSolo` `internal/cli/service/container.go` contract at commit `2ef1c4787989f11f868f81bb84ae2afd4a49a81d`.
//! Manages named containers, dedicated bridge networks, named persistent volumes,
//! port bindings, and partial-failure cleanup (cleaning only newly created resources).

use crate::container_ports::parse_container_ports;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;

/// Resolves the Docker container name for a cluster instance.
///
/// If name is "diorama" (default), "kubesolo", or empty, returns "kubesolo".
/// Otherwise returns "kubesolo-<name>".
pub fn container_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed == "diorama" || trimmed == "kubesolo" {
        "kubesolo".to_string()
    } else {
        format!("kubesolo-{trimmed}")
    }
}

/// Resolves the dedicated Docker bridge network name for a cluster instance.
///
/// Follows `<container_name>-net`.
pub fn network_name(name: &str) -> String {
    format!("{}-net", container_name(name))
}

/// Resolves the named Docker volume name for a cluster instance.
///
/// Follows `<container_name>-data`.
pub fn volume_name(name: &str) -> String {
    format!("{}-data", container_name(name))
}

/// Request payload for creating a Docker network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateNetworkRequest {
    pub name: String,
    pub driver: String,
    pub options: BTreeMap<String, String>,
}

impl CreateNetworkRequest {
    pub fn new(name: impl Into<String>, mtu: Option<u32>) -> Self {
        let mut options = BTreeMap::new();
        let mtu_val = mtu.unwrap_or(1500);
        options.insert(
            "com.docker.network.driver.mtu".to_string(),
            mtu_val.to_string(),
        );
        Self {
            name: name.into(),
            driver: "bridge".to_string(),
            options,
        }
    }
}

/// Request payload for creating a Docker volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateVolumeRequest {
    pub name: String,
    pub driver: String,
    pub labels: BTreeMap<String, String>,
}

impl CreateVolumeRequest {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            driver: "local".to_string(),
            labels: BTreeMap::new(),
        }
    }
}

/// Host port binding representation in Docker Engine API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPortBinding {
    pub host_ip: String,
    pub host_port: String,
}

/// Port configuration and bindings for container creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerPortConfig {
    /// Map of `<container_port>/<protocol>` to empty object for `ExposedPorts`.
    pub exposed_ports: Vec<String>,
    /// Map of `<container_port>/<protocol>` to list of `HostPortBinding` for `PortBindings`.
    pub port_bindings: BTreeMap<String, Vec<HostPortBinding>>,
}

/// Configuration for creating a diorama container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerConfig {
    pub image: String,
    pub hostname: String,
    pub env: Vec<String>,
    pub exposed_ports: Vec<String>,
    pub port_bindings: BTreeMap<String, Vec<HostPortBinding>>,
    pub binds: Vec<String>,
    pub network_mode: String,
    pub privileged: bool,
    pub cgroupns_mode: String,
    pub restart_policy: String,
}

/// Container status inspection summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerInspect {
    pub id: String,
    pub name: String,
    pub running: bool,
    /// Effective D2K configuration observed on this instance, independent of workload ports.
    pub d2k_enabled: bool,
    pub exit_code: i32,
    /// Host port mapping discovered from running container inspection.
    /// Maps e.g. "6443/tcp" to the allocated host port (such as 32768 or 6443).
    pub allocated_ports: HashMap<String, u16>,
}

/// Abstraction for Docker Engine API interactions.
///
/// Enables mock-driven testing without a live Docker daemon,
/// verification of Linux/macOS engine requests, and WSL2 workflow qualification.
pub trait ContainerEngineClient {
    /// Inspects whether a network exists.
    fn inspect_network(&mut self, name: &str) -> io::Result<Option<CreateNetworkRequest>>;
    /// Creates a network.
    fn create_network(&mut self, req: &CreateNetworkRequest) -> io::Result<()>;
    /// Removes a network.
    fn remove_network(&mut self, name: &str) -> io::Result<()>;

    /// Inspects whether a volume exists.
    fn inspect_volume(&mut self, name: &str) -> io::Result<Option<()>>;
    /// Creates a volume.
    fn create_volume(&mut self, req: &CreateVolumeRequest) -> io::Result<()>;
    /// Removes a volume.
    fn remove_volume(&mut self, name: &str) -> io::Result<()>;

    /// Inspects whether an image exists locally.
    fn inspect_image(&mut self, image: &str) -> io::Result<Option<()>>;
    /// Pulls an image if missing.
    fn pull_image(&mut self, image: &str) -> io::Result<()>;
    /// Import an already verified compressed Docker image archive.
    fn load_image(&mut self, _bytes: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "image import is not implemented by this Engine adapter",
        ))
    }

    /// Inspects container state.
    fn inspect_container(&mut self, name: &str) -> io::Result<Option<ContainerInspect>>;
    /// Creates a container with the given name and config.
    fn create_container(&mut self, name: &str, config: &ContainerConfig) -> io::Result<String>;
    /// Starts a container.
    fn start_container(&mut self, id_or_name: &str) -> io::Result<()>;
    /// Stops a container.
    fn stop_container(&mut self, id_or_name: &str, timeout_secs: u32) -> io::Result<()>;
    /// Removes a container.
    fn remove_container(&mut self, id_or_name: &str, force: bool) -> io::Result<()>;
}

/// Tracks newly created resources during a lifecycle operation to support selective rollback.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreatedResources {
    pub network: Option<String>,
    pub volume: Option<String>,
    pub container: Option<String>,
}

impl CreatedResources {
    /// Rolls back only newly created resources on failure.
    pub fn rollback(&mut self, engine: &mut dyn ContainerEngineClient) -> Vec<String> {
        let mut warnings = Vec::new();

        if let Some(cname) = self.container.take()
            && let Err(e) = engine.remove_container(&cname, true)
        {
            warnings.push(format!("failed to remove container {cname}: {e}"));
        }

        if let Some(nname) = self.network.take()
            && let Err(e) = engine.remove_network(&nname)
        {
            warnings.push(format!("failed to remove network {nname}: {e}"));
        }

        if let Some(vname) = self.volume.take()
            && let Err(e) = engine.remove_volume(&vname)
        {
            warnings.push(format!("failed to remove volume {vname}: {e}"));
        }

        warnings
    }
}

/// Input parameters for container mode installation.
#[derive(Clone, Debug)]
pub struct ContainerInstallParams {
    pub instance_name: String,
    pub image: String,
    pub mtu: Option<u32>,
    pub d2k: bool,
    pub container_ports: Option<String>,
    pub extra_env: Vec<(String, String)>,
    pub apiserver_host_port: Option<u16>,
    pub d2k_host_port: Option<u16>,
}

/// Result of container installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerInstallResult {
    pub container_name: String,
    pub container_id: String,
    pub network_name: String,
    pub volume_name: String,
    pub apiserver_port: u16,
    pub d2k_port: Option<u16>,
    pub created_new_network: bool,
    pub created_new_volume: bool,
}

/// Errors during container lifecycle operations.
#[derive(Debug)]
pub enum ContainerLifecycleError {
    InvalidRunMode(String),
    UnsupportedCpuManagerPolicy(String),
    PortValidation(crate::container_ports::PortParseError),
    Engine(String),
    RollbackFailed(Vec<String>),
}

impl fmt::Display for ContainerLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRunMode(mode) => {
                write!(
                    f,
                    "invalid run-mode \"{mode}\"; container mode required on this platform"
                )
            },
            Self::UnsupportedCpuManagerPolicy(p) => {
                write!(
                    f,
                    "cpu-manager-policy \"{p}\" is not supported in container mode (only \"none\" is supported)"
                )
            },
            Self::PortValidation(err) => write!(f, "container port error: {err}"),
            Self::Engine(err) => write!(f, "container engine error: {err}"),
            Self::RollbackFailed(warns) => {
                write!(f, "rollback warnings: {}", warns.join("; "))
            },
        }
    }
}

impl std::error::Error for ContainerLifecycleError {}

/// Builds port bindings for the container creation request.
///
/// Maps 6443/tcp (API server) to 127.0.0.1 with ephemeral or explicit host port.
/// If d2k is enabled, maps 2376/tcp to 127.0.0.1 with ephemeral or explicit host port.
/// Appends any validated user `--container-ports`.
pub fn build_port_configuration(
    apiserver_host_port: Option<u16>,
    d2k: bool,
    d2k_host_port: Option<u16>,
    user_ports: Option<&str>,
) -> Result<ContainerPortConfig, ContainerLifecycleError> {
    let mut exposed_ports = Vec::new();
    let mut port_bindings: BTreeMap<String, Vec<HostPortBinding>> = BTreeMap::new();
    if apiserver_host_port == Some(0) || (d2k && d2k_host_port == Some(0)) {
        return Err(ContainerLifecycleError::PortValidation(
            crate::container_ports::PortParseError::InvalidPortNumber("0".into()),
        ));
    }
    if d2k
        && let Some(port) = apiserver_host_port
        && Some(port) == d2k_host_port
    {
        return Err(ContainerLifecycleError::PortValidation(
            crate::container_ports::PortParseError::DuplicateHostPort(port, "tcp".into()),
        ));
    }

    // 1. Kubernetes API Server: 6443/tcp
    let api_key = "6443/tcp".to_string();
    exposed_ports.push(api_key.clone());
    let api_host_port_str = apiserver_host_port.map_or_else(String::new, |p| p.to_string());
    port_bindings.insert(
        api_key,
        vec![HostPortBinding {
            host_ip: "127.0.0.1".to_string(),
            host_port: api_host_port_str,
        }],
    );

    // 2. D2K (Docker-to-Kubernetes API): 2376/tcp if enabled
    if d2k {
        let d2k_key = "2376/tcp".to_string();
        exposed_ports.push(d2k_key.clone());
        let d2k_host_port_str = d2k_host_port.map_or_else(String::new, |p| p.to_string());
        port_bindings.insert(
            d2k_key,
            vec![HostPortBinding {
                host_ip: "127.0.0.1".to_string(),
                host_port: d2k_host_port_str,
            }],
        );
    }

    // 3. User container ports
    if let Some(specs) = user_ports {
        let parsed_mappings =
            parse_container_ports(specs).map_err(ContainerLifecycleError::PortValidation)?;

        for mapping in parsed_mappings {
            if mapping.protocol == "tcp" {
                if mapping.container_port == 6443 || (d2k && mapping.container_port == 2376) {
                    return Err(ContainerLifecycleError::PortValidation(
                        crate::container_ports::PortParseError::DuplicateContainerPort(
                            mapping.container_port,
                            mapping.protocol,
                        ),
                    ));
                }
                if Some(mapping.host_port) == apiserver_host_port
                    || (d2k && Some(mapping.host_port) == d2k_host_port)
                {
                    return Err(ContainerLifecycleError::PortValidation(
                        crate::container_ports::PortParseError::DuplicateHostPort(
                            mapping.host_port,
                            mapping.protocol,
                        ),
                    ));
                }
            }
            let key = mapping.container_port_key();
            if !exposed_ports.contains(&key) {
                exposed_ports.push(key.clone());
            }

            let binding = HostPortBinding {
                host_ip: mapping.host_ip,
                host_port: mapping.host_port.to_string(),
            };

            port_bindings.entry(key).or_default().push(binding);
        }
    }

    Ok(ContainerPortConfig {
        exposed_ports,
        port_bindings,
    })
}

/// Executes container creation and startup workflow matching `KubeSolo` container mode contract.
///
/// Steps:
/// 1. Validate CPU manager policy (must be "none")
/// 2. Validate container ports and prepare port bindings
/// 3. Pull image if needed, before replacing an existing instance
/// 4. Verify/create network `<cname>-net`
/// 5. Verify/create volume `<cname>-data`
/// 6. Create container with:
///    - `Privileged`: true
///    - `CgroupnsMode`: "host"
///    - `Binds`: `["<vname>:/var/lib/diorama"]`
///    - `NetworkMode`: `"<nname>"`
///    - `RestartPolicy`: "unless-stopped"
///    - `PortBindings`: 6443/tcp (+ optional 2376/tcp, + user ports)
/// 7. Start container
/// 8. Inspect container to resolve actual host port bindings for readiness address
///
/// On failure at any step, rolls back ONLY newly created resources (preserves pre-existing ones).
#[allow(clippy::too_many_lines)]
pub fn install_container(
    engine: &mut dyn ContainerEngineClient,
    params: &ContainerInstallParams,
) -> Result<ContainerInstallResult, ContainerLifecycleError> {
    install_container_inner(engine, params, None)
}

/// Install using the exact bytes and tag validated by the offline image decoder.
pub fn install_container_with_bundled_image(
    engine: &mut dyn ContainerEngineClient,
    params: &ContainerInstallParams,
    image: &crate::container_image::VerifiedContainerImage<'_>,
) -> Result<ContainerInstallResult, ContainerLifecycleError> {
    if params.image != image.reference() {
        return Err(ContainerLifecycleError::Engine(
            "installation image disagrees with verified bundle tag".into(),
        ));
    }
    install_container_inner(engine, params, Some(image))
}

#[allow(clippy::too_many_lines)]
fn install_container_inner(
    engine: &mut dyn ContainerEngineClient,
    params: &ContainerInstallParams,
    bundled: Option<&crate::container_image::VerifiedContainerImage<'_>>,
) -> Result<ContainerInstallResult, ContainerLifecycleError> {
    // 0. Validate CPU manager policy (only "none" supported in container mode)
    if let Some((_, v)) = params
        .extra_env
        .iter()
        .find(|(k, _)| k == "KUBESOLO_CPU_MANAGER_POLICY")
        && v != "none"
        && !v.is_empty()
    {
        return Err(ContainerLifecycleError::UnsupportedCpuManagerPolicy(
            v.clone(),
        ));
    }

    let cname = container_name(&params.instance_name);
    let nname = network_name(&params.instance_name);
    let vname = volume_name(&params.instance_name);

    // Build and validate port configurations first
    let port_config = build_port_configuration(
        params.apiserver_host_port,
        params.d2k,
        params.d2k_host_port,
        params.container_ports.as_deref(),
    )?;

    let mut created = CreatedResources::default();
    let mut removed_existing = false;

    let install_action = || -> Result<ContainerInstallResult, ContainerLifecycleError> {
        if let Some(image) = bundled {
            engine.load_image(image.bytes()).map_err(|e| {
                ContainerLifecycleError::Engine(format!("verified image import failed: {e}"))
            })?;
        }
        let image_exists = engine
            .inspect_image(&params.image)
            .map_err(|e| ContainerLifecycleError::Engine(format!("image inspect failed: {e}")))?
            .is_some();
        if !image_exists {
            if bundled.is_some() {
                return Err(ContainerLifecycleError::Engine(
                    "verified image tag is unavailable after import; registry fallback is disabled"
                        .into(),
                ));
            }
            engine
                .pull_image(&params.image)
                .map_err(|e| ContainerLifecycleError::Engine(format!("image pull failed: {e}")))?;
        }
        // Reinstall only the selected instance; retain its persistent data volume.
        if let Some(existing) = engine.inspect_container(&cname).map_err(|e| {
            ContainerLifecycleError::Engine(format!("container inspect failed: {e}"))
        })? {
            if existing.running {
                engine.stop_container(&cname, 10).map_err(|e| {
                    ContainerLifecycleError::Engine(format!("container stop failed: {e}"))
                })?;
            }
            engine.remove_container(&cname, false).map_err(|e| {
                ContainerLifecycleError::Engine(format!("container removal failed: {e}"))
            })?;
            removed_existing = true;
        }
        // 1. Ensure Network
        let network = engine
            .inspect_network(&nname)
            .map_err(|e| ContainerLifecycleError::Engine(format!("network inspect failed: {e}")))?;
        let requested_network = CreateNetworkRequest::new(&nname, params.mtu);
        let network_exists = if let Some(existing) = network {
            if existing.driver != requested_network.driver
                || existing.options != requested_network.options
            {
                engine.remove_network(&nname).map_err(|e| {
                    ContainerLifecycleError::Engine(format!("network reconcile failed: {e}"))
                })?;
                false
            } else {
                true
            }
        } else {
            false
        };

        let created_new_network = if network_exists {
            false
        } else {
            let net_req = CreateNetworkRequest::new(&nname, params.mtu);
            engine.create_network(&net_req).map_err(|e| {
                ContainerLifecycleError::Engine(format!("network create failed: {e}"))
            })?;
            created.network = Some(nname.clone());
            true
        };

        // 2. Ensure Volume
        let volume_exists = engine
            .inspect_volume(&vname)
            .map_err(|e| ContainerLifecycleError::Engine(format!("volume inspect failed: {e}")))?
            .is_some();

        let created_new_volume = if volume_exists {
            false
        } else {
            let vol_req = CreateVolumeRequest::new(&vname);
            engine.create_volume(&vol_req).map_err(|e| {
                ContainerLifecycleError::Engine(format!("volume create failed: {e}"))
            })?;
            created.volume = Some(vname.clone());
            true
        };

        // 5. Build ContainerConfig
        let mut env_vars = vec![
            "KUBESOLO_CONTAINER_MODE=true".to_string(),
            format!("KUBESOLO_NAME={}", params.instance_name),
        ];
        for (k, v) in &params.extra_env {
            if !matches!(
                k.as_str(),
                "KUBESOLO_D2K" | "KUBESOLO_CONTAINER_MODE" | "KUBESOLO_NAME"
            ) {
                env_vars.push(format!("{k}={v}"));
            }
        }

        env_vars.push(format!("KUBESOLO_D2K={}", params.d2k));

        let container_cfg = ContainerConfig {
            image: params.image.clone(),
            hostname: cname.clone(),
            env: env_vars,
            exposed_ports: port_config.exposed_ports,
            port_bindings: port_config.port_bindings,
            binds: vec![format!("{vname}:/var/lib/diorama")],
            network_mode: nname.clone(),
            privileged: true,
            cgroupns_mode: "host".to_string(),
            restart_policy: "unless-stopped".to_string(),
        };

        // 6. Create container
        let container_id = engine
            .create_container(&cname, &container_cfg)
            .map_err(|e| {
                ContainerLifecycleError::Engine(format!("container create failed: {e}"))
            })?;
        created.container = Some(cname.clone());

        // 7. Start container
        engine
            .start_container(&container_id)
            .map_err(|e| ContainerLifecycleError::Engine(format!("container start failed: {e}")))?;

        // 8. Inspect container to discover allocated host ports
        let inspect = engine
            .inspect_container(&container_id)
            .map_err(|e| {
                ContainerLifecycleError::Engine(format!("post-start inspect failed: {e}"))
            })?
            .ok_or_else(|| {
                ContainerLifecycleError::Engine("container not found after start".to_string())
            })?;

        let apiserver_port = inspect
            .allocated_ports
            .get("6443/tcp")
            .copied()
            .filter(|port| *port != 0)
            .ok_or_else(|| ContainerLifecycleError::Engine("missing allocated API port".into()))?;

        let d2k_port = if params.d2k {
            Some(
                inspect
                    .allocated_ports
                    .get("2376/tcp")
                    .copied()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| {
                        ContainerLifecycleError::Engine("missing allocated D2K port".into())
                    })?,
            )
        } else {
            None
        };

        Ok(ContainerInstallResult {
            container_name: cname,
            container_id,
            network_name: nname,
            volume_name: vname,
            apiserver_port,
            d2k_port,
            created_new_network,
            created_new_volume,
        })
    };

    match install_action() {
        Ok(result) => Ok(result),
        Err(err) => {
            let rollback_warnings = created.rollback(engine);
            if !rollback_warnings.is_empty() {
                eprintln!("warnings during cleanup: {}", rollback_warnings.join(", "));
            }
            if removed_existing {
                Err(ContainerLifecycleError::Engine(format!(
                    "{err}; previous container was removed; existing data volume retained"
                )))
            } else {
                Err(err)
            }
        },
    }
}
/// Host endpoints published by a running instance, as reported by engine inspection.
///
/// API and D2K bindings use loopback; the host port is whatever the
/// engine actually allocated, which differs from the request when ephemeral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedEndpoints {
    pub apiserver: std::net::SocketAddr,
    pub d2k: Option<std::net::SocketAddr>,
}

/// Discovers the published API (and optional d2k) endpoints from an inspected container.
///
/// Returns `None` when the container does not publish the API server port, so callers
/// never fabricate an address that the engine did not allocate.
#[must_use]
pub fn published_endpoints(inspect: &ContainerInspect) -> Option<PublishedEndpoints> {
    if !inspect.running {
        return None;
    }
    let loopback = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let api = *inspect
        .allocated_ports
        .get("6443/tcp")
        .filter(|port| **port != 0)?;
    Some(PublishedEndpoints {
        apiserver: std::net::SocketAddr::new(loopback, api),
        d2k: inspect
            .allocated_ports
            .get("2376/tcp")
            .filter(|_| inspect.d2k_enabled)
            .filter(|port| **port != 0)
            .map(|p| std::net::SocketAddr::new(loopback, *p)),
    })
}
