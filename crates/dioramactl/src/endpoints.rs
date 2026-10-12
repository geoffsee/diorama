//! Published container endpoint resolution and selective kubeconfig edits for
//! named instances. Only the entries owned by the selected context are touched;
//! certificate and credential data are never modified.
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::time::SystemTime;

use serde_json::Value;

use crate::contract::KubeconfigOptions;
use crate::kubeconfig::{
    atomic_write_secure, create_premerge_backup, parse_kubeconfig_content, resolve_destination,
    resolve_invoking_user, serialize_kubeconfig,
};

/// Host-reachable loopback endpoint a container published its API port on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedEndpoint {
    pub port: u16,
}

impl PublishedEndpoint {
    /// Server URL routed through loopback, preserving the https scheme.
    pub fn server_url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EndpointError {
    NoPublishedPort,
    ContextNotFound(String),
    ClusterNotFound(String),
    SharedCluster(String),
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPublishedPort => f.write_str("no published host port found"),
            Self::ContextNotFound(n) => write!(f, "context '{n}' not found"),
            Self::ClusterNotFound(n) => write!(f, "cluster '{n}' not found"),
            Self::SharedCluster(n) => write!(
                f,
                "cluster '{n}' is shared with another context; routing would change its endpoint"
            ),
        }
    }
}

impl std::error::Error for EndpointError {}

/// Parses `docker port <container> <port>/tcp` output (for example
/// `0.0.0.0:49153` and `[::]:49153`) into a loopback endpoint.
pub fn resolve_published_endpoint(port_output: &str) -> Result<PublishedEndpoint, EndpointError> {
    let mut port = None;
    for line in port_output.lines().filter(|line| !line.trim().is_empty()) {
        let address: std::net::SocketAddr = line
            .trim()
            .parse()
            .map_err(|_| EndpointError::NoPublishedPort)?;
        if address.port() == 0
            || !(address.ip().is_unspecified() || address.ip().is_loopback())
            || port.is_some_and(|p| p != address.port())
        {
            return Err(EndpointError::NoPublishedPort);
        }
        port = Some(address.port());
    }
    port.map(|port| PublishedEndpoint { port })
        .ok_or(EndpointError::NoPublishedPort)
}

fn find_named<'a>(cfg: &'a Value, list: &str, name: &str) -> Option<&'a Value> {
    cfg.get(list)?
        .as_array()?
        .iter()
        .find(|e| e.get("name").and_then(Value::as_str) == Some(name))
}

/// Rewrites only the server of the cluster referenced by `context`.
/// Certificate authority and user credentials remain intact.
pub fn route_context(
    cfg: &mut Value,
    context: &str,
    endpoint: PublishedEndpoint,
) -> Result<(), EndpointError> {
    let cluster_name = find_named(cfg, "contexts", context)
        .ok_or_else(|| EndpointError::ContextNotFound(context.to_string()))?
        .get("context")
        .and_then(|c| c.get("cluster"))
        .and_then(Value::as_str)
        .ok_or_else(|| EndpointError::ClusterNotFound(String::new()))?
        .to_string();
    if cfg
        .get("contexts")
        .and_then(Value::as_array)
        .is_some_and(|contexts| {
            contexts.iter().any(|entry| {
                entry.get("name").and_then(Value::as_str) != Some(context)
                    && entry
                        .get("context")
                        .and_then(|value| value.get("cluster"))
                        .and_then(Value::as_str)
                        == Some(cluster_name.as_str())
            })
        })
    {
        return Err(EndpointError::SharedCluster(cluster_name));
    }
    let cluster = cfg
        .get_mut("clusters")
        .and_then(Value::as_array_mut)
        .and_then(|l| {
            l.iter_mut()
                .find(|e| e.get("name").and_then(Value::as_str) == Some(&cluster_name))
        })
        .and_then(|e| e.get_mut("cluster"))
        .and_then(Value::as_object_mut)
        .ok_or(EndpointError::ClusterNotFound(cluster_name))?;
    cluster.insert("server".to_string(), Value::String(endpoint.server_url()));
    Ok(())
}

fn referenced(cfg: &Value, key: &str, name: &str) -> bool {
    cfg.get("contexts")
        .and_then(Value::as_array)
        .is_some_and(|l| {
            l.iter().any(|c| {
                c.get("context")
                    .and_then(|x| x.get(key))
                    .and_then(Value::as_str)
                    == Some(name)
            })
        })
}

/// Removes the named context and its cluster/user entries when no other
/// context still references them. Unrelated data is preserved; a matching
/// `current-context` is cleared. Returns whether the context existed.
pub fn remove_instance(cfg: &mut Value, context: &str) -> bool {
    let Some(entry) = find_named(cfg, "contexts", context) else {
        return false;
    };
    let ctx = entry.get("context");
    let cluster = ctx
        .and_then(|c| c.get("cluster"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let user = ctx
        .and_then(|c| c.get("user"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let drop_named = |cfg: &mut Value, list: &str, name: &str| {
        if let Some(l) = cfg.get_mut(list).and_then(Value::as_array_mut) {
            l.retain(|e| e.get("name").and_then(Value::as_str) != Some(name));
        }
    };
    drop_named(cfg, "contexts", context);
    if let Some(c) = cluster
        && !referenced(cfg, "cluster", &c)
    {
        drop_named(cfg, "clusters", &c);
    }
    if let Some(u) = user
        && !referenced(cfg, "user", &u)
    {
        drop_named(cfg, "users", &u);
    }
    if cfg.get("current-context").and_then(Value::as_str) == Some(context)
        && let Some(o) = cfg.as_object_mut()
    {
        o.remove("current-context");
    }
    true
}

/// Narrow seam for container engine port inspection.
///
/// Implementations resolve the instance's container name and return the raw
/// `docker port <container> <port>/tcp` output for [`resolve_published_endpoint`].
pub trait EnginePortInspector {
    fn inspect_port(&mut self, container: &str, container_port: u16) -> io::Result<String>;
}

/// Production inspector for the named Docker instance's published API port.
#[derive(Debug)]
pub struct DockerPortInspector;

impl EnginePortInspector for DockerPortInspector {
    fn inspect_port(&mut self, instance: &str, container_port: u16) -> io::Result<String> {
        let output = std::process::Command::new("docker")
            .args([
                "port",
                &crate::container::container_name(instance),
                &format!("{container_port}/tcp"),
            ])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "docker port failed with {}",
                output.status
            )));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Docker port output"))
    }
}

/// Explicit unavailable inspector for callers that do not permit Engine access.
#[derive(Debug)]
pub struct UnavailableEngine;

impl EnginePortInspector for UnavailableEngine {
    fn inspect_port(&mut self, _container: &str, _container_port: u16) -> io::Result<String> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "container engine port inspection is not available in this build",
        ))
    }
}

/// Kubernetes API port inside the container.
pub const CONTAINER_API_PORT: u16 = 6443;

/// Executes `dioramactl kubeconfig route|remove --name <instance>`.
pub fn execute_endpoint_command(
    options: &KubeconfigOptions,
    engine: &mut dyn EnginePortInspector,
    environment: &BTreeMap<String, String>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    if !matches!(options.subcommand.as_deref(), Some("route" | "remove")) {
        writeln!(stderr, "error: unknown kubeconfig endpoint subcommand")?;
        return Ok(1);
    }
    let Some(name) = options.name.as_deref().filter(|n| !n.is_empty()) else {
        writeln!(
            stderr,
            "error: --name is required for kubeconfig route/remove"
        )?;
        return Ok(1);
    };
    let user = resolve_invoking_user(environment);
    let dest = resolve_destination(&user, options.output.as_deref());
    let Ok(content) = fs::read_to_string(&dest) else {
        writeln!(
            stderr,
            "error: failed to read kubeconfig {}",
            dest.display()
        )?;
        return Ok(1);
    };
    let Ok(mut cfg) = parse_kubeconfig_content(&content) else {
        writeln!(stderr, "error: invalid kubeconfig {}", dest.display())?;
        return Ok(1);
    };
    let remove = options.subcommand.as_deref() == Some("remove");
    let message = if remove {
        if !remove_instance(&mut cfg, name) {
            writeln!(stderr, "error: context '{name}' not found")?;
            return Ok(1);
        }
        format!("Removed context '{name}' from {}", dest.display())
    } else {
        let raw = match engine.inspect_port(name, CONTAINER_API_PORT) {
            Ok(raw) => raw,
            Err(err) => {
                writeln!(stderr, "error: port inspection failed: {err}")?;
                return Ok(1);
            },
        };
        let endpoint = match resolve_published_endpoint(&raw) {
            Ok(e) => e,
            Err(err) => {
                writeln!(stderr, "error: {err}")?;
                return Ok(1);
            },
        };
        if let Err(err) = route_context(&mut cfg, name, endpoint) {
            writeln!(stderr, "error: {err}")?;
            return Ok(1);
        }
        format!("Routed context '{name}' to {}", endpoint.server_url())
    };
    if let Some(backup) = create_premerge_backup(&dest, SystemTime::now())? {
        writeln!(
            stderr,
            "Created backup of existing kubeconfig at {}",
            backup.display()
        )?;
    }
    atomic_write_secure(&dest, serialize_kubeconfig(&cfg).as_bytes(), &user)?;
    writeln!(stdout, "{message}")?;
    Ok(0)
}
