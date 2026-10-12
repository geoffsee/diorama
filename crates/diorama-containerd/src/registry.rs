//! Registry configuration management via containerd's `hosts.toml` directory model.
//!
//! `KubeSolo` configures containerd's `config_path` to point to a registry directory
//! (default: `<base_path>/containerd/registry`). Within this directory, operators
//! place per-host configurations:
//!
//! ```text
//! <registry_dir>/
//! ├── docker.io/
//! │   └── hosts.toml
//! ├── ghcr.io/
//! │   └── hosts.toml
//! └── _default/
//!     └── hosts.toml
//! ```
//!
//! containerd reads these files dynamically at pull time. These files survive
//! containerd configuration regenerations and service restarts.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryHostFile {
    /// Upstream registry server URL (e.g. `https://registry-1.docker.io`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Host endpoints for mirrors, proxies, or private instances.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub host: BTreeMap<String, HostEndpointConfig>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEndpointConfig {
    /// Capabilities supported by this endpoint (e.g. `["pull", "resolve"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// Set to true if the mirror path contains project prefix and containerd
    /// should not prepend its own `/v2/`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_path: Option<bool>,

    /// Path to a custom CA certificate file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,

    /// Skip TLS verification (useful for local insecure registries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_verify: Option<bool>,

    /// Custom HTTP headers (e.g. `Authorization = ["Basic ..."]`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub header: BTreeMap<String, Vec<String>>,
}

#[derive(Debug)]
pub enum RegistryError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    Serialize {
        source: toml::ser::Error,
    },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "I/O error at '{}': {source}", path.display())
            },
            Self::Parse { path, source } => {
                write!(f, "failed to parse TOML at '{}': {source}", path.display())
            },
            Self::Serialize { source } => {
                write!(f, "failed to serialize registry config to TOML: {source}")
            },
        }
    }
}

impl std::error::Error for RegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Serialize { source } => Some(source),
        }
    }
}

/// Ensure the base registry configuration directory exists.
pub fn ensure_registry_dir(registry_dir: &Path) -> Result<(), RegistryError> {
    fs::create_dir_all(registry_dir).map_err(|err| RegistryError::Io {
        path: registry_dir.to_path_buf(),
        source: err,
    })
}

/// Write a `hosts.toml` file for a specific registry host into the registry directory.
///
/// Places the file at `<registry_dir>/<host_name>/hosts.toml`.
pub fn write_registry_hosts_toml(
    registry_dir: &Path,
    host_name: &str,
    config: &RegistryHostFile,
) -> Result<PathBuf, RegistryError> {
    let host_dir = registry_dir.join(host_name);
    fs::create_dir_all(&host_dir).map_err(|err| RegistryError::Io {
        path: host_dir.clone(),
        source: err,
    })?;

    let target_file = host_dir.join("hosts.toml");
    let content =
        toml::to_string(config).map_err(|err| RegistryError::Serialize { source: err })?;

    let tmp_file = host_dir.join(".hosts.toml.tmp");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_file)
            .map_err(|err| RegistryError::Io {
                path: tmp_file.clone(),
                source: err,
            })?;

        file.write_all(content.as_bytes())
            .map_err(|err| RegistryError::Io {
                path: tmp_file.clone(),
                source: err,
            })?;

        file.sync_all().map_err(|err| RegistryError::Io {
            path: tmp_file.clone(),
            source: err,
        })?;
    }

    fs::rename(&tmp_file, &target_file).map_err(|err| RegistryError::Io {
        path: target_file.clone(),
        source: err,
    })?;

    Ok(target_file)
}

/// Read a `hosts.toml` file for a specific registry host.
pub fn read_registry_hosts_toml(
    registry_dir: &Path,
    host_name: &str,
) -> Result<Option<RegistryHostFile>, RegistryError> {
    let target_file = registry_dir.join(host_name).join("hosts.toml");
    if !target_file.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&target_file).map_err(|err| RegistryError::Io {
        path: target_file.clone(),
        source: err,
    })?;

    let config: RegistryHostFile =
        toml::from_str(&content).map_err(|err| RegistryError::Parse {
            path: target_file,
            source: err,
        })?;

    Ok(Some(config))
}

/// List all host names that have a configured `hosts.toml` inside the registry directory.
pub fn list_configured_registries(registry_dir: &Path) -> Result<Vec<String>, RegistryError> {
    if !registry_dir.exists() {
        return Ok(Vec::new());
    }

    let mut hosts = Vec::new();
    let entries = fs::read_dir(registry_dir).map_err(|err| RegistryError::Io {
        path: registry_dir.to_path_buf(),
        source: err,
    })?;

    for entry in entries {
        let entry = entry.map_err(|err| RegistryError::Io {
            path: registry_dir.to_path_buf(),
            source: err,
        })?;

        let path = entry.path();
        if path.is_dir()
            && path.join("hosts.toml").is_file()
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
        {
            hosts.push(name.to_string());
        }
    }

    hosts.sort();
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn roundtrip_registry_hosts_toml() {
        let temp = TempDir::new().unwrap();
        let registry_dir = temp.path().join("registry");

        let mut config = RegistryHostFile {
            server: Some("https://registry-1.docker.io".to_string()),
            host: BTreeMap::new(),
        };

        let mut endpoint = HostEndpointConfig {
            capabilities: vec!["pull".to_string(), "resolve".to_string()],
            override_path: Some(true),
            ca: Some("/etc/ssl/certs/harbor-ca.crt".to_string()),
            skip_verify: Some(false),
            header: BTreeMap::new(),
        };
        endpoint.header.insert(
            "Authorization".to_string(),
            vec!["Basic cm9ib3Q6dG9rZW4=".to_string()],
        );

        config.host.insert(
            "https://harbor.corp.internal/v2/docker.io".to_string(),
            endpoint,
        );

        let path = write_registry_hosts_toml(&registry_dir, "docker.io", &config).unwrap();
        assert!(path.is_file());

        let read_back = read_registry_hosts_toml(&registry_dir, "docker.io")
            .unwrap()
            .expect("should exist");
        assert_eq!(read_back, config);

        let hosts = list_configured_registries(&registry_dir).unwrap();
        assert_eq!(hosts, vec!["docker.io"]);
    }
}
