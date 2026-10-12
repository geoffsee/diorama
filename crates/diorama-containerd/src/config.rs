//! Containerd configuration generator and serializer.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cgroup::use_systemd_cgroup;
use crate::shim::{DEFAULT_SHIM_BINARY_NAME, RUNTIME_RUNC_V2};
use crate::snapshotter::{Snapshotter, detect_snapshotter};

/// Standard containerd config format version.
pub const CONTAINERD_CONFIG_VERSION: u32 = 3;

/// Default configuration directory for drop-in imports.
pub const DEFAULT_CONTAINERD_CONFIG_DIR: &str = "/etc/containerd/config.d";

/// Default standard CNI configuration directory.
pub const DEFAULT_STANDARD_CNI_CONF_DIR: &str = "/etc/cni/net.d";

/// Default image pull progress timeout.
pub const DEFAULT_IMAGE_PULL_TIMEOUT: &str = "2m0s";

/// Default sandbox image reference.
pub const DEFAULT_SANDBOX_IMAGE: &str = "portainer/pause:latest";

/// Default runtime name.
pub const DEFAULT_RUNTIME_NAME: &str = "crun";

/// Supported task platforms.
pub const DEFAULT_PLATFORMS: &[&str] = &["linux/amd64", "linux/arm64", "linux/arm"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerdConfigFile {
    pub version: u32,
    pub root: String,
    pub state: String,
    pub imports: Vec<String>,
    pub grpc: GrpcConfig,
    pub plugins: PluginsConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrpcConfig {
    pub address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginsConfig {
    #[serde(rename = "io.containerd.cri.v1.images")]
    pub cri_images: CriImagesPluginConfig,

    #[serde(rename = "io.containerd.cri.v1.runtime")]
    pub cri_runtime: CriRuntimePluginConfig,

    #[serde(rename = "io.containerd.runtime.v2.task")]
    pub task: TaskPluginConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriImagesPluginConfig {
    pub image_pull_progress_timeout: String,
    pub pinned_images: PinnedImagesConfig,
    pub registry: RegistryPluginConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedImagesConfig {
    pub sandbox: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryPluginConfig {
    pub config_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriRuntimePluginConfig {
    pub cni: CniConfig,
    pub containerd: ContainerdRuntimeSettings,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CniConfig {
    pub bin_dirs: Vec<String>,
    pub conf_dir: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerdRuntimeSettings {
    pub default_runtime_name: String,
    pub runtimes: BTreeMap<String, RuntimeDefinition>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDefinition {
    /// Must remain the registered runc-v2 type ("io.containerd.runc.v2").
    pub runtime_type: String,

    /// `runtime_path` must NEVER be set: containerd resolves the shim via PATH.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_path: Option<String>,

    pub snapshotter: Snapshotter,
    pub options: RuntimeOptions,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeOptions {
    #[serde(rename = "BinaryName")]
    pub binary_name: String,

    #[serde(rename = "SystemdCgroup")]
    pub systemd_cgroup: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskPluginConfig {
    pub platforms: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerdServicePaths {
    pub config_file: PathBuf,
    pub root_dir: PathBuf,
    pub state_dir: PathBuf,
    pub socket_file: PathBuf,
    pub registry_config_dir: PathBuf,
    pub cni_plugins_dir: PathBuf,
    pub crun_binary_file: PathBuf,
    pub shim_binary_file: PathBuf,
    pub cni_conf_dir: Option<PathBuf>,
    pub config_d_dir: Option<PathBuf>,
}

impl ContainerdServicePaths {
    /// Construct default paths rooted at a specified base directory (e.g. `/var/lib/diorama` or a custom root).
    #[must_use]
    pub fn from_base_dir(base_dir: &Path) -> Self {
        let containerd_dir = base_dir.join("containerd");
        Self {
            config_file: containerd_dir.join("config.toml"),
            root_dir: containerd_dir.join("root"),
            state_dir: containerd_dir.join("state"),
            socket_file: containerd_dir.join("containerd.sock"),
            registry_config_dir: containerd_dir.join("registry"),
            cni_plugins_dir: containerd_dir.join("cni/plugins"),
            crun_binary_file: containerd_dir.join("crun"),
            shim_binary_file: containerd_dir.join(DEFAULT_SHIM_BINARY_NAME),
            cni_conf_dir: None,
            config_d_dir: None,
        }
    }
}

/// Options to control configuration generation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContainerdConfigOptions {
    pub snapshotter: Option<Snapshotter>,
    pub systemd_cgroup: Option<bool>,
    pub sandbox_image: Option<String>,
    pub image_pull_timeout: Option<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    Io { path: PathBuf, source: io::Error },
    Serialize { source: toml::ser::Error },
    Deserialize { source: toml::de::Error },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "I/O error at '{}': {source}", path.display())
            },
            Self::Serialize { source } => {
                write!(f, "failed to serialize containerd config to TOML: {source}")
            },
            Self::Deserialize { source } => {
                write!(f, "failed to deserialize containerd config: {source}")
            },
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialize { source } => Some(source),
            Self::Deserialize { source } => Some(source),
        }
    }
}

/// Generate the structured `ContainerdConfigFile` based on given paths and options.
#[must_use]
pub fn generate_containerd_config(
    paths: &ContainerdServicePaths,
    options: &ContainerdConfigOptions,
) -> ContainerdConfigFile {
    let snapshotter = options
        .snapshotter
        .unwrap_or_else(|| detect_snapshotter(&paths.root_dir));

    let systemd_cgroup = options.systemd_cgroup.unwrap_or_else(use_systemd_cgroup);

    let sandbox_image = options
        .sandbox_image
        .as_deref()
        .unwrap_or(DEFAULT_SANDBOX_IMAGE);

    let pull_timeout = options
        .image_pull_timeout
        .as_deref()
        .unwrap_or(DEFAULT_IMAGE_PULL_TIMEOUT);

    let config_d_glob = paths.config_d_dir.as_ref().map_or_else(
        || format!("{DEFAULT_CONTAINERD_CONFIG_DIR}/*.toml"),
        |dir| format!("{}/*.toml", dir.display()),
    );

    let cni_conf_dir = paths.cni_conf_dir.as_ref().map_or_else(
        || DEFAULT_STANDARD_CNI_CONF_DIR.to_string(),
        |dir| dir.display().to_string(),
    );

    let mut runtimes = BTreeMap::new();
    runtimes.insert(
        DEFAULT_RUNTIME_NAME.to_string(),
        RuntimeDefinition {
            runtime_type: RUNTIME_RUNC_V2.to_string(),
            runtime_path: None, // Deliberately None!
            snapshotter,
            options: RuntimeOptions {
                binary_name: paths.crun_binary_file.display().to_string(),
                systemd_cgroup,
            },
        },
    );

    ContainerdConfigFile {
        version: CONTAINERD_CONFIG_VERSION,
        root: paths.root_dir.display().to_string(),
        state: paths.state_dir.display().to_string(),
        imports: vec![config_d_glob],
        grpc: GrpcConfig {
            address: paths.socket_file.display().to_string(),
        },
        plugins: PluginsConfig {
            cri_images: CriImagesPluginConfig {
                image_pull_progress_timeout: pull_timeout.to_string(),
                pinned_images: PinnedImagesConfig {
                    sandbox: sandbox_image.to_string(),
                },
                registry: RegistryPluginConfig {
                    config_path: paths.registry_config_dir.display().to_string(),
                },
            },
            cri_runtime: CriRuntimePluginConfig {
                cni: CniConfig {
                    bin_dirs: vec![paths.cni_plugins_dir.display().to_string()],
                    conf_dir: cni_conf_dir,
                },
                containerd: ContainerdRuntimeSettings {
                    default_runtime_name: DEFAULT_RUNTIME_NAME.to_string(),
                    runtimes,
                },
            },
            task: TaskPluginConfig {
                platforms: DEFAULT_PLATFORMS.iter().map(|&s| s.to_string()).collect(),
            },
        },
    }
}

/// Render the containerd configuration as a valid TOML string.
pub fn render_containerd_config(config: &ContainerdConfigFile) -> Result<String, ConfigError> {
    let raw = toml::to_string(config).map_err(|err| ConfigError::Serialize { source: err })?;
    let quoted = raw
        .replace(
            "[plugins.io.containerd.cri.v1.images",
            "[plugins.\"io.containerd.cri.v1.images\"",
        )
        .replace(
            "[plugins.io.containerd.cri.v1.runtime",
            "[plugins.\"io.containerd.cri.v1.runtime\"",
        )
        .replace(
            "[plugins.io.containerd.runtime.v2.task",
            "[plugins.\"io.containerd.runtime.v2.task\"",
        );
    Ok(quoted)
}

/// Write the containerd configuration to the destination specified in `paths.config_file`.
///
/// Ensures parent directories exist. Preserves surrounding directories such as `registry/`.
pub fn write_containerd_config_file(
    paths: &ContainerdServicePaths,
    options: &ContainerdConfigOptions,
) -> Result<PathBuf, ConfigError> {
    let config = generate_containerd_config(paths, options);
    let toml_str = render_containerd_config(&config)?;

    if let Some(parent) = paths.config_file.parent() {
        fs::create_dir_all(parent).map_err(|err| ConfigError::Io {
            path: parent.to_path_buf(),
            source: err,
        })?;
    }

    fs::write(&paths.config_file, toml_str).map_err(|err| ConfigError::Io {
        path: paths.config_file.clone(),
        source: err,
    })?;

    Ok(paths.config_file.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_config_structure() {
        let paths = ContainerdServicePaths::from_base_dir(Path::new("/var/lib/diorama"));
        let options = ContainerdConfigOptions {
            snapshotter: Some(Snapshotter::Overlayfs),
            systemd_cgroup: Some(false),
            sandbox_image: None,
            image_pull_timeout: None,
        };

        let config = generate_containerd_config(&paths, &options);
        assert_eq!(config.version, 3);
        assert_eq!(config.root, "/var/lib/diorama/containerd/root");
        assert_eq!(config.state, "/var/lib/diorama/containerd/state");
        assert_eq!(
            config.imports,
            vec!["/etc/containerd/config.d/*.toml".to_string()]
        );
        assert_eq!(
            config.grpc.address,
            "/var/lib/diorama/containerd/containerd.sock"
        );

        let crun = config
            .plugins
            .cri_runtime
            .containerd
            .runtimes
            .get("crun")
            .expect("crun runtime defined");
        assert_eq!(crun.runtime_type, "io.containerd.runc.v2");
        assert!(crun.runtime_path.is_none());
        assert_eq!(crun.snapshotter, Snapshotter::Overlayfs);
        assert_eq!(crun.options.binary_name, "/var/lib/diorama/containerd/crun");
        assert!(!crun.options.systemd_cgroup);

        let toml_out = render_containerd_config(&config).unwrap();
        assert!(toml_out.contains("version = 3"));
        assert!(toml_out.contains("runtime_type = \"io.containerd.runc.v2\""));
        assert!(!toml_out.contains("runtime_path"));
        assert!(toml_out.contains("BinaryName = \"/var/lib/diorama/containerd/crun\""));
        assert!(toml_out.contains("SystemdCgroup = false"));
        assert!(toml_out.contains("config_path = \"/var/lib/diorama/containerd/registry\""));
    }
}
