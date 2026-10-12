//! Supervised containerd runtime service adapter.

use crate::cgroup::use_systemd_cgroup;
use crate::cleanup::{CleanupError, CleanupReport, clean_stale_runtime_state};
use crate::config::{
    ContainerdConfigOptions, ContainerdServicePaths, write_containerd_config_file,
};
use crate::health::{
    DEFAULT_READINESS_TIMEOUT, DEFAULT_RETRY_INTERVAL, RuntimeVersionInfo,
    probe_containerd_readiness,
};
use crate::image::{ImageImportConfig, ImageImportSummary, import_or_pull_images};
use crate::namespace::{DEFAULT_K8S_NAMESPACE, ensure_k8s_namespace};
use crate::shim::build_containerd_path;
use crate::snapshotter::detect_snapshotter;
use crate::symlink::ensure_system_socket_link;
use diorama_supervisor::process::{
    OutputLimit, OwnedProcessAdapter, ProcessCleanup, ProcessCommand,
};
use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy,
};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const COMPONENT_CONTAINERD: &str = "containerd";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerdPaths {
    pub root_dir: PathBuf,
    pub state_dir: PathBuf,
    pub config_path: PathBuf,
    pub socket_path: PathBuf,
    pub binary_path: PathBuf,
    pub shim_binary_path: PathBuf,
    pub crun_binary_path: PathBuf,
    pub cni_bin_dir: PathBuf,
    pub cni_conf_dir: PathBuf,
    pub registry_hosts_dir: PathBuf,
    pub images_dir: PathBuf,
}

impl ContainerdPaths {
    pub fn from_base(base: impl AsRef<Path>) -> Self {
        let base = base.as_ref();
        let bin_dir = base.join("bin");
        let containerd_dir = base.join("containerd");
        Self {
            root_dir: containerd_dir.join("root"),
            state_dir: containerd_dir.join("state"),
            config_path: containerd_dir.join("config.toml"),
            socket_path: containerd_dir.join("state").join("containerd.sock"),
            binary_path: bin_dir.join("containerd"),
            shim_binary_path: bin_dir.join("containerd-shim-runc-v2"),
            crun_binary_path: bin_dir.join("crun"),
            cni_bin_dir: base.join("cni").join("bin"),
            cni_conf_dir: base.join("cni").join("net.d"),
            registry_hosts_dir: containerd_dir.join("registry"),
            images_dir: base.join("images"),
        }
    }

    pub fn to_service_paths(&self) -> ContainerdServicePaths {
        ContainerdServicePaths {
            config_file: self.config_path.clone(),
            root_dir: self.root_dir.clone(),
            state_dir: self.state_dir.clone(),
            socket_file: self.socket_path.clone(),
            registry_config_dir: self.registry_hosts_dir.clone(),
            cni_plugins_dir: self.cni_bin_dir.clone(),
            crun_binary_file: self.crun_binary_path.clone(),
            shim_binary_file: self.shim_binary_path.clone(),
            cni_conf_dir: Some(self.cni_conf_dir.clone()),
            config_d_dir: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ContainerdServiceOptions {
    pub paths: ContainerdPaths,
    pub image_config: ImageImportConfig,
    pub readiness_timeout: Duration,
    pub retry_interval: Duration,
    pub ensure_socket_symlink: bool,
    pub clean_stale_state_on_startup: bool,
    pub output_limit: Option<OutputLimit>,
}

impl ContainerdServiceOptions {
    pub fn new(paths: ContainerdPaths, image_config: ImageImportConfig) -> Self {
        Self {
            paths,
            image_config,
            readiness_timeout: DEFAULT_READINESS_TIMEOUT,
            retry_interval: DEFAULT_RETRY_INTERVAL,
            ensure_socket_symlink: true,
            clean_stale_state_on_startup: true,
            output_limit: None,
        }
    }
}

pub struct ContainerdService {
    options: ContainerdServiceOptions,
}

impl fmt::Debug for ContainerdService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContainerdService")
            .field("socket_path", &self.options.paths.socket_path)
            .field("config_path", &self.options.paths.config_path)
            .finish()
    }
}

impl ContainerdService {
    pub fn new(options: ContainerdServiceOptions) -> Self {
        Self { options }
    }

    /// Cleans stale containerd runtime state from prior runs.
    pub fn cleanup(&self, system_socket: Option<&Path>) -> Result<CleanupReport, CleanupError> {
        clean_stale_runtime_state(&self.options.paths, system_socket)
    }

    /// Prepares local filesystem: cleans stale disposable state if enabled,
    /// ensures directories exist, and renders config.toml.
    pub fn prepare(&self) -> Result<(), std::io::Error> {
        if self.options.clean_stale_state_on_startup {
            let _ = self
                .cleanup(None)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }

        let paths = &self.options.paths;
        std::fs::create_dir_all(&paths.root_dir)?;
        std::fs::create_dir_all(&paths.state_dir)?;
        std::fs::create_dir_all(&paths.registry_hosts_dir)?;

        let snapshotter = detect_snapshotter(&paths.root_dir);
        let systemd_cgroup = use_systemd_cgroup();

        let service_paths = paths.to_service_paths();
        let config_options = ContainerdConfigOptions {
            snapshotter: Some(snapshotter),
            systemd_cgroup: Some(systemd_cgroup),
            sandbox_image: None,
            image_pull_timeout: None,
        };

        write_containerd_config_file(&service_paths, &config_options)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(())
    }

    /// Build component specification for supervisor registration.
    pub fn component_spec(startup_timeout: Duration) -> ComponentSpec {
        ComponentSpec {
            id: COMPONENT_CONTAINERD.into(),
            prerequisites: Vec::new(),
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout,
        }
    }

    /// Converts this containerd service into an `OwnedProcessAdapter` managed by the supervisor.
    pub fn into_process_adapter(
        self,
    ) -> Result<(OwnedProcessAdapter, ProcessCleanup), std::io::Error> {
        self.prepare()?;
        let bin_dir = self
            .options
            .paths
            .binary_path
            .parent()
            .unwrap_or_else(|| Path::new("/usr/local/bin"));
        let env_path = build_containerd_path(bin_dir, std::env::var_os("PATH").as_deref());

        let mut command = ProcessCommand::new(&self.options.paths.binary_path);
        command = command
            .arg("--config")
            .arg(&self.options.paths.config_path)
            .env("PATH", env_path);

        let options = self.options.clone();
        let readiness = async move {
            let (channel, _version_info) = probe_containerd_readiness(
                &options.paths.socket_path,
                options.readiness_timeout,
                options.retry_interval,
            )
            .await
            .map_err(|_| AdapterError {
                code: "containerd_readiness_failed",
            })?;

            if options.ensure_socket_symlink {
                let _ = ensure_system_socket_link(&options.paths.socket_path, None);
            }

            ensure_k8s_namespace(channel.clone(), DEFAULT_K8S_NAMESPACE)
                .await
                .map_err(|_| AdapterError {
                    code: "containerd_namespace_failed",
                })?;

            import_or_pull_images(channel, &options.image_config)
                .await
                .map_err(|_| AdapterError {
                    code: "containerd_image_import_failed",
                })?;

            Ok(())
        };

        if let Some(limit) = self.options.output_limit {
            let (adapter, cleanup, _output) =
                OwnedProcessAdapter::new_with_bounded_output(command, readiness, limit);
            Ok((adapter, cleanup))
        } else {
            let (adapter, cleanup) = OwnedProcessAdapter::new(command, readiness);
            Ok((adapter, cleanup))
        }
    }

    /// Executes the containerd post-startup sequence: probe CRI readiness,
    /// link system socket, ensure k8s.io namespace, and import enabled images.
    pub async fn post_startup(
        &self,
    ) -> Result<(RuntimeVersionInfo, ImageImportSummary), AdapterError> {
        let (channel, version_info) = probe_containerd_readiness(
            &self.options.paths.socket_path,
            self.options.readiness_timeout,
            self.options.retry_interval,
        )
        .await
        .map_err(|_| AdapterError {
            code: "containerd_readiness_failed",
        })?;

        if self.options.ensure_socket_symlink {
            let _ = ensure_system_socket_link(&self.options.paths.socket_path, None);
        }

        ensure_k8s_namespace(channel.clone(), DEFAULT_K8S_NAMESPACE)
            .await
            .map_err(|_| AdapterError {
                code: "containerd_namespace_failed",
            })?;

        let summary = import_or_pull_images(channel, &self.options.image_config)
            .await
            .map_err(|_| AdapterError {
                code: "containerd_image_import_failed",
            })?;

        Ok((version_info, summary))
    }
}

impl Adapter for ContainerdService {
    fn run(self: Box<Self>, context: AdapterContext) -> AdapterFuture {
        match self.into_process_adapter() {
            Ok((adapter, _cleanup)) => Box::new(adapter).run(context),
            Err(_) => Box::pin(async move {
                Err(AdapterError {
                    code: "containerd_prepare_failed",
                })
            }),
        }
    }
}
