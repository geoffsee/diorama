//! Managed runtime image importing and registry fallback.

use diorama_assets::AssetId;
use diorama_config::Config;
use diorama_cri::runtime::v1::image_service_client::ImageServiceClient;
use diorama_cri::runtime::v1::{ImageSpec, PullImageRequest};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use tonic::transport::Channel;

pub const DEFAULT_COREDNS_IMAGE: &str = "docker.io/coredns/coredns:1.14.4";
pub const DEFAULT_PAUSE_IMAGE: &str = "docker.io/portainer/pause:latest";
pub const DEFAULT_LOCAL_PATH_IMAGE: &str =
    "ghcr.io/geoffsee/diorama-local-path-provisioner:v0.0.36-1";
pub const DEFAULT_BUSYBOX_IMAGE: &str = "docker.io/library/busybox:latest";
pub const DEFAULT_PORTAINER_AGENT_IMAGE: &str = "docker.io/portainer/agent:lts";
pub const DEFAULT_D2K_IMAGE: &str = "docker.io/portainer/d2k:1.2.3";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageTarget {
    pub id: AssetId,
    pub reference: String,
    pub filename: String,
    pub required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageImportConfig {
    pub images_dir: PathBuf,
    pub local_storage_enabled: bool,
    pub portainer_edge_enabled: bool,
    pub portainer_edge_image: Option<String>,
    pub d2k_enabled: bool,
}

impl ImageImportConfig {
    pub fn new(images_dir: impl AsRef<Path>) -> Self {
        Self {
            images_dir: images_dir.as_ref().to_path_buf(),
            local_storage_enabled: true,
            portainer_edge_enabled: false,
            portainer_edge_image: None,
            d2k_enabled: false,
        }
    }

    pub fn from_config(config: &Config, images_dir: impl AsRef<Path>) -> Self {
        Self {
            images_dir: images_dir.as_ref().to_path_buf(),
            local_storage_enabled: config.storage.local_path.enabled,
            portainer_edge_enabled: !config.portainer.edge_id.is_empty(),
            portainer_edge_image: if config.portainer.image.is_empty() {
                None
            } else {
                Some(config.portainer.image.clone())
            },
            d2k_enabled: config.d2k.enabled,
        }
    }

    /// Returns all image targets enabled according to configuration.
    pub fn enabled_targets(&self) -> Vec<ImageTarget> {
        let mut targets = vec![
            ImageTarget {
                id: AssetId::ImageCoredns,
                reference: DEFAULT_COREDNS_IMAGE.into(),
                filename: "coredns.tar.gz".into(),
                required: true,
            },
            ImageTarget {
                id: AssetId::ImagePause,
                reference: DEFAULT_PAUSE_IMAGE.into(),
                filename: "pause.tar.gz".into(),
                required: true,
            },
        ];

        if self.local_storage_enabled {
            targets.push(ImageTarget {
                id: AssetId::ImageLocalPath,
                reference: DEFAULT_LOCAL_PATH_IMAGE.into(),
                filename: "local-path-provisioner.tar.gz".into(),
                required: true,
            });
            targets.push(ImageTarget {
                id: AssetId::ImageLocalPathHelper,
                reference: DEFAULT_BUSYBOX_IMAGE.into(),
                filename: "busybox.tar.gz".into(),
                required: false,
            });
        }

        if self.portainer_edge_enabled {
            let edge_image = self
                .portainer_edge_image
                .as_deref()
                .unwrap_or(DEFAULT_PORTAINER_AGENT_IMAGE);
            let is_custom = edge_image != DEFAULT_PORTAINER_AGENT_IMAGE;
            targets.push(ImageTarget {
                id: AssetId::ImagePortainerAgent,
                reference: edge_image.into(),
                filename: if is_custom {
                    String::new()
                } else {
                    "portainer-agent.tar.gz".into()
                },
                // A custom edge agent image is not embedded; pull failure is non-fatal warm cache
                required: !is_custom,
            });
        }

        if self.d2k_enabled {
            targets.push(ImageTarget {
                id: AssetId::ImageD2k,
                reference: DEFAULT_D2K_IMAGE.into(),
                filename: "d2k.tar.gz".into(),
                required: true,
            });
        }

        targets
    }

    /// Returns list of disabled image asset IDs that must NOT be imported.
    pub fn disabled_targets(&self) -> Vec<AssetId> {
        let mut disabled = Vec::new();
        if !self.local_storage_enabled {
            disabled.push(AssetId::ImageLocalPath);
            disabled.push(AssetId::ImageLocalPathHelper);
        }
        if !self.portainer_edge_enabled {
            disabled.push(AssetId::ImagePortainerAgent);
        }
        if !self.d2k_enabled {
            disabled.push(AssetId::ImageD2k);
        }
        disabled
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImageImportSummary {
    pub imported: Vec<String>,
    pub pulled: Vec<String>,
    pub skipped: Vec<AssetId>,
}

#[derive(Debug)]
pub enum ImageError {
    PullFailed {
        image: String,
        status: tonic::Status,
    },
    ArchiveReadFailed {
        path: PathBuf,
        source: std::io::Error,
    },
    ImportFailed {
        image: String,
        details: String,
    },
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PullFailed { image, status } => {
                write!(f, "failed to pull image {image}: {status}")
            },
            Self::ArchiveReadFailed { path, source } => {
                write!(
                    f,
                    "failed to read image archive {}: {source}",
                    path.display()
                )
            },
            Self::ImportFailed { image, details } => {
                write!(f, "failed to import image {image}: {details}")
            },
        }
    }
}

impl std::error::Error for ImageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PullFailed { status, .. } => Some(status),
            Self::ArchiveReadFailed { source, .. } => Some(source),
            Self::ImportFailed { .. } => None,
        }
    }
}

/// Imports embedded image archives or falls back to pulling images from registry via CRI.
pub async fn import_or_pull_images(
    channel: Channel,
    config: &ImageImportConfig,
) -> Result<ImageImportSummary, ImageError> {
    let mut client = ImageServiceClient::new(channel);
    let mut summary = ImageImportSummary {
        imported: Vec::new(),
        pulled: Vec::new(),
        skipped: config.disabled_targets(),
    };

    for target in config.enabled_targets() {
        let is_embedded = if target.filename.is_empty() {
            false
        } else {
            let archive_path = config.images_dir.join(&target.filename);
            archive_path.is_file() && std::fs::metadata(&archive_path).is_ok_and(|m| m.len() > 0)
        };

        if is_embedded {
            // Local embedded archive exists; mark as imported
            summary.imported.push(target.reference);
        } else {
            if config.images_dir.join("offline").exists() {
                return Err(ImageError::ImportFailed {
                    image: target.reference,
                    details: "image unavailable offline; disable the optional integration, load its add-on archive with dioramactl addon load, and apply its installation Job".into(),
                });
            }
            // Fall back to CRI pull_image
            let req = tonic::Request::new(PullImageRequest {
                image: Some(ImageSpec {
                    image: target.reference.clone(),
                    annotations: BTreeMap::new(),
                    runtime_handler: String::new(),
                    user_specified_image: target.reference.clone(),
                }),
                auth: None,
                sandbox_config: None,
            });

            match client.pull_image(req).await {
                Ok(_) => {
                    summary.pulled.push(target.reference);
                },
                Err(status) => {
                    if target.required {
                        return Err(ImageError::PullFailed {
                            image: target.reference,
                            status,
                        });
                    }
                    // Non-required target pull failure is non-fatal
                },
            }
        }
    }

    Ok(summary)
}

/// Load archives into Kubernetes' namespace before CRI readiness is reported.
pub async fn import_archives(
    binary_dir: &Path,
    socket: &Path,
    config: &ImageImportConfig,
) -> Result<(), ImageError> {
    let ctr = binary_dir.join("ctr");
    let socket = socket.to_owned();
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        let mut archives: Vec<_> = config
            .enabled_targets()
            .into_iter()
            .filter_map(|target| {
                let archive = config.images_dir.join(&target.filename);
                (!target.filename.is_empty() && archive.is_file())
                    .then_some((target.reference, archive))
            })
            .collect();
        let addons = config.images_dir.join("addons");
        if addons.exists() {
            for entry in std::fs::read_dir(addons).map_err(retained_image_error)? {
                let entry = entry.map_err(retained_image_error)?;
                if entry.file_type().map_err(retained_image_error)?.is_file()
                    && entry.file_name().to_string_lossy().ends_with(".tar.gz")
                {
                    archives.push((
                        entry.file_name().to_string_lossy().into_owned(),
                        entry.path(),
                    ));
                }
            }
        }
        archives.sort();
        for (reference, archive) in archives {
            let result = std::process::Command::new(&ctr)
                .arg("--address")
                .arg(&socket)
                .args([
                    "--namespace",
                    "k8s.io",
                    "images",
                    "import",
                    "--all-platforms",
                ])
                .arg(&archive)
                .output()
                .map_err(|e| ImageError::ImportFailed {
                    image: reference.clone(),
                    details: e.to_string(),
                })?;
            if !result.status.success() {
                return Err(ImageError::ImportFailed {
                    image: reference,
                    details: String::from_utf8_lossy(&result.stderr).into_owned(),
                });
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| ImageError::ImportFailed {
        image: "offline archives".into(),
        details: e.to_string(),
    })?
}

#[allow(clippy::needless_pass_by_value)] // Adapter passed directly to Result::map_err.
fn retained_image_error(error: std::io::Error) -> ImageError {
    ImageError::ImportFailed {
        image: "retained add-on".into(),
        details: error.to_string(),
    }
}

#[cfg(all(test, unix))]
mod retained_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn retained_addons_import_even_with_legacy_integrations_disabled() {
        let root = tempfile::tempdir().unwrap();
        let images = root.path().join("images");
        std::fs::create_dir_all(images.join("addons")).unwrap();
        let archive = images.join("addons/addon-d2k-v1.tar.gz");
        std::fs::write(&archive, b"verified by loader").unwrap();
        std::fs::write(images.join("addons/.load.incomplete"), b"not published").unwrap();
        let ctr = root.path().join("ctr");
        std::fs::write(
            &ctr,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$(dirname \"$0\")/calls\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&ctr, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config = ImageImportConfig::new(images);
        import_archives(root.path(), Path::new("/node/socket"), &config)
            .await
            .unwrap();
        let calls = std::fs::read_to_string(root.path().join("calls")).unwrap();
        assert!(calls.contains("--namespace\nk8s.io\nimages\nimport\n"));
        assert!(calls.contains(archive.to_str().unwrap()));
        assert!(!calls.contains("incomplete"));
    }
}
