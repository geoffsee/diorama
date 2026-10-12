//! Execution runner for the platform coverage and sustained soak qualification suite.

use diorama_assets::{
    Architecture, AssetId, Libc, Matrix, NodeArchiveArtifact, OciImageIndexArtifact,
    OciPlatformDescriptor, ReleasePackageManifest, ReleasePackager, Variant, catalog,
};

use super::candidate::CandidateVerificationSummary;
use super::matrix::EnvironmentMapping;
use super::regressions::RegressionSuite;
use super::report::{PlatformSoakError, PlatformSoakReport};
use super::restart::RestartSummary;
use super::soak::SustainedSoakSummary;

/// Qualification runner executing platform coverage, candidate verification, and soak tests.
#[derive(Debug, Default)]
pub struct PlatformSoakRunner;

impl PlatformSoakRunner {
    /// Create a new platform soak qualification runner.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Construct synthetic manifest metadata for fixtures, without observing candidate bytes.
    #[must_use]
    pub fn synthetic_candidate_manifest(version: &str) -> ReleasePackageManifest {
        let mut archives = Vec::with_capacity(16);
        for variant in Matrix::all_node_variants() {
            let filename = variant.archive_filename("diorama-kube", version);
            let arch_str = match variant.architecture {
                Architecture::Amd64 => "amd64",
                Architecture::Arm64 => "arm64",
                Architecture::ArmV7 => "arm",
                Architecture::Riscv64 => "riscv64",
            };
            let libc_str = match variant.libc {
                Libc::Glibc => "glibc",
                Libc::Musl => "musl",
            };
            let variant_str = match variant.variant {
                Variant::Online => "online",
                Variant::Offline => "offline",
            };

            let bundled_assets: Vec<String> = catalog()
                .iter()
                .filter(|entry| match entry.id {
                    AssetId::ImagePortainerAgent => {
                        variant.variant == Variant::Offline
                            && variant.architecture != Architecture::Riscv64
                    },
                    AssetId::ImageD2k => {
                        variant.variant == Variant::Offline
                            && matches!(
                                variant.architecture,
                                Architecture::Amd64 | Architecture::Arm64
                            )
                    },
                    AssetId::ImageLocalPath
                    | AssetId::ImageLocalPathHelper
                    | AssetId::ImageKubesolo => variant.variant == Variant::Offline,
                    _ => true,
                })
                .map(|entry| {
                    match entry.id {
                        AssetId::KubeApiserver => "kube-apiserver",
                        AssetId::KubeControllerManager => "kube-controller-manager",
                        AssetId::Kubelet => "kubelet",
                        AssetId::KubeProxy => "kube-proxy",
                        AssetId::Kine => "kine",
                        AssetId::Containerd => "containerd",
                        AssetId::ContainerdShim => "containerd-shim-runc-v2",
                        AssetId::Crun => "crun",
                        AssetId::CniBridge => "cni-bridge",
                        AssetId::CniHostLocal => "cni-host-local",
                        AssetId::CniPortmap => "cni-portmap",
                        AssetId::CniLoopback => "cni-loopback",
                        AssetId::FuseOverlayfsSnapshotter => "fuse-overlayfs-snapshotter",
                        AssetId::ImageCoredns => "image-coredns",
                        AssetId::ImagePause => "image-pause",
                        AssetId::ImageLocalPath => "image-local-path",
                        AssetId::ImageLocalPathHelper => "image-local-path-helper",
                        AssetId::ImagePortainerAgent => "image-portainer-agent",
                        AssetId::ImageD2k => "image-d2k",
                        AssetId::ImageKubesolo => "image-kubesolo",
                    }
                    .to_string()
                })
                .collect();

            let sha256 = ReleasePackager::sha256_hex(filename.as_bytes());
            let size_bytes = filename.len() as u64;

            archives.push(NodeArchiveArtifact {
                cell: variant.cell,
                filename,
                architecture: arch_str.to_string(),
                libc: libc_str.to_string(),
                variant: variant_str.to_string(),
                size_bytes,
                sha256,
                bundled_assets,
            });
        }

        let management = vec![
            diorama_assets::ManagementArtifact {
                os: "linux".into(),
                architecture: "amd64".into(),
                filename: "dioramactl-linux-amd64".into(),
                size_bytes: b"dioramactl-linux-amd64".len() as u64,
                sha256: ReleasePackager::sha256_hex(b"dioramactl-linux-amd64"),
            },
            diorama_assets::ManagementArtifact {
                os: "linux".into(),
                architecture: "arm64".into(),
                filename: "dioramactl-linux-arm64".into(),
                size_bytes: b"dioramactl-linux-arm64".len() as u64,
                sha256: ReleasePackager::sha256_hex(b"dioramactl-linux-arm64"),
            },
            diorama_assets::ManagementArtifact {
                os: "darwin".into(),
                architecture: "amd64".into(),
                filename: "dioramactl-darwin-amd64".into(),
                size_bytes: b"dioramactl-darwin-amd64".len() as u64,
                sha256: ReleasePackager::sha256_hex(b"dioramactl-darwin-amd64"),
            },
            diorama_assets::ManagementArtifact {
                os: "darwin".into(),
                architecture: "arm64".into(),
                filename: "dioramactl-darwin-arm64".into(),
                size_bytes: b"dioramactl-darwin-arm64".len() as u64,
                sha256: ReleasePackager::sha256_hex(b"dioramactl-darwin-arm64"),
            },
        ];

        let image_ids = [
            (
                "image-diorama-kube",
                "ghcr.io/portainer/diorama-kube:v0.1.0",
            ),
            ("image-coredns", "docker.io/coredns/coredns:1.14.4"),
            ("image-pause", "docker.io/portainer/pause:latest"),
            (
                "image-local-path",
                "docker.io/rancher/local-path-provisioner:v0.0.36",
            ),
            (
                "image-local-path-helper",
                "docker.io/library/busybox:latest",
            ),
            ("image-portainer-agent", "docker.io/portainer/agent:lts"),
            ("image-d2k", "docker.io/portainer/d2k:1.2.3"),
        ];

        let mut oci_images = Vec::with_capacity(7);
        for (id, reference) in image_ids {
            let unsupported: Vec<String> = match id {
                "image-portainer-agent" => vec!["linux/riscv64".into()],
                "image-d2k" => vec!["linux/arm/v7".into(), "linux/riscv64".into()],
                _ => vec![],
            };

            let platforms = Matrix::all_oci_platforms()
                .iter()
                .filter(|platform| !unsupported.iter().any(|p| p == **platform))
                .map(|platform| {
                    let arch = match *platform {
                        "linux/arm64" => "arm64",
                        "linux/arm/v7" => "arm",
                        "linux/riscv64" => "riscv64",
                        _ => "amd64",
                    };
                    OciPlatformDescriptor {
                        platform: (*platform).to_string(),
                        architecture: arch.to_string(),
                        os: "linux".into(),
                        media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                        digest: format!(
                            "sha256:{}",
                            ReleasePackager::sha256_hex(format!("{id}-{platform}").as_bytes())
                        ),
                        size_bytes: format!("{id}-{platform}").len() as u64,
                    }
                })
                .collect();

            let index_hash = ReleasePackager::sha256_hex(format!("index-{id}").as_bytes());

            oci_images.push(OciImageIndexArtifact {
                asset_id: id.to_string(),
                image_reference: reference.to_string(),
                index_media_type: "application/vnd.oci.image.index.v1+json".into(),
                index_digest: format!("sha256:{index_hash}"),
                index_size_bytes: format!("index-{id}").len() as u64,
                platforms,
                unsupported_platforms: unsupported,
            });
        }

        ReleasePackageManifest {
            schema_version: 1,
            product_name: "diorama-kube".into(),
            version: version.to_string(),
            node_archives: archives,
            management_binaries: management,
            oci_images,
            excluded_targets: vec![
                "windows".into(),
                "windows-amd64".into(),
                "windows-arm64".into(),
            ],
        }
    }

    /// Retained-node qualification is unavailable until independent live receipts exist.
    pub fn run_qualification(
        &self,
        _: &str,
        _: Option<&ReleasePackageManifest>,
    ) -> Result<PlatformSoakReport, PlatformSoakError> {
        Err(PlatformSoakError::RegressionFailed(
            "C14 qualification runner is not implemented; synthetic fixtures cannot qualify".into(),
        ))
    }

    /// Generate deterministic synthetic records solely to exercise report arithmetic.
    pub fn run_fixture(&self, version: &str) -> Result<PlatformSoakReport, PlatformSoakError> {
        let report = PlatformSoakReport {
            schema_version: 2,
            product: "diorama-kube".into(),
            version: version.into(),
            evidence_kind: "SyntheticFixture".into(),
            timestamp: format!(
                "unix:{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| PlatformSoakError::Serialization(e.to_string()))?
                    .as_secs()
            ),
            receipt_id: None,
            receipt_integrity_hash: None,
            environments: EnvironmentMapping::canonical_matrix(),
            candidate_verification: CandidateVerificationSummary::unobserved(),
            soak_results: SustainedSoakSummary::canonical_soak_records(),
            restart_results: RestartSummary::canonical_cases(),
            historical_regressions: RegressionSuite::historical_regressions(),
            epic_regressions: RegressionSuite::epic_regressions(),
            overall_qualified: false,
        };
        report.validate_fixture(Some(version))?;
        Ok(report)
    }
}
