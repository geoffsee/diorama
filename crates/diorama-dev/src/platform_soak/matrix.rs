//! Platform, runtime, variant, container, and host matrix mappings.
//!
//! Maps every promised environment from the acceptance matrix to results or explicit
//! unsupported decisions with technical rationale and no silent omissions.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Dimension category within the accepted qualification matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionCategory {
    NodeVariantCell,
    ManagementTarget,
    OciContainerImage,
    RuntimeProvider,
    RuntimeBuildMode,
    InitSystem,
    ContainerRunMode,
    HostCapability,
    DeliveryMode,
    RuntimeOwnership,
    AddonComponent,
}

impl DimensionCategory {
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::NodeVariantCell => "Node Distribution Archive Cells (16 Cells)",
            Self::ManagementTarget => "Management CLI Targets (4 Targets)",
            Self::OciContainerImage => "OCI Container Images Multi-Arch Manifests",
            Self::RuntimeProvider => "Container Runtime Providers",
            Self::RuntimeBuildMode => "Runtime Build Modes",
            Self::InitSystem => "Init & Service Lifecycle Systems",
            Self::ContainerRunMode => "Named Container Run Modes",
            Self::HostCapability => "Host Capabilities & OS Variants",
            Self::DeliveryMode => "Delivery Modes (Online vs Offline)",
            Self::RuntimeOwnership => "External Runtime State Ownership",
            Self::AddonComponent => "Optional Addon Components",
        }
    }
}

/// Official support status for an environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SupportStatus {
    Supported,
    Unsupported { rationale: String },
}

/// Execution or qualification result for an environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum EnvironmentResult {
    Verified,
    Simulated { caveat: String },
    Unsupported { rationale: String },
}

/// Record of an environment within the platform matrix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentRecord {
    pub id: String,
    pub name: String,
    pub dimension: DimensionCategory,
    pub support_status: SupportStatus,
    pub result: EnvironmentResult,
    pub candidate_digest: Option<String>,
    pub details: String,
}

/// Canonical mapping generator and completeness validator.
#[derive(Debug, Default)]
pub struct EnvironmentMapping;

fn unsupported_image_rationale(
    id_prefix: &str,
    arch_key: &str,
    name: &str,
    platform: &str,
) -> String {
    match (id_prefix, arch_key) {
        ("image-portainer-agent", "riscv64") => {
            "Portainer does not publish upstream agent binaries or OCI images for linux/riscv64.".into()
        },
        ("image-d2k", "armv7") => {
            "D2K Docker API bridge upstream binaries are only built for 64-bit architectures; linux/arm/v7 is disabled.".into()
        },
        ("image-d2k", "riscv64") => {
            "D2K Docker API bridge upstream binaries are only built for 64-bit amd64/arm64; linux/riscv64 is disabled.".into()
        },
        _ => format!("Image {name} is unsupported on {platform}."),
    }
}

impl EnvironmentMapping {
    /// Generate all exhaustive environments promised in the acceptance matrix.
    #[must_use]
    pub fn canonical_matrix() -> Vec<EnvironmentRecord> {
        let mut list = Vec::with_capacity(70);

        // 1. Node Variant Cells (16 cells)
        list.extend(Self::node_variant_cells());

        // 2. Management Targets (4 targets + Windows exclusion)
        list.extend(Self::management_targets());

        // 3. OCI Container Images Multi-Arch Matrix
        list.extend(Self::oci_container_images());

        // 4. Runtime Providers
        list.extend(Self::runtime_providers());

        // 5. Runtime Build Modes
        list.extend(Self::runtime_build_modes());

        // 6. Init Systems
        list.extend(Self::init_systems());

        // 7. Container Run Modes
        list.extend(Self::container_run_modes());

        // 8. Host Capabilities
        list.extend(Self::host_capabilities());

        // 9. Delivery Modes
        list.extend(Self::delivery_modes());

        // 10. Runtime Ownership
        list.extend(Self::runtime_ownership());

        // 11. Addon Components
        list.extend(Self::addon_components());

        for record in &mut list {
            record.candidate_digest = None;
            record.details = format!("Synthetic plan (not executed): {}", record.details);
            if matches!(record.support_status, SupportStatus::Supported) {
                record.result = EnvironmentResult::Simulated {
                    caveat: "Synthetic matrix plan; execution not qualified".into(),
                };
            } else if let SupportStatus::Unsupported { rationale } = &record.support_status {
                record.result = EnvironmentResult::Unsupported {
                    rationale: rationale.clone(),
                };
            }
        }
        list
    }

    fn node_variant_cells() -> Vec<EnvironmentRecord> {
        let cells = [
            (1, "amd64", "glibc", "online", "linux/amd64"),
            (2, "amd64", "glibc", "offline", "linux/amd64"),
            (3, "amd64", "musl", "online", "linux/amd64"),
            (4, "amd64", "musl", "offline", "linux/amd64"),
            (5, "arm64", "glibc", "online", "linux/arm64"),
            (6, "arm64", "glibc", "offline", "linux/arm64"),
            (7, "arm64", "musl", "online", "linux/arm64"),
            (8, "arm64", "musl", "offline", "linux/arm64"),
            (9, "arm", "glibc", "online", "linux/arm/v7"),
            (10, "arm", "glibc", "offline", "linux/arm/v7"),
            (11, "arm", "musl", "online", "linux/arm/v7"),
            (12, "arm", "musl", "offline", "linux/arm/v7"),
            (13, "riscv64", "glibc", "online", "linux/riscv64"),
            (14, "riscv64", "glibc", "offline", "linux/riscv64"),
            (15, "riscv64", "musl", "online", "linux/riscv64"),
            (16, "riscv64", "musl", "offline", "linux/riscv64"),
        ];

        cells
            .into_iter()
            .map(|(cell, arch, libc, delivery, oci_platform)| {
                let id = format!("node-cell-{cell:02}");
                let name = format!("Cell {cell:02} ({arch}-{libc}-{delivery})");
                EnvironmentRecord {
                    id,
                    name,
                    dimension: DimensionCategory::NodeVariantCell,
                    support_status: SupportStatus::Supported,
                    result: EnvironmentResult::Verified,
                    candidate_digest: Some(format!("sha256:cell{cell:02}")),
                    details: format!(
                        "Architecture {arch}, libc {libc}, delivery {delivery}, OCI platform {oci_platform}"
                    ),
                }
            })
            .collect()
    }

    fn management_targets() -> Vec<EnvironmentRecord> {
        vec![
            EnvironmentRecord {
                id: "mgmt-linux-amd64".into(),
                name: "dioramactl Linux amd64".into(),
                dimension: DimensionCategory::ManagementTarget,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: Some("sha256:mgmt-linux-amd64".into()),
                details: "64-bit x86_64 Linux management CLI".into(),
            },
            EnvironmentRecord {
                id: "mgmt-linux-arm64".into(),
                name: "dioramactl Linux arm64".into(),
                dimension: DimensionCategory::ManagementTarget,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: Some("sha256:mgmt-linux-arm64".into()),
                details: "64-bit AArch64 Linux management CLI".into(),
            },
            EnvironmentRecord {
                id: "mgmt-darwin-amd64".into(),
                name: "dioramactl macOS amd64".into(),
                dimension: DimensionCategory::ManagementTarget,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: Some("sha256:mgmt-darwin-amd64".into()),
                details: "64-bit Intel macOS management CLI".into(),
            },
            EnvironmentRecord {
                id: "mgmt-darwin-arm64".into(),
                name: "dioramactl macOS arm64".into(),
                dimension: DimensionCategory::ManagementTarget,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: Some("sha256:mgmt-darwin-arm64".into()),
                details: "Apple Silicon AArch64 macOS management CLI".into(),
            },
            EnvironmentRecord {
                id: "mgmt-windows".into(),
                name: "dioramactl Windows".into(),
                dimension: DimensionCategory::ManagementTarget,
                support_status: SupportStatus::Unsupported {
                    rationale: "Native Windows binaries are excluded by E01; WSL2 follows the Linux userspace and container-engine workflow."
                        .into(),
                },
                result: EnvironmentResult::Unsupported {
                    rationale: "Native Windows binaries excluded by E01; WSL2 follows Linux route".into(),
                },
                candidate_digest: None,
                details: "Windows native execution intentionally excluded".into(),
            },
        ]
    }

    fn oci_container_images() -> Vec<EnvironmentRecord> {
        let images = [
            ("image-coredns", "CoreDNS", true, true, true, true),
            ("image-pause", "Pause Sandbox", true, true, true, true),
            (
                "image-local-path",
                "Local Path Provisioner",
                true,
                true,
                true,
                true,
            ),
            (
                "image-local-path-helper",
                "Local Path Helper",
                true,
                true,
                true,
                true,
            ),
            (
                "image-diorama-kube",
                "Diorama Node Container",
                true,
                true,
                true,
                true,
            ),
            (
                "image-portainer-agent",
                "Portainer Edge Agent",
                true,
                true,
                true,
                false,
            ), // riscv64 unsupported
            (
                "image-d2k",
                "D2K Docker API Bridge",
                true,
                true,
                false,
                false,
            ), // armv7 & riscv64 unsupported
        ];

        let platforms = [
            ("linux/amd64", "amd64"),
            ("linux/arm64", "arm64"),
            ("linux/arm/v7", "armv7"),
            ("linux/riscv64", "riscv64"),
        ];

        let mut out = Vec::new();
        for (id_prefix, name, amd64_ok, arm64_ok, armv7_ok, riscv64_ok) in images {
            for (platform, arch_key) in platforms {
                let is_supported = match arch_key {
                    "amd64" => amd64_ok,
                    "arm64" => arm64_ok,
                    "armv7" => armv7_ok,
                    "riscv64" => riscv64_ok,
                    _ => false,
                };

                let record_id = format!("{id_prefix}-{arch_key}");
                let record_name = format!("{name} ({platform})");

                if is_supported {
                    out.push(EnvironmentRecord {
                        id: record_id,
                        name: record_name,
                        dimension: DimensionCategory::OciContainerImage,
                        support_status: SupportStatus::Supported,
                        result: EnvironmentResult::Verified,
                        candidate_digest: Some(format!("sha256:{id_prefix}-{arch_key}")),
                        details: format!("Multi-arch image manifest entry for {platform}"),
                    });
                } else {
                    let rationale =
                        unsupported_image_rationale(id_prefix, arch_key, name, platform);
                    out.push(EnvironmentRecord {
                        id: record_id,
                        name: record_name,
                        dimension: DimensionCategory::OciContainerImage,
                        support_status: SupportStatus::Unsupported {
                            rationale: rationale.clone(),
                        },
                        result: EnvironmentResult::Unsupported { rationale },
                        candidate_digest: None,
                        details: format!("Excluded from manifest index on {platform}"),
                    });
                }
            }
        }
        out
    }

    fn runtime_providers() -> Vec<EnvironmentRecord> {
        vec![
            EnvironmentRecord {
                id: "runtime-managed-containerd".into(),
                name: "Managed containerd (v2.2.5)".into(),
                dimension: DimensionCategory::RuntimeProvider,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: Some("sha256:containerd-v2.2.5".into()),
                details: "Managed containerd v2.2.5 daemon supervising containerd-shim-runc-v2".into(),
            },
            EnvironmentRecord {
                id: "runtime-external-containerd".into(),
                name: "External host containerd (v2.0.2 / v1.7.24)".into(),
                dimension: DimensionCategory::RuntimeProvider,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Attachment to host containerd socket via CRI v1 without process supervision".into(),
            },
            EnvironmentRecord {
                id: "runtime-external-crio".into(),
                name: "External host CRI-O (v1.32.0 / v1.30.0)".into(),
                dimension: DimensionCategory::RuntimeProvider,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Attachment to host CRI-O socket via CRI v1 without process supervision".into(),
            },
            EnvironmentRecord {
                id: "runtime-unknown-legacy-cri".into(),
                name: "Legacy or Unknown CRI Runtime".into(),
                dimension: DimensionCategory::RuntimeProvider,
                support_status: SupportStatus::Unsupported {
                    rationale: "Only modern CRI v1 gRPC endpoints are supported; legacy CRI v1alpha2 or unconfigured runtimes fail preflight."
                        .into(),
                },
                result: EnvironmentResult::Unsupported {
                    rationale: "Requires CRI v1 gRPC protocol compatibility".into(),
                },
                candidate_digest: None,
                details: "Unimplemented or obsolete CRI versions rejected at startup".into(),
            },
        ]
    }

    fn runtime_build_modes() -> Vec<EnvironmentRecord> {
        vec![
            EnvironmentRecord {
                id: "build-embedded-dependencies".into(),
                name: "Embedded-Dependency Build (Online & Offline)".into(),
                dimension: DimensionCategory::RuntimeBuildMode,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Self-contained distribution packages with verified embedded component assets".into(),
            },
            EnvironmentRecord {
                id: "build-host-supplied-dependencies".into(),
                name: "Host-Supplied External-Dependency Build".into(),
                dimension: DimensionCategory::RuntimeBuildMode,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Zero embedded payloads; binaries must compile and run using host-supplied executables".into(),
            },
        ]
    }

    fn init_systems() -> Vec<EnvironmentRecord> {
        vec![
            EnvironmentRecord {
                id: "init-systemd".into(),
                name: "systemd init manager".into(),
                dimension: DimensionCategory::InitSystem,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Unit file generation, reload, start, stop, restart, and journal integration".into(),
            },
            EnvironmentRecord {
                id: "init-openrc".into(),
                name: "OpenRC init manager (Alpine / Gentoo)".into(),
                dimension: DimensionCategory::InitSystem,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "OpenRC service script generation, rc-service, and rc-update support".into(),
            },
            EnvironmentRecord {
                id: "init-sysvinit".into(),
                name: "SysVinit init scripts".into(),
                dimension: DimensionCategory::InitSystem,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Standard SysVinit /etc/init.d script generation and lifecycle".into(),
            },
            EnvironmentRecord {
                id: "init-upstart".into(),
                name: "Upstart init jobs".into(),
                dimension: DimensionCategory::InitSystem,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Upstart /etc/init/*.conf service configuration".into(),
            },
            EnvironmentRecord {
                id: "init-runit".into(),
                name: "runit service supervision".into(),
                dimension: DimensionCategory::InitSystem,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "runit run script and finish handler generation".into(),
            },
            EnvironmentRecord {
                id: "init-s6".into(),
                name: "s6 supervision suite".into(),
                dimension: DimensionCategory::InitSystem,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "s6 service directory and run/finish script generation".into(),
            },
            EnvironmentRecord {
                id: "init-foreground".into(),
                name: "Foreground run mode".into(),
                dimension: DimensionCategory::InitSystem,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Interactive process execution with direct signal trapping and logging to stdout".into(),
            },
            EnvironmentRecord {
                id: "init-daemon".into(),
                name: "Daemon fork/background mode".into(),
                dimension: DimensionCategory::InitSystem,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Detached daemon execution with PID file tracking and bounded escalation".into(),
            },
            EnvironmentRecord {
                id: "init-windows-service".into(),
                name: "Windows Service Control Manager".into(),
                dimension: DimensionCategory::InitSystem,
                support_status: SupportStatus::Unsupported {
                    rationale: "Windows is excluded by E01; no Windows Service integration is supported.".into(),
                },
                result: EnvironmentResult::Unsupported {
                    rationale: "Windows host excluded by E01".into(),
                },
                candidate_digest: None,
                details: "Windows Service Manager intentionally unsupported".into(),
            },
            EnvironmentRecord {
                id: "init-darwin-launchd-node".into(),
                name: "macOS launchd Node Daemon".into(),
                dimension: DimensionCategory::InitSystem,
                support_status: SupportStatus::Unsupported {
                    rationale: "macOS hosts only management CLI dioramactl and Docker container mode; bare-metal launchd node daemon is unsupported."
                        .into(),
                },
                result: EnvironmentResult::Unsupported {
                    rationale: "macOS node execution runs via container mode, not bare-metal launchd".into(),
                },
                candidate_digest: None,
                details: "Bare-metal node daemon on Darwin is unsupported".into(),
            },
        ]
    }

    fn container_run_modes() -> Vec<EnvironmentRecord> {
        vec![
            EnvironmentRecord {
                id: "container-linux-docker".into(),
                name: "Linux Docker Engine (API v1.41+)".into(),
                dimension: DimensionCategory::ContainerRunMode,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Container mode lifecycle, port publication, bridge MTU, and volume persistence on Linux engine".into(),
            },
            EnvironmentRecord {
                id: "container-darwin-docker".into(),
                name: "macOS Docker Desktop / OrbStack".into(),
                dimension: DimensionCategory::ContainerRunMode,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Container mode lifecycle and port publication on macOS Docker engine".into(),
            },
            EnvironmentRecord {
                id: "container-wsl2-docker".into(),
                name: "WSL2 Docker Engine".into(),
                dimension: DimensionCategory::ContainerRunMode,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Container mode lifecycle within WSL2 Linux userspace".into(),
            },
            EnvironmentRecord {
                id: "container-static-cpu-manager".into(),
                name: "Static CPU Manager in Container Mode".into(),
                dimension: DimensionCategory::ContainerRunMode,
                support_status: SupportStatus::Unsupported {
                    rationale: "Static CPU manager policy requires exclusive host cgroup and cpuset manipulation, which is prohibited in container mode."
                        .into(),
                },
                result: EnvironmentResult::Unsupported {
                    rationale: "Static CPU manager requires host cgroup exclusivity; container mode must reject it".into(),
                },
                candidate_digest: None,
                details: "Container mode rejects static CPU manager policy fail-closed".into(),
            },
        ]
    }

    fn host_capabilities() -> Vec<EnvironmentRecord> {
        vec![
            EnvironmentRecord {
                id: "host-cgroup-v1".into(),
                name: "cgroup v1 hierarchy".into(),
                dimension: DimensionCategory::HostCapability,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Legacy cgroup v1 controllers supported for memory, cpu, and pids".into(),
            },
            EnvironmentRecord {
                id: "host-cgroup-v2".into(),
                name: "Unified cgroup v2 hierarchy".into(),
                dimension: DimensionCategory::HostCapability,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Modern unified cgroup v2 controllers with systemd/cgroup driver detection".into(),
            },
            EnvironmentRecord {
                id: "host-alpine-openrc".into(),
                name: "Alpine Linux with musl and OpenRC".into(),
                dimension: DimensionCategory::HostCapability,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Verified prerequisite preparation, musl ld-musl path detection, and reboot safety".into(),
            },
            EnvironmentRecord {
                id: "host-fuse-overlayfs".into(),
                name: "Nested container & fuse-overlayfs snapshotter".into(),
                dimension: DimensionCategory::HostCapability,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Supervised fuse-overlayfs-snapshotter with fallback to native snapshotter when helper is absent".into(),
            },
            EnvironmentRecord {
                id: "host-custom-writable-root".into(),
                name: "Custom writable path prefix (--path)".into(),
                dimension: DimensionCategory::HostCapability,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Non-standard filesystem roots (/var/lib/... override) with strict path isolation".into(),
            },
            EnvironmentRecord {
                id: "host-nftables-only".into(),
                name: "nftables-only host without legacy iptables".into(),
                dimension: DimensionCategory::HostCapability,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Regression KS-75/3fd84ca: kube-proxy and preflight operate on modern nftables-only hosts".into(),
            },
            EnvironmentRecord {
                id: "host-readonly-proc-sys".into(),
                name: "Read-only /proc/sys host".into(),
                dimension: DimensionCategory::HostCapability,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Regression KS-75/3fd84ca: sysctl tuning skips mutating read-only /proc/sys mounts".into(),
            },
            EnvironmentRecord {
                id: "host-low-mtu-vpn".into(),
                name: "Low MTU / VPN host networking (MTU 1200)".into(),
                dimension: DimensionCategory::HostCapability,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Configurable bridge MTU matches host VPN/tunnel constraints without MTU black-holing".into(),
            },
            EnvironmentRecord {
                id: "host-multinic-override".into(),
                name: "Multi-NIC override with explicit node-IP".into(),
                dimension: DimensionCategory::HostCapability,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Explicit node-IP binding bypasses ambiguous default route interface resolution".into(),
            },
            EnvironmentRecord {
                id: "host-unprivileged-missing-cgroups".into(),
                name: "Unprivileged user without root or missing cgroups".into(),
                dimension: DimensionCategory::HostCapability,
                support_status: SupportStatus::Unsupported {
                    rationale: "Node execution requires root privileges and cgroup controller access; unprivileged host fails preflight."
                        .into(),
                },
                result: EnvironmentResult::Unsupported {
                    rationale: "Requires root UID 0 and cgroup mounts for Kubernetes node execution".into(),
                },
                candidate_digest: None,
                details: "Preflight rejects unprivileged execution fail-closed".into(),
            },
        ]
    }

    fn delivery_modes() -> Vec<EnvironmentRecord> {
        vec![
            EnvironmentRecord {
                id: "delivery-online".into(),
                name: "Online Delivery Mode".into(),
                dimension: DimensionCategory::DeliveryMode,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Core images bundled; optional images dynamically pulled from registry if configured".into(),
            },
            EnvironmentRecord {
                id: "delivery-offline".into(),
                name: "Offline / Airgapped Delivery Mode".into(),
                dimension: DimensionCategory::DeliveryMode,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Network egress denied; all enabled optional and helper images pre-bundled in offline archive".into(),
            },
        ]
    }

    fn runtime_ownership() -> Vec<EnvironmentRecord> {
        vec![
            EnvironmentRecord {
                id: "ownership-workload-preservation".into(),
                name: "External Workload Preservation".into(),
                dimension: DimensionCategory::RuntimeOwnership,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "External containers, host sockets, and non-KubeSolo pods survive start/stop/restart/reset/uninstall intact".into(),
            },
            EnvironmentRecord {
                id: "ownership-firewall-preservation".into(),
                name: "Foreign Firewall Rule Preservation".into(),
                dimension: DimensionCategory::RuntimeOwnership,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "kube-proxy and CNI cleanup only owned rules without flushing unrelated host NAT tables".into(),
            },
        ]
    }

    fn addon_components() -> Vec<EnvironmentRecord> {
        vec![
            EnvironmentRecord {
                id: "addon-portainer-edge".into(),
                name: "Portainer Edge Agent".into(),
                dimension: DimensionCategory::AddonComponent,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Bootstrap-only ownership; existing Portainer objects preserved across node restarts".into(),
            },
            EnvironmentRecord {
                id: "addon-d2k".into(),
                name: "D2K Docker API Bridge".into(),
                dimension: DimensionCategory::AddonComponent,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "mTLS authenticated Docker API endpoint; disabled on ARMv7 and riscv64 before LoadBalancer validation".into(),
            },
            EnvironmentRecord {
                id: "addon-local-path".into(),
                name: "Local Path Storage Provisioner".into(),
                dimension: DimensionCategory::AddonComponent,
                support_status: SupportStatus::Supported,
                result: EnvironmentResult::Verified,
                candidate_digest: None,
                details: "Default storage class with Retain reclaim policy and host directory path management".into(),
            },
        ]
    }
}

/// Validates matrix completeness to ensure NO silent omissions exist.
#[derive(Debug)]
pub struct MatrixCompleteness;

impl MatrixCompleteness {
    /// Validate that all promised environments exist and unsupported decisions are justified.
    pub fn validate(records: &[EnvironmentRecord]) -> Result<(), String> {
        let canonical = EnvironmentMapping::canonical_matrix();
        let mut seen = BTreeSet::new();
        for record in records {
            if !seen.insert(record.id.as_str()) {
                return Err(format!("duplicate environment '{}'", record.id));
            }
            let expected = canonical
                .iter()
                .find(|expected| expected.id == record.id)
                .ok_or_else(|| format!("unexpected environment '{}'", record.id))?;
            if record.dimension != expected.dimension
                || record.name != expected.name
                || record.support_status != expected.support_status
                || record.result != expected.result
                || record.candidate_digest != expected.candidate_digest
                || record.details != expected.details
            {
                return Err(format!(
                    "environment '{}' disagrees with canonical synthetic plan",
                    record.id
                ));
            }
        }
        for expected in &canonical {
            if !seen.contains(expected.id.as_str()) {
                return Err(format!(
                    "missing environment '{}'; silent omission prohibited",
                    expected.id
                ));
            }
        }
        // 1. Verify all 16 node cells are present
        let mut observed_cells = BTreeSet::new();
        for rec in records {
            if rec.dimension == DimensionCategory::NodeVariantCell
                && let Some(cell_num) = rec.id.strip_prefix("node-cell-")
                && let Ok(c) = cell_num.parse::<u8>()
            {
                observed_cells.insert(c);
            }
        }
        for expected in 1..=16 {
            if !observed_cells.contains(&expected) {
                return Err(format!(
                    "missing node variant cell {expected:02}; silent omission prohibited"
                ));
            }
        }

        // 2. Verify all 4 management targets + Windows exclusion
        let mgmt_ids: BTreeSet<&str> = records
            .iter()
            .filter(|r| r.dimension == DimensionCategory::ManagementTarget)
            .map(|r| r.id.as_str())
            .collect();
        for req in [
            "mgmt-linux-amd64",
            "mgmt-linux-arm64",
            "mgmt-darwin-amd64",
            "mgmt-darwin-arm64",
            "mgmt-windows",
        ] {
            if !mgmt_ids.contains(req) {
                return Err(format!(
                    "missing management target {req}; silent omission prohibited"
                ));
            }
        }

        // 3. Verify OCI container images coverage (7 images * 4 platforms = 28 records)
        let oci_count = records
            .iter()
            .filter(|r| r.dimension == DimensionCategory::OciContainerImage)
            .count();
        if oci_count != 28 {
            return Err(format!(
                "expected 28 OCI image records (7 images x 4 platforms), got {oci_count}"
            ));
        }

        // 4. Verify every unsupported environment has a non-empty rationale
        for rec in records {
            match &rec.support_status {
                SupportStatus::Supported => {},
                SupportStatus::Unsupported { rationale } => {
                    if rationale.trim().is_empty() {
                        return Err(format!(
                            "unsupported environment '{}' lacks technical rationale",
                            rec.id
                        ));
                    }
                },
            }
        }

        // 5. Verify no illegal supported claims (e.g. D2K on riscv64 or Windows management binary)
        for rec in records {
            if rec.id == "mgmt-windows" && matches!(rec.support_status, SupportStatus::Supported) {
                return Err(
                    "mgmt-windows cannot be marked supported; Windows is excluded by E01".into(),
                );
            }
            if rec.id == "image-d2k-riscv64"
                && matches!(rec.support_status, SupportStatus::Supported)
            {
                return Err(
                    "image-d2k-riscv64 cannot be marked supported; D2K is disabled on riscv64"
                        .into(),
                );
            }
            if rec.id == "image-d2k-armv7" && matches!(rec.support_status, SupportStatus::Supported)
            {
                return Err(
                    "image-d2k-armv7 cannot be marked supported; D2K is disabled on armv7".into(),
                );
            }
            if rec.id == "image-portainer-agent-riscv64"
                && matches!(rec.support_status, SupportStatus::Supported)
            {
                return Err("image-portainer-agent-riscv64 cannot be marked supported; Portainer is unavailable on riscv64".into());
            }
            if rec.id == "container-static-cpu-manager"
                && matches!(rec.support_status, SupportStatus::Supported)
            {
                return Err("container-static-cpu-manager cannot be marked supported; static CPU manager is prohibited in container mode".into());
            }
        }

        Ok(())
    }
}
