use diorama_platform::{Architecture, HostEvidence, Libc, NodeTarget, classify};
use std::fmt;

pub const ARCHIVE_PREFIX: &str = "diorama";
pub const DEFAULT_VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));
pub const DEFAULT_RELEASE_BASE_URL: &str = "https://github.com/geoffsee/diorama/releases/download";
pub const DEFAULT_DATA_PATH: &str = "/var/lib/diorama";
pub const DEFAULT_INSTALL_PATH: &str = "/usr/local/bin/diorama";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactSelectionError {
    UnsupportedArch(String),
    DarwinRequiresArch,
    UnsupportedHost(String),
    MissingHostEvidence,
}

impl fmt::Display for ArtifactSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArch(arch) => write!(
                f,
                "unsupported target arch \"{arch}\": valid values are amd64, arm64, arm, riscv64, amd64-musl, arm64-musl, arm-musl, riscv64-musl"
            ),
            Self::DarwinRequiresArch => write!(
                f,
                "on macOS, diorama has no native binaries — specify the target Linux arch with --arch (e.g. --arch=amd64 or --arch=arm64)"
            ),
            Self::UnsupportedHost(os) => write!(
                f,
                "unsupported host OS \"{os}\"; only Linux is supported for native host installation"
            ),
            Self::MissingHostEvidence => {
                write!(f, "host evidence required for automatic target detection")
            },
        }
    }
}

impl std::error::Error for ArtifactSelectionError {}

/// Resolves the intended `NodeTarget` given an optional explicit architecture argument,
/// an optional explicit libc override, and optional host evidence from shared preflight.
pub fn resolve_target(
    arch_arg: Option<&str>,
    libc_override: Option<Libc>,
    evidence: Option<&HostEvidence>,
) -> Result<NodeTarget, ArtifactSelectionError> {
    if let Some(raw_arch) = arch_arg {
        let (arch, inferred_libc) = match raw_arch {
            "amd64" => (Architecture::Amd64, Libc::Glibc),
            "amd64-musl" => (Architecture::Amd64, Libc::Musl),
            "arm64" => (Architecture::Arm64, Libc::Glibc),
            "arm64-musl" => (Architecture::Arm64, Libc::Musl),
            "arm" | "armv7" => (Architecture::ArmV7, Libc::Glibc),
            "arm-musl" | "armv7-musl" => (Architecture::ArmV7, Libc::Musl),
            "riscv64" => (Architecture::Riscv64, Libc::Glibc),
            "riscv64-musl" => (Architecture::Riscv64, Libc::Musl),
            other => return Err(ArtifactSelectionError::UnsupportedArch(other.to_string())),
        };
        let libc = libc_override.unwrap_or(inferred_libc);
        Ok(NodeTarget {
            architecture: arch,
            libc,
        })
    } else {
        let ev = evidence.ok_or(ArtifactSelectionError::MissingHostEvidence)?;
        if ev.executable.os == "darwin" {
            return Err(ArtifactSelectionError::DarwinRequiresArch);
        }
        if ev.executable.os != "linux" {
            return Err(ArtifactSelectionError::UnsupportedHost(
                ev.executable.os.clone(),
            ));
        }
        let arch = match ev.executable.architecture.as_str() {
            "x86_64" | "amd64" => Architecture::Amd64,
            "aarch64" | "arm64" => Architecture::Arm64,
            "arm" | "armv7" | "armv7l" => Architecture::ArmV7,
            "riscv64" => Architecture::Riscv64,
            other => return Err(ArtifactSelectionError::UnsupportedArch(other.to_string())),
        };
        let libc = libc_override.unwrap_or_else(|| {
            let caps = classify(ev);
            match caps.host_libc_hint {
                diorama_platform::Observation::Present(l) => l,
                _ => Libc::Glibc,
            }
        });
        Ok(NodeTarget {
            architecture: arch,
            libc,
        })
    }
}

/// Constructs the exact archive filename for the selected target, version, and online/offline variant.
pub fn artifact_archive_name(version: &str, target: NodeTarget, offline: bool) -> String {
    let arch_suffix = match target.architecture {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
        Architecture::ArmV7 => "arm",
        Architecture::Riscv64 => "riscv64",
    };
    let libc_suffix = match target.libc {
        Libc::Glibc => "",
        Libc::Musl => "-musl",
    };
    let offline_suffix = if offline { "-offline" } else { "" };
    format!("{ARCHIVE_PREFIX}-{version}-linux-{arch_suffix}{libc_suffix}{offline_suffix}.tar.gz")
}

/// Constructs the download URL, honoring custom URLs when configured.
pub fn artifact_download_url(
    version: &str,
    archive_name: &str,
    custom_url: Option<&str>,
) -> String {
    if let Some(custom) = custom_url {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    format!("{DEFAULT_RELEASE_BASE_URL}/{version}/{archive_name}")
}

/// Constructs the management CLI release asset name for a target OS and architecture.
pub fn installer_asset_name(os: &str, arch: Architecture) -> String {
    let arch_suffix = match arch {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
        Architecture::ArmV7 => "arm",
        Architecture::Riscv64 => "riscv64",
    };
    format!("dioramactl-{os}-{arch_suffix}")
}

/// Current releases publish a separate offline archive per installation mode.
pub fn core_archive_name(version: &str, target: NodeTarget, container: bool) -> String {
    artifact_archive_name(version, target, true).replace(
        "-offline.tar.gz",
        if container {
            "-container-offline.tar.gz"
        } else {
            "-host-offline.tar.gz"
        },
    )
}
