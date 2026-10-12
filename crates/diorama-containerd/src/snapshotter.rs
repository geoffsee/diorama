//! Snapshotter selection for containerd root filesystem.

use std::fmt;
use std::path::Path;

/// Statfs filesystem magic for `OverlayFS` (`0x794c7630`).
pub const OVERLAYFS_SUPER_MAGIC: u32 = 0x794c_7630;

/// Snapshotter driver selected for containerd.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Snapshotter {
    /// Kernel `OverlayFS` (fastest, standard on Linux).
    Overlayfs,
    /// FUSE userspace `OverlayFS` (used when containerd root is itself on an overlayfs
    /// and `fuse-overlayfs` binary is present in PATH).
    FuseOverlayfs,
    /// Native snapshotter (copies layers instead of stacking; fallback when root is on
    /// an overlayfs but `fuse-overlayfs` is not installed).
    Native,
}

impl Snapshotter {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Overlayfs => "overlayfs",
            Self::FuseOverlayfs => "fuse-overlayfs",
            Self::Native => "native",
        }
    }
}

impl fmt::Display for Snapshotter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for Snapshotter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Snapshotter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "overlayfs" => Ok(Self::Overlayfs),
            "fuse-overlayfs" => Ok(Self::FuseOverlayfs),
            "native" => Ok(Self::Native),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["overlayfs", "fuse-overlayfs", "native"],
            )),
        }
    }
}

/// Choose a containerd snapshotter based on filesystem magic and userspace binary availability.
///
/// Logic:
/// 1. If the target path or its parent does not use overlayfs, return `Overlayfs`.
/// 2. If the target path uses overlayfs:
///    - If `fuse-overlayfs` is found via `has_fuse_overlayfs`, return `FuseOverlayfs`.
///    - Otherwise, fall back to `Native`.
#[must_use]
pub fn select_snapshotter(is_overlay_fs: bool, has_fuse_overlayfs: bool) -> Snapshotter {
    if is_overlay_fs {
        if has_fuse_overlayfs {
            Snapshotter::FuseOverlayfs
        } else {
            Snapshotter::Native
        }
    } else {
        Snapshotter::Overlayfs
    }
}

/// Check if a path is on an `OverlayFS` mount.
///
/// Inspects the directory (or its parent if the directory does not exist yet).
/// On Linux, uses `rustix::fs::statfs`. On non-Linux or on error, returns false (safe default).
#[must_use]
pub fn is_overlayfs(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        let target = path.ancestors().find(|p| p.exists()).unwrap_or(path);

        if let Ok(stat) = rustix::fs::statfs(target) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            return (stat.f_type as u32) == OVERLAYFS_SUPER_MAGIC;
        }
        false
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        false
    }
}

/// Check if `fuse-overlayfs` is present in the provided or system `PATH`.
#[must_use]
pub fn check_fuse_overlayfs_in_path(path_env: Option<&std::ffi::OsStr>) -> bool {
    let path_val = match path_env {
        Some(val) => val.to_os_string(),
        None => match std::env::var_os("PATH") {
            Some(val) => val,
            None => return false,
        },
    };

    for dir in std::env::split_paths(&path_val) {
        let candidate = dir.join("fuse-overlayfs");
        if candidate.is_file() {
            return true;
        }
    }
    false
}

/// Detect the appropriate snapshotter for the given containerd root directory on the current host.
#[must_use]
pub fn detect_snapshotter(root_dir: &Path) -> Snapshotter {
    let is_overlay = is_overlayfs(root_dir);
    let has_fuse = check_fuse_overlayfs_in_path(None);
    select_snapshotter(is_overlay, has_fuse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_host_selects_overlayfs() {
        assert_eq!(select_snapshotter(false, false), Snapshotter::Overlayfs);
        assert_eq!(select_snapshotter(false, true), Snapshotter::Overlayfs);
    }

    #[test]
    fn overlay_host_with_fuse_selects_fuse_overlayfs() {
        assert_eq!(select_snapshotter(true, true), Snapshotter::FuseOverlayfs);
    }

    #[test]
    fn overlay_host_without_fuse_falls_back_to_native() {
        assert_eq!(select_snapshotter(true, false), Snapshotter::Native);
    }

    #[test]
    fn snapshotter_serialization() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Wrapper {
            snapshotter: Snapshotter,
        }

        let w = Wrapper {
            snapshotter: Snapshotter::Overlayfs,
        };
        let s = toml::to_string(&w).unwrap();
        assert_eq!(s.trim(), "snapshotter = \"overlayfs\"");

        let de: Wrapper = toml::from_str(&s).unwrap();
        assert_eq!(de, w);
    }
}
