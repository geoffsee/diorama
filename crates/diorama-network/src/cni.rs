use std::fs;
use std::path::{Path, PathBuf};

use crate::error::NetworkError;

pub const DEFAULT_POD_CIDR: &str = "10.42.0.0/16";
pub const DEFAULT_BRIDGE_NAME: &str = "cni0";
pub const DEFAULT_CNI_CONFIG_NAME: &str = "10-bridge.conflist";
pub const DEFAULT_STANDARD_CNI_CONF_DIR: &str = "/etc/cni/net.d";
pub const DEFAULT_STANDARD_CNI_BIN_DIR: &str = "/opt/cni/bin";
pub const REQUIRED_CNI_PLUGINS: [&str; 4] = ["bridge", "host-local", "portmap", "loopback"];
pub const CNI_CONFIG_EXTENSIONS: [&str; 3] = [".conf", ".conflist", ".json"];

/// Allocates a unique `/24` `PodCIDR` subnet for `node_id` (`10.42.<node_id>.0/24`).
#[must_use]
pub fn pod_cidr_for_node(node_id: u64) -> String {
    let octet = u8::try_from(node_id % 255).unwrap_or(0);
    format!("10.42.{octet}.0/24")
}

/// Results of inspecting the CNI configuration directory ordering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CniOrderingInspection {
    /// CNI configuration files sorting lexicographically before our owned configuration.
    pub earlier_competing: Vec<String>,
    /// CNI configuration files sorting lexicographically after our owned configuration.
    pub later_entries: Vec<String>,
}

/// Generates the standard CNI configuration data structure.
///
/// Supports single IPv4 CIDR, comma-separated dual-stack CIDRs, or defaults to `DEFAULT_POD_CIDR`.
#[must_use]
pub fn generate_cni_config(mtu: u32, pod_cidr: Option<&str>) -> serde_json::Value {
    let subnet_input = pod_cidr.unwrap_or(DEFAULT_POD_CIDR);
    let cidrs: Vec<&str> = subnet_input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    generate_cni_config_from_cidrs(mtu, &cidrs)
}

/// Generates dual-stack CNI configuration with explicit IPv4 and optional IPv6 CIDR.
#[must_use]
pub fn generate_cni_config_dual_stack(
    mtu: u32,
    ipv4_cidr: Option<&str>,
    ipv6_cidr: Option<&str>,
) -> serde_json::Value {
    let mut cidrs = Vec::new();
    let v4 = ipv4_cidr.unwrap_or(DEFAULT_POD_CIDR);
    cidrs.push(v4);
    if let Some(v6) = ipv6_cidr {
        cidrs.push(v6);
    }
    generate_cni_config_from_cidrs(mtu, &cidrs)
}

/// Generates CNI configuration from a slice of CIDR subnets (IPv4 and/or IPv6).
#[must_use]
pub fn generate_cni_config_from_cidrs(mtu: u32, cidrs: &[&str]) -> serde_json::Value {
    let mut ranges = Vec::new();
    let mut routes = Vec::new();

    let effective_cidrs = if cidrs.is_empty() {
        vec![DEFAULT_POD_CIDR]
    } else {
        cidrs.to_vec()
    };

    for cidr in effective_cidrs {
        ranges.push(vec![serde_json::json!({ "subnet": cidr })]);
        if cidr.contains(':') {
            routes.push(serde_json::json!({ "dst": "::/0" }));
        } else {
            routes.push(serde_json::json!({ "dst": "0.0.0.0/0" }));
        }
    }

    serde_json::json!({
        "cniVersion": "1.0.0",
        "name": "diorama-net",
        "plugins": [
            {
                "type": "bridge",
                "bridge": DEFAULT_BRIDGE_NAME,
                "isGateway": true,
                "ipMasq": false,
                "hairpinMode": true,
                "mtu": mtu,
                "capabilities": {
                    "portMappings": true,
                    "ips": true
                },
                "ipam": {
                    "type": "host-local",
                    "ranges": ranges,
                    "routes": routes
                }
            },
            {
                "type": "portmap",
                "capabilities": {
                    "portMappings": true
                }
            },
            {
                "type": "loopback"
            }
        ]
    })
}

/// Formats the CNI configuration as pretty-printed JSON.
pub fn generate_cni_config_json(mtu: u32, pod_cidr: Option<&str>) -> Result<String, NetworkError> {
    let value = generate_cni_config(mtu, pod_cidr);
    serde_json::to_string_pretty(&value).map_err(|e| NetworkError::SerializationError {
        reason: format!("{e}"),
    })
}

/// Writes the CNI configuration JSON file to `path` with permissions 0644.
static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn write_cni_config_file(
    path: &Path,
    mtu: u32,
    pod_cidr: Option<&str>,
) -> Result<(), NetworkError> {
    use std::io::Write;
    use std::sync::atomic::Ordering;

    let content = generate_cni_config_json(mtu, pod_cidr)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    // Atomic replacement: write to a unique temporary file in the same directory, set permissions, then rename
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("cni-config");
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!(
        ".{file_name}.tmp-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        counter
    );
    let temp_path = parent.join(temp_name);

    let mut temp_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = temp_file.set_permissions(fs::Permissions::from_mode(0o644)) {
            let _ = fs::remove_file(&temp_path);
            return Err(NetworkError::Io(e));
        }
    }

    if let Err(e) = temp_file.write_all(content.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(NetworkError::Io(e));
    }

    if let Err(e) = temp_file.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(NetworkError::Io(e));
    }
    drop(temp_file);

    if let Err(e) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(NetworkError::Io(e));
    }

    Ok(())
}

/// Removes a file at `path` if it is a symbolic link.
/// Returns Ok(true) if a symlink was detected and removed, Ok(false) if absent or regular file.
pub fn remove_if_symlink(path: &Path) -> Result<bool, NetworkError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                fs::remove_file(path)?;
                Ok(true)
            } else {
                Ok(false)
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(NetworkError::Io(e)),
    }
}

/// Writes CNI configuration in managed mode (embedded containerd).
///
/// Writes the configuration to `<base_path>/containerd/cni/conf/10-bridge.conflist`
/// and atomically installs or updates a symlink from `<standard_conf_dir>/10-bridge.conflist` pointing to it.
pub fn write_managed_cni_config(
    base_path: &Path,
    mtu: u32,
    pod_cidr: Option<&str>,
    standard_conf_dir: Option<&Path>,
) -> Result<PathBuf, NetworkError> {
    use std::sync::atomic::Ordering;

    let managed_conf_dir = base_path.join("containerd/cni/conf");
    let managed_config_file = managed_conf_dir.join(DEFAULT_CNI_CONFIG_NAME);

    fs::create_dir_all(&managed_conf_dir)?;
    write_cni_config_file(&managed_config_file, mtu, pod_cidr)?;

    let target_dir = standard_conf_dir.unwrap_or_else(|| Path::new(DEFAULT_STANDARD_CNI_CONF_DIR));
    fs::create_dir_all(target_dir)?;

    #[cfg(unix)]
    if target_dir != managed_conf_dir {
        let symlink_path = target_dir.join(DEFAULT_CNI_CONFIG_NAME);
        let symlink_target = fs::canonicalize(&managed_config_file)?;
        let temp_symlink_name = format!(
            ".{DEFAULT_CNI_CONFIG_NAME}.symlink-tmp-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let temp_symlink_path = target_dir.join(temp_symlink_name);
        std::os::unix::fs::symlink(&symlink_target, &temp_symlink_path)?;
        if let Err(e) = fs::rename(&temp_symlink_path, &symlink_path) {
            let _ = fs::remove_file(&temp_symlink_path);
            return Err(NetworkError::Io(e));
        }
    }

    Ok(managed_config_file)
}

/// Writes CNI configuration in external runtime mode (host-managed containerd or CRI-O).
///
/// Writes directly to `<conf_dir>/10-bridge.conflist`, atomically replacing any dangling symlink
/// from a previous embedded run. Other unrelated files and runtime configurations
/// in `conf_dir` are strictly preserved.
pub fn write_external_cni_config(
    conf_dir: &Path,
    mtu: u32,
    pod_cidr: Option<&str>,
) -> Result<PathBuf, NetworkError> {
    fs::create_dir_all(conf_dir)?;

    let cni_config_file = conf_dir.join(DEFAULT_CNI_CONFIG_NAME);

    if let Ok(meta) = fs::symlink_metadata(&cni_config_file)
        && meta.file_type().is_symlink()
    {
        tracing::info!(
            component = "network",
            path = %cni_config_file.display(),
            "replacing CNI config symlink left by previous embedded run"
        );
    }

    write_cni_config_file(&cni_config_file, mtu, pod_cidr)?;

    let _ = inspect_cni_dir_ordering(conf_dir, DEFAULT_CNI_CONFIG_NAME);

    Ok(cni_config_file)
}

/// Inspects the CNI configuration directory for other CNI configuration files.
///
/// Warns if any configuration sorts lexicographically ahead of `owned_name`,
/// which would cause the container runtime to use that CNI instead of ours.
pub fn inspect_cni_dir_ordering(
    conf_dir: &Path,
    owned_name: &str,
) -> Result<CniOrderingInspection, NetworkError> {
    let mut inspection = CniOrderingInspection::default();
    let Ok(entries) = fs::read_dir(conf_dir) else {
        return Ok(inspection);
    };

    let mut sorted_entries: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|name| {
            name != owned_name && CNI_CONFIG_EXTENSIONS.iter().any(|ext| name.ends_with(ext))
        })
        .collect();

    sorted_entries.sort();

    for name in sorted_entries {
        if name.as_str() < owned_name {
            tracing::warn!(
                component = "network",
                cni_config = %name,
                owned = %owned_name,
                "cni config {name} sorts before {owned_name} and will be used instead... pods will join that network"
            );
            inspection.earlier_competing.push(name);
        } else {
            tracing::info!(
                component = "network",
                cni_config = %name,
                owned = %owned_name,
                "found additional cni config {name}, which sorts after {owned_name}"
            );
            inspection.later_entries.push(name);
        }
    }

    Ok(inspection)
}

/// Checks whether required CNI plugins exist in `plugins_dir`.
///
/// Returns a list of any missing plugin names.
#[must_use]
pub fn warn_missing_cni_plugins(plugins_dir: &Path) -> Vec<String> {
    let mut missing = Vec::new();

    for &plugin in &REQUIRED_CNI_PLUGINS {
        if !plugins_dir.join(plugin).exists() {
            missing.push(plugin.to_string());
        }
    }

    if missing.is_empty() {
        tracing::debug!(
            component = "network",
            plugins_dir = %plugins_dir.display(),
            "all required cni plugins are present in {}",
            plugins_dir.display()
        );
    } else {
        tracing::warn!(
            component = "network",
            missing = ?missing,
            plugins_dir = %plugins_dir.display(),
            "cni plugins {} were not found in {}... the host has to provide them, or the container runtime has to be configured to load them from elsewhere, otherwise pods will fail to start",
            missing.join(", "),
            plugins_dir.display()
        );
    }

    missing
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_cni_config_golden() {
        let value = generate_cni_config(1500, None);
        assert_eq!(value["cniVersion"], "1.0.0");
        assert_eq!(value["name"], "diorama-net");

        let plugins = value["plugins"].as_array().expect("plugins array");
        assert_eq!(plugins.len(), 3);

        // 1. Bridge plugin
        let bridge = &plugins[0];
        assert_eq!(bridge["type"], "bridge");
        assert_eq!(bridge["bridge"], "cni0");
        assert_eq!(bridge["isGateway"], true);
        assert_eq!(bridge["ipMasq"], false);
        assert_eq!(bridge["hairpinMode"], true);
        assert_eq!(bridge["mtu"], 1500);
        assert_eq!(bridge["capabilities"]["portMappings"], true);
        assert_eq!(bridge["capabilities"]["ips"], true);
        assert_eq!(bridge["ipam"]["type"], "host-local");
        assert_eq!(bridge["ipam"]["ranges"][0][0]["subnet"], "10.42.0.0/16");
        assert_eq!(bridge["ipam"]["routes"][0]["dst"], "0.0.0.0/0");

        // 2. Portmap plugin
        let portmap = &plugins[1];
        assert_eq!(portmap["type"], "portmap");
        assert_eq!(portmap["capabilities"]["portMappings"], true);

        // 3. Loopback plugin
        let loopback = &plugins[2];
        assert_eq!(loopback["type"], "loopback");
    }

    #[test]
    fn test_generate_cni_config_custom_mtu_and_cidr() {
        let value = generate_cni_config(1420, Some("10.244.0.0/16"));
        assert_eq!(value["plugins"][0]["mtu"], 1420);
        assert_eq!(
            value["plugins"][0]["ipam"]["ranges"][0][0]["subnet"],
            "10.244.0.0/16"
        );
    }

    #[test]
    fn test_generate_cni_config_dual_stack() {
        let value =
            generate_cni_config_dual_stack(1500, Some("10.42.0.0/16"), Some("fd00:10:42::/64"));
        let plugins = value["plugins"].as_array().expect("plugins array");
        let bridge = &plugins[0];

        assert_eq!(bridge["hairpinMode"], true);
        assert_eq!(bridge["isGateway"], true);
        assert_eq!(bridge["ipMasq"], false);

        let ranges = bridge["ipam"]["ranges"].as_array().expect("ranges array");
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0][0]["subnet"], "10.42.0.0/16");
        assert_eq!(ranges[1][0]["subnet"], "fd00:10:42::/64");

        let routes = bridge["ipam"]["routes"].as_array().expect("routes array");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0]["dst"], "0.0.0.0/0");
        assert_eq!(routes[1]["dst"], "::/0");

        // Comma-separated also works identically
        let value_csv = generate_cni_config(1500, Some("10.42.0.0/16, fd00:10:42::/64"));
        assert_eq!(value, value_csv);
    }

    #[test]
    fn test_write_external_cni_config_preserves_unrelated_files() {
        let dir = tempdir().expect("tempdir");
        let conf_dir = dir.path();

        // Create unrelated configuration files
        fs::write(conf_dir.join("99-loopback.conf"), b"existing-content").expect("write unrelated");
        fs::write(conf_dir.join("readme.txt"), b"documentation").expect("write readme");

        let written_path = write_external_cni_config(conf_dir, 1500, None).expect("write external");
        assert_eq!(written_path, conf_dir.join("10-bridge.conflist"));
        assert!(written_path.exists());

        // Unrelated files remain byte-identical
        assert_eq!(
            fs::read(conf_dir.join("99-loopback.conf")).expect("read unrelated"),
            b"existing-content"
        );
        assert_eq!(
            fs::read(conf_dir.join("readme.txt")).expect("read readme"),
            b"documentation"
        );
    }

    #[test]
    fn test_write_external_cni_config_removes_dangling_symlink() {
        let dir = tempdir().expect("tempdir");
        let conf_dir = dir.path();
        let target_file = conf_dir.join("10-bridge.conflist");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(conf_dir.join("nonexistent-embedded-target"), &target_file)
                .expect("create dangling symlink");
            assert!(target_file.is_symlink());
        }

        let written_path = write_external_cni_config(conf_dir, 1500, None).expect("write external");
        assert_eq!(written_path, target_file);
        assert!(written_path.exists());
        assert!(!written_path.is_symlink());

        let content = fs::read_to_string(&written_path).expect("read content");
        assert!(content.contains("diorama-net"));
    }

    #[test]
    fn test_inspect_cni_dir_ordering() {
        let dir = tempdir().expect("tempdir");
        let conf_dir = dir.path();

        // Create earlier competing entries and later entries
        fs::write(conf_dir.join("05-cilium.conflist"), b"{}").expect("write cilium");
        fs::write(conf_dir.join("00-calico.conf"), b"{}").expect("write calico");
        fs::write(conf_dir.join("20-flannel.conflist"), b"{}").expect("write flannel");
        fs::write(conf_dir.join("99-other.json"), b"{}").expect("write other");
        fs::write(conf_dir.join("ignored.txt"), b"text").expect("write text");

        let inspection =
            inspect_cni_dir_ordering(conf_dir, "10-bridge.conflist").expect("inspect ordering");

        assert_eq!(
            inspection.earlier_competing,
            vec!["00-calico.conf", "05-cilium.conflist"]
        );
        assert_eq!(
            inspection.later_entries,
            vec!["20-flannel.conflist", "99-other.json"]
        );
    }

    #[test]
    fn test_warn_missing_cni_plugins() {
        let dir = tempdir().expect("tempdir");
        let plugins_dir = dir.path();

        // Missing all
        let missing = warn_missing_cni_plugins(plugins_dir);
        assert_eq!(missing, vec!["bridge", "host-local", "portmap", "loopback"]);

        // Add bridge and portmap
        fs::write(plugins_dir.join("bridge"), b"").expect("write bridge");
        fs::write(plugins_dir.join("portmap"), b"").expect("write portmap");

        let missing = warn_missing_cni_plugins(plugins_dir);
        assert_eq!(missing, vec!["host-local", "loopback"]);

        // Add the rest
        fs::write(plugins_dir.join("host-local"), b"").expect("write host-local");
        fs::write(plugins_dir.join("loopback"), b"").expect("write loopback");

        let missing = warn_missing_cni_plugins(plugins_dir);
        assert_eq!(missing, Vec::<String>::new());
    }

    #[test]
    fn test_write_managed_cni_config() {
        let dir = tempdir().expect("tempdir");
        let base_path = dir.path().join("var/lib/diorama");
        let standard_conf_dir = dir.path().join("etc/cni/net.d");

        let written_path = write_managed_cni_config(
            &base_path,
            1450,
            Some("10.42.0.0/16"),
            Some(&standard_conf_dir),
        )
        .expect("write managed");

        assert_eq!(
            written_path,
            base_path.join("containerd/cni/conf/10-bridge.conflist")
        );
        assert!(written_path.exists());

        #[cfg(unix)]
        {
            let symlink = standard_conf_dir.join("10-bridge.conflist");
            assert!(symlink.is_symlink());
            let target = fs::read_link(&symlink).expect("read symlink");
            assert_eq!(
                target,
                fs::canonicalize(&written_path).expect("canonicalize")
            );
        }
    }
}
