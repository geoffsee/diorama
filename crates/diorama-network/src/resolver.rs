use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use crate::error::NetworkError;
use crate::ip::is_valid_nameserver;
use crate::model::{FALLBACK_NAMESERVERS, MAX_NAMESERVERS};

/// Checks whether a resolv.conf file exists and contains at least one valid
/// upstream nameserver (global unicast address or metadata IP), and NO invalid
/// nameservers (such as loopback 127.0.0.53).
#[must_use]
pub fn is_valid_resolv_conf(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let reader = BufReader::new(file);

    let mut found_nameserver = false;
    for line in reader.lines() {
        let Ok(line) = line else {
            return false;
        };
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let ns = rest.trim();
            if ns.is_empty() || !is_valid_nameserver(ns) {
                return false;
            }
            found_nameserver = true;
        }
    }

    found_nameserver
}

/// Reads the resolv.conf at `src_path`, deduplicates nameservers, and caps them
/// to `MAX_NAMESERVERS` (3).
///
/// If no sanitization is needed, returns `src_path` unchanged.
/// Otherwise, writes the sanitized version to `<data_dir>/resolv.conf` and returns its path.
pub fn sanitize_resolv_conf(src_path: &Path, data_dir: &Path) -> Result<PathBuf, NetworkError> {
    let Ok(file) = fs::File::open(src_path) else {
        return Ok(src_path.to_path_buf());
    };
    let reader = BufReader::new(file);

    let mut other_lines = Vec::new();
    let mut nameservers = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut had_duplicates = false;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let ns = rest.trim().to_string();
            if !ns.is_empty() {
                if seen.insert(ns.clone()) {
                    nameservers.push(ns);
                } else {
                    had_duplicates = true;
                }
            }
            continue;
        }
        other_lines.push(line);
    }

    let had_excess = nameservers.len() > MAX_NAMESERVERS;
    if !had_duplicates && !had_excess {
        return Ok(src_path.to_path_buf());
    }

    if had_excess {
        let omitted = &nameservers[MAX_NAMESERVERS..];
        tracing::warn!(
            component = "network",
            omitted_count = omitted.len(),
            "host resolv.conf has more than {MAX_NAMESERVERS} nameservers; capping to prevent kubelet warnings"
        );
        nameservers.truncate(MAX_NAMESERVERS);
    }

    let mut output = String::new();
    for ns in &nameservers {
        let _ = writeln!(output, "nameserver {ns}");
    }
    for line in &other_lines {
        output.push_str(line);
        output.push('\n');
    }

    let dest_path = data_dir.join("resolv.conf");
    fs::write(&dest_path, output)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dest_path, fs::Permissions::from_mode(0o644));
    }

    Ok(dest_path)
}

/// Returns the path to a resolv.conf file containing real upstream nameservers
/// suitable for use by pods.
///
/// In container mode, returns `/dev/null` to prevent host DNS leakage.
/// Otherwise, checks `/etc/resolv.conf` and `/run/systemd/resolve/resolv.conf`.
/// If no valid configuration exists, generates a fallback in `<data_dir>/resolv.conf`.
#[must_use]
pub fn get_host_resolv_conf(data_dir: &Path, container_mode: bool) -> PathBuf {
    get_host_resolv_conf_with_candidates(
        data_dir,
        container_mode,
        &[
            Path::new("/etc/resolv.conf"),
            Path::new("/run/systemd/resolve/resolv.conf"),
        ],
    )
}

/// Returns the path to a resolv.conf file inspecting the specified candidate paths.
#[must_use]
pub fn get_host_resolv_conf_with_candidates(
    data_dir: &Path,
    container_mode: bool,
    candidates: &[&Path],
) -> PathBuf {
    if container_mode {
        tracing::info!(
            component = "network",
            "running in container mode - using /dev/null for resolv.conf to prevent host DNS leakage into pods"
        );
        return PathBuf::from("/dev/null");
    }

    let mut rejected_candidates = Vec::new();
    for &conf in candidates {
        if is_valid_resolv_conf(conf) {
            if !rejected_candidates.is_empty() {
                tracing::info!(
                    component = "network",
                    earlier_unusable = ?rejected_candidates,
                    selected = %conf.display(),
                    "earlier resolv.conf candidate(s) were unusable; selected {}",
                    conf.display()
                );
            }
            match sanitize_resolv_conf(conf, data_dir) {
                Ok(path) => return path,
                Err(e) => {
                    tracing::warn!(
                        component = "network",
                        error = %e,
                        "failed to sanitize resolv.conf, using original"
                    );
                    return conf.to_path_buf();
                },
            }
        }
        rejected_candidates.push(conf.display().to_string());
    }

    // No valid resolv.conf found — generate fallback with public DNS servers
    let dest = data_dir.join("resolv.conf");
    let content = format!(
        "nameserver {}\nnameserver {}\n",
        FALLBACK_NAMESERVERS[0], FALLBACK_NAMESERVERS[1]
    );

    if let Err(e) = fs::write(&dest, content) {
        tracing::error!(
            component = "network",
            error = %e,
            "failed to write fallback resolv.conf"
        );
        return PathBuf::from("/etc/resolv.conf");
    }

    tracing::warn!(
        component = "network",
        "host resolv.conf includes loopback or link-local nameservers - using autogenerated resolv.conf with {} and {}",
        FALLBACK_NAMESERVERS[0],
        FALLBACK_NAMESERVERS[1]
    );

    dest
}
