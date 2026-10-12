//! Read-only constrained-host facts and policy; no execution or ownership transfer.
use crate::discover::{bounded_text, error, exists, validate_limits};
use crate::preflight::{CheckStatus, RuntimeOwnership};
use crate::{Observation, PlatformError, ProbeFailure, ProbeLimits};
use std::fs;
use std::path::Path;

pub const OWNED_CNI_CONFIG: &str = "10-bridge.conflist";
pub const SYSCTL_PATHS: [&str; 4] = [
    "/proc/sys/net/ipv4/ip_forward",
    "/proc/sys/net/ipv6/conf/all/disable_ipv6",
    "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    "/proc/sys/net/ipv6/conf/lo/disable_ipv6",
];
pub const CNI_PLUGINS: [&str; 4] = ["bridge", "host-local", "portmap", "loopback"];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstrainedFacts {
    pub sysctls: [Observation<String>; 4],
    /// `/proc` or `/proc/sys` mounted read-only. A wrong value cannot be prepared in place.
    pub proc_sys_read_only: Observation<bool>,
    pub ip_tables_names: Observation<bool>,
    pub default_cni_plugins: [Observation<bool>; 4],
    /// Entry names only, including directories as in the baseline ordering warning.
    pub cni_config_names: Observation<Vec<String>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstrainedInputs {
    pub runtime: RuntimeOwnership,
    /// Output from a separately owned bounded command probe. No command runs here.
    pub iptables_version: Observation<String>,
    /// Carried unchanged; selecting nft never waives the existing `xt_comment` check.
    pub xtables_comment: CheckStatus,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyBackend {
    Iptables,
    Nftables,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleFamily {
    Legacy,
    NfTables,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysctlState {
    AlreadyCorrect,
    NeedsPreparation,
    /// Missing IPv6 controls do not require a write; IPv4 forwarding is mandatory.
    OptionalAbsent,
    RequiredAbsent,
    /// The value needs a write, but the sysctl mount is read-only.
    ReadOnly,
    Unknown(ProbeFailure),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CniOrdering {
    pub earlier: usize,
    pub later: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PluginState {
    Present,
    DefaultLocationMissing,
    Unknown(ProbeFailure),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeResponsibilities {
    /// Describes responsibility only; no preparation action is authorized.
    Managed,
    /// Runtime process/config, OCI runtime, CNI binaries and sandbox images stay host-owned.
    External,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstrainedReport {
    pub sysctls: [SysctlState; 4],
    /// Selection heuristic, not proof that the backend can program rules.
    pub proxy_selection: Observation<ProxyBackend>,
    /// Independent version-based hint, not module loadability evidence.
    pub module_family: Observation<ModuleFamily>,
    pub xtables_comment: CheckStatus,
    pub plugins: [PluginState; 4],
    pub cni_ordering: Observation<CniOrdering>,
    pub responsibilities: RuntimeResponsibilities,
}
fn sysctl(
    value: Observation<&String>,
    optional: bool,
    read_only: Observation<bool>,
) -> SysctlState {
    let state = match value {
        Observation::Present(text) => match text.trim() {
            "1" => SysctlState::AlreadyCorrect,
            "0" => SysctlState::NeedsPreparation,
            _ => SysctlState::Unknown(ProbeFailure::Malformed),
        },
        Observation::Absent if optional => SysctlState::OptionalAbsent,
        Observation::Absent => SysctlState::RequiredAbsent,
        Observation::Unknown(error) => SysctlState::Unknown(error),
    };
    match (state, read_only) {
        (
            SysctlState::NeedsPreparation | SysctlState::RequiredAbsent,
            Observation::Present(true),
        ) => SysctlState::ReadOnly,
        (state, _) => state,
    }
}
fn ordering(names: Observation<&Vec<String>>) -> Observation<CniOrdering> {
    match names {
        Observation::Present(names) => {
            let mut result = CniOrdering {
                earlier: 0,
                later: 0,
            };
            for name in names {
                if name.is_empty() || name.contains('/') || name.contains('\0') {
                    return Observation::Unknown(ProbeFailure::Malformed);
                }
                if name == OWNED_CNI_CONFIG
                    || ![".conf", ".conflist", ".json"]
                        .iter()
                        .any(|suffix| name.ends_with(suffix))
                {
                    continue;
                }
                if name.as_str() < OWNED_CNI_CONFIG {
                    result.earlier += 1;
                } else {
                    result.later += 1;
                }
            }
            Observation::Present(result)
        },
        Observation::Absent => Observation::Absent,
        Observation::Unknown(error) => Observation::Unknown(error),
    }
}
/// Produces observations and advisory requirements, never an overall host-ready verdict.
pub fn evaluate_constrained(
    facts: &ConstrainedFacts,
    inputs: &ConstrainedInputs,
) -> ConstrainedReport {
    let proxy_selection = match facts.ip_tables_names {
        Observation::Present(true) => Observation::Present(ProxyBackend::Iptables),
        Observation::Present(false) | Observation::Absent => {
            Observation::Present(ProxyBackend::Nftables)
        },
        Observation::Unknown(error) => Observation::Unknown(error),
    };
    let module_family = match inputs.iptables_version.as_ref() {
        Observation::Present(text) if text.contains("(nf_tables)") => {
            Observation::Present(ModuleFamily::NfTables)
        },
        Observation::Present(_) => Observation::Present(ModuleFamily::Legacy),
        Observation::Absent => Observation::Absent,
        Observation::Unknown(error) => Observation::Unknown(error),
    };
    ConstrainedReport {
        sysctls: std::array::from_fn(|i| {
            sysctl(facts.sysctls[i].as_ref(), i != 0, facts.proc_sys_read_only)
        }),
        proxy_selection,
        module_family,
        xtables_comment: inputs.xtables_comment,
        plugins: facts.default_cni_plugins.map(|value| match value {
            Observation::Present(true) => PluginState::Present,
            Observation::Present(false) | Observation::Absent => {
                PluginState::DefaultLocationMissing
            },
            Observation::Unknown(error) => PluginState::Unknown(error),
        }),
        cni_ordering: ordering(facts.cni_config_names.as_ref()),
        responsibilities: match inputs.runtime {
            RuntimeOwnership::Managed => RuntimeResponsibilities::Managed,
            RuntimeOwnership::External => RuntimeResponsibilities::External,
        },
    }
}
fn directory_names(path: &Path, limit: usize) -> Observation<Vec<String>> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(failure) => return error(&failure),
    };
    let mut names = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= limit {
            return Observation::Unknown(ProbeFailure::TooLarge);
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(failure) => return error(&failure),
        };
        let Ok(name) = entry.file_name().into_string() else {
            return Observation::Unknown(ProbeFailure::Malformed);
        };
        if name.len() > 255 {
            return Observation::Unknown(ProbeFailure::TooLarge);
        }
        names.push(name);
    }
    names.sort();
    Observation::Present(names)
}
fn proc_sys_read_only(limit: usize) -> Observation<bool> {
    let text = match bounded_text(Path::new("/proc/mounts"), limit.min(65_536)) {
        Observation::Present(text) => text,
        Observation::Absent => return Observation::Absent,
        Observation::Unknown(failure) => return Observation::Unknown(failure),
    };
    let mut read_only = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(_device) = fields.next() else {
            continue;
        };
        let Some(mount) = fields.next() else {
            continue;
        };
        let Some(_filesystem) = fields.next() else {
            continue;
        };
        let Some(options) = fields.next() else {
            continue;
        };
        if mount == "/proc" || mount == "/proc/sys" {
            read_only = Some(options.split(',').any(|option| option == "ro"));
            if mount == "/proc/sys" {
                break;
            }
        }
    }
    read_only.map_or(Observation::Absent, Observation::Present)
}
/// Reads fixed public paths only. No write, command, access, socket or CRI probe.
/// Limits bound allocation/counts, not filesystem or kernel latency.
pub fn collect_constrained(limits: ProbeLimits) -> Result<ConstrainedFacts, PlatformError> {
    if !cfg!(target_os = "linux") {
        return Err(PlatformError::UnsupportedHost);
    }
    validate_limits(limits)?;
    Ok(ConstrainedFacts {
        sysctls: SYSCTL_PATHS
            .map(|path| bounded_text(Path::new(path), limits.bytes_per_file.min(4096))),
        proc_sys_read_only: proc_sys_read_only(limits.bytes_per_file),
        ip_tables_names: exists(Path::new("/proc/net/ip_tables_names")),
        default_cni_plugins: CNI_PLUGINS.map(|name| exists(&Path::new("/opt/cni/bin").join(name))),
        cni_config_names: directory_names(Path::new("/etc/cni/net.d"), limits.directory_entries),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_observations_are_bounded_and_preserve_unknown_names() {
        let root = std::env::temp_dir().join(format!("diorama-cni-read-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        assert_eq!(
            directory_names(&root.join("absent"), 2),
            Observation::Absent
        );
        fs::write(root.join("20-second.conf"), "untouched").unwrap();
        fs::write(root.join("00-first.conflist"), "untouched").unwrap();
        assert_eq!(
            directory_names(&root, 1),
            Observation::Unknown(ProbeFailure::TooLarge)
        );
        assert_eq!(
            directory_names(&root, 2),
            Observation::Present(vec!["00-first.conflist".into(), "20-second.conf".into()])
        );
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStringExt;
            fs::write(
                root.join(std::ffi::OsString::from_vec(vec![255])),
                "untouched",
            )
            .unwrap();
            assert_eq!(
                directory_names(&root, 3),
                Observation::Unknown(ProbeFailure::Malformed)
            );
        }
        assert_eq!(
            fs::read_to_string(root.join("20-second.conf")).unwrap(),
            "untouched"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
