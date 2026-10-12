use crate::{
    Architecture, AvailableModule, CgroupVersion, Cgroups, Environment, HostCapabilities,
    HostEvidence, InitSystem, Libc, MountFact, NodeTarget, Observation, PlatformError,
    ProbeFailure,
};
use std::collections::BTreeSet;

/// Validate a requested node artifact target, independently of this process/kernel.
/// D01 accepts all four architectures with both libc variants.
pub fn node_target(os: &str, arch: &str, libc: Libc) -> Result<NodeTarget, PlatformError> {
    if os != "linux" {
        return Err(PlatformError::UnsupportedTarget);
    }
    let architecture = match arch {
        "amd64" => Architecture::Amd64,
        "arm64" => Architecture::Arm64,
        "arm" => Architecture::ArmV7,
        "riscv64" => Architecture::Riscv64,
        _ => return Err(PlatformError::UnsupportedTarget),
    };
    Ok(NodeTarget { architecture, libc })
}
fn exists(e: &HostEvidence, path: &str) -> Observation<bool> {
    e.landmarks
        .get(path)
        .copied()
        .unwrap_or(Observation::Unknown(ProbeFailure::Malformed))
}
fn file<'a>(e: &'a HostEvidence, path: &str) -> Observation<&'a String> {
    e.files.get(path).map_or(
        Observation::Unknown(ProbeFailure::Malformed),
        Observation::as_ref,
    )
}
fn any(values: impl IntoIterator<Item = Observation<bool>>) -> Observation<bool> {
    let mut unknown = None;
    for value in values {
        match value {
            Observation::Present(true) => return Observation::Present(true),
            Observation::Unknown(error) => {
                unknown.get_or_insert(error);
            },
            Observation::Absent | Observation::Present(false) => {},
        }
    }
    unknown.map_or(Observation::Present(false), Observation::Unknown)
}
fn both(a: Observation<bool>, b: Observation<bool>) -> Observation<bool> {
    match (a, b) {
        (Observation::Absent | Observation::Present(false), _)
        | (_, Observation::Absent | Observation::Present(false)) => Observation::Present(false),
        (Observation::Unknown(e), _) | (_, Observation::Unknown(e)) => Observation::Unknown(e),
        _ => Observation::Present(true),
    }
}
fn not(value: Observation<bool>) -> Observation<bool> {
    match value {
        Observation::Present(value) => Observation::Present(!value),
        Observation::Absent => Observation::Present(true),
        Observation::Unknown(error) => Observation::Unknown(error),
    }
}
fn command(e: &HostEvidence, name: &str) -> Observation<bool> {
    any(crate::discover::BIN_DIRS
        .iter()
        .map(|directory| exists(e, &format!("{directory}/{name}"))))
}
fn init(e: &HostEvidence) -> Observation<InitSystem> {
    let candidates = [
        (
            InitSystem::Systemd,
            any([
                exists(e, "/run/systemd/private"),
                both(exists(e, "/etc/systemd/system"), command(e, "systemctl")),
            ]),
        ),
        (
            InitSystem::Upstart,
            both(
                both(exists(e, "/etc/init"), not(exists(e, "/etc/systemd"))),
                any([exists(e, "/sbin/initctl"), command(e, "initctl")]),
            ),
        ),
        (
            InitSystem::OpenRc,
            any([command(e, "openrc"), exists(e, "/sbin/openrc")]),
        ),
        (
            InitSystem::S6,
            any([
                exists(e, "/etc/s6"),
                command(e, "s6-svc"),
                exists(e, "/etc/s6-overlay"),
            ]),
        ),
        (
            InitSystem::Runit,
            any([
                command(e, "runit"),
                exists(e, "/etc/runit"),
                exists(e, "/var/service"),
            ]),
        ),
        (InitSystem::SysV, exists(e, "/etc/init.d")),
    ];
    for (system, fact) in candidates {
        match fact {
            Observation::Present(true) => return Observation::Present(system),
            Observation::Unknown(error) => return Observation::Unknown(error),
            _ => {},
        }
    }
    Observation::Present(InitSystem::Unknown)
}
fn contains(fact: Observation<&String>, matches: impl FnOnce(&str) -> bool) -> Observation<bool> {
    match fact {
        Observation::Present(value) => Observation::Present(matches(value)),
        Observation::Absent => Observation::Present(false),
        Observation::Unknown(error) => Observation::Unknown(error),
    }
}
fn installer_environment(e: &HostEvidence) -> Observation<Environment> {
    let container = any([
        exists(e, "/.dockerenv"),
        exists(e, "/run/.containerenv"),
        contains(file(e, "/proc/1/cgroup"), |s| s.contains("docker")),
    ]);
    match container {
        Observation::Present(true) => return Observation::Present(Environment::Container),
        Observation::Unknown(error) => return Observation::Unknown(error),
        _ => {},
    }
    match contains(file(e, "/proc/device-tree/model"), |s| {
        ["raspberry", "beagle", "odroid", "nano", "rock"]
            .iter()
            .any(|marker| s.to_lowercase().contains(marker))
    }) {
        Observation::Present(true) => return Observation::Present(Environment::Embedded),
        Observation::Unknown(error) => return Observation::Unknown(error),
        _ => {},
    }
    Observation::Present(
        if ["arm", "aarch64", "arm64"].contains(&e.executable.architecture.as_str()) {
            Environment::Arm
        } else {
            Environment::Standard
        },
    )
}
fn cgroups(e: &HostEvidence) -> Observation<Cgroups> {
    match file(e, "/sys/fs/cgroup/cgroup.controllers") {
        Observation::Present(value) => Observation::Present(Cgroups {
            version: CgroupVersion::V2,
            controllers: value
                .split_whitespace()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }),
        Observation::Unknown(error) => Observation::Unknown(error),
        Observation::Absent => {
            match exists(e, "/sys/fs/cgroup") {
                Observation::Present(true) => {},
                Observation::Unknown(error) => return Observation::Unknown(error),
                _ => return Observation::Absent,
            }
            let mut controllers = Vec::new();
            for (name, directory) in [
                ("cpuset", "cpuset"),
                ("cpu", "cpu"),
                ("io", "blkio"),
                ("memory", "memory"),
                ("pids", "pids"),
            ] {
                match exists(e, &format!("/sys/fs/cgroup/{directory}")) {
                    Observation::Present(true) => controllers.push(name.into()),
                    Observation::Unknown(error) => return Observation::Unknown(error),
                    _ => {},
                }
            }
            Observation::Present(Cgroups {
                version: CgroupVersion::V1,
                controllers,
            })
        },
    }
}
fn modules(e: &HostEvidence) -> Observation<Vec<String>> {
    match file(e, "/proc/modules") {
        Observation::Present(value) => {
            let mut names = BTreeSet::new();
            for line in value.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                if !(6..=7).contains(&fields.len())
                    || fields[1].parse::<u64>().is_err()
                    || (fields[2] != "-" && fields[2].parse::<i64>().is_err())
                    || (fields.len() == 7
                        && !(fields[6].starts_with('(')
                            && fields[6].ends_with(')')
                            && fields[6].len() > 2))
                {
                    return Observation::Unknown(ProbeFailure::Malformed);
                }
                names.insert(fields[0].to_owned());
            }
            Observation::Present(names.into_iter().collect())
        },
        Observation::Absent => Observation::Absent,
        Observation::Unknown(error) => Observation::Unknown(error),
    }
}
fn unescape(value: &str) -> Result<String, ProbeFailure> {
    let mut output = Vec::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            let escape = bytes
                .get(index + 1..index + 4)
                .ok_or(ProbeFailure::Malformed)?;
            output.push(match escape {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(ProbeFailure::Malformed),
            });
            index += 4;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(|_| ProbeFailure::Malformed)
}
/// Parse Linux mountinfo without inferring write permission or mount ownership.
pub fn parse_mountinfo(value: &str) -> Result<Vec<MountFact>, ProbeFailure> {
    let mut mounts = Vec::new();
    for line in value.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let separator = fields
            .iter()
            .position(|v| *v == "-")
            .ok_or(ProbeFailure::Malformed)?;
        if separator < 6
            || fields.len() != separator + 4
            || fields[0].parse::<u64>().is_err()
            || fields[1].parse::<u64>().is_err()
        {
            return Err(ProbeFailure::Malformed);
        }
        let device: Vec<_> = fields[2].split(':').collect();
        if device.len() != 2 || device.iter().any(|v| v.parse::<u64>().is_err()) {
            return Err(ProbeFailure::Malformed);
        }
        unescape(fields[3])?;
        unescape(fields[separator + 2])?;
        let mount_point = std::path::PathBuf::from(unescape(fields[4])?);
        if !mount_point.is_absolute() {
            return Err(ProbeFailure::Malformed);
        }
        mounts.push(MountFact {
            mount_point,
            filesystem: fields[separator + 1].into(),
            mount_read_only: fields[5].split(',').any(|v| v == "ro"),
            superblock_read_only: fields[separator + 3].split(',').any(|v| v == "ro"),
            propagation: fields[6..separator]
                .iter()
                .map(|v| (*v).to_owned())
                .collect(),
        });
    }
    Ok(mounts)
}
fn module_index<'a>(e: &'a HostEvidence, name: &str) -> Observation<&'a String> {
    match &e.kernel {
        Observation::Present(kernel) => file(e, &format!("/lib/modules/{}/{name}", kernel.release)),
        Observation::Absent => Observation::Absent,
        Observation::Unknown(error) => Observation::Unknown(*error),
    }
}
fn module_path(text: &str) -> Result<std::path::PathBuf, ProbeFailure> {
    if text.is_empty()
        || text.starts_with('/')
        || text.contains('\\')
        || text.chars().any(char::is_whitespace)
        || text
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || ![".ko", ".ko.xz", ".ko.zst", ".ko.gz"]
            .iter()
            .any(|suffix| text.ends_with(suffix))
    {
        return Err(ProbeFailure::Malformed);
    }
    Ok(text.into())
}
fn available_modules(e: &HostEvidence) -> Observation<Vec<AvailableModule>> {
    let text = match module_index(e, "modules.dep") {
        Observation::Present(text) => text,
        Observation::Absent => return Observation::Absent,
        Observation::Unknown(error) => return Observation::Unknown(error),
    };
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for line in text.lines() {
        let Some((name, dependencies)) = line.split_once(':') else {
            return Observation::Unknown(ProbeFailure::Malformed);
        };
        let Ok(path) = module_path(name) else {
            return Observation::Unknown(ProbeFailure::Malformed);
        };
        if !seen.insert(path.clone()) {
            return Observation::Unknown(ProbeFailure::Malformed);
        }
        let dependencies = match dependencies
            .split_whitespace()
            .map(module_path)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(paths) => paths,
            Err(error) => return Observation::Unknown(error),
        };
        result.push(AvailableModule { path, dependencies });
    }
    Observation::Present(result)
}
fn builtin_modules(e: &HostEvidence) -> Observation<Vec<std::path::PathBuf>> {
    match module_index(e, "modules.builtin") {
        Observation::Present(text) => {
            match text.lines().map(module_path).collect::<Result<Vec<_>, _>>() {
                Ok(paths) => Observation::Present(paths),
                Err(error) => Observation::Unknown(error),
            }
        },
        Observation::Absent => Observation::Absent,
        Observation::Unknown(error) => Observation::Unknown(error),
    }
}
pub fn classify(e: &HostEvidence) -> HostCapabilities {
    let mounts = match file(e, "/proc/self/mountinfo") {
        Observation::Present(value) => match parse_mountinfo(value) {
            Ok(value) => Observation::Present(value),
            Err(error) => Observation::Unknown(error),
        },
        Observation::Absent => Observation::Absent,
        Observation::Unknown(error) => Observation::Unknown(error),
    };
    HostCapabilities {
        init: init(e),
        installer_environment: installer_environment(e),
        runtime_container: any([
            exists(e, "/.dockerenv"),
            exists(e, "/run/.containerenv"),
            Observation::Present(e.container_environment_set),
        ]),
        host_libc_hint: match &e.musl_linkers {
            Observation::Present(values) => Observation::Present(if values.is_empty() {
                Libc::Glibc
            } else {
                Libc::Musl
            }),
            Observation::Absent => Observation::Absent,
            Observation::Unknown(error) => Observation::Unknown(*error),
        },
        cgroups: cgroups(e),
        loaded_modules: modules(e),
        available_modules: available_modules(e),
        builtin_modules: builtin_modules(e),
        mounts,
    }
}
