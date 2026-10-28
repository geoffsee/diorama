use crate::{
    DiscoveryRequest, ExecutableAbi, HostEvidence, KernelIdentity, Observation, PathFacts,
    PathKind, PlatformError, Privileges, ProbeFailure, ProbeLimits, RequestedPath,
};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::Path;

pub(crate) const BIN_DIRS: [&str; 6] = [
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];
const LANDMARKS: [&str; 18] = [
    "/run/systemd/private",
    "/etc/systemd/system",
    "/etc/systemd",
    "/etc/init",
    "/sbin/initctl",
    "/sbin/openrc",
    "/etc/s6",
    "/etc/s6-overlay",
    "/etc/runit",
    "/var/service",
    "/etc/init.d",
    "/.dockerenv",
    "/run/.containerenv",
    "/sys/fs/cgroup",
    "/sys/fs/cgroup/cpuset",
    "/sys/fs/cgroup/cpu",
    "/sys/fs/cgroup/blkio",
    "/sys/fs/cgroup/memory",
];
const FILES: [&str; 6] = [
    "/proc/1/cgroup",
    "/proc/device-tree/model",
    "/sys/fs/cgroup/cgroup.controllers",
    "/proc/modules",
    "/proc/self/mountinfo",
    "/proc/net/ip_tables_matches",
];
pub(crate) fn glibc_linker(architecture: &str) -> Option<&'static str> {
    match architecture {
        "x86_64" | "amd64" => Some("/lib64/ld-linux-x86-64.so.2"),
        "aarch64" | "arm64" => Some("/lib/ld-linux-aarch64.so.1"),
        "arm" | "armv7" | "armv7l" => Some("/lib/ld-linux-armhf.so.3"),
        "riscv64" => Some("/lib/ld-linux-riscv64-lp64d.so.1"),
        _ => None,
    }
}
pub(crate) fn error<T>(error: &io::Error) -> Observation<T> {
    match error.kind() {
        io::ErrorKind::NotFound => Observation::Absent,
        io::ErrorKind::PermissionDenied => Observation::Unknown(ProbeFailure::PermissionDenied),
        _ => Observation::Unknown(ProbeFailure::Io),
    }
}
pub(crate) fn exists(path: &Path) -> Observation<bool> {
    match fs::metadata(path) {
        Ok(_) => Observation::Present(true),
        Err(failure) => error(&failure),
    }
}
pub(crate) fn bounded_text(path: &Path, limit: usize) -> Observation<String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY)
                .bits()
                .cast_signed(),
        );
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(failure) => return error(&failure),
    };
    match file.metadata() {
        Ok(metadata) if metadata.is_file() => {},
        Ok(_) => return Observation::Unknown(ProbeFailure::NotRegular),
        Err(failure) => return error(&failure),
    }
    let mut bytes = Vec::new();
    if let Err(failure) = file
        .take(u64::try_from(limit).unwrap_or(u64::MAX - 1) + 1)
        .read_to_end(&mut bytes)
    {
        return error(&failure);
    }
    if bytes.len() > limit {
        return Observation::Unknown(ProbeFailure::TooLarge);
    }
    match String::from_utf8(bytes) {
        Ok(text) => Observation::Present(text),
        Err(_) => Observation::Unknown(ProbeFailure::Malformed),
    }
}
fn linkers(limit: usize) -> Observation<Vec<String>> {
    let mut found = Vec::new();
    let mut count = 0;
    for directory in ["/lib", "/usr/lib"] {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(failure) if failure.kind() == io::ErrorKind::NotFound => continue,
            Err(failure) => return error(&failure),
        };
        for entry in entries {
            count += 1;
            if count > limit {
                return Observation::Unknown(ProbeFailure::TooLarge);
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(failure) => return error(&failure),
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with("ld-musl-") && name.ends_with(".so.1") {
                found.push(entry.path().to_string_lossy().into_owned());
            }
        }
    }
    found.sort();
    found.dedup();
    Observation::Present(found)
}
fn path_facts(path: &Path) -> Observation<PathFacts> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(failure) => return error(&failure),
    };
    let kind = if metadata.is_symlink() {
        PathKind::Symlink
    } else if metadata.is_file() {
        PathKind::File
    } else if metadata.is_dir() {
        PathKind::Directory
    } else {
        PathKind::Other
    };
    let symlink_target = if metadata.is_symlink() {
        match fs::read_link(path) {
            Ok(target) => Some(target),
            Err(failure) => return error(&failure),
        }
    } else {
        None
    };
    #[cfg(unix)]
    let unix_mode = {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.mode())
    };
    #[cfg(not(unix))]
    let unix_mode = None;
    Observation::Present(PathFacts {
        kind,
        unix_mode,
        symlink_target,
    })
}
fn executable() -> ExecutableAbi {
    let environment = if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "gnu") {
        "gnu"
    } else {
        "other"
    };
    ExecutableAbi {
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        environment: environment.into(),
    }
}
pub(crate) fn validate_limits(limits: ProbeLimits) -> Result<(), PlatformError> {
    if limits.bytes_per_file == 0
        || limits.bytes_per_file > 4 * 1024 * 1024
        || limits.directory_entries == 0
        || limits.directory_entries > 16384
        || limits.requested_paths > 256
    {
        return Err(PlatformError::InvalidLimits);
    }
    Ok(())
}
/// Observe the current namespace without preparation, command execution or write probes.
/// Relative paths resolve against the caller's current directory, retaining their spelling.
/// Limits bound bytes/counts, not latency of arbitrary kernel/filesystem operations.
pub fn discover(request: &DiscoveryRequest) -> Result<HostEvidence, PlatformError> {
    if !cfg!(target_os = "linux") {
        return Err(PlatformError::UnsupportedHost);
    }
    let limits = request.limits;
    validate_limits(limits)?;
    if request.paths.len() > limits.requested_paths {
        return Err(PlatformError::TooManyPaths);
    }
    if request
        .paths
        .iter()
        .any(|path| path.as_os_str().len() > 4096)
    {
        return Err(PlatformError::PathTooLong);
    }
    let (kernel, privileges, hostname) = identity();
    let executable = executable();
    let mut landmarks = BTreeMap::new();
    for path in LANDMARKS.into_iter().chain([
        "/sys/fs/cgroup/pids",
        "/etc/alpine-release",
        "/var/run/docker.sock",
        "/usr/bin/docker",
        "/usr/local/bin/docker",
    ]) {
        landmarks.insert(path.into(), exists(Path::new(path)));
    }
    if let Some(path) = glibc_linker(&executable.architecture) {
        landmarks.insert(path.into(), exists(Path::new(path)));
    }
    for directory in BIN_DIRS {
        for name in [
            "systemctl",
            "initctl",
            "openrc",
            "s6-svc",
            "runit",
            "nft",
            "iptables",
            "modprobe",
        ] {
            let path = format!("{directory}/{name}");
            landmarks.insert(path.clone(), exists(Path::new(&path)));
        }
    }
    let mut files: BTreeMap<String, Observation<String>> = FILES
        .into_iter()
        .map(|path| {
            (
                path.into(),
                bounded_text(Path::new(path), limits.bytes_per_file),
            )
        })
        .collect();
    // Index files are evidence for the running kernel, never the executable target.
    if let Observation::Present(identity) = &kernel
        && !identity.release.is_empty()
        && !identity.release.contains('/')
        && !identity.release.contains('\\')
        && identity.release != "."
        && identity.release != ".."
    {
        for name in ["modules.dep", "modules.builtin"] {
            let path = format!("/lib/modules/{}/{name}", identity.release);
            files.insert(
                path.clone(),
                bounded_text(Path::new(&path), limits.bytes_per_file),
            );
        }
    }
    Ok(HostEvidence {
        executable,
        kernel,
        privileges,
        hostname,
        container_environment_set: std::env::var_os("container")
            .is_some_and(|value| !value.is_empty()),
        landmarks,
        musl_linkers: linkers(limits.directory_entries),
        files,
        requested_paths: request
            .paths
            .iter()
            .map(|path| RequestedPath {
                path: path.clone(),
                facts: path_facts(path),
            })
            .collect(),
    })
}
type Identity = (
    Observation<KernelIdentity>,
    Observation<Privileges>,
    Observation<String>,
);
#[cfg(target_os = "linux")]
fn identity() -> Identity {
    let uname = rustix::system::uname();
    let string = |value: &std::ffi::CStr| {
        value
            .to_str()
            .map(str::to_owned)
            .map_err(|_| ProbeFailure::Malformed)
    };
    let kernel = match (
        string(uname.sysname()),
        string(uname.release()),
        string(uname.machine()),
    ) {
        (Ok(os), Ok(release), Ok(machine)) => Observation::Present(KernelIdentity {
            os,
            release,
            machine,
        }),
        _ => Observation::Unknown(ProbeFailure::Malformed),
    };
    let hostname = match string(uname.nodename()) {
        Ok(value) => Observation::Present(value),
        Err(error) => Observation::Unknown(error),
    };
    (
        kernel,
        Observation::Present(Privileges {
            real_uid: rustix::process::getuid().as_raw(),
            effective_uid: rustix::process::geteuid().as_raw(),
        }),
        hostname,
    )
}
#[cfg(not(target_os = "linux"))]
fn identity() -> Identity {
    (
        Observation::Unknown(ProbeFailure::UnsupportedPlatform),
        Observation::Unknown(ProbeFailure::UnsupportedPlatform),
        Observation::Unknown(ProbeFailure::UnsupportedPlatform),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_reader_distinguishes_missing_directory_and_oversize() {
        let path =
            std::env::temp_dir().join(format!("diorama-platform-read-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        let file = path.join("data");
        fs::write(&file, "12345").unwrap();
        assert_eq!(
            bounded_text(&file, 4),
            Observation::Unknown(ProbeFailure::TooLarge)
        );
        assert_eq!(bounded_text(&file, 5), Observation::Present("12345".into()));
        assert_eq!(bounded_text(&path.join("absent"), 5), Observation::Absent);
        assert_eq!(
            bounded_text(&path, 5),
            Observation::Unknown(ProbeFailure::NotRegular)
        );
        fs::write(&file, [255]).unwrap();
        assert_eq!(
            bounded_text(&file, 5),
            Observation::Unknown(ProbeFailure::Malformed)
        );
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let fifo = path.join("pipe");
            rustix::fs::mkfifoat(
                rustix::fs::CWD,
                &fifo,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .unwrap();
            assert_eq!(
                bounded_text(&fifo, 5),
                Observation::Unknown(ProbeFailure::NotRegular)
            );
            if rustix::process::geteuid().as_raw() != 0 {
                fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
                assert_eq!(
                    bounded_text(&file, 5),
                    Observation::Unknown(ProbeFailure::PermissionDenied)
                );
                fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        fs::remove_dir_all(path).unwrap();
    }
}
