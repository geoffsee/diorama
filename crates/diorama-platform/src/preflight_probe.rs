//! Supplemental observations. No module loading, host preparation or process discovery.
#[cfg(any(target_os = "linux", test))]
use crate::ProbeFailure;
use crate::preflight::PortAvailability;
use crate::{Observation, PlatformError, ProbeLimits};
#[cfg(any(target_os = "linux", test))]
use std::ffi::OsString;
#[cfg(any(target_os = "linux", test))]
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupplementalFacts {
    pub xt_comment_on_disk: Observation<bool>,
    pub alpine_rc_service: Observation<bool>,
}

/// Read exact baseline filesystem candidates, without changing the host.
pub fn collect_supplemental(limits: ProbeLimits) -> Result<SupplementalFacts, PlatformError> {
    validate_limits(limits)?;
    #[cfg(target_os = "linux")]
    {
        Ok(collect(&RealFs, limits))
    }
    #[cfg(not(target_os = "linux"))]
    Err(PlatformError::UnsupportedHost)
}

/// Briefly bind/listen on wildcard TCP ports, then close each owned descriptor.
/// This is an observation, never a reservation or evidence of another process's identity.
pub fn probe_ports(pprof: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError> {
    #[cfg(target_os = "linux")]
    {
        Ok(ports_with(pprof, |port| {
            if bind_port(port).is_ok() {
                PortAvailability::Available
            } else {
                PortAvailability::BindFailed
            }
        }))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pprof;
        Err(PlatformError::UnsupportedHost)
    }
}

fn validate_limits(limits: ProbeLimits) -> Result<(), PlatformError> {
    if limits.bytes_per_file == 0
        || limits.bytes_per_file > 4 * 1024 * 1024
        || limits.directory_entries == 0
        || limits.directory_entries > 16384
        || limits.requested_paths == 0
        || limits.requested_paths > 256
    {
        return Err(PlatformError::InvalidLimits);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn ports_with(
    pprof: bool,
    mut probe: impl FnMut(u16) -> PortAvailability,
) -> [Observation<PortAvailability>; 4] {
    let mut result = [Observation::Unknown(ProbeFailure::UnsupportedPlatform); 4];
    for (slot, port) in [2379, 6443, 10443, 6060].into_iter().enumerate() {
        if slot != 3 || pprof {
            result[slot] = Observation::Present(probe(port));
        }
    }
    result
}

#[cfg(any(target_os = "linux", test))]
trait Filesystem {
    fn text(&self, path: &Path, limit: usize) -> Observation<String>;
    fn exists(&self, path: &Path) -> Observation<bool>;
    /// Each entry across every visited directory charges the same remaining budget.
    fn entries(&self, path: &Path, remaining: &mut usize) -> Result<Vec<OsString>, ProbeFailure>;
}

#[cfg(any(target_os = "linux", test))]
fn collect(fs: &impl Filesystem, limits: ProbeLimits) -> SupplementalFacts {
    SupplementalFacts {
        xt_comment_on_disk: module_on_disk(fs, limits),
        alpine_rc_service: fs.exists(Path::new("/sbin/rc-service")),
    }
}

#[cfg(any(target_os = "linux", test))]
fn release(text: &str) -> Result<&str, ProbeFailure> {
    let value = text
        .split_whitespace()
        .nth(2)
        .ok_or(ProbeFailure::Malformed)?;
    if value.len() > 255
        || matches!(value, "." | "..")
        || value.bytes().any(|byte| matches!(byte, b'/' | b'\\' | 0))
    {
        return Err(ProbeFailure::Malformed);
    }
    Ok(value)
}

#[cfg(any(target_os = "linux", test))]
fn module_on_disk(fs: &impl Filesystem, limits: ProbeLimits) -> Observation<bool> {
    let text = match fs.text(Path::new("/proc/version"), limits.bytes_per_file) {
        Observation::Present(text) => text,
        Observation::Absent => return Observation::Absent,
        Observation::Unknown(error) => return Observation::Unknown(error),
    };
    let version = match release(&text) {
        Ok(value) => value,
        Err(error) => return Observation::Unknown(error),
    };
    let base = Path::new("/lib/modules").join(version);
    let mut unknown = None;
    for suffix in ["", ".xz", ".zst", ".gz"] {
        match fs.exists(&base.join(format!("kernel/net/netfilter/xt_comment.ko{suffix}"))) {
            Observation::Present(true) => return Observation::Present(true),
            Observation::Unknown(error) => {
                unknown.get_or_insert(error);
            },
            Observation::Absent | Observation::Present(false) => {},
        }
    }
    let mut remaining = limits.directory_entries;
    let directories = match fs.entries(&base, &mut remaining) {
        Ok(value) => value,
        Err(error) => return Observation::Unknown(error),
    };
    for directory in directories {
        match fs.entries(&base.join(directory), &mut remaining) {
            Ok(entries) => {
                // Go filepath.Glob accepts names (including broken symlinks/directories),
                // not just regular files. Do not narrow that existence heuristic.
                if entries
                    .iter()
                    .any(|name| name.as_encoded_bytes().starts_with(b"xt_comment.ko"))
                {
                    return Observation::Present(true);
                }
            },
            Err(error) => {
                unknown.get_or_insert(error);
            },
        }
    }
    unknown.map_or(Observation::Present(false), Observation::Unknown)
}

#[cfg(target_os = "linux")]
struct RealFs;
#[cfg(target_os = "linux")]
fn io_failure(error: &std::io::Error) -> ProbeFailure {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => ProbeFailure::PermissionDenied,
        _ => ProbeFailure::Io,
    }
}
#[cfg(target_os = "linux")]
impl Filesystem for RealFs {
    fn text(&self, path: &Path, limit: usize) -> Observation<String> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY)
                    .bits()
                    .cast_signed(),
            )
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Observation::Absent;
            },
            Err(error) => return Observation::Unknown(io_failure(&error)),
        };
        match file.metadata() {
            Ok(metadata) if metadata.is_file() => {},
            Ok(_) => return Observation::Unknown(ProbeFailure::NotRegular),
            Err(error) => return Observation::Unknown(io_failure(&error)),
        }
        let mut bytes = Vec::new();
        if let Err(error) = file.take((limit + 1) as u64).read_to_end(&mut bytes) {
            return Observation::Unknown(io_failure(&error));
        }
        if bytes.len() > limit {
            return Observation::Unknown(ProbeFailure::TooLarge);
        }
        match String::from_utf8(bytes) {
            Ok(value) => Observation::Present(value),
            Err(_) => Observation::Unknown(ProbeFailure::Malformed),
        }
    }
    fn exists(&self, path: &Path) -> Observation<bool> {
        match std::fs::metadata(path) {
            Ok(_) => Observation::Present(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Observation::Absent,
            Err(error) => Observation::Unknown(io_failure(&error)),
        }
    }
    fn entries(&self, path: &Path, remaining: &mut usize) -> Result<Vec<OsString>, ProbeFailure> {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                return Ok(Vec::new());
            },
            Err(error) => return Err(io_failure(&error)),
        };
        let mut names = Vec::new();
        for entry in entries {
            *remaining = remaining.checked_sub(1).ok_or(ProbeFailure::TooLarge)?;
            names.push(entry.map_err(|error| io_failure(&error))?.file_name());
        }
        Ok(names)
    }
}

#[cfg(target_os = "linux")]
fn ipv6_unavailable(error: rustix::io::Errno) -> bool {
    use rustix::io::Errno;
    matches!(
        error,
        Errno::AFNOSUPPORT
            | Errno::PROTONOSUPPORT
            | Errno::NOPROTOOPT
            | Errno::OPNOTSUPP
            | Errno::ADDRNOTAVAIL
    )
}

#[cfg(target_os = "linux")]
fn bind_port(port: u16) -> Result<(), rustix::io::Errno> {
    use rustix::net::{self, AddressFamily, SocketFlags, SocketType};
    use std::net::{Ipv6Addr, SocketAddrV6};
    let ipv6 = || {
        let fd = net::socket_with(
            AddressFamily::INET6,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )?;
        net::sockopt::set_ipv6_v6only(&fd, false)?;
        // Never accept an IPv6-only success that could miss an IPv4 conflict.
        if net::sockopt::ipv6_v6only(&fd)? {
            return Err(rustix::io::Errno::OPNOTSUPP);
        }
        net::sockopt::set_socket_reuseaddr(&fd, true)?;
        net::bind(&fd, &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))?;
        net::listen(&fd, 128)
    };
    bind_with_ipv6_result(port, ipv6())
}

#[cfg(target_os = "linux")]
fn bind_with_ipv6_result(
    port: u16,
    ipv6: Result<(), rustix::io::Errno>,
) -> Result<(), rustix::io::Errno> {
    use rustix::net::{self, AddressFamily, SocketFlags, SocketType};
    use std::net::{Ipv4Addr, SocketAddrV4};
    match ipv6 {
        Ok(()) => Ok(()),
        Err(error) if ipv6_unavailable(error) => {
            let fd = net::socket_with(
                AddressFamily::INET,
                SocketType::STREAM,
                SocketFlags::CLOEXEC,
                None,
            )?;
            net::sockopt::set_socket_reuseaddr(&fd, true)?;
            net::bind(&fd, &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?;
            net::listen(&fd, 128)
        },
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    struct FakeFs {
        version: Observation<String>,
        paths: BTreeMap<PathBuf, Observation<bool>>,
        directories: BTreeMap<PathBuf, Result<Vec<OsString>, ProbeFailure>>,
    }
    impl Default for FakeFs {
        fn default() -> Self {
            Self {
                version: Observation::Present("Linux version fixture".into()),
                paths: BTreeMap::new(),
                directories: BTreeMap::new(),
            }
        }
    }
    impl Filesystem for FakeFs {
        fn text(&self, path: &Path, limit: usize) -> Observation<String> {
            assert_eq!(path, Path::new("/proc/version"));
            match &self.version {
                Observation::Present(text) if text.len() > limit => {
                    Observation::Unknown(ProbeFailure::TooLarge)
                },
                value => value.clone(),
            }
        }
        fn exists(&self, path: &Path) -> Observation<bool> {
            self.paths.get(path).copied().unwrap_or(Observation::Absent)
        }
        fn entries(
            &self,
            path: &Path,
            remaining: &mut usize,
        ) -> Result<Vec<OsString>, ProbeFailure> {
            let names = self
                .directories
                .get(path)
                .cloned()
                .unwrap_or(Ok(Vec::new()))?;
            *remaining = remaining
                .checked_sub(names.len())
                .ok_or(ProbeFailure::TooLarge)?;
            Ok(names)
        }
    }

    #[test]
    fn exact_candidates_and_one_level_glob_match_baseline_existence() {
        for suffix in ["", ".xz", ".zst", ".gz"] {
            let mut fs = FakeFs::default();
            fs.paths.insert(
                format!("/lib/modules/fixture/kernel/net/netfilter/xt_comment.ko{suffix}").into(),
                Observation::Present(true),
            );
            assert_eq!(
                collect(&fs, ProbeLimits::default()).xt_comment_on_disk,
                Observation::Present(true)
            );
        }
        let mut fs = FakeFs::default();
        fs.directories
            .insert("/lib/modules/fixture".into(), Ok(vec!["extra".into()]));
        fs.directories.insert(
            "/lib/modules/fixture/extra".into(),
            Ok(vec!["xt_comment.ko.anything".into()]),
        );
        assert_eq!(
            collect(&fs, ProbeLimits::default()).xt_comment_on_disk,
            Observation::Present(true)
        );
        fs.directories.insert(
            "/lib/modules/fixture/extra".into(),
            Ok(vec!["nested".into()]),
        );
        fs.directories.insert(
            "/lib/modules/fixture/extra/nested".into(),
            Ok(vec!["xt_comment.ko".into()]),
        );
        assert_eq!(
            collect(&fs, ProbeLimits::default()).xt_comment_on_disk,
            Observation::Present(false)
        );
    }

    #[test]
    fn unsafe_release_limits_and_errors_are_unknown_not_absent() {
        for value in [
            "",
            "Linux",
            "Linux version ..",
            "Linux version a/b",
            "Linux version a\\b",
            "Linux version a\0b",
        ] {
            let fs = FakeFs {
                version: Observation::Present(value.into()),
                ..FakeFs::default()
            };
            assert_eq!(
                collect(&fs, ProbeLimits::default()).xt_comment_on_disk,
                Observation::Unknown(ProbeFailure::Malformed)
            );
        }
        for failure in [
            ProbeFailure::PermissionDenied,
            ProbeFailure::Io,
            ProbeFailure::Malformed,
            ProbeFailure::TooLarge,
        ] {
            let fs = FakeFs {
                version: Observation::Unknown(failure),
                ..FakeFs::default()
            };
            assert_eq!(
                collect(&fs, ProbeLimits::default()).xt_comment_on_disk,
                Observation::Unknown(failure)
            );
        }
        let mut fs = FakeFs::default();
        fs.directories.insert(
            "/lib/modules/fixture".into(),
            Ok(vec!["a".into(), "b".into()]),
        );
        fs.directories.insert(
            "/lib/modules/fixture/a".into(),
            Ok(vec!["irrelevant".into()]),
        );
        let limits = ProbeLimits {
            directory_entries: 2,
            ..ProbeLimits::default()
        };
        assert_eq!(
            collect(&fs, limits).xt_comment_on_disk,
            Observation::Unknown(ProbeFailure::TooLarge)
        );
        fs.paths.insert(
            "/sbin/rc-service".into(),
            Observation::Unknown(ProbeFailure::PermissionDenied),
        );
        assert_eq!(
            collect(&fs, limits).alpine_rc_service,
            Observation::Unknown(ProbeFailure::PermissionDenied)
        );
        assert_eq!(
            collect(
                &fs,
                ProbeLimits {
                    bytes_per_file: 2,
                    ..limits
                }
            )
            .xt_comment_on_disk,
            Observation::Unknown(ProbeFailure::TooLarge)
        );
    }

    #[test]
    fn definitive_presence_survives_other_candidate_errors_and_rc_is_exact() {
        let mut fs = FakeFs::default();
        fs.paths.insert(
            "/lib/modules/fixture/kernel/net/netfilter/xt_comment.ko".into(),
            Observation::Unknown(ProbeFailure::PermissionDenied),
        );
        assert_eq!(
            collect(&fs, ProbeLimits::default()).xt_comment_on_disk,
            Observation::Unknown(ProbeFailure::PermissionDenied)
        );
        fs.paths.insert(
            "/lib/modules/fixture/kernel/net/netfilter/xt_comment.ko.xz".into(),
            Observation::Present(true),
        );
        fs.paths
            .insert("/usr/bin/rc-service".into(), Observation::Present(true));
        let facts = collect(&fs, ProbeLimits::default());
        assert_eq!(facts.xt_comment_on_disk, Observation::Present(true));
        assert_eq!(facts.alpine_rc_service, Observation::Absent);
        fs.paths
            .insert("/sbin/rc-service".into(), Observation::Present(true));
        assert_eq!(
            collect(&fs, ProbeLimits::default()).alpine_rc_service,
            Observation::Present(true)
        );
    }

    #[test]
    fn port_phase_is_explicit_and_does_not_probe_unused_pprof() {
        let mut visited = Vec::new();
        let values = ports_with(false, |port| {
            visited.push(port);
            PortAvailability::Available
        });
        assert_eq!(visited, [2379, 6443, 10443]);
        assert!(matches!(values[3], Observation::Unknown(_)));
        let mut visited = Vec::new();
        let values = ports_with(true, |port| {
            visited.push(port);
            PortAvailability::BindFailed
        });
        assert_eq!(visited, [2379, 6443, 10443, 6060]);
        assert_eq!(
            values,
            [Observation::Present(PortAvailability::BindFailed); 4]
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod disposable_filesystem {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
    use std::os::unix::{ffi::OsStringExt, fs::PermissionsExt};
    use std::path::PathBuf;
    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    impl Filesystem for Root {
        fn text(&self, path: &Path, limit: usize) -> Observation<String> {
            RealFs.text(&self.0.join(path.strip_prefix("/").unwrap()), limit)
        }
        fn exists(&self, path: &Path) -> Observation<bool> {
            RealFs.exists(&self.0.join(path.strip_prefix("/").unwrap()))
        }
        fn entries(
            &self,
            path: &Path,
            remaining: &mut usize,
        ) -> Result<Vec<OsString>, ProbeFailure> {
            RealFs.entries(&self.0.join(path.strip_prefix("/").unwrap()), remaining)
        }
    }
    fn write(root: &Root, path: &str, bytes: &[u8]) {
        let path = root.0.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    fn check(root: &Root, limits: ProbeLimits, expected: Observation<bool>, name: &str) {
        assert_eq!(collect(root, limits).xt_comment_on_disk, expected, "{name}");
        println!("diorama_PREFLIGHT_FILES {name} pass");
    }
    #[test]
    #[ignore = "actual filesystem fixtures only inside owned disposable Linux container"]
    #[allow(clippy::too_many_lines)] // One owned fixture root and ordered cleanup throughout.
    fn disposable_real_filesystem_limits_errors_and_baseline_candidates() {
        assert_eq!(
            std::env::var("diorama_PREFLIGHT_DISPOSABLE").as_deref(),
            Ok("1")
        );
        assert!(Path::new("/.dockerenv").exists());
        assert_eq!(rustix::process::geteuid().as_raw(), 65532);
        let root =
            Root(std::env::temp_dir().join(format!("diorama-supplemental-{}", std::process::id())));
        std::fs::create_dir(&root.0).unwrap();
        let limits = ProbeLimits::default();
        check(&root, limits, Observation::Absent, "missing_version");
        write(&root, "proc/version", b"Linux version fixture");
        check(&root, limits, Observation::Present(false), "no_candidates");
        for suffix in ["", ".xz", ".zst", ".gz"] {
            let name = format!("lib/modules/fixture/kernel/net/netfilter/xt_comment.ko{suffix}");
            write(&root, &name, b"sentinel");
            check(
                &root,
                limits,
                Observation::Present(true),
                &format!("exact{suffix}"),
            );
            assert_eq!(std::fs::read(root.0.join(&name)).unwrap(), b"sentinel");
            std::fs::remove_file(root.0.join(name)).unwrap();
        }
        let extra = root.0.join("lib/modules/fixture/extra");
        std::fs::create_dir(&extra).unwrap();
        let link = extra.join("xt_comment.ko.custom");
        std::os::unix::fs::symlink("absent", &link).unwrap();
        check(
            &root,
            limits,
            Observation::Present(true),
            "glob_broken_symlink",
        );
        std::fs::remove_file(link).unwrap();
        let binary_name = extra.join(OsString::from_vec(b"xt_comment.ko\xff".to_vec()));
        std::fs::write(&binary_name, b"unchanged").unwrap();
        check(
            &root,
            limits,
            Observation::Present(true),
            "glob_non_utf8_name",
        );
        std::fs::remove_file(binary_name).unwrap();
        write(
            &root,
            "lib/modules/fixture/extra/deeper/xt_comment.ko",
            b"too_deep",
        );
        check(&root, limits, Observation::Present(false), "not_recursive");
        check(
            &root,
            ProbeLimits {
                directory_entries: 1,
                ..limits
            },
            Observation::Unknown(ProbeFailure::TooLarge),
            "entry_limit",
        );
        check(
            &root,
            ProbeLimits {
                bytes_per_file: 2,
                ..limits
            },
            Observation::Unknown(ProbeFailure::TooLarge),
            "byte_limit",
        );
        write(&root, "proc/version", b"Linux version \xff");
        check(
            &root,
            limits,
            Observation::Unknown(ProbeFailure::Malformed),
            "non_utf8_version",
        );
        write(&root, "proc/version", b"Linux version ../escape");
        check(
            &root,
            limits,
            Observation::Unknown(ProbeFailure::Malformed),
            "unsafe_release",
        );
        write(&root, "proc/version", b"Linux version fixture");
        let version = root.0.join("proc/version");
        std::fs::set_permissions(&version, std::fs::Permissions::from_mode(0o0)).unwrap();
        check(
            &root,
            limits,
            Observation::Unknown(ProbeFailure::PermissionDenied),
            "permission_denied",
        );
        std::fs::set_permissions(&version, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(&version).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &version,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        check(
            &root,
            limits,
            Observation::Unknown(ProbeFailure::NotRegular),
            "fifo_nonblocking",
        );
        write(&root, "sbin/rc-service", b"nonexecutable");
        assert_eq!(
            collect(&root, limits).alpine_rc_service,
            Observation::Present(true)
        );
        println!("diorama_PREFLIGHT_FILES rc_service_exact pass");
        // Inject only unsupported IPv6 creation; fallback really binds IPv4.
        let unsupported = Err(rustix::io::Errno::AFNOSUPPORT);
        assert_eq!(bind_with_ipv6_result(2379, unsupported), Ok(()));
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2379)).unwrap();
        assert_eq!(
            bind_with_ipv6_result(2379, unsupported),
            Err(rustix::io::Errno::ADDRINUSE)
        );
        drop(listener);
        assert_eq!(bind_with_ipv6_result(2379, unsupported), Ok(()));
        let rebound = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 2379)).unwrap();
        drop(rebound);
        println!("diorama_PREFLIGHT_FILES injected_ipv6_unsupported_real_ipv4 pass");
    }
    #[test]
    fn only_unavailable_ipv6_allows_ipv4_fallback() {
        use rustix::io::Errno;
        for error in [
            Errno::AFNOSUPPORT,
            Errno::PROTONOSUPPORT,
            Errno::NOPROTOOPT,
            Errno::OPNOTSUPP,
            Errno::ADDRNOTAVAIL,
        ] {
            assert!(ipv6_unavailable(error));
        }
        for error in [
            Errno::ADDRINUSE,
            Errno::ACCESS,
            Errno::PERM,
            Errno::MFILE,
            Errno::INVAL,
        ] {
            assert!(!ipv6_unavailable(error));
        }
    }
}
