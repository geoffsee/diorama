#![allow(unused)]

use diorama_platform::*;
use std::collections::BTreeMap;

fn evidence() -> HostEvidence {
    let mut landmarks = BTreeMap::new();
    for path in [
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
        "/sys/fs/cgroup/pids",
    ] {
        landmarks.insert(path.into(), Observation::Absent);
    }
    for dir in [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ] {
        for name in ["systemctl", "initctl", "openrc", "s6-svc", "runit"] {
            landmarks.insert(format!("{dir}/{name}"), Observation::Absent);
        }
    }
    HostEvidence {
        executable: ExecutableAbi {
            os: "linux".into(),
            architecture: "aarch64".into(),
            environment: "gnu".into(),
        },
        kernel: Observation::Present(KernelIdentity {
            os: "Linux".into(),
            release: "fixture".into(),
            machine: "x86_64".into(),
        }),
        privileges: Observation::Present(Privileges {
            real_uid: 1000,
            effective_uid: 1000,
        }),
        hostname: Observation::Present("Raw-Host".into()),
        container_environment_set: false,
        landmarks,
        musl_linkers: Observation::Present(Vec::new()),
        files: [
            "/proc/1/cgroup",
            "/proc/device-tree/model",
            "/sys/fs/cgroup/cgroup.controllers",
            "/proc/modules",
            "/proc/self/mountinfo",
        ]
        .into_iter()
        .map(|path| (path.into(), Observation::Absent))
        .collect(),
        requested_paths: Vec::new(),
    }
}
fn init_name(value: &Observation<InitSystem>) -> &str {
    match value {
        Observation::Present(InitSystem::Systemd) => "systemd",
        Observation::Present(InitSystem::Upstart) => "upstart",
        Observation::Present(InitSystem::OpenRc) => "openrc",
        Observation::Present(InitSystem::S6) => "s6",
        Observation::Present(InitSystem::Runit) => "runit",
        Observation::Present(InitSystem::SysV) => "sysvinit",
        Observation::Present(InitSystem::Unknown) => "unknown",
        _ => "error",
    }
}
#[cfg(any())]
#[test]
fn observed_go_classifier_cases_match_independent_expectations() {
    for line in include_str!("../../../tools/parity/fixtures/platform-discovery/expected.tsv")
        .lines()
        .filter(|line| !line.starts_with("target\t"))
    {
        let row: Vec<_> = line.split('\t').collect();
        let mut fixture = evidence();
        let paths: &[&str] = match row[0] {
            "empty" => &[],
            "systemd_socket" => &["/run/systemd/private"],
            "systemd_units" | "command_directory" => &["/etc/systemd/system", "/usr/bin/systemctl"],
            "custom_path_only" => &["/etc/systemd/system", "/custom/bin/systemctl"],
            "upstart" => &["/etc/init", "/sbin/initctl"],
            "openrc" => &["/sbin/openrc"],
            "s6" => &["/etc/s6"],
            "runit" => &["/var/service"],
            "sysv" => &["/etc/init.d"],
            "precedence" => &[
                "/run/systemd/private",
                "/sbin/openrc",
                "/etc/s6",
                "/etc/init.d",
            ],
            "docker_marker" => &["/.dockerenv"],
            "podman_marker" => &["/run/.containerenv"],
            "docker_cgroup" => {
                fixture.files.insert(
                    "/proc/1/cgroup".into(),
                    Observation::Present("0::/docker/fixture".into()),
                );
                &[]
            },
            "embedded" => {
                fixture.files.insert(
                    "/proc/device-tree/model".into(),
                    Observation::Present("Raspberry Pi fixture".into()),
                );
                &[]
            },
            "musl" => {
                fixture.musl_linkers =
                    Observation::Present(vec!["/lib/ld-musl-aarch64.so.1".into()]);
                &[]
            },
            _ => panic!("unknown independent fixture"),
        };
        for path in paths {
            fixture
                .landmarks
                .insert((*path).into(), Observation::Present(true));
        }
        let classified = classify(&fixture);
        assert_eq!(init_name(&classified.init), row[1], "{}", row[0]);
        let environment = match classified.installer_environment {
            Observation::Present(Environment::Arm) => "arm",
            Observation::Present(Environment::Container) => "container",
            Observation::Present(Environment::Embedded) => "embedded",
            _ => "unexpected",
        };
        assert_eq!(environment, row[2]);
        assert_eq!(
            classified.host_libc_hint,
            Observation::Present(if row[3] == "musl" {
                Libc::Musl
            } else {
                Libc::Glibc
            })
        );
    }
}
#[test]
fn accepted_d01_targets_include_all_arch_libc_pairs_without_using_kernel_or_executable() {
    for (arch, architecture) in [
        ("amd64", Architecture::Amd64),
        ("arm64", Architecture::Arm64),
        ("arm", Architecture::ArmV7),
        ("riscv64", Architecture::Riscv64),
    ] {
        for libc in [Libc::Glibc, Libc::Musl] {
            assert_eq!(
                node_target("linux", arch, libc).unwrap(),
                NodeTarget { architecture, libc }
            );
        }
    }
    for (os, arch) in [
        ("windows", "amd64"),
        ("darwin", "arm64"),
        ("linux", "mips"),
        ("linux", "armv6"),
    ] {
        assert_eq!(
            node_target(os, arch, Libc::Glibc),
            Err(PlatformError::UnsupportedTarget)
        );
    }
}
#[test]
fn native_glibc_loader_takes_precedence_over_optional_musl_toolchains() {
    for (arch, glibc, musl) in [
        (
            "x86_64",
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/ld-musl-x86_64.so.1",
        ),
        (
            "aarch64",
            "/lib/ld-linux-aarch64.so.1",
            "/lib/ld-musl-aarch64.so.1",
        ),
        ("arm", "/lib/ld-linux-armhf.so.3", "/lib/ld-musl-armhf.so.1"),
        (
            "riscv64",
            "/lib/ld-linux-riscv64-lp64d.so.1",
            "/lib/ld-musl-riscv64.so.1",
        ),
    ] {
        for environment in ["gnu", "musl"] {
            let mut fixture = evidence();
            fixture.executable.architecture = arch.into();
            fixture.executable.environment = environment.into();
            fixture.musl_linkers = Observation::Present(vec![musl.into()]);
            fixture
                .landmarks
                .insert(glibc.into(), Observation::Present(true));
            assert_eq!(
                classify(&fixture).host_libc_hint,
                Observation::Present(Libc::Glibc),
                "{arch}/{environment}"
            );

            fixture.landmarks.insert(glibc.into(), Observation::Absent);
            assert_eq!(
                classify(&fixture).host_libc_hint,
                Observation::Present(Libc::Musl)
            );
        }
    }
}

#[test]
fn foreign_glibc_loader_does_not_override_native_musl() {
    let mut fixture = evidence();
    fixture.musl_linkers = Observation::Present(vec!["/lib/ld-musl-aarch64.so.1".into()]);
    fixture.landmarks.insert(
        "/lib64/ld-linux-x86-64.so.2".into(),
        Observation::Present(true),
    );
    assert_eq!(
        classify(&fixture).host_libc_hint,
        Observation::Present(Libc::Musl)
    );
}

#[test]
fn missing_or_unreadable_evidence_never_becomes_a_positive_default() {
    let mut fixture = evidence();
    fixture.landmarks.insert(
        "/run/systemd/private".into(),
        Observation::Unknown(ProbeFailure::PermissionDenied),
    );
    fixture
        .landmarks
        .insert("/sbin/openrc".into(), Observation::Present(true));
    assert_eq!(
        classify(&fixture).init,
        Observation::Unknown(ProbeFailure::PermissionDenied)
    );
    fixture.musl_linkers = Observation::Unknown(ProbeFailure::Io);
    assert_eq!(
        classify(&fixture).host_libc_hint,
        Observation::Unknown(ProbeFailure::Io)
    );
    fixture.files.insert(
        "/sys/fs/cgroup/cgroup.controllers".into(),
        Observation::Unknown(ProbeFailure::PermissionDenied),
    );
    fixture
        .landmarks
        .insert("/sys/fs/cgroup".into(), Observation::Present(true));
    assert_eq!(
        classify(&fixture).cgroups,
        Observation::Unknown(ProbeFailure::PermissionDenied)
    );
}
#[test]
fn runtime_container_and_installer_environment_keep_distinct_indicators() {
    let mut fixture = evidence();
    fixture.container_environment_set = true;
    let capabilities = classify(&fixture);
    assert_eq!(capabilities.runtime_container, Observation::Present(true));
    assert_eq!(
        capabilities.installer_environment,
        Observation::Present(Environment::Arm)
    );
    fixture.container_environment_set = false;
    fixture.files.insert(
        "/proc/1/cgroup".into(),
        Observation::Present("0::docker".into()),
    );
    let capabilities = classify(&fixture);
    assert_eq!(capabilities.runtime_container, Observation::Present(false));
    assert_eq!(
        capabilities.installer_environment,
        Observation::Present(Environment::Container)
    );
    assert_eq!(fixture.hostname, Observation::Present("Raw-Host".into()));
}
#[test]
fn cgroup_generations_and_loaded_modules_are_observations_not_policy_success() {
    let mut fixture = evidence();
    fixture
        .landmarks
        .insert("/sys/fs/cgroup".into(), Observation::Present(true));
    fixture
        .landmarks
        .insert("/sys/fs/cgroup/blkio".into(), Observation::Present(true));
    assert_eq!(
        classify(&fixture).cgroups,
        Observation::Present(Cgroups {
            version: CgroupVersion::V1,
            controllers: vec!["io".into()]
        })
    );
    fixture.files.insert(
        "/sys/fs/cgroup/cgroup.controllers".into(),
        Observation::Present("pids cpu cpu memory".into()),
    );
    assert_eq!(
        classify(&fixture).cgroups,
        Observation::Present(Cgroups {
            version: CgroupVersion::V2,
            controllers: vec!["cpu".into(), "memory".into(), "pids".into()]
        })
    );
    fixture.files.insert(
        "/proc/modules".into(),
        Observation::Present(
            "overlay 123 0 - Live 0x00000000\nxt_comment 456 1 - Live 0x00000000\n".into(),
        ),
    );
    assert_eq!(
        classify(&fixture).loaded_modules,
        Observation::Present(vec!["overlay".into(), "xt_comment".into()])
    );
    for record in [
        "tainted 456 1 - Live 0x00000000 (OE)\n",
        "tainted 456 - - Live 0x00000000\n",
        "tainted 456 0 [permanent], Live 0x00000000 (OE+)\n",
    ] {
        fixture
            .files
            .insert("/proc/modules".into(), Observation::Present(record.into()));
        assert_eq!(
            classify(&fixture).loaded_modules,
            Observation::Present(vec!["tainted".into()])
        );
    }
    fixture.files.insert(
        "/proc/modules".into(),
        Observation::Present("truncated".into()),
    );
    assert_eq!(
        classify(&fixture).loaded_modules,
        Observation::Unknown(ProbeFailure::Malformed)
    );
}
#[test]
fn mountinfo_decodes_paths_and_keeps_mount_and_superblock_readonly_separate() {
    let mounts =
        parse_mountinfo("24 1 8:1 / /custom\\040root rw,relatime shared:1 - ext4 /dev/x ro\n")
            .unwrap();
    assert_eq!(
        mounts[0].mount_point,
        std::path::PathBuf::from("/custom root")
    );
    assert!(!mounts[0].mount_read_only);
    assert!(mounts[0].superblock_read_only);
    assert_eq!(mounts[0].propagation, ["shared:1"]);
    for line in [
        "truncated",
        "1 2 bad / / ro - ext4 x ro",
        "1 2 8:1 / /bad\\099 ro - ext4 x ro",
        "1 2 8:1 / relative ro - ext4 x ro",
    ] {
        assert_eq!(parse_mountinfo(line), Err(ProbeFailure::Malformed));
    }
}
#[cfg(not(target_os = "linux"))]
#[test]
fn nonlinux_discovery_is_explicitly_unsupported() {
    assert_eq!(
        discover(&DiscoveryRequest::default()),
        Err(PlatformError::UnsupportedHost)
    );
}
#[cfg(target_os = "linux")]
#[test]
fn real_discovery_preserves_custom_paths_and_does_not_create_or_rewrite_them() {
    use std::fs;
    let directory =
        std::env::temp_dir().join(format!("diorama-platform-purity-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let file = directory.join("sentinel");
    fs::write(&file, b"unchanged").unwrap();
    let link = directory.join("link");
    std::os::unix::fs::symlink("sentinel", &link).unwrap();
    let missing = directory.join("absent");
    let relative = std::path::PathBuf::from("./diorama-platform-nonexistent-relative");
    let request = DiscoveryRequest {
        paths: vec![
            file.clone(),
            link.clone(),
            missing.clone(),
            relative.clone(),
        ],
        ..DiscoveryRequest::default()
    };
    let before: Vec<_> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    for _ in 0..2 {
        let observed = discover(&request).unwrap();
        assert_eq!(observed.requested_paths[2].facts, Observation::Absent);
        assert_eq!(observed.requested_paths[3].path, relative);
        assert!(matches!(observed.kernel, Observation::Present(_)));
        assert!(
            matches!(&observed.requested_paths[1].facts,Observation::Present(PathFacts{kind:PathKind::Symlink,symlink_target:Some(target),..}) if target==std::path::Path::new("sentinel"))
        );
    }
    assert_eq!(fs::read(file).unwrap(), b"unchanged");
    let after: Vec<_> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(before, after);
    assert!(!missing.exists());
    fs::remove_dir_all(directory).unwrap();
    assert_eq!(
        discover(&DiscoveryRequest {
            limits: ProbeLimits {
                bytes_per_file: 0,
                ..ProbeLimits::default()
            },
            ..DiscoveryRequest::default()
        }),
        Err(PlatformError::InvalidLimits)
    );
}

#[test]
fn available_builtin_and_loaded_modules_remain_distinct_and_malformed_indexes_fail_closed() {
    let mut fixture = evidence();
    fixture.files.insert("/lib/modules/fixture/modules.dep".into(),Observation::Present("kernel/net/xt_comment.ko.xz: kernel/net/x_tables.ko.zst\nkernel/net/x_tables.ko.zst:\n".into()));
    fixture.files.insert(
        "/lib/modules/fixture/modules.builtin".into(),
        Observation::Present("kernel/fs/overlayfs/overlay.ko\n".into()),
    );
    let capabilities = classify(&fixture);
    assert_eq!(capabilities.loaded_modules, Observation::Absent);
    assert_eq!(
        capabilities.builtin_modules,
        Observation::Present(vec!["kernel/fs/overlayfs/overlay.ko".into()])
    );
    assert_eq!(
        capabilities.available_modules,
        Observation::Present(vec![
            AvailableModule {
                path: "kernel/net/xt_comment.ko.xz".into(),
                dependencies: vec!["kernel/net/x_tables.ko.zst".into()]
            },
            AvailableModule {
                path: "kernel/net/x_tables.ko.zst".into(),
                dependencies: vec![]
            }
        ])
    );
    for value in [
        "missing-colon",
        "../escape.ko:",
        "/absolute.ko:",
        "a.ko: bad",
        "a.ko:\na.ko:",
    ] {
        fixture.files.insert(
            "/lib/modules/fixture/modules.dep".into(),
            Observation::Present(value.into()),
        );
        assert_eq!(
            classify(&fixture).available_modules,
            Observation::Unknown(ProbeFailure::Malformed)
        );
    }
    fixture.files.insert(
        "/lib/modules/fixture/modules.dep".into(),
        Observation::Unknown(ProbeFailure::TooLarge),
    );
    fixture.files.insert(
        "/lib/modules/fixture/modules.builtin".into(),
        Observation::Unknown(ProbeFailure::PermissionDenied),
    );
    assert_eq!(
        classify(&fixture).available_modules,
        Observation::Unknown(ProbeFailure::TooLarge)
    );
    assert_eq!(
        classify(&fixture).builtin_modules,
        Observation::Unknown(ProbeFailure::PermissionDenied)
    );
}
