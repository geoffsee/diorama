use dioramactl::cleanup::{CleanupHost, CleanupKind, run_container_cleanup, run_host_cleanup};
use dioramactl::upgrade::{ContainerSpec, Runner};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

fn data() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for path in [
        "kine/db",
        "local-path-storage",
        "containerd/root",
        "containerd/state",
        "containerd/images",
        "containerd/registry/docker.io",
        "kubelet",
        "neighbor",
    ] {
        fs::create_dir_all(dir.path().join(path)).unwrap();
        fs::write(dir.path().join(path).join("record"), path).unwrap();
    }
    fs::write(dir.path().join("containerd/containerd"), "binary").unwrap();
    fs::write(
        dir.path().join("containerd/registry/docker.io/hosts.toml"),
        "credentials",
    )
    .unwrap();
    dir
}

#[derive(Default)]
struct Host {
    mounts: Vec<PathBuf>,
    calls: Vec<String>,
}
impl CleanupHost for Host {
    fn stop_service(&mut self) -> io::Result<()> {
        self.calls.push("stop".into());
        Ok(())
    }
    fn start_service(&mut self) -> io::Result<()> {
        self.calls.push("start".into());
        Ok(())
    }
    fn mounts_under(&mut self, _: &Path) -> io::Result<Vec<PathBuf>> {
        Ok(self.mounts.clone())
    }
    fn unmount(&mut self, path: &Path) -> io::Result<()> {
        self.calls.push(format!("umount {}", path.display()));
        self.mounts.retain(|p| p != path);
        Ok(())
    }
    fn remove_service_artifacts(&mut self) -> io::Result<Vec<PathBuf>> {
        self.calls.push("remove artifacts".into());
        Ok(vec![])
    }
}

#[test]
fn reset_clears_actual_cluster_state_and_preserves_required_runtime_inputs() {
    let dir = data();
    let mut host = Host::default();
    run_host_cleanup(
        &mut host,
        CleanupKind::Reset,
        dir.path(),
        true,
        &mut io::Cursor::new(Vec::<u8>::new()),
        &mut Vec::new(),
    )
    .unwrap();
    for path in ["kine/db", "containerd/root", "containerd/state", "kubelet"] {
        assert!(!dir.path().join(path).exists(), "{path}");
    }
    for path in [
        "containerd/containerd",
        "containerd/registry/docker.io/hosts.toml",
        "containerd/images/record",
        "local-path-storage/record",
        "neighbor/record",
    ] {
        assert!(dir.path().join(path).exists(), "{path}");
    }
    assert_eq!(host.calls, ["stop", "start"]);
}

#[test]
fn retained_and_root_mounts_survive_while_selected_mounts_are_unmounted() {
    let dir = data();
    let keep = vec![
        dir.path().to_owned(),
        dir.path().join("neighbor"),
        dir.path().join("local-path-storage"),
        dir.path().join("containerd/registry"),
    ];
    let removed_mount = dir.path().join("kubelet/pods/pod");
    let mut mounts = vec![removed_mount.clone()];
    mounts.extend(keep.clone());
    let mut host = Host {
        mounts,
        calls: vec![],
    };
    run_host_cleanup(
        &mut host,
        CleanupKind::Reset,
        dir.path(),
        true,
        &mut io::Cursor::new(Vec::<u8>::new()),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(host.mounts, keep);
    assert_eq!(
        host.calls,
        [
            "stop".to_string(),
            format!("umount {}", removed_mount.display()),
            "start".to_string()
        ]
    );
}

#[derive(Debug)]
struct Engine {
    fail: &'static str,
    names: Option<String>,
    calls: Vec<String>,
}
impl Runner for Engine {
    fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
        let call = format!("{program} {}", args.join(" "));
        self.calls.push(call.clone());
        if args.first().is_some_and(|arg| arg == "ps") {
            return self
                .names
                .clone()
                .ok_or_else(|| io::Error::other("daemon unavailable"));
        }
        if call.contains(self.fail) {
            Err(io::Error::other("engine failed"))
        } else {
            Ok(String::new())
        }
    }
}

fn spec() -> ContainerSpec {
    ContainerSpec::parse("name=diorama\nimage=example/node:v1.2.0\n").unwrap()
}

#[test]
fn daemon_stop_and_removal_failures_never_delete_container_state() {
    for (kind, fail, names) in [
        (CleanupKind::Reset, "stop", Some("diorama\n")),
        (
            CleanupKind::Uninstall {
                purge: true,
                keep_config: false,
            },
            "stop",
            Some("diorama\n"),
        ),
        (
            CleanupKind::Uninstall {
                purge: true,
                keep_config: false,
            },
            "stop",
            None,
        ),
        (
            CleanupKind::Uninstall {
                purge: true,
                keep_config: false,
            },
            "rm",
            Some("diorama\n"),
        ),
    ] {
        let dir = data();
        let mut engine = Engine {
            fail,
            names: names.map(str::to_string),
            calls: vec![],
        };
        assert!(
            run_container_cleanup(
                &mut engine,
                "docker",
                &spec(),
                kind,
                dir.path(),
                true,
                &mut io::Cursor::new(Vec::<u8>::new()),
                &mut Vec::new()
            )
            .is_err()
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("kine/db/record")).unwrap(),
            "kine/db"
        );
        assert!(dir.path().join("local-path-storage/record").is_file());
        assert!(
            !engine
                .calls
                .iter()
                .any(|call| call == "docker start diorama")
        );
    }
}

#[test]
fn verified_absence_is_idempotent_for_uninstall_and_refused_for_reset() {
    let dir = data();
    let mut engine = Engine {
        fail: "stop",
        names: Some("neighbor\n".into()),
        calls: vec![],
    };
    assert!(
        run_container_cleanup(
            &mut engine,
            "docker",
            &spec(),
            CleanupKind::Reset,
            dir.path(),
            true,
            &mut io::Cursor::new(Vec::<u8>::new()),
            &mut Vec::new()
        )
        .is_err()
    );
    assert!(dir.path().join("kine/db/record").is_file());
    for _ in 0..2 {
        run_container_cleanup(
            &mut engine,
            "docker",
            &spec(),
            CleanupKind::Uninstall {
                purge: true,
                keep_config: false,
            },
            dir.path(),
            true,
            &mut io::Cursor::new(Vec::<u8>::new()),
            &mut Vec::new(),
        )
        .unwrap();
    }
    assert!(!dir.path().join("kine/db").exists());
    assert!(!dir.path().join("local-path-storage").exists());
    assert!(dir.path().join("neighbor/record").is_file());
    assert!(!engine.calls.iter().any(|call| call == "docker rm diorama"));
}

#[test]
fn ordinary_uninstall_retains_datastore_volumes_and_runtime_inputs() {
    let dir = data();
    let mut host = Host::default();
    let result = run_host_cleanup(
        &mut host,
        CleanupKind::Uninstall {
            purge: false,
            keep_config: false,
        },
        dir.path(),
        true,
        &mut io::Cursor::new(Vec::<u8>::new()),
        &mut Vec::new(),
    )
    .unwrap();
    assert!(result.removed.is_empty());
    for path in [
        "kine/db/record",
        "local-path-storage/record",
        "containerd/containerd",
        "containerd/root/record",
    ] {
        assert!(dir.path().join(path).is_file());
    }
    assert_eq!(host.calls, ["stop", "remove artifacts"]);
}

#[cfg(unix)]
#[test]
fn symlinked_parent_is_refused_before_service_stop_or_foreign_deletion() {
    let dir = data();
    let foreign = tempfile::tempdir().unwrap();
    fs::create_dir(foreign.path().join("db")).unwrap();
    fs::write(foreign.path().join("db/important"), "private").unwrap();
    fs::remove_dir_all(dir.path().join("kine")).unwrap();
    std::os::unix::fs::symlink(foreign.path(), dir.path().join("kine")).unwrap();
    let mut host = Host::default();
    assert!(
        run_host_cleanup(
            &mut host,
            CleanupKind::Reset,
            dir.path(),
            true,
            &mut io::Cursor::new(Vec::<u8>::new()),
            &mut Vec::new()
        )
        .is_err()
    );
    assert!(host.calls.is_empty());
    assert_eq!(
        fs::read_to_string(foreign.path().join("db/important")).unwrap(),
        "private"
    );
}

#[test]
fn upgrade_receipts_are_retained_with_recovery_backups_until_explicit_purge() {
    let dir = tempfile::tempdir().unwrap();
    let receipts = [
        ".upgrade-pending",
        ".upgrade-committing",
        ".upgrade-completed",
    ];
    for receipt in receipts {
        fs::write(dir.path().join(receipt), "backup=backups/retained").unwrap();
    }
    fs::write(dir.path().join(".upgrade.lock"), "").unwrap();
    for kind in [
        CleanupKind::Reset,
        CleanupKind::Uninstall {
            purge: false,
            keep_config: false,
        },
    ] {
        let plan = dioramactl::cleanup::plan_cleanup(kind, dir.path());
        for receipt in receipts {
            assert!(plan.retain.contains(&dir.path().join(receipt)));
            assert!(!plan.remove.contains(&dir.path().join(receipt)));
        }
    }
    let plan = dioramactl::cleanup::plan_cleanup(
        CleanupKind::Uninstall {
            purge: true,
            keep_config: false,
        },
        dir.path(),
    );
    for receipt in receipts {
        assert!(plan.remove.contains(&dir.path().join(receipt)));
    }
    // Keeping the lock inode avoids allowing a second upgrade to obtain a new lock.
    assert!(!plan.remove.contains(&dir.path().join(".upgrade.lock")));
}
