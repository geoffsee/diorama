use dioramactl::upgrade::{
    ContainerBackend, ContainerSpec, HostBackend, Runner, TransitionBackend, UpgradeOutcome,
    backup_state, run_upgrade,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Debug, Default)]
struct Recorded {
    calls: Vec<String>,
    fail: Option<String>,
    running: bool,
}

impl Runner for Recorded {
    fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
        let call = format!("{program} {}", args.join(" "));
        self.calls.push(call.clone());
        if self
            .fail
            .as_ref()
            .is_some_and(|needle| call.contains(needle))
        {
            return Err(io::Error::other("injected failure"));
        }
        if args.first().is_some_and(|arg| arg == "inspect") {
            if args
                .last()
                .is_some_and(|name| name.ends_with("-pre-upgrade"))
            {
                return Ok("false".into());
            }
            return Ok(self.running.to_string());
        }
        Ok("v1.2.0".into())
    }
}

fn data() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("kine/db")).unwrap();
    fs::create_dir_all(dir.path().join("pki")).unwrap();
    fs::write(dir.path().join("kine/db/state.db"), "old-db").unwrap();
    fs::write(dir.path().join("kine/db/state.db-wal"), "old-wal").unwrap();
    fs::write(dir.path().join("pki/ca.key"), "old-key").unwrap();
    dir
}

#[test]
fn backups_capture_real_layout_are_private_and_never_reuse_a_timestamp() {
    let dir = data();
    let first = backup_state(dir.path(), None, "v1.2.0", 7).unwrap();
    let second = backup_state(dir.path(), None, "v1.2.0", 7).unwrap();
    assert_ne!(first, second);
    assert_eq!(
        fs::read_to_string(first.join("kine/db/state.db-wal")).unwrap(),
        "old-wal"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(first).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[cfg(unix)]
#[test]
fn backup_refuses_symlinked_datastore_roots_and_ancestors() {
    for relative in ["kine", "kine/db", "backups"] {
        let dir = data();
        let foreign = tempfile::tempdir().unwrap();
        let linked = dir.path().join(relative);
        if linked.exists() {
            fs::remove_dir_all(&linked).unwrap();
        }
        std::os::unix::fs::symlink(foreign.path(), linked).unwrap();
        assert!(backup_state(dir.path(), None, "v1.2.0", 1).is_err());
        assert!(fs::read_dir(foreign.path()).unwrap().next().is_none());
    }
}

#[cfg(unix)]
#[test]
fn host_binary_replacement_is_executable_without_exposing_config_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = data();
    let binary = dir.path().join("kubesolo");
    let staged = dir.path().join("staged");
    fs::write(&binary, "old").unwrap();
    fs::write(&staged, "new").unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).unwrap();
    let mut runner = Recorded::default();
    let mut backend = HostBackend {
        binary: binary.clone(),
        staged,
        service: "kubesolo".into(),
        runner: &mut runner,
        systemd: true,
        service_file: None,
        legacy_config: None,
    };
    backend.replace("v1.3.0").unwrap();
    assert_eq!(
        fs::metadata(binary).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn container_commit_persists_version_and_failed_launch_restores_record() {
    for failure in [None, Some("run -d"), Some("rm diorama-pre-upgrade")] {
        let dir = data();
        let spec_path = dir.path().join("container.spec");
        let original = "name=diorama\nimage=example/node:v1.2.0\narg=--debug\nport=6443:6443\n";
        fs::write(&spec_path, original).unwrap();
        let spec = ContainerSpec::parse(original).unwrap();
        let mut runner = Recorded {
            running: true,
            fail: failure.map(str::to_string),
            ..Recorded::default()
        };
        let mut backend =
            ContainerBackend::new("docker", spec, &mut runner).with_spec_path(spec_path.clone());
        let result =
            run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 1, &mut Vec::new()).unwrap();
        let recorded = ContainerSpec::parse(&fs::read_to_string(spec_path).unwrap()).unwrap();
        if failure.is_none() {
            assert!(matches!(result, UpgradeOutcome::Upgraded { .. }));
            assert_eq!(recorded.tag(), Some("v1.3.0"));
            assert_eq!(
                run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 1, &mut Vec::new()).unwrap(),
                UpgradeOutcome::Unchanged
            );
        } else {
            assert!(matches!(result, UpgradeOutcome::RolledBack { .. }));
            assert_eq!(recorded.tag(), Some("v1.2.0"));
        }
    }
}

#[test]
fn exited_replacement_does_not_discard_old_container() {
    let dir = data();
    let mut runner = Recorded::default();
    let spec = ContainerSpec::parse("name=diorama\nimage=example/node:v1.2.0\n").unwrap();
    let mut backend = ContainerBackend::new("docker", spec, &mut runner);
    let result = run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 1, &mut Vec::new()).unwrap();
    assert!(matches!(result, UpgradeOutcome::RolledBack { .. }));
    assert!(
        !runner
            .calls
            .iter()
            .any(|call| call == "docker rm diorama-pre-upgrade")
    );
    assert!(
        runner
            .calls
            .iter()
            .any(|call| call == "docker start diorama")
    );
}

#[derive(Debug)]
struct MutatingStart {
    data: PathBuf,
    calls: Vec<String>,
    first: bool,
}
impl Runner for MutatingStart {
    fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
        self.calls.push(format!("{program} {}", args.join(" ")));
        if args.first().is_some_and(|arg| arg == "start") && self.first {
            self.first = false;
            fs::write(self.data.join("kine/db/state.db"), "new-db")?;
            fs::write(self.data.join("kine/db/new-file"), "new")?;
            fs::write(self.data.join("pki/ca.key"), "new-key")?;
            return Err(io::Error::other("startup failed after mutations"));
        }
        Ok("v1.2.0".into())
    }
}

#[test]
fn host_rollback_restores_all_state_and_removes_migration_created_config() {
    let dir = data();
    let binary = dir.path().join("kubesolo");
    let staged = dir.path().join("staged");
    let service = dir.path().join("node.service");
    let config = dir.path().join("config.yaml");
    let original = "Description=kubesolo\nExecStart=/usr/local/bin/diorama --debug\n";
    fs::write(&binary, "old-binary").unwrap();
    fs::write(&staged, "new-binary").unwrap();
    fs::write(&service, original).unwrap();
    let mut runner = MutatingStart {
        data: dir.path().to_owned(),
        calls: vec![],
        first: true,
    };
    let mut backend = HostBackend {
        binary: binary.clone(),
        staged,
        service: "kubesolo".into(),
        runner: &mut runner,
        systemd: true,
        service_file: Some(service.clone()),
        legacy_config: Some(config.clone()),
    };
    let result = run_upgrade(
        &mut backend,
        dir.path(),
        Some(&config),
        "v1.3.0",
        1,
        &mut Vec::new(),
    )
    .unwrap();
    assert!(matches!(result, UpgradeOutcome::RolledBack { .. }));
    assert_eq!(fs::read_to_string(binary).unwrap(), "old-binary");
    assert_eq!(fs::read_to_string(service).unwrap(), original);
    assert_eq!(
        fs::read_to_string(dir.path().join("kine/db/state.db")).unwrap(),
        "old-db"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("pki/ca.key")).unwrap(),
        "old-key"
    );
    assert!(!dir.path().join("kine/db/new-file").exists());
    assert!(!config.exists());
    assert_eq!(
        runner
            .calls
            .iter()
            .filter(|call| *call == "systemctl daemon-reload")
            .count(),
        2
    );
}

struct BackupFailure {
    data: PathBuf,
    calls: Vec<&'static str>,
}
impl TransitionBackend for BackupFailure {
    fn current_version(&mut self) -> io::Result<String> {
        Ok("v1.2.0".into())
    }
    fn prepare(&mut self, _: &str) -> io::Result<()> {
        self.calls.push("prepare");
        Ok(())
    }
    fn stop(&mut self) -> io::Result<()> {
        self.calls.push("stop");
        fs::write(self.data.join("kine/db/state.db"), "quiesced")
    }
    fn snapshot(&mut self, dir: &Path) -> io::Result<()> {
        assert_eq!(
            fs::read_to_string(dir.join("kine/db/state.db"))?,
            "quiesced"
        );
        self.calls.push("snapshot");
        Err(io::Error::other("snapshot unavailable"))
    }
    fn replace(&mut self, _: &str) -> io::Result<()> {
        panic!("must not replace without backup")
    }
    fn start(&mut self) -> io::Result<()> {
        self.calls.push("start");
        Ok(())
    }
    fn restore(&mut self, _: &Path) -> io::Result<()> {
        panic!("no replacement happened")
    }
}

#[test]
fn snapshot_is_quiesced_and_snapshot_failure_restarts_old_deployment() {
    let dir = data();
    let mut backend = BackupFailure {
        data: dir.path().to_owned(),
        calls: vec![],
    };
    assert!(run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 1, &mut Vec::new()).is_err());
    assert_eq!(backend.calls, ["prepare", "stop", "snapshot", "start"]);
}

#[test]
fn incomplete_snapshot_restarts_old_service_without_receipt_or_replacement() {
    for (relative, empty) in [
        ("pki", false),
        ("pki", true),
        ("kine/db", false),
        ("kine/db", true),
    ] {
        let dir = data();
        fs::remove_dir_all(dir.path().join(relative)).unwrap();
        if empty {
            fs::create_dir_all(dir.path().join(relative)).unwrap();
        }
        let binary = dir.path().join("kubesolo");
        let staged = dir.path().join("staged");
        fs::write(&binary, "old-binary").unwrap();
        fs::write(&staged, "target-binary").unwrap();
        let mut runner = Recorded::default();
        let mut backend = HostBackend {
            binary: binary.clone(),
            staged,
            service: "kubesolo".into(),
            runner: &mut runner,
            systemd: true,
            service_file: None,
            legacy_config: None,
        };
        assert!(run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 1, &mut Vec::new()).is_err());
        assert_eq!(fs::read(binary).unwrap(), b"old-binary");
        assert_eq!(runner.calls.last().unwrap(), "systemctl start kubesolo");
        assert!(!dir.path().join(".upgrade-pending").exists());
        assert!(
            fs::read_dir(dir.path().join("backups"))
                .unwrap()
                .next()
                .is_none()
        );
    }
}

#[test]
fn host_snapshot_allows_initially_absent_unit_but_rejects_present_nonregular_unit() {
    let dir = data();
    let binary = dir.path().join("kubesolo");
    let staged = dir.path().join("staged");
    fs::write(&binary, "old-binary").unwrap();
    fs::write(&staged, "target-binary").unwrap();
    let mut runner = Recorded::default();
    let mut backend = HostBackend {
        binary: binary.clone(),
        staged,
        service: "kubesolo".into(),
        runner: &mut runner,
        systemd: true,
        service_file: Some(dir.path().join("absent-unit")),
        legacy_config: None,
    };
    let backup = backup_state(dir.path(), None, "v1.2.0", 1).unwrap();
    backend.snapshot(&backup).unwrap();
    backend.validate_snapshot(&backup).unwrap();
    fs::create_dir(backup.join("service.unit")).unwrap();
    assert!(backend.validate_snapshot(&backup).is_err());
    fs::remove_dir(backup.join("service.unit")).unwrap();
    assert!(matches!(
        run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 2, &mut Vec::new()).unwrap(),
        UpgradeOutcome::Upgraded { .. }
    ));
    assert_eq!(fs::read(binary).unwrap(), b"target-binary");
}

#[test]
fn failed_committing_host_restore_retries_as_rollback_not_commit() {
    use dioramactl::upgrade::{RecoveryOutcome, recover_interrupted_upgrade, seal_backup};
    let dir = data();
    let binary = dir.path().join("kubesolo");
    let config = dir.path().join("missing-parent/config.yaml");
    fs::write(&binary, "old-binary").unwrap();
    let mut runner = MutatingStart {
        data: dir.path().to_owned(),
        calls: Vec::new(),
        first: true,
    };
    let mut backend = HostBackend {
        binary: binary.clone(),
        staged: binary.clone(),
        service: "kubesolo".into(),
        runner: &mut runner,
        systemd: true,
        service_file: None,
        legacy_config: None,
    };
    let backup = backup_state(dir.path(), None, "v1.2.0", 1).unwrap();
    backend.snapshot(&backup).unwrap();
    fs::write(backup.join("config.yaml"), "old-config").unwrap();
    seal_backup(&backup).unwrap();
    fs::write(&binary, "target-binary").unwrap();
    fs::write(
        dir.path().join(".upgrade-committing"),
        format!("from=v1.2.0\ntarget=v1.3.0\nbackup={}\n", backup.display()),
    )
    .unwrap();
    assert!(
        recover_interrupted_upgrade(&mut backend, dir.path(), Some(&config), &mut Vec::new())
            .is_err()
    );
    assert_eq!(fs::read(&binary).unwrap(), b"old-binary");
    assert!(dir.path().join(".upgrade-pending").is_file());
    assert!(!dir.path().join(".upgrade-committing").exists());
    fs::create_dir(config.parent().unwrap()).unwrap();
    assert!(matches!(
        recover_interrupted_upgrade(&mut backend, dir.path(), Some(&config), &mut Vec::new())
            .unwrap(),
        RecoveryOutcome::RolledBack { .. }
    ));
    assert_eq!(fs::read(config).unwrap(), b"old-config");
    assert_eq!(
        fs::read(dir.path().join("kine/db/state.db")).unwrap(),
        b"old-db"
    );
    assert_eq!(fs::read(dir.path().join("pki/ca.key")).unwrap(), b"old-key");
    assert!(!dir.path().join(".upgrade-pending").exists());
}

#[test]
fn live_lock_and_interrupted_receipt_refuse_new_mutations() {
    let dir = data();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.path().join(".upgrade.lock"))
        .unwrap();
    lock.lock().unwrap();
    let mut backend = BackupFailure {
        data: dir.path().to_owned(),
        calls: vec![],
    };
    assert!(run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 1, &mut Vec::new()).is_err());
    assert!(backend.calls.is_empty());
    drop(lock);
    fs::write(
        dir.path().join(".upgrade-pending"),
        "backup=/retained/backup",
    )
    .unwrap();
    assert!(run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 1, &mut Vec::new()).is_err());
    assert!(backend.calls.is_empty());
}

#[derive(Clone, Copy)]
enum ReceiptFailure {
    BeforeCommit,
    CommitAndRollback,
    CompletionRename,
    CompletedCleanup,
}

struct ReceiptBackend {
    data: PathBuf,
    failure: ReceiptFailure,
    committed: bool,
    restored: bool,
}
impl TransitionBackend for ReceiptBackend {
    fn current_version(&mut self) -> io::Result<String> {
        Ok(if self.committed { "v1.3.0" } else { "v1.2.0" }.into())
    }
    fn prepare(&mut self, _: &str) -> io::Result<()> {
        Ok(())
    }
    fn snapshot(&mut self, _: &Path) -> io::Result<()> {
        Ok(())
    }
    fn stop(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn replace(&mut self, _: &str) -> io::Result<()> {
        Ok(())
    }
    fn start(&mut self) -> io::Result<()> {
        if !self.restored && matches!(self.failure, ReceiptFailure::BeforeCommit) {
            // An invalid receipt cannot be safely staged or removed as a file.
            fs::remove_file(self.data.join(".upgrade-pending"))?;
            fs::create_dir(self.data.join(".upgrade-pending"))?;
        }
        Ok(())
    }
    fn restore(&mut self, _: &Path) -> io::Result<()> {
        assert!(
            !self.committed,
            "irreversible commit must never be rolled back"
        );
        if matches!(self.failure, ReceiptFailure::CommitAndRollback) {
            return Err(io::Error::other("rollback unavailable"));
        }
        self.restored = true;
        Ok(())
    }
    fn commit(&mut self) -> io::Result<()> {
        assert!(!self.data.join(".upgrade-pending").exists());
        assert!(self.data.join(".upgrade-committing").is_file());
        if matches!(self.failure, ReceiptFailure::CommitAndRollback) {
            return Err(io::Error::other("commit unavailable"));
        }
        self.committed = true;
        match self.failure {
            ReceiptFailure::CompletionRename => {
                fs::create_dir(self.data.join(".upgrade-completed"))?;
                fs::write(self.data.join(".upgrade-completed/obstruction"), "x")?;
            },
            ReceiptFailure::CompletedCleanup => {
                fs::remove_file(self.data.join(".upgrade-committing"))?;
                fs::create_dir(self.data.join(".upgrade-committing"))?;
            },
            _ => {},
        }
        Ok(())
    }
}

#[test]
fn receipt_failures_keep_recovery_evidence_and_never_report_a_committed_upgrade_as_failed() {
    for failure in [
        ReceiptFailure::BeforeCommit,
        ReceiptFailure::CommitAndRollback,
        ReceiptFailure::CompletionRename,
        ReceiptFailure::CompletedCleanup,
    ] {
        let dir = data();
        let mut backend = ReceiptBackend {
            data: dir.path().into(),
            failure,
            committed: false,
            restored: false,
        };
        let mut stderr = Vec::new();
        let outcome = run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 1, &mut stderr);
        match failure {
            ReceiptFailure::BeforeCommit => {
                let error = outcome.unwrap_err();
                let diagnostic = error.to_string();
                assert!(diagnostic.contains("upgrade failed ("));
                assert!(diagnostic.contains("rolled back to v1.2.0"));
                assert!(
                    diagnostic.contains(&dir.path().join(".upgrade-pending").display().to_string())
                );
                assert!(diagnostic.contains("backup kept at"));
                assert!(diagnostic.contains(&dir.path().join("backups").display().to_string()));
                assert!(diagnostic.contains("Rollback is complete"));
                assert!(backend.restored);
                assert!(!backend.committed);
                assert!(dir.path().join(".upgrade-pending").exists());
            },
            ReceiptFailure::CommitAndRollback => {
                assert!(outcome.unwrap_err().to_string().contains("rollback failed"));
                assert!(dir.path().join(".upgrade-committing").is_file());
                assert!(
                    run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 2, &mut Vec::new())
                        .unwrap_err()
                        .to_string()
                        .contains("interrupted upgrade")
                );
            },
            ReceiptFailure::CompletionRename | ReceiptFailure::CompletedCleanup => {
                assert!(matches!(outcome.unwrap(), UpgradeOutcome::Upgraded { .. }));
                assert!(backend.committed);
                assert!(!backend.restored);
                assert!(
                    String::from_utf8(stderr)
                        .unwrap()
                        .contains("Upgrade committed; receipt cleanup failed")
                );
                assert!(
                    run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 2, &mut Vec::new())
                        .is_err()
                );
            },
        }
    }
}

#[derive(Debug)]
struct InactiveRunner {
    status: Option<i32>,
    probe_error: bool,
}
impl Runner for InactiveRunner {
    fn run(&mut self, _: &str, _: &[String]) -> io::Result<String> {
        Err(io::Error::other("stop denied"))
    }
    fn status_code(&mut self, program: &str, args: &[String]) -> io::Result<Option<i32>> {
        assert_eq!(program, "service");
        assert_eq!(args, ["kubesolo", "status"]);
        if self.probe_error {
            Err(io::Error::other("cannot query service"))
        } else {
            Ok(self.status)
        }
    }
}

#[test]
fn non_systemd_restore_accepts_only_explicit_inactive_status() {
    for (status, probe_error) in [
        (Some(3), false),
        (Some(0), false),
        (Some(4), false),
        (None, false),
        (Some(3), true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("node");
        fs::write(&binary, "new").unwrap();
        fs::write(dir.path().join("kubesolo.bin"), "old").unwrap();
        let mut runner = InactiveRunner {
            status,
            probe_error,
        };
        let mut backend = HostBackend {
            binary: binary.clone(),
            staged: binary.clone(),
            service: "kubesolo".into(),
            runner: &mut runner,
            systemd: false,
            service_file: None,
            legacy_config: None,
        };
        let outcome = backend.restore(dir.path());
        if status == Some(3) && !probe_error {
            outcome.unwrap();
            assert_eq!(fs::read_to_string(&binary).unwrap(), "old");
        } else {
            assert_eq!(outcome.unwrap_err().to_string(), "stop denied");
            assert_eq!(fs::read_to_string(&binary).unwrap(), "new");
        }
    }
}

#[test]
fn a_durable_completed_receipt_is_cleaned_without_ambiguous_recovery() {
    let dir = data();
    fs::write(
        dir.path().join(".upgrade-completed"),
        "from=v1.2.0\ntarget=v1.3.0\n",
    )
    .unwrap();
    let mut backend = ReceiptBackend {
        data: dir.path().into(),
        failure: ReceiptFailure::CommitAndRollback,
        committed: true,
        restored: false,
    };
    assert_eq!(
        run_upgrade(&mut backend, dir.path(), None, "v1.3.0", 1, &mut Vec::new()).unwrap(),
        UpgradeOutcome::Unchanged
    );
    assert!(!dir.path().join(".upgrade-completed").exists());
    assert!(!backend.restored);
}

struct RejectSuccessOutput;
impl io::Write for RejectSuccessOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if String::from_utf8_lossy(bytes).contains("Upgraded to") {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "output closed after commit",
            ))
        } else {
            Ok(bytes.len())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn success_output_failure_does_not_turn_an_irreversible_commit_into_failure() {
    let dir = data();
    let mut runner = Recorded {
        running: true,
        ..Recorded::default()
    };
    let spec = ContainerSpec::parse("name=diorama\nimage=example/node:v1.2.0\n").unwrap();
    let mut backend = ContainerBackend::new("docker", spec, &mut runner);
    assert!(matches!(
        run_upgrade(
            &mut backend,
            dir.path(),
            None,
            "v1.3.0",
            1,
            &mut RejectSuccessOutput
        )
        .unwrap(),
        UpgradeOutcome::Upgraded { .. }
    ));
    assert!(
        runner
            .calls
            .iter()
            .any(|call| call == "docker rm diorama-pre-upgrade")
    );
    assert!(
        !runner
            .calls
            .iter()
            .any(|call| call.starts_with("docker rm -f"))
    );
    assert!(!dir.path().join(".upgrade-pending").exists());
    assert!(!dir.path().join(".upgrade-committing").exists());
    assert!(!dir.path().join(".upgrade-completed").exists());
}

#[test]
fn interrupted_upgrade_recovery_restores_pre_upgrade_state_from_pending_receipt() {
    use dioramactl::upgrade::{
        ReceiptKind, RecoveryOutcome, find_active_receipt, parse_receipt_file,
        recover_interrupted_upgrade,
    };

    let dir = data();
    let binary = dir.path().join("kubesolo");
    let staged = dir.path().join("staged");
    let service = dir.path().join("node.service");
    let config = dir.path().join("config.yaml");

    let original_service = "Description=kubesolo\nExecStart=/usr/local/bin/diorama --debug\n";
    fs::write(&binary, "old-binary").unwrap();
    fs::write(&staged, "new-binary").unwrap();
    fs::write(&service, original_service).unwrap();

    // Create a valid backup
    let backup_dir = dir.path().join("backups/pre-upgrade-v1.2.0-1-valid");
    fs::create_dir_all(backup_dir.join("pki")).unwrap();
    fs::create_dir_all(backup_dir.join("kine/db")).unwrap();
    fs::write(backup_dir.join("pki/ca.key"), "old-key").unwrap();
    fs::write(backup_dir.join("kine/db/state.db"), "old-db").unwrap();
    fs::write(backup_dir.join("kubesolo.bin"), "old-binary").unwrap();
    fs::write(backup_dir.join("service.unit"), original_service).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&backup_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    dioramactl::upgrade::seal_backup(&backup_dir).unwrap();

    // Simulate an interruption after replacement and dirty mutation:
    fs::write(&binary, "new-corrupted-binary").unwrap();
    fs::write(
        &service,
        "Description=kubesolo\nExecStart=/usr/local/bin/diorama --config=/etc/diorama/config.yaml\n",
    )
    .unwrap();
    fs::write(&config, "network:\n  nodeIP: 10.0.0.1\n").unwrap();
    fs::write(dir.path().join("pki/ca.key"), "dirty-key").unwrap();
    fs::write(dir.path().join("kine/db/state.db"), "dirty-db").unwrap();

    // Create .upgrade-pending receipt
    let pending_receipt = dir.path().join(".upgrade-pending");
    fs::write(
        &pending_receipt,
        format!(
            "from=v1.2.0\ntarget=v1.3.0\nbackup={}\n",
            backup_dir.display()
        ),
    )
    .unwrap();

    let active = find_active_receipt(dir.path()).unwrap().unwrap();
    assert_eq!(active.kind, ReceiptKind::Pending);
    assert_eq!(active.from, "v1.2.0");
    assert_eq!(active.target, "v1.3.0");
    assert_eq!(active.backup, backup_dir);

    let parsed = parse_receipt_file(&pending_receipt, ReceiptKind::Pending).unwrap();
    assert_eq!(parsed.from, "v1.2.0");

    let mut runner = Recorded::default();
    let mut backend = HostBackend {
        binary: binary.clone(),
        staged,
        service: "kubesolo".into(),
        runner: &mut runner,
        systemd: true,
        service_file: Some(service.clone()),
        legacy_config: Some(config.clone()),
    };

    let outcome =
        recover_interrupted_upgrade(&mut backend, dir.path(), Some(&config), &mut Vec::new())
            .unwrap();

    assert_eq!(
        outcome,
        RecoveryOutcome::RolledBack {
            from: "v1.2.0".into(),
            backup: backup_dir.clone(),
        }
    );

    // Verify all state restored cleanly
    assert_eq!(fs::read_to_string(&binary).unwrap(), "old-binary");
    assert_eq!(fs::read_to_string(&service).unwrap(), original_service);
    assert_eq!(
        fs::read_to_string(dir.path().join("pki/ca.key")).unwrap(),
        "old-key"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("kine/db/state.db")).unwrap(),
        "old-db"
    );
    assert!(!config.exists(), "migration-created config was cleaned up");
    assert!(!pending_receipt.exists(), "pending receipt was cleaned up");

    // Re-running recovery reports already clean
    let clean =
        recover_interrupted_upgrade(&mut backend, dir.path(), Some(&config), &mut Vec::new())
            .unwrap();
    assert_eq!(clean, RecoveryOutcome::AlreadyClean);
}

#[test]
fn interrupted_upgrade_recovery_refuses_corrupted_or_missing_backup_without_mutation() {
    use dioramactl::upgrade::{
        BackupIntegrityError, recover_interrupted_upgrade, validate_backup_integrity,
    };

    let dir = data();
    let binary = dir.path().join("kubesolo");
    let staged = dir.path().join("staged");
    let service = dir.path().join("node.service");

    fs::write(&binary, "current-binary").unwrap();
    fs::write(&staged, "new-binary").unwrap();
    fs::write(&service, "service-content").unwrap();

    // 1. Missing backup directory
    let non_existent_backup = dir.path().join("backups/missing");
    let pending_receipt = dir.path().join(".upgrade-pending");
    fs::write(
        &pending_receipt,
        format!(
            "from=v1.2.0\ntarget=v1.3.0\nbackup={}\n",
            non_existent_backup.display()
        ),
    )
    .unwrap();

    let mut runner = Recorded::default();
    let mut backend = HostBackend {
        binary: binary.clone(),
        staged: staged.clone(),
        service: "kubesolo".into(),
        runner: &mut runner,
        systemd: true,
        service_file: Some(service.clone()),
        legacy_config: None,
    };

    let err =
        recover_interrupted_upgrade(&mut backend, dir.path(), None, &mut Vec::new()).unwrap_err();
    assert!(
        err.to_string().contains("recovery refused: backup at"),
        "error must explain backup refusal: {err}"
    );
    // Crucial: pending receipt and files were NOT destroyed!
    assert!(pending_receipt.exists());
    assert_eq!(fs::read_to_string(&binary).unwrap(), "current-binary");

    // 2. Corrupted backup (missing kine/db state directory)
    let corrupt_backup = dir.path().join("backups/corrupt");
    fs::create_dir_all(corrupt_backup.join("pki")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&corrupt_backup, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(corrupt_backup.join("pki/ca.crt"), "ca").unwrap();
    // Missing kine/db directory
    assert!(matches!(
        validate_backup_integrity(&corrupt_backup),
        Err(BackupIntegrityError::MissingStateDirectory { .. })
    ));

    fs::write(
        &pending_receipt,
        format!(
            "from=v1.2.0\ntarget=v1.3.0\nbackup={}\n",
            corrupt_backup.display()
        ),
    )
    .unwrap();

    let err2 =
        recover_interrupted_upgrade(&mut backend, dir.path(), None, &mut Vec::new()).unwrap_err();
    assert!(
        err2.to_string()
            .contains("missing required state directory")
    );
    assert!(pending_receipt.exists());
}

#[test]
fn recovery_prevalidation_rejects_changed_bytes_missing_artifacts_and_unsafe_entries() {
    use dioramactl::upgrade::{recover_interrupted_upgrade, seal_backup};
    for defect in [
        "database",
        "key",
        "binary",
        "service",
        "extra",
        "nested-link",
        "intermediate-link",
        "permissions",
    ] {
        let dir = data();
        let binary = dir.path().join("kubesolo");
        let service = dir.path().join("service");
        fs::write(&binary, "original binary").unwrap();
        fs::write(&service, "original service").unwrap();
        let mut runner = Recorded::default();
        let mut backend = HostBackend {
            binary: binary.clone(),
            staged: binary.clone(),
            service: "kubesolo".into(),
            runner: &mut runner,
            systemd: true,
            service_file: Some(service.clone()),
            legacy_config: None,
        };
        let backup = backup_state(dir.path(), None, "v1.2.0", 1).unwrap();
        backend.snapshot(&backup).unwrap();
        seal_backup(&backup).unwrap();
        match defect {
            "database" => {
                fs::write(backup.join("kine/db/state.db"), "corrupt nonempty DB").unwrap();
            },
            "key" => fs::write(backup.join("pki/ca.key"), "invalid nonempty key").unwrap(),
            "binary" => fs::remove_file(backup.join("kubesolo.bin")).unwrap(),
            "service" => fs::remove_file(backup.join("service.unit")).unwrap(),
            "extra" => fs::write(backup.join("pki/unknown"), "foreign").unwrap(),
            #[cfg(unix)]
            "nested-link" => std::os::unix::fs::symlink(&binary, backup.join("pki/link")).unwrap(),
            #[cfg(unix)]
            "intermediate-link" => {
                fs::remove_dir_all(backup.join("kine")).unwrap();
                std::os::unix::fs::symlink(dir.path().join("kine"), backup.join("kine")).unwrap();
            },
            #[cfg(unix)]
            "permissions" => {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&backup, fs::Permissions::from_mode(0o755)).unwrap();
            },
            _ => continue,
        }
        let receipt = dir.path().join(".upgrade-pending");
        fs::write(
            &receipt,
            format!("from=v1.2.0\ntarget=v1.3.0\nbackup={}\n", backup.display()),
        )
        .unwrap();
        fs::write(dir.path().join("pki/ca.key"), "live key").unwrap();
        fs::write(dir.path().join("kine/db/state.db"), "live database").unwrap();
        assert!(
            recover_interrupted_upgrade(&mut backend, dir.path(), None, &mut Vec::new()).is_err(),
            "{defect}"
        );
        drop(backend);
        assert!(
            runner.calls.is_empty(),
            "service effect before validating {defect}"
        );
        assert!(receipt.exists());
        assert_eq!(fs::read(&binary).unwrap(), b"original binary");
        assert_eq!(
            fs::read(dir.path().join("pki/ca.key")).unwrap(),
            b"live key"
        );
        assert_eq!(
            fs::read(dir.path().join("kine/db/state.db")).unwrap(),
            b"live database"
        );
    }
}

#[derive(Debug)]
// Independent failure injection switches in the engine double, not production state.
#[allow(clippy::struct_excessive_bools)]
struct RecoveryEngine {
    containers: std::collections::BTreeMap<String, (String, bool)>,
    fail_stop: bool,
    fail_commit: bool,
    fail_start_once: bool,
    fail_rollback_stop: bool,
    rollback_stop_unconfirmed: bool,
    calls: Vec<Vec<String>>,
}
impl Runner for RecoveryEngine {
    fn run(&mut self, _: &str, args: &[String]) -> io::Result<String> {
        self.calls.push(args.to_vec());
        let name = args.last().unwrap();
        match args[0].as_str() {
            "ps" => Ok(self
                .containers
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")),
            "inspect" => {
                let (image, running) = self
                    .containers
                    .get(name)
                    .ok_or_else(|| io::Error::other("missing"))?;
                Ok(if args[2] == "{{.Config.Image}}" {
                    image.clone()
                } else {
                    running.to_string()
                })
            },
            "stop" if self.fail_stop => Err(io::Error::other("stop failed")),
            "stop" if self.fail_rollback_stop && name.ends_with("-pre-upgrade") => {
                Err(io::Error::other("rollback container stop failed"))
            },
            "start" if self.fail_start_once => {
                self.fail_start_once = false;
                Err(io::Error::other("injected target start failure"))
            },
            "stop" | "start" => {
                if args[0] == "stop"
                    && name.ends_with("-pre-upgrade")
                    && self.rollback_stop_unconfirmed
                {
                    return Ok(String::new());
                }
                self.containers
                    .get_mut(name)
                    .ok_or_else(|| io::Error::other("missing"))?
                    .1 = args[0] == "start";
                Ok(String::new())
            },
            "rename" => {
                if self
                    .containers
                    .get(&args[1])
                    .is_some_and(|(_, running)| *running)
                {
                    return Err(io::Error::other(
                        "cannot restore from a running rollback container",
                    ));
                }
                let value = self
                    .containers
                    .remove(&args[1])
                    .ok_or_else(|| io::Error::other("missing"))?;
                self.containers.insert(name.clone(), value);
                Ok(String::new())
            },
            "rm" if self.fail_commit && name.ends_with("-pre-upgrade") => {
                Err(io::Error::other("commit failed"))
            },
            "rm" => {
                self.containers
                    .remove(name)
                    .ok_or_else(|| io::Error::other("missing"))?;
                Ok(String::new())
            },
            other => Err(io::Error::other(format!("unexpected command {other}"))),
        }
    }
}

#[test]
// Keep each fresh-backend interruption and its retry in one complete transaction assertion.
#[allow(clippy::too_many_lines)]
fn fresh_container_recovery_reconstructs_rollback_and_retains_failed_commit_for_retry() {
    use dioramactl::upgrade::{RecoveryOutcome, recover_interrupted_upgrade, seal_backup};
    for phase in [
        "pending",
        "committing",
        "stop-failure",
        "rename-only",
        "committed-crash",
        "image-mismatch",
        "dual-marker",
        "commit-start-failure",
        "commit-restore-failure",
        "old-running",
        "old-stop-failure",
        "old-stop-unconfirmed",
        "committing-old-running",
    ] {
        let dir = data();
        let spec = ContainerSpec::parse(
            "name=diorama\nimage=example/diorama:v1.2.0\nmount=/owned:/var/lib/diorama\n",
        )
        .unwrap();
        let spec_path = dir.path().join("container.spec");
        fs::write(&spec_path, spec.render()).unwrap();
        let backup = backup_state(dir.path(), None, "v1.2.0", 1).unwrap();
        fs::write(backup.join("container.spec"), spec.render()).unwrap();
        let config = dir.path().join("missing-parent/config.yaml");
        if phase == "commit-restore-failure" {
            fs::write(backup.join("config.yaml"), "old-config").unwrap();
        }
        seal_backup(&backup).unwrap();
        let committing = matches!(
            phase,
            "committing"
                | "committed-crash"
                | "commit-start-failure"
                | "commit-restore-failure"
                | "committing-old-running"
        );
        let receipt = dir.path().join(if committing {
            ".upgrade-committing"
        } else {
            ".upgrade-pending"
        });
        fs::write(
            &receipt,
            format!("from=v1.2.0\ntarget=v1.3.0\nbackup={}\n", backup.display()),
        )
        .unwrap();
        if phase == "dual-marker" {
            fs::hard_link(&receipt, dir.path().join(".upgrade-committing")).unwrap();
        }
        fs::write(dir.path().join("kine/db/state.db"), "dirty").unwrap();
        let mut engine = RecoveryEngine {
            containers: [
                ("diorama".into(), ("example/diorama:v1.3.0".into(), true)),
                ("diorama-pre-upgrade".into(), (spec.image.clone(), false)),
            ]
            .into(),
            fail_stop: phase == "stop-failure",
            fail_commit: phase == "committing",
            fail_start_once: matches!(phase, "commit-start-failure" | "commit-restore-failure"),
            fail_rollback_stop: phase == "old-stop-failure",
            rollback_stop_unconfirmed: phase == "old-stop-unconfirmed",
            calls: Vec::new(),
        };
        if matches!(
            phase,
            "old-running" | "old-stop-failure" | "old-stop-unconfirmed" | "committing-old-running"
        ) {
            engine.containers.get_mut("diorama-pre-upgrade").unwrap().1 = true;
        }
        let installed = if phase == "committed-crash" {
            engine.containers.remove("diorama-pre-upgrade");
            let installed = spec.with_version("v1.3.0");
            fs::write(&spec_path, installed.render()).unwrap();
            installed
        } else {
            spec.clone()
        };
        if phase == "rename-only" {
            engine.containers.remove("diorama");
        }
        if phase == "image-mismatch" {
            engine.containers.get_mut("diorama").unwrap().0 = "unrelated:v1.3.0".into();
        }
        {
            let mut backend = ContainerBackend::new("docker", installed, &mut engine)
                .with_spec_path(spec_path.clone());
            let recovery_config = (phase == "commit-restore-failure").then_some(config.as_path());
            let outcome = recover_interrupted_upgrade(
                &mut backend,
                dir.path(),
                recovery_config,
                &mut Vec::new(),
            );
            if phase == "committing" {
                assert!(outcome.unwrap_err().to_string().contains("commit failed"));
            } else if matches!(
                phase,
                "stop-failure"
                    | "image-mismatch"
                    | "old-stop-failure"
                    | "old-stop-unconfirmed"
                    | "commit-restore-failure"
            ) {
                assert!(outcome.is_err());
            } else if matches!(phase, "committed-crash" | "committing-old-running") {
                assert!(matches!(
                    outcome.unwrap(),
                    RecoveryOutcome::Committed { .. }
                ));
            } else {
                assert!(matches!(
                    outcome.unwrap(),
                    RecoveryOutcome::RolledBack { .. }
                ));
            }
        }
        if phase == "commit-restore-failure" {
            assert!(dir.path().join(".upgrade-pending").is_file());
            assert!(!receipt.exists());
            assert!(!engine.containers.contains_key("diorama-pre-upgrade"));
            assert_eq!(engine.containers["diorama"], (spec.image.clone(), false));
            fs::create_dir(config.parent().unwrap()).unwrap();
            let installed = ContainerSpec::parse(&fs::read_to_string(&spec_path).unwrap()).unwrap();
            let mut backend = ContainerBackend::new("docker", installed, &mut engine)
                .with_spec_path(spec_path.clone());
            assert!(matches!(
                recover_interrupted_upgrade(
                    &mut backend,
                    dir.path(),
                    Some(&config),
                    &mut Vec::new()
                )
                .unwrap(),
                RecoveryOutcome::RolledBack { .. }
            ));
            assert_eq!(fs::read(config).unwrap(), b"old-config");
            assert_eq!(engine.containers["diorama"], (spec.image, true));
            assert_eq!(
                fs::read(dir.path().join("kine/db/state.db")).unwrap(),
                b"old-db"
            );
            assert!(!dir.path().join(".upgrade-pending").exists());
        } else if matches!(
            phase,
            "stop-failure" | "image-mismatch" | "old-stop-failure" | "old-stop-unconfirmed"
        ) {
            assert!(receipt.exists());
            assert_eq!(
                fs::read(dir.path().join("kine/db/state.db")).unwrap(),
                b"dirty"
            );
            assert!(engine.containers.contains_key("diorama-pre-upgrade"));
            if matches!(phase, "old-stop-failure" | "old-stop-unconfirmed") {
                assert!(engine.containers.contains_key("diorama"));
                assert!(!engine.calls.iter().any(|args| args[0] == "rm"));
            }
        } else if matches!(phase, "committed-crash" | "committing-old-running") {
            assert!(!receipt.exists());
            assert!(!engine.containers.contains_key("diorama-pre-upgrade"));
            assert_eq!(
                fs::read(dir.path().join("kine/db/state.db")).unwrap(),
                b"dirty"
            );
            assert_eq!(
                ContainerSpec::parse(&fs::read_to_string(&spec_path).unwrap())
                    .unwrap()
                    .tag(),
                Some("v1.3.0")
            );
        } else if phase == "committing" {
            assert!(receipt.exists(), "failed commit must preserve marker");
            assert!(engine.containers.contains_key("diorama-pre-upgrade"));
            engine.fail_commit = false;
            let installed = ContainerSpec::parse(&fs::read_to_string(&spec_path).unwrap()).unwrap();
            let mut backend = ContainerBackend::new("docker", installed, &mut engine)
                .with_spec_path(spec_path.clone());
            assert!(matches!(
                recover_interrupted_upgrade(&mut backend, dir.path(), None, &mut Vec::new())
                    .unwrap(),
                RecoveryOutcome::Committed { .. }
            ));
            assert!(!receipt.exists());
        } else {
            assert!(!receipt.exists());
            assert!(!dir.path().join(".upgrade-committing").exists());
            assert_eq!(engine.containers["diorama"], (spec.image, true));
            assert!(!engine.containers.contains_key("diorama-pre-upgrade"));
            assert_eq!(
                fs::read(dir.path().join("kine/db/state.db")).unwrap(),
                b"old-db"
            );
        }
    }
}

#[test]
fn recovery_rejects_foreign_backup_before_backend_calls() {
    let dir = data();
    let foreign = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(".upgrade-pending"),
        format!(
            "from=v1.2.0\ntarget=v1.3.0\nbackup={}\n",
            foreign.path().display()
        ),
    )
    .unwrap();
    let mut runner = Recorded::default();
    let mut backend = HostBackend {
        binary: dir.path().join("binary"),
        staged: PathBuf::new(),
        service: "kubesolo".into(),
        runner: &mut runner,
        systemd: true,
        service_file: None,
        legacy_config: None,
    };
    let error = dioramactl::upgrade::recover_interrupted_upgrade(
        &mut backend,
        dir.path(),
        None,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("outside the owned backup directory")
    );
    drop(backend);
    assert!(runner.calls.is_empty());
    assert!(dir.path().join(".upgrade-pending").exists());
}

#[test]
fn upgrade_recovery_flag_is_explicit_and_defaults_to_normal_upgrade() {
    use dioramactl::{Command, parse_command};
    let args = |tokens: &[&str]| tokens.iter().map(|s| (*s).into()).collect::<Vec<String>>();
    let environment = std::collections::BTreeMap::default();
    assert!(
        matches!(parse_command(&args(&["upgrade", "--recover", "--path", "/owned"]), &environment).unwrap(), Command::Upgrade(options) if options.recover && options.path == Path::new("/owned"))
    );
    assert!(
        matches!(parse_command(&args(&["upgrade", "--recover=false"]), &environment).unwrap(), Command::Upgrade(options) if !options.recover)
    );
    assert!(
        matches!(parse_command(&args(&["upgrade"]), &environment).unwrap(), Command::Upgrade(options) if !options.recover)
    );
}
