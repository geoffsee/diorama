use dioramactl::cleanup::{
    CleanupHost, CleanupKind, ConfigurationSelection, run_container_cleanup,
    run_container_cleanup_with_configuration, run_container_cleanup_with_selection,
    run_host_cleanup, run_host_cleanup_with_configuration,
};
use dioramactl::upgrade::{ContainerSpec, Runner};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Default)]
struct Host {
    calls: Vec<&'static str>,
    fail_stop: bool,
}
impl CleanupHost for Host {
    fn stop_service(&mut self) -> io::Result<()> {
        self.calls.push("stop");
        if self.fail_stop {
            Err(io::Error::other("stop failed"))
        } else {
            Ok(())
        }
    }
    fn start_service(&mut self) -> io::Result<()> {
        self.calls.push("start");
        Ok(())
    }
    fn mounts_under(&mut self, _: &Path) -> io::Result<Vec<PathBuf>> {
        Ok(vec![])
    }
    fn unmount(&mut self, _: &Path) -> io::Result<()> {
        Ok(())
    }
    fn remove_service_artifacts(&mut self) -> io::Result<Vec<PathBuf>> {
        self.calls.push("artifacts");
        Ok(vec![])
    }
}
#[derive(Debug, Default)]
struct Engine {
    fail_remove: bool,
}
impl Runner for Engine {
    fn run(&mut self, _: &str, args: &[String]) -> io::Result<String> {
        if self.fail_remove && args[0] == "rm" {
            Err(io::Error::other("remove failed"))
        } else {
            Ok(String::new())
        }
    }
}
fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let configuration = root.path().join("configuration");
    fs::create_dir_all(data.join("pki")).unwrap();
    fs::create_dir(&configuration).unwrap();
    fs::write(configuration.join("config.yaml"), "desired config").unwrap();
    fs::write(configuration.join("config.yaml.bak"), "previous config").unwrap();
    fs::write(configuration.join("foreign"), "neighbor").unwrap();
    let data = fs::canonicalize(data).unwrap();
    let configuration = fs::canonicalize(configuration).unwrap();
    (root, data, configuration)
}

#[test]
fn file_bind_cleanup_preserves_adjacent_backups_and_uses_exact_source() {
    for purge in [false, true] {
        for keep_config in [false, true] {
            let (_root, data, configuration) = fixture();
            let selected = configuration.join("custom.yaml");
            fs::rename(configuration.join("config.yaml"), &selected).unwrap();
            fs::write(configuration.join("custom.yaml.bak"), "foreign backup").unwrap();
            let report = run_container_cleanup_with_selection(
                &mut Engine::default(),
                "docker",
                &ContainerSpec::default(),
                CleanupKind::Uninstall { purge, keep_config },
                &data,
                Some(&ConfigurationSelection::File(selected.clone())),
                true,
                &mut &b""[..],
                &mut Vec::new(),
            )
            .unwrap();
            assert_eq!(selected.exists(), keep_config);
            assert_eq!(report.removed.contains(&selected), !keep_config);
            assert_eq!(report.retained.contains(&selected), keep_config);
            assert_eq!(
                fs::read_to_string(configuration.join("config.yaml.bak")).unwrap(),
                "previous config"
            );
            assert_eq!(
                fs::read_to_string(configuration.join("custom.yaml.bak")).unwrap(),
                "foreign backup"
            );
            assert_eq!(
                fs::read_to_string(configuration.join("foreign")).unwrap(),
                "neighbor"
            );
        }
    }
}
#[test]
fn host_and_container_share_explicit_configuration_retention() {
    for (container, purge, keep_config) in [
        (false, false, false),
        (false, false, true),
        (false, true, false),
        (false, true, true),
        (true, false, false),
        (true, false, true),
        (true, true, false),
        (true, true, true),
    ] {
        let (_root, data, configuration) = fixture();
        let kind = CleanupKind::Uninstall { purge, keep_config };
        let report = if container {
            run_container_cleanup_with_configuration(
                &mut Engine::default(),
                "docker",
                &ContainerSpec::default(),
                kind,
                &data,
                Some(&configuration),
                true,
                &mut io::empty(),
                &mut vec![],
            )
        } else {
            run_host_cleanup_with_configuration(
                &mut Host::default(),
                kind,
                &data,
                Some(&configuration),
                true,
                &mut io::empty(),
                &mut vec![],
            )
        }
        .unwrap();
        for name in ["config.yaml", "config.yaml.bak"] {
            let path = configuration.join(name);
            assert_eq!(path.exists(), keep_config);
            assert!(if keep_config {
                report.retained.contains(&path)
            } else {
                report.removed.contains(&path)
            });
        }
        assert_eq!(
            fs::read(configuration.join("foreign")).unwrap(),
            b"neighbor"
        );
    }
}
#[test]
fn library_cleanup_without_configuration_selection_keeps_fixtures() {
    let (_root, data, configuration) = fixture();
    let kind = CleanupKind::Uninstall {
        purge: false,
        keep_config: false,
    };
    run_host_cleanup(
        &mut Host::default(),
        kind,
        &data,
        true,
        &mut io::empty(),
        &mut vec![],
    )
    .unwrap();
    run_container_cleanup(
        &mut Engine::default(),
        "docker",
        &ContainerSpec::default(),
        kind,
        &data,
        true,
        &mut io::empty(),
        &mut vec![],
    )
    .unwrap();
    assert!(configuration.join("config.yaml").exists());
    assert!(configuration.join("config.yaml.bak").exists());
}
#[test]
fn lifecycle_failures_and_declined_confirmation_keep_configuration() {
    let (_root, data, configuration) = fixture();
    let kind = CleanupKind::Uninstall {
        purge: true,
        keep_config: false,
    };
    let mut host = Host {
        fail_stop: true,
        ..Host::default()
    };
    assert!(
        run_host_cleanup_with_configuration(
            &mut host,
            kind,
            &data,
            Some(&configuration),
            true,
            &mut io::empty(),
            &mut vec![]
        )
        .is_err()
    );
    assert!(
        run_container_cleanup_with_configuration(
            &mut Engine { fail_remove: true },
            "docker",
            &ContainerSpec::default(),
            kind,
            &data,
            Some(&configuration),
            true,
            &mut io::empty(),
            &mut vec![]
        )
        .is_err()
    );
    host.fail_stop = false;
    host.calls.clear();
    let mut output = vec![];
    let report = run_host_cleanup_with_configuration(
        &mut host,
        kind,
        &data,
        Some(&configuration),
        false,
        &mut io::Cursor::new(b"n\n"),
        &mut output,
    )
    .unwrap();
    assert!(report.declined && host.calls.is_empty());
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains(&configuration.join("config.yaml").display().to_string())
    );
    assert!(configuration.join("config.yaml").exists());
    assert!(configuration.join("config.yaml.bak").exists());
}
#[test]
fn symlinked_configuration_parent_is_rejected_before_side_effects() {
    let (root, data, configuration) = fixture();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&configuration, &link).unwrap();
    let mut host = Host::default();
    assert!(
        run_host_cleanup_with_configuration(
            &mut host,
            CleanupKind::Uninstall {
                purge: true,
                keep_config: false
            },
            &data,
            Some(&link),
            true,
            &mut io::empty(),
            &mut vec![]
        )
        .is_err()
    );
    assert_eq!(host.calls, <[&str; 0]>::default());
    assert!(configuration.join("config.yaml").exists());
}
