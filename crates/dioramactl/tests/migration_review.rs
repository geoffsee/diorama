use dioramactl::migrate::migrate_legacy_service;
use std::fs;

#[test]
fn whole_token_quoted_paths_with_spaces_are_rejected_before_publication() {
    for argument in ["\"--path=/data/my dir\"", "'--path=/data/my dir'"] {
        let directory = tempfile::tempdir().unwrap();
        let service = directory.path().join("node.service");
        let config = directory.path().join("config.yaml");
        let original = format!("ExecStart=/usr/local/bin/diorama {argument}\n");
        fs::write(&service, &original).unwrap();
        assert!(
            migrate_legacy_service(&service, Some(&config), "v1.3.0", None, &mut Vec::new())
                .is_err()
        );
        assert_eq!(fs::read_to_string(&service).unwrap(), original);
        assert!(!config.exists());
        assert!(!directory.path().join("node.service.bak").exists());
        assert!(
            !directory
                .path()
                .join("node.service.migration-pending")
                .exists()
        );
    }
}

#[test]
fn backup_obstruction_preserves_files_and_allows_retry() {
    let dir = tempfile::tempdir().unwrap();
    let service = dir.path().join("node.service");
    let config = dir.path().join("config.yaml");
    let backup = dir.path().join("node.service.bak");
    let original = "ExecStart=/usr/local/bin/diorama --debug --node-ip 10.0.0.1\n";
    fs::write(&service, original).unwrap();
    fs::create_dir(&backup).unwrap();
    assert!(
        migrate_legacy_service(&service, Some(&config), "v1.3.0", None, &mut Vec::new()).is_err()
    );
    assert!(!config.exists());
    assert_eq!(fs::read_to_string(&service).unwrap(), original);
    fs::remove_dir(backup).unwrap();
    migrate_legacy_service(&service, Some(&config), "v1.3.0", None, &mut Vec::new()).unwrap();
    assert!(config.exists());
    assert!(fs::read_to_string(service).unwrap().contains("--config="));
}

#[cfg(unix)]
#[test]
fn symlink_backup_and_predictable_temp_cannot_overwrite_unrelated_files() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let service = dir.path().join("node.service");
    let config = dir.path().join("config.yaml");
    let backup = dir.path().join("node.service.bak");
    let victim = dir.path().join("unrelated");
    fs::write(&victim, "private").unwrap();
    fs::write(&service, "ExecStart=/usr/local/bin/diorama --debug\n").unwrap();
    symlink(&victim, &backup).unwrap();
    let predictable = dir
        .path()
        .join(format!(".diorama.service.tmp-{}", std::process::id()));
    symlink(&victim, &predictable).unwrap();
    assert!(
        migrate_legacy_service(&service, Some(&config), "v1.3.0", None, &mut Vec::new()).is_err()
    );
    assert_eq!(fs::read_to_string(&victim).unwrap(), "private");
    assert!(!config.exists());
    fs::remove_file(backup).unwrap();
    migrate_legacy_service(&service, Some(&config), "v1.3.0", None, &mut Vec::new()).unwrap();
    assert_eq!(fs::read_to_string(&victim).unwrap(), "private");
    assert!(
        fs::symlink_metadata(&predictable)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn interrupted_publication_resumes_only_matching_pending_migration() {
    let dir = tempfile::tempdir().unwrap();
    let service = dir.path().join("node.service");
    let config = dir.path().join("config.yaml");
    let marker = dir.path().join("node.service.migration-pending");
    let original = "ExecStart=/usr/local/bin/diorama --debug\n";
    fs::write(&service, original).unwrap();
    fs::write(dir.path().join("node.service.bak"), original).unwrap();
    let extracted = diorama_config::legacy::extract_service_flags(original);
    let yaml = diorama_config::legacy::render_config_from_flags(&extracted, None).unwrap();
    fs::write(&config, &yaml).unwrap();
    fs::write(&marker, &yaml).unwrap();
    migrate_legacy_service(&service, Some(&config), "v1.3.0", None, &mut Vec::new()).unwrap();
    assert!(fs::read_to_string(&service).unwrap().contains("--config="));
    assert!(!marker.exists());
    assert_eq!(fs::read_to_string(config).unwrap(), yaml);
}
#[cfg(unix)]
#[test]
fn library_migration_preserves_a_dangling_destination_link() {
    use diorama_config::legacy::{MigrationOutcome, migrate_service_flags};
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("config.yaml");
    let absent = directory.path().join("absent.yaml");
    std::os::unix::fs::symlink(&absent, &destination).unwrap();
    assert_eq!(
        migrate_service_flags("exec diorama --debug", Some(&destination), None).unwrap(),
        MigrationOutcome::DestinationConfigExists
    );
    assert_eq!(std::fs::read_link(destination).unwrap(), absent);
    assert!(!absent.exists());
}
