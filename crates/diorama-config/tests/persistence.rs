use diorama_config::{API_VERSION, Config, KIND, PersistenceStage, read_file, write_document};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "diorama-write-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("owned test directory");
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("config.yaml")
    }
}
impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn entries(path: &Path) -> Vec<String> {
    let mut values: Vec<_> = fs::read_dir(path)
        .expect("read owned directory")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    values.sort();
    values
}
fn mode(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}
#[test]
fn replacement_backs_up_exact_bytes_and_fills_metadata_without_mutating_input() {
    let root = OwnedDirectory::new();
    let path = root.path();
    let old = b"# exact comments\nnetwork: {mtu: 1250}\n";
    fs::write(&path, old).unwrap();
    let before = fs::metadata(&path).unwrap().ino();
    let mut config = Config::default();
    config.api_version.clear();
    config.kind.clear();
    let outcome = write_document(&path, &config).unwrap();
    assert!(outcome.backup_created);
    assert!(config.api_version.is_empty());
    assert!(config.kind.is_empty());
    assert_eq!(fs::read(root.0.join("config.yaml.bak")).unwrap(), old);
    let loaded = read_file(&path).unwrap().unwrap();
    assert_eq!(loaded.config.api_version, API_VERSION);
    assert_eq!(loaded.config.kind, KIND);
    assert_ne!(fs::metadata(&path).unwrap().ino(), before);
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&root.0.join("config.yaml.bak")), 0o600);
    assert_eq!(entries(&root.0), ["config.yaml", "config.yaml.bak"]);
}
#[test]
fn first_write_creates_nested_parent_without_backup() {
    let root = OwnedDirectory::new();
    let path = root.0.join("nested/config.yaml");
    assert!(
        !write_document(&path, &Config::default())
            .unwrap()
            .backup_created
    );
    assert_eq!(entries(path.parent().unwrap()), ["config.yaml"]);
}
#[test]
fn destination_symlink_is_replaced_and_referent_preserved() {
    let root = OwnedDirectory::new();
    let path = root.path();
    let other = root.0.join("other");
    fs::write(&other, b"# original referent\n").unwrap();
    symlink("other", &path).unwrap();
    write_document(&path, &Config::default()).unwrap();
    assert!(
        !fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&other).unwrap(), b"# original referent\n");
    assert_eq!(
        fs::read(root.0.join("config.yaml.bak")).unwrap(),
        b"# original referent\n"
    );
}
#[test]
fn backup_links_are_replaced_without_changing_referents() {
    for hard in [false, true] {
        let root = OwnedDirectory::new();
        let path = root.path();
        let backup = root.0.join("config.yaml.bak");
        let other = root.0.join("other");
        fs::write(&path, b"old exact bytes").unwrap();
        fs::write(&other, b"sentinel").unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o644)).unwrap();
        if hard {
            fs::hard_link(&other, &backup).unwrap();
        } else {
            symlink("other", &backup).unwrap();
        }
        write_document(&path, &Config::default()).unwrap();
        assert_eq!(fs::read(&other).unwrap(), b"sentinel");
        assert_eq!(mode(&other), 0o644);
        assert_eq!(fs::read(&backup).unwrap(), b"old exact bytes");
        assert_eq!(mode(&backup), 0o600);
        assert!(fs::symlink_metadata(&backup).unwrap().is_file());
        assert_ne!(
            fs::metadata(&backup).unwrap().ino(),
            fs::metadata(&other).unwrap().ino()
        );
        assert_eq!(
            entries(&root.0),
            ["config.yaml", "config.yaml.bak", "other"]
        );
    }
}
#[test]
fn directory_and_invalid_parent_errors_preserve_originals_and_cleanup() {
    let root = OwnedDirectory::new();
    let path = root.path();
    fs::write(&path, b"old").unwrap();
    fs::create_dir(root.0.join("config.yaml.bak")).unwrap();
    let error = write_document(&path, &Config::default()).unwrap_err();
    assert_eq!(error.stage, PersistenceStage::RenameBackup);
    assert!(!error.committed);
    assert!(error.cleanup_failures.is_empty());
    assert_eq!(fs::read(&path).unwrap(), b"old");
    assert_eq!(entries(&root.0), ["config.yaml", "config.yaml.bak"]);
    let error = write_document(&path.join("nested"), &Config::default()).unwrap_err();
    assert_eq!(error.stage, PersistenceStage::CreateDirectory);
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(
        !write_document(&path, &Config::default())
            .unwrap_err()
            .committed
    );
    assert!(path.is_dir());
    assert_eq!(entries(&root.0), ["config.yaml", "config.yaml.bak"]);
}
#[test]
fn restrictive_umask_runs_in_separate_process() {
    let root = OwnedDirectory::new();
    let status = std::process::Command::new("sh")
        .args([
            "-c",
            "umask 0777; exec \"$1\" --exact persistence::restrictive_umask_child --nocapture",
            "diorama-owned-test",
        ])
        .arg(std::env::current_exe().unwrap())
        .env("diorama_PERSISTENCE_TEST_DIRECTORY", &root.0)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(mode(&root.path()), 0o600);
    assert_eq!(mode(&root.0.join("config.yaml.bak")), 0o600);
}
#[test]
fn restrictive_umask_child() {
    let Some(root) = std::env::var_os("diorama_PERSISTENCE_TEST_DIRECTORY") else {
        return;
    };
    let root = PathBuf::from(root);
    let path = root.join("config.yaml");
    write_document(&path, &Config::default()).unwrap();
    let backup = root.join("config.yaml.bak");
    fs::write(&backup, b"prior backup").unwrap();
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o644)).unwrap();
    write_document(&path, &Config::default()).unwrap();
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&backup), 0o600);
}

#[test]
fn persisted_yaml_matches_independent_go_writer_document() {
    let reference: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tools/parity/fixtures/config-api/config.json"
    ))
    .unwrap();
    let root = OwnedDirectory::new();
    let mut config = Config::default();
    config.portainer.edge_key = "fixture-synthetic-key".into();
    write_document(&root.path(), &config).unwrap();
    // Captured Go documents use `/var/lib/kubesolo`. diorama persists `/var/lib/diorama`.
    let diorama_path = |document: &str| document.replace("/var/lib/kubesolo", "/var/lib/diorama");
    assert_eq!(
        fs::read_to_string(root.path()).unwrap(),
        diorama_path(reference[0]["first"].as_str().unwrap())
    );
    config.network.mtu = 1400;
    write_document(&root.path(), &config).unwrap();
    assert_eq!(
        fs::read_to_string(root.path()).unwrap(),
        diorama_path(reference[0]["second"].as_str().unwrap())
    );
    assert_eq!(
        fs::read_to_string(root.0.join("config.yaml.bak")).unwrap(),
        diorama_path(reference[0]["first"].as_str().unwrap())
    );
}
