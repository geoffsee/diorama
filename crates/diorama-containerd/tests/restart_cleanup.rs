//! Integration tests for managed containerd restart cleanup boundaries.
//!
//! Validates:
//! - Disposable managed runtime state (`root/` with stale `meta.db`, `state/` with dead sockets/FIFOs)
//!   is purged across clean and crash restarts to restore pod synchronization.
//! - Preserved inputs (source image archives in `images/`, registry mirror configs in `registry/hosts.toml`,
//!   and runtime binaries) remain completely intact in custom writable roots.
//! - External and unrelated runtime data (e.g. host containerd sockets or external files) are never touched.
//! - Arbitrary pulled images stored within disposable `root/` are evicted as expected.

use diorama_config::Config;
use diorama_containerd::cleanup::{clean_stale_runtime_state, validate_cleanup_path};
use diorama_containerd::image::ImageImportConfig;
use diorama_containerd::registry::{RegistryHostFile, write_registry_hosts_toml};
use diorama_containerd::service::{ContainerdPaths, ContainerdService, ContainerdServiceOptions};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn populate_disposable_state(paths: &ContainerdPaths) -> (PathBuf, PathBuf) {
    let meta_db = paths.root_dir.join("meta.db");
    fs::write(&meta_db, b"corrupted-or-stale-bbolt-task-metadata").unwrap();

    let pulled_blob = paths
        .root_dir
        .join("io.containerd.content.v1.content")
        .join("blobs")
        .join("sha256")
        .join("abc1234");
    fs::create_dir_all(pulled_blob.parent().unwrap()).unwrap();
    fs::write(&pulled_blob, b"arbitrary-pulled-image-layer").unwrap();

    let dead_socket = paths.state_dir.join("containerd.sock");
    fs::write(&dead_socket, b"stale-socket-stub").unwrap();

    let dead_fifo = paths
        .state_dir
        .join("tasks")
        .join("dead-task-id")
        .join("init-stdin");
    fs::create_dir_all(dead_fifo.parent().unwrap()).unwrap();
    fs::write(&dead_fifo, b"dead-pipe").unwrap();

    if let Some(parent) = paths.root_dir.parent() {
        let stale_tmp = parent.join("stale_temp_file.tmp");
        fs::write(&stale_tmp, b"stale-file").unwrap();
    }

    (meta_db, pulled_blob)
}

fn populate_preserved_inputs(paths: &ContainerdPaths) -> (PathBuf, PathBuf, PathBuf) {
    let hosts_toml = paths
        .registry_hosts_dir
        .join("docker.io")
        .join("hosts.toml");
    let mut hosts = BTreeMap::new();
    hosts.insert(
        "https://mirror.internal:5000".into(),
        diorama_containerd::registry::HostEndpointConfig {
            capabilities: vec!["pull".into(), "resolve".into()],
            ..Default::default()
        },
    );
    let host_file = RegistryHostFile {
        server: Some("https://registry-1.docker.io".into()),
        host: hosts,
    };
    write_registry_hosts_toml(&paths.registry_hosts_dir, "docker.io", &host_file).unwrap();

    let coredns_archive = paths.images_dir.join("coredns.tar.gz");
    let pause_archive = paths.images_dir.join("pause.tar.gz");
    fs::write(&coredns_archive, b"archive-bytes-coredns").unwrap();
    fs::write(&pause_archive, b"archive-bytes-pause").unwrap();

    fs::write(&paths.binary_path, b"mock-containerd-binary").unwrap();
    fs::write(&paths.shim_binary_path, b"mock-shim-binary").unwrap();
    fs::write(&paths.crun_binary_path, b"mock-crun-binary").unwrap();

    (hosts_toml, coredns_archive, pause_archive)
}

#[test]
fn test_clean_stale_runtime_state_purges_disposable_and_preserves_inputs() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join("kubesolo-root");
    let paths = ContainerdPaths::from_base(&base);

    fs::create_dir_all(&paths.root_dir).unwrap();
    fs::create_dir_all(&paths.state_dir).unwrap();
    fs::create_dir_all(&paths.registry_hosts_dir).unwrap();
    fs::create_dir_all(&paths.images_dir).unwrap();
    fs::create_dir_all(paths.binary_path.parent().unwrap()).unwrap();

    let kine_dir = base.join("kine").join("db");
    let pki_dir = base.join("pki");
    fs::create_dir_all(&kine_dir).unwrap();
    fs::create_dir_all(&pki_dir).unwrap();
    fs::write(kine_dir.join("state.db"), b"mock-sqlite-or-wal-data").unwrap();
    fs::write(pki_dir.join("ca.crt"), b"mock-ca-certificate").unwrap();

    let cni_conf = base.join("containerd").join("cni").join("conf");
    fs::create_dir_all(&cni_conf).unwrap();
    let cni_config = cni_conf.join("10-bridge.conflist");
    fs::write(&cni_config, b"{\"cniVersion\":\"1.0.0\"}").unwrap();

    let (meta_db, pulled_blob) = populate_disposable_state(&paths);
    let (hosts_toml, coredns, pause) = populate_preserved_inputs(&paths);

    let run_dir = temp.path().join("run").join("containerd");
    fs::create_dir_all(&run_dir).unwrap();
    let system_socket = run_dir.join("containerd.sock");
    unix_fs::symlink(&paths.socket_path, &system_socket).unwrap();

    let report = clean_stale_runtime_state(&paths, Some(&system_socket)).unwrap();

    assert!(report.system_socket_cleaned);
    assert!(!system_socket.exists());
    assert!(!paths.root_dir.exists());
    assert!(!paths.state_dir.exists());
    assert!(!meta_db.exists());
    assert!(
        !pulled_blob.exists(),
        "pulled layer in root must be evicted"
    );

    assert!(hosts_toml.exists(), "registry hosts.toml preserved");
    assert!(coredns.exists(), "coredns archive preserved");
    assert_eq!(fs::read(&coredns).unwrap(), b"archive-bytes-coredns");
    assert!(pause.exists(), "pause archive preserved");
    assert_eq!(fs::read(&pause).unwrap(), b"archive-bytes-pause");

    assert!(paths.binary_path.exists(), "binary preserved");
    assert!(paths.shim_binary_path.exists(), "shim preserved");
    assert!(paths.crun_binary_path.exists(), "crun preserved");
    assert!(kine_dir.join("state.db").exists(), "kine db preserved");
    assert!(pki_dir.join("ca.crt").exists(), "pki ca.crt preserved");
    assert!(
        cni_config.exists(),
        "CNI conflist must survive startup cleanup"
    );
}

#[test]
fn test_unrelated_and_external_runtime_data_remains_intact() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join("kubesolo-root");
    let paths = ContainerdPaths::from_base(&base);

    let host_dir = temp.path().join("host-containerd");
    fs::create_dir_all(&host_dir).unwrap();
    let external_socket = host_dir.join("host.sock");
    fs::write(&external_socket, b"external-host-socket").unwrap();

    let run_dir = temp.path().join("run").join("containerd");
    fs::create_dir_all(&run_dir).unwrap();
    let system_socket = run_dir.join("containerd.sock");

    unix_fs::symlink(&external_socket, &system_socket).unwrap();
    let report = clean_stale_runtime_state(&paths, Some(&system_socket)).unwrap();

    assert!(!report.system_socket_cleaned);
    assert!(system_socket.exists(), "external link must not be removed");
    assert_eq!(fs::read_link(&system_socket).unwrap(), external_socket);

    fs::remove_file(&system_socket).unwrap();
    fs::write(&system_socket, b"real-file-or-socket").unwrap();

    let report = clean_stale_runtime_state(&paths, Some(&system_socket)).unwrap();
    assert!(!report.system_socket_cleaned);
    assert!(
        system_socket.exists(),
        "real host socket must not be removed"
    );
    assert_eq!(fs::read(&system_socket).unwrap(), b"real-file-or-socket");
}

#[test]
fn test_unsafe_paths_validation() {
    assert!(validate_cleanup_path(Path::new("")).is_err());
    assert!(validate_cleanup_path(Path::new("/")).is_err());
    assert!(validate_cleanup_path(Path::new("/usr")).is_err());
    assert!(validate_cleanup_path(Path::new("/etc")).is_err());
    assert!(validate_cleanup_path(Path::new("/var")).is_err());

    assert!(validate_cleanup_path(Path::new("/var/lib/diorama/containerd/root")).is_ok());
    assert!(validate_cleanup_path(Path::new("/mnt/data/custom/state")).is_ok());
}

#[test]
fn test_clean_crash_restart_recovers_pod_synchronization() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join("custom-writable-root");
    let paths = ContainerdPaths::from_base(&base);

    let image_config = ImageImportConfig::from_config(&Config::default(), &paths.images_dir);
    let options = ContainerdServiceOptions::new(paths.clone(), image_config.clone());
    let service = ContainerdService::new(options);

    service.prepare().unwrap();
    assert!(paths.root_dir.exists());
    assert!(paths.state_dir.exists());
    assert!(paths.config_path.exists());

    fs::create_dir_all(&paths.images_dir).unwrap();
    fs::write(
        paths.images_dir.join("coredns.tar.gz"),
        b"mock-coredns-archive",
    )
    .unwrap();
    let mut hosts = BTreeMap::new();
    hosts.insert(
        "https://registry.local".into(),
        diorama_containerd::registry::HostEndpointConfig {
            capabilities: vec!["pull".into(), "resolve".into()],
            ..Default::default()
        },
    );
    let host_file = RegistryHostFile {
        server: Some("https://registry-1.docker.io".into()),
        host: hosts,
    };
    write_registry_hosts_toml(&paths.registry_hosts_dir, "docker.io", &host_file).unwrap();

    let meta_db = paths.root_dir.join("meta.db");
    fs::write(&meta_db, b"stale-tasks-causing-pod-sync-failure").unwrap();

    let dead_task_sock = paths.state_dir.join("task-dead.sock");
    fs::write(&dead_task_sock, b"stale-socket").unwrap();

    let restart_service =
        ContainerdService::new(ContainerdServiceOptions::new(paths.clone(), image_config));
    restart_service.prepare().unwrap();

    assert!(paths.root_dir.exists(), "fresh root_dir recreated");
    assert!(paths.state_dir.exists(), "fresh state_dir recreated");
    assert!(
        !meta_db.exists(),
        "stale meta.db must be purged to recover pod synchronization"
    );
    assert!(!dead_task_sock.exists(), "dead task socket must be purged");

    assert!(paths.images_dir.join("coredns.tar.gz").exists());
    assert!(
        paths
            .registry_hosts_dir
            .join("docker.io")
            .join("hosts.toml")
            .exists()
    );
    assert!(paths.config_path.exists(), "config.toml freshly generated");
}
