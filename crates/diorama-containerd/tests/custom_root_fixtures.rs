//! Integration tests asserting that custom root directories operate without
//! global binary/shim/CNI-plugin symlinks and respect compatibility links.

use std::fs;
use tempfile::TempDir;

use diorama_containerd::{
    ContainerdConfigOptions, ContainerdServicePaths, Snapshotter, ensure_system_socket_link,
    generate_containerd_config, render_containerd_config, select_snapshotter,
    write_containerd_config_file,
};

#[test]
fn custom_root_is_completely_self_contained() {
    let temp = TempDir::new().unwrap();
    let custom_root = temp.path().join("isolated_workspace/custom_diorama");

    let paths = ContainerdServicePaths::from_base_dir(&custom_root);
    let options = ContainerdConfigOptions {
        snapshotter: Some(Snapshotter::Overlayfs),
        systemd_cgroup: Some(false),
        sandbox_image: None,
        image_pull_timeout: None,
    };

    write_containerd_config_file(&paths, &options).expect("config write succeeds");

    // Verify all generated configuration paths stay within the custom_root
    assert!(paths.config_file.starts_with(&custom_root));
    assert!(paths.root_dir.starts_with(&custom_root));
    assert!(paths.state_dir.starts_with(&custom_root));
    assert!(paths.socket_file.starts_with(&custom_root));
    assert!(paths.registry_config_dir.starts_with(&custom_root));
    assert!(paths.cni_plugins_dir.starts_with(&custom_root));
    assert!(paths.crun_binary_file.starts_with(&custom_root));
    assert!(paths.shim_binary_file.starts_with(&custom_root));

    let config = generate_containerd_config(&paths, &options);
    let toml_str = render_containerd_config(&config).unwrap();

    // Confirm rendered paths match custom root
    assert!(toml_str.contains(&format!("root = \"{}\"", paths.root_dir.display())));
    assert!(toml_str.contains(&format!("state = \"{}\"", paths.state_dir.display())));
    assert!(toml_str.contains(&format!("address = \"{}\"", paths.socket_file.display())));
    assert!(toml_str.contains(&format!(
        "config_path = \"{}\"",
        paths.registry_config_dir.display()
    )));
    assert!(toml_str.contains(&format!(
        "BinaryName = \"{}\"",
        paths.crun_binary_file.display()
    )));
    assert!(toml_str.contains(&format!(
        "bin_dirs = [\"{}\"]",
        paths.cni_plugins_dir.display()
    )));

    // Confirm absence of hardcoded /usr/local/bin or /opt/cni symlinks in config
    assert!(!toml_str.contains("/usr/local/bin/runc"));
    assert!(!toml_str.contains("/usr/local/bin/containerd-shim-runc-v2"));
    assert!(!toml_str.contains("/opt/cni/bin"));
}

#[test]
fn socket_compatibility_link_is_idempotent_and_preserves_correct_link() {
    let temp = TempDir::new().unwrap();
    let managed_sock = temp.path().join("containerd/containerd.sock");
    fs::create_dir_all(managed_sock.parent().unwrap()).unwrap();
    fs::write(&managed_sock, b"").unwrap();

    let compat_sock = temp.path().join("run/containerd/containerd.sock");

    // 1. Initial creation of compatibility link
    ensure_system_socket_link(&managed_sock, Some(&compat_sock)).unwrap();
    assert_eq!(fs::read_link(&compat_sock).unwrap(), managed_sock);

    // 2. Second invocation preserves existing correct link without failing or modifying
    ensure_system_socket_link(&managed_sock, Some(&compat_sock)).unwrap();
    assert_eq!(fs::read_link(&compat_sock).unwrap(), managed_sock);

    // 3. Stale or incorrect link gets updated
    let other_sock = temp.path().join("other.sock");
    fs::write(&other_sock, b"").unwrap();
    ensure_system_socket_link(&other_sock, Some(&compat_sock)).unwrap();
    assert_eq!(fs::read_link(&compat_sock).unwrap(), other_sock);
}

#[test]
fn snapshotter_selection_across_filesystem_fixtures() {
    // Normal host: overlayfs
    assert_eq!(select_snapshotter(false, false), Snapshotter::Overlayfs);
    assert_eq!(select_snapshotter(false, true), Snapshotter::Overlayfs);

    // Overlayfs root (e.g. Alpine live-boot) with fuse-overlayfs helper: fuse-overlayfs
    assert_eq!(select_snapshotter(true, true), Snapshotter::FuseOverlayfs);

    // Overlayfs root without fuse-overlayfs helper: fallback to native
    assert_eq!(select_snapshotter(true, false), Snapshotter::Native);
}
