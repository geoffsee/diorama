//! Integration tests for managed containerd runtime fixtures:
//! Ordinary host, Alpine host, Nested container, and Overlay root.

use diorama_config::Config;
use diorama_containerd::cgroup::evaluate_systemd_cgroup;
use diorama_containerd::config::{
    ContainerdConfigOptions, generate_containerd_config, render_containerd_config,
};
use diorama_containerd::image::ImageImportConfig;
use diorama_containerd::service::{ContainerdPaths, ContainerdService, ContainerdServiceOptions};
use diorama_containerd::snapshotter::{Snapshotter, select_snapshotter};
use tempfile::TempDir;

#[test]
fn ordinary_fixture_runtime_detection_and_config() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join("ordinary_host");
    let paths = ContainerdPaths::from_base(&base);

    // Ordinary fixture: cgroup v2 available, systemd running, ext4/xfs (not overlayfs)
    let systemd_cgroup = evaluate_systemd_cgroup(true, true);
    assert!(
        systemd_cgroup,
        "Ordinary host with systemd + cgroup v2 must enable SystemdCgroup"
    );

    let snapshotter = select_snapshotter(false, false);
    assert_eq!(snapshotter, Snapshotter::Overlayfs);

    let service_paths = paths.to_service_paths();
    let options = ContainerdConfigOptions {
        snapshotter: Some(snapshotter),
        systemd_cgroup: Some(systemd_cgroup),
        sandbox_image: None,
        image_pull_timeout: None,
    };

    let config = generate_containerd_config(&service_paths, &options);
    let toml = render_containerd_config(&config).unwrap();

    assert!(toml.contains("snapshotter = \"overlayfs\""));
    assert!(toml.contains("SystemdCgroup = true"));
    assert!(toml.contains("runtime_type = \"io.containerd.runc.v2\""));
    assert!(!toml.contains("runtime_path"));

    // Verify default image selection
    let default_config = Config::default();
    let img_config = ImageImportConfig::from_config(&default_config, &paths.images_dir);
    let enabled = img_config.enabled_targets();
    let refs: Vec<&str> = enabled.iter().map(|t| t.reference.as_str()).collect();

    assert!(refs.contains(&"docker.io/coredns/coredns:1.14.4"));
    assert!(refs.contains(&"docker.io/portainer/pause:latest"));
    assert!(refs.contains(&"docker.io/rancher/local-path-provisioner:v0.0.36"));
    assert!(refs.contains(&"docker.io/library/busybox:latest"));
}

#[test]
fn alpine_fixture_runtime_detection_and_config() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join("alpine_host");
    let paths = ContainerdPaths::from_base(&base);

    // Alpine fixture: OpenRC init (systemd is not running)
    let systemd_cgroup = evaluate_systemd_cgroup(true, false);
    assert!(
        !systemd_cgroup,
        "Alpine with OpenRC must not use SystemdCgroup"
    );

    let snapshotter = select_snapshotter(false, false);
    assert_eq!(snapshotter, Snapshotter::Overlayfs);

    let service_paths = paths.to_service_paths();
    let options = ContainerdConfigOptions {
        snapshotter: Some(snapshotter),
        systemd_cgroup: Some(systemd_cgroup),
        sandbox_image: None,
        image_pull_timeout: None,
    };

    let config = generate_containerd_config(&service_paths, &options);
    let toml = render_containerd_config(&config).unwrap();

    assert!(toml.contains("SystemdCgroup = false"));
    assert!(toml.contains("snapshotter = \"overlayfs\""));
}

#[test]
fn nested_container_fixture_runtime_detection_and_config() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join("nested_container");
    let paths = ContainerdPaths::from_base(&base);

    // Nested-container fixture: root is on overlayfs, systemd is not running, fuse-overlayfs is present
    let is_root_overlay = true;
    let fuse_overlayfs_present = true;
    let snapshotter = select_snapshotter(is_root_overlay, fuse_overlayfs_present);
    assert_eq!(
        snapshotter,
        Snapshotter::FuseOverlayfs,
        "Nested container on overlay rootfs with fuse-overlayfs installed must select fuse-overlayfs"
    );

    let systemd_cgroup = evaluate_systemd_cgroup(true, false);
    assert!(
        !systemd_cgroup,
        "Container environment without systemd must use cgroupfs"
    );

    let service_paths = paths.to_service_paths();
    let options = ContainerdConfigOptions {
        snapshotter: Some(snapshotter),
        systemd_cgroup: Some(systemd_cgroup),
        sandbox_image: None,
        image_pull_timeout: None,
    };

    let config = generate_containerd_config(&service_paths, &options);
    let toml = render_containerd_config(&config).unwrap();

    assert!(toml.contains("snapshotter = \"fuse-overlayfs\""));
    assert!(toml.contains("SystemdCgroup = false"));
}

#[test]
fn overlay_root_without_fuse_fallback() {
    let temp = TempDir::new().unwrap();
    let base = temp.path().join("overlay_root_no_fuse");
    let paths = ContainerdPaths::from_base(&base);

    // Overlay root without fuse-overlayfs available in PATH falls back to native snapshotter
    let is_root_overlay = true;
    let fuse_overlayfs_present = false;
    let snapshotter = select_snapshotter(is_root_overlay, fuse_overlayfs_present);
    assert_eq!(
        snapshotter,
        Snapshotter::Native,
        "Overlay root without fuse-overlayfs must fall back to native snapshotter"
    );

    let service_paths = paths.to_service_paths();
    let options = ContainerdConfigOptions {
        snapshotter: Some(snapshotter),
        systemd_cgroup: Some(false),
        sandbox_image: None,
        image_pull_timeout: None,
    };

    let config = generate_containerd_config(&service_paths, &options);
    let toml = render_containerd_config(&config).unwrap();

    assert!(toml.contains("snapshotter = \"native\""));
    assert!(toml.contains("SystemdCgroup = false"));
}

#[test]
fn custom_writable_root_fixture_service_preparation() {
    let temp = TempDir::new().unwrap();
    let custom_base = temp.path().join("opt/diorama-instance");

    let paths = ContainerdPaths::from_base(&custom_base);
    let default_config = Config::default();
    let image_config = ImageImportConfig::from_config(&default_config, &paths.images_dir);

    let service_options = ContainerdServiceOptions::new(paths.clone(), image_config);
    let service = ContainerdService::new(service_options);

    // Prepare directories and config file
    service.prepare().expect("service prepare should succeed");

    assert!(paths.root_dir.is_dir());
    assert!(paths.state_dir.is_dir());
    assert!(paths.registry_hosts_dir.is_dir());
    assert!(paths.config_path.is_file());

    let content = std::fs::read_to_string(&paths.config_path).unwrap();
    assert!(content.contains(&format!("root = \"{}\"", paths.root_dir.display())));
    assert!(content.contains(&format!("state = \"{}\"", paths.state_dir.display())));
}
