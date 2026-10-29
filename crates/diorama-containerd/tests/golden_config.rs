//! Golden containerd configuration tests asserting parity with `diorama` requirements.

use diorama_containerd::{
    CONTAINERD_CONFIG_VERSION, ContainerdConfigFile, ContainerdConfigOptions,
    ContainerdServicePaths, DEFAULT_CONTAINERD_CONFIG_DIR, DEFAULT_RUNTIME_NAME,
    DEFAULT_SANDBOX_IMAGE, DEFAULT_STANDARD_CNI_CONF_DIR, RUNTIME_RUNC_V2, Snapshotter,
    generate_containerd_config, render_containerd_config,
};
use std::path::Path;

#[test]
fn golden_containerd_configuration_parity() {
    let base_dir = Path::new("/var/lib/diorama");
    let paths = ContainerdServicePaths::from_base_dir(base_dir);
    let options = ContainerdConfigOptions {
        snapshotter: Some(Snapshotter::Overlayfs),
        systemd_cgroup: Some(false),
        sandbox_image: Some(DEFAULT_SANDBOX_IMAGE.to_string()),
        image_pull_timeout: Some("2m0s".to_string()),
    };

    let config = generate_containerd_config(&paths, &options);

    // 1. Version must be 3
    assert_eq!(config.version, CONTAINERD_CONFIG_VERSION);
    assert_eq!(config.version, 3);

    // 2. Base paths
    assert_eq!(config.root, "/var/lib/diorama/containerd/root");
    assert_eq!(config.state, "/var/lib/diorama/containerd/state");
    assert_eq!(
        config.grpc.address,
        "/var/lib/diorama/containerd/containerd.sock"
    );

    // 3. Imports must include default config.d glob
    assert_eq!(
        config.imports,
        vec![format!("{DEFAULT_CONTAINERD_CONFIG_DIR}/*.toml")]
    );

    // 4. CRI images plugin
    let cri_images = &config.plugins.cri_images;
    assert_eq!(cri_images.image_pull_progress_timeout, "2m0s");
    assert_eq!(cri_images.pinned_images.sandbox, "portainer/pause:latest");
    assert_eq!(
        cri_images.registry.config_path,
        "/var/lib/diorama/containerd/registry"
    );

    // 5. CRI runtime plugin and CNI
    let cri_runtime = &config.plugins.cri_runtime;
    assert_eq!(
        cri_runtime.cni.bin_dirs,
        vec!["/var/lib/diorama/containerd/cni/plugins".to_string()]
    );
    assert_eq!(cri_runtime.cni.conf_dir, DEFAULT_STANDARD_CNI_CONF_DIR);
    assert_eq!(
        cri_runtime.containerd.default_runtime_name,
        DEFAULT_RUNTIME_NAME
    );

    // 6. Runtime definition: must retain io.containerd.runc.v2 and intended BinaryName
    let crun = cri_runtime
        .containerd
        .runtimes
        .get("crun")
        .expect("crun runtime definition must be present");

    assert_eq!(crun.runtime_type, RUNTIME_RUNC_V2);
    assert_eq!(crun.runtime_type, "io.containerd.runc.v2");

    // runtime_path MUST NOT be set
    assert!(crun.runtime_path.is_none());

    assert_eq!(crun.snapshotter, Snapshotter::Overlayfs);
    assert_eq!(crun.options.binary_name, "/var/lib/diorama/containerd/crun");
    assert!(!crun.options.systemd_cgroup);

    // 7. Task plugin platforms
    assert_eq!(
        config.plugins.task.platforms,
        vec![
            "linux/amd64".to_string(),
            "linux/arm64".to_string(),
            "linux/arm".to_string()
        ]
    );

    // 8. Render to TOML and verify exact serialization format
    let rendered = render_containerd_config(&config).expect("serialization succeeds");

    // Verify key TOML fragments
    assert!(rendered.contains("version = 3\n"));
    assert!(rendered.contains("root = \"/var/lib/diorama/containerd/root\"\n"));
    assert!(rendered.contains("state = \"/var/lib/diorama/containerd/state\"\n"));
    assert!(rendered.contains("imports = [\"/etc/containerd/config.d/*.toml\"]\n"));
    assert!(rendered.contains("address = \"/var/lib/diorama/containerd/containerd.sock\"\n"));
    assert!(rendered.contains("[plugins.\"io.containerd.cri.v1.images\"]\n"));
    assert!(rendered.contains("image_pull_progress_timeout = \"2m0s\"\n"));
    assert!(rendered.contains("config_path = \"/var/lib/diorama/containerd/registry\"\n"));
    assert!(rendered.contains("default_runtime_name = \"crun\"\n"));
    assert!(rendered.contains("runtime_type = \"io.containerd.runc.v2\"\n"));
    assert!(rendered.contains("BinaryName = \"/var/lib/diorama/containerd/crun\"\n"));
    assert!(rendered.contains("SystemdCgroup = false\n"));

    // Ensure runtime_path does NOT appear anywhere in the rendered TOML
    assert!(
        !rendered.contains("runtime_path"),
        "rendered TOML must NOT contain runtime_path"
    );

    // Roundtrip verification: parse rendered TOML back into ContainerdConfigFile
    let parsed: ContainerdConfigFile =
        toml::from_str(&rendered).expect("rendered TOML must parse cleanly");
    assert_eq!(parsed, config);
}

#[test]
fn golden_config_with_systemd_cgroup_enabled() {
    let base_dir = Path::new("/var/lib/diorama");
    let paths = ContainerdServicePaths::from_base_dir(base_dir);
    let options = ContainerdConfigOptions {
        snapshotter: Some(Snapshotter::FuseOverlayfs),
        systemd_cgroup: Some(true),
        sandbox_image: None,
        image_pull_timeout: None,
    };

    let config = generate_containerd_config(&paths, &options);
    let crun = &config.plugins.cri_runtime.containerd.runtimes["crun"];
    assert_eq!(crun.snapshotter, Snapshotter::FuseOverlayfs);
    assert!(crun.options.systemd_cgroup);

    let rendered = render_containerd_config(&config).unwrap();
    assert!(rendered.contains("SystemdCgroup = true\n"));
    assert!(rendered.contains("snapshotter = \"fuse-overlayfs\"\n"));
    assert!(!rendered.contains("runtime_path"));
}
