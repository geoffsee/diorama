//! Integration tests for image import selection, enabled/disabled handling,
//! and registry pull fallback behaviors.

use diorama_assets::AssetId;
use diorama_config::Config;
use diorama_containerd::image::{DEFAULT_PORTAINER_AGENT_IMAGE, ImageImportConfig};
use std::fs;
use tempfile::TempDir;

#[test]
fn local_path_uses_public_image_unless_a_nonempty_archive_is_available() {
    let temp = TempDir::new().unwrap();
    let config = ImageImportConfig::new(temp.path());
    let selected = || {
        config
            .enabled_targets()
            .into_iter()
            .find(|target| target.id == AssetId::ImageLocalPath)
            .unwrap()
            .reference
    };
    let public = "docker.io/rancher/local-path-provisioner:v0.0.36";
    assert_eq!(selected(), public);
    let archive = temp.path().join("local-path-provisioner.tar.gz");
    fs::write(&archive, b"").unwrap();
    assert_eq!(selected(), public);
    fs::write(&archive, b"bundled archive").unwrap();
    assert_eq!(
        selected(),
        "ghcr.io/geoffsee/diorama-local-path-provisioner:v0.0.36-1"
    );
    fs::remove_file(&archive).unwrap();
    fs::create_dir(&archive).unwrap();
    assert_eq!(selected(), public);
}

#[test]
fn default_config_enables_core_and_storage_images() {
    let temp = TempDir::new().unwrap();
    let config = Config::default();
    let img_config = ImageImportConfig::from_config(&config, temp.path());

    let enabled = img_config.enabled_targets();
    let enabled_ids: Vec<AssetId> = enabled.iter().map(|t| t.id).collect();

    assert!(enabled_ids.contains(&AssetId::ImageCoredns));
    assert!(enabled_ids.contains(&AssetId::ImagePause));
    assert!(enabled_ids.contains(&AssetId::ImageLocalPath));
    assert!(enabled_ids.contains(&AssetId::ImageLocalPathHelper));

    // Optional addons are disabled by default
    assert!(!enabled_ids.contains(&AssetId::ImagePortainerAgent));
    assert!(!enabled_ids.contains(&AssetId::ImageD2k));

    let disabled = img_config.disabled_targets();
    assert!(disabled.contains(&AssetId::ImagePortainerAgent));
    assert!(disabled.contains(&AssetId::ImageD2k));
    assert!(!disabled.contains(&AssetId::ImageCoredns));
    assert!(!disabled.contains(&AssetId::ImagePause));
}

#[test]
fn disabled_storage_excludes_local_path_images() {
    let temp = TempDir::new().unwrap();
    let mut config = Config::default();
    config.storage.local_path.enabled = false;

    let img_config = ImageImportConfig::from_config(&config, temp.path());
    let enabled = img_config.enabled_targets();
    let enabled_ids: Vec<AssetId> = enabled.iter().map(|t| t.id).collect();

    assert!(!enabled_ids.contains(&AssetId::ImageLocalPath));
    assert!(!enabled_ids.contains(&AssetId::ImageLocalPathHelper));

    let disabled = img_config.disabled_targets();
    assert!(disabled.contains(&AssetId::ImageLocalPath));
    assert!(disabled.contains(&AssetId::ImageLocalPathHelper));
}

#[test]
fn enabling_d2k_and_portainer_edge_includes_their_images() {
    let temp = TempDir::new().unwrap();
    let mut config = Config::default();
    config.d2k.enabled = true;
    config.portainer.edge_id = "edge-agent-01".into();

    let img_config = ImageImportConfig::from_config(&config, temp.path());
    let enabled = img_config.enabled_targets();
    let enabled_ids: Vec<AssetId> = enabled.iter().map(|t| t.id).collect();

    assert!(enabled_ids.contains(&AssetId::ImageD2k));
    assert!(enabled_ids.contains(&AssetId::ImagePortainerAgent));

    let disabled = img_config.disabled_targets();
    assert!(!disabled.contains(&AssetId::ImageD2k));
    assert!(!disabled.contains(&AssetId::ImagePortainerAgent));
}

#[test]
fn custom_portainer_edge_image_uses_custom_reference_and_is_non_fatal() {
    let temp = TempDir::new().unwrap();
    let mut config = Config::default();
    config.portainer.edge_id = "edge-01".into();
    config.portainer.image = "registry.internal.corp/portainer/custom-agent:2.19".into();

    let img_config = ImageImportConfig::from_config(&config, temp.path());
    let enabled = img_config.enabled_targets();

    let agent_target = enabled
        .iter()
        .find(|t| t.id == AssetId::ImagePortainerAgent)
        .expect("agent target should be present");

    assert_eq!(
        agent_target.reference,
        "registry.internal.corp/portainer/custom-agent:2.19"
    );
    // Custom edge image is not embedded in standard release archive
    assert_eq!(agent_target.filename, "");
    // Pull failure for custom edge image is non-fatal warm cache
    assert!(!agent_target.required);
}

#[test]
fn default_portainer_edge_image_is_required_with_archive_filename() {
    let temp = TempDir::new().unwrap();
    let mut config = Config::default();
    config.portainer.edge_id = "edge-01".into();
    config.portainer.image = String::new(); // default

    let img_config = ImageImportConfig::from_config(&config, temp.path());
    let enabled = img_config.enabled_targets();

    let agent_target = enabled
        .iter()
        .find(|t| t.id == AssetId::ImagePortainerAgent)
        .expect("agent target should be present");

    assert_eq!(agent_target.reference, DEFAULT_PORTAINER_AGENT_IMAGE);
    assert_eq!(agent_target.filename, "portainer-agent.tar.gz");
    assert!(agent_target.required);
}

#[test]
fn enabled_and_disabled_targets_are_strictly_disjoint() {
    let temp = TempDir::new().unwrap();
    let config = Config::default();
    let img_config = ImageImportConfig::from_config(&config, temp.path());

    let enabled: Vec<AssetId> = img_config.enabled_targets().iter().map(|t| t.id).collect();
    let disabled = img_config.disabled_targets();

    for id in &enabled {
        assert!(
            !disabled.contains(id),
            "Enabled asset {id:?} must not appear in disabled list"
        );
    }
    for id in &disabled {
        assert!(
            !enabled.contains(id),
            "Disabled asset {id:?} must not appear in enabled list"
        );
    }
}

#[test]
fn embedded_archive_detection_distinguishes_local_file_from_missing() {
    let temp = TempDir::new().unwrap();
    let images_dir = temp.path().join("images");
    fs::create_dir_all(&images_dir).unwrap();

    // Create non-empty tarball for coredns and pause
    fs::write(images_dir.join("coredns.tar.gz"), b"mock-coredns-tar-bytes").unwrap();
    fs::write(images_dir.join("pause.tar.gz"), b"mock-pause-tar-bytes").unwrap();
    // Leave local-path-provisioner and busybox missing

    let mut config = Config::default();
    config.storage.local_path.enabled = true;
    let img_config = ImageImportConfig::from_config(&config, &images_dir);

    let targets = img_config.enabled_targets();
    let coredns = targets
        .iter()
        .find(|t| t.id == AssetId::ImageCoredns)
        .unwrap();
    let pause = targets
        .iter()
        .find(|t| t.id == AssetId::ImagePause)
        .unwrap();
    let local_path = targets
        .iter()
        .find(|t| t.id == AssetId::ImageLocalPath)
        .unwrap();

    let coredns_path = images_dir.join(&coredns.filename);
    let pause_path = images_dir.join(&pause.filename);
    let local_path_path = images_dir.join(&local_path.filename);

    assert!(coredns_path.is_file());
    assert!(pause_path.is_file());
    assert!(!local_path_path.exists());
}

#[tokio::test]
async fn enabled_integrations_missing_offline_images_fail_before_a_registry_request() {
    use diorama_containerd::image::{ImageError, import_or_pull_images};
    for addon in ["portainer", "custom-portainer", "d2k"] {
        let root = TempDir::new().unwrap();
        for file in ["offline", "coredns.tar.gz", "pause.tar.gz"] {
            fs::write(root.path().join(file), b"already imported").unwrap();
        }
        let mut config = ImageImportConfig::new(root.path());
        config.local_storage_enabled = false;
        config.d2k_enabled = addon == "d2k";
        config.portainer_edge_enabled = addon != "d2k";
        if addon == "custom-portainer" {
            config.portainer_edge_image = Some("example.invalid/agent:v1".into());
        }
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let error = import_or_pull_images(channel, &config).await.unwrap_err();
        assert!(matches!(error, ImageError::ImportFailed { .. }), "{error}");
        assert!(error.to_string().contains("dioramactl addon load"));
    }
}
