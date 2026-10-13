use diorama_assets::{DecodeLimits, InventoryRequest, Limits, Manifest, Scope, Variant};
use diorama_platform::{Architecture, Libc, NodeTarget};
use dioramactl::{InstallOptions, container::*, container_image::install_selected_container};
use serde_json::{Value, json};
use std::{collections::HashMap, io};
#[path = "../../diorama-assets/tests/common/archive.rs"]
mod vectors;

fn image_inventory() -> (diorama_assets::DeclaredInventory, Vec<u8>) {
    image_inventory_with_tags(&["example.invalid/image:fixture"])
}

fn image_inventory_with_tags(tags: &[&str]) -> (diorama_assets::DeclaredInventory, Vec<u8>) {
    let raw_layer = vectors::entry("payload", b"image fixture");
    let layer = vectors::gzip(&raw_layer);
    let mut config: Value = serde_json::from_slice(&vectors::config("amd64", None, 1)).unwrap();
    config["rootfs"]["diff_ids"] = json!([format!("sha256:{}", vectors::hex(&raw_layer))]);
    let config = serde_json::to_vec(&config).unwrap();
    let mut archive_manifest: Value =
        serde_json::from_slice(&vectors::manifest(&config, &[&layer])).unwrap();
    archive_manifest[0]["RepoTags"] = json!(tags);
    let archive = vectors::archive(
        &config,
        &[&layer],
        &serde_json::to_vec(&archive_manifest).unwrap(),
    );
    let bytes = vectors::gzip(&archive);
    let mut manifest: Value = serde_json::from_slice(include_bytes!(
        "../../diorama-assets/tests/fixtures/offline-arm64.json"
    ))
    .unwrap();
    manifest["target"]["architecture"] = json!("amd64");
    for row in manifest["assets"].as_array_mut().unwrap() {
        if row["id"] == "image-kubesolo" {
            row["delivery"]["encoded_bytes"] = json!(bytes.len());
            row["delivery"]["sha256"] = json!(vectors::hex(&bytes));
        }
    }
    let inventory = Manifest::decode(&serde_json::to_vec(&manifest).unwrap(), Limits::default())
        .unwrap()
        .validate_inventory(
            InventoryRequest {
                target: NodeTarget {
                    architecture: Architecture::Amd64,
                    libc: Libc::Glibc,
                },
                variant: Variant::Offline,
                scope: Scope::SupervisedBundle,
            },
            Limits::default(),
        )
        .unwrap();
    (inventory, bytes)
}

#[derive(Default)]
struct Engine {
    calls: Vec<&'static str>,
    loaded: Vec<u8>,
    import_error: bool,
    tag_missing: bool,
    created: bool,
}
impl ContainerEngineClient for Engine {
    fn inspect_network(&mut self, _: &str) -> io::Result<Option<CreateNetworkRequest>> {
        Ok(None)
    }
    fn create_network(&mut self, _: &CreateNetworkRequest) -> io::Result<()> {
        self.calls.push("network");
        Ok(())
    }
    fn remove_network(&mut self, _: &str) -> io::Result<()> {
        Ok(())
    }
    fn inspect_volume(&mut self, _: &str) -> io::Result<Option<()>> {
        Ok(None)
    }
    fn create_volume(&mut self, _: &CreateVolumeRequest) -> io::Result<()> {
        self.calls.push("volume");
        Ok(())
    }
    fn remove_volume(&mut self, _: &str) -> io::Result<()> {
        Ok(())
    }
    fn inspect_image(&mut self, _: &str) -> io::Result<Option<()>> {
        Ok((!self.loaded.is_empty() && !self.tag_missing).then_some(()))
    }
    fn pull_image(&mut self, _: &str) -> io::Result<()> {
        self.calls.push("pull");
        Err(io::Error::other("registry egress denied"))
    }
    fn load_image(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.calls.push("load");
        if self.import_error {
            return Err(io::Error::other("import failed"));
        }
        self.loaded = bytes.into();
        Ok(())
    }
    fn inspect_container(&mut self, _: &str) -> io::Result<Option<ContainerInspect>> {
        Ok(self.created.then(|| ContainerInspect {
            id: "id".into(),
            name: "node".into(),
            running: true,
            d2k_enabled: false,
            exit_code: 0,
            allocated_ports: HashMap::from([("6443/tcp".into(), 32768)]),
        }))
    }
    fn create_container(&mut self, _: &str, config: &ContainerConfig) -> io::Result<String> {
        assert_eq!(config.image, "example.invalid/image:fixture");
        self.calls.push("create");
        self.created = true;
        Ok("id".into())
    }
    fn start_container(&mut self, _: &str) -> io::Result<()> {
        self.calls.push("start");
        Ok(())
    }
    fn stop_container(&mut self, _: &str, _: u32) -> io::Result<()> {
        Ok(())
    }
    fn remove_container(&mut self, _: &str, _: bool) -> io::Result<()> {
        Ok(())
    }
}
fn params() -> ContainerInstallParams {
    ContainerInstallParams {
        instance_name: "offline".into(),
        image: "ignored".into(),
        mtu: None,
        d2k: false,
        container_ports: None,
        extra_env: vec![],
        apiserver_host_port: None,
        d2k_host_port: None,
    }
}

#[test]
fn offline_install_imports_verified_bytes_before_creating_owned_resources_without_pull() {
    let (inventory, bytes) = image_inventory();
    let mut session = inventory.decoding_session(DecodeLimits::default()).unwrap();
    let mut engine = Engine::default();
    install_selected_container(
        &mut engine,
        &InstallOptions::default(),
        params(),
        Some((&mut session, &bytes)),
    )
    .unwrap();
    assert_eq!(engine.loaded, bytes);
    assert_eq!(
        engine.calls,
        ["load", "network", "volume", "create", "start"]
    );
}

#[test]
fn corrupt_payload_import_failure_and_missing_imported_tag_never_pull_or_create() {
    let (inventory, bytes) = image_inventory();
    let mut corrupt = bytes.clone();
    corrupt[0] ^= 1;
    let mut session = inventory.decoding_session(DecodeLimits::default()).unwrap();
    let mut engine = Engine::default();
    assert!(
        install_selected_container(
            &mut engine,
            &InstallOptions::default(),
            params(),
            Some((&mut session, &corrupt))
        )
        .is_err()
    );
    assert_eq!(engine.calls, <[&str; 0]>::default());
    for (import_error, tag_missing) in [(true, false), (false, true)] {
        let mut session = inventory.decoding_session(DecodeLimits::default()).unwrap();
        let mut engine = Engine {
            import_error,
            tag_missing,
            ..Engine::default()
        };
        assert!(
            install_selected_container(
                &mut engine,
                &InstallOptions::default(),
                params(),
                Some((&mut session, &bytes))
            )
            .is_err()
        );
        assert_eq!(engine.calls, ["load"]);
    }
}

#[test]
fn multiple_or_missing_tags_fail_before_any_engine_effect() {
    for tags in [
        vec![],
        vec![
            "example.invalid/image:fixture",
            "unrelated.local/image:keep",
        ],
    ] {
        let (inventory, bytes) = image_inventory_with_tags(&tags);
        let mut session = inventory.decoding_session(DecodeLimits::default()).unwrap();
        let mut engine = Engine::default();
        assert!(
            install_selected_container(
                &mut engine,
                &InstallOptions::default(),
                params(),
                Some((&mut session, &bytes)),
            )
            .is_err()
        );
        assert_eq!(engine.calls, <[&str; 0]>::default());
    }
}
