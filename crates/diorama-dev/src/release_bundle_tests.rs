use super::*;
#[path = "../../diorama-assets/tests/common/archive.rs"]
mod archive;
#[path = "../../diorama-assets/tests/common/elf.rs"]
mod elf;

fn image(arch: &str, reference: &str) -> Vec<u8> {
    let layer = archive::entry("payload", b"offline release fixture");
    let compressed = archive::gzip(&layer);
    let mut config: serde_json::Value =
        serde_json::from_slice(&archive::config(arch, None, 1)).unwrap();
    config["rootfs"]["diff_ids"] = json!([format!("sha256:{}", archive::hex(&layer))]);
    let config = serde_json::to_vec(&config).unwrap();
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&archive::manifest(&config, &[&compressed])).unwrap();
    manifest[0]["RepoTags"] = json!([reference]);
    archive::gzip(&archive::archive(
        &config,
        &[&compressed],
        &serde_json::to_vec(&manifest).unwrap(),
    ))
}

fn fixtures(root: &Path, arch: &str) -> (PathBuf, PathBuf) {
    let binaries = root.join("binaries");
    let assets = root.join("assets");
    fs::create_dir_all(&binaries).unwrap();
    let binary = elf::executable(if arch == "amd64" { 62 } else { 183 }, 2);
    for name in ["diorama", "dioramactl"] {
        fs::write(binaries.join(name), &binary).unwrap();
    }
    for entry in catalog() {
        let path = assets.join(AssetLayout::default_relative_path(entry.id));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = if entry.kind == Kind::Executable {
            binary.clone()
        } else {
            image(
                arch,
                if entry.id == AssetId::ImageDiorama {
                    "ghcr.io/geoffsee/diorama:v0.1.0"
                } else {
                    entry.reference
                },
            )
        };
        fs::write(path, bytes).unwrap();
    }
    (binaries, assets)
}

#[test]
fn both_release_bundles_have_a_complete_verified_installer_layout() {
    for arch in ["amd64", "arm64"] {
        let root = tempfile::tempdir().unwrap();
        let (binaries, assets) = fixtures(root.path(), arch);
        let bundle = package(
            "v0.1.0",
            arch,
            &binaries,
            &assets,
            &root.path().join("dist"),
        )
        .unwrap();
        assert_eq!(
            bundle.file_name().unwrap().to_str().unwrap(),
            format!("diorama-v0.1.0-linux-{arch}-offline.tar.gz")
        );
        let installed = root.path().join("installed");
        extract(&bundle, &installed).unwrap();
        let manifest = dioramactl::install::verify_staged_bundle(
            &installed,
            architecture(arch).unwrap(),
            Libc::Glibc,
        )
        .unwrap();
        assert_eq!(manifest.version, "v0.1.0");
        for name in ["diorama", "dioramactl"] {
            assert_eq!(
                fs::read(installed.join("bin").join(name)).unwrap(),
                fs::read(binaries.join(name)).unwrap()
            );
        }
        for entry in catalog() {
            let relative = AssetLayout::default_relative_path(entry.id);
            assert_eq!(
                fs::read(installed.join(relative)).unwrap(),
                fs::read(assets.join(relative)).unwrap()
            );
        }
        let inventory = Manifest::decode(
            &fs::read(installed.join("asset-inventory.json")).unwrap(),
            Limits::default(),
        )
        .unwrap()
        .validate_inventory(
            InventoryRequest {
                target: NodeTarget {
                    architecture: architecture(arch).unwrap(),
                    libc: Libc::Glibc,
                },
                variant: Variant::Offline,
                scope: Scope::SupervisedBundle,
            },
            Limits::default(),
        )
        .unwrap();
        assert_eq!(inventory.bundled_assets().len(), 15);
        let node_image = fs::read(installed.join("images/diorama.tar.gz")).unwrap();
        let mut session = inventory.decoding_session(DecodeLimits::default()).unwrap();
        assert_eq!(
            dioramactl::container_image::verify_container_image(&mut session, &node_image)
                .unwrap()
                .reference(),
            "ghcr.io/geoffsee/diorama:v0.1.0"
        );
        assert!(installed.join("release-inputs.json").is_file());
    }
}

#[test]
fn incomplete_wrong_platform_and_corrupt_inputs_never_publish_a_bundle() {
    for case in [
        "missing-runtime",
        "missing-cli",
        "foreign-elf",
        "foreign-image",
        "wrong-tag",
        "corrupt-image",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (binaries, assets) = fixtures(root.path(), "amd64");
        match case {
            "missing-runtime" => {
                fs::remove_file(assets.join("bin/containerd-fuse-overlayfs-grpc")).unwrap();
            },
            "missing-cli" => fs::remove_file(binaries.join("dioramactl")).unwrap(),
            "foreign-elf" => fs::write(assets.join("bin/crun"), elf::executable(183, 2)).unwrap(),
            "foreign-image" => fs::write(
                assets.join("images/diorama.tar.gz"),
                image("arm64", "ghcr.io/geoffsee/diorama:v0.1.0"),
            )
            .unwrap(),
            "wrong-tag" => fs::write(
                assets.join("images/diorama.tar.gz"),
                image("amd64", "portainer/kubesolo:latest"),
            )
            .unwrap(),
            "corrupt-image" => {
                fs::write(assets.join("images/diorama.tar.gz"), b"invalid image").unwrap();
            },
            _ => unreachable!(),
        }
        let output = root.path().join("dist");
        assert!(
            package("v0.1.0", "amd64", &binaries, &assets, &output).is_err(),
            "{case}"
        );
        assert!(
            !output
                .join("diorama-v0.1.0-linux-amd64-offline.tar.gz")
                .exists(),
            "{case}"
        );
    }
}

#[test]
fn pinned_inputs_cover_every_runtime_and_workload_role_on_both_release_targets() {
    use std::collections::BTreeSet;
    let sources: Sources = serde_json::from_str(INPUTS).unwrap();
    let expected: BTreeSet<_> = catalog()
        .iter()
        .filter(|entry| entry.kind == Kind::Executable)
        .map(|entry| AssetLayout::default_relative_path(entry.id))
        .collect();
    for arch in ["amd64", "arm64"] {
        let downloads = &sources.downloads[arch];
        let actual: BTreeSet<_> = downloads
            .iter()
            .flat_map(|source| source.files.values().map(String::as_str))
            .collect();
        assert_eq!(actual, expected);
        for source in downloads.iter().chain(sources.tools.values()) {
            assert!(source.url.starts_with("https://github.com/"));
            assert_eq!(source.sha256.len(), 64);
            assert!(source.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        let expected: BTreeSet<_> = catalog()
            .iter()
            .filter(|entry| entry.kind == Kind::Image && entry.id != AssetId::ImageDiorama)
            .map(|entry| entry.id)
            .collect();
        let actual: BTreeSet<_> = sources.images.iter().map(|image| image.id).collect();
        assert_eq!(actual, expected);
        assert_eq!(sources.images.len(), expected.len());
        for image in &sources.images {
            assert_eq!(
                image.reference,
                catalog()
                    .iter()
                    .find(|entry| entry.id == image.id)
                    .unwrap()
                    .reference
            );
            assert!(image.digests[arch].starts_with("sha256:"));
            assert_eq!(image.digests[arch].len(), 71);
        }
    }
}
