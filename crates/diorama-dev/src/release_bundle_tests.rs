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
    fs::create_dir_all(assets.join("bin")).unwrap();
    fs::write(assets.join("bin/ctr"), &binary).unwrap();
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
            BundleKind::Host,
            None,
            "v0.1.0",
            arch,
            &binaries,
            &assets,
            &root.path().join("dist"),
        )
        .unwrap();
        assert_eq!(
            bundle.file_name().unwrap().to_str().unwrap(),
            format!("diorama-v0.1.0-linux-{arch}-host-offline.tar.gz")
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
        for entry in catalog().iter().filter(|e| {
            !matches!(
                e.id,
                AssetId::ImageDiorama | AssetId::ImagePortainerAgent | AssetId::ImageD2k
            )
        }) {
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
        assert_eq!(inventory.bundled_assets().len(), 12);
        for (id, path, encoding, _) in inventory.bundled_assets() {
            assert_eq!(path, AssetLayout::default_relative_path(id));
            let kind = catalog().iter().find(|entry| entry.id == id).unwrap().kind;
            assert_eq!(
                encoding,
                if kind == Kind::Executable {
                    Encoding::Identity
                } else {
                    Encoding::Gzip
                }
            );
        }
        assert!(!installed.join("payloads").exists());
        let parsed = diorama_assets::ArtifactNaming::parse_node_archive(
            bundle.file_name().unwrap().to_str().unwrap(),
        )
        .unwrap();
        dioramactl::offline::validate(&installed, &parsed, BundleKind::Host).unwrap();
        assert!(!installed.join("images/diorama.tar.gz").exists());
        assert!(!installed.join("images/portainer-agent.tar.gz").exists());
        assert!(!installed.join("images/d2k.tar.gz").exists());
        assert!(installed.join("release-inputs.json").is_file());
    }
}

fn staged_host() -> (
    tempfile::TempDir,
    PathBuf,
    diorama_assets::ParsedNodeArchive,
) {
    let root = tempfile::tempdir().unwrap();
    let (binaries, assets) = fixtures(root.path(), "arm64");
    let bundle = package(
        BundleKind::Host,
        None,
        "v0.1.0",
        "arm64",
        &binaries,
        &assets,
        &root.path().join("dist"),
    )
    .unwrap();
    let installed = root.path().join("installed");
    extract(&bundle, &installed).unwrap();
    let parsed = diorama_assets::ArtifactNaming::parse_node_archive(
        bundle.file_name().unwrap().to_str().unwrap(),
    )
    .unwrap();
    (root, installed, parsed)
}

// Refresh outer checksums so these tests exercise the independent inventory checks.
fn refresh_manifest(root: &Path, additional: &[String]) {
    use dioramactl::install::{BundleEntry, BundleManifest};
    let path = root.join("bundle.manifest");
    let mut manifest = BundleManifest::parse(&fs::read_to_string(&path).unwrap()).unwrap();
    for relative in additional {
        manifest.entries.push(BundleEntry {
            path: relative.into(),
            sha256: String::new(),
            executable: false,
        });
    }
    for entry in &mut manifest.entries {
        entry.sha256 = sha256(&root.join(&entry.path)).unwrap();
    }
    fs::write(path, manifest.render()).unwrap();
    dioramactl::install::verify_staged_bundle(root, Architecture::Arm64, Libc::Glibc).unwrap();
}

#[test]
fn host_inventory_checks_the_installed_executable_without_a_second_payload() {
    for (case, diagnostic) in [
        ("checksum", "encoded-byte verification failed"),
        ("size", "invalid size"),
        ("shadow-path", "installed executable path"),
        ("elf-structure", "malformed ELF structure"),
    ] {
        let (_root, installed, parsed) = staged_host();
        let path = installed.join("asset-inventory.json");
        let mut inventory: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut extra = Vec::new();
        let executable = installed.join(AssetLayout::default_relative_path(AssetId::Crun));
        match case {
            "checksum" => {
                let mut bytes = fs::read(&executable).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                fs::write(&executable, bytes).unwrap();
            },
            "size" => {
                let mut bytes = fs::read(&executable).unwrap();
                bytes.push(0);
                fs::write(&executable, bytes).unwrap();
            },
            "shadow-path" => {
                let shadow = "verified-copy";
                fs::copy(&executable, installed.join(shadow)).unwrap();
                let record = inventory["assets"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|r| r["id"] == "crun")
                    .unwrap();
                record["delivery"]["path"] = json!(shadow);
                extra.push(shadow.into());
            },
            "elf-structure" => {
                let mut bytes = fs::read(&executable).unwrap();
                elf::put(&mut bytes, 32, 512, 8); // Program header table extends beyond EOF.
                fs::write(&executable, bytes).unwrap();
                let record = inventory["assets"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|r| r["id"] == "crun")
                    .unwrap();
                record["delivery"]["sha256"] = json!(sha256(&executable).unwrap());
            },
            _ => unreachable!(),
        }
        fs::write(path, serde_json::to_vec(&inventory).unwrap()).unwrap();
        refresh_manifest(&installed, &extra);
        let error =
            dioramactl::offline::validate(&installed, &parsed, BundleKind::Host).unwrap_err();
        assert!(error.contains(diagnostic), "{case}: {error}");
    }
}

#[test]
fn previously_emitted_zstd_host_payloads_remain_supported_and_bound_to_installed_bytes() {
    let (_root, installed, parsed) = staged_host();
    let path = installed.join("asset-inventory.json");
    let mut inventory: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    fs::create_dir_all(installed.join("payloads")).unwrap();
    let mut extra = Vec::new();
    for entry in catalog()
        .iter()
        .filter(|entry| entry.encoding == Encoding::Zstd)
    {
        let record = inventory["assets"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["id"] == json!(entry.id))
            .unwrap();
        let relative = format!("payloads/{}.zst", record["id"].as_str().unwrap());
        let raw = fs::read(installed.join(AssetLayout::default_relative_path(entry.id))).unwrap();
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        fs::write(installed.join(&relative), &compressed).unwrap();
        record["delivery"] = json!({"kind":"bundled", "path":relative, "encoding":"zstd", "encoded_bytes":compressed.len(), "sha256":sha256(&installed.join(&relative)).unwrap()});
        extra.push(relative);
    }
    fs::write(path, serde_json::to_vec(&inventory).unwrap()).unwrap();
    refresh_manifest(&installed, &extra);
    dioramactl::offline::validate(&installed, &parsed, BundleKind::Host).unwrap();

    let executable = installed.join(AssetLayout::default_relative_path(AssetId::Crun));
    let mut bytes = fs::read(&executable).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(executable, bytes).unwrap();
    refresh_manifest(&installed, &[]);
    let error = dioramactl::offline::validate(&installed, &parsed, BundleKind::Host).unwrap_err();
    assert!(error.contains("raw executable differs"), "{error}");
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
                assets.join("images/coredns.tar.gz"),
                image("arm64", "docker.io/coredns/coredns:1.14.4"),
            )
            .unwrap(),
            "wrong-tag" => fs::write(
                assets.join("images/coredns.tar.gz"),
                image("amd64", "portainer/kubesolo:latest"),
            )
            .unwrap(),
            "corrupt-image" => {
                fs::write(assets.join("images/coredns.tar.gz"), b"invalid image").unwrap();
            },
            _ => unreachable!(),
        }
        let output = root.path().join("dist");
        assert!(
            package(
                BundleKind::Host,
                None,
                "v0.1.0",
                "amd64",
                &binaries,
                &assets,
                &output
            )
            .is_err(),
            "{case}"
        );
        assert!(
            !output
                .join("diorama-v0.1.0-linux-amd64-host-offline.tar.gz")
                .exists(),
            "{case}"
        );
    }
}

#[test]
fn pinned_inputs_cover_every_runtime_and_workload_role_on_both_release_targets() {
    use std::collections::BTreeSet;
    let sources: Sources = serde_json::from_str(INPUTS).unwrap();
    let mut expected: BTreeSet<_> = catalog()
        .iter()
        .filter(|entry| entry.kind == Kind::Executable)
        .map(|entry| AssetLayout::default_relative_path(entry.id))
        .collect();
    expected.insert("bin/ctr");
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
            if image.id != AssetId::ImageLocalPath {
                assert_eq!(
                    image.reference,
                    catalog()
                        .iter()
                        .find(|entry| entry.id == image.id)
                        .unwrap()
                        .reference
                );
            }
            assert!(image.digests[arch].starts_with("sha256:"));
            assert_eq!(image.digests[arch].len(), 71);
        }
    }
}

#[test]
fn separate_container_and_addon_packs_validate_only_their_declared_assets() {
    for arch in ["amd64", "arm64"] {
        for (kind, capability, id) in [
            (BundleKind::Container, None, AssetId::ImageDiorama),
            (BundleKind::Addon, Some(Capability::D2k), AssetId::ImageD2k),
            (
                BundleKind::Addon,
                Some(Capability::PortainerAgent),
                AssetId::ImagePortainerAgent,
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let assets = root.path().join("assets");
            fs::create_dir_all(assets.join("images")).unwrap();
            let metadata = BundleMetadata {
                kind,
                version: "v0.1.0".into(),
                capabilities: capability.map_or_else(
                    || vec![Capability::Core, Capability::LocalStorage],
                    |c| vec![c],
                ),
            };
            fs::write(
                assets.join(AssetLayout::default_relative_path(id)),
                image(arch, &metadata.image_reference(id).unwrap()),
            )
            .unwrap();
            let archive = package(
                kind,
                capability,
                "v0.1.0",
                arch,
                &root.path().join("no-binaries"),
                &assets,
                &root.path().join("dist"),
            )
            .unwrap();
            let unpacked = root.path().join("unpacked");
            extract(&archive, &unpacked).unwrap();
            let parsed = diorama_assets::ArtifactNaming::parse_node_archive(
                archive.file_name().unwrap().to_str().unwrap(),
            )
            .unwrap();
            let inventory = dioramactl::offline::validate(&unpacked, &parsed, kind)
                .unwrap()
                .unwrap();
            assert_eq!(inventory.bundled_assets().len(), 1);
            assert!(!unpacked.join("bin").exists());
            assert!(dioramactl::offline::validate(&unpacked, &parsed, BundleKind::Host).is_err());
            let mut wrong_version = parsed.clone();
            wrong_version.version = "v9.0.0".into();
            assert!(dioramactl::offline::validate(&unpacked, &wrong_version, kind).is_err());
            if kind == BundleKind::Addon {
                assert!(unpacked.join("install-job.json").is_file());
            }
        }
    }
}

#[test]
fn oversized_host_archives_are_not_left_publishable() {
    let root = tempfile::tempdir().unwrap();
    for ceiling in [120_000_000, 140_000_000] {
        let archive = root.path().join("host.tar.gz");
        File::create(&archive).unwrap().set_len(ceiling).unwrap();
        assert!(enforce_host_ceiling(&archive, ceiling).is_ok());
        File::create(&archive)
            .unwrap()
            .set_len(ceiling + 1)
            .unwrap();
        assert!(enforce_host_ceiling(&archive, ceiling).is_err());
        assert!(!archive.exists());
    }
}
