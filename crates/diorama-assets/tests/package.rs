#[allow(clippy::duplicate_mod)]
#[path = "common/archive.rs"]
mod vectors;

use diorama_assets::{
    AssetId, DeclaredInventory, Encoding, InventoryRequest, Limits, ManagementArtifact,
    ManagementTarget, Manifest, Matrix, NodeArchiveArtifact, NodeTarget, NodeVariant,
    OciImageIndexArtifact, OciPlatformDescriptor, OptionalFeature, PackageError,
    ReleasePackageManifest, ReleasePackager, Scope, Variant,
};
use diorama_platform::{Architecture, Libc};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
use vectors::{entry, gzip, hex};

const ONLINE_ARM64_JSON: &str = include_str!("fixtures/online-arm64.json");
const OFFLINE_ARM64_JSON: &str = include_str!("fixtures/offline-arm64.json");

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("create test dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o755));
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn create_synthetic_payload(id: AssetId, encoding: Encoding) -> (Vec<u8>, Vec<u8>, u64, String) {
    let content = match id {
        AssetId::ImageCoredns
        | AssetId::ImagePause
        | AssetId::ImageLocalPath
        | AssetId::ImageLocalPathHelper
        | AssetId::ImagePortainerAgent
        | AssetId::ImageD2k
        | AssetId::ImageDiorama => {
            let tar_data = entry("layer.tar", b"synthetic image layer");
            gzip(&tar_data)
        },
        _ => format!("synthetic-binary-{id:?}").into_bytes(),
    };

    let encoded_bytes = match encoding {
        Encoding::Identity | Encoding::Gzip => content.clone(),
        Encoding::Zstd => zstd::encode_all(content.as_slice(), 0).expect("zstd encode"),
    };

    let encoded_len = encoded_bytes.len() as u64;
    let digest_hex = hex(&encoded_bytes);

    (content, encoded_bytes, encoded_len, digest_hex)
}

fn resolve_asset_delivery(variant: NodeVariant, id: AssetId) -> (bool, bool, Encoding) {
    let unavailable = match id {
        AssetId::ImagePortainerAgent => {
            variant.optional_feature_support(OptionalFeature::PortainerAgent)
                == diorama_assets::FeatureSupport::UnsupportedTarget
        },
        AssetId::ImageD2k => {
            variant.optional_feature_support(OptionalFeature::D2k)
                == diorama_assets::FeatureSupport::UnsupportedTarget
        },
        _ => false,
    };

    let is_bundled = !unavailable
        && (matches!(
            id,
            AssetId::Containerd
                | AssetId::KubeScheduler
                | AssetId::FuseOverlayfsSnapshotter
                | AssetId::ContainerdShim
                | AssetId::Crun
                | AssetId::CniBridge
                | AssetId::CniHostLocal
                | AssetId::CniPortmap
                | AssetId::CniLoopback
                | AssetId::ImageCoredns
                | AssetId::ImagePause
        ) || variant.variant == Variant::Offline);

    let encoding = match id {
        AssetId::ContainerdShim
        | AssetId::Crun
        | AssetId::CniBridge
        | AssetId::CniHostLocal
        | AssetId::CniPortmap
        | AssetId::CniLoopback => Encoding::Zstd,
        AssetId::ImageCoredns
        | AssetId::ImagePause
        | AssetId::ImageLocalPath
        | AssetId::ImageLocalPathHelper
        | AssetId::ImagePortainerAgent
        | AssetId::ImageD2k
        | AssetId::ImageDiorama => Encoding::Gzip,
        _ => Encoding::Identity,
    };

    (unavailable, is_bundled, encoding)
}

fn parse_catalog_asset_id(id_str: &str) -> AssetId {
    match id_str {
        "containerd" => AssetId::Containerd,
        "kube-scheduler" => AssetId::KubeScheduler,
        "fuse-overlayfs-snapshotter" => AssetId::FuseOverlayfsSnapshotter,
        "containerd-shim-runc-v2" => AssetId::ContainerdShim,
        "crun" => AssetId::Crun,
        "cni-bridge" => AssetId::CniBridge,
        "cni-host-local" => AssetId::CniHostLocal,
        "cni-portmap" => AssetId::CniPortmap,
        "cni-loopback" => AssetId::CniLoopback,
        "image-coredns" => AssetId::ImageCoredns,
        "image-pause" => AssetId::ImagePause,
        "image-local-path" => AssetId::ImageLocalPath,
        "image-local-path-helper" => AssetId::ImageLocalPathHelper,
        "image-portainer-agent" => AssetId::ImagePortainerAgent,
        "image-d2k" => AssetId::ImageD2k,
        "image-diorama" => AssetId::ImageDiorama,
        other => panic!("unknown asset {other}"),
    }
}

fn populate_archive_rows(
    variant: NodeVariant,
    assets_arr: &mut [Value],
    archive_bytes: &mut Vec<u8>,
) -> Vec<String> {
    let mut bundled = Vec::new();
    for row in assets_arr.iter_mut() {
        let id_str = row["id"].as_str().expect("asset id").to_string();
        let id = parse_catalog_asset_id(&id_str);
        let (unavailable, is_bundled, encoding) = resolve_asset_delivery(variant, id);

        if unavailable {
            row["delivery"] = json!({ "kind": "unavailable" });
        } else if !is_bundled {
            row["delivery"] = json!({ "kind": "registry-required" });
        } else {
            let (_content, encoded_bytes, encoded_len, digest_hex) =
                create_synthetic_payload(id, encoding);
            let encoding_str = match encoding {
                Encoding::Identity => "identity",
                Encoding::Zstd => "zstd",
                Encoding::Gzip => "gzip",
            };
            let path = format!("fixtures/{id_str}");
            row["delivery"] = json!({
                "kind": "bundled",
                "path": path,
                "encoding": encoding_str,
                "encoded_bytes": encoded_len,
                "sha256": digest_hex,
            });
            archive_bytes.extend(entry(&path, &encoded_bytes));
            bundled.push(id_str);
        }
    }
    bundled
}

fn build_synthetic_cell_archive(
    variant: NodeVariant,
    source_json: &str,
) -> (DeclaredInventory, Vec<u8>, NodeArchiveArtifact) {
    let mut manifest_val: Value = serde_json::from_str(source_json).expect("valid fixture");
    let mut archive_bytes = Vec::new();

    manifest_val["target"]["architecture"] = json!(match variant.architecture {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
        Architecture::ArmV7 => "armv7",
        Architecture::Riscv64 => "riscv64",
    });
    manifest_val["target"]["libc"] = json!(match variant.libc {
        Libc::Glibc => "glibc",
        Libc::Musl => "musl",
    });
    manifest_val["variant"] = json!(match variant.variant {
        Variant::Online => "online",
        Variant::Offline => "offline",
    });

    let assets_arr = manifest_val["assets"].as_array_mut().expect("assets array");
    let bundled_asset_names = populate_archive_rows(variant, assets_arr, &mut archive_bytes);
    archive_bytes.extend([0u8; 1024]);

    let manifest_bytes = serde_json::to_vec(&manifest_val).expect("serialized json");
    let inventory = Manifest::decode(&manifest_bytes, Limits::default())
        .expect("manifest decode")
        .validate_inventory(
            InventoryRequest {
                target: NodeTarget {
                    architecture: variant.architecture,
                    libc: variant.libc,
                },
                variant: variant.variant,
                scope: Scope::SupervisedBundle,
            },
            Limits::default(),
        )
        .expect("inventory validate");

    let filename = variant.archive_filename("diorama", "0.1.0");
    let sha256 = ReleasePackager::sha256_hex(&archive_bytes);
    let size_bytes = archive_bytes.len() as u64;

    let artifact = NodeArchiveArtifact {
        cell: variant.cell,
        filename,
        architecture: match variant.architecture {
            Architecture::Amd64 => "amd64".to_string(),
            Architecture::Arm64 => "arm64".to_string(),
            Architecture::ArmV7 => "arm".to_string(),
            Architecture::Riscv64 => "riscv64".to_string(),
        },
        libc: match variant.libc {
            Libc::Glibc => "glibc".to_string(),
            Libc::Musl => "musl".to_string(),
        },
        variant: match variant.variant {
            Variant::Online => "online".to_string(),
            Variant::Offline => "offline".to_string(),
        },
        size_bytes,
        sha256,
        bundled_assets: bundled_asset_names,
    };

    (inventory, archive_bytes, artifact)
}

fn build_synthetic_management_binary(target: ManagementTarget) -> (Vec<u8>, ManagementArtifact) {
    let content = format!(
        "synthetic-management-binary-{}-{}",
        target.os, target.architecture
    )
    .into_bytes();
    let filename = target.binary_filename("dioramactl");
    let sha256 = ReleasePackager::sha256_hex(&content);
    let size_bytes = content.len() as u64;

    let artifact = ManagementArtifact {
        os: target.os.to_string(),
        architecture: target.architecture.to_string(),
        filename,
        size_bytes,
        sha256,
    };

    (content, artifact)
}

fn oci_descriptor(platform: &str, arch: &str, digest: &str) -> OciPlatformDescriptor {
    OciPlatformDescriptor {
        platform: platform.to_string(),
        architecture: arch.to_string(),
        os: "linux".to_string(),
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        digest: digest.to_string(),
        size_bytes: 2048,
    }
}

fn build_synthetic_oci_images() -> Vec<OciImageIndexArtifact> {
    let mut images = vec![
        OciImageIndexArtifact {
            asset_id: "image-coredns".to_string(),
            image_reference: "docker.io/coredns/coredns:1.14.4".to_string(),
            index_media_type: "application/vnd.oci.image.index.v1+json".to_string(),
            index_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            index_size_bytes: 4096,
            platforms: vec![
                oci_descriptor(
                    "linux/amd64",
                    "amd64",
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                ),
                oci_descriptor(
                    "linux/arm64",
                    "arm64",
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                ),
                oci_descriptor(
                    "linux/arm/v7",
                    "arm",
                    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                ),
                oci_descriptor(
                    "linux/riscv64",
                    "riscv64",
                    "sha256:4444444444444444444444444444444444444444444444444444444444444444",
                ),
            ],
            unsupported_platforms: vec![],
        },
        OciImageIndexArtifact {
            asset_id: "image-portainer-agent".to_string(),
            image_reference: "docker.io/portainer/agent:lts".to_string(),
            index_media_type: "application/vnd.oci.image.index.v1+json".to_string(),
            index_digest: "sha256:5555555555555555555555555555555555555555555555555555555555555555"
                .to_string(),
            index_size_bytes: 4096,
            platforms: vec![
                oci_descriptor(
                    "linux/amd64",
                    "amd64",
                    "sha256:6666666666666666666666666666666666666666666666666666666666666666",
                ),
                oci_descriptor(
                    "linux/arm64",
                    "arm64",
                    "sha256:7777777777777777777777777777777777777777777777777777777777777777",
                ),
                oci_descriptor(
                    "linux/arm/v7",
                    "arm",
                    "sha256:8888888888888888888888888888888888888888888888888888888888888888",
                ),
            ],
            unsupported_platforms: vec!["linux/riscv64".to_string()],
        },
        OciImageIndexArtifact {
            asset_id: "image-d2k".to_string(),
            image_reference: "docker.io/portainer/d2k:1.2.3".to_string(),
            index_media_type: "application/vnd.oci.image.index.v1+json".to_string(),
            index_digest: "sha256:9999999999999999999999999999999999999999999999999999999999999999"
                .to_string(),
            index_size_bytes: 4096,
            platforms: vec![
                oci_descriptor(
                    "linux/amd64",
                    "amd64",
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
                oci_descriptor(
                    "linux/arm64",
                    "arm64",
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ],
            unsupported_platforms: vec!["linux/arm/v7".to_string(), "linux/riscv64".to_string()],
        },
    ];
    for (id, reference) in [
        ("image-diorama", "ghcr.io/geoffsee/diorama:0.1.0"),
        ("image-pause", "docker.io/portainer/pause:latest"),
        (
            "image-local-path",
            "ghcr.io/geoffsee/diorama-local-path-provisioner:v0.0.36-1",
        ),
        (
            "image-local-path-helper",
            "docker.io/library/busybox:latest",
        ),
    ] {
        let mut image = images[0].clone();
        image.asset_id = id.into();
        image.image_reference = reference.into();
        images.push(image);
    }
    images
}

#[test]
fn smoke_check_layout_all_16_node_cells() {
    let variants = Matrix::all_node_variants();
    assert_eq!(variants.len(), 16);

    for variant in variants {
        let fixture_json = match variant.variant {
            Variant::Online => ONLINE_ARM64_JSON,
            Variant::Offline => OFFLINE_ARM64_JSON,
        };

        let (inventory, archive_bytes, descriptor) =
            build_synthetic_cell_archive(*variant, fixture_json);

        // Verify descriptor naming and roundtrip
        let verified_variant =
            ReleasePackager::verify_node_archive_descriptor(&descriptor, "diorama", "0.1.0")
                .expect("verify descriptor");
        assert_eq!(verified_variant.cell, variant.cell);

        // Verify synthetic dependency materialization; no node executable or installation.
        let test_dir = TestDir::new(&format!("smoke-cell-{}", variant.cell));
        let outcome = ReleasePackager::smoke_check_node_archive_layout(
            inventory,
            test_dir.path(),
            archive_bytes.as_slice(),
        )
        .expect("smoke check layout");

        // Verify assets materialized
        assert_ne!(
            outcome.assets,
            Vec::<diorama_assets::MaterializedAsset>::new()
        );
        for asset in outcome.assets {
            assert!(asset.path.exists());
            if asset.path.to_str().unwrap().contains("bin/")
                || asset.path.to_str().unwrap().contains("containerd/")
            {
                if asset.path.extension().is_none() {
                    assert_eq!(asset.mode, 0o755);
                } else {
                    assert_eq!(asset.mode, 0o644);
                }
            }
        }
    }
}

#[test]
fn verify_all_management_targets_and_rejections() {
    let targets = Matrix::all_management_targets();
    assert_eq!(targets.len(), 4);

    for target in targets {
        let (_content, artifact) = build_synthetic_management_binary(*target);
        let verified = ReleasePackager::verify_management_artifact(&artifact, "dioramactl")
            .expect("verify management target");
        assert_eq!(verified, *target);
    }

    // Windows target rejection
    let windows_artifact = ManagementArtifact {
        os: "windows".to_string(),
        architecture: "amd64".to_string(),
        filename: "dioramactl-windows-amd64.exe".to_string(),
        size_bytes: 1024,
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    };
    match ReleasePackager::verify_management_artifact(&windows_artifact, "dioramactl") {
        Err(PackageError::WindowsTargetIncluded(name)) => {
            assert!(name.contains("dioramactl-windows-amd64.exe"));
        },
        other => panic!("expected WindowsTargetIncluded error, got {other:?}"),
    }

    // Unknown OS
    let solaris_artifact = ManagementArtifact {
        os: "solaris".to_string(),
        architecture: "amd64".to_string(),
        filename: "dioramactl-solaris-amd64".to_string(),
        size_bytes: 1024,
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
    };
    assert!(ReleasePackager::verify_management_artifact(&solaris_artifact, "dioramactl").is_err());
}

#[test]
fn verify_oci_image_manifest_indices() {
    let oci_images = build_synthetic_oci_images();
    for img in &oci_images {
        ReleasePackager::verify_oci_image_index(img).expect("verify oci index");
    }

    // Unsupported platform mistakenly included in platforms
    let mut invalid_portainer = oci_images[1].clone();
    invalid_portainer.platforms.push(OciPlatformDescriptor {
        platform: "linux/riscv64".to_string(),
        architecture: "riscv64".to_string(),
        os: "linux".to_string(),
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_string(),
        size_bytes: 2048,
    });
    match ReleasePackager::verify_oci_image_index(&invalid_portainer) {
        Err(PackageError::UnsupportedOciPlatformBundled { platform, .. }) => {
            assert_eq!(platform, "linux/riscv64");
        },
        other => panic!("expected UnsupportedOciPlatformBundled, got {other:?}"),
    }

    // Missing unsupported declaration
    let mut missing_declaration = oci_images[1].clone();
    missing_declaration.unsupported_platforms.clear();
    match ReleasePackager::verify_oci_image_index(&missing_declaration) {
        Err(PackageError::MissingRequiredPlatform { platform, .. }) => {
            assert!(platform.contains("unsupported declaration for linux/riscv64"));
        },
        other => panic!("expected MissingRequiredPlatform, got {other:?}"),
    }
}

fn synthetic_release_manifest() -> ReleasePackageManifest {
    let mut node_archives = Vec::new();
    for variant in Matrix::all_node_variants() {
        let fixture_json = match variant.variant {
            Variant::Online => ONLINE_ARM64_JSON,
            Variant::Offline => OFFLINE_ARM64_JSON,
        };
        let (_inv, _bytes, descriptor) = build_synthetic_cell_archive(*variant, fixture_json);
        node_archives.push(descriptor);
    }

    let mut management_binaries = Vec::new();
    for target in Matrix::all_management_targets() {
        let (_content, artifact) = build_synthetic_management_binary(*target);
        management_binaries.push(artifact);
    }

    let oci_images = build_synthetic_oci_images();

    ReleasePackageManifest {
        schema_version: 1,
        product_name: "diorama".to_string(),
        version: "0.1.0".to_string(),
        node_archives,
        management_binaries,
        oci_images,
        excluded_targets: vec![
            "Windows binaries (native win32/win64 excluded per E01; WSL2 uses Linux userspace)"
                .to_string(),
        ],
    }
}

#[test]
fn complete_release_package_manifest_verification() {
    let manifest = synthetic_release_manifest();
    ReleasePackager::verify_release_manifest(&manifest, "diorama", "dioramactl", "0.1.0")
        .expect("verify complete release package manifest");

    // Serialization roundtrip
    let json_str = serde_json::to_string_pretty(&manifest).expect("serialize manifest");
    let deserialized: ReleasePackageManifest =
        serde_json::from_str(&json_str).expect("deserialize manifest");
    assert_eq!(deserialized, manifest);
}

#[test]
fn release_metadata_rejects_incomplete_or_contradictory_descriptors() {
    let mutations: &[fn(&mut ReleasePackageManifest)] = &[
        |m| m.oci_images.clear(),
        |m| {
            m.oci_images.pop();
        },
        |m| m.oci_images.push(m.oci_images[0].clone()),
        |m| m.schema_version = 999,
        |m| m.product_name = "other-product".into(),
        |m| m.version = "9.9.9".into(),
        |m| m.node_archives[0].architecture = "windows-x86".into(),
        |m| m.node_archives[0].libc = "unknown".into(),
        |m| m.node_archives[0].variant = "hardened".into(),
        |m| m.node_archives[0].size_bytes = 0,
        |m| m.node_archives[0].filename = format!("../../x/{}", m.node_archives[0].filename),
        |m| m.node_archives[0].filename = format!("dir\\{}", m.node_archives[0].filename),
        |m| {
            let artifact = m
                .node_archives
                .iter_mut()
                .find(|a| a.architecture == "arm")
                .unwrap();
            artifact.filename = artifact.filename.replace("-arm", "-armv7");
        },
        |m| {
            m.management_binaries[0].filename =
                format!("dir/{}", m.management_binaries[0].filename);
        },
        |m| {
            m.management_binaries[0].filename =
                format!("dir\\{}", m.management_binaries[0].filename);
        },
        |m| m.node_archives[0].sha256 = "A".repeat(64),
        |m| m.management_binaries[0].sha256 = "A".repeat(64),
        |m| m.oci_images[0].index_digest = format!("sha256:{}", "A".repeat(64)),
        |m| m.oci_images[0].platforms[0].digest = format!("sha256:{}", "A".repeat(64)),
        |m| m.node_archives[0].bundled_assets.clear(),
        |m| m.node_archives[0].bundled_assets.push("image-d2k".into()),
        |m| m.management_binaries[0].size_bytes = 0,
        |m| m.management_binaries[1] = m.management_binaries[0].clone(),
        |m| m.oci_images[0].image_reference = "docker.io/unrelated:latest".into(),
        |m| m.oci_images[0].index_digest = "not-a-digest".into(),
        |m| m.oci_images[0].index_media_type = "text/plain".into(),
        |m| m.oci_images[0].platforms[0].digest = format!("sha256:{}", "z".repeat(64)),
        |m| m.oci_images[0].platforms[0].os = "windows".into(),
        |m| m.oci_images[0].platforms[0].architecture = "incorrect".into(),
        |m| m.oci_images[0].platforms[0].media_type = "text/plain".into(),
        |m| {
            let p = m.oci_images[0].platforms[0].clone();
            m.oci_images[0].platforms.push(p);
        },
        |m| {
            m.oci_images[0]
                .unsupported_platforms
                .push("linux/amd64".into());
        },
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut manifest = synthetic_release_manifest();
        mutate(&mut manifest);
        assert!(
            ReleasePackager::verify_release_manifest(&manifest, "diorama", "dioramactl", "0.1.0")
                .is_err(),
            "mutation {index} accepted"
        );
    }
}
