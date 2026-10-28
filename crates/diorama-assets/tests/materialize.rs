#[allow(clippy::duplicate_mod)]
#[path = "common/archive.rs"]
mod vectors;

use diorama_assets::{
    AssetId, DeclaredInventory, Encoding, InventoryRequest, Kind, Limits, Manifest,
    MaterializationError, Materializer, Scope, Variant,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Cursor,
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
            // Restore write permissions in case test made it read-only
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o755));
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn arm64_request(variant: Variant) -> InventoryRequest {
    InventoryRequest {
        target: NodeTarget {
            architecture: Architecture::Arm64,
            libc: Libc::Glibc,
        },
        variant,
        scope: Scope::SupervisedBundle,
    }
}

fn create_synthetic_payload(
    id: AssetId,
    encoding: Encoding,
) -> (Vec<u8>, Vec<u8>, u64, String, [u8; 32]) {
    // Returns: (uncompressed_content, encoded_bytes, encoded_length, encoded_hex, encoded_hash)
    let content = match id {
        AssetId::ImageCoredns
        | AssetId::ImagePause
        | AssetId::ImageLocalPath
        | AssetId::ImageLocalPathHelper
        | AssetId::ImagePortainerAgent
        | AssetId::ImageD2k
        | AssetId::ImageDiorama => {
            // Valid minimal tar.gz image payload
            let tar_data = entry("layer.tar", b"synthetic image layer");
            gzip(&tar_data)
        },
        _ => format!("synthetic-arm64-binary-{id:?}").into_bytes(),
    };

    let encoded_bytes = match encoding {
        Encoding::Identity | Encoding::Gzip => content.clone(),
        Encoding::Zstd => zstd::encode_all(content.as_slice(), 0).expect("zstd encode"),
    };

    let encoded_len = encoded_bytes.len() as u64;
    let digest: [u8; 32] = Sha256::digest(&encoded_bytes).into();
    let digest_hex = hex(&encoded_bytes);

    (content, encoded_bytes, encoded_len, digest_hex, digest)
}

fn build_synthetic_manifest_and_archive(
    source_json: &str,
    variant: Variant,
) -> (DeclaredInventory, Vec<u8>) {
    let mut manifest_val: Value = serde_json::from_str(source_json).expect("valid fixture");
    let mut archive_bytes = Vec::new();

    let assets_arr = manifest_val["assets"].as_array_mut().expect("assets array");
    for row in assets_arr.iter_mut() {
        let id_str = row["id"].as_str().expect("asset id");
        let delivery_kind = row["delivery"]["kind"].as_str().unwrap_or("");
        if delivery_kind == "bundled" {
            let id = match id_str {
                "containerd" => AssetId::Containerd,
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
            };

            let encoding_str = row["delivery"]["encoding"].as_str().unwrap_or("identity");
            let encoding = match encoding_str {
                "identity" => Encoding::Identity,
                "gzip" => Encoding::Gzip,
                "zstd" => Encoding::Zstd,
                other => panic!("unknown encoding {other}"),
            };

            let (_content, encoded_bytes, encoded_len, digest_hex, _digest) =
                create_synthetic_payload(id, encoding);

            row["delivery"]["encoded_bytes"] = json!(encoded_len);
            row["delivery"]["sha256"] = json!(digest_hex);

            let path = row["delivery"]["path"].as_str().expect("path");
            archive_bytes.extend(entry(path, &encoded_bytes));
        }
    }
    archive_bytes.extend([0u8; 1024]); // tar EOF blocks

    let manifest_bytes = serde_json::to_vec(&manifest_val).expect("serialized json");
    let inventory = Manifest::decode(&manifest_bytes, Limits::default())
        .expect("decode manifest")
        .validate_inventory(arm64_request(variant), Limits::default())
        .expect("validate inventory");

    (inventory, archive_bytes)
}

#[test]
fn accepted_linux_arm64_glibc_payload_cell_materializes_idempotently() {
    for (fixture_json, variant) in [
        (ONLINE_ARM64_JSON, Variant::Online),
        (OFFLINE_ARM64_JSON, Variant::Offline),
    ] {
        let (inventory, archive_data) = build_synthetic_manifest_and_archive(fixture_json, variant);
        let test_dir = TestDir::new("diorama-test-mat-arm64");
        let materializer = Materializer::new(inventory, test_dir.path());

        // First materialization
        let outcome1 = materializer
            .materialize_from_archive(Cursor::new(&archive_data))
            .expect("first materialization succeeds");

        assert_eq!(
            outcome1.assets.len(),
            materializer.inventory().bundled_assets().len()
        );

        for materialized in &outcome1.assets {
            assert!(
                materialized.path.exists(),
                "path {:?} must exist",
                materialized.path
            );
            let meta = fs::metadata(&materialized.path).expect("file metadata");
            assert!(meta.is_file());

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode() & 0o777;
                match materialized.kind {
                    Kind::Executable => {
                        assert_eq!(mode, 0o755, "executable {:?} mode", materialized.path);
                    },
                    Kind::Image => {
                        assert_eq!(mode, 0o644, "image payload {:?} mode", materialized.path);
                    },
                }
            }
        }

        // Second materialization (idempotency check)
        let outcome2 = materializer
            .materialize_from_archive(Cursor::new(&archive_data))
            .expect("second materialization succeeds idempotently");

        assert_eq!(outcome2.assets.len(), outcome1.assets.len());

        for (a1, a2) in outcome1.assets.iter().zip(outcome2.assets.iter()) {
            assert_eq!(a1.id, a2.id);
            assert_eq!(a1.path, a2.path);
            assert_eq!(a1.mode, a2.mode);
            assert_eq!(a1.bytes_written, a2.bytes_written);
            assert_eq!(a1.sha256, a2.sha256);
        }
    }
}

#[test]
fn digest_verification_enforces_arm64_manifest_hashes() {
    let online_bytes = ONLINE_ARM64_JSON.as_bytes();
    let online = Manifest::decode(online_bytes, Limits::default())
        .expect("valid online manifest")
        .validate_inventory(arm64_request(Variant::Online), Limits::default())
        .expect("valid inventory");

    let test_dir = TestDir::new("diorama-test-digest-enforce");
    let materializer = Materializer::new(online, test_dir.path());

    // Provide bad data for containerd
    let bad_data = vec![0x99u8; 45_332_336];
    let err = materializer
        .materialize_single_asset(AssetId::Containerd, Cursor::new(&bad_data))
        .unwrap_err();

    match err {
        MaterializationError::DigestMismatch {
            asset,
            expected,
            observed,
        } => {
            assert_eq!(asset, AssetId::Containerd);
            let expected_hex = expected.iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write;
                write!(&mut s, "{b:02x}").unwrap();
                s
            });
            assert_eq!(
                expected_hex, "b0e4f5a10a8d18e77b276c8cb89638c9d2438579b35286d29ca9fe2521bd2c12",
                "enforces exact ARM64 manifest hash"
            );
            assert_ne!(expected, observed);
        },
        other => panic!("expected DigestMismatch, got {other:?}"),
    }

    // Destination file must NOT exist after digest mismatch
    let final_dest = materializer
        .layout()
        .resolve_destination(test_dir.path(), AssetId::Containerd)
        .unwrap();
    assert!(
        !final_dest.exists(),
        "corrupted asset must not be placed at destination"
    );
}

#[test]
fn repeated_materialization_preserves_content_and_permissions() {
    let (inventory, archive_data) =
        build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
    let test_dir = TestDir::new("diorama-test-perm-preserve");
    let materializer = Materializer::new(inventory, test_dir.path());

    let outcome = materializer
        .materialize_from_archive(Cursor::new(&archive_data))
        .expect("first materialization succeeds");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Intentionally tamper with permissions on disk
        for asset in &outcome.assets {
            fs::set_permissions(&asset.path, fs::Permissions::from_mode(0o600)).unwrap();
            let meta = fs::metadata(&asset.path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        // Repeated materialization should restore correct permissions
        let outcome2 = materializer
            .materialize_from_archive(Cursor::new(&archive_data))
            .expect("second materialization succeeds");

        for asset in &outcome2.assets {
            let meta = fs::metadata(&asset.path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            match asset.kind {
                Kind::Executable => assert_eq!(mode, 0o755),
                Kind::Image => assert_eq!(mode, 0o644),
            }
        }
    }
}

#[test]
fn failed_extraction_leaves_no_usable_looking_partial_install() {
    let (inventory, archive_data) =
        build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
    let test_dir = TestDir::new("diorama-test-partial-install");
    let materializer = Materializer::new(inventory, test_dir.path());

    // Truncate archive data right in the middle
    let truncated_len = archive_data.len() / 2;
    let corrupted_archive = &archive_data[..truncated_len];

    let result = materializer.materialize_from_archive(Cursor::new(corrupted_archive));
    assert!(
        result.is_err(),
        "materialization must fail on truncated archive"
    );

    // Verify destination has NO partial files
    for (id, _, _, _) in materializer.inventory().bundled_assets() {
        let dest = materializer
            .layout()
            .resolve_destination(test_dir.path(), id)
            .unwrap();
        assert!(
            !dest.exists(),
            "destination file {dest:?} must not exist after failed extraction"
        );
    }

    // Verify staging directory does not remain
    let entries: Vec<_> = fs::read_dir(test_dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            !name.starts_with(".staging-"),
            "staging directory {name} should be cleaned up on failure"
        );
    }
}

#[test]
fn corrupt_archive_fails_precisely_without_writing_outside_owned_paths() {
    let (inventory, mut archive_data) =
        build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
    let test_dir = TestDir::new("diorama-test-corrupt-archive");
    let materializer = Materializer::new(inventory, test_dir.path());

    // Test 1: corrupt tar header checksum
    if archive_data.len() >= 150 {
        archive_data[148..156].copy_from_slice(b"999999\0 ");
    }
    let res = materializer.materialize_from_archive(Cursor::new(&archive_data));
    assert!(
        matches!(res, Err(MaterializationError::CorruptArchive(_))),
        "must report CorruptArchive on header checksum failure"
    );

    // Test 2: completely random bytes
    let random_data = vec![0xde, 0xad, 0xbe, 0xef, 0x12, 0x34];
    let res2 = materializer.materialize_from_archive(Cursor::new(&random_data));
    assert!(res2.is_err());

    // Destination root must have no leaked files
    for (id, _, _, _) in materializer.inventory().bundled_assets() {
        let dest = materializer
            .layout()
            .resolve_destination(test_dir.path(), id)
            .unwrap();
        assert!(!dest.exists());
    }
}

#[test]
#[cfg(unix)]
fn read_only_destination_reports_precise_failure() {
    use std::os::unix::fs::PermissionsExt;

    let (inventory, archive_data) =
        build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
    let test_dir = TestDir::new("diorama-test-read-only");

    // Make the test dir read-only
    fs::set_permissions(test_dir.path(), fs::Permissions::from_mode(0o555)).unwrap();

    // Privileged environments may bypass mode bits; characterize enforcement first.
    let probe = test_dir.path().join("permission-probe");
    if fs::write(&probe, b"probe").is_ok() {
        fs::remove_file(probe).unwrap();
        return;
    }

    let materializer = Materializer::new(inventory, test_dir.path());
    let res = materializer.materialize_from_archive(Cursor::new(&archive_data));

    // Restore permissions so drop cleanup can succeed
    let _ = fs::set_permissions(test_dir.path(), fs::Permissions::from_mode(0o755));

    assert!(
        matches!(
            res,
            Err(MaterializationError::ReadOnlyDestination { .. } | MaterializationError::Io { .. })
        ),
        "must report ReadOnlyDestination or PermissionDenied Io error, got {res:?}"
    );
}

#[test]
fn custom_root_fixture_stays_strictly_within_configured_root() {
    let (_inventory, _archive_data) =
        build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
    let test_dir = TestDir::new("diorama-test-path-traversal");

    let layout = materializer_layout_with_traversal();
    let err = layout
        .resolve_destination(test_dir.path(), AssetId::Containerd)
        .unwrap_err();

    assert!(
        matches!(err, MaterializationError::PathEscapesRoot(_)),
        "path traversal must be rejected with PathEscapesRoot, got {err:?}"
    );

    // Absolute path escaping
    let layout_abs =
        diorama_assets::AssetLayout::canonical().with_path(AssetId::Containerd, "/etc/shadow");
    let err_abs = layout_abs
        .resolve_destination(test_dir.path(), AssetId::Containerd)
        .unwrap_err();
    assert!(
        matches!(err_abs, MaterializationError::PathEscapesRoot(_)),
        "absolute escape must be rejected"
    );
}

fn materializer_layout_with_traversal() -> diorama_assets::AssetLayout {
    diorama_assets::AssetLayout::canonical().with_path(AssetId::Containerd, "../../../etc/passwd")
}

#[test]
#[cfg(unix)]
fn existing_directory_and_file_symlinks_cannot_redirect_materialization() {
    for directory in [true, false] {
        let (inventory, archive) =
            build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
        let root = TestDir::new("diorama-no-follow-root");
        let outside = TestDir::new("diorama-no-follow-outside");
        let protected = outside.path().join("containerd");
        fs::write(&protected, b"unmanaged bytes").unwrap();
        if directory {
            std::os::unix::fs::symlink(outside.path(), root.path().join("bin")).unwrap();
        } else {
            fs::create_dir(root.path().join("bin")).unwrap();
            std::os::unix::fs::symlink(&protected, root.path().join("bin/containerd")).unwrap();
        }
        let materializer = Materializer::new(inventory, root.path());
        assert!(
            materializer
                .materialize_from_archive(Cursor::new(archive))
                .is_err()
        );
        assert_eq!(fs::read(protected).unwrap(), b"unmanaged bytes");
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);
    }
}

#[test]
fn obstruction_preserves_prior_installation_and_leaves_no_new_executable() {
    for prior_installation in [false, true] {
        let (inventory, archive) =
            build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
        let root = TestDir::new("diorama-preflight-failure");
        fs::create_dir_all(root.path().join("bin/crun")).unwrap();
        let executable = root.path().join("bin/containerd");
        if prior_installation {
            fs::write(&executable, b"previous installation").unwrap();
        }
        let materializer = Materializer::new(inventory, root.path());
        assert!(
            materializer
                .materialize_from_archive(Cursor::new(archive))
                .is_err()
        );
        if prior_installation {
            assert_eq!(fs::read(executable).unwrap(), b"previous installation");
        } else {
            assert!(!executable.exists());
        }
        assert!(!fs::read_dir(root.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".staging-")
        }));
    }
}

#[test]
fn corrupt_and_truncated_outer_gzip_trailers_fail_before_commit() {
    for corruption in ["crc", "size", "truncated", "concatenated", "trailing"] {
        let (inventory, archive) =
            build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
        let mut archive = gzip(&archive);
        let length = archive.len();
        match corruption {
            "crc" => archive[length - 8] ^= 0x80,
            "size" => archive[length - 4] ^= 0x80,
            "concatenated" => archive.extend(gzip(b"second member")),
            "trailing" => archive.extend(b"junk"),
            _ => archive.truncate(length - 4),
        }
        let root = TestDir::new("diorama-outer-gzip-integrity");
        assert!(
            Materializer::new(inventory, root.path())
                .materialize_from_archive(Cursor::new(archive))
                .is_err()
        );
        assert!(!root.path().join("bin/containerd").exists());
    }
}

#[test]
fn valid_outer_gzip_supports_short_reader_reads() {
    struct ShortReads<T>(T);
    impl<T: std::io::Read> std::io::Read for ShortReads<T> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let size = output.len().min(1);
            self.0.read(&mut output[..size])
        }
    }
    let (inventory, archive) =
        build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
    let root = TestDir::new("diorama-short-gzip-reads");
    Materializer::new(inventory, root.path())
        .materialize_from_archive(ShortReads(Cursor::new(gzip(&archive))))
        .unwrap();
    assert!(root.path().join("bin/containerd").is_file());
}

#[test]
#[cfg(unix)]
fn repeat_materialization_clears_all_special_permission_bits() {
    use std::os::unix::fs::PermissionsExt;
    let (inventory, archive) =
        build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
    let root = TestDir::new("diorama-exact-modes");
    let materializer = Materializer::new(inventory, root.path());
    let first = materializer
        .materialize_from_archive(Cursor::new(&archive))
        .unwrap();
    for asset in &first.assets {
        fs::set_permissions(&asset.path, fs::Permissions::from_mode(asset.mode | 0o7000)).unwrap();
    }
    let repeated = materializer
        .materialize_from_archive(Cursor::new(&archive))
        .unwrap();
    for asset in &repeated.assets {
        assert_eq!(
            fs::metadata(&asset.path).unwrap().permissions().mode() & 0o7777,
            asset.mode
        );
    }
}

#[test]
#[cfg(unix)]
fn ancestor_replaced_during_payload_read_cannot_redirect_commit() {
    let (inventory, _) = build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
    let payloads = inventory
        .bundled_assets()
        .map(|(id, _, encoding, _)| (id, create_synthetic_payload(id, encoding).1))
        .collect::<std::collections::BTreeMap<_, _>>();
    let root = TestDir::new("diorama-ancestor-race");
    let outside = TestDir::new("diorama-ancestor-race-outside");
    fs::create_dir(root.path().join("bin")).unwrap();
    fs::write(root.path().join("bin/containerd"), b"previous installation").unwrap();
    let materializer = Materializer::new(inventory, root.path());
    let mut replaced = false;
    let result = materializer.materialize_from_payloads(|id, _| {
        if !replaced {
            fs::rename(root.path().join("bin"), root.path().join("original-bin")).unwrap();
            std::os::unix::fs::symlink(outside.path(), root.path().join("bin")).unwrap();
            replaced = true;
        }
        Ok(Box::new(Cursor::new(payloads[&id].clone())))
    });
    assert!(result.is_err());
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    assert_eq!(
        fs::read(root.path().join("original-bin/containerd")).unwrap(),
        b"previous installation"
    );
}

#[test]
fn concurrent_materializers_preserve_complete_owned_assets() {
    let (inventory, archive) =
        build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
    let root = TestDir::new("diorama-concurrent-materialization");
    let materializer = Materializer::new(inventory, root.path());
    std::thread::scope(|scope| {
        let first = scope.spawn(|| materializer.materialize_from_archive(Cursor::new(&archive)));
        let second = scope.spawn(|| materializer.materialize_from_archive(Cursor::new(&archive)));
        assert_eq!(
            first.join().unwrap().unwrap().assets,
            second.join().unwrap().unwrap().assets
        );
    });
    assert!(!fs::read_dir(root.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".staging-")
    }));
}

#[test]
fn archive_stages_members_before_reading_the_next_header() {
    use std::io::Read;
    struct ObserveStaging<'a> {
        source: Cursor<Vec<u8>>,
        root: &'a Path,
        first_end: u64,
        observed: bool,
    }
    impl Read for ObserveStaging<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            assert!(
                buffer.len() <= 8192,
                "archive reads must use bounded buffers"
            );
            if !self.observed && self.source.position() >= self.first_end {
                self.observed = fs::read_dir(self.root)?
                    .filter_map(Result::ok)
                    .flat_map(|dir| fs::read_dir(dir.path()).into_iter().flatten())
                    .filter_map(Result::ok)
                    .any(|file| file.file_name().to_string_lossy().starts_with("staged-"));
                assert!(
                    self.observed,
                    "first payload must stage before the next header is read"
                );
            }
            self.source.read(buffer)
        }
    }
    let (inventory, archive) =
        build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
    let size = u64::from_str_radix(std::str::from_utf8(&archive[124..135]).unwrap(), 8).unwrap();
    let root = TestDir::new("diorama-stream-member");
    let mut reader = ObserveStaging {
        source: Cursor::new(archive),
        root: root.path(),
        first_end: 512 + size.div_ceil(512) * 512,
        observed: false,
    };
    Materializer::new(inventory, root.path())
        .materialize_from_archive(&mut reader)
        .unwrap();
    assert!(reader.observed);
}

#[test]
fn duplicate_selected_members_are_rejected_before_commit() {
    let (inventory, archive) =
        build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
    let size = usize::from_str_radix(std::str::from_utf8(&archive[124..135]).unwrap(), 8).unwrap();
    let first_end = 512 + size.div_ceil(512) * 512;
    let duplicate = archive[..first_end]
        .iter()
        .chain(archive.iter())
        .copied()
        .collect::<Vec<_>>();
    let root = TestDir::new("diorama-duplicate-member");
    assert!(matches!(
        Materializer::new(inventory, root.path()).materialize_from_archive(Cursor::new(duplicate)),
        Err(MaterializationError::CorruptArchive(_))
    ));
    assert!(!root.path().join("bin").exists());
}

#[test]
fn nonregular_members_obey_count_and_byte_budgets_and_reject_truncation() {
    for scenario in ["count", "size", "truncated"] {
        let (inventory, _) =
            build_synthetic_manifest_and_archive(ONLINE_ARM64_JSON, Variant::Online);
        let mut header = entry("ignored-dir", b"")[..512].to_vec();
        header[156] = b'5';
        let size = if scenario == "size" {
            4 * 1024 * 1024 * 1024u64
        } else if scenario == "truncated" {
            100
        } else {
            0
        };
        header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        vectors::checksum(&mut header);
        let archive = if scenario == "count" {
            [header.clone(), header].concat()
        } else {
            header
        };
        let root = TestDir::new("diorama-nonregular-budget");
        let materializer = Materializer::new(inventory, root.path()).with_limits(
            diorama_assets::MaterializationLimits {
                max_total_bytes: 1024,
                max_archive_members: 1,
                ..Default::default()
            },
        );
        let result = materializer.materialize_from_archive(Cursor::new(archive));
        if scenario == "size" {
            assert!(matches!(
                result,
                Err(MaterializationError::BudgetExceeded { .. })
            ));
        } else {
            assert!(matches!(
                result,
                Err(MaterializationError::CorruptArchive(_))
            ));
        }
        assert!(!root.path().join("bin").exists());
    }
}

#[test]
fn compressed_single_asset_enforces_decoded_budget_without_committing() {
    let mut manifest: Value = serde_json::from_str(ONLINE_ARM64_JSON).unwrap();
    let content = vec![b'x'; 128 * 1024];
    let encoded = zstd::encode_all(content.as_slice(), 0).unwrap();
    let row = manifest["assets"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["id"] == "crun")
        .unwrap();
    row["delivery"]["encoded_bytes"] = json!(encoded.len());
    row["delivery"]["sha256"] = json!(hex(&encoded));
    let inventory = Manifest::decode(&serde_json::to_vec(&manifest).unwrap(), Limits::default())
        .unwrap()
        .validate_inventory(arm64_request(Variant::Online), Limits::default())
        .unwrap();
    let root = TestDir::new("diorama-decoded-budget");
    let materializer = Materializer::new(inventory, root.path()).with_limits(
        diorama_assets::MaterializationLimits {
            max_asset_bytes: 1024,
            ..Default::default()
        },
    );
    assert!(matches!(
        materializer.materialize_single_asset(AssetId::Crun, Cursor::new(encoded)),
        Err(MaterializationError::BudgetExceeded { .. })
    ));
    assert!(!root.path().join("bin").exists());
    assert!(!fs::read_dir(root.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".staging-")
    }));
}
