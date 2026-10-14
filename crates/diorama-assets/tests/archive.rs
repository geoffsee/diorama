use diorama_assets::{
    ArchiveError, ArchiveLimits, ArchivePolicyError as Policy, AssetId, DeclaredInventory,
    DecodeError, DecodeLimits, DecodePolicyError, DockerArchiveObservation, ImagePlatformStatus,
    InventoryRequest, Limits, Manifest, Scope, Variant,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde_json::{Value, json};
#[allow(clippy::duplicate_mod)]
#[path = "common/archive.rs"]
mod vectors;
use vectors::{archive, checksum, config, entry, gzip, hex, manifest, standard};
fn inventory(bytes: &[u8], arch: Architecture) -> DeclaredInventory {
    let mut value: Value =
        serde_json::from_slice(include_bytes!("fixtures/online-amd64.json")).unwrap();
    value["target"]["architecture"] = json!(match arch {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
        Architecture::ArmV7 => "armv7",
        Architecture::Riscv64 => "riscv64",
    });
    for row in value["assets"].as_array_mut().unwrap() {
        if row["id"] == "image-coredns" {
            row["delivery"]["encoded_bytes"] = json!(bytes.len());
            row["delivery"]["sha256"] = json!(hex(bytes));
        }
        if (row["id"] == "image-d2k" && matches!(arch, Architecture::ArmV7 | Architecture::Riscv64))
            || (row["id"] == "image-portainer-agent" && arch == Architecture::Riscv64)
        {
            row["delivery"] = json!({"kind":"unavailable"});
        }
    }
    Manifest::decode(&serde_json::to_vec(&value).unwrap(), Limits::default())
        .unwrap()
        .validate_inventory(
            InventoryRequest {
                target: NodeTarget {
                    architecture: arch,
                    libc: Libc::Glibc,
                },
                variant: Variant::Online,
                scope: Scope::SupervisedBundle,
            },
            Limits::default(),
        )
        .unwrap()
}
fn inspect(
    bytes: &[u8],
    arch: Architecture,
    limits: ArchiveLimits,
) -> Result<DockerArchiveObservation, ArchiveError> {
    inventory(bytes, arch)
        .decoding_session(DecodeLimits::default())
        .unwrap()
        .inspect_crane_image_archive(AssetId::ImageCoredns, bytes, limits)
}
fn inspect_tar(tar: &[u8]) -> Result<DockerArchiveObservation, ArchiveError> {
    inspect(&gzip(tar), Architecture::Amd64, ArchiveLimits::default())
}
fn policy(error: &ArchiveError) -> Policy {
    match error {
        ArchiveError::Policy(p) | ArchiveError::Decode(DecodeError::Observer(p)) => *p,
        ArchiveError::Decode(_) => panic!("unexpected error: {error:?}"),
    }
}
#[test]
fn complete_outer_archive_reports_member_identity_without_layer_integrity_claim() {
    let tar = standard();
    let bytes = gzip(&tar);
    let result = inspect(&bytes, Architecture::Amd64, ArchiveLimits::default()).unwrap();
    assert_eq!(
        result.decoded_observation().decoded_bytes(),
        tar.len() as u64
    );
    assert_eq!(
        result.decoded_observation().encoded().id(),
        AssetId::ImageCoredns
    );
    assert_eq!(result.config().architecture(), "amd64");
    assert_eq!(result.config().os(), "linux");
    assert_eq!(
        result.config().platform_status(),
        ImagePlatformStatus::DeclaredMatch
    );
    assert_eq!(result.layers().len(), 1);
    assert_eq!(result.layers()[0].bytes(), 3);
    // SHA256(abc) is independent; member bytes are intentionally not a gzip stream/tar layer.
    assert_eq!(
        result.layers()[0].sha256(),
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    assert_eq!(result.layers()[0].declared_diff_id(), &[0x11; 32]);
    assert_eq!(result.repo_tags(), &["example.invalid/image:fixture"]);
}
#[test]
fn deduplicated_members_preserve_repeated_ordered_layer_references() {
    let c = config("amd64", None, 3);
    let layers = [&b"abc"[..], &b"xyz"[..], &b"abc"[..]];
    let result = inspect_tar(&archive(&c, &layers, &manifest(&c, &layers))).unwrap();
    assert_eq!(result.layers().len(), 3);
    assert_eq!(result.layers()[0].sha256(), result.layers()[2].sha256());
    assert_ne!(result.layers()[0].sha256(), result.layers()[1].sha256());
}
#[test]
fn ordered_layer_repeats_cannot_declare_conflicting_diffids() {
    let mut c: Value = serde_json::from_slice(&config("amd64", None, 2)).unwrap();
    c["rootfs"]["diff_ids"][1] = json!(format!("sha256:{}", "22".repeat(32)));
    let c = serde_json::to_vec(&c).unwrap();
    let layers = [&b"abc"[..], &b"abc"[..]];
    assert_eq!(
        policy(&inspect_tar(&archive(&c, &layers, &manifest(&c, &layers))).unwrap_err()),
        Policy::References
    );
}
#[test]
fn manifest_may_precede_members_and_null_or_empty_tags_are_metadata_only() {
    let c = config("amd64", None, 1);
    let layers = [&b"abc"[..]];
    for tags in [Value::Null, json!([])] {
        let mut m: Value = serde_json::from_slice(&manifest(&c, &layers)).unwrap();
        m[0]["RepoTags"] = tags;
        let m = serde_json::to_vec(&m).unwrap();
        let mut tar = entry("manifest.json", &m);
        tar.extend(entry(&format!("{}.tar.gz", hex(b"abc")), b"abc"));
        tar.extend(entry(&format!("sha256:{}", hex(&c)), &c));
        tar.extend([0; 1024]);
        let empty: &[String] = &[];
        assert_eq!(inspect_tar(&tar).unwrap().repo_tags(), empty);
    }
}
#[test]
fn checksummed_wrong_platform_and_arm_variant_remain_distinct() {
    for (os, arch, target, variant, expected) in [
        (
            "linux",
            "arm64",
            Architecture::Amd64,
            None,
            Some(Policy::PlatformMismatch),
        ),
        (
            "windows",
            "amd64",
            Architecture::Amd64,
            None,
            Some(Policy::PlatformMismatch),
        ),
        (
            "linux",
            "arm",
            Architecture::ArmV7,
            Some("v6"),
            Some(Policy::PlatformMismatch),
        ),
        ("linux", "arm", Architecture::ArmV7, None, None),
        ("linux", "arm", Architecture::ArmV7, Some("v7"), None),
        ("linux", "arm64", Architecture::Arm64, Some("v8.1"), None),
        ("linux", "riscv64", Architecture::Riscv64, None, None),
    ] {
        let mut c: Value = serde_json::from_slice(&config(arch, variant, 1)).unwrap();
        c["os"] = json!(os);
        let c = serde_json::to_vec(&c).unwrap();
        let layers = [&b"abc"[..]];
        let result = inspect(
            &gzip(&archive(&c, &layers, &manifest(&c, &layers))),
            target,
            ArchiveLimits::default(),
        );
        if let Some(expected) = expected {
            assert_eq!(policy(&result.unwrap_err()), expected);
        } else {
            let expected = if (target == Architecture::ArmV7 && variant.is_none())
                || variant == Some("v8.1")
            {
                ImagePlatformStatus::VariantUnresolved
            } else {
                ImagePlatformStatus::DeclaredMatch
            };
            assert_eq!(result.unwrap().config().platform_status(), expected);
        }
    }
}
#[test]
fn duplicate_json_keys_fail_even_inside_ignored_config_extensions() {
    let base = String::from_utf8(config("amd64", None, 1)).unwrap();
    for c in [
        format!("{{\"os\":\"linux\",{}", &base[1..]),
        format!("{{\"new\":{{\"x\":1,\"x\":2}},{}", &base[1..]),
        format!("{{\"new\":[{{\"x\":1,\"\\u0078\":2}}],{}", &base[1..]),
    ] {
        let c = c.into_bytes();
        let layers = [&b"abc"[..]];
        assert_eq!(
            policy(&inspect_tar(&archive(&c, &layers, &manifest(&c, &layers))).unwrap_err()),
            Policy::Json
        );
    }
    let c = config("amd64", None, 1);
    let layers = [&b"abc"[..]];
    let m = String::from_utf8(manifest(&c, &layers)).unwrap();
    let m = format!("[{{\"Layers\":[],{}", &m[2..]);
    assert_eq!(
        policy(&inspect_tar(&archive(&c, &layers, m.as_bytes())).unwrap_err()),
        Policy::Json
    );
}
#[test]
fn json_depth_and_metadata_limits_fail_before_unbounded_retention() {
    let tar = standard();
    let bytes = gzip(&tar);
    for limits in [
        ArchiveLimits {
            config_bytes: 1,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            manifest_bytes: 1,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            members: 2,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            json_depth: 2,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            tag_bytes: 1,
            ..ArchiveLimits::default()
        },
    ] {
        assert!(inspect(&bytes, Architecture::Amd64, limits).is_err());
    }
    let c = config("amd64", None, 2);
    let layers = [&b"abc"[..], &b"abc"[..]];
    assert!(
        inspect(
            &gzip(&archive(&c, &layers, &manifest(&c, &layers))),
            Architecture::Amd64,
            ArchiveLimits {
                layer_references: 1,
                ..ArchiveLimits::default()
            }
        )
        .is_err()
    );
}
#[test]
fn header_checksum_numeric_encoding_and_unsupported_types_are_rejected() {
    let original = standard();
    let mut bad = original.clone();
    bad[100] ^= 1;
    assert_eq!(policy(&inspect_tar(&bad).unwrap_err()), Policy::Header);
    for offset in [124, 136] {
        let mut bad = original.clone();
        bad[offset] = 0x80;
        checksum(&mut bad[..512]);
        assert_eq!(policy(&inspect_tar(&bad).unwrap_err()), Policy::Header);
    }
    for kind in [
        b'1', b'2', b'3', b'4', b'5', b'6', b'x', b'g', b'L', b'K', b'S', 0,
    ] {
        let mut bad = original.clone();
        bad[156] = kind;
        checksum(&mut bad[..512]);
        assert_eq!(
            policy(&inspect_tar(&bad).unwrap_err()),
            Policy::UnsupportedEntry
        );
    }
    for offset in [157, 345] {
        let mut bad = original.clone();
        bad[offset] = b'x';
        checksum(&mut bad[..512]);
        assert_eq!(
            policy(&inspect_tar(&bad).unwrap_err()),
            Policy::UnsupportedEntry
        );
    }
}
#[test]
fn names_duplicates_and_member_digest_mismatch_are_rejected() {
    for name in [
        "../manifest.json",
        "/manifest.json",
        "./manifest.json",
        "a/b",
        "C:\\escape",
        "sha256:bad",
    ] {
        let mut tar = entry(name, b"{}");
        tar.extend([0; 1024]);
        assert_eq!(policy(&inspect_tar(&tar).unwrap_err()), Policy::Name);
    }
    let original = standard();
    let mut tar = original[..original.len() - 1024].to_vec();
    tar.extend_from_slice(&original[..1024]);
    tar.extend([0; 1024]);
    assert_eq!(
        policy(&inspect_tar(&tar).unwrap_err()),
        Policy::DuplicateMember
    );
    let mut bad = original.clone();
    bad[512] ^= 1;
    assert_eq!(
        policy(&inspect_tar(&bad).unwrap_err()),
        Policy::MemberDigest
    );
    let mut bad = original;
    bad[1024 + 512] ^= 1;
    assert_eq!(
        policy(&inspect_tar(&bad).unwrap_err()),
        Policy::MemberDigest
    );
}
#[test]
fn padding_end_markers_truncation_and_trailing_tar_fail_after_outer_rehash() {
    let original = standard();
    let mut bad = original.clone();
    bad[1023] = 1;
    assert_eq!(policy(&inspect_tar(&bad).unwrap_err()), Policy::Padding);
    for length in [
        1,
        511,
        513,
        original.len() - 1024,
        original.len() - 512,
        original.len() - 1,
    ] {
        assert!(inspect_tar(&original[..length]).is_err(), "{length}");
    }
    for tail in [vec![0], vec![0; 512], vec![1; 512], original.clone()] {
        let mut bad = original.clone();
        bad.extend(tail);
        assert_eq!(policy(&inspect_tar(&bad).unwrap_err()), Policy::Trailing);
    }
    let mut bad = original.clone();
    let end = bad.len() - 512;
    bad[end] = 1;
    assert_eq!(policy(&inspect_tar(&bad).unwrap_err()), Policy::Header);
}
#[test]
fn reference_closure_foreign_layers_and_manifest_shape_are_checked() {
    let c = config("amd64", None, 1);
    let layers = [&b"abc"[..]];
    let base: Value = serde_json::from_slice(&manifest(&c, &layers)).unwrap();
    for (field, value, expected) in [
        ("Config", json!("sha256:missing"), Policy::References),
        ("Layers", json!([]), Policy::References),
        ("Layers", json!(["missing.tar.gz"]), Policy::References),
        ("LayerSources", json!({"source":{}}), Policy::ForeignLayers),
        ("RepoTags", json!([5]), Policy::Manifest),
        ("Other", json!(true), Policy::Manifest),
    ] {
        let mut m = base.clone();
        m[0][field] = value;
        assert_eq!(
            policy(
                &inspect_tar(&archive(&c, &layers, &serde_json::to_vec(&m).unwrap())).unwrap_err()
            ),
            expected
        );
    }
    for m in [
        json!([]),
        json!([base[0].clone(), base[0].clone()]),
        json!({}),
    ] {
        assert_eq!(
            policy(
                &inspect_tar(&archive(&c, &layers, &serde_json::to_vec(&m).unwrap())).unwrap_err()
            ),
            Policy::Manifest
        );
    }
    let extra = [&b"abc"[..], &b"unreferenced"[..]];
    assert_eq!(
        policy(&inspect_tar(&archive(&c, &extra, &manifest(&c, &layers))).unwrap_err()),
        Policy::References
    );
}
#[test]
fn corrupt_outer_gzip_trailer_never_publishes_complete_archive_observation() {
    let original = gzip(&standard());
    for index in [original.len() - 8, original.len() - 4] {
        let mut bytes = original.clone();
        bytes[index] ^= 1;
        assert!(matches!(
            inspect(&bytes, Architecture::Amd64, ArchiveLimits::default()),
            Err(ArchiveError::Decode(DecodeError::Decoder(_)))
        ));
    }
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(matches!(
        inspect(&trailing, Architecture::Amd64, ArchiveLimits::default()),
        Err(ArchiveError::Decode(DecodeError::Policy(
            DecodePolicyError::Trailing
        )))
    ));
    let mut multiple = original.clone();
    multiple.extend(original);
    assert!(inspect(&multiple, Architecture::Amd64, ArchiveLimits::default()).is_err());
}
#[test]
fn limits_roles_and_failed_attempts_preserve_retained_session_accounting() {
    let tar = standard();
    let bytes = gzip(&tar);
    let inv = inventory(&bytes, Architecture::Amd64);
    let cost = tar.len() as u64 + 1;
    let mut session = inv
        .decoding_session(DecodeLimits {
            total_bytes: cost * 2,
            ..DecodeLimits::default()
        })
        .unwrap();
    let before = (
        session.remaining_encoded_budget(),
        session.remaining_decoded_budget(),
    );
    assert!(
        session
            .inspect_crane_image_archive(AssetId::Crun, &bytes, ArchiveLimits::default())
            .is_err()
    );
    for limits in [
        ArchiveLimits {
            archive_bytes: 0,
            ..ArchiveLimits::default()
        },
        ArchiveLimits {
            json_depth: 65,
            ..ArchiveLimits::default()
        },
    ] {
        assert!(
            session
                .inspect_crane_image_archive(AssetId::ImageCoredns, &bytes, limits)
                .is_err()
        );
    }
    assert_eq!(
        before,
        (
            session.remaining_encoded_budget(),
            session.remaining_decoded_budget()
        )
    );
    session
        .inspect_crane_image_archive(
            AssetId::ImageCoredns,
            &bytes,
            ArchiveLimits {
                archive_bytes: tar.len() as u64,
                ..ArchiveLimits::default()
            },
        )
        .unwrap();
    assert_eq!(session.remaining_decoded_budget(), cost);
    assert!(
        session
            .inspect_crane_image_archive(
                AssetId::ImageCoredns,
                &bytes,
                ArchiveLimits {
                    archive_bytes: tar.len() as u64 - 1,
                    ..ArchiveLimits::default()
                }
            )
            .is_err()
    );
    assert_eq!(session.remaining_decoded_budget(), 1);
    assert_eq!(
        session.remaining_encoded_budget(),
        before.0 - 2 * (bytes.len() as u64 + 1)
    );
    assert!(
        session
            .inspect_crane_image_archive(AssetId::ImageCoredns, &bytes, ArchiveLimits::default())
            .is_err()
    );
    assert_eq!(session.remaining_decoded_budget(), 0);
}
#[test]
fn parser_failure_after_full_decode_keeps_all_charged_bytes() {
    let c = config("arm64", None, 1);
    let layers = [&b"abc"[..]];
    let tar = archive(&c, &layers, &manifest(&c, &layers));
    let bytes = gzip(&tar);
    let inv = inventory(&bytes, Architecture::Amd64);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    assert_eq!(
        policy(
            &session
                .inspect_crane_image_archive(
                    AssetId::ImageCoredns,
                    &bytes,
                    ArchiveLimits::default()
                )
                .unwrap_err()
        ),
        Policy::PlatformMismatch
    );
    assert_eq!(
        session.remaining_decoded_budget(),
        DecodeLimits::default().total_bytes - tar.len() as u64 - 1
    );
    assert_eq!(
        session.remaining_encoded_budget(),
        Limits::default().encoded_total_bytes - bytes.len() as u64 - 1
    );
}

#[test]
fn corrupt_trailer_and_midchunk_parser_failure_retain_consumed_budgets() {
    let c = config("amd64", None, 1);
    let layer = vec![b'a'; 20001];
    let layers = [layer.as_slice()];
    let tar = archive(&c, &layers, &manifest(&c, &layers));
    let mut bytes = gzip(&tar);
    let index = bytes.len() - 8;
    bytes[index] ^= 1;
    let inv = inventory(&bytes, Architecture::Amd64);
    let mut generic = inv.decoding_session(DecodeLimits::default()).unwrap();
    assert!(
        generic
            .inspect_compressed_blob(AssetId::ImageCoredns, &bytes, |_| Ok::<
                _,
                std::convert::Infallible,
            >(()))
            .is_err()
    );
    assert!(generic.remaining_decoded_budget() < DecodeLimits::default().total_bytes - 8192);
    let mut composed = inv.decoding_session(DecodeLimits::default()).unwrap();
    assert!(
        composed
            .inspect_crane_image_archive(AssetId::ImageCoredns, &bytes, ArchiveLimits::default())
            .is_err()
    );
    assert_eq!(
        composed.remaining_decoded_budget(),
        generic.remaining_decoded_budget()
    );
    assert_eq!(
        composed.remaining_encoded_budget(),
        generic.remaining_encoded_budget()
    );
    let mut tar = standard();
    tar[0] = b'/';
    checksum(&mut tar[..512]);
    let bytes = gzip(&tar);
    let inv = inventory(&bytes, Architecture::Amd64);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    assert_eq!(
        policy(
            &session
                .inspect_crane_image_archive(
                    AssetId::ImageCoredns,
                    &bytes,
                    ArchiveLimits::default()
                )
                .unwrap_err()
        ),
        Policy::Name
    );
    assert_eq!(
        session.remaining_encoded_budget(),
        Limits::default().encoded_total_bytes - bytes.len() as u64 - 1
    );
    assert_eq!(
        session.remaining_decoded_budget(),
        DecodeLimits::default().total_bytes - tar.len() as u64 - 1
    );
}
#[test]
fn empty_layer_inventory_and_declared_hash_guards_are_observable() {
    let c = config("amd64", None, 0);
    let tar = archive(&c, &[], &manifest(&c, &[]));
    assert!(inspect_tar(&tar).unwrap().layers().is_empty());
    let bytes = gzip(&standard());
    let inv = inventory(&bytes, Architecture::Amd64);
    let mut changed = bytes.clone();
    changed[4] ^= 1;
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    assert!(matches!(
        session.inspect_crane_image_archive(
            AssetId::ImageCoredns,
            &changed,
            ArchiveLimits::default()
        ),
        Err(ArchiveError::Decode(DecodeError::Encoded(_)))
    ));
    assert_eq!(
        session.remaining_decoded_budget(),
        DecodeLimits::default().total_bytes - 1
    );
}

#[test]
fn large_layer_streams_across_decoder_chunks_and_tighter_cap_stops_midmember() {
    let c = config("amd64", None, 1);
    let layer = vec![0x53; 32781];
    let layers = [layer.as_slice()];
    let tar = archive(&c, &layers, &manifest(&c, &layers));
    let bytes = gzip(&tar);
    let result = inspect(&bytes, Architecture::Amd64, ArchiveLimits::default()).unwrap();
    assert_eq!(result.layers()[0].bytes(), 32781);
    let expected: [u8; 32] =
        sha2::Digest::finalize(sha2::Digest::chain_update(sha2::Sha256::default(), &layer)).into();
    assert_eq!(result.layers()[0].sha256(), &expected);
    let inv = inventory(&bytes, Architecture::Amd64);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    assert!(matches!(
        session.inspect_crane_image_archive(
            AssetId::ImageCoredns,
            &bytes,
            ArchiveLimits {
                archive_bytes: 20000,
                ..ArchiveLimits::default()
            }
        ),
        Err(ArchiveError::Decode(DecodeError::Observer(Policy::Limit)))
    ));
    // Header's declared layer size already exceeds this archive policy; that first decoded
    // chunk is charged before the private observer rejects its header.
    assert_eq!(
        session.remaining_decoded_budget(),
        DecodeLimits::default().total_bytes - 8193
    );
    let mut session = inv
        .decoding_session(DecodeLimits {
            image_bytes: 20000,
            ..DecodeLimits::default()
        })
        .unwrap();
    assert!(matches!(
        session.inspect_crane_image_archive(
            AssetId::ImageCoredns,
            &bytes,
            ArchiveLimits::default()
        ),
        Err(ArchiveError::Decode(DecodeError::Policy(
            DecodePolicyError::ContentLimit
        )))
    ));
    assert_eq!(
        session.remaining_decoded_budget(),
        DecodeLimits::default().total_bytes - 20001
    );
}
