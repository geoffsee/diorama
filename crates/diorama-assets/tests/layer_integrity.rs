use diorama_assets::{
    ArchiveError, ArchiveLimits, ArchivePolicyError, AssetId, DeclaredInventory, DecodeError,
    DecodeLimits, InventoryRequest, LayerCodec, LayerDecodeLimits, LayerDigestArchiveObservation,
    LayerPolicyError as P, Limits, Manifest, Scope, Variant,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde_json::{Value, json};
#[allow(clippy::duplicate_mod)]
#[path = "common/archive.rs"]
mod vectors;
use vectors::{archive, config, entry, gzip, hex, manifest};
const ZSTD: &[u8] = &[
    0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, 0x19, 0, 0, b'a', b'b', b'c',
];
fn zstd_raw(raw: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x50];
    bytes.extend_from_slice(&((u32::try_from(raw.len()).unwrap() << 3) | 1).to_le_bytes()[..3]);
    bytes.extend(raw);
    bytes
}
fn tar(layers: &[&[u8]], decoded: &[&[u8]]) -> Vec<u8> {
    let mut c: Value = serde_json::from_slice(&config("amd64", None, layers.len())).unwrap();
    c["rootfs"]["diff_ids"] = json!(
        decoded
            .iter()
            .map(|b| format!("sha256:{}", hex(b)))
            .collect::<Vec<_>>()
    );
    let c = serde_json::to_vec(&c).unwrap();
    archive(&c, layers, &manifest(&c, layers))
}
fn inventory(bytes: &[u8]) -> DeclaredInventory {
    let mut v: Value =
        serde_json::from_slice(include_bytes!("fixtures/online-amd64.json")).unwrap();
    for row in v["assets"].as_array_mut().unwrap() {
        if row["id"] == "image-coredns" {
            row["delivery"]["encoded_bytes"] = json!(bytes.len());
            row["delivery"]["sha256"] = json!(hex(bytes));
        }
    }
    Manifest::decode(&serde_json::to_vec(&v).unwrap(), Limits::default())
        .unwrap()
        .validate_inventory(
            InventoryRequest {
                target: NodeTarget {
                    architecture: Architecture::Amd64,
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
    limits: LayerDecodeLimits,
) -> Result<LayerDigestArchiveObservation, ArchiveError> {
    inventory(bytes)
        .decoding_session(DecodeLimits::default())
        .unwrap()
        .verify_crane_image_layer_digests(
            AssetId::ImageCoredns,
            bytes,
            ArchiveLimits::default(),
            limits,
        )
}
fn layer_error(error: ArchiveError) -> P {
    match error {
        ArchiveError::Policy(ArchivePolicyError::Layer(p))
        | ArchiveError::Decode(DecodeError::Observer(ArchivePolicyError::Layer(p))) => p,
        e => panic!("unexpected {e:?}"),
    }
}
#[test]
fn independent_gzip_and_zstd_streams_match_exact_declared_diffids() {
    let gz = gzip(b"abc");
    let bytes = gzip(&tar(&[&gz, ZSTD], &[b"abc", b"abc"]));
    let result = inspect(&bytes, LayerDecodeLimits::default()).unwrap();
    assert_eq!(result.layers()[0].codec(), LayerCodec::Gzip);
    assert_eq!(result.layers()[1].codec(), LayerCodec::Zstd);
    for row in result.layers() {
        assert_eq!(row.decoded_bytes(), 3);
        assert_eq!(row.frames(), 1);
        assert_eq!(
            row.diff_id(),
            result.archive().layers()[0].declared_diff_id()
        );
    }
}
#[test]
fn concatenated_members_and_frames_hash_the_whole_decoded_stream() {
    for member in [gzip(b"abc"), ZSTD.to_vec()] {
        let stored = [member.as_slice(), member.as_slice()].concat();
        let bytes = gzip(&tar(&[&stored], &[b"abcabc"]));
        let result = inspect(&bytes, LayerDecodeLimits::default()).unwrap();
        assert_eq!(result.layers()[0].frames(), 2);
        assert_eq!(result.layers()[0].decoded_bytes(), 6);
        assert_eq!(
            layer_error(
                inspect(
                    &bytes,
                    LayerDecodeLimits {
                        frames: 1,
                        ..LayerDecodeLimits::default()
                    }
                )
                .unwrap_err()
            ),
            P::FrameLimit
        );
    }
}
#[test]
fn repeated_references_decode_once_but_charge_ordered_size_every_time() {
    let gz = gzip(b"abc");
    let t = tar(&[&gz, ZSTD, &gz], &[b"abc", b"abc", b"abc"]);
    let bytes = gzip(&t);
    let inv = inventory(&bytes);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    let before = session.remaining_decoded_budget();
    let limits = LayerDecodeLimits {
        unique_decoded_bytes: 6,
        ordered_decoded_bytes: 9,
        ..LayerDecodeLimits::default()
    };
    let result = session
        .verify_crane_image_layer_digests(
            AssetId::ImageCoredns,
            &bytes,
            ArchiveLimits::default(),
            limits,
        )
        .unwrap();
    assert_eq!(
        before - session.remaining_decoded_budget(),
        1 + t.len() as u64 + 6 + 2
    );
    assert_eq!(result.layers().len(), 3);
    assert_eq!(
        result.layers()[0].stored_sha256(),
        result.layers()[2].stored_sha256()
    );
    assert_eq!(
        layer_error(
            inspect(
                &bytes,
                LayerDecodeLimits {
                    ordered_decoded_bytes: 8,
                    ..limits
                }
            )
            .unwrap_err()
        ),
        P::OrderedLimit
    );
    assert_eq!(
        layer_error(
            inspect(
                &bytes,
                LayerDecodeLimits {
                    unique_decoded_bytes: 5,
                    ..limits
                }
            )
            .unwrap_err()
        ),
        P::UniqueLimit
    );
}
#[test]
fn complete_inner_streams_do_not_publish_before_outer_crc_validation() {
    let gz = gzip(b"abc");
    let t = tar(&[&gz], &[b"abc"]);
    let mut bytes = gzip(&t);
    let n = bytes.len();
    bytes[n - 8] ^= 1;
    let inv = inventory(&bytes);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    let before = session.remaining_decoded_budget();
    assert!(
        session
            .verify_crane_image_layer_digests(
                AssetId::ImageCoredns,
                &bytes,
                ArchiveLimits::default(),
                LayerDecodeLimits::default()
            )
            .is_err()
    );
    assert_eq!(
        before - session.remaining_decoded_budget(),
        // The outer CRC failure retains the final offered capacity after prior output.
        1 + t.len() as u64 + 3 + 1 + 8192
    );
}
#[test]
fn rehashed_layer_and_config_cannot_hide_wrong_declared_diffids() {
    let gz = gzip(b"abd");
    let bytes = gzip(&tar(&[&gz], &[b"abc"]));
    assert_eq!(
        layer_error(inspect(&bytes, LayerDecodeLimits::default()).unwrap_err()),
        P::DiffId
    );
    let bytes = gzip(&tar(&[&gz, &gz], &[b"abd", b"abc"]));
    assert!(inspect(&bytes, LayerDecodeLimits::default()).is_err());
}
#[test]
fn metadata_may_precede_or_follow_layers() {
    let gz = gzip(b"abc");
    let mut c: Value = serde_json::from_slice(&config("amd64", None, 1)).unwrap();
    c["rootfs"]["diff_ids"] = json!([format!("sha256:{}", hex(b"abc"))]);
    let c = serde_json::to_vec(&c).unwrap();
    let entries = [
        entry("manifest.json", &manifest(&c, &[&gz])),
        entry(&format!("{}.tar.gz", hex(&gz)), &gz),
        entry(&format!("sha256:{}", hex(&c)), &c),
    ];
    for order in [[0, 1, 2], [1, 2, 0], [2, 0, 1]] {
        let mut raw = Vec::new();
        for i in order {
            raw.extend_from_slice(&entries[i]);
        }
        raw.extend([0; 1024]);
        assert!(inspect(&gzip(&raw), LayerDecodeLimits::default()).is_ok());
    }
}
#[test]
fn truncations_inner_checksums_and_trailing_junk_never_match() {
    let gz = gzip(b"abc");
    let mut z = ZSTD.to_vec();
    z[4] |= 4;
    z.extend([0x99, 0x09, 0x77, 0xad]);
    for stored in [&gz, &z] {
        assert!(
            inspect(
                &gzip(&tar(&[stored], &[b"abc"])),
                LayerDecodeLimits::default()
            )
            .is_ok()
        );
        for end in 0..stored.len() {
            assert!(
                inspect(
                    &gzip(&tar(&[&stored[..end]], &[b"abc"])),
                    LayerDecodeLimits::default()
                )
                .is_err(),
                "prefix {end}"
            );
        }
        let mut bad = stored.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(
            inspect(
                &gzip(&tar(&[&bad], &[b"abc"])),
                LayerDecodeLimits::default()
            )
            .is_err()
        );
        let mut bad = stored.clone();
        bad.extend(b"junk");
        assert!(
            inspect(
                &gzip(&tar(&[&bad], &[b"abc"])),
                LayerDecodeLimits::default()
            )
            .is_err()
        );
    }
}
#[test]
fn identity_skippable_dictionary_and_mixed_codecs_are_explicitly_unsupported() {
    let mut dictionary = ZSTD.to_vec();
    dictionary[4] |= 1;
    dictionary.insert(5, 1);
    let gz = gzip(b"abc");
    let mixed = [gz.as_slice(), ZSTD].concat();
    for (stored, expected) in [
        (b"raw tar bytes".to_vec(), P::UnsupportedCodec),
        (
            vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0],
            P::UnsupportedCodec,
        ),
        (dictionary, P::Dictionary),
        (mixed, P::UnsupportedCodec),
    ] {
        assert_eq!(
            layer_error(
                inspect(
                    &gzip(&tar(&[&stored], &[b"abc"])),
                    LayerDecodeLimits::default()
                )
                .unwrap_err()
            ),
            expected
        );
    }
}
#[test]
fn large_streams_stop_at_exact_limits_without_whole_layer_retention() {
    let raw = vec![b'x'; 32781];
    for stored in [gzip(&raw), zstd_raw(&raw)] {
        let bytes = gzip(&tar(&[&stored], &[&raw]));
        let limits = LayerDecodeLimits {
            stored_bytes: stored.len() as u64,
            decoded_bytes: raw.len() as u64,
            unique_decoded_bytes: raw.len() as u64,
            ordered_decoded_bytes: raw.len() as u64,
            ..LayerDecodeLimits::default()
        };
        assert!(inspect(&bytes, limits).is_ok());
        assert_eq!(
            layer_error(
                inspect(
                    &bytes,
                    LayerDecodeLimits {
                        decoded_bytes: raw.len() as u64 - 1,
                        ..limits
                    }
                )
                .unwrap_err()
            ),
            P::DecodedLimit
        );
        assert_eq!(
            layer_error(
                inspect(
                    &bytes,
                    LayerDecodeLimits {
                        stored_bytes: stored.len() as u64 - 1,
                        ..limits
                    }
                )
                .unwrap_err()
            ),
            P::StoredLimit
        );
    }
}
#[test]
fn invalid_limits_and_wrong_role_have_no_session_effects() {
    let gz = gzip(b"abc");
    let bytes = gzip(&tar(&[&gz], &[b"abc"]));
    let inv = inventory(&bytes);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    let before = (
        session.remaining_encoded_budget(),
        session.remaining_decoded_budget(),
    );
    for limits in [
        LayerDecodeLimits {
            frames: 0,
            ..LayerDecodeLimits::default()
        },
        LayerDecodeLimits {
            header_bytes: 8193,
            ..LayerDecodeLimits::default()
        },
        LayerDecodeLimits {
            window_log: 27,
            ..LayerDecodeLimits::default()
        },
    ] {
        assert!(
            session
                .verify_crane_image_layer_digests(
                    AssetId::ImageCoredns,
                    &bytes,
                    ArchiveLimits::default(),
                    limits
                )
                .is_err()
        );
        assert_eq!(
            before,
            (
                session.remaining_encoded_budget(),
                session.remaining_decoded_budget()
            )
        );
    }
    assert!(
        session
            .verify_crane_image_layer_digests(
                AssetId::Crun,
                &bytes,
                ArchiveLimits::default(),
                LayerDecodeLimits::default()
            )
            .is_err()
    );
    assert_eq!(
        before,
        (
            session.remaining_encoded_budget(),
            session.remaining_decoded_budget()
        )
    );
}
#[test]
fn outer_driver_rechecks_shared_budget_after_nested_output_and_retries() {
    let raw = vec![b'x'; 20000];
    let stored = gzip(&raw);
    let t = tar(&[&stored], &[&raw]);
    let bytes = gzip(&t);
    let inv = inventory(&bytes);
    let total = 1 + t.len() as u64 + raw.len() as u64 + 1;
    let mut exact = inv
        .decoding_session(DecodeLimits {
            total_bytes: total,
            ..DecodeLimits::default()
        })
        .unwrap();
    assert!(
        exact
            .verify_crane_image_layer_digests(
                AssetId::ImageCoredns,
                &bytes,
                ArchiveLimits::default(),
                LayerDecodeLimits::default()
            )
            .is_ok()
    );
    assert_eq!(exact.remaining_decoded_budget(), 0);
    assert!(
        exact
            .verify_crane_image_layer_digests(
                AssetId::ImageCoredns,
                &bytes,
                ArchiveLimits::default(),
                LayerDecodeLimits::default()
            )
            .is_err()
    );
    let mut short = inv
        .decoding_session(DecodeLimits {
            total_bytes: total - 1,
            ..DecodeLimits::default()
        })
        .unwrap();
    assert!(
        short
            .verify_crane_image_layer_digests(
                AssetId::ImageCoredns,
                &bytes,
                ArchiveLimits::default(),
                LayerDecodeLimits::default()
            )
            .is_err()
    );
    assert_eq!(short.remaining_decoded_budget(), 0);
}
#[test]
fn gzip_optional_header_crc_and_window_caps_are_checked() {
    let base = gzip(b"abc");
    let mut stored = base[..10].to_vec();
    stored[3] = 0x1e;
    stored.extend([2, 0, 7, 8, b'n', 0, b'c', 0]);
    let crc = vectors::crc32(&stored);
    stored.extend_from_slice(&crc.to_le_bytes()[..2]);
    stored.extend_from_slice(&base[10..]);
    assert!(
        inspect(
            &gzip(&tar(&[&stored], &[b"abc"])),
            LayerDecodeLimits::default()
        )
        .is_ok()
    );
    assert_eq!(
        layer_error(
            inspect(
                &gzip(&tar(&[&stored], &[b"abc"])),
                LayerDecodeLimits {
                    header_bytes: 19,
                    ..LayerDecodeLimits::default()
                }
            )
            .unwrap_err()
        ),
        P::HeaderLimit
    );
    stored[18] ^= 1;
    assert_eq!(
        layer_error(
            inspect(
                &gzip(&tar(&[&stored], &[b"abc"])),
                LayerDecodeLimits::default()
            )
            .unwrap_err()
        ),
        P::Checksum
    );
    let z = zstd_raw(b"abc");
    assert_eq!(
        layer_error(
            inspect(
                &gzip(&tar(&[&z], &[b"abc"])),
                LayerDecodeLimits {
                    window_log: 10,
                    ..LayerDecodeLimits::default()
                }
            )
            .unwrap_err()
        ),
        P::Window
    );
}
#[test]
fn digest_mismatch_and_parser_failure_retain_both_budget_charges() {
    let gz = gzip(b"abc");
    let t = tar(&[&gz], &[b"abd"]);
    let bytes = gzip(&t);
    let inv = inventory(&bytes);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    let before = (
        session.remaining_encoded_budget(),
        session.remaining_decoded_budget(),
    );
    assert_eq!(
        layer_error(
            session
                .verify_crane_image_layer_digests(
                    AssetId::ImageCoredns,
                    &bytes,
                    ArchiveLimits::default(),
                    LayerDecodeLimits::default()
                )
                .unwrap_err()
        ),
        P::DiffId
    );
    assert!(session.remaining_encoded_budget() < before.0);
    assert_eq!(
        before.1 - session.remaining_decoded_budget(),
        1 + t.len() as u64 + 3 + 1
    );
}

#[test]
fn compressed_expansion_is_bounded_and_late_inner_errors_keep_output_charges() {
    // Independently produced by Python gzip/zlib 1.2.12, dynamic DEFLATE: 32781 x bytes.
    let compressed: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 237, 193, 49, 1, 0, 0, 0, 194, 160, 218, 139, 239, 109,
        7, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 128, 51, 247, 221, 66, 186, 13, 128, 0, 0,
    ];
    let raw = vec![b'x'; 32781];
    let t = tar(&[compressed], &[&raw]);
    let bytes = gzip(&t);
    assert_eq!(
        inspect(&bytes, LayerDecodeLimits::default())
            .unwrap()
            .layers()[0]
            .decoded_bytes(),
        32781
    );
    let inv = inventory(&bytes);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    let before = session.remaining_decoded_budget();
    assert_eq!(
        layer_error(
            session
                .verify_crane_image_layer_digests(
                    AssetId::ImageCoredns,
                    &bytes,
                    ArchiveLimits::default(),
                    LayerDecodeLimits {
                        decoded_bytes: 8193,
                        ..LayerDecodeLimits::default()
                    }
                )
                .unwrap_err()
        ),
        P::DecodedLimit
    );
    assert_eq!(
        before - session.remaining_decoded_budget(),
        1 + t.len() as u64 + 1 + 8193
    );
    let mut bad = compressed.to_vec();
    let n = bad.len();
    bad[n - 8] ^= 1;
    let t = tar(&[&bad], &[&raw]);
    let bytes = gzip(&t);
    let inv = inventory(&bytes);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    let before = session.remaining_decoded_budget();
    assert_eq!(
        layer_error(
            session
                .verify_crane_image_layer_digests(
                    AssetId::ImageCoredns,
                    &bytes,
                    ArchiveLimits::default(),
                    LayerDecodeLimits::default()
                )
                .unwrap_err()
        ),
        P::Checksum
    );
    assert_eq!(
        before - session.remaining_decoded_budget(),
        1 + t.len() as u64 + 1 + 32781
    );
}

#[test]
fn retry_with_relaxed_limits_cannot_replenish_failed_attempt_charges() {
    let stored = gzip(b"abc");
    let t = tar(&[&stored], &[b"abc"]);
    let bytes = gzip(&t);
    let inv = inventory(&bytes);
    let failed_cost = 1 + t.len() as u64 + 1 + 2;
    let success_cost = 1 + t.len() as u64 + 1 + 3;
    let mut session = inv
        .decoding_session(DecodeLimits {
            total_bytes: failed_cost + success_cost - 1,
            ..DecodeLimits::default()
        })
        .unwrap();
    let encoded = session.remaining_encoded_budget();
    assert_eq!(
        layer_error(
            session
                .verify_crane_image_layer_digests(
                    AssetId::ImageCoredns,
                    &bytes,
                    ArchiveLimits::default(),
                    LayerDecodeLimits {
                        decoded_bytes: 2,
                        ..LayerDecodeLimits::default()
                    }
                )
                .unwrap_err()
        ),
        P::DecodedLimit
    );
    assert_eq!(session.remaining_decoded_budget(), success_cost - 1);
    assert!(
        session
            .verify_crane_image_layer_digests(
                AssetId::ImageCoredns,
                &bytes,
                ArchiveLimits::default(),
                LayerDecodeLimits::default()
            )
            .is_err()
    );
    assert_eq!(session.remaining_decoded_budget(), 0);
    assert!(encoded - session.remaining_encoded_budget() >= 2 * bytes.len() as u64);
}
