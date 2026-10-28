use diorama_assets::{
    AssetId, DeclaredInventory, DecodeError, DecodeLimits, DecodePolicyError, InventoryRequest,
    Limits, Manifest, Scope, Variant,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{convert::Infallible, fmt::Write, io};
// Independently assembled RFC1952 member: stored DEFLATE block, CRC32(abc), ISIZE3.
const GZIP: &[u8] = &[
    0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 1, 3, 0, 0xfc, 0xff, b'a', b'b', b'c', 0xc2, 0x41, 0x24,
    0x35, 3, 0, 0, 0,
];
// Zstandard single-segment frame, content-size3, final raw block length3.
const ZSTD: &[u8] = &[
    0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, 0x19, 0, 0, b'a', b'b', b'c',
];
const ABC_SHA: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];
fn id(bytes: &[u8]) -> AssetId {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        AssetId::ImageCoredns
    } else {
        AssetId::Crun
    }
}
fn inventory(bytes: &[u8], asset: AssetId) -> DeclaredInventory {
    let mut value: Value =
        serde_json::from_slice(include_bytes!("fixtures/online-amd64.json")).unwrap();
    let name = if asset == AssetId::Crun {
        "crun"
    } else {
        "image-coredns"
    };
    let hash = Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            write!(&mut s, "{b:02x}").unwrap();
            s
        });
    for row in value["assets"].as_array_mut().unwrap() {
        if row["id"] == name {
            row["delivery"]["encoded_bytes"] = json!(bytes.len());
            row["delivery"]["sha256"] = json!(hash);
        }
    }
    Manifest::decode(&serde_json::to_vec(&value).unwrap(), Limits::default())
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
    asset: AssetId,
) -> Result<diorama_assets::DecodedObservation, DecodeError<Infallible>> {
    inventory(bytes, asset)
        .decoding_session(DecodeLimits::default())
        .unwrap()
        .inspect_compressed_blob(asset, bytes, |_| Ok(()))
}
#[test]
fn independent_fixed_vectors_match_decoded_hash_and_binding() {
    for bytes in [GZIP, ZSTD] {
        let inv = inventory(bytes, id(bytes));
        let mut s = inv.decoding_session(DecodeLimits::default()).unwrap();
        let mut output = Vec::new();
        let result = s
            .inspect_compressed_blob(id(bytes), bytes, |chunk| {
                output.extend_from_slice(chunk);
                Ok::<_, Infallible>(())
            })
            .unwrap();
        assert_eq!(output, b"abc");
        assert_eq!(result.decoded_bytes(), 3);
        assert_eq!(result.decoded_sha256(), &ABC_SHA);
        assert_eq!(result.encoded().encoded_bytes(), bytes.len() as u64);
        assert_eq!(
            s.remaining_decoded_budget(),
            DecodeLimits::default().total_bytes - 4
        );
    }
}
#[test]
fn all_truncations_corrupt_checksum_and_trailing_members_fail_after_rehash() {
    for original in [GZIP, ZSTD] {
        let asset = id(original);
        for length in 1..original.len() {
            assert!(
                inspect(&original[..length], asset).is_err(),
                "truncation {length}"
            );
        }
        for suffix in [vec![0], b"junk".to_vec(), original.to_vec()] {
            let mut bytes = original.to_vec();
            bytes.extend(suffix);
            assert!(matches!(
                inspect(&bytes, asset),
                Err(DecodeError::Policy(DecodePolicyError::Trailing))
            ));
        }
    }
    for index in [18, 22] {
        let mut bytes = GZIP.to_vec();
        bytes[index] ^= 1;
        assert!(matches!(
            inspect(&bytes, AssetId::ImageCoredns),
            Err(DecodeError::Decoder(_))
        ));
    }
}
#[test]
fn same_encoded_slice_must_match_before_any_callback() {
    let inv = inventory(GZIP, AssetId::ImageCoredns);
    let mut s = inv.decoding_session(DecodeLimits::default()).unwrap();
    let mut bytes = GZIP.to_vec();
    bytes[4] = 1;
    let mut calls = 0;
    assert!(matches!(
        s.inspect_compressed_blob(AssetId::ImageCoredns, &bytes, |_| {
            calls += 1;
            Ok::<_, Infallible>(())
        }),
        Err(DecodeError::Encoded(_))
    ));
    assert_eq!(calls, 0);
    assert_eq!(
        s.remaining_decoded_budget(),
        DecodeLimits::default().total_bytes - 1
    );
    assert!(s.remaining_encoded_budget() < Limits::default().encoded_total_bytes);
    assert!(matches!(
        s.inspect_compressed_blob(AssetId::Containerd, b"abc", |_| Ok::<_, Infallible>(())),
        Err(DecodeError::Policy(DecodePolicyError::NotCompressed))
    ));
}
#[test]
fn exact_limit_succeeds_but_excess_and_failed_attempts_retain_budget_charges() {
    // Unknown-size zstd raw block "abc" with deliberately incorrect XXH64 checksum.
    // The pinned decoder can write abc and return an error with output.pos still zero.
    let corrupt = [
        0x28, 0xb5, 0x2f, 0xfd, 4, 0, 0x19, 0, 0, b'a', b'b', b'c', 0, 0, 0, 0,
    ];
    let inv = inventory(&corrupt, AssetId::Crun);
    let mut session = inv
        .decoding_session(DecodeLimits {
            total_bytes: 9000,
            ..DecodeLimits::default()
        })
        .unwrap();
    for remaining in [807, 0] {
        assert!(matches!(
            session.inspect_compressed_blob(
                AssetId::Crun,
                &corrupt,
                |_| -> Result<(), Infallible> {
                    panic!("failed output must not reach the observer")
                }
            ),
            Err(DecodeError::Decoder(_))
        ));
        assert_eq!(session.remaining_decoded_budget(), remaining);
    }
    let encoded_remaining = session.remaining_encoded_budget();
    assert!(matches!(
        session.inspect_compressed_blob(AssetId::Crun, &corrupt, |_| Ok::<_, Infallible>(())),
        Err(DecodeError::Policy(DecodePolicyError::Budget))
    ));
    assert_eq!(session.remaining_encoded_budget(), encoded_remaining);
    for original in [GZIP, ZSTD] {
        let asset = id(original);
        let inv = inventory(original, asset);
        let limits = DecodeLimits {
            executable_bytes: 3,
            image_bytes: 3,
            total_bytes: 8,
        };
        let mut s = inv.decoding_session(limits).unwrap();
        for _ in 0..2 {
            assert_eq!(
                s.inspect_compressed_blob(asset, original, |_| Ok::<_, Infallible>(()))
                    .unwrap()
                    .decoded_bytes(),
                3
            );
        }
        assert_eq!(s.remaining_decoded_budget(), 0);
        assert!(matches!(
            s.inspect_compressed_blob(asset, original, |_| Ok::<_, Infallible>(())),
            Err(DecodeError::Policy(DecodePolicyError::Budget))
        ));
    }
    let inv = inventory(GZIP, AssetId::ImageCoredns);
    let mut s = inv
        .decoding_session(DecodeLimits {
            image_bytes: 2,
            total_bytes: 4,
            ..DecodeLimits::default()
        })
        .unwrap();
    assert!(
        s.inspect_compressed_blob(AssetId::ImageCoredns, GZIP, |_| Ok::<_, Infallible>(()))
            .is_err()
    );
    assert_eq!(s.remaining_decoded_budget(), 1);
    assert!(
        s.inspect_compressed_blob(AssetId::ImageCoredns, GZIP, |_| Ok::<_, Infallible>(()))
            .is_err()
    );
    assert_eq!(s.remaining_decoded_budget(), 0);
}
#[test]
fn observer_failure_is_typed_provisional_and_display_does_not_leak() {
    let inv = inventory(GZIP, AssetId::ImageCoredns);
    let mut s = inv.decoding_session(DecodeLimits::default()).unwrap();
    let err = s
        .inspect_compressed_blob(AssetId::ImageCoredns, GZIP, |_| {
            Err(io::Error::other("synthetic-secret"))
        })
        .unwrap_err();
    assert!(matches!(&err,DecodeError::Observer(e) if e.to_string()=="synthetic-secret"));
    assert!(!err.to_string().contains("synthetic-secret"));
    assert!(!format!("{err:?}").contains("synthetic-secret"));
    assert_eq!(
        s.remaining_decoded_budget(),
        DecodeLimits::default().total_bytes - 4
    );
}
#[test]
fn zstd_skippable_dictionary_large_window_and_reserved_headers_are_rejected() {
    let cases = [
        vec![0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0],
        vec![
            0x28, 0xb5, 0x2f, 0xfd, 0x21, 1, 3, 0x19, 0, 0, b'a', b'b', b'c',
        ],
        vec![
            0x28, 0xb5, 0x2f, 0xfd, 0, 0x88, 0x19, 0, 0, b'a', b'b', b'c',
        ],
    ];
    for (bytes, expected) in cases.iter().zip([
        DecodePolicyError::Header,
        DecodePolicyError::Dictionary,
        DecodePolicyError::Window,
    ]) {
        assert!(
            matches!(inspect(bytes,AssetId::Crun),Err(DecodeError::Policy(value)) if value==expected)
        );
    }
    let mut bytes = ZSTD.to_vec();
    bytes[4] |= 8;
    assert!(matches!(
        inspect(&bytes, AssetId::Crun),
        Err(DecodeError::Policy(DecodePolicyError::Header))
    ));
}
#[test]
fn gzip_header_fields_are_bounded_before_decoder_allocation() {
    for flag in [8, 16] {
        let mut bytes = GZIP[..10].to_vec();
        bytes[3] = flag;
        bytes.extend(vec![b'x'; 8192]);
        bytes.push(0);
        bytes.extend_from_slice(&GZIP[10..]);
        assert!(matches!(
            inspect(&bytes, AssetId::ImageCoredns),
            Err(DecodeError::Policy(DecodePolicyError::HeaderLimit))
        ));
    }
    let mut bytes = GZIP[..10].to_vec();
    bytes[3] = 4;
    bytes.extend([0xff, 0xff]);
    bytes.extend_from_slice(&GZIP[10..]);
    assert!(matches!(
        inspect(&bytes, AssetId::ImageCoredns),
        Err(DecodeError::Policy(DecodePolicyError::HeaderLimit))
    ));
    let mut bytes = GZIP.to_vec();
    bytes[3] = 0xe0;
    assert!(matches!(
        inspect(&bytes, AssetId::ImageCoredns),
        Err(DecodeError::Policy(DecodePolicyError::Header))
    ));
}
#[test]
fn unknown_zstd_content_size_is_still_bounded_and_checksum_is_checked() {
    let bytes = [0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0x19, 0, 0, b'a', b'b', b'c'];
    assert_eq!(
        inspect(&bytes, AssetId::Crun).unwrap().decoded_sha256(),
        &ABC_SHA
    );
    let inv = inventory(&bytes, AssetId::Crun);
    let mut s = inv
        .decoding_session(DecodeLimits {
            executable_bytes: 2,
            total_bytes: 10,
            ..DecodeLimits::default()
        })
        .unwrap();
    assert!(
        s.inspect_compressed_blob(AssetId::Crun, &bytes, |_| Ok::<_, Infallible>(()))
            .is_err()
    );
    assert_eq!(s.remaining_decoded_budget(), 7);
    // Independent XXH64(abc)=44bc2cf5ad770999; zstd stores low32bits little-endian.
    let mut checksum = ZSTD.to_vec();
    checksum[4] |= 4;
    checksum.extend([0x99, 0x09, 0x77, 0xad]);
    assert_eq!(
        inspect(&checksum, AssetId::Crun).unwrap().decoded_bytes(),
        3
    );
    *checksum.last_mut().unwrap() ^= 1;
    assert!(matches!(
        inspect(&checksum, AssetId::Crun),
        Err(DecodeError::Decoder(_))
    ));
}
#[test]
fn invalid_limits_fail_without_a_session() {
    let inv = inventory(ZSTD, AssetId::Crun);
    for limits in [
        DecodeLimits {
            total_bytes: 0,
            ..DecodeLimits::default()
        },
        DecodeLimits {
            image_bytes: u64::MAX,
            ..DecodeLimits::default()
        },
    ] {
        assert!(matches!(
            inv.decoding_session(limits),
            Err(DecodePolicyError::InvalidLimits)
        ));
    }
}
#[test]
fn empty_frames_still_require_completion_and_consume_one_probe() {
    let gzip = [
        0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 1, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let zstd = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0, 1, 0, 0];
    for bytes in [&gzip[..], &zstd[..]] {
        let asset = id(bytes);
        let inv = inventory(bytes, asset);
        let mut session = inv
            .decoding_session(DecodeLimits {
                total_bytes: 1,
                ..DecodeLimits::default()
            })
            .unwrap();
        let result = session
            .inspect_compressed_blob(asset, bytes, |_| -> Result<(), Infallible> {
                panic!("empty frame observer")
            })
            .unwrap();
        assert_eq!(result.decoded_bytes(), 0);
        assert_eq!(session.remaining_decoded_budget(), 0);
    }
}
#[test]
fn unknown_size_rle_bomb_is_streamed_in_fixed_chunks_and_stops_at_limit() {
    // Window128KiB, unknown content size; final RLE block of100000 bytes 'a'.
    let bytes = [0x28, 0xb5, 0x2f, 0xfd, 0, 0x38, 0x03, 0x35, 0x0c, b'a'];
    let inv = inventory(&bytes, AssetId::Crun);
    let mut session = inv
        .decoding_session(DecodeLimits {
            executable_bytes: 9000,
            total_bytes: 10000,
            ..DecodeLimits::default()
        })
        .unwrap();
    let mut sizes = Vec::new();
    let result = session.inspect_compressed_blob(AssetId::Crun, &bytes, |chunk| {
        assert!(chunk.iter().all(|b| *b == b'a'));
        sizes.push(chunk.len());
        Ok::<_, Infallible>(())
    });
    assert!(matches!(
        result,
        Err(DecodeError::Policy(DecodePolicyError::ContentLimit))
    ));
    assert!(sizes.iter().all(|size| *size <= 8192));
    assert!(sizes.iter().sum::<usize>() <= 9000);
    assert_eq!(session.remaining_decoded_budget(), 999);
}
#[test]
fn aggregate_budget_is_checked_before_observer_and_retained_on_header_failure() {
    let mut bad = GZIP.to_vec();
    bad[3] = 0xe0;
    let inv = inventory(&bad, AssetId::ImageCoredns);
    let mut session = inv
        .decoding_session(DecodeLimits {
            total_bytes: 1,
            ..DecodeLimits::default()
        })
        .unwrap();
    assert!(matches!(
        session.inspect_compressed_blob(AssetId::ImageCoredns, &bad, |_| Ok::<_, Infallible>(())),
        Err(DecodeError::Policy(DecodePolicyError::Header))
    ));
    assert_eq!(session.remaining_decoded_budget(), 0);
    let encoded = session.remaining_encoded_budget();
    assert!(matches!(
        session.inspect_compressed_blob(AssetId::ImageCoredns, &bad, |_| Ok::<_, Infallible>(())),
        Err(DecodeError::Policy(DecodePolicyError::Budget))
    ));
    assert_eq!(session.remaining_encoded_budget(), encoded);
}
#[test]
fn gzip_optional_fields_and_header_crc_are_checked_without_using_names_as_paths() {
    // CRC32 of this exact18byte header has low16bits0x0c96 (independent zlib oracle).
    let mut bytes = vec![
        0x1f, 0x8b, 8, 0x1e, 0, 0, 0, 0, 0, 0xff, 2, 0, 0x12, 0x34, b'x', 0, b'y', 0, 0x96, 0x0c,
    ];
    bytes.extend_from_slice(&GZIP[10..]);
    assert_eq!(
        inspect(&bytes, AssetId::ImageCoredns)
            .unwrap()
            .decoded_sha256(),
        &ABC_SHA
    );
    bytes[18] ^= 1;
    assert!(matches!(
        inspect(&bytes, AssetId::ImageCoredns),
        Err(DecodeError::Decoder(_))
    ));
}
#[test]
fn image_limit_and_executable_limit_are_distinct_and_receipt_requires_full_trailer() {
    for (bytes, asset) in [(GZIP, AssetId::ImageCoredns), (ZSTD, AssetId::Crun)] {
        let inv = inventory(bytes, asset);
        let mut s = inv
            .decoding_session(DecodeLimits {
                executable_bytes: 2,
                image_bytes: 3,
                total_bytes: 10,
            })
            .unwrap();
        let result = s.inspect_compressed_blob(asset, bytes, |_| Ok::<_, Infallible>(()));
        assert_eq!(result.is_ok(), asset == AssetId::ImageCoredns);
    }
    let mut corrupt = GZIP.to_vec();
    corrupt[18] ^= 1;
    let inv = inventory(&corrupt, AssetId::ImageCoredns);
    let mut s = inv.decoding_session(DecodeLimits::default()).unwrap();
    let mut observed = Vec::new();
    let result = s.inspect_compressed_blob(AssetId::ImageCoredns, &corrupt, |chunk| {
        observed.extend_from_slice(chunk);
        Ok::<_, Infallible>(())
    });
    assert_eq!(observed, b"abc");
    assert!(matches!(result, Err(DecodeError::Decoder(_))));
}
