use diorama_assets::{
    ArmFloatAbi, AssetId, CompressedElfError, DeclaredInventory, DecodeError, DecodeLimits,
    DecodePolicyError, ElfError, ElfLimits, InventoryRequest, Limits, LoaderFamily, LoaderRelation,
    Manifest, Scope, Variant, VerificationError,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{convert::Infallible, fmt::Write};
#[allow(clippy::duplicate_mod)]
#[path = "common/elf.rs"]
mod common;
use common::{executable, put};

// A normal zstd frame with unknown size, 1KiB window, and one final raw block.
// Constructed directly from the frame/block format, without any compressor.
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0];
    let block = (u32::try_from(bytes.len()).unwrap() << 3) | 1;
    out.extend_from_slice(&block.to_le_bytes()[..3]);
    out.extend_from_slice(bytes);
    out
}
fn inventory(
    bytes: &[u8],
    architecture: Architecture,
    libc: Libc,
    tight: bool,
) -> DeclaredInventory {
    let mut value: Value =
        serde_json::from_slice(include_bytes!("fixtures/online-amd64.json")).unwrap();
    value["target"]["architecture"] = json!(match architecture {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
        Architecture::ArmV7 => "armv7",
        Architecture::Riscv64 => "riscv64",
    });
    value["target"]["libc"] = json!(if libc == Libc::Musl { "musl" } else { "glibc" });
    let digest = Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            write!(&mut s, "{b:02x}").unwrap();
            s
        });
    for row in value["assets"].as_array_mut().unwrap() {
        if row["id"] == "crun" || row["id"] == "image-coredns" {
            row["delivery"]["encoded_bytes"] = json!(bytes.len());
            row["delivery"]["sha256"] = json!(digest);
        }
        if (row["id"] == "image-d2k"
            && matches!(architecture, Architecture::ArmV7 | Architecture::Riscv64))
            || (row["id"] == "image-portainer-agent" && architecture == Architecture::Riscv64)
        {
            row["delivery"] = json!({"kind":"unavailable"});
        }
    }
    let mut limits = Limits::default();
    if tight {
        limits.encoded_total_bytes = value["assets"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["delivery"]["encoded_bytes"].as_u64().map(|n| n + 1))
            .sum();
    }
    Manifest::decode(&serde_json::to_vec(&value).unwrap(), limits)
        .unwrap()
        .validate_inventory(
            InventoryRequest {
                target: NodeTarget { architecture, libc },
                variant: Variant::Online,
                scope: Scope::SupervisedBundle,
            },
            limits,
        )
        .unwrap()
}
fn inv(bytes: &[u8]) -> DeclaredInventory {
    inventory(bytes, Architecture::Amd64, Libc::Glibc, false)
}
#[test]
fn raw_frame_and_independent_elf_share_completed_digest_and_observations() {
    let bytes = frame(&executable(62, 2));
    let inv = inv(&bytes);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    let result = session
        .inspect_compressed_elf(AssetId::Crun, &bytes, ElfLimits::default())
        .unwrap();
    let decoded = result.decoded_observation();
    assert_eq!(decoded.encoded().id(), AssetId::Crun);
    assert_eq!(decoded.encoded().encoded_bytes(), bytes.len() as u64);
    assert_eq!(decoded.decoded_bytes(), 512);
    // Fixed independent Python hashlib vector over the manually specified ELF layout.
    assert_eq!(
        decoded.decoded_sha256(),
        &[
            0xad, 0xba, 0xa9, 0x77, 0x32, 0x87, 0x1a, 0x11, 0xb5, 0xb2, 0xd5, 0x47, 0x77, 0xb4,
            0x1d, 0x34, 0x7d, 0x97, 0x02, 0xec, 0x96, 0xd7, 0xb5, 0x66, 0x1b, 0x19, 0xfe, 0x81,
            0xa3, 0x08, 0x23, 0x1c,
        ]
    );
    assert_eq!(result.elf().id(), AssetId::Crun);
    assert_eq!(result.elf().machine(), 62);
    assert_eq!(result.elf().loader_relation(), LoaderRelation::Unresolved);
    assert!(result.elf().interpreter().is_none());
    assert_eq!(
        session.remaining_decoded_budget(),
        DecodeLimits::default().total_bytes - 513
    );
}
#[test]
fn every_supported_machine_preserves_header_only_abi_boundary() {
    for (machine, class, arch) in [
        (62, 2, Architecture::Amd64),
        (183, 2, Architecture::Arm64),
        (40, 1, Architecture::ArmV7),
        (243, 2, Architecture::Riscv64),
    ] {
        let bytes = frame(&executable(machine, class));
        let inv = inventory(&bytes, arch, Libc::Musl, false);
        let result = inv
            .decoding_session(DecodeLimits::default())
            .unwrap()
            .inspect_compressed_elf(AssetId::Crun, &bytes, ElfLimits::default())
            .unwrap();
        assert_eq!(result.elf().machine(), machine);
        assert_eq!(result.elf().loader_relation(), LoaderRelation::Unresolved);
        assert_eq!(
            result.elf().arm_float_abi(),
            if machine == 40 {
                ArmFloatAbi::Missing
            } else {
                ArmFloatAbi::NotArm
            }
        );
    }
}
#[test]
fn exact_encoded_hash_does_not_hide_wrong_machine_class_endian_or_loader() {
    let raw = executable(62, 2);
    let bytes = frame(&raw);
    let inv = inventory(&bytes, Architecture::Arm64, Libc::Glibc, false);
    assert!(matches!(
        inv.decoding_session(DecodeLimits::default())
            .unwrap()
            .inspect_compressed_elf(AssetId::Crun, &bytes, ElfLimits::default()),
        Err(CompressedElfError::Elf(ElfError::TargetMismatch))
    ));
    for (offset, value) in [(4, 1), (5, 2)] {
        let mut raw = raw.clone();
        raw[offset] = value;
        let bytes = frame(&raw);
        assert!(matches!(
            self::inv(&bytes)
                .decoding_session(DecodeLimits::default())
                .unwrap()
                .inspect_compressed_elf(AssetId::Crun, &bytes, ElfLimits::default()),
            Err(CompressedElfError::Elf(ElfError::TargetMismatch))
        ));
    }
    let mut raw = raw;
    let loader = b"/lib64/ld-linux-x86-64.so.2";
    for (offset, value, width) in [
        (56, 2, 2),
        (120, 3, 4),
        (128, 300, 8),
        (152, loader.len() as u64 + 1, 8),
    ] {
        put(&mut raw, offset, value, width);
    }
    raw[300..300 + loader.len()].copy_from_slice(loader);
    let bytes = frame(&raw);
    let inv = inventory(&bytes, Architecture::Amd64, Libc::Musl, false);
    let result = inv
        .decoding_session(DecodeLimits::default())
        .unwrap()
        .inspect_compressed_elf(AssetId::Crun, &bytes, ElfLimits::default())
        .unwrap();
    assert_eq!(result.elf().loader_family(), LoaderFamily::Glibc);
    assert_eq!(
        result.elf().loader_relation(),
        LoaderRelation::KnownMismatch
    );
}
#[test]
fn incomplete_or_corrupt_frames_never_reach_elf_inspection() {
    for raw in [executable(62, 2), vec![b'x'; 512]] {
        let good = frame(&raw);
        let mut cases = vec![good[..good.len() - 1].to_vec()];
        let mut trailing = good.clone();
        trailing.push(0);
        cases.push(trailing);
        let mut multiple = good.clone();
        multiple.extend_from_slice(&good);
        cases.push(multiple);
        let mut checksum = good.clone();
        checksum[4] |= 4;
        checksum.extend_from_slice(&[0, 0, 0, 0]);
        cases.push(checksum);
        for bytes in cases {
            let error = inv(&bytes)
                .decoding_session(DecodeLimits::default())
                .unwrap()
                .inspect_compressed_elf(AssetId::Crun, &bytes, ElfLimits::default())
                .unwrap_err();
            assert!(matches!(error, CompressedElfError::Decode(_)), "{error:?}");
        }
    }
}
#[test]
fn tighter_elf_decode_and_session_limits_bound_unknown_size_output() {
    let bytes = frame(&executable(62, 2));
    for (elf_bytes, executable_bytes, total_bytes, succeeds) in [
        (512, 512, 513, true),
        (511, 1024, 1025, false),
        (1024, 511, 1025, false),
        (1024, 1024, 512, false),
    ] {
        let inv = inv(&bytes);
        let mut session = inv
            .decoding_session(DecodeLimits {
                executable_bytes,
                total_bytes,
                ..DecodeLimits::default()
            })
            .unwrap();
        let result = session.inspect_compressed_elf(
            AssetId::Crun,
            &bytes,
            ElfLimits {
                bytes: elf_bytes,
                ..ElfLimits::default()
            },
        );
        if succeeds {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(CompressedElfError::Decode(DecodeError::Policy(
                    DecodePolicyError::ContentLimit
                )))
            ));
        }
        let admitted = (elf_bytes as u64)
            .min(executable_bytes)
            .min(total_bytes - 1);
        assert_eq!(
            session.remaining_decoded_budget(),
            total_bytes - admitted - 1
        );
    }
}
#[test]
fn invalid_limits_identity_and_gzip_image_are_rejected_without_budget_effects() {
    let raw = executable(62, 2);
    // Independent RFC1952 member with stored block and fixed CRC32 of the ELF vector.
    let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 1, 0, 2, 0xff, 0xfd];
    gzip.extend_from_slice(&raw);
    gzip.extend_from_slice(&[0xd5, 0x9d, 0x47, 0x96, 0, 2, 0, 0]);
    let inv = inv(&gzip);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    let before = (
        session.remaining_encoded_budget(),
        session.remaining_decoded_budget(),
    );
    assert!(matches!(
        session.inspect_compressed_elf(AssetId::ImageCoredns, &gzip, ElfLimits::default()),
        Err(CompressedElfError::NotExecutable)
    ));
    assert!(matches!(
        session.inspect_compressed_elf(AssetId::KubeApiserver, b"abc", ElfLimits::default()),
        Err(CompressedElfError::Decode(DecodeError::Policy(
            DecodePolicyError::NotCompressed
        )))
    ));
    for field in 0..8 {
        let mut limits = ElfLimits::default();
        match field {
            0 => limits.bytes = 0,
            1 => limits.program_headers = 0,
            2 => limits.section_headers = 0,
            3 => limits.dynamic_entries = 0,
            4 => limits.interpreter_bytes = 0,
            5 => limits.dependency_names = 0,
            6 => limits.dependency_name_bytes = 0,
            _ => limits.arm_attribute_bytes = 0,
        }
        assert!(matches!(
            session.inspect_compressed_elf(AssetId::Crun, &gzip, limits),
            Err(CompressedElfError::Elf(ElfError::InvalidLimits))
        ));
    }
    assert_eq!(
        before,
        (
            session.remaining_encoded_budget(),
            session.remaining_decoded_budget()
        )
    );
    assert_eq!(
        session
            .inspect_compressed_blob(AssetId::ImageCoredns, &gzip, |_| Ok::<_, Infallible>(()))
            .unwrap()
            .decoded_bytes(),
        512
    );
}
#[test]
fn failed_elf_parsing_keeps_both_budgets_and_repeated_calls_exhaust_decoded_budget() {
    let bytes = frame(&executable(183, 2));
    let inv = inv(&bytes);
    let mut session = inv
        .decoding_session(DecodeLimits {
            total_bytes: 1026,
            ..DecodeLimits::default()
        })
        .unwrap();
    let initial = session.remaining_encoded_budget();
    for i in 1..=2 {
        assert!(matches!(
            session.inspect_compressed_elf(AssetId::Crun, &bytes, ElfLimits::default()),
            Err(CompressedElfError::Elf(ElfError::TargetMismatch))
        ));
        assert_eq!(session.remaining_decoded_budget(), 1026 - 513 * i);
        assert_eq!(
            session.remaining_encoded_budget(),
            initial - (bytes.len() as u64 + 1) * i
        );
    }
    assert!(matches!(
        session.inspect_compressed_elf(AssetId::Crun, &bytes, ElfLimits::default()),
        Err(CompressedElfError::Decode(DecodeError::Policy(
            DecodePolicyError::Budget
        )))
    ));
}
#[test]
fn retained_encoded_budget_cannot_be_refreshed_by_composition() {
    let bytes = frame(&executable(62, 2));
    let inv = inventory(&bytes, Architecture::Amd64, Libc::Glibc, true);
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    let attempts = session.remaining_encoded_budget() / (bytes.len() as u64 + 1);
    for _ in 0..attempts {
        session
            .inspect_compressed_elf(AssetId::Crun, &bytes, ElfLimits::default())
            .unwrap();
    }
    let before = session.remaining_decoded_budget();
    assert!(matches!(
        session.inspect_compressed_elf(AssetId::Crun, &bytes, ElfLimits::default()),
        Err(CompressedElfError::Decode(DecodeError::Encoded(
            VerificationError::BudgetExceeded(AssetId::Crun)
        )))
    ));
    assert_eq!(session.remaining_decoded_budget(), before - 1);
}
#[test]
fn altered_encoded_slice_fails_before_decode_and_keeps_attempt_charge() {
    let bytes = frame(&executable(62, 2));
    let inv = inv(&bytes);
    let mut changed = bytes.clone();
    changed[400] ^= 1;
    let mut session = inv.decoding_session(DecodeLimits::default()).unwrap();
    let initial = session.remaining_encoded_budget();
    assert!(matches!(
        session.inspect_compressed_elf(AssetId::Crun, &changed, ElfLimits::default()),
        Err(CompressedElfError::Decode(DecodeError::Encoded(
            VerificationError::DigestMismatch(AssetId::Crun)
        )))
    ));
    assert_eq!(
        session.remaining_decoded_budget(),
        DecodeLimits::default().total_bytes - 1
    );
    assert_eq!(
        session.remaining_encoded_budget(),
        initial - bytes.len() as u64 - 1
    );
}
#[test]
fn rle_expansion_stops_at_tighter_elf_cap_before_parser() {
    // Unknown content size; final RLE block expands to 100000 bytes of 'a'.
    let bytes = [0x28, 0xb5, 0x2f, 0xfd, 0, 0x38, 0x03, 0x35, 0x0c, b'a'];
    let inv = inv(&bytes);
    let mut session = inv
        .decoding_session(DecodeLimits {
            total_bytes: 10000,
            ..DecodeLimits::default()
        })
        .unwrap();
    assert!(matches!(
        session.inspect_compressed_elf(
            AssetId::Crun,
            &bytes,
            ElfLimits {
                bytes: 9000,
                ..ElfLimits::default()
            }
        ),
        Err(CompressedElfError::Decode(DecodeError::Policy(
            DecodePolicyError::ContentLimit
        )))
    ));
    assert_eq!(session.remaining_decoded_budget(), 999);
}
