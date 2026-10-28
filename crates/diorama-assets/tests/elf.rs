use diorama_assets::{ArmFloatAbi, AssetId, ElfError, ElfLimits, LoaderFamily, LoaderRelation};
use diorama_platform::{Architecture, Libc};
#[allow(clippy::duplicate_mod)]
#[path = "common/elf.rs"]
mod common;
use common::{executable, inspect, inventory, put};
#[test]
fn independent_machine_vectors_and_missing_loader_are_observations_only() {
    for (machine, class, architecture) in [
        (62, 2, Architecture::Amd64),
        (183, 2, Architecture::Arm64),
        (40, 1, Architecture::ArmV7),
        (243, 2, Architecture::Riscv64),
    ] {
        let b = executable(machine, class);
        let r = inventory(&b, architecture, Libc::Glibc)
            .inspect_identity_elf(AssetId::Containerd, &b, ElfLimits::default())
            .unwrap();
        assert_eq!(r.machine(), machine);
        assert_eq!(r.loader_relation(), LoaderRelation::Unresolved);
        assert_eq!(r.loader_family(), LoaderFamily::Unknown);
        assert!(r.interpreter().is_none());
        let empty: &[Vec<u8>] = &[];
        assert_eq!(r.needed(), empty);
    }
}
#[test]
fn recomputed_hash_does_not_hide_wrong_machine_class_endian_or_type() {
    let original = executable(62, 2);
    for (offset, value, width, kind) in [
        (18, 183, 2, 0),
        (4, 1, 1, 0),
        (5, 2, 1, 0),
        (16, 1, 2, 1),
        (24, 0, 8, 1),
    ] {
        let mut b = original.clone();
        put(&mut b, offset, value, width);
        let err = inspect(&b).unwrap_err();
        if kind == 0 {
            assert!(matches!(err, ElfError::TargetMismatch));
        } else {
            assert!(matches!(err, ElfError::Unsupported));
        }
    }
}
#[test]
fn truncation_overflow_entry_and_ranges_are_rejected_after_rehash() {
    let original = executable(62, 2);
    for length in [1, 8, 32, 63, 100, 511] {
        let b = &original[..length];
        assert!(inspect(b).is_err());
    }
    for (offset, value, width) in [
        (32, u64::MAX, 8),
        (96, u64::MAX, 8),
        (80, u64::MAX, 8),
        (104, 1, 8),
        (112, 3, 8),
        (24, 0x50_0000, 8),
        (56, 129, 2),
        (20, 2, 4),
    ] {
        let mut b = original.clone();
        put(&mut b, offset, value, width);
        assert!(inspect(&b).is_err(), "offset {offset}");
    }
}
fn with_loader(loader: &[u8]) -> Vec<u8> {
    let mut b = executable(62, 2);
    put(&mut b, 56, 2, 2);
    for (o, v, w) in [
        (120, 3, 4),
        (128, 300, 8),
        (152, loader.len() as u64 + 1, 8),
    ] {
        put(&mut b, o, v, w);
    }
    b[300..300 + loader.len()].copy_from_slice(loader);
    b
}
#[test]
fn known_loader_mismatch_is_never_compatible() {
    let b = with_loader(b"/lib64/ld-linux-x86-64.so.2");
    let r = inventory(&b, Architecture::Amd64, Libc::Musl)
        .inspect_identity_elf(AssetId::Containerd, &b, ElfLimits::default())
        .unwrap();
    assert_eq!(r.loader_family(), LoaderFamily::Glibc);
    assert_eq!(r.loader_relation(), LoaderRelation::KnownMismatch);
    let r = inspect(&b).unwrap();
    assert_eq!(r.loader_relation(), LoaderRelation::Unresolved);
    let b = with_loader(b"/unreviewed/loader");
    assert_eq!(inspect(&b).unwrap().loader_family(), LoaderFamily::Unknown);
}
#[test]
fn arm_flags_are_not_cpu_or_complete_pcs_proof() {
    for (flags, expected) in [
        (0x0500_0400, ArmFloatAbi::HardFlag),
        (0x0500_0200, ArmFloatAbi::SoftFlag),
        (0x0500_0600, ArmFloatAbi::Conflicting),
        (0, ArmFloatAbi::Missing),
    ] {
        let mut b = executable(40, 1);
        put(&mut b, 36, flags, 4);
        let r = inventory(&b, Architecture::ArmV7, Libc::Musl)
            .inspect_identity_elf(AssetId::Containerd, &b, ElfLimits::default())
            .unwrap();
        assert_eq!(r.arm_float_abi(), expected);
        assert_eq!(r.loader_relation(), LoaderRelation::Unresolved);
        assert!(!r.arm_attributes_present());
    }
}
#[test]
fn exact_same_bytes_and_identity_are_required() {
    let b = executable(62, 2);
    let inv = inventory(&b, Architecture::Amd64, Libc::Glibc);
    let mut altered = b.clone();
    altered[400] = 7;
    assert!(matches!(
        inv.inspect_identity_elf(AssetId::Containerd, &altered, ElfLimits::default()),
        Err(ElfError::Encoded(_))
    ));
    assert!(matches!(
        inv.inspect_identity_elf(AssetId::Crun, &b, ElfLimits::default()),
        Err(ElfError::NotIdentity)
    ));
    let limits = ElfLimits {
        bytes: b.len() - 1,
        ..ElfLimits::default()
    };
    assert!(matches!(
        inv.inspect_identity_elf(AssetId::Containerd, &b, limits),
        Err(ElfError::Limit)
    ));
    let limits = ElfLimits {
        program_headers: 0,
        ..ElfLimits::default()
    };
    assert!(matches!(
        inv.inspect_identity_elf(AssetId::Containerd, &b, limits),
        Err(ElfError::InvalidLimits)
    ));
}
#[test]
fn bounded_dynamic_table_resolves_names_through_load_segments() {
    let mut b = executable(62, 2);
    put(&mut b, 56, 2, 2);
    for (o, v, w) in [
        (120, 2, 4),
        (128, 300, 8),
        (152, 64, 8),
        (300, 5, 8),
        (308, 0x40_0190, 8),
        (316, 10, 8),
        (324, 12, 8),
        (332, 1, 8),
        (340, 0, 8),
    ] {
        put(&mut b, o, v, w);
    }
    b[400..412].copy_from_slice(b"libc.so.6\0\0\0");
    assert_eq!(inspect(&b).unwrap().needed(), &[b"libc.so.6".to_vec()]);
    let inv = inventory(&b, Architecture::Amd64, Libc::Glibc);
    let separate_limits = ElfLimits {
        interpreter_bytes: 1,
        dependency_name_bytes: 9,
        ..ElfLimits::default()
    };
    assert_eq!(
        inv.inspect_identity_elf(AssetId::Containerd, &b, separate_limits)
            .unwrap()
            .needed(),
        &[b"libc.so.6".to_vec()]
    );
    for (bytes, invalid) in [(8, false), (0, true)] {
        let error = inv
            .inspect_identity_elf(
                AssetId::Containerd,
                &b,
                ElfLimits {
                    dependency_name_bytes: bytes,
                    ..separate_limits
                },
            )
            .unwrap_err();
        if invalid {
            assert!(matches!(error, ElfError::InvalidLimits));
        } else {
            assert!(matches!(error, ElfError::Limit));
        }
    }
    let limits = ElfLimits {
        dynamic_entries: 3,
        ..ElfLimits::default()
    };
    assert!(matches!(
        inv.inspect_identity_elf(AssetId::Containerd, &b, limits),
        Err(ElfError::Limit)
    ));
    put(&mut b, 308, u64::MAX, 8);
    assert!(inspect(&b).is_err());
}
#[test]
fn section_counts_and_arm_attribute_bytes_are_bounded() {
    let mut b = executable(40, 1);
    put(&mut b, 32, 320, 4);
    put(&mut b, 48, 2, 2);
    put(&mut b, 364, 0x7000_0003, 4);
    put(&mut b, 376, 420, 4);
    put(&mut b, 380, 20, 4);
    let inv = inventory(&b, Architecture::ArmV7, Libc::Musl);
    assert!(
        inv.inspect_identity_elf(AssetId::Containerd, &b, ElfLimits::default())
            .unwrap()
            .arm_attributes_present()
    );
    for limits in [
        ElfLimits {
            section_headers: 1,
            ..ElfLimits::default()
        },
        ElfLimits {
            arm_attribute_bytes: 19,
            ..ElfLimits::default()
        },
    ] {
        assert!(matches!(
            inv.inspect_identity_elf(AssetId::Containerd, &b, limits),
            Err(ElfError::Limit)
        ));
    }
    put(&mut b, 376, 500, 4);
    assert!(
        inventory(&b, Architecture::ArmV7, Libc::Musl)
            .inspect_identity_elf(AssetId::Containerd, &b, ElfLimits::default())
            .is_err()
    );
}
#[test]
fn interpreter_termination_duplicates_and_limit_are_checked() {
    let mut b = with_loader(b"/lib64/ld-linux-x86-64.so.2");
    let inv = inventory(&b, Architecture::Amd64, Libc::Glibc);
    assert!(
        inv.inspect_identity_elf(
            AssetId::Containerd,
            &b,
            ElfLimits {
                dependency_name_bytes: 1,
                ..ElfLimits::default()
            }
        )
        .is_ok()
    );
    assert!(
        inv.inspect_identity_elf(
            AssetId::Containerd,
            &b,
            ElfLimits {
                interpreter_bytes: 4,
                ..ElfLimits::default()
            }
        )
        .is_err()
    );
    b[305] = 0;
    assert!(inspect(&b).is_err());
    let mut b = with_loader(b"/loader");
    put(&mut b, 56, 3, 2);
    let duplicate = b[120..176].to_vec();
    b[176..232].copy_from_slice(&duplicate);
    assert!(inspect(&b).is_err());
}
