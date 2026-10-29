use diorama_assets::{
    AssetId, DeclaredInventory, InventoryRequest, Limits, Manifest, Scope, Variant,
    VerificationError,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use std::{
    error::Error,
    io::{self, Cursor, Read},
};
const SOURCE: &[u8] = include_bytes!("fixtures/online-amd64.json");
const ABC: &[u8] = include_bytes!("fixtures/abc.bin");
fn inventory(limits: Limits) -> DeclaredInventory {
    let mut manifest_val: serde_json::Value =
        serde_json::from_slice(SOURCE).expect("valid fixture");
    if let Some(assets) = manifest_val["assets"].as_array_mut() {
        for row in assets.iter_mut() {
            if row["delivery"]["kind"] == "bundled" {
                row["delivery"]["encoded_bytes"] = serde_json::json!(3);
                row["delivery"]["sha256"] = serde_json::json!(
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                );
            }
        }
    }
    let manifest_bytes = serde_json::to_vec(&manifest_val).expect("serialized synthetic manifest");
    Manifest::decode(&manifest_bytes, limits)
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
            limits,
        )
        .unwrap()
}
#[test]
fn known_independent_sha256_vector_matches_encoded_bytes_only() {
    let inventory = inventory(Limits::default());
    let mut session = inventory.verification_session();
    let result = session
        .verify_encoded_blob(AssetId::Containerd, ABC)
        .unwrap();
    assert_eq!(result.id(), AssetId::Containerd);
    assert_eq!(result.encoded_bytes(), 3);
    assert_eq!(
        result.sha256(),
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    // These bytes are neither ELF nor gzip. Only their encoded hash is established.
    assert!(
        session
            .verify_encoded_blob(AssetId::ImageCoredns, ABC)
            .is_ok()
    );
}
#[test]
fn corruption_truncation_empty_and_extra_bytes_are_distinct() {
    let inventory = inventory(Limits::default());
    let mut session = inventory.verification_session();
    assert!(matches!(
        session.verify_encoded_blob(AssetId::Containerd, &b"abd"[..]),
        Err(VerificationError::DigestMismatch(AssetId::Containerd))
    ));
    for (bytes, observed) in [(&b""[..], 0), (&b"ab"[..], 2), (&b"abcd"[..], 4)] {
        assert!(
            matches!(session.verify_encoded_blob(AssetId::Containerd,bytes),Err(VerificationError::SizeMismatch { expected:3,observed:n,.. }) if n==observed)
        );
    }
}
#[test]
fn long_input_consumes_no_more_than_declared_size_plus_one() {
    let inventory = inventory(Limits::default());
    let mut session = inventory.verification_session();
    let mut input = Cursor::new(vec![b'a'; 1_000_000]);
    assert!(matches!(
        session.verify_encoded_blob(AssetId::Containerd, &mut input),
        Err(VerificationError::SizeMismatch { observed: 4, .. })
    ));
    assert_eq!(input.position(), 4);
}
#[derive(Debug)]
struct OneByte<'a>(&'a [u8]);
impl Read for OneByte<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if let Some((first, rest)) = self.0.split_first() {
            bytes[0] = *first;
            self.0 = rest;
            Ok(1)
        } else {
            Ok(0)
        }
    }
}
#[test]
fn short_reads_are_hashed_without_assuming_single_read() {
    let inventory = inventory(Limits::default());
    assert!(
        inventory
            .verification_session()
            .verify_encoded_blob(AssetId::Containerd, OneByte(ABC))
            .is_ok()
    );
}
#[derive(Debug)]
struct Failed;
impl Read for Failed {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test-owned error detail",
        ))
    }
}
#[test]
fn io_source_is_preserved_and_attempts_consume_aggregate_budget() {
    let inventory = inventory(Limits {
        encoded_total_bytes: 44,
        ..Limits::default()
    });
    let mut session = inventory.verification_session();
    for remaining in (0..11).rev() {
        let error = session
            .verify_encoded_blob(AssetId::Containerd, Failed)
            .unwrap_err();
        assert!(
            matches!(error,VerificationError::Io { ref source,.. } if source.kind()==io::ErrorKind::PermissionDenied)
        );
        assert!(error.source().is_some());
        assert!(!error.to_string().contains("test-owned error detail"));
        assert_eq!(session.remaining_budget(), remaining * 4);
    }
    let mut input = Cursor::new(ABC);
    assert!(matches!(
        session.verify_encoded_blob(AssetId::Containerd, &mut input),
        Err(VerificationError::BudgetExceeded(_))
    ));
    assert_eq!(input.position(), 0);
}
#[test]
fn aggregate_budget_can_verify_each_bundled_input_once() {
    let inventory = inventory(Limits {
        encoded_total_bytes: 44,
        ..Limits::default()
    });
    let mut session = inventory.verification_session();
    for (id, _, _, _) in inventory.bundled_assets() {
        assert!(session.verify_encoded_blob(id, ABC).is_ok());
    }
    assert_eq!(session.remaining_budget(), 0);
}
#[test]
fn absent_payload_is_rejected_without_touching_reader() {
    let inventory = inventory(Limits::default());
    let mut input = Cursor::new(ABC);
    assert!(matches!(
        inventory
            .verification_session()
            .verify_encoded_blob(AssetId::ImageD2k, &mut input),
        Err(VerificationError::NotBundled(AssetId::ImageD2k))
    ));
    assert_eq!(input.position(), 0);
}
#[derive(Debug)]
struct InvalidCount;
impl Read for InvalidCount {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(usize::MAX)
    }
}
#[test]
fn invalid_reader_counts_are_errors_not_panics() {
    let inventory = inventory(Limits::default());
    assert!(matches!(
        inventory
            .verification_session()
            .verify_encoded_blob(AssetId::Containerd, InvalidCount),
        Err(VerificationError::InvalidReadCount(_))
    ));
}
