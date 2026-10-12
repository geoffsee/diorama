//! Opt-in pinned-crane nested stream qualification; never executes image contents.
use diorama_assets::{
    ArchiveError, ArchiveLimits, AssetId, DecodeError, DecodeLimits, InventoryRequest,
    LayerDecodeLimits, Limits, Manifest, Scope, Variant,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fmt::Write, path::Path};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(&mut out, "{byte:02x}").unwrap();
        out
    })
}
fn inventory(bytes: &[u8]) -> diorama_assets::DeclaredInventory {
    let encoded_hash = hex(&Sha256::digest(bytes));
    let mut value: Value =
        serde_json::from_slice(include_bytes!("fixtures/online-amd64.json")).unwrap();
    for row in value["assets"].as_array_mut().unwrap() {
        if row["id"] == "image-coredns" {
            row["delivery"]["encoded_bytes"] = json!(bytes.len());
            row["delivery"]["sha256"] = json!(encoded_hash);
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
#[test]
#[ignore = "requires owned pinned-crane Docker fixture; never executes image contents"]
fn verify_pinned_crane_layers() {
    let directory = std::env::var_os("diorama_LAYER_FIXTURE").expect("explicit fixture directory");
    for case in [
        "gzip",
        "gzip-concat",
        "zstd",
        "zstd-concat",
        "gzip-crc",
        "zstd-checksum",
        "gzip-truncated",
        "zstd-truncated",
        "wrong-diffid",
        "outer-crc",
        "decoded-limit",
        "ordered-limit",
    ] {
        let path = Path::new(&directory).join(format!("{case}.tar.gz"));
        assert!(path.metadata().unwrap().len() <= 1024 * 1024);
        let bytes = std::fs::read(path).unwrap();
        let encoded_hash = hex(&Sha256::digest(&bytes));
        let inventory = inventory(&bytes);
        let mut session = inventory.decoding_session(DecodeLimits::default()).unwrap();
        let before_encoded = session.remaining_encoded_budget();
        let before_decoded = session.remaining_decoded_budget();
        let mut limits = LayerDecodeLimits::default();
        if case == "decoded-limit" {
            limits.decoded_bytes = 8192;
        }
        if case == "ordered-limit" {
            limits.ordered_decoded_bytes = 80000;
        }
        let result = session.verify_crane_image_layer_digests(
            AssetId::ImageCoredns,
            &bytes,
            ArchiveLimits::default(),
            limits,
        );
        let observed = match result {
            Ok(value) => {
                assert!(matches!(
                    case,
                    "gzip" | "gzip-concat" | "zstd" | "zstd-concat"
                ));
                let layers = value.layers();
                assert_eq!(layers.len(), 3);
                assert_eq!(layers[0].diff_id(), layers[2].diff_id());
                let decoded = value.archive().decoded_observation();
                let expected_charge = 1
                    + decoded.decoded_bytes()
                    + layers[..2]
                        .iter()
                        .map(|l| l.decoded_bytes() + u64::from(l.frames()))
                        .sum::<u64>();
                assert_eq!(
                    before_decoded - session.remaining_decoded_budget(),
                    expected_charge
                );
                json!({"status":"ok","outer_bytes":decoded.decoded_bytes(),"outer_sha256":hex(decoded.decoded_sha256()),
                    "layers":layers.iter().map(|l|json!({"stored_sha256":hex(l.stored_sha256()),"stored_bytes":l.stored_bytes(),
                    "diff_id":hex(l.diff_id()),"decoded_bytes":l.decoded_bytes(),"frames":l.frames(),
                    "codec":format!("{:?}",l.codec()).to_lowercase()})).collect::<Vec<_>>()})
            },
            Err(
                ArchiveError::Policy(error) | ArchiveError::Decode(DecodeError::Observer(error)),
            ) => json!({"status":format!("policy:{error:?}")}),
            Err(ArchiveError::Decode(_)) => json!({"status":"decode"}),
        };
        assert_eq!(
            before_encoded - session.remaining_encoded_budget(),
            u64::try_from(bytes.len()).unwrap() + 1
        );
        let retained = session.remaining_decoded_budget();
        assert!(retained < before_decoded);
        // These fixtures force produced output before late framing/closure failures.
        if matches!(
            case,
            "outer-crc" | "gzip-crc" | "zstd-checksum" | "wrong-diffid"
        ) {
            assert!(before_decoded - retained > 8192);
        }
        if case == "zstd-checksum" {
            let raw_a = 512 + ((b"synthetic-layer-a\n".len() * 2049).div_ceil(512) * 512) + 1024;
            // The small first stored layer fails inside the first outer 8192-byte callback.
            // Visible successful inner buffers alone are shorter than this raw stream;
            // the final failed output buffer must retain its offered capacity too.
            assert!(before_decoded - retained >= 8192 + u64::try_from(raw_a).unwrap() + 2);
        }
        let retry = session.verify_crane_image_layer_digests(
            AssetId::ImageCoredns,
            &bytes,
            ArchiveLimits::default(),
            limits,
        );
        assert_eq!(retry.is_ok(), observed["status"] == "ok");
        assert!(session.remaining_decoded_budget() < retained);
        assert_eq!(
            before_encoded - session.remaining_encoded_budget(),
            2 * (u64::try_from(bytes.len()).unwrap() + 1)
        );
        println!(
            "diorama_LAYER {}",
            json!({"case":case,"archive_sha256":encoded_hash,"observed":observed,
            "retained_budget":true,"retry_retained_budget":true})
        );
    }
}
