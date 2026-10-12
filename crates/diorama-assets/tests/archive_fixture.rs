//! Explicit opt-in consumer for tiny, synthetic, pinned-crane serialization fixtures.
use diorama_assets::{
    ArchiveError, ArchiveLimits, AssetId, DecodeError, DecodeLimits, InventoryRequest, Limits,
    Manifest, Scope, Variant,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde_json::{Value, json};
use std::{fmt::Write, path::Path};
#[allow(clippy::duplicate_mod)]
#[path = "common/archive.rs"]
mod vectors;
fn digest_text(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(&mut out, "{byte:02x}").unwrap();
        out
    })
}
#[test]
#[ignore = "requires owned pinned-crane Docker fixture; never executes image contents"]
fn inspect_pinned_crane_serialization() {
    let directory =
        std::env::var_os("diorama_ARCHIVE_FIXTURE").expect("explicit fixture directory");
    for case in [
        "amd64-repeated",
        "armv7-unresolved",
        "outer-crc",
        "member-digest",
        "unsafe-name",
        "missing-reference",
        "duplicate-json",
        "wrong-platform",
    ] {
        let path = Path::new(&directory).join(format!("{case}.tar.gz"));
        assert!(path.metadata().unwrap().len() <= 1024 * 1024);
        let bytes = std::fs::read(path).unwrap();
        let arch = if case == "armv7-unresolved" {
            Architecture::ArmV7
        } else {
            Architecture::Amd64
        };
        let mut value: Value =
            serde_json::from_slice(include_bytes!("fixtures/online-amd64.json")).unwrap();
        value["target"]["architecture"] = json!(if arch == Architecture::ArmV7 {
            "armv7"
        } else {
            "amd64"
        });
        for row in value["assets"].as_array_mut().unwrap() {
            if row["id"] == "image-coredns" {
                row["delivery"]["encoded_bytes"] = json!(bytes.len());
                row["delivery"]["sha256"] = json!(vectors::hex(&bytes));
            }
            if row["id"] == "image-d2k" && arch == Architecture::ArmV7 {
                row["delivery"] = json!({"kind":"unavailable"});
            }
        }
        let inventory = Manifest::decode(&serde_json::to_vec(&value).unwrap(), Limits::default())
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
            .unwrap();
        let mut session = inventory.decoding_session(DecodeLimits::default()).unwrap();
        let before_encoded = session.remaining_encoded_budget();
        let before_decoded = session.remaining_decoded_budget();
        let result = session.inspect_crane_image_archive(
            AssetId::ImageCoredns,
            &bytes,
            ArchiveLimits::default(),
        );
        let observed = match result {
            Ok(value) => json!({
                "status":"ok", "decoded_bytes":value.decoded_observation().decoded_bytes(),
                "decoded_sha256":digest_text(value.decoded_observation().decoded_sha256()),
                "config_sha256":digest_text(value.config().sha256()), "config_bytes":value.config().bytes(),
                "os":value.config().os(), "architecture":value.config().architecture(),
                "variant":value.config().variant(), "platform_status":format!("{:?}",value.config().platform_status()),
                "archive_manifest_sha256":digest_text(value.archive_manifest_sha256()),
                "repo_tags":value.repo_tags(),
                "layers":value.layers().iter().map(|layer|json!({"sha256":digest_text(layer.sha256()),"bytes":layer.bytes(),"declared_diff_id":digest_text(layer.declared_diff_id())})).collect::<Vec<_>>()
            }),
            Err(
                ArchiveError::Policy(error) | ArchiveError::Decode(DecodeError::Observer(error)),
            ) => json!({"status":format!("policy:{error:?}")}),
            Err(ArchiveError::Decode(_)) => json!({"status":"decode"}),
        };
        assert!(session.remaining_encoded_budget() < before_encoded);
        assert!(session.remaining_decoded_budget() < before_decoded);
        println!(
            "diorama_ARCHIVE {}",
            json!({"case":case,"archive_sha256":vectors::hex(&bytes),"observed":observed})
        );
    }
}
