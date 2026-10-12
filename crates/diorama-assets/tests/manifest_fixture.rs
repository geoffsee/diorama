//! Opt-in offline qualification. No image payload is extracted or executed.
use diorama_assets::{
    ArchiveLimits, AssetId, DeclaredImageManifestPin, DecodeLimits, ImageManifestFormat,
    InventoryRequest, LayerDecodeLimits, Limits, Manifest, ManifestBindingLimits, Scope, Variant,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fmt::Write as _, path::Path};
mod synthetic {
    include!("manifest_binding.rs");
    pub(super) fn run() {
        complete_oci_and_docker_bindings_preserve_ordered_repeated_layers();
        separately_declared_identity_rejects_role_archive_and_manifest_substitution();
        rehashed_config_and_ordered_descriptor_mutations_fail();
        media_types_and_nonimage_profiles_are_explicitly_rejected();
        numeric_and_digest_types_are_not_coerced();
        duplicated_json_and_depth_limits_apply_before_semantic_interpretation();
        exact_metadata_and_reference_caps_and_invalid_pins();
        linux_platform_binding_preserves_unresolved_variant_boundary();
    }
}
fn hash(value: &Value) -> [u8; 32] {
    let value = value.as_str().unwrap();
    assert_eq!(value.len(), 64);
    std::array::from_fn(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(&mut output, "{byte:02x}").unwrap();
        output
    })
}
#[test]
#[ignore = "requires owned pinned-crane manifest fixture"]
fn verify_pinned_crane_manifest() {
    let directory =
        std::env::var_os("diorama_MANIFEST_FIXTURE").expect("explicit fixture directory");
    let directory = Path::new(&directory);
    let path = directory.join("coredns.tar.gz");
    assert!(path.metadata().unwrap().len() <= 32 * 1024 * 1024);
    let bytes = std::fs::read(path).unwrap();
    let archive_pin: Value = serde_json::from_str(include_str!(
        "../../../tools/assets-manifest/archive-pin.json"
    ))
    .unwrap();
    assert_eq!(hex(&Sha256::digest(&bytes)), archive_pin["archive_sha256"]);
    assert_eq!(
        bytes.len(),
        usize::try_from(archive_pin["archive_bytes"].as_u64().unwrap()).unwrap()
    );
    let path = directory.join("cases.json");
    assert!(path.metadata().unwrap().len() <= 256 * 1024);
    let cases: Vec<Value> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(cases.len(), 20);
    let mut declared: Value =
        serde_json::from_slice(include_bytes!("fixtures/online-amd64.json")).unwrap();
    declared["target"]["architecture"] = "arm64".into();
    for row in declared["assets"].as_array_mut().unwrap() {
        if row["id"] == "image-coredns" {
            row["delivery"]["sha256"] = archive_pin["archive_sha256"].clone();
            row["delivery"]["encoded_bytes"] = archive_pin["archive_bytes"].clone();
        }
    }
    let inventory = Manifest::decode(&serde_json::to_vec(&declared).unwrap(), Limits::default())
        .unwrap()
        .validate_inventory(
            InventoryRequest {
                target: NodeTarget {
                    architecture: Architecture::Arm64,
                    libc: Libc::Glibc,
                },
                variant: Variant::Online,
                scope: Scope::SupervisedBundle,
            },
            Limits::default(),
        )
        .unwrap();
    for case in cases {
        observe_case(&inventory, &bytes, &archive_pin, &case);
    }
    synthetic::run();
    println!("diorama_SYNTHETIC 8");
}

fn observe_case(
    inventory: &diorama_assets::DeclaredInventory,
    bytes: &[u8],
    archive_pin: &Value,
    case: &Value,
) {
    let mut session = inventory
        .decoding_session(DecodeLimits {
            image_bytes: 32 * 1024 * 1024,
            total_bytes: 128 * 1024 * 1024,
            ..DecodeLimits::default()
        })
        .unwrap();
    let observation = session
        .verify_crane_image_layer_digests(
            AssetId::ImageCoredns,
            bytes,
            ArchiveLimits::default(),
            LayerDecodeLimits {
                stored_bytes: 32 * 1024 * 1024,
                decoded_bytes: 80 * 1024 * 1024,
                unique_decoded_bytes: 80 * 1024 * 1024,
                ordered_decoded_bytes: 80 * 1024 * 1024,
                frames: 1,
                ..LayerDecodeLimits::default()
            },
        )
        .unwrap();
    let decoded = observation.archive().decoded_observation();
    let charge = decoded.decoded_bytes()
        + 1
        + observation
            .layers()
            .iter()
            .map(|layer| layer.decoded_bytes() + u64::from(layer.frames()))
            .sum::<u64>();
    assert_eq!(
        128 * 1024 * 1024 - session.remaining_decoded_budget(),
        charge
    );
    let remaining = (
        session.remaining_encoded_budget(),
        session.remaining_decoded_budget(),
    );
    let raw = case["raw"].as_str().unwrap().as_bytes();
    let mode = case["mode"].as_str().unwrap();
    let mut pin = DeclaredImageManifestPin {
        asset: AssetId::ImageCoredns,
        architecture: Architecture::Arm64,
        archive_sha256: hash(&archive_pin["archive_sha256"]),
        archive_bytes: archive_pin["archive_bytes"].as_u64().unwrap(),
        manifest_sha256: hash(&case["manifest_sha256"]),
        manifest_bytes: case["manifest_bytes"].as_u64().unwrap(),
        format: ImageManifestFormat::DockerV2,
    };
    let mut bounds = ManifestBindingLimits {
        manifest_bytes: 64 * 1024,
        layer_references: 32,
        json_depth: 16,
    };
    match mode {
        "normal" => {},
        "depth" => bounds.json_depth = 2,
        "bytes" => bounds.manifest_bytes = raw.len() - 1,
        "references" => bounds.layer_references = 12,
        "archive-identity" => pin.archive_sha256 = [0; 32],
        "asset" => pin.asset = AssetId::ImagePause,
        "platform" => pin.architecture = Architecture::Amd64,
        _ => panic!("unknown case mode"),
    }
    let status = match observation.bind_manifest(&pin, raw, bounds) {
        Ok(bound) => {
            assert_eq!(bound.declared_pin(), &pin);
            assert_eq!(bound.observation().layers().len(), 13);
            let observation = bound.observation();
            let config = observation.archive().config();
            let outer = observation.archive().decoded_observation();
            println!(
                "diorama_BOUND {}",
                json!({"outer_sha256":hex(outer.decoded_sha256()),"outer_bytes":outer.decoded_bytes(),"config_sha256":hex(config.sha256()),"config_bytes":config.bytes(),"layers":observation.layers().iter().map(|layer|json!({"stored_sha256":hex(layer.stored_sha256()),"stored_bytes":layer.stored_bytes(),"diff_id":hex(layer.diff_id()),"decoded_bytes":layer.decoded_bytes(),"frames":layer.frames(),"codec":format!("{:?}",layer.codec()).to_lowercase()})).collect::<Vec<_>>()})
            );
            "ok".into()
        },
        Err(error) => format!("{error:?}"),
    };
    assert_eq!(
        remaining,
        (
            session.remaining_encoded_budget(),
            session.remaining_decoded_budget()
        )
    );
    println!(
        "diorama_MANIFEST {}",
        json!({"case":case["name"],"manifest_sha256":hex(&Sha256::digest(raw)),"status":status,"budget_unchanged":true})
    );
}
