use diorama_assets::{
    AssetId, DeclaredInventory, Delivery, FeatureSupport, InventoryError, InventoryRequest, Limits,
    Manifest, OptionalFeature, Scope, Variant, feature_support,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde_json::{Value, json};
const SOURCE: &str = include_str!("fixtures/online-amd64.json");
const HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
fn request(architecture: Architecture, libc: Libc, variant: Variant) -> InventoryRequest {
    InventoryRequest {
        target: NodeTarget { architecture, libc },
        variant,
        scope: Scope::SupervisedBundle,
    }
}
fn decode(
    value: &Value,
    request: InventoryRequest,
    limits: Limits,
) -> Result<DeclaredInventory, InventoryError> {
    Manifest::decode(&serde_json::to_vec(value).expect("test JSON"), limits)?
        .validate_inventory(request, limits)
}
fn standard() -> InventoryRequest {
    request(Architecture::Amd64, Libc::Glibc, Variant::Online)
}
fn fixture() -> Value {
    serde_json::from_str(SOURCE).expect("independent fixture")
}
fn configure_images(records: &mut [Value], variant: Variant, unavailable: usize) {
    for row in records {
        let id = row["id"].as_str().expect("id").to_owned();
        let disabled = id == "image-d2k" && unavailable > 0
            || id == "image-portainer-agent" && unavailable == 2;
        if disabled {
            row["delivery"] = json!({"kind":"unavailable"});
        } else if variant == Variant::Offline && id.starts_with("image-") {
            row["delivery"] = json!({"kind":"bundled","path":format!("fixtures/{id}"),"encoding":"gzip","encoded_bytes":3,"sha256":HASH});
        }
    }
}
fn assert_delivery(inventory: &DeclaredInventory, id: AssetId, bundled: bool) {
    let delivery = inventory
        .assets()
        .find(|(asset, _)| *asset == id)
        .expect("catalog role")
        .1;
    assert_eq!(
        matches!(delivery, Delivery::Bundled { .. }),
        bundled,
        "{id:?}"
    );
}
fn assert_optional_support(inventory: &DeclaredInventory, architecture: Architecture) {
    assert_eq!(
        inventory.optional_feature_support().collect::<Vec<_>>(),
        [
            (
                OptionalFeature::LocalPathStorage,
                FeatureSupport::SupportedTarget,
            ),
            (
                OptionalFeature::PortainerAgent,
                if architecture == Architecture::Riscv64 {
                    FeatureSupport::UnsupportedTarget
                } else {
                    FeatureSupport::SupportedTarget
                },
            ),
            (
                OptionalFeature::D2k,
                if matches!(architecture, Architecture::Amd64 | Architecture::Arm64) {
                    FeatureSupport::SupportedTarget
                } else {
                    FeatureSupport::UnsupportedTarget
                },
            ),
        ]
    );
}
fn assert_image_contract(
    inventory: &DeclaredInventory,
    architecture: Architecture,
    variant: Variant,
) {
    assert_delivery(inventory, AssetId::ImageCoredns, true);
    assert_delivery(inventory, AssetId::ImagePause, true);
    if variant == Variant::Offline {
        assert_delivery(inventory, AssetId::ImageLocalPath, true);
        assert_delivery(inventory, AssetId::ImageLocalPathHelper, true);
        assert_delivery(
            inventory,
            AssetId::ImagePortainerAgent,
            architecture != Architecture::Riscv64,
        );
        assert_delivery(
            inventory,
            AssetId::ImageD2k,
            matches!(architecture, Architecture::Amd64 | Architecture::Arm64),
        );
        assert_delivery(inventory, AssetId::ImageDiorama, true);
    }
}
#[test]
fn all_sixteen_target_variant_cells_have_exact_declared_roles() {
    let expected = [
        "containerd",
        "fuse-overlayfs-snapshotter",
        "containerd-shim-runc-v2",
        "crun",
        "cni-bridge",
        "cni-host-local",
        "cni-portmap",
        "cni-loopback",
        "image-coredns",
        "image-pause",
        "image-local-path",
        "image-local-path-helper",
        "image-portainer-agent",
        "image-d2k",
        "image-diorama",
        "kube-scheduler",
    ];
    let mut cells = 0;
    for (architecture, name, unavailable) in [
        (Architecture::Amd64, "amd64", 0),
        (Architecture::Arm64, "arm64", 0),
        (Architecture::ArmV7, "armv7", 1),
        (Architecture::Riscv64, "riscv64", 2),
    ] {
        for (libc, libc_name) in [(Libc::Glibc, "glibc"), (Libc::Musl, "musl")] {
            for variant in [Variant::Online, Variant::Offline] {
                let mut value = fixture();
                value["target"]["architecture"] = json!(name);
                value["target"]["libc"] = json!(libc_name);
                value["variant"] = json!(if variant == Variant::Online {
                    "online"
                } else {
                    "offline"
                });
                let records = value["assets"].as_array_mut().expect("array");
                assert_eq!(
                    records
                        .iter()
                        .map(|r| r["id"].as_str().expect("id"))
                        .collect::<Vec<_>>(),
                    expected
                );
                configure_images(records, variant, unavailable);
                let inventory = decode(
                    &value,
                    request(architecture, libc, variant),
                    Limits::default(),
                )
                .expect("complete cell");
                assert_eq!(inventory.assets().len(), 16);
                assert_eq!(
                    inventory.bundled_assets().len(),
                    if variant == Variant::Online {
                        11
                    } else {
                        16 - unavailable
                    }
                );
                assert_eq!(
                    inventory
                        .assets()
                        .filter(|(_, d)| matches!(d, Delivery::Unavailable {}))
                        .count(),
                    unavailable
                );
                assert_optional_support(&inventory, architecture);
                assert_image_contract(&inventory, architecture, variant);
                cells += 1;
            }
        }
    }
    assert_eq!(cells, 16);
}
#[test]
fn feature_support_matches_expected_architecture_policy() {
    for arch in [
        Architecture::Amd64,
        Architecture::Arm64,
        Architecture::ArmV7,
        Architecture::Riscv64,
    ] {
        assert_eq!(
            feature_support(arch, OptionalFeature::LocalPathStorage),
            FeatureSupport::SupportedTarget
        );
    }
    assert_eq!(
        feature_support(Architecture::Amd64, OptionalFeature::PortainerAgent),
        FeatureSupport::SupportedTarget
    );
    assert_eq!(
        feature_support(Architecture::Arm64, OptionalFeature::PortainerAgent),
        FeatureSupport::SupportedTarget
    );
    assert_eq!(
        feature_support(Architecture::ArmV7, OptionalFeature::PortainerAgent),
        FeatureSupport::SupportedTarget
    );
    assert_eq!(
        feature_support(Architecture::Riscv64, OptionalFeature::PortainerAgent),
        FeatureSupport::UnsupportedTarget
    );

    assert_eq!(
        feature_support(Architecture::Amd64, OptionalFeature::D2k),
        FeatureSupport::SupportedTarget
    );
    assert_eq!(
        feature_support(Architecture::Arm64, OptionalFeature::D2k),
        FeatureSupport::SupportedTarget
    );
    assert_eq!(
        feature_support(Architecture::ArmV7, OptionalFeature::D2k),
        FeatureSupport::UnsupportedTarget
    );
    assert_eq!(
        feature_support(Architecture::Riscv64, OptionalFeature::D2k),
        FeatureSupport::UnsupportedTarget
    );
}
#[test]
fn structural_linux_arm64_glibc_manifests_validate_both_variants() {
    let online_bytes = include_bytes!("fixtures/online-arm64.json");
    let online = Manifest::decode(online_bytes, Limits::default())
        .expect("valid online manifest")
        .validate_inventory(
            request(Architecture::Arm64, Libc::Glibc, Variant::Online),
            Limits::default(),
        )
        .expect("valid online arm64 glibc inventory");
    assert_eq!(online.assets().len(), 16);
    assert_eq!(online.bundled_assets().len(), 11);
    assert_image_contract(&online, Architecture::Arm64, Variant::Online);
    assert_optional_support(&online, Architecture::Arm64);

    let offline_bytes = include_bytes!("fixtures/offline-arm64.json");
    let offline = Manifest::decode(offline_bytes, Limits::default())
        .expect("valid offline manifest")
        .validate_inventory(
            request(Architecture::Arm64, Libc::Glibc, Variant::Offline),
            Limits::default(),
        )
        .expect("valid offline arm64 glibc inventory");
    assert_eq!(offline.assets().len(), 16);
    assert_eq!(offline.bundled_assets().len(), 16);
    assert_image_contract(&offline, Architecture::Arm64, Variant::Offline);
    assert_optional_support(&offline, Architecture::Arm64);
    assert_structural_placeholders(online_bytes, &online);
    assert_structural_placeholders(offline_bytes, &offline);
}

#[test]
fn structural_linux_amd64_glibc_manifest_validates_online_variant() {
    let online_bytes = include_bytes!("fixtures/online-amd64.json");
    let online = Manifest::decode(online_bytes, Limits::default())
        .expect("valid online manifest")
        .validate_inventory(
            request(Architecture::Amd64, Libc::Glibc, Variant::Online),
            Limits::default(),
        )
        .expect("valid online amd64 glibc inventory");
    assert_eq!(online.assets().len(), 16);
    assert_eq!(online.bundled_assets().len(), 11);
    assert_image_contract(&online, Architecture::Amd64, Variant::Online);
    assert_optional_support(&online, Architecture::Amd64);
    assert_structural_placeholders(online_bytes, &online);
}

const EXPECTED_ONLINE_AMD64: &[(AssetId, u64, &str)] = &[
    (
        AssetId::Containerd,
        48_117_256,
        "0d36f83ad8311019e32e2c15ebe63f9fae841f82d2ffe01b0d54cdc95efe51cb",
    ),
    (
        AssetId::ContainerdShim,
        2_645_520,
        "6cfdb015be1d8212a18354d9d11873e9700101866d9b5e4415669b3112dadfd2",
    ),
    (
        AssetId::Crun,
        1_281_496,
        "48a16dd40f3aa45cd0dd8a3a62367abd874e16bf356e0daecb8ebfd3276e95b1",
    ),
    (
        AssetId::CniBridge,
        2_935_354,
        "e3c56c7d925a520d7c7045105001692da4168302d9cd2ad9f2d3272c22bff035",
    ),
    (
        AssetId::CniHostLocal,
        2_311_800,
        "1df67da3b5a6fab15cc99e85436c2ad07ee8857271bda17311b10aa85fa3c9af",
    ),
    (
        AssetId::CniPortmap,
        2_663_776,
        "12ada2d3dc71a72d427f16458f003621765b14ac01483f6eeb9f7388ce98ae67",
    ),
    (
        AssetId::CniLoopback,
        2_281_531,
        "0aed308e7ca73d9775879faa49b2977973c798d60cf954c51cc3a4015131103c",
    ),
    (
        AssetId::FuseOverlayfsSnapshotter,
        12_079_288,
        "e048f9cc616299544fcdcd647cfecba10f60169537721c57e3628ac6c8a0c5c7",
    ),
    (
        AssetId::ImageCoredns,
        23_563_387,
        "0d595a7756626ad5446ce4adb5706d4b1927ae48f03ca009ecda54892b84ce49",
    ),
    (
        AssetId::ImagePause,
        340_417,
        "a4afc718f83d14fbbdf30d39349451f859fc2b663c302e22bfe80012e4800401",
    ),
    (
        AssetId::KubeScheduler,
        47_636_664,
        "93a3e6bb3521416aebef6382b3d0054d3cb304d8ecb37e062f6d7e9f7020e6e5",
    ),
];

const EXPECTED_ONLINE_ARM64: &[(AssetId, u64, &str)] = &[
    (
        AssetId::Containerd,
        45_332_336,
        "b0e4f5a10a8d18e77b276c8cb89638c9d2438579b35286d29ca9fe2521bd2c12",
    ),
    (
        AssetId::ContainerdShim,
        2_359_700,
        "a539169644149dc606034a3fc78d4061116ea8b413ac96bc7d1c797244a877bb",
    ),
    (
        AssetId::Crun,
        1_186_244,
        "67a4299d7a39b5ed52014092c7c7cf347cccec6716f9083906236ce58006c08c",
    ),
    (
        AssetId::CniBridge,
        2_696_184,
        "814c1614ae9e96ae240da32b667f0011d100bec0acdd6835cc83002e58c44d53",
    ),
    (
        AssetId::CniHostLocal,
        2_132_112,
        "1c501f73bbeeab9ac680857eed608cc7c6c0653e31a2e0a200a86c70d3bb65ca",
    ),
    (
        AssetId::CniPortmap,
        2_451_234,
        "5bccb64a8abbf3c9c86dae0f843b1a72494da4e2858b284a35ad3ca853400eb0",
    ),
    (
        AssetId::CniLoopback,
        2_106_418,
        "1005af08976311547fe2b0a41c389c612bfe542622ce2f644e17117c76c8a57f",
    ),
    (
        AssetId::FuseOverlayfsSnapshotter,
        11_534_520,
        "eb5e7ace1b1b15ab104f387276d62e1e0405b9925baf99018e0224db3f05cc5e",
    ),
    (
        AssetId::ImageCoredns,
        21_035_204,
        "3533745d553d9ada7a5fec2018567473c4c60df3a1646fc129efcdc780708e13",
    ),
    (
        AssetId::ImagePause,
        277_677,
        "012543d9e326717065a20db77e054190ae25e6bdfcf68b3e3793d4b55727f0c5",
    ),
    (
        AssetId::KubeScheduler,
        44_630_200,
        "571faf2a0d19951aade0b3d4f5f2e0b2504ee3a14ccdd2cdd0668ccd04a3c33c",
    ),
];

const EXPECTED_OFFLINE_ARM64: &[(AssetId, u64, &str)] = &[
    (
        AssetId::Containerd,
        45_332_336,
        "b0e4f5a10a8d18e77b276c8cb89638c9d2438579b35286d29ca9fe2521bd2c12",
    ),
    (
        AssetId::ContainerdShim,
        2_359_700,
        "a539169644149dc606034a3fc78d4061116ea8b413ac96bc7d1c797244a877bb",
    ),
    (
        AssetId::Crun,
        1_186_244,
        "67a4299d7a39b5ed52014092c7c7cf347cccec6716f9083906236ce58006c08c",
    ),
    (
        AssetId::CniBridge,
        2_696_184,
        "814c1614ae9e96ae240da32b667f0011d100bec0acdd6835cc83002e58c44d53",
    ),
    (
        AssetId::CniHostLocal,
        2_132_112,
        "1c501f73bbeeab9ac680857eed608cc7c6c0653e31a2e0a200a86c70d3bb65ca",
    ),
    (
        AssetId::CniPortmap,
        2_451_234,
        "5bccb64a8abbf3c9c86dae0f843b1a72494da4e2858b284a35ad3ca853400eb0",
    ),
    (
        AssetId::CniLoopback,
        2_106_418,
        "1005af08976311547fe2b0a41c389c612bfe542622ce2f644e17117c76c8a57f",
    ),
    (
        AssetId::FuseOverlayfsSnapshotter,
        11_534_520,
        "eb5e7ace1b1b15ab104f387276d62e1e0405b9925baf99018e0224db3f05cc5e",
    ),
    (
        AssetId::ImageCoredns,
        21_035_204,
        "3533745d553d9ada7a5fec2018567473c4c60df3a1646fc129efcdc780708e13",
    ),
    (
        AssetId::ImagePause,
        277_677,
        "012543d9e326717065a20db77e054190ae25e6bdfcf68b3e3793d4b55727f0c5",
    ),
    (
        AssetId::ImageLocalPath,
        84_212_031,
        "36f9db385a63293a58c1c8308da6341e59072c78cb3c255766243f002b464373",
    ),
    (
        AssetId::ImageLocalPathHelper,
        1_912_967,
        "10d8c9d113fdc1c5fa1cbb2a941dd33f31e0da986e9852c6d5e6024fad052278",
    ),
    (
        AssetId::ImagePortainerAgent,
        43_659_205,
        "b138701456bf3e836ca831a7e28cc6581dea14f5f59eb01a8baad6ee4c1de91f",
    ),
    (
        AssetId::ImageD2k,
        12_129_075,
        "59aebbc8922ad7ce4b5deb43a1256482d63f9250cf20c85cf9a521453f28a59f",
    ),
    (
        AssetId::ImageDiorama,
        85_689_657,
        "868c6b3b9b563800bbe02b14219f549314138415955d8537d6dc2701c518a678",
    ),
    (
        AssetId::KubeScheduler,
        44_630_200,
        "571faf2a0d19951aade0b3d4f5f2e0b2504ee3a14ccdd2cdd0668ccd04a3c33c",
    ),
];

fn assert_structural_placeholders(raw: &[u8], inventory: &DeclaredInventory) {
    let text = std::str::from_utf8(raw).expect("fixture utf-8");
    for reused in [
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "35b5ba6e08cdd034b8d1920f9c7203e5d66f258e1915f164a01de0af14f34710",
        "114dde0fefebbca13165d0da9c500a66190e497a82a53dcaabc3172d630be1e9",
        "ba5b1d81f9993f384b8f032914e5491306f056088821c2dba1c366bcb0893169",
        "33b37ab0b0901175c2699d81c10b0c887f0dff944de74763cca00c155904d6fb",
        "546ffb720afb37c1c537c5113c366b9cd3f7a714a4f80e5c3ca11843eedc6124",
        "78bb7ccefd41ab2d1c83ef2f0f5178bd57a4cdb359cb5298961d3d2fef6bd591",
        "7334035c70464154385408b773496920602ba4012b6a690eb1f635b02dd62c30",
        "adde2235bc72cdd111fe7cef9de85d196eb24d6a24c975b8e43d65491eaa811c",
        "df28e12d46743e1810d54e39fa0288e0285e0d8dae67c755fad6e57c6c5f62c2",
        "2d7720ad0daa2fc1238ee21e305af372b0d0d87c3e4a2754d588fac3172cdeef",
        "d10ed367231b7a5637885ae36ccb1b3162fed4a48fe48ee894339caa1c5d024a",
        "2397d068a8d1552a4c3f9147ba9c94e086bfd66fb2acb5bbaf47197105127d5f",
        "3935c8f4bf206670ccecc8126fa81f54dc0248576a1be29153c3b1ea6ed8e6f3",
        "dd0e4c5ec09bd5e73f21e4f297acf5355f9b2d924d976090e22d6098089eb1a3",
        "c43544793a1810ab5e7149f17d37833c473d85c8279739ee9d42b0274b5c727c",
        "55ec058998391634e19a91a8e7b7393c3c3ee7a4645df0b5221f64ede22d62fe",
        "a8e722d3f5a1b9e7aa7db1e77cf03efff286664fb1fe811ef83f52e3def79405",
        "3d92978a213132043410654949cd06ade2b05cbbefe61ac57b6c667f94ee1bda",
        "a9b9a9f9a512e3fe70571c58d4d76862deb09566eca282ea6b1afa2fed287743",
    ] {
        assert!(!text.contains(reused), "reused digest {reused}");
    }
    for (id, delivery) in inventory.assets() {
        let Delivery::Bundled {
            sha256,
            encoded_bytes,
            ..
        } = delivery
        else {
            continue;
        };
        assert!(
            *encoded_bytes > 64,
            "expected real size for {id:?}, got {encoded_bytes}"
        );
        assert_eq!(sha256.len(), 64, "{id:?}");
        assert!(
            sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "{id:?}"
        );
    }
    let actual: Vec<(AssetId, u64, &str)> = inventory
        .assets()
        .filter_map(|(id, delivery)| match delivery {
            Delivery::Bundled {
                encoded_bytes,
                sha256,
                ..
            } => Some((id, *encoded_bytes, sha256.as_str())),
            _ => None,
        })
        .collect();
    let expected = match (
        inventory.request().target.architecture,
        inventory.request().variant,
    ) {
        (Architecture::Amd64, Variant::Online) => EXPECTED_ONLINE_AMD64,
        (Architecture::Arm64, Variant::Online) => EXPECTED_ONLINE_ARM64,
        (Architecture::Arm64, Variant::Offline) => EXPECTED_OFFLINE_ARM64,
        other => panic!("unexpected fixture {other:?}"),
    };
    let mut expected = expected.to_vec();
    expected.sort_by_key(|entry| entry.0);
    assert_eq!(actual, expected);
}
#[test]
fn absent_or_truncated_manifest_bytes_fail_before_inventory_validation() {
    for bytes in [&b""[..], &b"{\"schema_version\":1"[..]] {
        assert!(matches!(
            Manifest::decode(bytes, Limits::default()),
            Err(InventoryError::InvalidJson { .. })
        ));
    }
    let complete = SOURCE.trim_end().as_bytes();
    assert!(matches!(
        Manifest::decode(&complete[..complete.len() - 1], Limits::default()),
        Err(InventoryError::InvalidJson { .. })
    ));
}
#[test]
fn unknown_duplicate_fields_ids_and_versions_fail() {
    for raw in [
        SOURCE.replacen(
            "\"schema_version\": 1",
            "\"schema_version\": 1, \"schema_version\": 1",
            1,
        ),
        SOURCE.replacen(
            "\"encoded_bytes\":",
            "\"encoded_bytes\": 3, \"encoded_bytes\":",
            1,
        ),
        SOURCE.replacen(
            "\"os\": \"linux\"",
            "\"os\": \"linux\", \"os\": \"linux\"",
            1,
        ),
        SOURCE.replacen(
            "\"kind\": \"registry-required\"",
            "\"kind\": \"registry-required\", \"extra\": true",
            1,
        ),
        SOURCE.replacen(
            "\"kind\": \"bundled\"",
            "\"kind\": \"bundled\", \"kind\": \"bundled\"",
            1,
        ),
        SOURCE.replacen(
            "\"schema_version\": 1",
            "\"extra\": 1, \"schema_version\": 1",
            1,
        ),
        SOURCE.replacen("\"schema_version\": 1", "\"schema_version\": true", 1),
        SOURCE.replacen("\"containerd\"", "\"unknown-component\"", 1),
    ] {
        assert!(
            Manifest::decode(raw.as_bytes(), Limits::default()).is_err(),
            "accepted malformed schema"
        );
    }
    let mut v = fixture();
    v["schema_version"] = json!(2);
    assert_eq!(
        decode(&v, standard(), Limits::default()).unwrap_err(),
        InventoryError::SchemaVersion
    );
    let mut v = fixture();
    let first = v["assets"][0].clone();
    v["assets"].as_array_mut().unwrap().push(first);
    assert_eq!(
        decode(&v, standard(), Limits::default()).unwrap_err(),
        InventoryError::DuplicateAsset(AssetId::Containerd)
    );
}
#[test]
fn missing_mandatory_roles_wrong_target_and_delivery_fail() {
    for index in [0, 8, 9, 11] {
        let mut v = fixture();
        v["assets"].as_array_mut().unwrap().remove(index);
        assert!(matches!(
            decode(&v, standard(), Limits::default()),
            Err(InventoryError::MissingAsset(_))
        ));
    }
    let v = fixture();
    assert_eq!(
        decode(
            &v,
            request(Architecture::Arm64, Libc::Glibc, Variant::Online),
            Limits::default()
        )
        .unwrap_err(),
        InventoryError::TargetMismatch
    );
    let mut v = fixture();
    v["assets"][8]["delivery"] = json!({"kind":"registry-required"});
    assert!(matches!(
        decode(&v, standard(), Limits::default()),
        Err(InventoryError::WrongDelivery(_))
    ));
    let mut v = fixture();
    v["assets"][0]["delivery"]["encoding"] = json!("zstd");
    assert!(matches!(
        decode(&v, standard(), Limits::default()),
        Err(InventoryError::WrongEncoding(_))
    ));
}
#[test]
fn unsafe_conflicting_paths_and_invalid_digests_are_rejected() {
    for path in [
        "", "/abs", "../up", "a/../b", "a//b", "./a", "a/", "a\\b", "C:x", "é", "a\0b",
    ] {
        let mut v = fixture();
        v["assets"][0]["delivery"]["path"] = json!(path);
        assert!(
            matches!(
                decode(&v, standard(), Limits::default()),
                Err(InventoryError::UnsafePath(_))
            ),
            "{path}"
        );
    }
    for path in [
        "fixtures/containerd",
        "fixtures",
        "fixtures/containerd/nested",
    ] {
        let mut v = fixture();
        v["assets"][1]["delivery"]["path"] = json!(path);
        assert!(matches!(
            decode(&v, standard(), Limits::default()),
            Err(InventoryError::ConflictingPath(_))
        ));
    }
    for hash in [
        "",
        "0",
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        &"g".repeat(64),
    ] {
        let mut v = fixture();
        v["assets"][0]["delivery"]["sha256"] = json!(hash);
        assert!(matches!(
            decode(&v, standard(), Limits::default()),
            Err(InventoryError::InvalidDigest(_))
        ));
    }
}
#[test]
fn limits_include_aggregate_probe_budget_and_checked_size_arithmetic() {
    let v = fixture();
    let bundled_budget: u64 = v["assets"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["delivery"]["encoded_bytes"].as_u64())
        .map(|b| b + 1)
        .sum();
    let limits = Limits {
        encoded_total_bytes: bundled_budget - 1,
        ..Limits::default()
    };
    assert_eq!(
        decode(&v, standard(), limits).unwrap_err(),
        InventoryError::LimitExceeded
    );
    assert!(
        decode(
            &v,
            standard(),
            Limits {
                encoded_total_bytes: bundled_budget,
                ..limits
            }
        )
        .is_ok()
    );
    for size in [0, u64::MAX] {
        let mut v = fixture();
        v["assets"][0]["delivery"]["encoded_bytes"] = json!(size);
        assert!(matches!(
            decode(&v, standard(), Limits::default()),
            Err(InventoryError::InvalidSize(_))
        ));
    }
    assert!(
        Manifest::decode(
            SOURCE.as_bytes(),
            Limits {
                manifest_bytes: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        Manifest::decode(
            SOURCE.as_bytes(),
            Limits {
                records: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        Manifest::decode(
            SOURCE.as_bytes(),
            Limits {
                encoded_asset_bytes: u64::MAX,
                ..Limits::default()
            }
        )
        .is_err()
    );
}
#[test]
fn legacy_external_scope_is_empty_and_does_not_qualify_supervised_roles() {
    let mut v = fixture();
    v["scope"] = json!("legacy-external-deps");
    let r = InventoryRequest {
        scope: Scope::LegacyExternalDeps,
        ..standard()
    };
    assert_eq!(
        decode(&v, r, Limits::default()).unwrap_err(),
        InventoryError::LegacyScopeHasPayloads
    );
    v["assets"] = json!([]);
    let inventory = decode(&v, r, Limits::default()).unwrap();
    assert_eq!(inventory.assets().len(), 0);
    assert_eq!(inventory.request().scope, Scope::LegacyExternalDeps);
    assert!(decode(&v, standard(), Limits::default()).is_err());
}

#[test]
fn validation_rechecks_exact_original_json_length_including_whitespace() {
    let padded = format!("{SOURCE}                 ");
    let exact = Limits {
        manifest_bytes: padded.len(),
        ..Limits::default()
    };
    assert!(
        Manifest::decode(padded.as_bytes(), exact)
            .unwrap()
            .validate_inventory(standard(), exact)
            .is_ok()
    );
    let decoded = Manifest::decode(padded.as_bytes(), Limits::default()).unwrap();
    let stricter = Limits {
        manifest_bytes: padded.len() - 1,
        ..Limits::default()
    };
    assert_eq!(
        decoded
            .validate_inventory(standard(), stricter)
            .unwrap_err(),
        InventoryError::LimitExceeded
    );
    let decoded = Manifest::decode(SOURCE.as_bytes(), Limits::default()).unwrap();
    assert_eq!(
        decoded
            .validate_inventory(
                standard(),
                Limits {
                    manifest_bytes: 1,
                    ..Limits::default()
                }
            )
            .unwrap_err(),
        InventoryError::LimitExceeded
    );
}
