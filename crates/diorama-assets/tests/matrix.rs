use diorama_assets::{
    ArtifactNaming, ArtifactNamingError, AssetId, DeclaredInventory, Delivery, FeatureSupport,
    InventoryRequest, Limits, ManagementArch, ManagementOs, ManagementTarget, Manifest, Matrix,
    MatrixError, OptionalFeature, Scope, Variant,
};
use diorama_platform::{Architecture, Libc, NodeTarget};

#[test]
fn exhaustive_16_node_variants() {
    let variants = Matrix::all_node_variants();
    assert_eq!(variants.len(), 16);

    for (index, variant) in variants.iter().enumerate() {
        let expected_cell = u8::try_from(index + 1).expect("cell index fits in u8");
        assert_eq!(variant.cell, expected_cell);
        assert_eq!(
            Matrix::from_cell(expected_cell).expect("valid cell"),
            *variant
        );
    }

    assert_eq!(Matrix::from_cell(0), Err(MatrixError::InvalidCell(0)));
    assert_eq!(Matrix::from_cell(17), Err(MatrixError::InvalidCell(17)));
    assert_eq!(Matrix::from_cell(255), Err(MatrixError::InvalidCell(255)));

    // Verify all 4 architectures x 2 libcs x 2 variants are present
    let arches = [
        Architecture::Amd64,
        Architecture::Arm64,
        Architecture::ArmV7,
        Architecture::Riscv64,
    ];
    let libcs = [Libc::Glibc, Libc::Musl];
    let modes = [Variant::Online, Variant::Offline];

    for arch in arches {
        for libc in libcs {
            for mode in modes {
                let found = Matrix::find_node_variant(arch, libc, mode);
                assert!(
                    found.is_some(),
                    "missing variant for {arch:?}/{libc:?}/{mode:?}"
                );
                let v = found.unwrap();
                assert_eq!(v.architecture, arch);
                assert_eq!(v.libc, libc);
                assert_eq!(v.variant, mode);
                assert_eq!(
                    v.node_target(),
                    NodeTarget {
                        architecture: arch,
                        libc,
                    }
                );
            }
        }
    }
}

#[test]
fn oci_platform_mappings() {
    let oci_platforms = Matrix::all_oci_platforms();
    assert_eq!(
        *oci_platforms,
        [
            "linux/amd64",
            "linux/arm64",
            "linux/arm/v7",
            "linux/riscv64",
        ]
    );

    for variant in Matrix::all_node_variants() {
        let expected_platform = match variant.architecture {
            Architecture::Amd64 => "linux/amd64",
            Architecture::Arm64 => "linux/arm64",
            Architecture::ArmV7 => "linux/arm/v7",
            Architecture::Riscv64 => "linux/riscv64",
        };
        assert_eq!(variant.oci_platform(), expected_platform);
    }
}

#[test]
fn optional_image_restrictions_enforced_per_cell() {
    for variant in Matrix::all_node_variants() {
        // LocalPathStorage is supported on all targets
        assert_eq!(
            variant.optional_feature_support(OptionalFeature::LocalPathStorage),
            FeatureSupport::SupportedTarget
        );

        match variant.architecture {
            Architecture::Amd64 | Architecture::Arm64 => {
                assert_eq!(
                    variant.optional_feature_support(OptionalFeature::PortainerAgent),
                    FeatureSupport::SupportedTarget
                );
                assert_eq!(
                    variant.optional_feature_support(OptionalFeature::D2k),
                    FeatureSupport::SupportedTarget
                );
            },
            Architecture::ArmV7 => {
                assert_eq!(
                    variant.optional_feature_support(OptionalFeature::PortainerAgent),
                    FeatureSupport::SupportedTarget
                );
                // D2K disabled on ARMv7
                assert_eq!(
                    variant.optional_feature_support(OptionalFeature::D2k),
                    FeatureSupport::UnsupportedTarget
                );
            },
            Architecture::Riscv64 => {
                // Portainer unavailable and D2K disabled on riscv64
                assert_eq!(
                    variant.optional_feature_support(OptionalFeature::PortainerAgent),
                    FeatureSupport::UnsupportedTarget
                );
                assert_eq!(
                    variant.optional_feature_support(OptionalFeature::D2k),
                    FeatureSupport::UnsupportedTarget
                );
            },
        }

        // Online variants bundle no optional images (registry required)
        if variant.variant == Variant::Online {
            assert!(!variant.is_image_bundled(OptionalFeature::LocalPathStorage));
            assert!(!variant.is_image_bundled(OptionalFeature::PortainerAgent));
            assert!(!variant.is_image_bundled(OptionalFeature::D2k));
        } else {
            // Offline variants bundle only supported optional images
            assert!(variant.is_image_bundled(OptionalFeature::LocalPathStorage));
            match variant.architecture {
                Architecture::Amd64 | Architecture::Arm64 => {
                    assert!(variant.is_image_bundled(OptionalFeature::PortainerAgent));
                    assert!(variant.is_image_bundled(OptionalFeature::D2k));
                },
                Architecture::ArmV7 => {
                    assert!(variant.is_image_bundled(OptionalFeature::PortainerAgent));
                    assert!(!variant.is_image_bundled(OptionalFeature::D2k));
                },
                Architecture::Riscv64 => {
                    assert!(!variant.is_image_bundled(OptionalFeature::PortainerAgent));
                    assert!(!variant.is_image_bundled(OptionalFeature::D2k));
                },
            }
        }
    }
}

#[test]
fn management_targets_and_windows_exclusion() {
    let targets = Matrix::all_management_targets();
    assert_eq!(targets.len(), 4);

    let expected_filenames = [
        (
            "dioramactl-linux-amd64",
            ManagementOs::Linux,
            ManagementArch::Amd64,
        ),
        (
            "dioramactl-linux-arm64",
            ManagementOs::Linux,
            ManagementArch::Arm64,
        ),
        (
            "dioramactl-darwin-amd64",
            ManagementOs::Darwin,
            ManagementArch::Amd64,
        ),
        (
            "dioramactl-darwin-arm64",
            ManagementOs::Darwin,
            ManagementArch::Arm64,
        ),
    ];

    for (expected_name, os, arch) in expected_filenames {
        let target = Matrix::find_management_target(os, arch).expect("management target");
        assert_eq!(target.binary_filename("dioramactl"), expected_name);

        let parsed = ArtifactNaming::parse_management_binary(expected_name)
            .expect("parse management binary");
        assert_eq!(parsed.prefix, "dioramactl");
        assert_eq!(parsed.target, target);
    }

    // Baseline prefix kubesoloctl
    let kubesolo_parsed = ArtifactNaming::parse_management_binary("kubesoloctl-darwin-arm64")
        .expect("parse baseline kubesoloctl");
    assert_eq!(kubesolo_parsed.prefix, "kubesoloctl");
    assert_eq!(
        kubesolo_parsed.target,
        ManagementTarget::new(ManagementOs::Darwin, ManagementArch::Arm64)
    );

    // E01 Windows exclusion validation
    let win_err1 = ArtifactNaming::parse_management_binary("dioramactl-windows-amd64");
    assert!(matches!(
        win_err1,
        Err(ArtifactNamingError::WindowsExcluded(_))
    ));

    let win_err2 = ArtifactNaming::parse_management_binary("dioramactl.exe");
    assert!(matches!(
        win_err2,
        Err(ArtifactNamingError::WindowsExcluded(_))
    ));

    let win_err3 = ArtifactNaming::parse_management_binary("kubesoloctl-windows-arm64.exe");
    assert!(matches!(
        win_err3,
        Err(ArtifactNamingError::WindowsExcluded(_))
    ));
}

#[test]
fn node_archive_naming_and_roundtrip_all_16_cells() {
    let prefixes = ["diorama", "kubesolo"];
    let versions = ["0.1.0", "v1.35.7", "v1.1.8"];

    for prefix in prefixes {
        for version in versions {
            for variant in Matrix::all_node_variants() {
                let filename = variant.archive_filename(prefix, version);
                let parsed = ArtifactNaming::parse_node_archive(&filename)
                    .unwrap_or_else(|e| panic!("failed to parse {filename}: {e:?}"));

                assert_eq!(parsed.prefix, prefix);
                assert_eq!(parsed.version, version);
                assert_eq!(parsed.variant.cell, variant.cell);
                assert_eq!(parsed.variant.architecture, variant.architecture);
                assert_eq!(parsed.variant.libc, variant.libc);
                assert_eq!(parsed.variant.variant, variant.variant);

                // Clean-checkout validation
                let validated_name =
                    ArtifactNaming::validate_clean_checkout_inputs(prefix, version, *variant, &[])
                        .expect("validate clean checkout inputs");
                assert_eq!(validated_name, filename);
            }
        }
    }
}

#[test]
fn node_archive_arm_and_armv7_aliases() {
    let arm_archive = "diorama-0.1.0-linux-arm.tar.gz";
    let parsed_arm = ArtifactNaming::parse_node_archive(arm_archive).expect("parse arm");
    assert_eq!(parsed_arm.variant.architecture, Architecture::ArmV7);
    assert_eq!(parsed_arm.variant.libc, Libc::Glibc);
    assert_eq!(parsed_arm.variant.variant, Variant::Online);

    let armv7_archive = "diorama-0.1.0-linux-armv7-musl-offline.tar.gz";
    let parsed_armv7 = ArtifactNaming::parse_node_archive(armv7_archive).expect("parse armv7");
    assert_eq!(parsed_armv7.variant.architecture, Architecture::ArmV7);
    assert_eq!(parsed_armv7.variant.libc, Libc::Musl);
    assert_eq!(parsed_armv7.variant.variant, Variant::Offline);
    assert!(matches!(
        ArtifactNaming::canonical_node_archive(armv7_archive),
        Err(ArtifactNamingError::NonCanonical { .. })
    ));
}

#[test]
fn node_archive_negative_and_mismatch_cases() {
    // Missing .tar.gz extension
    let err_ext = ArtifactNaming::parse_node_archive("diorama-0.1.0-linux-amd64.tar");
    assert!(matches!(
        err_ext,
        Err(ArtifactNamingError::InvalidExtension { .. })
    ));

    // Windows node archive
    let err_win = ArtifactNaming::parse_node_archive("diorama-0.1.0-windows-amd64.tar.gz");
    assert!(matches!(
        err_win,
        Err(ArtifactNamingError::WindowsExcluded(_))
    ));

    // Missing -linux- separator
    let err_fmt = ArtifactNaming::parse_node_archive("diorama-0.1.0-amd64.tar.gz");
    assert!(matches!(
        err_fmt,
        Err(ArtifactNamingError::InvalidFormat(_))
    ));

    // Unsupported architecture
    let err_arch = ArtifactNaming::parse_node_archive("diorama-0.1.0-linux-mips64.tar.gz");
    assert!(matches!(
        err_arch,
        Err(ArtifactNamingError::UnsupportedArchitecture(_))
    ));

    // Unknown suffix token
    let err_tok = ArtifactNaming::parse_node_archive("diorama-0.1.0-linux-amd64-unknown.tar.gz");
    assert!(matches!(
        err_tok,
        Err(ArtifactNamingError::InvalidFormat(_))
    ));

    // Clean-checkout validation errors
    let cell1 = Matrix::from_cell(1).unwrap();
    let err_empty_prefix = ArtifactNaming::validate_clean_checkout_inputs("", "1.0.0", cell1, &[]);
    assert!(matches!(
        err_empty_prefix,
        Err(ArtifactNamingError::InvalidFormat(_))
    ));

    let err_empty_version =
        ArtifactNaming::validate_clean_checkout_inputs("diorama", "", cell1, &[]);
    assert!(matches!(
        err_empty_version,
        Err(ArtifactNamingError::EmptyVersion)
    ));

    let err_invalid_ver =
        ArtifactNaming::validate_clean_checkout_inputs("diorama", "1/0/0", cell1, &[]);
    assert!(matches!(
        err_invalid_ver,
        Err(ArtifactNamingError::InvalidVersion(_))
    ));

    assert!(
        ArtifactNaming::parse_node_archive("diorama-0.1.0-linux-amd64-offline-musl.tar.gz")
            .is_err()
    );
    assert!(
        ArtifactNaming::parse_node_archive("diorama-0.1.0-linux-amd64-musl-musl.tar.gz").is_err()
    );
}

#[test]
fn optional_images_and_packaged_digests_are_enforced() {
    let riscv_offline =
        Matrix::find_node_variant(Architecture::Riscv64, Libc::Glibc, Variant::Offline)
            .expect("riscv64 offline cell");
    assert!(matches!(
        ArtifactNaming::validate_clean_checkout_inputs(
            "diorama",
            "0.1.0",
            riscv_offline,
            &[OptionalFeature::D2k],
        ),
        Err(ArtifactNamingError::OptionalImageRejected { .. })
    ));

    let arm64_online = Matrix::find_node_variant(Architecture::Arm64, Libc::Glibc, Variant::Online)
        .expect("arm64 online cell");
    assert!(matches!(
        ArtifactNaming::validate_clean_checkout_inputs(
            "diorama",
            "0.1.0",
            arm64_online,
            &[OptionalFeature::D2k],
        ),
        Err(ArtifactNamingError::OptionalImageRejected { .. })
    ));

    let arm64_offline =
        Matrix::find_node_variant(Architecture::Arm64, Libc::Glibc, Variant::Offline)
            .expect("arm64 offline cell");
    ArtifactNaming::validate_clean_checkout_inputs(
        "diorama",
        "0.1.0",
        arm64_offline,
        &[
            OptionalFeature::LocalPathStorage,
            OptionalFeature::PortainerAgent,
            OptionalFeature::D2k,
        ],
    )
    .expect("supported offline images");

    let inventory = Manifest::decode(
        include_bytes!("fixtures/offline-arm64.json"),
        Limits::default(),
    )
    .expect("decode fixture")
    .validate_inventory(
        InventoryRequest {
            target: NodeTarget {
                architecture: Architecture::Arm64,
                libc: Libc::Glibc,
            },
            variant: Variant::Offline,
            scope: Scope::SupervisedBundle,
        },
        Limits::default(),
    )
    .expect("validate fixture");
    let owned = packaged_digests(&inventory);
    let pairs: Vec<(AssetId, &str)> = owned
        .iter()
        .map(|(id, digest)| (*id, digest.as_str()))
        .collect();
    ArtifactNaming::validate_packaged_digests(&inventory, &pairs).expect("fixture digests");
    let mut altered = owned.clone();
    altered[0].1 = "0".repeat(64);
    let altered_pairs: Vec<(AssetId, &str)> = altered
        .iter()
        .map(|(id, digest)| (*id, digest.as_str()))
        .collect();
    assert!(matches!(
        ArtifactNaming::validate_packaged_digests(&inventory, &altered_pairs),
        Err(ArtifactNamingError::DigestMismatch { .. })
    ));
}

fn packaged_digests(inventory: &DeclaredInventory) -> Vec<(AssetId, String)> {
    inventory
        .assets()
        .filter_map(|(id, delivery)| match delivery {
            Delivery::Bundled { sha256, .. } => Some((id, sha256.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn linux_artifact_prefixes_may_contain_windows_substrings() {
    for prefix in ["darwin64tools", "windows-tools", "win32-helper"] {
        let name = format!("{prefix}-1.0-linux-amd64.tar.gz");
        let parsed = ArtifactNaming::parse_node_archive(&name).expect("linux OS token");
        assert_eq!(parsed.prefix, prefix);
    }
}
