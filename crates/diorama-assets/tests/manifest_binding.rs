use diorama_assets::{
    ArchiveLimits, AssetId, DeclaredImageManifestPin, DecodeLimits, ImageManifestFormat as Format,
    InventoryRequest, LayerDecodeLimits, LayerDigestArchiveObservation, Limits, Manifest,
    ManifestBindingError as Error, ManifestBindingLimits as Bounds, Scope, Variant,
};
use diorama_platform::{Architecture, Libc, NodeTarget};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[allow(clippy::duplicate_mod)]
#[path = "common/archive.rs"]
mod vectors;
use vectors::{archive, config, gzip, hex, manifest};
const OCI: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER: &str = "application/vnd.docker.distribution.manifest.v2+json";
struct Fixture {
    bytes: Vec<u8>,
    config: Vec<u8>,
    layers: Vec<Vec<u8>>,
    architecture: Architecture,
}
impl Fixture {
    fn new(architecture: Architecture, variant: Option<&str>, zstd: bool) -> Self {
        let first = if zstd {
            vec![
                0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, 0x19, 0, 0, b'a', b'b', b'c',
            ]
        } else {
            gzip(b"abc")
        };
        let layers = vec![first.clone(), gzip(b"second"), first];
        let arch = match architecture {
            Architecture::Amd64 => "amd64",
            Architecture::Arm64 => "arm64",
            Architecture::ArmV7 => "arm",
            Architecture::Riscv64 => "riscv64",
        };
        let mut cfg: Value = serde_json::from_slice(&config(arch, variant, 3)).unwrap();
        cfg["rootfs"]["diff_ids"] = json!([
            format!("sha256:{}", hex(b"abc")),
            format!("sha256:{}", hex(b"second")),
            format!("sha256:{}", hex(b"abc"))
        ]);
        let config = serde_json::to_vec(&cfg).unwrap();
        let refs = layers.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let bytes = gzip(&archive(&config, &refs, &manifest(&config, &refs)));
        Self {
            bytes,
            config,
            layers,
            architecture,
        }
    }
    fn observe(&self, id: AssetId) -> LayerDigestArchiveObservation {
        let mut value: Value =
            serde_json::from_slice(include_bytes!("fixtures/online-amd64.json")).unwrap();
        let arch = match self.architecture {
            Architecture::Amd64 => "amd64",
            Architecture::Arm64 => "arm64",
            Architecture::ArmV7 => "armv7",
            Architecture::Riscv64 => "riscv64",
        };
        value["target"]["architecture"] = json!(arch);
        for row in value["assets"].as_array_mut().unwrap() {
            if row["id"] == "image-coredns" || row["id"] == "image-pause" {
                row["delivery"]["encoded_bytes"] = json!(self.bytes.len());
                row["delivery"]["sha256"] = json!(hex(&self.bytes));
            }
            if row["id"] == "image-d2k"
                && matches!(
                    self.architecture,
                    Architecture::ArmV7 | Architecture::Riscv64
                )
                || row["id"] == "image-portainer-agent"
                    && self.architecture == Architecture::Riscv64
            {
                row["delivery"] = json!({"kind":"unavailable"});
            }
        }
        let inventory = Manifest::decode(&serde_json::to_vec(&value).unwrap(), Limits::default())
            .unwrap()
            .validate_inventory(
                InventoryRequest {
                    target: NodeTarget {
                        architecture: self.architecture,
                        libc: Libc::Glibc,
                    },
                    variant: Variant::Online,
                    scope: Scope::SupervisedBundle,
                },
                Limits::default(),
            )
            .unwrap();
        let mut session = inventory.decoding_session(DecodeLimits::default()).unwrap();
        session
            .verify_crane_image_layer_digests(
                id,
                &self.bytes,
                ArchiveLimits::default(),
                LayerDecodeLimits::default(),
            )
            .unwrap()
    }
    fn registry(&self, format: Format) -> Value {
        let descriptor = |bytes: &[u8], media: &str| json!({"mediaType":media,"size":bytes.len(),"digest":format!("sha256:{}",hex(bytes)),"annotations":{"fixture":"independent"}});
        let cfg = if format == Format::OciV1 {
            "application/vnd.oci.image.config.v1+json"
        } else {
            "application/vnd.docker.container.image.v1+json"
        };
        let layers = self
            .layers
            .iter()
            .map(|b| {
                descriptor(
                    b,
                    if b.starts_with(&[0x28, 0xb5]) {
                        "application/vnd.oci.image.layer.v1.tar+zstd"
                    } else if format == Format::OciV1 {
                        "application/vnd.oci.image.layer.v1.tar+gzip"
                    } else {
                        "application/vnd.docker.image.rootfs.diff.tar.gzip"
                    },
                )
            })
            .collect::<Vec<_>>();
        json!({"schemaVersion":2,"mediaType":if format==Format::OciV1 {OCI} else {DOCKER},"config":descriptor(&self.config,cfg),"layers":layers,"annotations":{"test":"no registry claim"}})
    }
    fn pin(&self, raw: &[u8], format: Format) -> DeclaredImageManifestPin {
        DeclaredImageManifestPin {
            asset: AssetId::ImageCoredns,
            architecture: self.architecture,
            archive_sha256: Sha256::digest(&self.bytes).into(),
            archive_bytes: u64::try_from(self.bytes.len()).unwrap(),
            manifest_sha256: Sha256::digest(raw).into(),
            manifest_bytes: u64::try_from(raw.len()).unwrap(),
            format,
        }
    }
    fn check(
        &self,
        value: &Value,
        format: Format,
    ) -> Result<diorama_assets::ImageManifestBinding, Error> {
        let raw = serde_json::to_vec(value).unwrap();
        self.observe(AssetId::ImageCoredns).bind_manifest(
            &self.pin(&raw, format),
            &raw,
            Bounds::default(),
        )
    }
}
#[test]
fn complete_oci_and_docker_bindings_preserve_ordered_repeated_layers() {
    for format in [Format::OciV1, Format::DockerV2] {
        let fixture = Fixture::new(Architecture::Amd64, None, false);
        let binding = fixture.check(&fixture.registry(format), format).unwrap();
        assert_eq!(binding.declared_pin().format, format);
        let layers = binding.observation().layers();
        assert_eq!(layers.len(), 3);
        assert_eq!(layers[0].stored_sha256(), layers[2].stored_sha256());
        assert_ne!(layers[0].stored_sha256(), layers[1].stored_sha256());
    }
    let fixture = Fixture::new(Architecture::Amd64, None, true);
    assert!(
        fixture
            .check(&fixture.registry(Format::OciV1), Format::OciV1)
            .is_ok()
    );
    assert_eq!(
        fixture
            .check(&fixture.registry(Format::DockerV2), Format::DockerV2)
            .unwrap_err(),
        Error::Codec
    );
}
#[test]
fn separately_declared_identity_rejects_role_archive_and_manifest_substitution() {
    let fixture = Fixture::new(Architecture::Amd64, None, false);
    let raw = serde_json::to_vec(&fixture.registry(Format::OciV1)).unwrap();
    let pin = fixture.pin(&raw, Format::OciV1);
    assert_eq!(
        fixture
            .observe(AssetId::ImagePause)
            .bind_manifest(&pin, &raw, Bounds::default())
            .unwrap_err(),
        Error::Asset
    );
    for (changed, expected) in [
        (
            DeclaredImageManifestPin {
                asset: AssetId::Containerd,
                ..pin
            },
            Error::InvalidPin,
        ),
        (
            DeclaredImageManifestPin {
                archive_bytes: pin.archive_bytes + 1,
                ..pin
            },
            Error::ArchiveIdentity,
        ),
        (
            DeclaredImageManifestPin {
                archive_sha256: [0; 32],
                ..pin
            },
            Error::ArchiveIdentity,
        ),
        (
            DeclaredImageManifestPin {
                manifest_sha256: [0; 32],
                ..pin
            },
            Error::ManifestIdentity,
        ),
        (
            DeclaredImageManifestPin {
                manifest_bytes: pin.manifest_bytes + 1,
                ..pin
            },
            Error::ManifestIdentity,
        ),
        (
            DeclaredImageManifestPin {
                architecture: Architecture::Arm64,
                ..pin
            },
            Error::Platform,
        ),
    ] {
        assert_eq!(
            fixture
                .observe(AssetId::ImageCoredns)
                .bind_manifest(&changed, &raw, Bounds::default())
                .unwrap_err(),
            expected
        );
    }
    let other = Fixture::new(Architecture::Amd64, None, true);
    assert_eq!(
        other
            .observe(AssetId::ImageCoredns)
            .bind_manifest(&pin, &raw, Bounds::default())
            .unwrap_err(),
        Error::ArchiveIdentity
    );
}
#[test]
fn rehashed_config_and_ordered_descriptor_mutations_fail() {
    let f = Fixture::new(Architecture::Amd64, None, false);
    let original = f.registry(Format::OciV1);
    for field in ["digest", "size"] {
        let mut v = original.clone();
        v["config"][field] = if field == "size" {
            json!(1)
        } else {
            json!(format!("sha256:{}", "0".repeat(64)))
        };
        assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Config);
        let mut v = original.clone();
        v["layers"][0][field] = if field == "size" {
            json!(1)
        } else {
            json!(format!("sha256:{}", "0".repeat(64)))
        };
        assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Layers);
    }
    for mode in 0..3 {
        let mut v = original.clone();
        let rows = v["layers"].as_array_mut().unwrap();
        match mode {
            0 => {
                rows.swap(0, 1);
            },
            1 => {
                rows.pop();
            },
            _ => {
                rows.push(rows[0].clone());
            },
        }
        assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Layers);
    }
}
#[test]
fn media_types_and_nonimage_profiles_are_explicitly_rejected() {
    let f = Fixture::new(Architecture::Amd64, None, false);
    let original = f.registry(Format::OciV1);
    for media in [
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+gzip+encrypted",
        "application/vnd.oci.image.layer.v1.tar+zstd",
    ] {
        let mut v = original.clone();
        v["layers"][0]["mediaType"] = json!(media);
        assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Codec);
    }
    for field in ["subject", "artifactType", "unknown"] {
        let mut v = original.clone();
        v[field] = json!({});
        assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Profile);
    }
    for field in ["urls", "data", "platform"] {
        let mut v = original.clone();
        v["layers"][0][field] = json!([]);
        assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Profile);
    }
    let mut v = original.clone();
    v["mediaType"] = json!("application/vnd.oci.image.index.v1+json");
    assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Profile);
    let mut v = original.clone();
    v.as_object_mut().unwrap().remove("mediaType");
    assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Profile);
    let mut v = original;
    v["config"]["mediaType"] = json!("application/vnd.oci.empty.v1+json");
    assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Codec);
}
#[test]
fn numeric_and_digest_types_are_not_coerced() {
    let f = Fixture::new(Architecture::Amd64, None, false);
    let original = f.registry(Format::OciV1);
    for value in [
        json!(0),
        json!(-1),
        json!(true),
        json!(2.0),
        json!(u64::MAX),
        json!("3"),
    ] {
        let mut v = original.clone();
        v["layers"][0]["size"] = value;
        assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Descriptor);
    }
    for digest in [
        format!("sha256:{}", "A".repeat(64)),
        format!("sha512:{}", "a".repeat(64)),
        format!("sha256:{}", "a".repeat(63)),
        "sha256:é".to_string(),
    ] {
        let mut v = original.clone();
        v["config"]["digest"] = json!(digest);
        assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Descriptor);
    }
    for value in [json!(true), json!(2.0), json!("2"), json!(3)] {
        let mut v = original.clone();
        v["schemaVersion"] = value;
        assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Profile);
    }
    let mut v = original;
    v["annotations"]["test"] = json!(2);
    assert_eq!(f.check(&v, Format::OciV1).unwrap_err(), Error::Profile);
}
#[test]
fn duplicated_json_and_depth_limits_apply_before_semantic_interpretation() {
    let f = Fixture::new(Architecture::Amd64, None, false);
    let raw = serde_json::to_string(&f.registry(Format::OciV1)).unwrap();
    for bad in [
        raw.replacen(
            "\"schemaVersion\":2",
            "\"schemaVersion\":2,\"schemaVersion\":2",
            1,
        ),
        raw.replacen(
            "\"fixture\":\"independent\"",
            "\"fixture\":\"independent\",\"fixture\":\"independent\"",
            1,
        ),
        format!("{raw} null"),
        raw.replacen("\"size\":29", "\"size\":18446744073709551616", 1),
    ] {
        assert_ne!(bad, raw, "negative fixture must change the original bytes");
        assert!(
            f.observe(AssetId::ImageCoredns)
                .bind_manifest(
                    &f.pin(bad.as_bytes(), Format::OciV1),
                    bad.as_bytes(),
                    Bounds::default()
                )
                .is_err()
        );
    }
    assert_eq!(
        f.observe(AssetId::ImageCoredns)
            .bind_manifest(
                &f.pin(raw.as_bytes(), Format::OciV1),
                raw.as_bytes(),
                Bounds {
                    json_depth: 2,
                    ..Bounds::default()
                }
            )
            .unwrap_err(),
        Error::Json
    );
}
#[test]
fn exact_metadata_and_reference_caps_and_invalid_pins() {
    let f = Fixture::new(Architecture::Amd64, None, false);
    let raw = serde_json::to_vec(&f.registry(Format::OciV1)).unwrap();
    let pin = f.pin(&raw, Format::OciV1);
    let exact = Bounds {
        manifest_bytes: raw.len(),
        layer_references: 3,
        ..Bounds::default()
    };
    assert!(
        f.observe(AssetId::ImageCoredns)
            .bind_manifest(&pin, &raw, exact)
            .is_ok()
    );
    for limits in [
        Bounds {
            manifest_bytes: raw.len() - 1,
            ..exact
        },
        Bounds {
            layer_references: 2,
            ..exact
        },
    ] {
        assert_eq!(
            f.observe(AssetId::ImageCoredns)
                .bind_manifest(&pin, &raw, limits)
                .unwrap_err(),
            Error::Limit
        );
    }
    for limits in [
        Bounds {
            manifest_bytes: 0,
            ..exact
        },
        Bounds {
            layer_references: 0,
            ..exact
        },
        Bounds {
            json_depth: 65,
            ..exact
        },
    ] {
        assert_eq!(
            f.observe(AssetId::ImageCoredns)
                .bind_manifest(&pin, &raw, limits)
                .unwrap_err(),
            Error::InvalidLimits
        );
    }
    let oversized = DeclaredImageManifestPin {
        manifest_bytes: u64::MAX,
        ..pin
    };
    assert_eq!(
        f.observe(AssetId::ImageCoredns)
            .bind_manifest(&oversized, b"not JSON", exact)
            .unwrap_err(),
        Error::Limit
    );
    for changed in [
        DeclaredImageManifestPin {
            manifest_bytes: 0,
            ..pin
        },
        DeclaredImageManifestPin {
            archive_bytes: 0,
            ..pin
        },
        DeclaredImageManifestPin {
            archive_bytes: u64::MAX,
            ..pin
        },
    ] {
        assert_eq!(
            f.observe(AssetId::ImageCoredns)
                .bind_manifest(&changed, &raw, exact)
                .unwrap_err(),
            Error::InvalidPin
        );
    }
}
#[test]
fn linux_platform_binding_preserves_unresolved_variant_boundary() {
    for (arch, variant, accepted) in [
        (Architecture::Amd64, None, true),
        (Architecture::Arm64, None, true),
        (Architecture::Riscv64, None, true),
        (Architecture::ArmV7, Some("v7"), true),
        (Architecture::ArmV7, None, false),
        (Architecture::Arm64, Some("v8"), false),
    ] {
        let f = Fixture::new(arch, variant, false);
        let result = f.check(&f.registry(Format::OciV1), Format::OciV1);
        if accepted {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.unwrap_err(), Error::Platform);
        }
    }
}
