use super::super::archive::{Entry, gzip, pack, unpack};
use super::*;

struct Fixture {
    directory: tempfile::TempDir,
    pins: Value,
    entries: Vec<Entry>,
}
fn entry(name: String, body: Vec<u8>) -> Entry {
    let mut header = [0; 512];
    header[100..108].copy_from_slice(b"0000644\0");
    header[156] = b'0';
    header[257..265].copy_from_slice(b"ustar\x0000");
    Entry { name, body, header }
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("blobs")).unwrap();
        let mut layers = Vec::new();
        let mut entries = Vec::new();
        let mut descriptors = Vec::new();
        for index in 0..13 {
            let raw = format!("whole decoded layer {index}\n")
                .repeat(17)
                .into_bytes();
            let stored = gzip(&raw).unwrap();
            let digest = sha256(&stored);
            std::fs::write(directory.path().join(format!("blobs/{digest}")), &stored).unwrap();
            layers.push(json!({"stored_sha256":digest,"stored_bytes":stored.len(),
                "diff_id":sha256(&raw),"decoded_bytes":raw.len(),"codec":"gzip","frames":1}));
            descriptors.push(json!({"mediaType":LAYER_MEDIA,"size":stored.len(),"digest":format!("sha256:{digest}")}));
            entries.push(entry(format!("{digest}.tar.gz"), stored));
        }
        let diffs = layers
            .iter()
            .map(|row| format!("sha256:{}", row["diff_id"].as_str().unwrap()))
            .collect::<Vec<_>>();
        let config = serde_json::to_vec(&json!({"os":"linux","architecture":"arm64","rootfs":{"type":"layers","diff_ids":diffs}})).unwrap();
        let manifest = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":MANIFEST_MEDIA,
            "config":{"mediaType":CONFIG_MEDIA,"size":config.len(),"digest":format!("sha256:{}",sha256(&config))},"layers":descriptors})).unwrap();
        let pins = json!({"schema":1,"reference":"retained fixture","observed_at":"fixture","repo_tag":"fixture:manifest",
            "manifest_sha256":sha256(&manifest),"manifest_bytes":manifest.len(),
            "config_sha256":sha256(&config),"config_bytes":config.len(),"layers":layers});
        std::fs::write(directory.path().join("arm64-config.json"), &config).unwrap();
        std::fs::write(directory.path().join("arm64-manifest.json"), &manifest).unwrap();
        let names = entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>();
        let config_name = format!("sha256:{}", sha256(&config));
        entries.insert(0, entry(config_name.clone(), config));
        entries.push(entry(
            "manifest.json".into(),
            serde_json::to_vec(&json!([
                {"Config":config_name,"Layers":names,"RepoTags":["fixture:manifest"]}
            ]))
            .unwrap(),
        ));
        Self {
            directory,
            pins,
            entries,
        }
    }
    fn encoded(&self) -> Vec<u8> {
        gzip(&pack(&self.entries).unwrap()).unwrap()
    }
    fn verify(&self) -> Result<Value> {
        archive(self.directory.path(), &self.encoded(), &self.pins)
    }
    fn manifest_mutation(&mut self, mutate: impl FnOnce(&mut Value)) {
        let path = self.directory.path().join("arm64-manifest.json");
        let mut value = strict(&std::fs::read(&path).unwrap()).unwrap();
        mutate(&mut value);
        let raw = serde_json::to_vec(&value).unwrap();
        self.pins["manifest_sha256"] = sha256(&raw).into();
        self.pins["manifest_bytes"] = raw.len().into();
        std::fs::write(path, raw).unwrap();
    }
}
#[test]
fn independently_binds_exact_raw_inputs_and_packaged_order() {
    let fixture = Fixture::new();
    let result = fixture.verify().unwrap();
    assert_eq!(result["files"].as_object().unwrap().len(), 15);
    assert_eq!(result["layers"].as_array().unwrap().len(), 13);
    assert_eq!(result["archive_sha256"], sha256(&fixture.encoded()));
    assert!(!serde_json::to_string(&result).unwrap().contains("base64"));
}
#[test]
fn rejects_rehashed_manifest_reordering_size_and_media_changes() {
    for mutation in 0..3 {
        let mut fixture = Fixture::new();
        fixture.manifest_mutation(|value| match mutation {
            0 => value["layers"].as_array_mut().unwrap().swap(0, 1),
            1 => value["layers"][0]["size"] = json!(1),
            _ => value["layers"][0]["mediaType"] = json!("application/foreign"),
        });
        assert!(fixture.verify().is_err());
    }
}
#[test]
fn rejects_rehashed_config_diffid_platform_and_duplicate_json() {
    for mutation in 0..3 {
        let mut fixture = Fixture::new();
        let path = fixture.directory.path().join("arm64-config.json");
        let mut value = strict(&std::fs::read(&path).unwrap()).unwrap();
        if mutation == 0 {
            value["rootfs"]["diff_ids"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1);
        }
        if mutation == 1 {
            value["architecture"] = json!("amd64");
        }
        let mut raw = serde_json::to_vec(&value).unwrap();
        if mutation == 2 {
            raw.pop();
            raw.extend(b",\"os\":\"linux\"}");
        }
        fixture.pins["config_sha256"] = sha256(&raw).into();
        fixture.pins["config_bytes"] = raw.len().into();
        let digest = format!("sha256:{}", sha256(&raw));
        fixture.manifest_mutation(|manifest| {
            manifest["config"]["digest"] = json!(digest);
            manifest["config"]["size"] = json!(raw.len());
        });
        std::fs::write(path, raw).unwrap();
        assert!(inputs(fixture.directory.path(), &fixture.pins).is_err());
    }
}
#[test]
fn rejects_complete_gzip_checksum_truncation_extra_frames_and_bounded_expansion() {
    let raw = vec![42; 4096];
    let stored = gzip(&raw).unwrap();
    assert_eq!(gzip_identity(&stored, 4096).unwrap(), (sha256(&raw), 4096));
    assert!(gzip_identity(&stored, 4095).is_err());
    assert!(gzip_identity(&stored[..stored.len() - 1], 4096).is_err());
    let mut corrupt = stored.clone();
    let crc = corrupt.len() - 8;
    corrupt[crc] ^= 1;
    assert!(gzip_identity(&corrupt, 4096).is_err());
    for tail in [vec![0], stored.clone()] {
        let mut changed = stored.clone();
        changed.extend(tail);
        assert!(gzip_identity(&changed, 8192).is_err());
    }
}
#[test]
fn rejects_rehashed_stored_layer_without_corresponding_decoded_identity() {
    let mut fixture = Fixture::new();
    let stored = gzip(b"replacement layer").unwrap();
    let digest = sha256(&stored);
    std::fs::write(
        fixture.directory.path().join(format!("blobs/{digest}")),
        &stored,
    )
    .unwrap();
    fixture.pins["layers"][0]["stored_sha256"] = json!(digest);
    fixture.pins["layers"][0]["stored_bytes"] = json!(stored.len());
    fixture.manifest_mutation(|manifest| {
        manifest["layers"][0]["digest"] = json!(format!("sha256:{digest}"));
        manifest["layers"][0]["size"] = json!(stored.len());
    });
    assert!(inputs(fixture.directory.path(), &fixture.pins).is_err());
}
#[test]
fn rejects_packaged_substitution_reordering_missing_duplicate_and_extra_members() {
    for mutation in 0..6 {
        let mut fixture = Fixture::new();
        match mutation {
            0 => fixture.entries.swap(1, 2),
            1 => {
                fixture.entries.remove(1);
            },
            2 => fixture.entries[2] = fixture.entries[1].clone(),
            3 => fixture.entries.push(entry("extra".into(), vec![1])),
            4 => fixture.entries[1].body[0] ^= 1,
            _ => fixture.entries[0].body.push(b' '),
        }
        assert!(fixture.verify().is_err());
    }
}
#[test]
fn rejects_tar_header_payload_padding_termination_and_outer_corruption() {
    let fixture = Fixture::new();
    let raw = pack(&fixture.entries).unwrap();
    assert_eq!(members(&raw).unwrap().len(), unpack(&raw).unwrap().len());
    for at in [0, 512 + fixture.entries[0].body.len(), raw.len() - 1] {
        let mut changed = raw.clone();
        changed[at] ^= 1;
        assert!(members(&changed).is_err());
    }
    assert!(members(&raw[..raw.len() - 512]).is_err());
    let mut encoded = fixture.encoded();
    let at = encoded.len() - 8;
    encoded[at] ^= 1;
    assert!(outer(&encoded).is_err());
    assert!(outer(&vec![0; ARCHIVE_LIMIT + 1]).is_err());
}
#[test]
fn rejects_special_members_and_rehashed_packaged_metadata() {
    for mutation in 0..6 {
        let mut fixture = Fixture::new();
        match mutation {
            0 => fixture.entries[1].name = "../blob".into(),
            1 => fixture.entries[1].header[156] = b'2',
            2 => fixture.entries[1].header[345] = b'x',
            _ => {
                let mut value = strict(&fixture.entries[14].body).unwrap();
                match mutation {
                    3 => value[0]["RepoTags"] = json!(["substitution:tag"]),
                    4 => value[0]["Layers"].as_array_mut().unwrap().swap(0, 1),
                    _ => value[0]["LayerSources"] = json!({"foreign":"source"}),
                }
                fixture.entries[14].body = serde_json::to_vec(&value).unwrap();
            },
        }
        assert!(fixture.verify().is_err());
    }
}
#[test]
fn rejects_nonregular_retained_inputs_and_noninteger_pin_sizes() {
    let mut fixture = Fixture::new();
    fixture.pins["config_bytes"] = json!(true);
    assert!(inputs(fixture.directory.path(), &fixture.pins).is_err());
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("arm64-config.json");
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("arm64-manifest.json", &path).unwrap();
    assert!(inputs(fixture.directory.path(), &fixture.pins).is_err());
}
#[test]
#[ignore = "explicit retained input/cache and packaged archive qualification"]
fn retained_coredns_inputs_and_archive_are_independently_verified() {
    let directory = std::env::var_os("DIORAMA_MANIFEST_INPUTS").expect("retained input directory");
    let archive_path = std::env::var_os("DIORAMA_MANIFEST_ARCHIVE").expect("packaged archive");
    let input = verify_inputs(Path::new(&directory)).unwrap();
    assert_eq!(input["layers"].as_array().unwrap().len(), 13);
    let encoded = read(Path::new(&archive_path), ARCHIVE_LIMIT as u64).unwrap();
    let result = verify_archive(Path::new(&directory), &encoded).unwrap();
    assert_eq!(result["files"], input["files"]);
    assert_eq!(result, pinned_observation().unwrap());
}
