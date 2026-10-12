use super::*;
#[test]
fn hand_encoded_descriptors_preserve_known_and_unknown_fields() {
    assert_eq!(
        descriptor::descriptor(&[10, 1, b'x', 24, 7, 32, 1, 40, 5], "field", 0).unwrap(),
        json!({"name":["x"],"number":[7],"label":[1],"type":[5]})
    );
    let old = descriptor::descriptor(&[0x98, 6, 7], "field", 0).unwrap();
    assert_eq!(old, json!({"unknown_99":[{"wire":0,"value":7}]}));
    let new = descriptor::descriptor(&[0x98, 6, 8], "field", 0).unwrap();
    assert!(!changes(&old, &new, "").is_empty());
}
#[test]
fn malformed_descriptors_and_uint64_overflow_fail() {
    for data in [
        &[10, 5, b'x'][..],
        &[0],
        &[11],
        &[8, 1],
        &[128; 11],
        &[0x98, 6, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2],
    ] {
        assert!(descriptor::descriptor(data, "field", 0).is_err());
    }
    assert!(descriptor::descriptor(&[], "set", 65).is_err());
}
#[test]
fn source_authority_requires_unique_exact_pin() {
    let r = json!({"id":"version","url":"https://example.invalid/version.proto","sha256":"abc","bytes":3});
    let a = json!({"sources":[{"repository":"official","commit":"pin","files":[r]}]});
    assert_eq!(source_authority(&r, &a).unwrap()["commit"], "pin");
    let mut changed = r.clone();
    changed["bytes"] = 4.into();
    assert!(source_authority(&changed, &a).is_err());
    assert!(source_authority(&r, &json!({"sources":[]})).is_err());
    let mut duplicate = a.clone();
    duplicate["sources"]
        .as_array_mut()
        .unwrap()
        .push(a["sources"][0].clone());
    assert!(source_authority(&r, &duplicate).is_err());
}
fn snapshot() -> Value {
    let defaults = json!({"schema_version":1,"source_revision":"pin","go_version":"go1","platform":"linux/amd64","emulation_version":"1.35","minimum_compatibility_version":"1.34","cases":{"a":{"value":true}},"registered_feature_gates":{"Gate":false}});
    let mut apiserver = defaults.clone();
    apiserver["apiserver_options"] = json!({"port":6443});
    json!({"source":{"schema_version":2,"authority":{"repository":"official","commit":"pin"},"inputs":{},"openapi_definitions":{"Thing":{"properties":{"description":{"type":"string"}},"x-new":12}},"cri":{"files":[{"name":["api.proto"],"messages":[{"name":["A"],"fields":[{"name":["x"],"number":[1],"type":[9]}]}],"services":[{"name":["S"],"methods":[{"name":["Read"],"server_streaming":[1]}]}]}]},"containerd":{"files":[]}},"defaults":defaults,"apiserver":apiserver})
}
#[test]
fn report_separates_schema_fields_rpcs_defaults_gates_and_metadata() {
    let before = snapshot();
    let mut after = before.clone();
    after["source"]["openapi_definitions"]["Thing"]["properties"]["description"]["type"] =
        "integer".into();
    after["source"]["cri"]["files"][0]["messages"][0]["fields"][0]["number"][0] = 2.into();
    after["source"]["cri"]["files"][0]["services"][0]["methods"][0]["server_streaming"][0] =
        0.into();
    after["defaults"]["cases"]["a"]["value"] = false.into();
    after["apiserver"]["apiserver_options"]["port"] = 1.into();
    after["defaults"]["registered_feature_gates"]["Gate"] = true.into();
    after["source"]["authority"]["commit"] = "new".into();
    let r = report::build_report(&before, &after, &json!({}), &json!({})).unwrap();
    assert_eq!(r["change_count"], 7);
    for category in [
        "api_schema",
        "protobuf_fields",
        "protobuf_rpcs",
        "component_defaults",
        "apiserver_defaults",
        "feature_gates",
        "snapshot_metadata",
    ] {
        assert_eq!(
            r["changes"][category].as_array().unwrap().len(),
            1,
            "{category}"
        );
    }
}
#[test]
fn named_arrays_ignore_order_but_reject_duplicates_and_malformed_identity() {
    let a = json!({"files":[{"name":["a"]},{"name":["b"]}]});
    let b = json!({"files":[{"name":["b"]},{"name":["a"]}]});
    assert_eq!(
        report::named(&a, None).unwrap(),
        report::named(&b, None).unwrap()
    );
    for invalid in [
        json!({"files":[{"name":["a"]},{"name":["a"]}]}),
        json!({"files":{}}),
        json!({"files":[{"name":"x"}]}),
        json!({"files":[{"name":[1]}]}),
    ] {
        assert!(report::named(&invalid, None).is_err());
    }
}
#[test]
fn report_removals_pointer_escapes_and_scalar_types_are_visible() {
    let diff = report::changes(
        Some(&json!({"a/b~c":[true,1]})),
        Some(&json!({"a/b~c":[1]})),
        "",
    );
    assert_eq!(diff[0]["path"], "/a~1b~0c/0");
    assert_eq!(diff[0]["kind"], "type_changed");
    assert_eq!(diff[1]["kind"], "removed");
}
#[test]
fn report_rejects_missing_authority_and_noninteger_schema() {
    let before = snapshot();
    for bad in [json!(true), json!(2.0), json!("2")] {
        let mut s = before.clone();
        s["source"]["schema_version"] = bad;
        assert!(report::validate(&s).is_err());
    }
    let mut s = before;
    s["defaults"]["source_revision"] = "".into();
    assert!(report::validate(&s).is_err());
}
#[test]
fn markdown_snapshot_content_cannot_close_code_blocks() {
    let before = snapshot();
    let mut after = before.clone();
    after["defaults"]["cases"]["a"]["value"] = "```\n# injected\n\u{2028}".into();
    let r = report::build_report(&before, &after, &json!({}), &json!({})).unwrap();
    let md = report::markdown(&r).unwrap();
    assert!(md.contains("\\n# injected\\n\\u2028"));
    assert!(!md.contains("\n# injected"));
}
#[test]
fn accepted_snapshot_has_streaming_cri_and_full_containerd_graph() {
    let mut bytes = Vec::new();
    flate2::read::MultiGzDecoder::new(
        fs::File::open(upstream::root().join("tools/drift/inventory.json.gz")).unwrap(),
    )
    .read_to_end(&mut bytes)
    .unwrap();
    let raw = json!({"source": strict_json(&bytes).unwrap()});
    let source = &raw["source"];
    assert_eq!(source["containerd_inputs"].as_array().unwrap().len(), 17);
    let files = source["containerd"]["files"].as_array().unwrap();
    let services = files
        .iter()
        .filter_map(|f| f["services"].as_array())
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(services.len(), 11);
    assert_eq!(
        services
            .iter()
            .map(|s| s["methods"].as_array().unwrap().len())
            .sum::<usize>(),
        65
    );
    let file = &source["cri"]["files"][0];
    let runtime = file["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == json!(["RuntimeService"]))
        .unwrap();
    let event = runtime["methods"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == json!(["GetContainerEvents"]))
        .unwrap();
    assert_eq!(event["server_streaming"], json!([1]));
    assert_eq!(event["input"], json!([".runtime.v1.GetEventsRequest"]));
}
#[test]
fn report_load_rejects_duplicate_keys_and_gzip_expansion() {
    let d = tempfile::tempdir().unwrap();
    for name in ["defaults.json", "apiserver-defaults.json"] {
        fs::write(d.path().join(name), b"{}").unwrap();
    }
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(b"{\"a\":1,\"a\":2}").unwrap();
    fs::write(d.path().join("inventory.json.gz"), gzip.finish().unwrap()).unwrap();
    assert!(report::load_snapshot(d.path()).is_err());
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let block = [b' '; 8192];
    for _ in 0..4097 {
        gzip.write_all(&block).unwrap();
    }
    fs::write(d.path().join("inventory.json.gz"), gzip.finish().unwrap()).unwrap();
    assert!(
        report::load_snapshot(d.path())
            .unwrap_err()
            .to_string()
            .contains("32MiB")
    );
}
#[test]
fn resolved_report_merges_counts_pins_hashes_and_categories() {
    let mut report =
        report::build_report(&snapshot(), &snapshot(), &json!({}), &json!({})).unwrap();
    let resolved = json!({"changes":{"resolved_apiserver_options":[{"path":"/default/port","kind":"removed","before":6443}]},"source_pins":{"before":{"commit":"old"},"after":{"commit":"new"}},"snapshot_sha256":{"before":{"resolved.json":"abc"},"after":{"resolved.json":"def"}},"change_count":1,"removal_count":1});
    report::merge_resolved(&mut report, &resolved).unwrap();
    assert_eq!(report["change_count"], 1);
    assert_eq!(report["removal_count"], 1);
    assert_eq!(report["source_pins"]["after"]["resolved"]["commit"], "new");
    assert_eq!(
        report["snapshot_sha256"]["after"]["resolved/resolved.json"],
        "def"
    );
    assert_eq!(report["status"], "changed");
}
#[test]
fn report_named_removals_empty_collections_and_missing_null_stay_distinct() {
    let before = snapshot();
    let mut after = before.clone();
    after["source"]["cri"]["files"][0]["messages"][0]["fields"] = json!([]);
    let r = report::build_report(&before, &after, &json!({}), &json!({})).unwrap();
    assert_eq!(r["changes"]["protobuf_fields"][0]["kind"], "removed");
    assert!(
        r["changes"]["protobuf_fields"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with("/fields/x")
    );
    let mut before = before;
    before["source"]["cri"]["files"][0]
        .as_object_mut()
        .unwrap()
        .remove("services");
    after = before.clone();
    after["source"]["cri"]["files"][0]["services"] = json!([]);
    let r = report::build_report(&before, &after, &json!({}), &json!({})).unwrap();
    assert_eq!(r["changes"]["protobuf_rpcs"][0]["kind"], "added");
    let diff = report::changes(Some(&json!({})), Some(&json!({"missing":null})), "");
    assert_eq!(diff[0]["kind"], "added");
    let diff = report::changes(Some(&json!(1)), Some(&json!(1.0)), "");
    assert_eq!(diff[0]["kind"], "type_changed");
}
#[test]
#[ignore = "requires an explicitly selected prepared cache in DIORAMA_UPSTREAM_CACHE"]
fn actual_verified_protoc_detects_field_number_type_rpc_and_streaming_mutations() {
    let cache = std::path::PathBuf::from(
        std::env::var_os("DIORAMA_UPSTREAM_CACHE").expect("set DIORAMA_UPSTREAM_CACHE"),
    );
    let inputs = upstream::manifest(&upstream::root().join("tools/upstream/inputs.json")).unwrap();
    let compiler = upstream::verify(&inputs, &cache, &upstream::host_platform(), None).unwrap();
    let parse = |source: &str| {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("test.proto"), source).unwrap();
        let output = directory.path().join("out.pb");
        upstream::run(
            Command::new(&compiler)
                .arg(format!("-I{}", directory.path().display()))
                .arg(format!("--descriptor_set_out={}", output.display()))
                .arg("test.proto"),
            10,
        )
        .unwrap();
        descriptor::descriptor(&fs::read(output).unwrap(), "set", 0).unwrap()
    };
    let source = "syntax=\"proto3\"; package fixture; message A { string x = 1; } service S { rpc Read(A) returns(A); }";
    let original = parse(source);
    for replacement in [
        source.replace("x = 1", "x = 2"),
        source.replace("string x", "int32 x"),
        source.replace("rpc Read", "rpc Write"),
        source.replace("returns(A)", "returns(stream A)"),
    ] {
        assert!(!changes(&original, &parse(&replacement), "").is_empty());
    }
}
