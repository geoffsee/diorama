use super::*;
use std::io::Cursor;
use std::time::Instant;
fn record(data: &[u8]) -> Value {
    json!({"bytes":data.len(),"sha256":digest(data)})
}
fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        z.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        z.write_all(data).unwrap();
    }
    z.finish().unwrap().into_inner()
}
fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    {
        let mut tar = tar::Builder::new(&mut enc);
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o755);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            tar.append_data(&mut header, *name, *data).unwrap();
        }
        tar.finish().unwrap();
    }
    enc.finish().unwrap()
}
struct Fixture {
    dir: tempfile::TempDir,
    inputs: Value,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let proto = b"syntax=\"proto3\";\n";
        let binary = b"#!/bin/sh\nprintf 'libprotoc 36.2\\n'\n";
        let raw = zip(&[("bin/protoc", binary)]);
        let mut source = record(proto);
        source["id"] = "cri".into();
        source["url"] = "https://example.invalid/source".into();
        let mut member = record(binary);
        member["path"] = "bin/protoc".into();
        let mut compiler = record(&raw);
        compiler["platform"] = host_platform().into();
        compiler["url"] = "https://example.invalid/compiler".into();
        compiler["files"] = json!([member]);
        for (r, data) in [(&source, proto.as_slice()), (&compiler, raw.as_slice())] {
            atomic_write(dir.path(), &blob_name(r).unwrap(), data, false).unwrap();
        }
        atomic_write(
            dir.path(),
            &format!("protoc/{}/bin/protoc", host_platform()),
            binary,
            true,
        )
        .unwrap();
        Self {
            dir,
            inputs: json!({"schema_version":1,"protoc_version":"36.2","sources":[source],"protoc_archives":[compiler]}),
        }
    }
    fn add_proto(&mut self, name: &str, data: &[u8]) {
        let mut r = record(data);
        r["id"] = name.into();
        r["target"] = "containerd".into();
        r["proto_path"] = name.into();
        atomic_write(self.dir.path(), &blob_name(&r).unwrap(), data, false).unwrap();
        self.inputs["sources"].as_array_mut().unwrap().push(r);
    }
}
#[test]
fn strict_json_rejects_duplicates_nonfinite_and_trailing() {
    for raw in [
        r#"{"a":1,"a":2}"#,
        r#"{"nested":{"a":1,"a":2}}"#,
        r#"{"x":NaN}"#,
        r#"{"x":Infinity}"#,
        r#"{"x":-Infinity}"#,
        "{}{}",
    ] {
        assert!(strict_json(raw.as_bytes()).is_err());
    }
}
#[test]
fn record_types_and_paths_are_strict() {
    for bad in [
        "",
        "../outside",
        "/absolute",
        "a/../b",
        "a/./b",
        "a//b",
        "a\\b",
    ] {
        assert!(safe_relative(bad).is_err(), "{bad}");
    }
    assert_eq!(
        safe_relative("include/google/").unwrap(),
        ["include", "google"]
    );
    for bad in [json!(true), json!(0), json!(-1), json!(1.0), json!("1")] {
        let mut r = record(b"x");
        r["bytes"] = bad;
        assert!(validate_record(&r).is_err());
    }
}
#[test]
fn verify_is_offline_and_detects_each_tampered_artifact() {
    let f = Fixture::new();
    assert!(verify(&f.inputs, f.dir.path(), &host_platform(), None).is_ok());
    for key in ["sources", "protoc_archives"] {
        let f = Fixture::new();
        let name = blob_name(&f.inputs[key][0]).unwrap();
        fs::write(f.dir.path().join(name), b"corrupt").unwrap();
        assert!(verify(&f.inputs, f.dir.path(), &host_platform(), None).is_err());
    }
    let f = Fixture::new();
    let p = verify(&f.inputs, f.dir.path(), &host_platform(), None).unwrap();
    fs::write(&p, b"different").unwrap();
    assert!(verify(&f.inputs, f.dir.path(), &host_platform(), None).is_err());
}
#[test]
fn missing_input_and_alternate_binary_fail_before_execution() {
    let f = Fixture::new();
    let empty = tempfile::tempdir().unwrap();
    assert!(
        verify(&f.inputs, empty.path(), &host_platform(), None)
            .unwrap_err()
            .to_string()
            .contains("run fetch explicitly")
    );
    let alternate = f.dir.path().join("alternate");
    fs::write(
        &alternate,
        b"#!/bin/sh\nprintf 'libprotoc 36.2\\n'\n# changed",
    )
    .unwrap();
    assert!(verify(&f.inputs, f.dir.path(), &host_platform(), Some(&alternate)).is_err());
    assert!(fetch(&f.inputs, f.dir.path(), "unsupported-cpu").is_err());
}
#[test]
fn zip_traversal_links_and_size_mismatches_fail() {
    let raw = zip(&[("../outside", b"bad")]);
    let mut r = record(&raw);
    r["files"] = json!([]);
    assert!(archive_members(&raw, &r).is_err());
    let mut z = zip::ZipWriter::new(Cursor::new(Vec::new()));
    z.add_symlink("link", "/outside", zip::write::SimpleFileOptions::default())
        .unwrap();
    let raw = z.finish().unwrap().into_inner();
    let mut r = record(&raw);
    r["files"] = json!([]);
    assert!(archive_members(&raw, &r).is_err());
    let raw = zip(&[("bin/protoc", b"abc")]);
    let mut r = record(&raw);
    let mut m = record(b"abcd");
    m["path"] = "bin/protoc".into();
    r["files"] = json!([m]);
    assert!(archive_members(&raw, &r).is_err());
}
#[cfg(unix)]
#[test]
fn cache_and_output_symlinks_never_overwrite_external_files() {
    use std::os::unix::fs::symlink;
    let d = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), d.path().join("blobs")).unwrap();
    assert!(atomic_write(d.path(), "blobs/new", b"bad", false).is_err());
    assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
    symlink(outside.path().join("missing"), d.path().join("dangling")).unwrap();
    assert!(atomic_write(d.path(), "dangling", b"bad", false).is_err());
}
#[test]
fn import_closure_is_validated_before_staging() {
    let mut f = Fixture::new();
    f.add_proto(
        "example/service.proto",
        b"import \"example/missing.proto\";\n",
    );
    let out = f.dir.path().join("prepared");
    assert!(
        generation::prepare_containerd(&f.inputs, f.dir.path(), &host_platform(), &out).is_err()
    );
    assert!(!out.exists());
    f.add_proto("example/missing.proto", b"message A {}\n");
    assert!(
        generation::prepare_containerd(&f.inputs, f.dir.path(), &host_platform(), &out).is_ok()
    );
}
#[test]
fn duplicated_and_corrupted_transitive_imports_fail() {
    let mut f = Fixture::new();
    f.add_proto("types.proto", b"message Original {}\n");
    f.add_proto("types.proto", b"message Replacement {}\n");
    assert!(
        generation::prepare_containerd(
            &f.inputs,
            f.dir.path(),
            &host_platform(),
            &f.dir.path().join("out")
        )
        .is_err()
    );
    let mut f = Fixture::new();
    f.add_proto("types.proto", b"message A {}\n");
    let last = f.inputs["sources"].as_array().unwrap().last().unwrap();
    fs::write(f.dir.path().join(blob_name(last).unwrap()), b"bad").unwrap();
    assert!(
        generation::prepare_containerd(
            &f.inputs,
            f.dir.path(),
            &host_platform(),
            &f.dir.path().join("out")
        )
        .is_err()
    );
}
#[test]
fn streaming_routes_ignore_comments() {
    let raw=b"package example;\n// service Fake {rpc Nope(A) returns(A);}\nservice Storage {\n/* rpc Fake(A); */\n rpc Write(stream A) returns(stream A);\n rpc Read(A) returns(stream A);\n}\n";
    assert_eq!(
        generation::protocol_routes(raw).unwrap(),
        [
            b"/example.Storage/Write".to_vec(),
            b"/example.Storage/Read".to_vec()
        ]
    );
    assert!(generation::protocol_routes(b"service S {\nrpc A(A) returns(A);\n}\n").is_err());
}
#[cfg(unix)]
#[test]
fn generation_check_and_missing_rpc_leave_old_output_unchanged() {
    let mut f = Fixture::new();
    f.add_proto(
        "service.proto",
        b"package example;\nservice S {\nrpc Read(A) returns(A);\n}\n",
    );
    f.inputs["containerd_output_files"] = json!(["example.rs"]);
    let generator = f.dir.path().join("generator");
    atomic_write(
        f.dir.path(),
        "generator",
        b"#!/bin/sh\nmkdir -p \"$4\"\nprintf fresh > \"$4/example.rs\"\n",
        true,
    )
    .unwrap();
    let output = f.dir.path().join("output");
    atomic_write(&output, "example.rs", b"old", false).unwrap();
    let err = generation::generate(
        &f.inputs,
        f.dir.path(),
        &host_platform(),
        &generator,
        &output,
        true,
        None,
        "containerd",
    )
    .unwrap_err();
    assert!(err.to_string().contains("missing RPC"));
    assert_eq!(fs::read(output.join("example.rs")).unwrap(), b"old");
    atomic_write(
        f.dir.path(),
        "generator",
        b"#!/bin/sh\nmkdir -p \"$4\"\nprintf /example.S/Read > \"$4/example.rs\"\n",
        true,
    )
    .unwrap();
    assert!(
        generation::generate(
            &f.inputs,
            f.dir.path(),
            &host_platform(),
            &generator,
            &output,
            true,
            None,
            "containerd"
        )
        .unwrap_err()
        .to_string()
        .contains("drift")
    );
    assert_eq!(fs::read(output.join("example.rs")).unwrap(), b"old");
}
#[test]
fn committed_manifest_has_six_exact_compiler_members() {
    let inputs = manifest(&root().join("tools/upstream/inputs.json")).unwrap();
    for compiler in array(&inputs, "protoc_archives").unwrap() {
        assert_eq!(array(compiler, "files").unwrap().len(), 6);
        assert_eq!(compiler["files"][0]["path"], "bin/protoc");
    }
}
#[cfg(unix)]
#[test]
fn all_destination_types_are_validated_before_any_replacement() {
    let mut f = Fixture::new();
    f.add_proto("types.proto", b"package example; message A {}\n");
    f.inputs["containerd_output_files"] = json!(["a.rs", "b.rs", "z.rs"]);
    let output = f.dir.path().join("out");
    for name in ["a.rs", "b.rs"] {
        atomic_write(&output, name, b"previous", false).unwrap();
    }
    atomic_write(&output, "z.rs/retained", b"directory content", false).unwrap();
    atomic_write(
        f.dir.path(),
        "generator",
        b"#!/bin/sh\nmkdir -p \"$4\"\nfor name in a b z; do printf new > \"$4/$name.rs\"; done\n",
        true,
    )
    .unwrap();
    let err = generation::generate(
        &f.inputs,
        f.dir.path(),
        &host_platform(),
        &f.dir.path().join("generator"),
        &output,
        false,
        None,
        "containerd",
    )
    .unwrap_err();
    assert!(err.to_string().contains("not a regular file"));
    for name in ["a.rs", "b.rs"] {
        assert_eq!(fs::read(output.join(name)).unwrap(), b"previous");
    }
    assert_eq!(
        fs::read(output.join("z.rs/retained")).unwrap(),
        b"directory content"
    );
}
#[cfg(unix)]
#[test]
fn command_timeout_kills_and_reaps_child_and_errors_preserve_diagnostics() {
    let start = Instant::now();
    let err = run(Command::new("sh").args(["-c", "exec sleep 30"]), 0).unwrap_err();
    assert!(err.to_string().contains("timeout"));
    assert!(start.elapsed() < Duration::from_secs(3));
    let err = run(
        Command::new("sh").args(["-c", "printf failure >&2; exit 9"]),
        2,
    )
    .unwrap_err();
    assert!(err.to_string().contains("failure"));
    assert_eq!(
        run(Command::new("sh").args(["-c", "printf '\\000\\377' "]), 2).unwrap(),
        [0, 255]
    );
    assert!(run(&mut Command::new("cat"), 2).unwrap().is_empty());
}
#[test]
fn cancellation_between_commands_prevents_next_spawn_publication_and_success() {
    let dir = tempfile::tempdir().unwrap();
    let result = with_execution(|| {
        assert!(run(&mut Command::new("cat"), 2)?.is_empty());
        EXECUTION.with(|context| context.borrow().as_ref().unwrap().request());
        let marker = dir.path().join("must-not-exist");
        assert!(run(Command::new("touch").arg(&marker), 2).is_err());
        assert!(!marker.exists());
        assert!(atomic_write(dir.path(), "publication", b"data", false).is_err());
        assert!(!dir.path().join("publication").exists());
        Ok(())
    });
    assert!(result.unwrap_err().to_string().contains("cancelled"));
    assert!(EXECUTION.with(|context| context.borrow().is_none()));
}
#[test]
fn fetch_with_all_verified_cache_entries_never_needs_network() {
    let f = Fixture::new();
    fetch(&f.inputs, f.dir.path(), &host_platform()).unwrap();
    let compiler = verify(&f.inputs, f.dir.path(), &host_platform(), None).unwrap();
    assert!(compiler.is_file());
}
#[test]
fn rejected_download_scheme_keeps_existing_verified_inputs() {
    let mut f = Fixture::new();
    let source = f.inputs["sources"][0].clone();
    let archive = f.inputs["protoc_archives"][0].clone();
    fs::remove_file(f.dir.path().join(blob_name(&archive).unwrap())).unwrap();
    f.inputs["protoc_archives"][0]["url"] = "http://example.invalid/plaintext".into();
    assert!(
        fetch(&f.inputs, f.dir.path(), &host_platform())
            .unwrap_err()
            .to_string()
            .contains("HTTPS")
    );
    read_verified(f.dir.path(), &blob_name(&source).unwrap(), &source).unwrap();
    assert!(!f.dir.path().join(blob_name(&archive).unwrap()).exists());
}
#[test]
fn duplicate_zip_namespace_is_rejected_even_when_archive_hash_is_redeclared() {
    let mut raw = zip(&[("first__", b"one"), ("second_", b"two")]);
    for offset in 0..=raw.len() - 7 {
        if &raw[offset..offset + 7] == b"second_" {
            raw[offset..offset + 7].copy_from_slice(b"first__");
        }
    }
    let mut r = record(&raw);
    r["files"] = json!([]);
    assert!(archive_members(&raw, &r).is_err());
}
#[test]
fn manifest_validates_payload_binaries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inputs.json");
    let mut valid = json!({
        "schema_version": 1,
        "sources": [],
        "protoc_archives": [],
        "payload_binaries": [{
            "id": "my-bin",
            "platform": "linux-amd64",
            "url": "https://example.invalid/bin",
            "bytes": 10,
            "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        }],
    });
    fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
    assert!(manifest(&path).is_ok());

    valid["payload_binaries"][0]["url"] = "http://example.invalid/bin".into();
    fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
    assert!(manifest(&path).is_err());

    valid["payload_binaries"][0]["url"] = "https://example.invalid/bin".into();
    valid["payload_binaries"][0]["id"] = "../evil".into();
    fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
    assert!(manifest(&path).is_err());

    valid["payload_binaries"][0]["id"] = "my-bin".into();
    valid["payload_binaries"][0]["platform"] = "bad/platform".into();
    fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
    assert!(manifest(&path).is_err());

    let mut valid_archive = json!({
        "schema_version": 1,
        "sources": [],
        "protoc_archives": [],
        "payload_binaries": [{
            "id": "my-bin",
            "platform": "linux-amd64",
            "archive": {
                "url": "https://example.invalid/bin.tar.gz",
                "bytes": 20,
                "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "path": "bin/my-bin"
            },
            "bytes": 10,
            "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        }],
    });
    fs::write(&path, serde_json::to_vec(&valid_archive).unwrap()).unwrap();
    assert!(manifest(&path).is_ok());

    valid_archive["payload_binaries"][0]["url"] = "https://example.invalid/bin".into();
    fs::write(&path, serde_json::to_vec(&valid_archive).unwrap()).unwrap();
    assert!(manifest(&path).is_err());

    valid_archive["payload_binaries"][0]
        .as_object_mut()
        .unwrap()
        .remove("url");

    valid_archive["payload_binaries"][0]["archive"]["url"] =
        "http://example.invalid/bin.tar.gz".into();
    fs::write(&path, serde_json::to_vec(&valid_archive).unwrap()).unwrap();
    assert!(manifest(&path).is_err());

    valid_archive["payload_binaries"][0]["archive"]["url"] =
        "https://example.invalid/bin.tar.gz".into();
    valid_archive["payload_binaries"][0]["archive"]["path"] = "../bin/my-bin".into();
    fs::write(&path, serde_json::to_vec(&valid_archive).unwrap()).unwrap();
    assert!(manifest(&path).is_err());
}
#[test]
fn verify_payloads_is_offline_and_validates_platform_records() {
    let dir = tempfile::tempdir().unwrap();
    let bin_data = b"#!/bin/sh\necho payload\n";
    let mut payload = record(bin_data);
    payload["id"] = "test-binary".into();
    payload["platform"] = "linux-amd64".into();
    payload["url"] = "https://example.invalid/test-binary".into();

    let inputs = json!({
        "schema_version": 1,
        "payload_binaries": [payload],
    });

    let err = verify_payloads(&inputs, dir.path(), "linux-amd64").unwrap_err();
    assert!(err.to_string().contains("missing prepared payload"));

    atomic_write(
        dir.path(),
        "payloads/linux-amd64/test-binary",
        bin_data,
        true,
    )
    .unwrap();
    assert!(verify_payloads(&inputs, dir.path(), "linux-amd64").is_ok());

    fs::write(
        dir.path().join("payloads/linux-amd64/test-binary"),
        b"corrupted",
    )
    .unwrap();
    let err = verify_payloads(&inputs, dir.path(), "linux-amd64").unwrap_err();
    assert!(err.to_string().contains("length or SHA-256 mismatch"));

    assert!(verify_payloads(&inputs, dir.path(), "linux-arm64").is_err());
}
#[test]
fn fetch_payloads_with_existing_valid_cache_never_needs_network() {
    let dir = tempfile::tempdir().unwrap();
    let bin_data = b"echo test";
    let mut payload = record(bin_data);
    payload["id"] = "cached-bin".into();
    payload["platform"] = "linux-amd64".into();
    payload["url"] = "https://example.invalid/cached-bin".into();

    let inputs = json!({
        "schema_version": 1,
        "payload_binaries": [payload],
    });

    let cached_path = dir.path().join("payloads/linux-amd64/cached-bin");
    atomic_write(
        dir.path(),
        "payloads/linux-amd64/cached-bin",
        bin_data,
        false,
    )
    .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&cached_path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    assert!(fetch_payloads(&inputs, dir.path(), "linux-amd64").is_ok());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&cached_path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    assert!(verify_payloads(&inputs, dir.path(), "linux-amd64").is_ok());
}
#[test]
fn fetch_payloads_extracts_from_tar_gz_archive_blob() {
    let dir = tempfile::tempdir().unwrap();
    let bin_data = b"#!/bin/sh\necho in archive\n";
    let archive_bytes = tar_gz(&[("./bin/my-tool", bin_data)]);
    let archive_rec = record(&archive_bytes);

    let mut payload = record(bin_data);
    payload["id"] = "my-tool".into();
    payload["platform"] = "linux-amd64".into();
    payload["archive"] = json!({
        "url": "https://example.invalid/archive.tar.gz",
        "bytes": archive_rec["bytes"],
        "sha256": archive_rec["sha256"],
        "path": "bin/my-tool"
    });

    let inputs = json!({
        "schema_version": 1,
        "payload_binaries": [payload],
    });

    let blob_path = format!("blobs/{}", archive_rec["sha256"].as_str().unwrap());
    atomic_write(dir.path(), &blob_path, &archive_bytes, false).unwrap();

    assert!(fetch_payloads(&inputs, dir.path(), "linux-amd64").is_ok());

    let extracted_path = dir.path().join("payloads/linux-amd64/my-tool");
    assert_eq!(fs::read(&extracted_path).unwrap(), bin_data);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&extracted_path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    assert!(verify_payloads(&inputs, dir.path(), "linux-amd64").is_ok());
}
