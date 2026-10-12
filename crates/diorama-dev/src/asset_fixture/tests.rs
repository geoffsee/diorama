use super::{archive, common::*, elf, native};
use std::fmt::Write as _;
#[test]
fn strict_json_and_base64_reject_ambiguous_records() -> Result<()> {
    for bad in [
        "{\"x\":1,\"x\":2}",
        "{\"nested\":{\"x\":1,\"x\":2}}",
        "1.0",
        "NaN",
    ] {
        assert!(strict(bad.as_bytes()).is_err());
    }
    for bytes in [b"".as_slice(), b"a", b"ab", b"abc", b"abcdefg"] {
        assert_eq!(unb64(&b64(bytes))?, bytes);
    }
    for bad in ["ab?=", "====", "a===", "ab==AAAA", "AB=="] {
        assert!(unb64(bad).is_err());
    }
    Ok(())
}
#[test]
fn gzip_bounds_crc_and_full_closure() -> Result<()> {
    let bytes = b"abc".repeat(10000);
    let encoded = archive::gzip(&bytes)?;
    assert_eq!(archive::ungzip(&encoded)?, bytes);
    let mut corrupt = encoded.clone();
    let at = corrupt.len() - 8;
    corrupt[at] ^= 1;
    assert!(archive::ungzip(&corrupt).is_err());
    for end in 0..encoded.len().min(20) {
        assert!(archive::ungzip(&encoded[..end]).is_err());
    }
    let mut extra = encoded.clone();
    extra.extend(&encoded);
    assert!(archive::ungzip(&extra).is_err());
    Ok(())
}
#[test]
fn bounded_nofollow_reads_and_integer_distinctions() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("input");
    std::fs::write(&file, b"abc")?;
    assert_eq!(read(&file, 3)?, b"abc");
    assert!(read(&file, 2).is_err());
    std::os::unix::fs::symlink(&file, dir.path().join("link"))?;
    assert!(read(&dir.path().join("link"), 3).is_err());
    assert_ne!(strict(b"true")?, strict(b"1")?);
    Ok(())
}
#[test]
fn builder_nonce_and_substitutions_are_exact() -> Result<()> {
    let digest = "a".repeat(64);
    let raw = format!(
        "#4 0.1 DIORAMA_BUILD_BEGIN nonce\n#4 0.2 {digest}  /out/test\n#4 0.3 DIORAMA_BUILD_END nonce\n"
    );
    assert_eq!(native::builder(&raw, "nonce", &["test"])?["test"], digest);
    assert!(native::builder(&raw, "other", &["test"]).is_err());
    assert!(native::builder(&(raw.clone() + &raw), "nonce", &["test"]).is_err());
    assert!(native::builder(&raw, "nonce", &["wrong"]).is_err());
    Ok(())
}
#[test]
fn independent_elf_checks_bounds_without_loading() -> Result<()> {
    let mut bytes = vec![0u8; 64];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16] = 2;
    bytes[18] = 62;
    bytes[20] = 1;
    bytes[52] = 64;
    bytes[54] = 56;
    let result = elf::inspect(&bytes)?;
    assert_eq!(result["machine"], 62);
    bytes[56] = 1;
    bytes[32] = 64;
    assert!(elf::inspect(&bytes).is_err());
    Ok(())
}

fn historic_archive_inputs() -> Result<Vec<(String, Vec<u8>)>> {
    // Historical bytes test the new independent oracle; their receipts are never relabeled.
    let raw = String::from_utf8(read(
        &root()?.join("tools/assets-archive/evidence/first.log"),
        2 * 1024 * 1024,
    )?)?;
    raw.lines()
        .filter_map(|line| line.strip_prefix("DIORAMA_INPUT "))
        .take(2)
        .map(|line| {
            let row = strict(line.as_bytes())?;
            Ok((
                string(&row["case"])?.to_owned(),
                unb64(string(&row["gzip_base64"])?)?,
            ))
        })
        .collect()
}
#[test]
fn historical_crane_positive_bytes_match_independent_rust_oracle() -> Result<()> {
    let inputs = historic_archive_inputs()?;
    assert_eq!(inputs.len(), 2);
    let raw = String::from_utf8(read(
        &root()?.join("tools/assets-archive/evidence/first.log"),
        2 * 1024 * 1024,
    )?)?;
    for (name, bytes) in inputs {
        let expected = archive::expected(&bytes, &name)?;
        let prior = raw
            .lines()
            .filter_map(|line| line.strip_prefix("DIORAMA_ARCHIVE "))
            .map(|line| strict(line.as_bytes()))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .find(|v| v["case"] == name)
            .ok_or("historical positive")?;
        assert_eq!(expected, prior["observed"]);
    }
    Ok(())
}
#[test]
fn archive_corruptions_are_exact_and_rehash_json_changes() -> Result<()> {
    let positive = historic_archive_inputs()?;
    let inputs = archive::cases(&positive[0].1, &positive[1].1)?;
    let expected = archive::observations(&inputs)?;
    assert_eq!(expected.as_object().ok_or("expected")?.len(), 8);
    for index in 2..8 {
        let mut changed = inputs.clone();
        changed[index].1 = positive[0].1.clone();
        assert!(archive::observations(&changed).is_err());
    }
    for name in ["duplicate-json", "wrong-platform"] {
        let bytes = &inputs.iter().find(|p| p.0 == name).ok_or("case")?.1;
        let entries = archive::unpack(&archive::ungzip(bytes)?)?;
        assert_eq!(
            entries[0].name,
            format!("sha256:{}", sha256(&entries[0].body))
        );
        let manifest = strict(&entries[3].body)?;
        assert_eq!(manifest[0]["Config"], entries[0].name);
        if name == "duplicate-json" {
            assert!(strict(&entries[0].body).is_err());
        } else {
            assert_eq!(strict(&entries[0].body)?["architecture"], "arm64");
        }
    }
    Ok(())
}
#[test]
fn tar_closure_names_and_member_checksums_reject_mutations() -> Result<()> {
    let positive = historic_archive_inputs()?;
    let raw = archive::ungzip(&positive[0].1)?;
    let entries = archive::unpack(&raw)?;
    let mut duplicate = entries.clone();
    duplicate[1].name = duplicate[0].name.clone();
    assert!(archive::unpack(&archive::pack(&duplicate)?).is_err());
    let mut damaged = raw.clone();
    damaged[1] ^= 1;
    assert!(archive::unpack(&damaged).is_err());
    for suffix in [vec![0u8; 512], vec![1u8]] {
        let mut changed = raw.clone();
        changed.extend(suffix);
        assert!(archive::unpack(&changed).is_err());
    }
    let mut changed = entries.clone();
    changed[1].body[0] ^= 1;
    assert!(
        archive::expected(
            &archive::gzip(&archive::pack(&changed)?)?,
            archive::NAMES[0]
        )
        .is_err()
    );
    Ok(())
}
fn synthetic_native() -> String {
    let mut out = format!(
        "{}  /decode-tests\n{}  /decoded_elf-tests\n{}  /fixture\n",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64)
    );
    for (suite, names) in [
        ("decode", native::DECODE.as_slice()),
        ("decoded_elf", native::ELF.as_slice()),
    ] {
        let _ = writeln!(out, "DIORAMA_SUITE {suite}");
        for name in names {
            let _ = writeln!(out, "test {name} ... ok");
        }
        let _ = writeln!(
            out,
            "test result: ok. {} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s",
            names.len()
        );
    }
    out.push_str("DIORAMA_NAMESPACE {\"init\":1,\"shell\":7,\"helper\":8,\"processes\":[1,7,8]}\n");
    out
}
#[test]
fn native_exact_suite_inventory_and_namespace_boundary() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("run");
    let good = synthetic_native();
    std::fs::write(&path, &good)?;
    native::records(&path)?;
    for bad in [
        good.replace(" ... ok", " ... FAILED"),
        good.replace("DIORAMA_NAMESPACE ", "DIORAMA_UNKNOWN {}\nDIORAMA_NAMESPACE "),
        good.replace("\"helper\":8", "\"helper\":4294967296"),
        good.replace("0 ignored;", "1 ignored;"),
        good.replace("DIORAMA_SUITE decode\n", "DIORAMA_SUITE decoded_elf\n"),
        good.replace("[1,7,8]", "[1,7,8,9]"),
        good.replace("\"helper\":8", "\"helper\":true"),
        good.replace("test result:", "test surprise ... FAILED\ntest result:"),
    ] {
        std::fs::write(&path, bad)?;
        assert!(native::records(&path).is_err());
    }
    Ok(())
}
fn synthetic_receipt(directory: &std::path::Path) -> Result<serde_json::Value> {
    let root = root()?;
    let family = "decode";
    let tag = format!("diorama-decode-{}", "d".repeat(32));
    let sources = super::common::inventory(&root, family)?;
    save(&directory.join("source-inventory.json"), &sources)?;
    let names = super::capture::binaries(family)?;
    let mut build = format!("#10 0.1 DIORAMA_BUILD_BEGIN {tag}\n");
    for (name, c) in names.iter().zip(['a', 'b', 'c']) {
        let _ = writeln!(build, "#10 0.2 {}  /out/{name}", c.to_string().repeat(64));
    }
    let _ = writeln!(build, "#10 0.3 DIORAMA_BUILD_END {tag}");
    std::fs::write(directory.join("build.log"), &build)?;
    let mut runs = serde_json::Map::new();
    for name in ["first", "repeat"] {
        let path = directory.join(format!("{name}.log"));
        std::fs::write(&path, synthetic_native())?;
        let (rows, hashes) = native::records(&path)?;
        runs.insert(name.into(),json!({"command":super::capture::command(family,&tag,name)?,"raw_sha256":digest(&path)?,"binary_sha256":hashes,"records":rows}));
    }
    let context = "/tmp/diorama-asset-context-invented";
    let receipt = json!({"schema":3,"family":family,"revision":"e".repeat(40),"dirty":false,"tag":tag,"source_sha256":sources,"source_inventory_sha256":digest(&directory.join("source-inventory.json"))?,"containers":[format!("{tag}-first"),format!("{tag}-repeat")],"errors":[],"cleanup_errors":[],"remaining_containers":[],"remaining_images":[],"image_id":format!("sha256:{}","f".repeat(64)),"build_command":["docker","build","--progress=plain","--build-arg",format!("QUALIFICATION_NONCE={tag}"),"--platform=linux/arm64","-t",tag,"-f",format!("{context}/tools/assets-decode/Capture.Dockerfile"),context],"build_log_sha256":digest(&directory.join("build.log"))?,"build_binary_sha256":native::builder(&build,&tag,&names)?,"runs":runs});
    let mut receipt = receipt;
    receipt["cancelled"] = false.into();
    receipt["command_sha256"] = json!({});
    for label in ["build", "first", "repeat"] {
        bind_synthetic_command(directory, &mut receipt, label)?;
    }
    for (label, _) in super::capture::controls(&tag) {
        let raw = if label == "image-inspect" {
            format!("{}\n", string(&receipt["image_id"])?)
        } else {
            String::new()
        };
        std::fs::write(directory.join(format!("{label}.log")), raw)?;
        bind_synthetic_command(directory, &mut receipt, label)?;
    }
    save(&directory.join("receipt.json"), &receipt)?;
    super::capture::verify(&root, family, directory)?;
    Ok(receipt)
}
fn bind_synthetic_command(
    directory: &std::path::Path,
    receipt: &mut serde_json::Value,
    label: &str,
) -> Result<()> {
    let control = super::capture::controls(string(&receipt["tag"])?)
        .into_iter()
        .find(|(name, _)| *name == label);
    let raw_hash = digest(&directory.join(format!("{label}.log")))?;
    let raw_hash = json!(raw_hash);
    let (argv, hash) = if let Some((_, argv)) = &control {
        (argv, &raw_hash)
    } else if label == "build" {
        (&receipt["build_command"], &receipt["build_log_sha256"])
    } else {
        (
            &receipt["runs"][label]["command"],
            &receipt["runs"][label]["raw_sha256"],
        )
    };
    let record = json!({"spawned":true,"owned_pid":123,"owner_directory":"/tmp/diorama-process-synthetic","owned_process_group_absent":true,"cleanup_complete":true,"output_eof":true,"cleanup_errors":[],"exit_code":0,"timeout":false,"cancelled":false,"argv":argv,"merged_output":true,"output_limit":false,"stdout_sha256":hash,"stderr_sha256":sha256(b"")});
    let path = directory.join(format!("{label}.command.json"));
    save(&path, &record)?;
    receipt["command_sha256"][label] = digest(&path)?.into();
    Ok(())
}
#[test]
fn receipts_bind_source_command_cleanup_and_raw_observations() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = synthetic_receipt(directory.path())?;
    for (key, value) in [
        ("dirty", json!(true)),
        ("cancelled", json!(true)),
        ("revision", json!("invalid")),
        ("schema", json!(true)),
        ("cleanup_errors", json!(["failed"])),
        ("remaining_containers", json!(["owned"])),
        ("source_sha256", json!({})),
        ("build_log_sha256", json!("0".repeat(64))),
        ("build_command", json!([])),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        save(&directory.path().join("receipt.json"), &changed)?;
        assert!(super::capture::verify(&root()?, "decode", directory.path()).is_err());
    }
    Ok(())
}
#[test]
fn command_receipt_mutations_fail_even_when_outer_hash_is_updated() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = synthetic_receipt(directory.path())?;
    for label in [
        "build",
        "first",
        "repeat",
        "image-inspect",
        "cleanup-1",
        "cleanup-2",
        "cleanup-3",
        "cleanup-4",
        "cleanup-5",
    ] {
        let path = directory.path().join(format!("{label}.command.json"));
        let command = load(&path)?;
        for (key, value) in [
            ("spawned", json!(false)),
            ("owned_pid", json!(0)),
            ("owned_process_group_absent", json!(false)),
            ("cleanup_complete", json!(false)),
            ("output_eof", json!(false)),
            ("cleanup_errors", json!(["unknown"])),
            ("exit_code", json!(1)),
            ("timeout", json!(true)),
            ("cancelled", json!(true)),
            ("output_limit", json!(true)),
            ("merged_output", json!(false)),
            ("argv", json!(["different"])),
            ("stdout_sha256", json!("0".repeat(64))),
            ("stderr_sha256", json!("0".repeat(64))),
            ("owner_directory", json!("relative")),
        ] {
            let mut changed = command.clone();
            changed[key] = value;
            save(&path, &changed)?;
            let mut receipt = original.clone();
            receipt["command_sha256"][label] = digest(&path)?.into();
            save(&directory.path().join("receipt.json"), &receipt)?;
            assert!(
                super::capture::verify(&root()?, "decode", directory.path()).is_err(),
                "{label}/{key}"
            );
        }
        save(&path, &command)?;
    }
    Ok(())
}

#[test]
fn rehashed_control_outputs_cannot_claim_false_image_or_empty_cleanup() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let original = synthetic_receipt(directory.path())?;
    for label in ["image-inspect", "cleanup-4", "cleanup-5"] {
        let log = directory.path().join(format!("{label}.log"));
        let raw = std::fs::read(&log)?;
        let command = directory.path().join(format!("{label}.command.json"));
        let proof = std::fs::read(&command)?;
        let mut receipt = original.clone();
        std::fs::write(
            &log,
            if label == "image-inspect" {
                format!("sha256:{}\n", "0".repeat(64))
            } else {
                "still-owned\n".into()
            },
        )?;
        bind_synthetic_command(directory.path(), &mut receipt, label)?;
        save(&directory.path().join("receipt.json"), &receipt)?;
        assert!(super::capture::verify(&root()?, "decode", directory.path()).is_err());
        std::fs::write(log, raw)?;
        std::fs::write(command, proof)?;
    }
    save(&directory.path().join("receipt.json"), &original)?;
    let relocated = tempfile::tempdir()?;
    for entry in std::fs::read_dir(directory.path())? {
        let entry = entry?;
        std::fs::copy(entry.path(), relocated.path().join(entry.file_name()))?;
    }
    super::capture::verify(&root()?, "decode", relocated.path())?;
    std::fs::write(relocated.path().join("unrecorded.log"), b"extra")?;
    assert!(super::capture::verify(&root()?, "decode", relocated.path()).is_err());
    Ok(())
}

#[test]
fn uncertain_cleanup_stops_commands_and_retains_context() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().to_owned();
    let failure = || -> diorama_dev::Error {
        Box::new(diorama_dev::process::CommandFailure {
            message: "unsettled".into(),
            cleanup_complete: false,
            receipt: json!({"cleanup_complete":false}),
            owner: None,
        })
    };
    let mut report =
        json!({"cleanup_errors":[],"remaining_containers":null,"remaining_images":null});
    let mut calls = 0;
    let result = super::capture::cleanup(&mut report, "owned", |_| {
        calls += 1;
        Err(failure())
    });
    assert_eq!(calls, 1);
    assert!(report["remaining_containers"].is_null());
    assert!(report["remaining_images"].is_null());
    let result = retain(directory, result);
    assert!(result.as_ref().is_err_and(uncertain));
    assert!(path.is_dir());
    std::fs::remove_dir(&path)?;
    let publication = tempfile::tempdir()?;
    let receipt = publication.path().join("receipt.json");
    assert!(publish_result(&receipt, &mut report, result).is_err());
    assert_eq!(load(&receipt)?["failed_command"]["cleanup_complete"], false);
    Ok(())
}
#[test]
fn cancellation_after_settled_cleanup_rejects_successful_publication() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("receipt.json");
    let cancellation = diorama_dev::process::Cancellation::default();
    let mut report =
        json!({"cleanup_errors":[],"remaining_containers":null,"remaining_images":null});
    let mut calls = 0;
    super::capture::cleanup(&mut report, "owned", |_| {
        calls += 1;
        if calls == 5 {
            cancellation.request();
        }
        Ok(String::new())
    })?;
    assert_eq!(calls, 5);
    assert!(publish_with_cancellation(&path, &mut report, Ok(()), &cancellation).is_err());
    assert_eq!(load(&path)?["cancelled"], true);
    assert_eq!(load(&path)?["remaining_containers"], json!([]));
    Ok(())
}
#[test]
fn equal_substitution_of_both_runtime_binaries_still_fails_builder_proof() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut receipt = synthetic_receipt(directory.path())?;
    for name in ["first", "repeat"] {
        let path = directory.path().join(format!("{name}.log"));
        std::fs::write(
            &path,
            synthetic_native().replace(&"a".repeat(64), &"f".repeat(64)),
        )?;
        let (records, binaries) = native::records(&path)?;
        receipt["runs"][name]["raw_sha256"] = digest(&path)?.into();
        receipt["runs"][name]["records"] = records;
        receipt["runs"][name]["binary_sha256"] = binaries;
        bind_synthetic_command(directory.path(), &mut receipt, name)?;
    }
    save(&directory.path().join("receipt.json"), &receipt)?;
    assert!(super::capture::verify(&root()?, "decode", directory.path()).is_err());
    Ok(())
}
#[test]
fn historical_receipts_cannot_be_relabelled_as_current_rust_captures() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let mut receipt = synthetic_receipt(directory.path())?;
    for version in [json!(1), json!(2), json!(true), json!("3")] {
        receipt["schema"] = version;
        save(&directory.path().join("receipt.json"), &receipt)?;
        assert!(super::capture::verify(&root()?, "decode", directory.path()).is_err());
    }
    Ok(())
}

#[test]
#[ignore = "receipt checks disabled"]
fn elf_records_reject_extra_tests_unknown_markers_and_typed_mutations() -> Result<()> {
    let evidence = root()?.join("tools/assets-elf/evidence");
    let artifacts = load(&evidence.join("receipt.json"))?["artifacts"].clone();
    let good = String::from_utf8(read(&evidence.join("run0.log"), 8 * 1024 * 1024)?)?;
    elf::records(good.as_bytes(), &artifacts)?;
    let mut matching_forgery = artifacts.clone();
    for artifact in matching_forgery
        .as_object_mut()
        .ok_or("artifact map")?
        .values_mut()
    {
        artifact["oracle"]["flags"] = json!(false);
    }
    assert!(
        elf::records(
            good.replace("\"flags\":0", "\"flags\":false").as_bytes(),
            &matching_forgery
        )
        .is_err()
    );

    for bad in [
        format!("{good}\ntest unexpected ... FAILED\n"),
        format!("{good}\nDIORAMA_UNKNOWN {{}}\n"),
        good.replace("\"flags\":0", "\"flags\":false"),
        good.replace("\"machine\":183", "\"machine\":62"),
        good.replace("four_locked_release_executables", "different_test"),
    ] {
        assert!(elf::records(bad.as_bytes(), &artifacts).is_err());
    }
    Ok(())
}

#[test]
fn selected_go_graph_rejects_replacement_missing_duplicate_and_changed_checksums() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let actual = directory.path().join("actual");
    let pinned = directory.path().join("pinned");
    let dependency = json!({"Path":"example.invalid/module","Version":"v1.2.3","Sum":"h1:abc","GoModSum":"h1:def"});
    save(&pinned, &json!([dependency]))?;
    let main = json!({"Path":"diorama.invalid/assets-archive-fixture","Main":true});
    std::fs::write(&actual, format!("{main}\n{dependency}\n"))?;
    archive::graph(&actual, &pinned)?;
    let mut replaced = dependency.clone();
    replaced["Replace"] = json!({"Path":"different"});
    let mut altered = dependency.clone();
    altered["GoModSum"] = json!("h1:wrong");
    for bad in [
        format!("{main}"),
        format!("{dependency}"),
        format!("{main}\n{main}\n{dependency}"),
        format!("{main}\n{dependency}\n{dependency}"),
        format!("{main}\n{replaced}"),
        format!("{main}\n{altered}"),
        format!("{}\n{dependency}", json!({"Path":"wrong","Main":true})),
    ] {
        std::fs::write(&actual, bad)?;
        assert!(archive::graph(&actual, &pinned).is_err());
    }
    Ok(())
}

#[test]
fn archive_runtime_records_require_exact_oracle_cases_and_completion() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("runtime.log");
    let positive = historic_archive_inputs()?;
    let inputs = archive::cases(&positive[0].1, &positive[1].1)?;
    let expected = archive::observations(&inputs)?;
    let mut good = format!(
        "{}  /producer\n{}  /archive-tests\n{}  /fixture\nDIORAMA_PRODUCER go1.26.2 github.com/google/go-containerregistry v0.21.5 h1:KTJG9Pn/jC0VdZR6ctV3/jcN+q6/Iqlx0sTVz3ywZlM=\n",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64)
    );
    for (name, bytes) in inputs {
        writeln!(
            good,
            "DIORAMA_INPUT {}",
            json!({"case":name,"gzip_base64":b64(&bytes)})
        )?;
    }
    for name in archive::NAMES {
        writeln!(good, "DIORAMA_ARCHIVE {}", expected[name])?;
    }
    good.push_str("test inspect_pinned_crane_serialization ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n");
    writeln!(
        good,
        "DIORAMA_COMPLETE {}",
        json!({"cases":archive::NAMES,"consumer_command":["/archive-tests","--ignored","--exact","inspect_pinned_crane_serialization","--show-output","--test-threads=1"]})
    )?;
    good.push_str("DIORAMA_NAMESPACE {\"init\":1,\"shell\":7,\"helper\":8,\"processes\":[1,7,8]}\n");
    std::fs::write(&path, &good)?;
    archive::records(&path)?;
    for bad in [
        good.replace("DIORAMA_COMPLETE ", "DIORAMA_UNKNOWN {}\nDIORAMA_COMPLETE "),
        good.replace(
            "test inspect_pinned",
            "test extra ... FAILED\ntest inspect_pinned",
        ),
        good.replace("DIORAMA_ARCHIVE ", "DIORAMA_ARCHIVES "),
        good.replace("0 failed;", "1 failed;"),
        good.replace("\"helper\":8", "\"helper\":false"),
    ] {
        std::fs::write(&path, bad)?;
        assert!(archive::records(&path).is_err());
    }
    Ok(())
}

#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn published_elf_evidence_is_required() -> Result<()> {
    super::capture::verify(
        &root()?,
        "elf",
        &root()?.join("tools/assets-elf/rust-evidence"),
    )
}
#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn published_decode_evidence_is_required() -> Result<()> {
    super::capture::verify(
        &root()?,
        "decode",
        &root()?.join("tools/assets-decode/rust-evidence"),
    )
}
#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn published_archive_evidence_is_required() -> Result<()> {
    super::capture::verify(
        &root()?,
        "archive",
        &root()?.join("tools/assets-archive/rust-evidence"),
    )
}

#[test]
fn missing_source_precedes_output_creation_and_cache_rejects_bad_entries() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let missing = directory.path().join("missing-root");
    let output = directory.path().join("output");
    let cache = directory.path().join("cache");
    assert!(super::capture::docker(&missing, "decode", &output).is_err());
    assert!(!output.exists());
    assert!(elf::capture(&missing, &output, &cache).is_err());
    assert!(!output.exists());
    assert!(!cache.exists());
    let file = directory.path().join("asset");
    assert!(elf::cached(&file, &json!("0".repeat(64)))?.is_none());
    std::fs::write(&file, b"bad")?;
    assert!(elf::cached(&file, &json!("0".repeat(64))).is_err());
    assert_eq!(
        elf::cached(&file, &json!(sha256(b"bad")))?,
        Some(b"bad".to_vec())
    );
    std::fs::remove_file(&file)?;
    std::os::unix::fs::symlink("missing-target", &file)?;
    assert!(elf::cached(&file, &json!("0".repeat(64))).is_err());
    Ok(())
}

#[test]
fn producer_and_consumer_failures_emit_bounded_logs_without_masking_error() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let log = directory.path().join("output");
    std::fs::write(&log, b"producer diagnostic\n")?;
    let mut printed = Vec::new();
    let result = archive::emit_log(Err("original command failure".into()), &log, &mut printed);
    assert_eq!(
        result.expect_err("command fails").to_string(),
        "original command failure"
    );
    assert_eq!(printed, b"producer diagnostic\n");
    std::fs::write(&log, vec![b'x'; 65537])?;
    printed.clear();
    let result = archive::emit_log(Err("original command failure".into()), &log, &mut printed);
    assert_eq!(
        result
            .expect_err("oversize log preserves failure")
            .to_string(),
        "original command failure"
    );
    assert!(printed.is_empty());
    assert!(archive::emit_log(Ok(()), &log, &mut printed).is_err());
    std::fs::remove_file(&log)?;
    let result = archive::emit_log(Err("original command failure".into()), &log, &mut printed);
    assert_eq!(
        result
            .expect_err("missing log preserves failure")
            .to_string(),
        "original command failure"
    );
    Ok(())
}

#[test]
fn failed_daemon_cleanup_preserves_original_failure_and_unknown_resources() -> Result<()> {
    let mut report = json!({"errors":["original build failure"],"cleanup_errors":[],"remaining_containers":null,"remaining_images":null});
    let mut calls = Vec::new();
    let tag = format!("diorama-decode-{}", "1".repeat(32));
    super::capture::cleanup(&mut report, &tag, |args| {
        calls.push(
            args.iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>(),
        );
        Err("daemon unavailable".into())
    })?;
    assert_eq!(report["errors"], json!(["original build failure"]));
    assert_eq!(array(&report["cleanup_errors"])?.len(), 5);
    assert!(report["remaining_containers"].is_null());
    assert!(report["remaining_images"].is_null());
    assert_eq!(calls.len(), 5);
    assert_eq!(calls[0], ["rm", "-f", &format!("{tag}-first")]);
    assert_eq!(calls[1], ["rm", "-f", &format!("{tag}-repeat")]);
    assert_eq!(calls[2], ["rmi", "-f", &tag]);
    let directory = tempfile::tempdir()?;
    save(&directory.path().join("receipt.json"), &report)?;
    assert_eq!(load(&directory.path().join("receipt.json"))?, report);
    Ok(())
}

#[test]
fn publishing_current_receipts_does_not_change_the_source_file_inventory() -> Result<()> {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("harness.rs"), b"reviewed source")?;
    let before = super::common::files(directory.path())?;
    for name in ["evidence", "rust-evidence", "evidence-rust"] {
        std::fs::create_dir_all(directory.path().join(name).join("first"))?;
        std::fs::write(
            directory.path().join(name).join("first/receipt.json"),
            b"{}",
        )?;
    }
    assert_eq!(before, super::common::files(directory.path())?);
    assert_eq!(before, vec![directory.path().join("harness.rs")]);
    Ok(())
}
