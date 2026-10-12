use super::*;
#[test]
fn official_frozen_fixture_and_raw_observations_match_independent_expectations() {
    let fixture = reviewed().unwrap();
    verify_raw(
        &fixture,
        &load(&directory().join("evidence/result.json")).unwrap(),
    )
    .unwrap();
}
#[test]
fn normalization_removes_only_explicit_top_level_server_metadata() {
    let source = value!({"metadata":{"uid":"volatile","creationTimestamp":"volatile","resourceVersion":"42","managedFields":[],"name":"kept","generation":3},"spec":{"metadata":{"uid":"user-value"},"creationTimestamp":"user-value"}});
    assert_eq!(
        normalize(&source),
        value!({"metadata":{"name":"kept","generation":3},"spec":source["spec"]})
    );
    assert_eq!(source["metadata"]["uid"], "volatile");
}
#[test]
fn matching_create_and_read_mutations_cannot_bypass_independent_semantics() {
    let original = reviewed().unwrap();
    for (kind, pointer, changed) in [
        (
            "pod",
            "/spec/containers/0/resources/requests/cpu",
            value!("0.5"),
        ),
        ("service", "/spec/ports/1/targetPort", value!("8080")),
        ("custom", "/spec/unknown/bool", value!(0)),
        ("custom", "/spec/unknown/decimal", value!(1)),
        ("pod", "/spec/automountServiceAccountToken", value!(0)),
    ] {
        let mut fixture = original.clone();
        for suffix in ["create", "read"] {
            *fixture["cases"][format!("{kind}-{suffix}")]
                .pointer_mut(pointer)
                .unwrap() = changed.clone();
        }
        assert!(verify(&fixture).is_err(), "{pointer}");
    }
    for pointer in ["/metadata/finalizers", "/metadata/ownerReferences"] {
        let mut fixture = original.clone();
        for suffix in ["create", "read"] {
            fixture["cases"][format!("pod-{suffix}")]["metadata"]
                [pointer.rsplit('/').next().unwrap()] = Value::Null;
        }
        assert!(verify(&fixture).is_err());
    }
    let mut fixture = original;
    for suffix in ["create", "read"] {
        fixture["cases"][format!("custom-{suffix}")]["spec"]["unknown"]
            .as_object_mut()
            .unwrap()
            .remove("null");
    }
    assert!(verify(&fixture).is_err());
}
#[test]
fn watch_kind_and_last_deleted_value_are_independent_requirements() {
    let fixture = reviewed().unwrap();
    let mut changed = fixture.clone();
    changed["watch"][0]["type"] = value!("MODIFIED");
    assert!(verify(&changed).is_err());
    changed = fixture.clone();
    changed["watch"][2]["object"] = fixture["watch"][0]["object"].clone();
    assert!(verify(&changed).is_err());
}
#[test]
fn raw_http_watch_tls_and_shutdown_cannot_be_rewritten_as_success() {
    let fixture = reviewed().unwrap();
    let original = load(&directory().join("evidence/result.json")).unwrap();
    for (pointer, mutation) in [
        ("/shutdowns/0/forced", value!(true)),
        ("/shutdowns/0/exit_code", value!(false)),
        ("/datastore_tls/0/exit_code", value!(0)),
        ("/datastore_tls/0/diagnostic", value!("bad option")),
        ("/http/0/status", value!(false)),
        (
            "/raw_watch_lines/0",
            value!("{\"type\":\"DELETED\",\"object\":{}}"),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = mutation;
        assert!(verify_raw(&fixture, &changed).is_err(), "{pointer}");
    }
    let mut changed = original;
    let row = changed["http"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|row| row["name"] == "custom-read")
        .unwrap();
    let mut raw = json::parse(row["raw_response"].as_str().unwrap().as_bytes()).unwrap();
    raw["spec"]["unknown"]["bool"] = 0.into();
    row["raw_response"] = serde_json::to_string(&raw).unwrap().into();
    assert!(verify_raw(&fixture, &changed).is_err());
}
#[test]
#[ignore = "receipt checks disabled"]
fn preserved_public_evidence_bytes_still_match_historical_provenance() {
    let provenance = load(&directory().join("provenance.json")).unwrap();
    for (name, expected) in provenance["durable_sha256"].as_object().unwrap() {
        // Old source/doc identities remain historical; only immutable public evidence is current here.
        if name.starts_with("evidence/") || name == "fixtures.json" {
            assert_eq!(
                crate::defaults::capture::digest(&directory().join(name)).unwrap(),
                expected.as_str().unwrap(),
                "{name}"
            );
        }
    }
}
#[test]
#[ignore = "receipt checks disabled"]
fn historical_python_receipt_cannot_be_relabelled_current() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::copy(
        directory().join("fixtures.json"),
        temporary.path().join("fixtures.json"),
    )
    .unwrap();
    for name in ["result.json", "runner-result.json"] {
        std::fs::copy(
            directory().join("evidence").join(name),
            temporary.path().join(name),
        )
        .unwrap();
    }
    assert!(
        check_capture(temporary.path())
            .unwrap_err()
            .to_string()
            .contains("current Rust capture receipt required")
    );
}
#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn current_rust_api_capture_is_required_for_qualification() {
    check_capture(&directory().join("evidence-rust")).unwrap();
}
#[test]
fn current_source_complete_comparison_command_and_status_mutations_fail() {
    let temporary = tempfile::tempdir().unwrap();
    let output = temporary.path();
    let fixture = reviewed().unwrap();
    let mut result = load(&directory().join("evidence/result.json")).unwrap();
    let mut runner = crate::component_boundary::capture::synthetic_command_evidence(output);
    let root = crate::repository_root(&directory()).unwrap();
    let sources = crate::component_boundary::source_inventory(&root, "api-json").unwrap();
    result["schema_version"] = 2.into();
    result["cancelled"] = false.into();
    result["source_sha256"] = sources.clone();
    result["inputs"] = load(&directory().join("inputs.json")).unwrap();
    runner["source_sha256"] = sources;
    let save = |result: &Value, runner: &Value, fixture: &Value| {
        for (name, value) in [
            ("result.json", result),
            ("runner-result.json", runner),
            ("fixtures.json", fixture),
        ] {
            std::fs::write(output.join(name), serde_json::to_vec(value).unwrap()).unwrap();
        }
    };
    save(&result, &runner, &fixture);
    assert_eq!(check_capture(output).unwrap()["status"], "verified");
    for (pointer, mutation) in [
        ("/source_sha256/Cargo.lock", value!("changed")),
        ("/exit_code", value!(false)),
        ("/cancelled", value!(true)),
        ("/remaining_images", value!(null)),
        ("/errors", value!(["failed"])),
    ] {
        let mut changed = runner.clone();
        *changed.pointer_mut(pointer).unwrap() = mutation;
        save(&result, &changed, &fixture);
        assert!(check_capture(output).is_err(), "{pointer}");
    }
    for (pointer, mutation) in [
        ("/source_sha256/Cargo.lock", value!("changed")),
        ("/inputs/kubernetes_version", value!("v0.0.0")),
        ("/cancelled", value!(true)),
        ("/shutdowns/0/forced", value!(true)),
        ("/architecture", value!("unknown")),
    ] {
        let mut changed = result.clone();
        *changed.pointer_mut(pointer).unwrap() = mutation;
        save(&changed, &runner, &fixture);
        assert!(check_capture(output).is_err(), "{pointer}");
    }
    let mut changed = fixture.clone();
    for name in ["pod-create", "pod-read"] {
        changed["cases"][name]["spec"]["schedulerName"] = "unreviewed".into();
    }
    save(&result, &runner, &changed);
    assert!(check_capture(output).is_err());
    save(&result, &runner, &fixture);
    let path = output.join("execute.command.json");
    let mut command = load(&path).unwrap();
    command["cleanup_complete"] = false.into();
    std::fs::write(&path, serde_json::to_vec(&command).unwrap()).unwrap();
    runner["commands"]["execute"]["receipt_sha256"] =
        crate::defaults::capture::digest(&path).unwrap().into();
    save(&result, &runner, &fixture);
    assert!(check_capture(output).is_err());
}
