use super::*;
use std::fs;
#[test]
fn frozen_defaults_and_apiserver_have_independent_semantics_and_hashes() {
    let base = load_expected(&directory().join("expected.json"), false).unwrap();
    let api = load_expected(&directory().join("apiserver.expected.json"), true).unwrap();
    assert_eq!(
        api["apiserver_options"]["flags"].as_object().unwrap().len(),
        172
    );
    assert_eq!(
        api["registered_feature_gates"],
        base["registered_feature_gates"]
    );
}
#[test]
fn selected_default_mutations_reject_generated_nested_false_and_gate_changes() {
    let original = load(&directory().join("expected.json")).unwrap();
    for (path, replacement) in [
        (
            "/cases/zero/kubelet/authentication/anonymous/enabled",
            value!(true),
        ),
        ("/cases/explicit/kubelet/enableServer", value!(true)),
        (
            "/cases/zero/controller/KubeCloudShared/NodeMonitorPeriod",
            value!("0s"),
        ),
        (
            "/cases/explicit/kubelet/reservedMemory/0/limits/memory",
            value!("1000100u"),
        ),
        (
            "/cases/explicit/controller/KubeCloudShared/ConfigureCloudRoutes",
            value!(true),
        ),
        (
            "/registered_feature_gates/RotateKubeletServerCertificate/enabled",
            value!(false),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = replacement;
        assert!(verify(&changed).is_err(), "{path}");
    }
}
#[test]
fn apiserver_secure_port_host_auth_and_removal_are_checked() {
    let original = load(&directory().join("apiserver.expected.json")).unwrap();
    for (name, changed) in [
        ("secure-port", "443"),
        ("advertise-address", "192.0.2.8"),
        ("anonymous-auth", "false"),
    ] {
        let mut value = original.clone();
        value["apiserver_options"]["flags"][name]["default"] = changed.into();
        assert!(verify_apiserver(&value).is_err());
    }
    let mut changed = original.clone();
    changed["apiserver_options"]["flags"]
        .as_object_mut()
        .unwrap()
        .remove("service-node-port-range");
    assert_eq!(
        differences(&original, &changed)[0]["path"],
        "/apiserver_options/flags/service-node-port-range"
    );
}
#[test]
fn altered_expected_paths_cannot_refresh_provenance() {
    let dir = tempfile::tempdir().unwrap();
    for (api, name) in [(false, "expected.json"), (true, "apiserver.expected.json")] {
        let mut value = load(&directory().join(name)).unwrap();
        if api {
            value["apiserver_options"]["flags"]["profiling"]["default"] = "false".into();
        } else {
            value["registered_feature_gates"]["unreviewed_probe"] = value!({"enabled":true});
        }
        let path = dir.path().join(name);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            load_expected(&path, api)
                .unwrap_err()
                .to_string()
                .contains("provenance mismatch")
        );
    }
    let mut value = load(&directory().join("expected.json")).unwrap();
    value["cases"]["zero"]["kubelet"]["authentication"]["anonymous"]["enabled"] = true.into();
    let path = dir.path().join("bad.json");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        load_expected(&path, false)
            .unwrap_err()
            .to_string()
            .contains("anonymous authentication")
    );
}
#[test]
fn gate_removal_and_boolean_integer_mutation_stay_visible() {
    let original = load(&directory().join("expected.json")).unwrap();
    let mut changed = original.clone();
    changed["registered_feature_gates"]
        .as_object_mut()
        .unwrap()
        .remove("SidecarContainers");
    let delta = differences(&original, &changed);
    assert_eq!(
        delta[0]["path"],
        "/registered_feature_gates/SidecarContainers"
    );
    assert!(delta[0].get("removed").is_some());
    let mut changed = original.clone();
    let entry = changed["registered_feature_gates"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    entry["specs"][0]["locked"] = i32::from(entry["specs"][0]["locked"].as_bool().unwrap()).into();
    let delta = differences(&original, &changed);
    assert_eq!(delta.len(), 1);
    assert!(
        delta[0]["path"]
            .as_str()
            .unwrap()
            .ends_with("/specs/0/locked")
    );
}
#[test]
fn malformed_duplicate_and_nonfinite_json_fail() {
    for raw in [
        b"{\"a\":0,\"a\":1}".as_slice(),
        b"{\"a\":NaN}",
        b"{\"a\":Infinity}",
    ] {
        assert!(json::parse(raw).is_err());
    }
}
#[test]
fn archive_pin_still_matches_accepted_go_toolchain() {
    let root = crate::repository_root(&directory()).unwrap();
    let accepted = load(&root.join("docs/architecture/upstream-inputs.json")).unwrap();
    let inputs = load(&directory().join("inputs.json")).unwrap();
    let pin = accepted["go_extraction_toolchain"]["archives"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["os"] == "linux" && a["arch"] == "arm64")
        .unwrap();
    assert_eq!(inputs["go"]["sha256"], pin["sha256"]);
    assert_eq!(inputs["go"]["bytes"], pin["size"]);
}
#[test]
fn corrupt_archives_fail_before_output_creation() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad");
    fs::write(&bad, b"bad").unwrap();
    let args = capture::CaptureArgs {
        source: bad.clone(),
        go: bad,
        output: dir.path().join("output"),
    };
    let inputs = load(&directory().join("inputs.json")).unwrap();
    assert!(capture::validate_archives(&inputs, &args).is_err());
    assert!(!args.output.exists());
}
#[test]
#[ignore = "receipt checks disabled"]
fn historical_receipt_is_not_relabelled_as_current_rust_capture() {
    assert!(
        capture::verify_evidence(&directory(), &directory().join("evidence"), false)
            .unwrap_err()
            .to_string()
            .contains("current Rust capture receipt required")
    );
}
#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn current_defaults_capture_sources_outputs_and_cleanup_are_bound() {
    capture::verify_evidence(&directory(), &directory().join("rust-evidence"), false).unwrap();
}
