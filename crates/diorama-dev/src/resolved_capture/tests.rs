use super::*;
use std::fs;
#[test]
#[ignore = "receipt checks disabled"]
fn frozen_completion_semantics_and_two_historical_records_match() {
    let expected = load(&directory().join("expected.json")).unwrap();
    verify(&expected).unwrap();
    verify_file(&directory().join("expected.json")).unwrap();
    for index in 0..2 {
        equal(
            &load(&directory().join(format!("evidence/run{index}.json"))).unwrap(),
            &expected,
        )
        .unwrap();
    }
}
#[test]
fn independent_resolution_mutations_fail() {
    let original = load(&directory().join("expected.json")).unwrap();
    for (name, key, new) in [
        ("default", "service_ip", value!("10.0.0.2")),
        ("dual_stack", "secondary_service_cidr", value!("fd00::/108")),
        ("default", "advertise_address", value!("0.0.0.0")),
        ("default", "anonymous_auth", value!(true)),
        ("dual_stack", "authorization_modes", value!(["AlwaysAllow"])),
        ("dual_stack", "events_history_window", value!("1m15s")),
        (
            "dual_stack",
            "runtime_config",
            value!({"api/v1":"true","apps/v1":"true"}),
        ),
        ("dual_stack", "watch_cache_sizes", value!(["pods#42"])),
        ("dual_stack", "token_max_expiration", value!("0s")),
        ("default", "listener_created", value!(true)),
        ("default", "generated_serving_certificate", value!(1)),
    ] {
        let mut changed = original.clone();
        changed["cases"][name][key] = new;
        assert!(verify(&changed).is_err(), "{name}/{key}");
    }
}
#[test]
fn errors_cannot_disappear_or_become_success() {
    let original = load(&directory().join("expected.json")).unwrap();
    for name in [
        "invalid_cidr",
        "small_cidr",
        "invalid_watch_cache",
        "invalid_token_expiration",
    ] {
        let mut changed = original.clone();
        changed["cases"][name] = value!({"error":""});
        assert!(verify(&changed).is_err());
        changed["cases"].as_object_mut().unwrap().remove(name);
        assert!(verify(&changed).is_err());
    }
}
#[test]
fn flags_before_after_and_exact_complete_comparison_are_required() {
    let original = load(&directory().join("expected.json")).unwrap();
    let mut changed = original.clone();
    changed["cases"]["default"]["flags_after"] =
        changed["cases"]["default"]["flags_before"].clone();
    assert!(verify(&changed).is_err());
    for (a, b) in [
        (value!({}), value!({"a":null})),
        (value!({"a":0}), value!({"a":false})),
        (value!({"a":[]}), value!({"a":{}})),
        (value!(1), value!(1.0)),
    ] {
        assert!(equal(&a, &b).is_err());
    }
    let mut changed = original.clone();
    changed["cases"]["default"]["flags_after"]["request-timeout"] = "61s".into();
    verify(&changed).unwrap();
    assert!(equal(&changed, &original).is_err());
}
#[test]
fn malformed_record_inventory_and_json_fail() {
    for raw in [
        b"".as_slice(),
        b"DIORAMA_RESOLVED={}\nDIORAMA_RESOLVED={}\n",
        b"DIORAMA_RESOLVED={\"a\":1,\"a\":2}\n",
        b"DIORAMA_RESOLVED={\"a\":NaN}\n",
    ] {
        assert!(capture::extract_record(raw).is_err());
    }
    assert_eq!(
        capture::extract_record(b"diagnostic\nDIORAMA_RESOLVED={\"a\":1}\n").unwrap(),
        "{\"a\":1}"
    );
}
#[test]
fn strict_capture_verifier_rejects_empty_numeric_boolean_and_unreviewed_flag() {
    let original = load(&directory().join("expected.json")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    for kind in ["empty", "numeric", "unreviewed"] {
        let mut changed = original.clone();
        match kind {
            "empty" => changed = value!({}),
            "numeric" => changed["controls"]["server_started"] = 0.into(),
            _ => changed["cases"]["default"]["flags_after"]["request-timeout"] = "61s".into(),
        }
        let path = dir.path().join("capture.json");
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(verify_file(&path).is_err());
    }
}
#[test]
#[ignore = "receipt checks disabled"]
fn historical_receipt_is_not_current_rust_qualification() {
    assert!(
        crate::defaults::capture::verify_evidence(
            &directory(),
            &directory().join("evidence"),
            true
        )
        .unwrap_err()
        .to_string()
        .contains("current Rust capture receipt required")
    );
}
#[test]
#[ignore = "source hash qualification receipt checks disabled"]
fn current_resolved_sources_output_and_cleanup_are_bound() {
    crate::defaults::capture::verify_evidence(
        &directory(),
        &directory().join("rust-evidence"),
        true,
    )
    .unwrap();
}
