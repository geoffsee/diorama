use super::*;
use serde_json::json;

fn fixture_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures")
}

#[test]
#[ignore = "receipt checks disabled"]
fn retained_public_records_match_source_specified_oracles() -> Result<()> {
    // This checks historical public behavior only, not current capture provenance.
    let root = fixture_root();
    for component in ["apiserver", "kubelet"] {
        verify_repeats(
            &root.join("credentials/evidence"),
            component,
            &credentials::expected(component)?,
        )?;
    }
    verify_repeats(
        &root.join("runtime-mapping/evidence"),
        "mapping",
        &mapping::expected(),
    )?;
    verify_repeats(
        &root.join("webhooks/evidence"),
        "webhook",
        &webhook::expected()?,
    )?;
    Ok(())
}

#[test]
fn credentials_reject_identity_trust_permissions_crypto_and_type_changes() -> Result<()> {
    for (component, pointer, new) in [
        ("apiserver", "/checks/key_bits", json!(1024)),
        ("apiserver", "/checks/key_mode", json!("0644")),
        ("apiserver", "/checks/restart_preserves_key", json!(false)),
        ("apiserver", "/checks/key_valid", json!(1)),
        (
            "apiserver",
            "/synthetic_kubeconfig/current-context",
            json!("admin-token@kubesolo"),
        ),
        (
            "kubelet",
            "/path_kubeconfig/clusters/kubernetes/certificate-authority",
            json!("/wrong"),
        ),
        ("kubelet", "/checks/output_directory_fails", json!(false)),
    ] {
        let expected = credentials::expected(component)?;
        let mut changed = expected.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing mutation target")? = new;
        assert!(equal(&changed, &expected).is_err(), "{pointer}");
    }
    let expected = credentials::expected("apiserver")?;
    let mut changed = expected.clone();
    changed["checks"]
        .as_object_mut()
        .ok_or("checks")?
        .remove("missing_certificate_fails");
    assert!(equal(&changed, &expected).is_err());
    let mut changed = expected.clone();
    changed["synthetic_kubeconfig"]["users"]["admin-token"]["token"] = "secret".into();
    assert!(equal(&changed, &expected).is_err());
    assert!(credentials::expected("other").is_err());
    Ok(())
}

#[test]
fn mapping_rejects_paths_probes_hostnames_endpoints_and_missing_cases() -> Result<()> {
    let expected = mapping::expected();
    for (pointer, new) in [
        (
            "/0/embedded/KineSocketFile",
            json!("/var/lib/kubesolo/kine/kine.sock"),
        ),
        ("/0/embedded/KubeletCerts/CACert", json!("/wrong/ca")),
        ("/1/embedded/NodeName", json!("  Talos-CP-1  ")),
        ("/1/embedded/NodeIP", json!("198.51.100.1")),
        ("/1/embedded/MTU", json!(9000)),
        ("/1/embedded/ContainerMode", json!(false)),
        ("/1/embedded/IsPortainerEdge", json!(0)),
        ("/4/embedded/NodeName", json!("mixed-host")),
        ("/5/error", json!("empty hostname rejected")),
        ("/6/embedded/RuntimeExternal", json!(false)),
        ("/7/embedded/RuntimeSocketPath", json!("/run/runtime.sock")),
        ("/9/error", json!("")),
        ("/12/embedded/RuntimeEndpoint", json!("unix://")),
    ] {
        let mut changed = expected.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing mutation target")? = new;
        assert!(equal(&changed, &expected).is_err(), "{pointer}");
    }
    for kind in ["missing", "extra", "reordered", "missing-field"] {
        let mut changed = expected.clone();
        let array = changed.as_array_mut().ok_or("cases")?;
        match kind {
            "missing" => {
                array.pop();
            },
            "extra" => array.push(array[0].clone()),
            "reordered" => array.reverse(),
            _ => {
                array[0]["embedded"]
                    .as_object_mut()
                    .ok_or("embedded")?
                    .remove("RuntimeCgroupDriver");
            },
        }
        assert!(equal(&changed, &expected).is_err(), "{kind}");
    }
    Ok(())
}

#[test]
fn webhook_rejects_registration_patch_status_and_family_mutations() -> Result<()> {
    let expected = webhook::expected()?;
    for (pointer, new) in [
        ("/configurations/true/webhooks/0/sideEffects", json!("None")),
        (
            "/configurations/true/webhooks/0/failurePolicy",
            json!("Fail"),
        ),
        (
            "/configurations/true/webhooks/0/rules/0/operations",
            json!(["CREATE", "UPDATE"]),
        ),
        (
            "/configurations/true/webhooks/0/clientConfig/caBundle",
            json!("changed"),
        ),
        (
            "/handler_requests/pod_unassigned/admission_review/response/uid",
            json!("wrong"),
        ),
        (
            "/handler_requests/pod_unassigned/admission_review/response/allowed",
            json!(1),
        ),
        (
            "/fake_client_status/assign/actions/1/subresource",
            json!(""),
        ),
        ("/fake_client_status/patch_failure/patch_count", json!(1)),
    ] {
        let mut changed = expected.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing mutation target")? = new;
        assert!(equal(&changed, &expected).is_err(), "{pointer}");
    }
    for case in [
        "service_dry_run",
        "service_disabled",
        "service_no_address",
        "service_clusterip",
    ] {
        let mut changed = expected.clone();
        changed["handler_requests"][case]["scheduled_status_update"] = true.into();
        assert!(equal(&changed, &expected).is_err(), "{case}");
    }
    for (parent, key) in [
        ("", "fake_client_status"),
        ("/handler_requests", "malformed_typed_object"),
        ("/handler_requests", "pvc_existing_annotation"),
    ] {
        let mut changed = expected.clone();
        changed
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .ok_or("mutation target")?
            .remove(key);
        assert!(equal(&changed, &expected).is_err(), "{key}");
    }
    Ok(())
}

#[test]
fn records_reject_missing_duplicate_mutated_and_oversized_input() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("record");
    for raw in [
        "",
        "DIORAMA_CAPTURE {}\nDIORAMA_CAPTURE {}\n",
        "DIORAMA_CAPTURE {\"a\":1,\"a\":2}",
        "DIORAMA_CAPTURE {\"a\":NaN}",
        "DIORAMA_CAPTURE {\"a\":Infinity}",
        "DIORAMA_CAPTURE {\"a\":1e400}",
        "DIORAMA_CAPTURE {\"a\":-1e400}",
    ] {
        std::fs::write(&path, raw)?;
        assert!(record(&path).is_err(), "{raw}");
    }
    std::fs::write(&path, vec![b' '; usize::try_from(LIMIT)? + 1])?;
    assert!(record(&path).is_err());
    assert!(load(&path).is_err());
    let expected = credentials::expected("kubelet")?;
    std::fs::write(
        directory.path().join("kubelet.json"),
        serde_json::to_vec(&expected)?,
    )?;
    let line = format!("DIORAMA_CAPTURE {}\n", serde_json::to_string(&expected)?);
    for index in 0..2 {
        std::fs::write(directory.path().join(format!("kubelet-{index}.log")), &line)?;
    }
    verify_repeats(directory.path(), "kubelet", &expected)?;
    let mut changed = expected.clone();
    changed["checks"]["repeat_equal"] = 1.into();
    std::fs::write(
        directory.path().join("kubelet-1.log"),
        format!("DIORAMA_CAPTURE {changed}\n"),
    )?;
    assert!(verify_repeats(directory.path(), "kubelet", &expected).is_err());
    Ok(())
}
