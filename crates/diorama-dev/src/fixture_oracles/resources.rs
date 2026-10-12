//! Independent invariants for distribution-created Kubernetes resources.
use super::equal;
use crate::{Result, json};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub fn expected(component: &str) -> Result<Value> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures");
    let provenance = super::load(&root.join("resources/provenance.json"))?;
    let path = "resources/expected.json";
    let bytes = crate::read_bounded(&root.join(path), super::LIMIT)?;
    equal(
        &json!(crate::sha256(&bytes)),
        &provenance["durable_sha256"][path],
    )?;
    let records = crate::json::parse(&bytes)?;
    verify(&records)?;
    let selected = array(&records)?
        .iter()
        .filter(|record| record["component"] == component)
        .cloned()
        .collect::<Vec<_>>();
    require(!selected.is_empty(), "unknown resource component")?;
    Ok(json!(selected))
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
fn array(value: &Value) -> Result<&[Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| "resource array missing".into())
}
fn optional_array(value: &Value) -> Result<&[Value]> {
    if value.is_null() {
        Ok(&[])
    } else {
        array(value)
    }
}
fn string(value: &Value) -> Result<&str> {
    value
        .as_str()
        .ok_or_else(|| "resource string missing".into())
}
fn selector_matches(selector: &Value, labels: &Value) -> Result<()> {
    let selector = selector.as_object().ok_or("selector missing")?;
    require(
        !selector.is_empty()
            && selector
                .iter()
                .all(|(key, value)| labels.get(key) == Some(value)),
        "selector does not match pod labels",
    )
}

pub fn verify(records: &Value) -> Result<()> {
    let records = array(records)?;
    let expected = [
        ("coredns", "host-dual"),
        ("coredns", "container-dual"),
        ("coredns", "host-ipv4"),
        ("coredns", "container-ipv4"),
        ("localpath", "local"),
        ("localpath", "shared"),
        ("portainer", "sync"),
        ("portainer", "async"),
        ("d2k", "custom-namespace"),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let actual = records
        .iter()
        .map(|record| Ok((string(&record["component"])?, string(&record["variant"])?)))
        .collect::<Result<BTreeSet<_>>>()?;
    require(
        records.len() == 9 && actual == expected,
        "resource variant inventory differs",
    )?;
    for record in records {
        verify_record(record)?;
    }
    Ok(())
}
fn verify_record(record: &Value) -> Result<()> {
    let component = string(&record["component"])?;
    let variant = string(&record["variant"])?;
    let mut checks = json!({"repeat_success":true,"injected_error_propagated":true});
    match component {
        "portainer" => {
            checks["bootstrap_existing_config_preserved"] = json!(true);
            checks["bootstrap_existing_secret_preserved"] = json!(true);
        },
        "d2k" => {
            checks["missing_tls_input_rejected"] = json!(true);
            checks["tls_secret_updated"] = json!(true);
        },
        _ => {},
    }
    equal(&record["checks"], &checks)?;
    let objects = &record["objects"];
    let deployments = array(&objects["deployments"])?;
    require(deployments.len() == 1, "one deployment required")?;
    let deployment = &deployments[0];
    let spec = &deployment["spec"];
    equal(&spec["replicas"], &json!(1))?;
    let pod = &spec["template"]["spec"];
    let labels = &spec["template"]["metadata"]["labels"];
    selector_matches(&spec["selector"]["matchLabels"], labels)?;
    let accounts = array(&objects["serviceaccounts"])?;
    require(
        accounts.iter().any(|account| {
            account["metadata"]["name"] == pod["serviceAccountName"]
                && pod["serviceAccountName"].is_string()
        }),
        "deployment service account missing",
    )?;
    for service in optional_array(&objects["services"])? {
        for port in array(&service["spec"]["ports"])? {
            require(
                port["port"]
                    .as_u64()
                    .is_some_and(|port| (1..=65535).contains(&port)),
                "invalid service port",
            )?;
        }
        selector_matches(&service["spec"]["selector"], labels)?;
    }
    verify_bindings(objects, accounts)?;
    let container = &pod["containers"][0];
    match component {
        "coredns" => verify_coredns(objects, container, variant),
        "localpath" => verify_localpath(objects, container, variant),
        "portainer" => verify_portainer(objects, container, variant),
        "d2k" => verify_d2k(objects, container, deployment, pod),
        _ => Err("unknown resource component".into()),
    }
}

fn verify_bindings(objects: &Value, accounts: &[Value]) -> Result<()> {
    for key in ["rolebindings", "clusterrolebindings"] {
        for binding in optional_array(&objects[key])? {
            for subject in array(&binding["subjects"])? {
                if subject["kind"] != "ServiceAccount" {
                    continue;
                }
                require(
                    accounts.iter().any(|account| {
                        account["metadata"]["name"] == subject["name"]
                            && account["metadata"]["namespace"] == subject["namespace"]
                    }),
                    "binding service account missing",
                )?;
            }
        }
    }
    Ok(())
}

fn verify_coredns(objects: &Value, container: &Value, variant: &str) -> Result<()> {
    equal(
        &container["image"],
        &json!("docker.io/coredns/coredns:1.14.4"),
    )?;
    let service = &objects["services"][0]["spec"];
    equal(&service["clusterIP"], &json!("10.43.0.10"))?;
    let ports = array(&service["ports"])?;
    require(
        ports.len() == 2
            && ports.iter().all(|port| port["port"] == 53)
            && ports
                .iter()
                .map(|port| string(&port["protocol"]))
                .collect::<Result<BTreeSet<_>>>()?
                == ["TCP", "UDP"].into_iter().collect(),
        "DNS ports differ",
    )?;
    let corefile = string(&objects["configmaps"][0]["data"]["Corefile"])?;
    require(
        corefile.contains("kubernetes cluster.local")
            && corefile.contains("ip6.arpa") == variant.ends_with("dual")
            && corefile.contains("/etc/resolv.conf") == variant.starts_with("host"),
        "Corefile policy differs",
    )?;
    if variant.starts_with("container") {
        require(
            corefile.contains("1.1.1.1 8.8.8.8"),
            "container DNS forwarders differ",
        )?;
        let limits = &container["resources"]["limits"];
        require(
            limits.is_null() || limits.as_object().is_some_and(serde_json::Map::is_empty),
            "container DNS limits present",
        )?;
    } else {
        equal(&container["resources"]["limits"]["memory"], &json!("64Mi"))?;
    }
    Ok(())
}

fn verify_localpath(objects: &Value, container: &Value, variant: &str) -> Result<()> {
    equal(
        &container["image"],
        &json!("docker.io/rancher/local-path-provisioner:v0.0.36"),
    )?;
    let storage = &objects["storageclasses"][0];
    for (key, expected) in [
        ("provisioner", "rancher.io/local-path"),
        ("reclaimPolicy", "Retain"),
        ("volumeBindingMode", "WaitForFirstConsumer"),
    ] {
        equal(&storage[key], &json!(expected))?;
    }
    equal(
        &storage["metadata"]["annotations"]["storageclass.kubernetes.io/is-default-class"],
        &json!("true"),
    )?;
    let data = &objects["configmaps"][0]["data"];
    let config = json::parse(string(&data["config.json"])?.as_bytes())?;
    equal(
        &config,
        &if variant == "shared" {
            json!({"sharedFileSystemPath":"/fixture/shared"})
        } else {
            json!({"nodePathMap":[{"node":"DEFAULT_PATH_FOR_NON_LISTED_NODES","paths":["/fixture/storage"]}]})
        },
    )?;
    require(
        string(&data["helperPod.yaml"])?.contains("image: busybox"),
        "helper image differs",
    )?;
    Ok(())
}

fn verify_portainer(objects: &Value, container: &Value, variant: &str) -> Result<()> {
    equal(&container["image"], &json!("portainer/agent:fixture"))?;
    let data = &objects["configmaps"][0]["data"];
    for (key, expected) in [
        (
            "EDGE_ASYNC",
            if variant == "async" { "true" } else { "false" },
        ),
        ("EDGE_ID", "fixture-id"),
        ("EDGE_SECRET", "fixture-secret"),
    ] {
        equal(&data[key], &json!(expected))?;
    }
    equal(
        &objects["secrets"][0]["stringData"]["edge.key"],
        &json!("fixture-key"),
    )?;
    equal(&objects["services"][0]["spec"]["clusterIP"], &json!("None"))?;
    Ok(())
}

fn verify_d2k(objects: &Value, container: &Value, deployment: &Value, pod: &Value) -> Result<()> {
    equal(&deployment["metadata"]["namespace"], &json!("fixture-d2k"))?;
    equal(&container["image"], &json!("fixture/d2k:fixed"))?;
    equal(
        &objects["services"][0]["spec"]["ports"][0]["port"],
        &json!(2376),
    )?;
    let env = array(&container["env"])?;
    for (name, pointer, expected) in [
        (
            "D2K_NAMESPACE",
            "/valueFrom/fieldRef/fieldPath",
            "metadata.namespace",
        ),
        ("D2K_PORT", "/value", "2376"),
        ("D2K_SWARM_MODE", "/value", "true"),
    ] {
        let matching = env
            .iter()
            .filter(|entry| entry["name"] == name)
            .collect::<Vec<_>>();
        require(matching.len() == 1, "environment entry inventory differs")?;
        equal(
            matching[0]
                .pointer(pointer)
                .ok_or("environment value missing")?,
            &json!(expected),
        )?;
    }
    equal(
        &pod["volumes"][0]["secret"]["secretName"],
        &json!("d2k-tls"),
    )?;
    equal(&objects["secrets"][0]["type"], &json!("kubernetes.io/tls"))?;
    require(
        objects["secrets"][0]["data"]
            .as_object()
            .ok_or("TLS secret data missing")?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == ["tls.crt", "tls.key"].into_iter().collect(),
        "TLS secret keys differ",
    )?;
    equal(&container["volumeMounts"][0]["readOnly"], &json!(true))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn historical() -> Result<Value> {
        super::super::load(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../parity/fixtures/resources/expected.json"),
        )
    }
    #[test]
    fn historical_objects_satisfy_independent_source_invariants() -> Result<()> {
        verify(&historical()?)
    }
    #[test]
    fn historical_raw_records_and_surviving_capture_inputs_retain_original_hashes() -> Result<()> {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures");
        let provenance = super::super::load(&directory.join("resources/provenance.json"))?;
        let mut records = Vec::new();
        for component in ["coredns", "localpath", "portainer", "d2k"] {
            let bytes = crate::read_bounded(
                &directory.join(format!("resources/evidence/{component}.log")),
                super::super::LIMIT,
            )?;
            for line in std::str::from_utf8(&bytes)?
                .lines()
                .filter_map(|line| line.strip_prefix("DIORAMA_CAPTURE "))
            {
                records.push(crate::json::parse(line.as_bytes())?);
            }
        }
        verify(&json!(records))?;
        equal(&json!(records), &historical()?)?;
        for path in [
            "pki/evidence/pki.log",
            "pki/expected.json",
            "pki/pki_capture_test.go",
            "resources/Capture.Dockerfile",
            "resources/capture-receipt.json",
            "resources/coredns_capture_test.go",
            "resources/d2k_capture_test.go",
            "resources/localpath_capture_test.go",
            "resources/portainer_capture_test.go",
            "resources/expected.json",
            "resources/evidence/coredns.log",
            "resources/evidence/d2k.log",
            "resources/evidence/localpath.log",
            "resources/evidence/portainer.log",
        ] {
            equal(
                &json!(crate::sha256(&crate::read_bounded(
                    &directory.join(path),
                    super::super::LIMIT
                )?)),
                &provenance["durable_sha256"][path],
            )?;
        }
        Ok(())
    }
    #[test]
    fn rejects_inventory_selectors_types_policy_and_bootstrap_changes() -> Result<()> {
        assert!(verify(&json!([])).is_err());
        let original = historical()?;
        for (component, pointer, replacement) in [
            ("coredns", "/variant", json!("unknown")),
            (
                "coredns",
                "/objects/deployments/0/spec/replicas",
                json!(true),
            ),
            (
                "coredns",
                "/objects/services/0/spec/selector",
                json!({"wrong":"label"}),
            ),
            (
                "coredns",
                "/objects/configmaps/0/data/Corefile",
                json!("invalid"),
            ),
            (
                "localpath",
                "/objects/storageclasses/0/reclaimPolicy",
                json!("Delete"),
            ),
            (
                "portainer",
                "/checks/bootstrap_existing_config_preserved",
                json!(false),
            ),
            (
                "d2k",
                "/objects/deployments/0/spec/template/spec/containers/0/volumeMounts/0/readOnly",
                json!(false),
            ),
        ] {
            let mut changed = original.clone();
            let record = changed
                .as_array_mut()
                .ok_or("records")?
                .iter_mut()
                .find(|record| record["component"] == component)
                .ok_or("component")?;
            *record.pointer_mut(pointer).ok_or("mutation path")? = replacement;
            assert!(verify(&changed).is_err(), "accepted {component} {pointer}");
        }
        Ok(())
    }
}
