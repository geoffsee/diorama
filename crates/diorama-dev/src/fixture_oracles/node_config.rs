//! Source-reviewed kubelet/containerd configuration plus frozen rendering identity.
use super::{equal, load};
use crate::Result;
use serde_json::{Value, json};
use std::path::Path;

fn kubelet(name: &str) -> Value {
    let mut config = json!({"kind":"KubeletConfiguration","apiVersion":"kubelet.config.k8s.io/v1beta1",
        "containerRuntimeEndpoint":"unix:///fixture/runtime.sock",
        "authentication":{"anonymous":{"enabled":false},"webhook":{"enabled":true,"cacheTTL":"5m0s"},"x509":{"clientCAFile":"/fixture/ca.crt"}},
        "authorization":{"mode":"Webhook","webhook":{"cacheAuthorizedTTL":"10m0s","cacheUnauthorizedTTL":"1m0s"}},
        "clusterDomain":"cluster.local","clusterDNS":["10.43.0.10"],
        "resolvConf":if name=="host_default"{"/etc/resolv.conf"}else{"/dev/null"},
        "tlsCertFile":"/fixture/node.crt","tlsPrivateKeyFile":"/fixture/node.key",
        "cgroupDriver":if name=="reported_systemd"{"systemd"}else{"cgroupfs"},
        "readOnlyPort":0,"rotateCertificates":true,"failSwapOn":false});
    if name != "host_default" {
        for (key, value) in [
            ("cgroupsPerQOS", json!(false)),
            ("enforceNodeAllocatable", json!([])),
            ("imageGCHighThresholdPercent", json!(100)),
            (
                "evictionHard",
                json!({"memory.available":"50Mi","nodefs.available":"0%","nodefs.inodesFree":"0%","imagefs.available":"0%"}),
            ),
            ("systemReserved", json!({})),
            ("kubeReserved", json!({})),
        ] {
            config[key] = value;
        }
    }
    if name == "container_static" {
        for (key, value) in [
            ("cpuManagerPolicy", json!("static")),
            ("reservedSystemCPUs", json!("0-1")),
            ("cpuManagerPolicyOptions", json!({"full-pcpus-only":"true"})),
            ("systemReserved", json!({"cpu":"200m","memory":"128Mi"})),
        ] {
            config[key] = value;
        }
    }
    config
}

fn containerd() -> Value {
    json!({"version":3,"root":"/tmp/diorama-runtime/root","state":"/fixture/state","imports":["/etc/containerd/config.d/*.toml"],
        "grpc":{"address":"/fixture/containerd.sock"},"plugins":{
            "io.containerd.cri.v1.images":{"image_pull_progress_timeout":"2m0s","pinned_images":{"sandbox":"docker.io/portainer/pause:latest"},"registry":{"config_path":"/fixture/registry"}},
            "io.containerd.cri.v1.runtime":{"containerd":{"default_runtime_name":"crun","runtimes":{"crun":{"runtime_type":"io.containerd.runc.v2","snapshotter":"overlayfs","options":{"BinaryName":"/fixture/crun","SystemdCgroup":false}}}},"cni":{"bin_dirs":["/fixture/cni/bin"],"conf_dir":"/etc/cni/net.d"}},
            "io.containerd.runtime.v2.task":{"platforms":["linux/amd64","linux/arm64","linux/arm"]}}})
}

fn keys(value: &Value, expected: &[&str]) -> Result<()> {
    let keys = value
        .as_object()
        .ok_or("expected object")?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if keys != expected.iter().copied().collect() {
        return Err("node configuration field inventory differs".into());
    }
    Ok(())
}

pub fn verify(value: &Value, component: &str) -> Result<()> {
    equal(&value["component"], &json!(component))?;
    match component {
        "kubelet" => {
            keys(
                value,
                &[
                    "component",
                    "synthetic_resolver",
                    "variants",
                    "checkpoint_states",
                    "checkpoint_negative_control",
                    "args",
                    "failures",
                ],
            )?;
            equal(&value["synthetic_resolver"], &json!(["192.0.2.53"]))?;
            let variants = [
                "host_default",
                "container_default",
                "container_static",
                "reported_systemd",
                "reported_cgroupfs",
            ];
            keys(&value["variants"], &variants)?;
            for name in variants {
                let variant = &value["variants"][name];
                keys(
                    variant,
                    &["config", "rendered_config", "yaml", "repeat_equal"],
                )?;
                equal(&variant["config"], &kubelet(name))?;
                equal(&variant["rendered_config"], &kubelet(name))?;
                equal(&variant["repeat_equal"], &json!(true))?;
                if variant["yaml"].as_str().is_none_or(str::is_empty) {
                    return Err("rendered YAML missing".into());
                }
            }
            equal(
                &value["checkpoint_states"],
                &json!({"same":"unchanged","policy":"absent","options":"absent","reserved":"absent","unrelated":"unchanged","malformed_previous":"absent"}),
            )?;
            equal(&value["checkpoint_negative_control"], &json!("changed"))?;
            let mut args = json!({});
            for ip in ["192.0.2.8", "2001:db8::8", "127.0.0.1", "bad"] {
                let mut values = vec![
                    "--config",
                    "/tmp/diorama-node/kubelet.yaml",
                    "--hostname-override",
                    "fixture-node",
                    "--root-dir",
                    "/tmp/diorama-node",
                    "--kubeconfig",
                    "/fixture/node.kubeconfig",
                ];
                if ["192.0.2.8", "2001:db8::8"].contains(&ip) {
                    values.extend(["--node-ip", ip]);
                }
                args[ip] = json!(values);
            }
            equal(&value["args"], &args)?;
            equal(
                &value["failures"],
                &json!({"output_directory":true,"parent_file":true}),
            )?;
        },
        "containerd" => {
            keys(
                value,
                &["component", "config", "rendered_config", "toml", "checks"],
            )?;
            equal(&value["config"], &containerd())?;
            equal(&value["rendered_config"], &containerd())?;
            equal(
                &value["checks"],
                &json!({"repeat_equal":true,"tmpfs_snapshotter":"overlayfs","missing_parent_snapshotter":"overlayfs","systemd_cgroup":false,"output_directory_fails":true,"missing_parent_fails":true}),
            )?;
            if value["toml"].as_str().is_none_or(str::is_empty) {
                return Err("rendered TOML missing".into());
            }
        },
        _ => return Err("unknown node configuration component".into()),
    }
    Ok(())
}

pub fn expected(component: &str) -> Result<Value> {
    if !["kubelet", "containerd"].contains(&component) {
        return Err("unknown node component".into());
    }
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures/node-config");
    let path = directory.join("expected").join(format!("{component}.json"));
    let bytes = crate::read_bounded(&path, super::LIMIT)?;
    let provenance = load(&directory.join("provenance.json"))?;
    keys(&provenance["expected_sha256"], &["kubelet", "containerd"])?;
    equal(
        &json!(crate::sha256(&bytes)),
        &provenance["expected_sha256"][component],
    )?;
    let frozen = crate::json::parse(&bytes)?;
    verify(&frozen, component)?;
    Ok(frozen)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "receipt checks disabled"]
    fn historical_records_match_independent_semantics_and_rendering() -> Result<()> {
        let directory =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures/node-config/evidence");
        for component in ["kubelet", "containerd"] {
            let expected = expected(component)?;
            super::super::verify_repeats(&directory, component, &expected)?;
        }
        Ok(())
    }
    #[test]
    fn trust_cgroup_checkpoint_types_and_inventory_mutations_fail() -> Result<()> {
        for (component, pointer, new) in [
            (
                "kubelet",
                "/variants/host_default/config/readOnlyPort",
                json!(10255),
            ),
            (
                "kubelet",
                "/variants/host_default/config/authentication/anonymous/enabled",
                json!(true),
            ),
            (
                "kubelet",
                "/variants/container_default/config/cgroupsPerQOS",
                json!(true),
            ),
            (
                "kubelet",
                "/variants/reported_systemd/config/cgroupDriver",
                json!("cgroupfs"),
            ),
            ("kubelet", "/checkpoint_states/policy", json!("unchanged")),
            ("kubelet", "/checkpoint_states/same", json!("changed")),
            ("kubelet", "/checkpoint_states/options", json!("unchanged")),
            (
                "kubelet",
                "/checkpoint_negative_control",
                json!("unchanged"),
            ),
            (
                "kubelet",
                "/args/127.0.0.1",
                json!(["--node-ip", "127.0.0.1"]),
            ),
            (
                "kubelet",
                "/variants/container_default/rendered_config/cgroupsPerQOS",
                json!(0),
            ),
            ("kubelet", "/variants/host_default/repeat_equal", json!(1)),
            ("containerd", "/config/version", json!(2)),
            ("containerd", "/checks/systemd_cgroup", json!(true)),
            ("containerd", "/checks/missing_parent_fails", json!(false)),
            (
                "containerd",
                "/config/plugins/io.containerd.cri.v1.runtime/containerd/runtimes/crun/runtime_type",
                json!("/fixture/shim"),
            ),
            ("containerd", "/toml", json!("")),
        ] {
            let mut changed = expected(component)?;
            *changed.pointer_mut(pointer).ok_or("mutation target")? = new;
            assert!(verify(&changed, component).is_err(), "{pointer}");
        }
        let mut changed = expected("kubelet")?;
        changed
            .as_object_mut()
            .ok_or("object")?
            .remove("checkpoint_negative_control");
        assert!(verify(&changed, "kubelet").is_err());
        let mut changed = expected("kubelet")?;
        changed["variants"]
            .as_object_mut()
            .ok_or("variants")?
            .remove("host_default");
        assert!(verify(&changed, "kubelet").is_err());
        let mut changed = expected("containerd")?;
        changed["config"]["plugins"]["io.containerd.cri.v1.runtime"]["containerd"]["runtimes"]["crun"]
            ["runtime_path"] = "/fixture/shim".into();
        assert!(verify(&changed, "containerd").is_err());
        Ok(())
    }
}
