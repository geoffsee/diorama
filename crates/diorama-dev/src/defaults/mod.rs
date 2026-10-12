//! Official constructor/defaulting oracles and explicit disposable captures.
use crate::{Result, json, read_bounded, sha256};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
pub mod archives;
pub mod capture;
pub(crate) mod evidence;
#[cfg(test)]
mod tests;
pub fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../defaults")
}
pub fn load(path: &Path) -> Result<Value> {
    json::parse(&read_bounded(path, 32 * 1024 * 1024)?)
}
pub fn require(condition: bool, message: &str) -> Result<()> {
    if !condition {
        return Err(message.into());
    }
    Ok(())
}
fn at<'a>(value: &'a Value, path: &str) -> Result<&'a Value> {
    value
        .pointer(path)
        .ok_or_else(|| format!("missing field: {path}").into())
}
fn anchor(value: &Value, path: &str, expected: &Value, label: &str) -> Result<()> {
    require(at(value, path)? == expected, label)
}
pub fn verify(value: &Value) -> Result<()> {
    verify_anchors_0(value)?;
    verify_anchors_1(value)?;
    verify_anchors_2(value)?;
    let cases = value["cases"]
        .as_object()
        .ok_or("missing cases")?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    require(
        cases == BTreeSet::from(["zero", "explicit"]),
        "case inventory",
    )?;
    let sidecar = at(value, "/registered_feature_gates/SidecarContainers/specs")?
        .as_array()
        .and_then(|v| v.last())
        .ok_or("missing sidecar history")?;
    require(
        sidecar
            == &value!({"default":true,"locked":true,"stage":"","version":"1.33","minimum_compatibility":""}),
        "sidecar GA history",
    )
}
pub fn verify_apiserver(value: &Value) -> Result<()> {
    verify(value)?;
    let options = &value["apiserver_options"];
    for (path, expected, label) in [
        (
            "/construction_only",
            value!(true),
            "unexpected lifecycle scope",
        ),
        (
            "/system_namespaces",
            value!(["kube-system", "kube-public", "default", "kube-node-lease"]),
            "system namespace defaults",
        ),
        (
            "/kubelet_preferred_address_types",
            value!([
                "Hostname",
                "InternalDNS",
                "InternalIP",
                "ExternalDNS",
                "ExternalIP"
            ]),
            "kubelet address preference",
        ),
        (
            "/service_node_port_range",
            value!("30000-32767"),
            "service port range",
        ),
    ] {
        anchor(options, path, &expected, label)?;
    }
    for (name, default) in [
        ("secure-port", "6443"),
        ("allow-privileged", "false"),
        ("kubelet-port", "10250"),
        ("kubelet-timeout", "5s"),
        ("service-node-port-range", "30000-32767"),
        ("event-ttl", "1h0m0s"),
        ("storage-media-type", "application/vnd.kubernetes.protobuf"),
        ("watch-cache", "true"),
        ("apiserver-count", "1"),
        ("advertise-address", "<nil>"),
        ("external-hostname", ""),
        ("anonymous-auth", "true"),
        ("authorization-mode", "[]"),
    ] {
        require(
            options["flags"][name]["default"] == default,
            &format!("API-server default {name}"),
        )?;
    }
    Ok(())
}
pub fn load_expected(path: &Path, apiserver: bool) -> Result<Value> {
    let raw = read_bounded(path, 32 * 1024 * 1024)?;
    let expected = json::parse(&raw)?;
    if apiserver {
        verify_apiserver(&expected)?;
    } else {
        verify(&expected)?;
    }
    let provenance = load(&directory().join("provenance.json"))?;
    let key = if apiserver {
        "apiserver_expected_sha256"
    } else {
        "expected_sha256"
    };
    require(
        provenance[key] == sha256(&raw),
        "expected fixture provenance mismatch",
    )?;
    Ok(expected)
}
/// Preserve the historical defaults diff format: arrays of different lengths form one change.
pub fn differences(before: &Value, after: &Value) -> Vec<Value> {
    fn walk(a: &Value, b: &Value, path: &str, out: &mut Vec<Value>) {
        match (a, b) {
            (Value::Object(a), Value::Object(b)) => {
                for key in a.keys().chain(b.keys()).collect::<BTreeSet<_>>() {
                    let next = format!("{path}/{key}");
                    match (a.get(key), b.get(key)) {
                        (Some(a), Some(b)) => walk(a, b, &next, out),
                        (Some(a), None) => out.push(value!({"path":next,"removed":a})),
                        (None, Some(b)) => out.push(value!({"path":next,"added":b})),
                        _ => {},
                    }
                }
            },
            (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
                for (i, (a, b)) in a.iter().zip(b).enumerate() {
                    walk(a, b, &format!("{path}/{i}"), out);
                }
            },
            _ => {
                if a != b {
                    out.push(value!({"path":path,"before":a,"after":b}));
                }
            },
        }
    }
    let mut result = Vec::new();
    walk(before, after, "", &mut result);
    result
}
pub fn verify_cli(args: &[String]) -> Result<i32> {
    let path = args.first().ok_or("expected capture path")?;
    let alternate = match &args[1..] {
        [] => None,
        [option, path] if option == "--expected" => Some(PathBuf::from(path)),
        _ => return Err("usage: diorama-defaults verify CAPTURE [--expected PATH]".into()),
    };
    let actual = load(Path::new(path))?;
    let api = actual.get("apiserver_options").is_some();
    if api {
        verify_apiserver(&actual)?;
    } else {
        verify(&actual)?;
    }
    let expected = load_expected(
        &alternate.unwrap_or_else(|| {
            directory().join(if api {
                "apiserver.expected.json"
            } else {
                "expected.json"
            })
        }),
        api,
    )?;
    let changes = differences(&expected, &actual);
    println!(
        "{}",
        serde_json::to_string_pretty(
            &value!({"status":if changes.is_empty(){"unchanged"}else{"drift"},"changes":changes})
        )?
    );
    Ok(i32::from(!changes.is_empty()))
}
fn verify_anchors_0(value: &Value) -> Result<()> {
    for (path, expected, label) in [
        (
            "/source_revision",
            value!("96cb9ab4201d88ce5e549fde047a686171838fdb"),
            "source revision",
        ),
        ("/go_version", value!("go1.26.8"), "toolchain"),
        ("/platform", value!("linux/arm64"), "unqualified platform"),
        ("/emulation_version", value!("1.35"), "gate versions"),
        (
            "/minimum_compatibility_version",
            value!("1.34"),
            "gate versions",
        ),
        ("/feature_overrides", value!({}), "unexpected overrides"),
        (
            "/cases/zero/kubelet/enableServer",
            value!(true),
            "kubelet server default",
        ),
        (
            "/cases/zero/kubelet/port",
            value!(10250),
            "kubelet server default",
        ),
        (
            "/cases/zero/kubelet/authentication/anonymous/enabled",
            value!(false),
            "anonymous authentication default",
        ),
        (
            "/cases/zero/kubelet/authorization/mode",
            value!("Webhook"),
            "authorization default",
        ),
        (
            "/cases/zero/kubelet/healthzPort",
            value!(10248),
            "health defaults",
        ),
        (
            "/cases/zero/kubelet/healthzBindAddress",
            value!("127.0.0.1"),
            "health defaults",
        ),
        (
            "/cases/zero/proxy/bindAddress",
            value!("0.0.0.0"),
            "proxy bind default",
        ),
        (
            "/cases/zero/proxy/clientConnection/qps",
            value!(5),
            "proxy client limits",
        ),
    ] {
        anchor(value, path, &expected, label)?;
    }
    Ok(())
}
fn verify_anchors_1(value: &Value) -> Result<()> {
    for (path, expected, label) in [
        (
            "/cases/zero/proxy/clientConnection/burst",
            value!(10),
            "proxy client limits",
        ),
        (
            "/cases/zero/proxy/iptables/syncPeriod",
            value!("30s"),
            "iptables sync default",
        ),
        (
            "/cases/zero/controller/Generic/ClientConnection/qps",
            value!(20),
            "controller client limits",
        ),
        (
            "/cases/zero/controller/Generic/ClientConnection/burst",
            value!(30),
            "controller client limits",
        ),
        (
            "/cases/explicit/kubelet/enableServer",
            value!(false),
            "explicit false lost",
        ),
        (
            "/cases/explicit/kubelet/port",
            value!(10260),
            "explicit ports lost",
        ),
        (
            "/cases/explicit/kubelet/readOnlyPort",
            value!(1234),
            "explicit ports lost",
        ),
        (
            "/cases/explicit/proxy/bindAddress",
            value!("192.0.2.9"),
            "explicit proxy values lost",
        ),
        (
            "/cases/explicit/proxy/clientConnection/qps",
            value!(17),
            "explicit proxy values lost",
        ),
        (
            "/cases/explicit/controller/Generic/ClientConnection/qps",
            value!(19),
            "explicit controller QPS lost",
        ),
        (
            "/cases/zero/controller/KubeCloudShared/NodeMonitorPeriod",
            value!("5s"),
            "nested cloud duration defaults",
        ),
        (
            "/cases/zero/controller/KubeCloudShared/RouteReconciliationPeriod",
            value!("10s"),
            "nested cloud duration defaults",
        ),
        (
            "/cases/zero/controller/KubeCloudShared/ClusterName",
            value!("kubernetes"),
            "nested cloud identity/routes defaults",
        ),
        (
            "/cases/zero/controller/KubeCloudShared/ConfigureCloudRoutes",
            value!(true),
            "nested cloud identity/routes defaults",
        ),
    ] {
        anchor(value, path, &expected, label)?;
    }
    Ok(())
}
fn verify_anchors_2(value: &Value) -> Result<()> {
    for (path, expected, label) in [
        (
            "/cases/explicit/controller/KubeCloudShared/ClusterName",
            value!("fixture-cluster"),
            "nested explicit cloud values lost",
        ),
        (
            "/cases/explicit/controller/KubeCloudShared/ConfigureCloudRoutes",
            value!(false),
            "nested explicit cloud values lost",
        ),
        (
            "/cases/explicit/controller/KubeCloudShared/NodeMonitorPeriod",
            value!("7s"),
            "nested explicit/default cloud durations",
        ),
        (
            "/cases/explicit/controller/KubeCloudShared/RouteReconciliationPeriod",
            value!("10s"),
            "nested explicit/default cloud durations",
        ),
        (
            "/cases/explicit/kubelet/reservedMemory",
            value!([{"numaNode":0,"limits":{"memory":"1001m"}}]),
            "generated ResourceList milli rounding skipped",
        ),
        (
            "/registered_feature_gates/RotateKubeletServerCertificate/enabled",
            value!(true),
            "rotation gate default",
        ),
        (
            "/registered_feature_gates/RotateKubeletServerCertificate/specs",
            value!([{"default":false,"locked":false,"stage":"ALPHA","version":"1.7","minimum_compatibility":""},{"default":true,"locked":false,"stage":"BETA","version":"1.12","minimum_compatibility":""}]),
            "rotation gate history",
        ),
        (
            "/registered_feature_gates/SidecarContainers/enabled",
            value!(true),
            "sidecar enabled default",
        ),
    ] {
        anchor(value, path, &expected, label)?;
    }
    Ok(())
}
