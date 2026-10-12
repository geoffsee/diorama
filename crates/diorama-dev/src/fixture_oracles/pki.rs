//! Certificate policy and characterized restart behavior from the Go sources.
use serde_json::{Value, json};

use super::equal;
use crate::Result;

const NAMES: [&str; 10] = [
    "ca",
    "kubelet",
    "apiserver",
    "controller-manager",
    "admin",
    "webhook",
    "request-header-ca",
    "request-header-client",
    "d2k-server",
    "d2k-client",
];

fn certificate(name: &str, scenario: &str) -> Value {
    let (cn, organizations, is_ca) = match name {
        "ca" => ("kubernetes-ca", vec!["Kubernetes"], true),
        "kubelet" => ("system:node:fixture-node", vec!["system:nodes"], false),
        "apiserver" => ("kube-apiserver", vec!["Kubernetes"], false),
        "controller-manager" => (
            "system:kube-controller-manager",
            vec!["system:kube-controller-manager"],
            false,
        ),
        "admin" => ("kubesolo-admin", vec!["system:masters"], false),
        "webhook" => ("kubesolo-webhook", vec!["system:masters"], false),
        "request-header-ca" => ("request-header-ca", vec!["Kubernetes"], true),
        "request-header-client" => ("system:auth-proxy", vec!["system:auth-proxy"], false),
        "d2k-server" => ("d2k", vec!["kubesolo"], false),
        "d2k-client" => ("d2k-client", vec!["kubesolo"], false),
        _ => unreachable!("private constructor receives fixed names"),
    };
    let (dns, ips, usages) = match name {
        "ca" | "request-header-ca" => (Value::Null, json!([]), Value::Null),
        "admin" => (json!(["localhost"]), json!(["127.0.0.1"]), json!([2, 1])),
        "kubelet" => (
            json!(["fixture-node", "localhost"]),
            json!(["127.0.0.1"]),
            json!([2, 1]),
        ),
        "controller-manager" | "request-header-client" | "d2k-client" => {
            (Value::Null, json!([]), json!([2]))
        },
        "webhook" => (
            json!([
                "localhost",
                "kubesolo-webhook",
                "kubesolo-webhook.default",
                "kubesolo-webhook.default.svc"
            ]),
            json!(["127.0.0.1"]),
            json!([1]),
        ),
        "d2k-server" => (
            json!([
                "d2k",
                "d2k.fixture-d2k",
                "d2k.fixture-d2k.svc",
                "d2k.fixture-d2k.svc.cluster.local",
                "localhost"
            ]),
            json!(["127.0.0.1", "127.0.0.1"]),
            json!([1]),
        ),
        "apiserver" => {
            let mut dns = vec![
                "kubernetes",
                "kubernetes.default",
                "kubernetes.default.svc",
                "kubernetes.default.svc.cluster",
                "kubernetes.default.svc.cluster.local",
                "localhost",
                "api.fixture.test",
            ];
            if !["fresh", "node-ip-change"].contains(&scenario) {
                dns.push("new.fixture.test");
            }
            (
                json!(dns),
                json!([
                    "10.43.0.1",
                    "127.0.0.1",
                    if scenario == "fresh" {
                        "192.0.2.10"
                    } else {
                        "192.0.2.11"
                    },
                    "192.0.2.20"
                ]),
                json!([1, 2]),
            )
        },
        _ => unreachable!("private constructor receives fixed names"),
    };
    json!({"cn":cn,"organizations":organizations,"is_ca":is_ca,
        "valid_days":if is_ca {3650} else {365},"dns":dns,"ips":ips,
        "extended_key_usage":usages,"key_usage":if is_ca {97} else {5},
        "key_bits":2048,"key_mode":"0600","chain_verified":true,"key_matches":true,
        "serial_positive":true,"serial_bits_at_most_128":true})
}

fn certificates(scenario: &str) -> Value {
    Value::Object(
        NAMES
            .into_iter()
            .map(|name| (name.into(), certificate(name, scenario)))
            .collect(),
    )
}

pub fn expected() -> Value {
    let stable = Value::Object(
        NAMES
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    json!(["ca", "request-header-ca", "request-header-client"].contains(&name)),
                )
            })
            .collect(),
    );
    let rotations = Value::Object(
        [
            "node-ip-change",
            "extra-san-change",
            "corrupt-leaf",
            "expired-leaf",
        ]
        .into_iter()
        .map(|scenario| {
            (
                scenario.into(),
                json!({"certificates":certificates(scenario),"stable_certificates":stable}),
            )
        })
        .collect(),
    );
    json!([{"restart_unchanged":true,"invalid_extra_sans_ignored":true,
        "ipv6_extra_san_rotates":false,"existing_corrupt_key_is_skipped":true,
        "existing_mismatched_key_is_skipped":true,
        "unsafe_roots_rejected":{"":true,"/":true,".":true,"symlink":true},
        "fresh":certificates("fresh"),"rotations":rotations}])
}

pub fn verify(records: &Value) -> Result<()> {
    equal(records, &expected())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn historical_crypto_metadata_matches_source_policy_and_contains_no_private_keys() -> Result<()>
    {
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures/pki");
        verify(&super::super::load(&directory.join("expected.json"))?)?;
        let record = super::super::record(&directory.join("evidence/pki.log"))?;
        verify(&json!([record]))?;
        for name in ["expected.json", "evidence/pki.log"] {
            let bytes = crate::read_bounded(&directory.join(name), super::super::LIMIT)?;
            assert!(!String::from_utf8(bytes)?.contains("PRIVATE KEY-----"));
        }
        Ok(())
    }
    #[test]
    fn rejects_crypto_policy_trust_rotation_type_and_inventory_changes() {
        assert!(verify(&json!([])).is_err());
        for (pointer, replacement) in [
            ("/0/ipv6_extra_san_rotates", json!(true)),
            ("/0/fresh/ca/is_ca", json!(1)),
            ("/0/fresh/ca/key_usage", json!(true)),
            ("/0/fresh/ca/key_mode", json!("0644")),
            (
                "/0/rotations/node-ip-change/stable_certificates/ca",
                json!(false),
            ),
            ("/0/fresh/admin/key_matches", json!(false)),
            ("/0/fresh/admin/extended_key_usage", json!([1])),
            ("/0/fresh/apiserver/dns", json!(["localhost"])),
            ("/0/fresh/kubelet/dns", json!(["localhost"])),
            ("/0/fresh/ca/chain_verified", json!(false)),
            ("/0/fresh/ca/serial_positive", json!(false)),
            ("/0/fresh/ca/serial_bits_at_most_128", json!(false)),
            ("/0/fresh/ca/key_bits", json!(1024)),
            ("/0/fresh", json!({})),
        ] {
            let mut records = expected();
            *records.pointer_mut(pointer).expect("fixed oracle path") = replacement;
            assert!(verify(&records).is_err(), "accepted {pointer}");
        }
    }
}
