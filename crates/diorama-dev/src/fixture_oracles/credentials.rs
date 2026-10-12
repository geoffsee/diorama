use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use crate::Result;

pub fn expected(component: &str) -> Result<Value> {
    let value = match component {
        "apiserver" => json!({
            "component": component,
            "synthetic_kubeconfig": {
                "clusters": {"kubesolo": {"server": "https://192.0.2.8:6443",
                    "certificate-authority-data": STANDARD.encode("SYNTHETIC-CA")}},
                "users": {"kubernetes-admin": {
                    "client-certificate-data": STANDARD.encode("SYNTHETIC-CERT"),
                    "client-key-data": STANDARD.encode("SYNTHETIC-KEY")}, "admin-token": {}},
                "contexts": {
                    "kubernetes-admin@kubesolo": {"cluster":"kubesolo", "user":"kubernetes-admin"},
                    "admin-token@kubesolo": {"cluster":"kubesolo", "user":"admin-token"}},
                "current-context":"kubernetes-admin@kubesolo"
            },
            "checks": {
                "key_valid":true, "restart_preserves_key":true,
                "existing_corrupt_key_accepted":true, "existing_corrupt_key_preserved":true,
                "missing_parent_fails":true, "missing_certificate_fails":true,
                "kubeconfig_repeat_equal":true, "kubeconfig_refreshes_certificate":true,
                "output_directory_fails":true, "unreadable_key_fails":true,
                "baseline_static_token_matches":true, "key_type":"RSA PRIVATE KEY",
                "key_bits":2048, "key_mode":"0600", "kubeconfig_mode":"0600"
            }
        }),
        "kubelet" => json!({
            "component":component,
            "path_kubeconfig": {
                "clusters":{"kubernetes":{"server":"https://192.0.2.8:6443",
                    "certificate-authority":"/fixture/ca.crt"}},
                "users":{"system:node:fixture-node":{"client-certificate":"/fixture/node.crt",
                    "client-key":"/fixture/node.key"}},
                "contexts":{"system:node:fixture-node@kubernetes":{"cluster":"kubernetes",
                    "user":"system:node:fixture-node"}},
                "current-context":"system:node:fixture-node@kubernetes"
            },
            "checks": {"repeat_equal":true, "missing_referenced_credentials_accepted":true,
                "refreshes_identity":true, "output_directory_fails":true,
                "missing_parent_fails":true, "kubeconfig_mode":"0600"}
        }),
        _ => return Err("unknown credential component".into()),
    };
    Ok(value)
}
