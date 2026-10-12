//! Official `Complete()` semantics and owned disposable capture.
use crate::{
    Result,
    defaults::{load, require},
    json, read_bounded, sha256,
};
use serde_json::{Value, json as value};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
mod capture;
#[cfg(test)]
mod tests;
pub use capture::cli as capture_cli;
pub fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../resolved-defaults")
}
pub fn equal(actual: &Value, expected: &Value) -> Result<()> {
    require(
        json::changes(actual, expected).is_empty(),
        "resolved type, key inventory, or value mismatch",
    )
}
pub fn verify(value: &Value) -> Result<()> {
    equal(&value["schema_version"], &value!(1))?;
    equal(
        &value["runtime"],
        &value!({"go":"go1.26.8","os":"linux","arch":"arm64"}),
    )?;
    equal(
        &value["controls"],
        &value!({"bind_address":"127.0.0.1","external_address":"127.0.0.1","cert_directory":"","operation":"ServerRunOptions.Complete","server_started":false}),
    )?;
    let cases = value["cases"]
        .as_object()
        .ok_or("missing completion cases")?;
    let names = cases.keys().map(String::as_str).collect::<BTreeSet<_>>();
    require(
        names
            == BTreeSet::from([
                "default",
                "dual_stack",
                "invalid_cidr",
                "small_cidr",
                "invalid_watch_cache",
                "invalid_token_expiration",
            ]),
        "completion case inventory",
    )?;
    for (name, error) in [
        (
            "invalid_cidr",
            "service-cluster-ip-range[0] is not a valid cidr",
        ),
        (
            "small_cidr",
            "error determining service IP ranges for primary service cidr: the service cluster IP range must be at least 8 IP addresses",
        ),
        (
            "invalid_watch_cache",
            "invalid size of watch cache size: pods#invalid",
        ),
        (
            "invalid_token_expiration",
            "the service-account-max-token-expiration must be between 1 hour and 2^32 seconds",
        ),
    ] {
        equal(&cases[name], &value!({"error":error}))?;
    }
    for name in ["default", "dual_stack"] {
        verify_success(&cases[name], name == "dual_stack")?;
    }
    Ok(())
}
fn verify_success(case: &Value, dual: bool) -> Result<()> {
    let expected = value!({"primary_service_cidr":if dual{"10.96.0.0/20"}else{"10.0.0.0/24"},"secondary_service_cidr":if dual{"fd00:1234::/108"}else{"<nil>"},"service_ip":if dual{"10.96.0.1"}else{"10.0.0.1"},"advertise_address":"127.0.0.1","external_host":"127.0.0.1","authorization_modes":if dual{vec!["Node","RBAC"]}else{vec!["AlwaysAllow"]},"anonymous_auth":dual,"watch_cache_sizes":if dual{vec!["events#0","events.events.k8s.io#0","pods#42"]}else{vec!["events#0","events.events.k8s.io#0"]},"events_history_window":if dual{"2m15s"}else{"1m15s"},"runtime_config":if dual{value!({"/v1":"true","apps/v1":"true"})}else{value!({})},"token_max_expiration":if dual{"2h0m0s"}else{"0s"},"generated_serving_certificate":true,"serving_cert_file":"","serving_key_file":"","listener_created":false});
    for (key, want) in expected.as_object().ok_or("invalid expectations")? {
        equal(
            case.get(key)
                .ok_or_else(|| format!("missing completion field: {key}"))?,
            want,
        )?;
    }
    let before = case["flags_before"]
        .as_object()
        .ok_or("missing initial flags")?;
    let after = case["flags_after"]
        .as_object()
        .ok_or("missing completed flags")?;
    require(before.keys().eq(after.keys()), "flag inventory differs")?;
    for flags in [before, after] {
        require(
            flags.values().all(Value::is_string),
            "flag names/values must be strings",
        )?;
    }
    for (key, want) in [
        ("advertise-address", "<nil>"),
        ("external-hostname", ""),
        (
            "authorization-mode",
            if dual { "[Node,RBAC]" } else { "[]" },
        ),
        ("anonymous-auth", "true"),
    ] {
        equal(
            before.get(key).ok_or("missing initial flag")?,
            &value!(want),
        )?;
    }
    for (key, want) in [
        ("advertise-address", "127.0.0.1"),
        ("external-hostname", "127.0.0.1"),
        (
            "authorization-mode",
            if dual { "[Node,RBAC]" } else { "[AlwaysAllow]" },
        ),
        ("anonymous-auth", if dual { "true" } else { "false" }),
    ] {
        equal(
            after.get(key).ok_or("missing completed flag")?,
            &value!(want),
        )?;
    }
    Ok(())
}
pub fn verify_file(path: &Path) -> Result<()> {
    let actual = load(path)?;
    verify(&actual)?;
    let frozen = directory().join("expected.json");
    let raw = read_bounded(&frozen, 32 * 1024 * 1024)?;
    let provenance = load(&directory().join("provenance.json"))?;
    require(
        provenance["expected_sha256"] == sha256(&raw),
        "frozen fixture identity mismatch",
    )?;
    let expected = json::parse(&raw)?;
    verify(&expected)?;
    equal(&actual, &expected)
}
pub fn verify_cli(args: &[String]) -> Result<i32> {
    let [path] = args else {
        return Err("usage: diorama-resolved-defaults verify CAPTURE".into());
    };
    verify_file(Path::new(path))?;
    println!("resolved options match source expectations and complete reviewed fixture");
    Ok(0)
}
