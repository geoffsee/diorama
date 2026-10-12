//! Independent expectations for baseline preflight and constrained-host policy.
use super::{Result, Value, equal, load};
use serde_json::json;
use std::path::Path;

pub fn verify_completion(family: &str, raw: &[u8]) -> Result<()> {
    let name = if family == "preflight-policy" {
        "TestDioramaCapture"
    } else {
        "TestCapture"
    };
    let pattern = regex::Regex::new(&format!(r"(?m)^--- PASS: {name} \([0-9.]+s\)$"))?;
    if pattern.find_iter(std::str::from_utf8(raw)?).count() != 1 {
        return Err("missing or duplicate Go completion".into());
    }
    Ok(())
}

pub fn expected(family: &str, component: &str) -> Result<Value> {
    let rows: &[&str] = match (family, component) {
        ("preflight-policy", "preflight") => &[
            "root\ttrue",
            "hostname_valid\ttrue",
            "hostname_uppercase\tfalse",
            "hostname_empty\tfalse",
            "hostname_dot\tfalse",
            "hostname_underscore\tfalse",
            "hostname_space\tfalse",
            "hostname_label63\ttrue",
            "hostname_label64\tfalse",
            "hostname_total253\ttrue",
            "hostname_total254\tfalse",
            "hostname_unicode\tfalse",
            "hostname_dash\tfalse",
            "docker_absent\ttrue",
            "docker_socket\tfalse",
            "docker_binary\tfalse",
            "comment_absent\tfalse",
            "comment_loaded\ttrue",
            "comment_match\ttrue",
            "comment_substring\tfalse",
            "comment_disk\ttrue",
            "comment_glob\ttrue",
            "not_alpine\ttrue",
            "alpine_missing\tfalse",
            "alpine_tools\ttrue",
            "alpine_custom_paths\tfalse",
            "v2_all\ttrue",
            "v2_missing\tfalse",
            "v2_empty\tfalse",
            "v1_all\ttrue",
            "v1_io_wrong\tfalse",
            "alpine_rc_service\tfalse",
            "alpine_ready\ttrue",
            "ports_0_false\ttrue",
            "ports_0_true\ttrue",
            "ports_6060_false\ttrue",
            "ports_6060_true\tfalse",
            "ports_2379_false\tfalse",
            "ports_2379_true\tfalse",
            "ports_6443_false\tfalse",
            "ports_6443_true\tfalse",
            "ports_10443_false\tfalse",
            "ports_10443_true\tfalse",
            "suite_failfast\ttrue",
        ],
        ("constrained-policy", "network") => &[
            "correct_readonly\ttrue",
            "correct_readonly_bytes\t310a",
            "incorrect_readonly\tfalse",
            "incorrect_readonly_bytes\t300a",
            "absent\ttrue",
            "unreadable_skipped\ttrue",
            "unreadable_skipped_bytes\t300a",
            "prefix_one_accepted\ttrue",
            "prefix_one_accepted_bytes\t313067617262616765",
            "incorrect_writable\ttrue",
            "incorrect_writable_bytes\t31",
        ],
        ("constrained-policy", "system") => &[
            "nft\ttrue",
            "legacy\tfalse",
            "unrecognized\tfalse",
            "failed_assumes_nft\ttrue",
        ],
        ("constrained-policy", "proxy") => &[
            "absent\tnftables",
            "present\tiptables",
            "unreadable\tnftables",
        ],
        ("constrained-policy", "embedded") => &[
            "owned\t10-bridge.conflist",
            "plugins\tbridge,host-local,portmap,loopback",
            "default_missing_warning\ttrue",
            "ordering\t3,1",
            "files_unchanged\ttrue",
        ],
        _ => return Err("unknown policy component".into()),
    };
    Ok(json!(rows))
}

pub fn pins(family: &str) -> Result<Value> {
    match family {
        "preflight-policy" => Ok(
            json!({"preflight.go":"dd8d85a0593792886b627518b770645e13a9184e5f43a2dd55c071394973cb3e"}),
        ),
        "constrained-policy" => Ok(json!({
            "internal/core/embedded/host.go":"e64d143129383c17b130921afd8776bcb2c0111e2119e13863ceb414c40f1e6d",
            "internal/runtime/network/ipv6.go":"38d8fcf4efe237891328148d21f1fd9170871850156fe88724b8216b0b7ea0d5",
            "internal/system/modules.go":"543ef157f17a6a4f54310d68365327d2673963c1ccf97d175a2e3e5000ffb107",
            "pkg/kubernetes/kubeproxy/flags.go":"7935824118ee9f3e96299b057fd1c16fed4de56ccd94f2af3502b0fb41db802a",
            "types/const.go":"f60c550e2f40060a51b0ec45a0da0bb7c5add84a30e06570517c87588f55d52d"
        })),
        _ => Err("unknown policy source pins".into()),
    }
}

pub fn verify_sources(family: &str, raw: &[u8], components: &[&str]) -> Result<()> {
    let mut entries = serde_json::Map::new();
    for line in std::str::from_utf8(raw)?.lines() {
        let (hash, name) = line.split_once("  ").ok_or("source digest row")?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || entries.insert(name.into(), json!(hash)).is_some()
        {
            return Err("invalid or duplicate source digest".into());
        }
    }
    for component in components {
        entries
            .remove(&format!("/{component}.test"))
            .ok_or("missing binary digest")?;
    }
    equal(&Value::Object(entries), &pins(family)?)
}

pub fn verify(family: &str, directory: &Path) -> Result<()> {
    let components: &[&str] = match family {
        "preflight-policy" => &["preflight"],
        "constrained-policy" => &["network", "system", "proxy", "embedded"],
        _ => return Err("unknown policy family".into()),
    };
    for component in components {
        equal(
            &load(&directory.join(format!("{component}.json")))?,
            &expected(family, component)?,
        )?;
    }
    verify_sources(
        family,
        &crate::read_bounded(&directory.join("source.sha256"), super::LIMIT)?,
        components,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "receipt checks disabled"]
    fn historical_observations_and_raw_source_pins_match_independent_policy() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures");
        for family in ["preflight-policy", "constrained-policy"] {
            let profile = crate::fixture_capture::profile(family)?;
            let directory = root.join(family);
            for component in profile.components {
                let prefix = if family == "preflight-policy" {
                    "run"
                } else {
                    component
                };
                for index in 0..2 {
                    let label = format!("{prefix}{index}");
                    let raw = crate::read_bounded(
                        &directory.join(format!("evidence/{label}.log")),
                        super::super::LIMIT,
                    )?;
                    let records = std::str::from_utf8(&raw)?
                        .lines()
                        .filter_map(|line| line.strip_prefix("DIORAMA_CAPTURE "))
                        .map(|line| crate::json::parse(line.as_bytes()))
                        .collect::<Result<Vec<_>>>()?;
                    equal(&json!(records), &json!([expected(family, component)?]))?;
                }
            }
            verify_sources(
                family,
                &crate::read_bounded(
                    &directory.join("evidence/source.sha256"),
                    super::super::LIMIT,
                )?,
                profile.components,
            )?;
        }
        Ok(())
    }
    #[test]
    #[ignore = "receipt checks disabled"]
    fn immutable_historical_artifacts_keep_their_original_hashes() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../parity/fixtures");
        for family in ["preflight-policy", "constrained-policy"] {
            let directory = root.join(family);
            let provenance = load(&directory.join("provenance.json"))?;
            let prefix = if family == "preflight-policy" {
                directory.join("evidence")
            } else {
                directory.clone()
            };
            for (name, hash) in provenance["files"]
                .as_object()
                .ok_or("historical inventory")?
            {
                equal(
                    &json!(crate::sha256(&crate::read_bounded(
                        &prefix.join(name),
                        8 * 1024 * 1024
                    )?)),
                    hash,
                )?;
            }
        }
        Ok(())
    }
    #[test]
    fn source_inventory_rejects_duplicates_extra_and_missing_binary_rows() -> Result<()> {
        let source =
            "dd8d85a0593792886b627518b770645e13a9184e5f43a2dd55c071394973cb3e  preflight.go\n";
        let binary = format!("{}  /preflight.test\n", "a".repeat(64));
        verify_sources(
            "preflight-policy",
            format!("{source}{binary}").as_bytes(),
            &["preflight"],
        )?;
        for raw in [
            source.to_owned(),
            format!("{source}{binary}{binary}"),
            format!("{source}{binary}{}  extra\n", "a".repeat(64)),
        ] {
            assert!(verify_sources("preflight-policy", raw.as_bytes(), &["preflight"]).is_err());
        }
        Ok(())
    }
}
