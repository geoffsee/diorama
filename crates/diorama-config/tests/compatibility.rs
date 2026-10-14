use diorama_config::{
    Config, DecodeLimits, ErrorKind, FIELDS, HostContext, Presence, RuntimePath, RuntimeProbe,
    Warning, decode, decode_with_limits, normalize_image,
};
use serde_json::Value;

fn host() -> HostContext {
    HostContext {
        cpu_count: 8,
        architecture: "arm64".into(),
        detected_container_mode: true,
    }
}
fn effective(input: &str) -> Result<Config, diorama_config::ConfigError> {
    let mut c = decode(input)?.config;
    c.derive_socket_path();
    c.validate(&host())
        .map(diorama_config::ValidatedConfig::into_config)
}

#[test]
fn real_go_scalar_alias_and_document_observations_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/yaml-reference.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        let actual = effective(input);
        if case["exit_code"] == 0 {
            let expected: Config = serde_json::from_value(case["expected_typed"].clone()).unwrap();
            assert_eq!(actual.unwrap(), expected, "{}", case["id"]);
        } else {
            assert!(actual.is_err(), "{}", case["id"]);
        }
    }
}

#[test]
fn independent_full_document_and_negative_fixtures_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/config-command.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let input = case["files"]["config.yaml"].as_str().unwrap();
        let actual = effective(input);
        if case["expect"]["exit_code"] == 0 {
            let expected: Config = serde_json::from_value(case["expected_typed"].clone()).unwrap();
            assert_eq!(actual.unwrap(), expected, "{}", case["id"]);
        } else {
            assert!(actual.is_err(), "{}", case["id"]);
        }
    }
}

#[test]
fn thirty_fields_preserve_explicit_presence_and_defaults() {
    assert_eq!(FIELDS.len(), 30);
    let empty = decode("").unwrap();
    assert_eq!(empty.config, Config::default());
    assert!(
        FIELDS
            .iter()
            .all(|f| empty.presence(f.path) == Presence::Omitted)
    );
    let c = decode("network: {mtu: 0, nodeIP: '', loadBalancer: {enabled: false}}\nruntime: {containerMode: false}\nkubernetes: {apiServer: {extraSANs: []}, kubelet: {systemReserved: {}}}").unwrap();
    assert_eq!(c.presence("network.mtu"), Presence::Value);
    assert_eq!(c.presence("network.nodeIP"), Presence::Value);
    assert!(!c.config.network.load_balancer.enabled);
    assert_eq!(c.config.runtime.container_mode, Some(false));
    assert_eq!(c.config.kubernetes.api_server.extra_sans, Some(vec![]));
    assert_eq!(
        c.config.kubernetes.kubelet.system_reserved,
        Some(std::collections::BTreeMap::default())
    );
    let c = decode("network: null\nruntime: {containerMode: null}").unwrap();
    assert_eq!(c.presence("network"), Presence::Null);
    assert_eq!(c.presence("network.mtu"), Presence::Omitted);
    assert_eq!(c.presence("runtime.containerMode"), Presence::Null);
    assert_eq!(c.config.network, Config::default().network);
}

#[test]
fn warnings_and_fatal_categories_remain_distinct() {
    let c = decode("kind: Wrong\nfuture: true\nlogging: {debug: true, debug: false}").unwrap();
    assert_eq!(c.warnings.len(), 3);
    assert!(matches!(c.warnings[0], Warning::MissingVersion));
    assert!(matches!(c.warnings[1], Warning::UnexpectedKind(_)));
    assert!(matches!(c.warnings[2], Warning::IgnoredSettings { .. }));
    assert!(!c.config.logging.debug);
    assert_eq!(
        decode("apiVersion: future").unwrap_err().kind,
        ErrorKind::Version
    );
    assert_eq!(decode("logging: [").unwrap_err().kind, ErrorKind::Syntax);
    assert_eq!(
        decode("logging: {debug: 'true'}").unwrap_err().kind,
        ErrorKind::Type
    );
}

#[test]
fn parser_budgets_and_recursive_aliases_fail_without_effects() {
    let limits = DecodeLimits {
        input_bytes: 16,
        depth: 4,
        expanded_nodes: 10,
        expanded_bytes: 4096,
    };
    assert_eq!(
        decode_with_limits("a: aaaaaaaaaaaaaaaaa", limits)
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
    assert!(decode_with_limits("a: &a [*a]", limits).is_err());
    assert!(decode_with_limits("a: [[[[[0]]]]]", limits).is_err());
}

#[test]
fn validation_is_separate_and_checks_final_combination() {
    let decoded =
        decode("d2k: {enabled: true}\nnetwork: {loadBalancer: {enabled: false}}").unwrap();
    assert!(decoded.config.clone().validate(&host()).is_err());
    let arm = HostContext {
        architecture: "arm".into(),
        ..host()
    };
    let normalized = decoded.config.validate(&arm).unwrap();
    assert!(!normalized.config().d2k.enabled);
    assert_eq!(normalized.warnings[0].field, "d2k.enabled");
    assert_eq!(
        normalize_image("busybox").unwrap(),
        "docker.io/library/busybox:latest"
    );
    assert_eq!(
        normalize_image("portainerci/agent:develop").unwrap(),
        "docker.io/portainerci/agent:develop"
    );
    assert!(normalize_image("NOT A REF").is_err());
}

#[test]
fn cpu_reservations_and_options_follow_supplied_host() {
    let mut host = host();
    host.detected_container_mode = false;
    let base = "kubernetes: {kubelet: {cpuManager: {policy: static}}}";
    let c = decode(base).unwrap().config.validate(&host).unwrap();
    assert_eq!(c.config().kubernetes.kubelet.cpu_manager.reserved_cpus, "0");
    for invalid in [
        "kubernetes: {kubelet: {cpuManager: {policy: static, reservedCPUs: '0-7'}}}",
        "kubernetes: {kubelet: {cpuManager: {policy: static, policyOptions: {align-by-socket: true}}}}",
        "kubernetes: {kubelet: {systemReserved: {gpu: '1'}}}",
        "kubernetes: {kubelet: {systemReserved: {cpu: '7.000000000000000001'}}}",
    ] {
        assert!(
            decode(invalid).unwrap().config.validate(&host).is_err(),
            "{invalid}"
        );
    }
    for valid in ["7", "7000m", "7e0", "0.0068359375Ki", "-1", "0.00000000001"] {
        let input = format!("kubernetes: {{kubelet: {{systemReserved: {{cpu: '{valid}'}}}}}}");
        assert!(
            decode(&input).unwrap().config.validate(&host).is_ok(),
            "{valid}"
        );
    }
}

#[test]
fn runtime_conversion_uses_supplied_facts_and_owned_paths() {
    let mut config = Config {
        path: "/fixture/base/../state".into(),
        ..Config::default()
    };
    config.kubernetes.node_name = "  My-NODE  ".into();
    config.derive_socket_path();
    assert_eq!(config.api.socket_path, "/fixture/state/config.sock");
    let settings = config
        .validate(&host())
        .unwrap()
        .into_runtime(RuntimeProbe {
            hostname: "fallback".into(),
            node_ip: "192.0.2.10".into(),
            node_ip_pinned: true,
            ..RuntimeProbe::default()
        })
        .unwrap();
    assert_eq!(settings.node_name, "my-node");
    assert_eq!(
        settings.runtime.url,
        "unix:///fixture/state/containerd/containerd.sock"
    );
    assert!(!settings.runtime.external);
    assert_eq!(
        settings.paths[&RuntimePath::CaCertificate]
            .to_str()
            .unwrap(),
        "/fixture/state/pki/ca/ca.crt"
    );
    assert_eq!(settings.probe.node_ip, "192.0.2.10");
}

#[test]
fn schema_version_precedes_known_field_type_failure() {
    assert_eq!(
        decode("apiVersion: future\nlogging: {debug: 'no'}")
            .unwrap_err()
            .kind,
        ErrorKind::Version
    );
}

#[test]
fn bytes_support_bom_encodings_and_reject_invalid_unicode() {
    let text = "logging: {debug: true}";
    for little in [true, false] {
        let mut bytes = if little {
            vec![0xff, 0xfe]
        } else {
            vec![0xfe, 0xff]
        };
        for unit in text.encode_utf16() {
            bytes.extend(if little {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            });
        }
        assert!(
            diorama_config::decode_bytes(&bytes)
                .unwrap()
                .config
                .logging
                .debug
        );
    }
    assert!(diorama_config::decode_bytes(&[0xff]).is_err());
    assert!(diorama_config::decode_bytes(&[0xff, 0xfe, 1]).is_err());
}

#[test]
fn missing_files_are_explicit_and_do_not_add_schema_warnings() {
    let path = std::env::temp_dir()
        .join(format!("diorama-config-absent-{}", std::process::id()))
        .join("config.yaml");
    assert!(diorama_config::read_file(&path).unwrap().is_none());
}

#[test]
fn nested_alias_chains_cannot_bypass_depth_budget() {
    let input = "a: &a [1]\nb: &b [*a]\nc: &c [*b]\nd: [*c]";
    let limits = DecodeLimits {
        input_bytes: 1024,
        depth: 4,
        expanded_nodes: 1000,
        expanded_bytes: 4096,
    };
    assert_eq!(
        decode_with_limits(input, limits).unwrap_err().kind,
        ErrorKind::Limit
    );
}

#[test]
fn every_inventory_field_accepts_an_explicit_nondefault_typed_value() {
    for field in FIELDS {
        let value = match field.kind {
            diorama_config::FieldType::Boolean | diorama_config::FieldType::OptionalBool => {
                Value::Bool(true)
            },
            diorama_config::FieldType::Integer => Value::from(17),
            diorama_config::FieldType::String => Value::from("fixture-value"),
            diorama_config::FieldType::StringList => serde_json::json!(["fixture-value"]),
            diorama_config::FieldType::StringMap => serde_json::json!({"fixture": "value"}),
        };
        let mut document = value.clone();
        for part in field.path.split('.').rev() {
            document = serde_json::json!({part: document});
        }
        let decoded = decode(&document.to_string()).unwrap();
        assert_eq!(
            decoded.presence(field.path),
            Presence::Value,
            "{}",
            field.path
        );
        let output = serde_json::to_value(decoded.config).unwrap();
        let pointer = format!("/{}", field.path.replace('.', "/"));
        assert_eq!(output.pointer(&pointer), Some(&value), "{}", field.path);
        assert_ne!(field.owner, "");
    }
}

#[test]
fn semantic_edges_match_go_with_explicit_cpu_overflow_deviation() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/semantic-reference.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let actual = effective(case["input"].as_str().unwrap());
        if case["id"] == "cpu-huge-exp" {
            assert_eq!(
                case["exit_code"], 0,
                "baseline weakness must remain recorded"
            );
            assert!(actual.is_err(), "Rust must reject an overreservation");
        } else if case["exit_code"] == 0 {
            assert_eq!(
                actual.unwrap(),
                serde_json::from_value::<Config>(case["expected_typed"].clone()).unwrap(),
                "{}",
                case["id"]
            );
        } else {
            assert!(actual.is_err(), "{}", case["id"]);
        }
    }
}

#[test]
fn scalar_alias_and_anchor_storage_obey_byte_budget() {
    let limits = DecodeLimits {
        input_bytes: 1024,
        depth: 32,
        expanded_nodes: 1000,
        expanded_bytes: 80,
    };
    let input = "a: &a abcdefghijklmnopqrstuvwxyz\nb: [*a, *a, *a]\n";
    assert_eq!(
        decode_with_limits(input, limits).unwrap_err().kind,
        ErrorKind::Limit
    );
    let limits = DecodeLimits {
        expanded_bytes: 30,
        ..limits
    };
    assert_eq!(
        decode_with_limits("a: &a abcdefghijklmnopqrstuvwxyz", limits)
            .unwrap_err()
            .kind,
        ErrorKind::Limit
    );
}

#[test]
fn file_input_rejects_oversize_with_bounded_read() {
    let path =
        std::env::temp_dir().join(format!("diorama-config-limit-{}.yaml", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.set_len(DecodeLimits::default().input_bytes as u64 + 1)
        .unwrap();
    let result = diorama_config::read_file(&path);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(result.unwrap_err().kind, ErrorKind::Limit);
}

#[test]
fn comma_maps_and_image_names_match_independent_go_outputs() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/map-reference.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let expected: Config = serde_json::from_value(case["expected_typed"].clone()).unwrap();
        assert_eq!(
            effective(case["input"].as_str().unwrap()).unwrap(),
            expected,
            "{}",
            case["id"]
        );
    }
}

#[test]
fn malformed_integer_signs_remain_strings_without_negation_overflow() {
    for raw in [
        "--5",
        "++5",
        "+-5",
        "-+5",
        "0x-10",
        "-0b-1",
        "--170141183460469231731687303715884105728",
    ] {
        let input = format!("network: {{nodeIP: {raw}}}");
        assert_eq!(decode(&input).unwrap().config.network.node_ip, raw);
        assert_eq!(
            decode(&format!("network: {{mtu: {raw}}}"))
                .unwrap_err()
                .kind,
            ErrorKind::Type
        );
        assert_eq!(
            decode(&format!("network: {{mtu: !!int {raw}}}"))
                .unwrap_err()
                .kind,
            ErrorKind::Type
        );
    }
}

#[test]
fn debug_redacts_edge_key_without_changing_explicit_serialization() {
    let secret = "synthetic-sensitive-edge-key";
    let mut config = Config::default();
    config.portainer.edge_id = "visible-id".into();
    config.portainer.edge_key = secret.into();
    let direct = format!("{:?}", config.portainer);
    assert!(!direct.contains(secret));
    assert!(direct.contains("visible-id"));
    assert!(!format!("{config:?}").contains(secret));
    assert_eq!(
        serde_json::to_value(&config).unwrap()["portainer"]["edgeKey"],
        secret
    );
    let runtime = config
        .validate(&host())
        .unwrap()
        .into_runtime(RuntimeProbe {
            hostname: "fixture".into(),
            ..RuntimeProbe::default()
        })
        .unwrap();
    assert!(!format!("{runtime:?}").contains(secret));
}

#[test]
fn runtime_normalizes_fallback_hostname_and_rejects_missing_discovery() {
    let validated = Config::default().validate(&host()).unwrap();
    let runtime = validated
        .clone()
        .into_runtime(RuntimeProbe {
            hostname: "  HOST-NAME  ".into(),
            ..RuntimeProbe::default()
        })
        .unwrap();
    assert_eq!(runtime.node_name, "host-name");
    for hostname in ["", " "] {
        let error = validated
            .clone()
            .into_runtime(RuntimeProbe {
                hostname: hostname.into(),
                ..RuntimeProbe::default()
            })
            .unwrap_err();
        assert_eq!(error.path, "kubernetes.nodeName");
    }
    let mut explicit = Config::default();
    explicit.kubernetes.node_name = " Configured ".into();
    assert_eq!(
        explicit
            .validate(&host())
            .unwrap()
            .into_runtime(RuntimeProbe::default())
            .unwrap()
            .node_name,
        "configured"
    );
}

#[cfg(any())]
#[test]
fn scalar_signs_and_radix_prefixes_match_captured_go_results() {
    for fixture in [
        include_str!("fixtures/scalar-signs/base/evidence/result.json"),
        include_str!("fixtures/scalar-signs/extra/evidence/result.json"),
    ] {
        let cases: serde_json::Value = serde_json::from_str(fixture).unwrap();
        for (raw, expected) in cases.as_object().unwrap() {
            let string = decode(&format!("d2k: {{namespace: {raw}}}")).unwrap();
            assert_eq!(
                string.config.d2k.namespace, expected["string"]["namespace"],
                "{raw}"
            );
            for (case, tag) in [("integer", ""), ("explicit_integer", "!!int ")] {
                let actual = decode(&format!("network: {{mtu: {tag}{raw}}}"));
                if expected[case]["error"].as_str().unwrap().is_empty() {
                    assert_eq!(
                        actual.unwrap().config.network.mtu,
                        expected[case]["mtu"].as_i64().unwrap(),
                        "{raw}"
                    );
                } else {
                    assert_eq!(actual.unwrap_err().kind, ErrorKind::Type, "{raw}");
                }
            }
        }
    }
}

#[test]
fn merge_duplicate_warnings_use_registered_root_and_nested_paths() {
    let decoded = decode("kind: KubeSoloConfiguration\n<<: {kind: KubeSoloConfiguration}\nlogging: {debug: false, <<: {debug: true}}\n").unwrap();
    let duplicates: Vec<_> = decoded
        .warnings
        .iter()
        .filter_map(|warning| match warning {
            Warning::IgnoredSettings { duplicate, .. } => Some(duplicate.as_slice()),
            _ => None,
        })
        .flatten()
        .map(String::as_str)
        .collect();
    assert_eq!(duplicates, ["kind", "logging.debug"]);
    assert!(decoded.config.logging.debug);
}
