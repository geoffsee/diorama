use diorama_config::{
    Config, EnvironmentMode, ExplicitFlags, FIELDS, FieldType, HostContext, INPUT_BINDINGS, decode,
    parse_environment, render_effective_yaml, resolve_layers,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn host() -> HostContext {
    HostContext {
        cpu_count: 8,
        architecture: "arm64".into(),
        detected_container_mode: false,
    }
}
fn resolve(
    input: &str,
    environment: &BTreeMap<String, String>,
    flags: &ExplicitFlags,
) -> Result<Config, diorama_config::ConfigError> {
    resolve_layers(
        Some(decode(input)?),
        environment,
        flags,
        EnvironmentMode::Include,
        &host(),
    )
    .map(|v| v.validated.into_config())
}
fn samples(path: &str, kind: FieldType) -> (&'static str, &'static str, Value, Value) {
    match path {
        "kubernetes.role" => (
            "control-plane",
            "worker",
            json!("control-plane"),
            json!("worker"),
        ),
        "network.podAddressPool" => (
            "10.42.0.0/16",
            "10.50.0.0/16",
            json!("10.42.0.0/16"),
            json!("10.50.0.0/16"),
        ),
        "runtime.backend" => ("auto", "oci-cri", json!("auto"), json!("oci-cri")),
        "kubernetes.kubelet.cpuManager.policy" => {
            ("none", "static", json!("none"), json!("static"))
        },
        "kubernetes.kubelet.cpuManager.reservedCPUs" => ("1", "2", json!("1"), json!("2")),
        "kubernetes.kubelet.cpuManager.policyOptions" => (
            "full-pcpus-only=false",
            "full-pcpus-only=true",
            json!({"full-pcpus-only":"false"}),
            json!({"full-pcpus-only":"true"}),
        ),
        "kubernetes.kubelet.systemReserved" => (
            "memory=1Mi",
            "memory=2Mi",
            json!({"memory":"1Mi"}),
            json!({"memory":"2Mi"}),
        ),
        "portainer.image" => (
            "docker.io/library/busybox:lo",
            "docker.io/library/busybox:hi",
            json!("docker.io/library/busybox:lo"),
            json!("docker.io/library/busybox:hi"),
        ),
        "runtime.endpoint" => ("/lo.sock", "/hi.sock", json!("/lo.sock"), json!("/hi.sock")),
        _ => match kind {
            FieldType::Boolean | FieldType::OptionalBool => {
                ("false", "true", json!(false), json!(true))
            },
            FieldType::Integer => ("1", "2", json!(1), json!(2)),
            FieldType::StringList => (
                "lo.example",
                "hi.example",
                json!(["lo.example"]),
                json!(["hi.example"]),
            ),
            _ => ("lo", "hi", json!("lo"), json!("hi")),
        },
    }
}
#[test]
fn every_binding_obeys_file_environment_explicit_flag_precedence() {
    assert_eq!(INPUT_BINDINGS.len(), 35);
    for binding in INPUT_BINDINGS {
        let field = FIELDS.iter().find(|v| v.path == binding.path).unwrap();
        let (lo, hi, low, high) = samples(binding.path, field.kind);
        let mut base = serde_json::to_value(Config::default()).unwrap();
        if binding.path.ends_with("policyOptions") || binding.path.ends_with("reservedCPUs") {
            base["kubernetes"]["kubelet"]["cpuManager"]["policy"] = json!("static");
        }
        if binding.path == "kubernetes.role" {
            base["kubernetes"]["tokenFile"] = json!("/join-token");
        }
        let pointer = format!("/{}", binding.path.replace('.', "/"));
        *base.pointer_mut(&pointer).unwrap() = low.clone();
        let input = base.to_string();
        let file = serde_json::to_value(
            resolve(&input, &BTreeMap::new(), &ExplicitFlags::default()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            file.pointer(&pointer).unwrap(),
            &low,
            "{} file",
            binding.path
        );
        let env = BTreeMap::from([(binding.environment.to_string(), hi.to_string())]);
        let effective =
            serde_json::to_value(resolve(&input, &env, &ExplicitFlags::default()).unwrap())
                .unwrap();
        assert_eq!(
            effective.pointer(&pointer).unwrap(),
            &high,
            "{} environment",
            binding.path
        );
        if let Some(flag) = binding.flag {
            let explicit = ExplicitFlags(BTreeMap::from([(flag.to_string(), lo.to_string())]));
            let effective =
                serde_json::to_value(resolve(&input, &env, &explicit).unwrap()).unwrap();
            assert_eq!(
                effective.pointer(&pointer).unwrap(),
                &low,
                "{} explicit flag",
                binding.path
            );
        }
    }
}
#[test]
fn environment_can_be_checked_independently_or_explicitly_omitted() {
    let env = BTreeMap::from([("KUBESOLO_MTU".into(), "bad".into())]);
    assert_eq!(parse_environment(&env).unwrap_err().path, "KUBESOLO_MTU");
    assert!(
        resolve_layers(
            None,
            &env,
            &ExplicitFlags::default(),
            EnvironmentMode::Omit,
            &host()
        )
        .is_ok()
    );
}
#[test]
fn explicit_false_zero_empty_and_no_parser_defaults_override_file() {
    let input =
        r#"{"network":{"mtu":1400},"logging":{"debug":true},"portainer":{"edgeID":"from-file"}}"#;
    let flags = ExplicitFlags(BTreeMap::from([
        ("mtu".into(), "0".into()),
        ("debug".into(), "false".into()),
        ("portainer-edge-id".into(), String::new()),
    ]));
    let config = resolve(input, &BTreeMap::new(), &flags).unwrap();
    assert_eq!(config.network.mtu, 0);
    assert!(!config.logging.debug);
    assert_eq!(config.portainer.edge_id, "");
    assert_eq!(
        resolve(input, &BTreeMap::new(), &ExplicitFlags::default())
            .unwrap()
            .network
            .mtu,
        1400
    );
}
#[test]
fn go_layer_and_print_observations_match_independent_expected_outputs() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/layers-reference.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let env: BTreeMap<String, String> =
            serde_json::from_value(case["environment"].clone()).unwrap();
        let flags: BTreeMap<String, String> =
            serde_json::from_value(case["explicit_flags"].clone()).unwrap();
        let result = resolve(case["input"].as_str().unwrap(), &env, &ExplicitFlags(flags));
        if case["exit_code"] == 0 {
            let config = result.unwrap();
            assert_eq!(
                serde_json::to_value(&config).unwrap(),
                serde_json::to_value(
                    serde_json::from_value::<Config>(case["expected_typed"].clone()).unwrap()
                )
                .unwrap(),
                "{} typed",
                case["id"]
            );
            if !has_unicode_break(&serde_json::to_value(&config).unwrap()) {
                assert_eq!(
                    legacy_render(&config),
                    case["stdout"].as_str().unwrap(),
                    "{} print",
                    case["id"]
                );
            }
            assert_eq!(
                decode(&render_effective_yaml(&config).unwrap())
                    .unwrap()
                    .config,
                config,
                "{} round-trip",
                case["id"]
            );
        } else {
            assert!(result.is_err(), "{}", case["id"]);
        }
    }
}

#[test]
fn every_binding_matches_the_independent_go_schema_capture() {
    let source: Value =
        serde_json::from_str(include_str!("fixtures/bindings-reference.json")).unwrap();
    let settings = source["settings"].as_array().unwrap();
    assert_eq!(settings.len() + 5, INPUT_BINDINGS.len());
    // The managed backend selector extends the captured Go schema.
    for binding in INPUT_BINDINGS.iter().filter(|binding| {
        !matches!(
            binding.path,
            "runtime.backend"
                | "kubernetes.role"
                | "kubernetes.tokenFile"
                | "kubernetes.disableLocalKubelet"
                | "network.podAddressPool"
        )
    }) {
        let expected = settings
            .iter()
            .find(|field| field["path"] == binding.path)
            .unwrap();
        assert_eq!(expected["envar"], binding.environment);
        assert_eq!(expected["flag"].as_str(), binding.flag);
    }
}
#[test]
fn file_warnings_precede_final_validation_warnings() {
    let result = resolve_layers(
        Some(decode("kind: Other\nnetwork: {mtu: 100}\n").unwrap()),
        &BTreeMap::new(),
        &ExplicitFlags::default(),
        EnvironmentMode::Include,
        &host(),
    )
    .unwrap();
    let first_validation = result
        .warnings
        .iter()
        .position(|w| matches!(w, diorama_config::ResolutionWarning::Validation(_)))
        .unwrap();
    assert!(first_validation > 0);
    assert!(
        result.warnings[..first_validation]
            .iter()
            .all(|w| matches!(w, diorama_config::ResolutionWarning::File(_)))
    );
}

#[test]
fn direct_go_print_capture_preserves_escaped_control_data_with_named_deviation() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/linebreak/reference.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let config = decode(case["input"].as_str().unwrap()).unwrap().config;
        let printed = render_effective_yaml(&config).unwrap();
        if !has_unicode_break(&serde_json::to_value(&config).unwrap()) {
            assert_eq!(
                legacy_render(&config),
                case["printed"].as_str().unwrap(),
                "{}",
                case["id"]
            );
        }
        assert_eq!(
            decode(&printed)
                .unwrap_or_else(|e| panic!("{} roundtrip: {e}", case["id"]))
                .config,
            config,
            "{} roundtrip",
            case["id"]
        );
    }
}

#[test]
fn printable_strings_roundtrip_without_yaml_structure_injection() {
    let values = [
        "",
        "---",
        "...",
        "# key",
        "&alias",
        "*alias",
        "!tag value",
        "a: b",
        "a # b",
        "[a,b]",
        "{key: value}",
        "it's quoted",
        " leading",
        "trailing ",
        "a\n  b\n",
        "a \nb",
        "true",
        "NULL",
        "~",
        "0x10",
        "1:20",
        "2024-02-29",
        "2024-02-30",
        "雪😀",
        "\0\t\r\n\u{85}\u{2028}\u{2029}",
    ];
    for value in values {
        let mut config = Config::default();
        config.portainer.edge_key = value.into();
        let text = render_effective_yaml(&config).unwrap();
        assert_eq!(decode(&text).unwrap().config, config, "{value:?}");
    }
    let mut config = Config::default();
    config.portainer.edge_key = format!(
        "{}\t{}",
        "quoted with spaces ".repeat(20),
        "more words ".repeat(20)
    );
    assert_eq!(
        decode(&render_effective_yaml(&config).unwrap())
            .unwrap()
            .config,
        config
    );
}

fn has_unicode_break(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains(['\u{85}', '\u{2028}', '\u{2029}']),
        Value::Array(values) => values.iter().any(has_unicode_break),
        Value::Object(values) => values.values().any(has_unicode_break),
        _ => false,
    }
}
#[test]
fn short_unicode_break_combinations_preserve_typed_data() {
    let alphabet = ['a', ' ', '\n', '\u{85}', '\u{2028}', '\u{2029}'];
    for encoded in 0..216 {
        let mut digits = encoded;
        let mut config = Config::default();
        config.d2k.namespace.clear();
        for _ in 0..3 {
            config.d2k.namespace.push(alphabet[digits % alphabet.len()]);
            digits /= alphabet.len();
        }
        let yaml = render_effective_yaml(&config).unwrap();
        assert!(!yaml.contains(['\u{85}', '\u{2028}', '\u{2029}']));
        assert_eq!(
            decode(&yaml).unwrap().config,
            config,
            "{:?}",
            config.d2k.namespace
        );
    }
}

#[test]
fn explicit_empty_path_and_unicode_spacing_preserve_raw_go_values() {
    let inputs: Value =
        serde_json::from_str(include_str!("fixtures/print-preservation/inputs.json")).unwrap();
    let captures: Value =
        serde_json::from_str(include_str!("fixtures/print-preservation/reference.json")).unwrap();
    for (id, input) in inputs.as_object().unwrap() {
        let config = decode(input.as_str().unwrap()).unwrap().config;
        let expected = &captures[0][id];
        assert_eq!(config.path, expected["path"].as_str().unwrap());
        assert_eq!(
            config.d2k.namespace,
            expected["namespace"].as_str().unwrap()
        );
        assert_eq!(
            serde_json::to_value(&config.kubernetes.api_server.extra_sans).unwrap(),
            expected["extraSANs"]
        );
        let printed = render_effective_yaml(&config).unwrap();
        if id == "empty-path" {
            assert!(!expected["printed"].as_str().unwrap().contains("\npath:"));
            assert!(printed.contains("\npath: \"\"\n"));
        }
        let mut expected_config = config;
        if id == "empty-sans" {
            expected_config.kubernetes.api_server.extra_sans = None;
        }
        assert_eq!(decode(&printed).unwrap().config, expected_config, "{id}");
    }
}

#[test]
fn raw_input_debug_omits_secret_values() {
    let secret = "synthetic-sensitive-input-key";
    let flags = ExplicitFlags(BTreeMap::from([(
        "portainer-edge-key".into(),
        secret.into(),
    )]));
    let environment = BTreeMap::from([("KUBESOLO_PORTAINER_EDGE_KEY".into(), secret.into())]);
    let parsed = parse_environment(&environment).unwrap();
    assert!(!format!("{flags:?}").contains(secret));
    assert!(!format!("{parsed:?}").contains(secret));
    assert!(format!("{flags:?}").contains("portainer-edge-key"));
}

#[test]
fn managed_runtime_selector_rejects_unknown_backends_and_external_endpoints() {
    for input in [
        "runtime: {backend: typo}",
        "runtime: {backend: oci-cri, endpoint: /run/cri.sock}",
        "runtime: {backend: containerd, endpoint: /run/cri.sock}",
    ] {
        assert_eq!(
            resolve(input, &BTreeMap::new(), &ExplicitFlags::default())
                .unwrap_err()
                .path,
            "runtime.backend"
        );
    }
    let config = resolve(
        "runtime: {backend: oci-cri}",
        &BTreeMap::new(),
        &ExplicitFlags::default(),
    )
    .unwrap();
    assert!(
        render_effective_yaml(&config)
            .unwrap()
            .contains("backend: oci-cri")
    );
    assert!(
        diorama_config::diff_configs(&Config::default(), &config)
            .contains(&"runtime.backend".to_string())
    );
    assert_ne!(
        diorama_config::compute_etag(&Config::default()),
        diorama_config::compute_etag(&config)
    );
    let cleared =
        diorama_config::apply_merge_patch(&config, &json!({"runtime":{"backend":null}})).unwrap();
    assert_eq!(cleared.runtime.backend, "");
}

// The captured Go document predates worker roles; retain its exact legacy output
// comparison while checking the four added settings separately above.
fn legacy_render(config: &Config) -> String {
    render_effective_yaml(config)
        .unwrap()
        .lines()
        .filter(|line| {
            ![
                "  role:",
                "  tokenFile:",
                "  disableLocalKubelet:",
                "  podAddressPool:",
            ]
            .iter()
            .any(|prefix| line.starts_with(prefix))
        })
        .fold(String::new(), |mut output, line| {
            output.push_str(line);
            output.push('\n');
            output
        })
}
