use diorama_config::{
    Config, FIELDS, INPUT_BINDINGS, decode, describe_settings, render_effective_yaml,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fmt::Write;

fn leaves(value: &Value, prefix: &str, output: &mut BTreeSet<String>) {
    if let Some(object) = value.as_object() {
        for (key, value) in object {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            leaves(value, &path, output);
        }
    } else {
        output.insert(prefix.into());
    }
}

#[test]
fn complete_descriptors_match_the_independent_actual_go_schema() {
    let reference: Value = serde_json::from_str(include_str!("fixtures/bindings-reference.json"))
        .expect("reviewed actual Go capture");
    assert_eq!(json!(describe_settings()), reference["settings"]);
}

#[test]
fn inventory_is_complete_unique_sorted_and_has_model_leaves_and_bindings() {
    let descriptors = describe_settings();
    assert_eq!(descriptors.len(), 30);
    assert!(
        descriptors
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    );
    let paths: BTreeSet<_> = descriptors.iter().map(|field| field.path).collect();
    assert_eq!(paths, FIELDS.iter().map(|field| field.path).collect());
    assert_eq!(
        paths,
        INPUT_BINDINGS.iter().map(|field| field.path).collect()
    );
    assert_eq!(FIELDS.len(), paths.len());
    assert_eq!(INPUT_BINDINGS.len(), paths.len());
    let defaults = json!(Config::default());
    let mut model_paths = BTreeSet::new();
    leaves(&defaults, "", &mut model_paths);
    assert!(model_paths.remove("apiVersion"));
    assert!(model_paths.remove("kind"));
    assert_eq!(
        model_paths,
        paths.iter().map(|path| (*path).to_owned()).collect()
    );
    for descriptor in descriptors {
        let pointer = format!("/{}", descriptor.path.replace('.', "/"));
        let leaf = defaults.pointer(&pointer).expect("registered model leaf");
        if descriptor.secret {
            assert_eq!(descriptor.default, Value::Null);
        } else {
            assert_eq!(&descriptor.default, leaf);
        }
    }
}

#[test]
fn secret_null_and_underived_defaults_retain_their_declared_types() {
    let descriptors = describe_settings();
    let get = |path| descriptors.iter().find(|field| field.path == path).unwrap();
    let secret = get("portainer.edgeKey");
    assert!(secret.secret);
    assert_eq!(secret.json_type, "string");
    assert_eq!(secret.default, Value::Null);
    assert_eq!(get("api.socketPath").default, "");
    assert_eq!(get("runtime.containerMode").json_type, "boolean");
    assert_eq!(get("runtime.containerMode").default, Value::Null);
    assert_eq!(get("kubernetes.apiServer.extraSANs").json_type, "array");
    assert_eq!(get("kubernetes.kubelet.systemReserved").json_type, "object");
    assert_eq!(get("path").mutability, "immutable");
    assert_eq!(descriptors.iter().filter(|field| field.secret).count(), 1);
    assert_eq!(
        descriptors
            .iter()
            .filter(|field| field.mutability == "immutable")
            .count(),
        1
    );
}

#[test]
fn checked_in_example_is_exact_unresolved_default_render_and_roundtrips() {
    let example = include_str!("../examples/default-config.yaml");
    let defaults = Config::default();
    assert_eq!(render_effective_yaml(&defaults).unwrap(), example);
    let decoded = decode(example).unwrap();
    assert!(decoded.warnings.is_empty());
    assert_eq!(decoded.config, defaults);
    assert_eq!(render_effective_yaml(&decoded.config).unwrap(), example);
}

#[test]
fn documentation_lists_every_current_descriptor_without_stale_defaults() {
    let mut table = String::from(
        "| Setting | JSON type | Default | Legacy flag | Environment | Mutability | Secret |\n\
         | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for field in describe_settings() {
        writeln!(
            table,
            "| `{}` | {} | `{}` | {} | {} | {} | {} |",
            field.path,
            field.json_type,
            field.default,
            field.flag.unwrap_or("—"),
            field.envar.unwrap_or("—"),
            field.mutability,
            field.secret,
        )
        .unwrap();
    }
    let document = include_str!("../SCHEMA.md");
    let (_, content) = document.split_once("<!-- settings:start -->\n").unwrap();
    let (actual, _) = content.split_once("<!-- settings:end -->").unwrap();
    assert_eq!(actual, table);
}
