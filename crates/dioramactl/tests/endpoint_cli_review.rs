#![cfg(unix)]

use std::collections::BTreeMap;
use std::os::unix::fs::{PermissionsExt, symlink};

use dioramactl::KubeconfigOptions;
use dioramactl::endpoints::{EnginePortInspector, UnavailableEngine, execute_endpoint_command};
use serde_json::json;

struct Inspector;
impl EnginePortInspector for Inspector {
    fn inspect_port(&mut self, _: &str, _: u16) -> std::io::Result<String> {
        Ok("127.0.0.1:49153".into())
    }
}

fn document() -> String {
    json!({"apiVersion":"v1","kind":"Config","clusters":[{"name":"dev","cluster":{"server":"https://original:6443"}}],"contexts":[{"name":"dev","context":{"cluster":"dev"}}],"users":[]}).to_string()
}

#[test]
fn malformed_input_reports_path_without_parser_secrets_or_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    let original = "secret-token: [NEVER-PRINT-THIS";
    std::fs::write(&path, original).unwrap();
    for command in ["route", "remove"] {
        let options = KubeconfigOptions {
            subcommand: Some(command.into()),
            name: Some("dev".into()),
            output: Some(path.clone()),
            ..Default::default()
        };
        let mut stderr = Vec::new();
        assert_eq!(
            execute_endpoint_command(
                &options,
                &mut UnavailableEngine,
                &BTreeMap::new(),
                &mut Vec::new(),
                &mut stderr
            )
            .unwrap(),
            1
        );
        let error = String::from_utf8(stderr).unwrap();
        assert!(error.contains("invalid kubeconfig"));
        assert!(error.contains(&path.display().to_string()));
        assert!(!error.contains("NEVER-PRINT-THIS"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[test]
fn backup_failure_never_announces_success_for_route_or_remove() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("original");
    let path = dir.path().join("config");
    std::fs::write(&target, document()).unwrap();
    symlink(&target, &path).unwrap();
    for command in ["route", "remove"] {
        let options = KubeconfigOptions {
            subcommand: Some(command.into()),
            name: Some("dev".into()),
            output: Some(path.clone()),
            ..Default::default()
        };
        let mut stdout = Vec::new();
        assert!(
            execute_endpoint_command(
                &options,
                &mut Inspector,
                &BTreeMap::new(),
                &mut stdout,
                &mut Vec::new()
            )
            .is_err()
        );
        assert!(stdout.is_empty());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), document());
    }
}

#[test]
fn production_cli_inspects_named_container_and_preserves_config_on_engine_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    let docker = dir.path().join("docker");
    std::fs::write(&docker, "#!/bin/sh\n[ \"$1\" = port ] && [ \"$2\" = kubesolo-dev ] && [ \"$3\" = 6443/tcp ] || exit 9\nprintf '%s\\n' 127.0.0.1:49153\n").unwrap();
    std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(&path, document()).unwrap();
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_dioramactl"))
            .env_clear()
            .env("PATH", dir.path())
            .env("HOME", dir.path())
            .args(["kubeconfig", "route", "--name", "dev", "--output"])
            .arg(&path)
            .output()
            .unwrap()
    };
    let output = run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let changed = std::fs::read_to_string(&path).unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&changed).unwrap();
    assert_eq!(
        cfg["clusters"][0]["cluster"]["server"],
        "https://127.0.0.1:49153"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Routed context"));
    let stderr = String::from_utf8(output.stderr).unwrap();
    let backup = stderr
        .trim()
        .strip_prefix("Created backup of existing kubeconfig at ")
        .unwrap();
    assert_eq!(std::fs::read_to_string(backup).unwrap(), document());
    std::fs::write(&docker, "#!/bin/sh\nexit 7\n").unwrap();
    let failure = run();
    assert!(!failure.status.success());
    assert!(failure.stdout.is_empty());
    assert!(String::from_utf8_lossy(&failure.stderr).contains("port inspection failed"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), changed);
}

#[test]
fn unknown_endpoint_subcommand_fails_before_read_or_inspection() {
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let options = dioramactl::contract::KubeconfigOptions {
        subcommand: Some("rmove".into()),
        name: Some("dev".into()),
        ..Default::default()
    };
    let code = dioramactl::endpoints::execute_endpoint_command(
        &options,
        &mut dioramactl::endpoints::UnavailableEngine,
        &std::collections::BTreeMap::new(),
        &mut output,
        &mut errors,
    )
    .unwrap();
    assert_eq!(code, 1);
    assert!(output.is_empty());
    assert!(String::from_utf8(errors).unwrap().contains("unknown"));
}

#[test]
fn published_endpoint_requires_consistent_loopback_reachable_bindings() {
    for text in [
        "garbage:1234",
        "0.0.0.0:0",
        "0.0.0.0:1\n[::]:2",
        "192.0.2.1:1234",
        "0.0.0.0:1234\ngarbage",
    ] {
        assert!(
            dioramactl::endpoints::resolve_published_endpoint(text).is_err(),
            "{text}"
        );
    }
    assert_eq!(
        dioramactl::endpoints::resolve_published_endpoint("0.0.0.0:1234\n[::]:1234")
            .unwrap()
            .port,
        1234
    );
}
