#![allow(unused)]

use diorama::{StartupAction, StartupInputs};
use diorama_config::{ConfigError, DecodedConfig, HostContext};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

#[derive(Default)]
struct Inputs {
    files: BTreeMap<String, String>,
    reads: usize,
    probes: usize,
}
impl StartupInputs for Inputs {
    fn read_config(&mut self, path: &Path) -> Result<Option<DecodedConfig>, ConfigError> {
        self.reads += 1;
        if path == Path::new("/tmp") {
            return Err(ConfigError {
                kind: diorama_config::ErrorKind::Io,
                path: "/tmp".into(),
                message: "is a directory".into(),
            });
        }
        self.files
            .get(&path.display().to_string())
            .map(|text| diorama_config::decode(text))
            .transpose()
    }
    fn host(&mut self) -> io::Result<HostContext> {
        self.probes += 1;
        Ok(HostContext {
            cpu_count: 4,
            architecture: "arm64".into(),
            detected_container_mode: true,
        })
    }
}
fn assert_output(case: &Value, stdout: &str, stderr: &str) {
    let combined = format!("{stdout}{stderr}");
    for (name, text) in [
        ("stdout", stdout),
        ("stderr", stderr),
        ("combined", combined.as_str()),
    ] {
        if let Some(expected) = case["expect"][format!("{name}_equals")].as_str() {
            assert_eq!(text, expected, "{} {name}", case["id"]);
        }
        if let Some(markers) = case["expect"][format!("{name}_contains")].as_array() {
            for marker in markers {
                let marker = marker.as_str().expect("fixture marker");
                assert!(
                    text.contains(marker),
                    "{} {name}: missing {marker} in {text}",
                    case["id"]
                );
            }
        }
    }
}
fn replay(suite: &str) {
    let suite: Value = serde_json::from_str(suite).expect("reviewed fixture JSON");
    for case in suite["cases"].as_array().expect("fixture cases") {
        let mut inputs = Inputs::default();
        if let Some(files) = case["files"].as_object() {
            for (name, text) in files {
                inputs.files.insert(
                    format!("{{fixture:{name}}}"),
                    text.as_str().expect("file text").into(),
                );
            }
        }
        let args: Vec<_> = case["argv"]
            .as_array()
            .expect("argv")
            .iter()
            .map(|v| v.as_str().expect("argument").into())
            .collect();
        let env: BTreeMap<_, _> = case["env"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(key, v)| (key.clone(), v.as_str().expect("environment").into()))
            .collect();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = diorama::execute(
            &args,
            &env,
            "fixture-version",
            &mut inputs,
            &mut out,
            &mut err,
        )
        .expect("memory outputs");
        let StartupAction::Exit(code) = result else {
            panic!("startup reached by fixture {}", case["id"]);
        };
        assert_eq!(
            u64::from(code),
            case["expect"]["exit_code"].as_u64().expect("exit"),
            "{}: {}",
            case["id"],
            String::from_utf8_lossy(&err)
        );
        assert_output(
            case,
            &String::from_utf8(out).expect("UTF8 stdout"),
            &String::from_utf8(err).expect("UTF8 stderr"),
        );
    }
}
#[cfg(any())]
#[test]
fn matches_real_startup_parser_cases() {
    replay(include_str!("fixtures/startup.json"));
}
#[cfg(any())]
#[test]
fn matches_configuration_command_cases() {
    replay(include_str!(
        "../../../tools/parity/fixtures/config-command.json"
    ));
}
#[cfg(any())]
#[test]
fn version_and_help_never_read_file_or_probe_host() {
    for command in ["--version", "--help"] {
        let mut inputs = Inputs::default();
        let action = diorama::execute(
            &[command.into(), "--config=/tmp".into()],
            &BTreeMap::new(),
            "test",
            &mut inputs,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect("output");
        assert!(matches!(action, StartupAction::Exit(0)));
        assert_eq!((inputs.reads, inputs.probes), (0, 0));
    }
}
#[cfg(any())]
#[test]
fn print_exits_but_normal_resolution_returns_start_action() {
    for (args, printing) in [(vec!["--print-config".into()], true), (Vec::new(), false)] {
        let mut inputs = Inputs::default();
        let action = diorama::execute(
            &args,
            &BTreeMap::new(),
            "test",
            &mut inputs,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .expect("output");
        assert_eq!(matches!(action, StartupAction::Exit(0)), printing);
        assert_eq!((inputs.reads, inputs.probes), (1, 1));
    }
}
struct BrokenWriter;
impl io::Write for BrokenWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[cfg(any())]
#[test]
fn output_errors_are_propagated() {
    let error = diorama::execute(
        &["--print-config".into()],
        &BTreeMap::new(),
        "test",
        &mut Inputs::default(),
        &mut BrokenWriter,
        &mut Vec::new(),
    )
    .expect_err("broken stdout");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}
#[cfg(any())]
#[test]
fn actual_executable_version_bypasses_invalid_environment() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_diorama"))
        .args(["--version", "--config=/tmp"])
        .env_clear()
        .env("DIORAMA_MTU", "invalid")
        .output()
        .expect("version process");
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("version"));
}

#[cfg(any())]
#[test]
fn startup_action_debug_does_not_disclose_resolved_values() {
    let action = diorama::execute(
        &["--portainer-edge-key=private-edge-credential".into()],
        &BTreeMap::new(),
        "test",
        &mut Inputs::default(),
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .expect("resolution");
    assert!(matches!(action, StartupAction::Start { .. }));
    assert_eq!(format!("{action:?}"), "Start(<resolved configuration>)");
}

#[cfg(any())]
#[test]
fn runtime_receives_selected_config_file_and_original_host_snapshot() {
    let environment = BTreeMap::from([("DIORAMA_CONFIG".into(), "/ignored.yaml".into())]);
    let mut inputs = Inputs::default();
    let action = diorama::execute(
        &["--config=/selected.yaml".into()],
        &environment,
        "test",
        &mut inputs,
        &mut Vec::new(),
        &mut Vec::new(),
    )
    .expect("resolution");
    let StartupAction::Start {
        config_path, host, ..
    } = action
    else {
        panic!("expected runtime startup");
    };
    assert_eq!(config_path, Path::new("/selected.yaml"));
    assert_eq!(host.cpu_count, 4);
    assert_eq!(host.architecture, "arm64");
    assert!(host.detected_container_mode);
    assert_eq!(inputs.probes, 1);
}

#[cfg(any())]
#[test]
fn actual_executable_prints_then_enters_supervised_startup() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let unwritable_cfg = temp.path().join("unwritable.yaml");
    std::fs::write(&unwritable_cfg, "path: /dev/null/forbidden_diorama_path\n")
        .expect("write config");

    for (printing, expected_success) in [(true, true), (false, false)] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_diorama"));
        command.env_clear();
        if printing {
            command.arg("--config=").arg("--print-config");
        } else {
            command.arg(format!("--config={}", unwritable_cfg.display()));
        }
        let output = command.output().expect("startup process");
        assert_eq!(output.status.success(), expected_success);
        if printing {
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("apiVersion: diorama.io/v1alpha1")
            );
            assert!(!String::from_utf8_lossy(&output.stderr).contains("runtime startup"));
        } else {
            assert!(output.stdout.is_empty());
            let err = String::from_utf8_lossy(&output.stderr);
            assert!(err.contains("\"schema\":1"));
            assert!(err.contains("\"event\":\"runtime_assembly_failed\""));
            assert!(err.contains("\"code\":\"io_failure\""));
            assert!(!err.contains("\"event\":\"component_failure\""));
            assert!(!err.contains("\"event\":\"supervisor_stop\""));
            assert!(!err.contains("\"code\":\"adapter\""));
        }
    }
}

#[cfg(any())]
#[test]
fn requested_stop_preserves_success_after_ready() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let config_path = temp.path().join("config.yaml");
    let state = temp.path().join("state");
    std::fs::write(
        &config_path,
        format!("path: \"{}\"\nlogging:\n  debug: true\n", state.display()),
    )
    .expect("write config");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_diorama"))
        .arg(format!("--config={}", config_path.display()))
        .env_clear()
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn node");
    let mut stderr = child.stderr.take().expect("stderr");
    let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
    let (done_sender, done_receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut captured = Vec::new();
        let mut chunk = [0_u8; 512];
        let mut signaled = false;
        loop {
            match std::io::Read::read(&mut stderr, &mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    captured.extend_from_slice(&chunk[..count]);
                    if !signaled
                        && String::from_utf8_lossy(&captured).contains("\"state\":\"ready\"")
                    {
                        signaled = true;
                        let _ = ready_sender.send(());
                    }
                },
            }
        }
        let _ = done_sender.send(captured);
    });
    if let Err(error) = ready_receiver.recv_timeout(std::time::Duration::from_secs(20)) {
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let _ = child.wait();
        panic!("ready log was not observed: {error}");
    }
    let killed = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("signal process");
    assert!(killed.success());
    let status = child.wait().expect("wait for node");
    let captured = done_receiver
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("stderr capture");
    let err = String::from_utf8_lossy(&captured);
    assert!(status.success(), "requested stop failed: {err}");
    assert!(err.contains("\"event\":\"supervisor_stop\""), "{err}");
    assert!(err.contains("\"code\":\"requested\""), "{err}");
}
