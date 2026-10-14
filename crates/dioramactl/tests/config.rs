use diorama_config::{Config, write_document};
use dioramactl::{CheckInputs, execute};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;

#[derive(Default)]
struct DummyInputs;

impl CheckInputs for DummyInputs {
    fn discover(
        &mut self,
    ) -> Result<diorama_platform::HostEvidence, diorama_platform::PlatformError> {
        Err(diorama_platform::PlatformError::UnsupportedHost)
    }
    fn supplemental(
        &mut self,
    ) -> Result<diorama_platform::preflight_probe::SupplementalFacts, diorama_platform::PlatformError>
    {
        Err(diorama_platform::PlatformError::UnsupportedHost)
    }
    fn ports(
        &mut self,
        _pprof: bool,
    ) -> Result<
        [diorama_platform::Observation<diorama_platform::preflight::PortAvailability>; 4],
        diorama_platform::PlatformError,
    > {
        Err(diorama_platform::PlatformError::UnsupportedHost)
    }
}

fn args(slice: &[&str]) -> Vec<String> {
    slice.iter().map(|s| (*s).to_string()).collect()
}

// -----------------------------------------------------------------------------
// 1. Path command tests
// -----------------------------------------------------------------------------

#[test]
fn test_config_path_resolution() {
    let mut inputs = DummyInputs;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    // Default path
    let (_socket_dir, env) = isolated_environment();
    let code = execute(
        &args(&["config", "path"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(
        String::from_utf8_lossy(&stdout).trim(),
        "/etc/diorama/config.yaml"
    );

    // KUBESOLO_CONFIG environment variable
    stdout.clear();
    let mut env_custom = BTreeMap::new();
    env_custom.insert(
        "KUBESOLO_CONFIG".to_string(),
        "/custom/path/config.yaml".to_string(),
    );
    let code = execute(
        &args(&["config", "path"]),
        &env_custom,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(
        String::from_utf8_lossy(&stdout).trim(),
        "/custom/path/config.yaml"
    );

    // Explicit -f flag overrides
    stdout.clear();
    let code = execute(
        &args(&["config", "-f", "/explicit/flag.yaml", "path"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(
        String::from_utf8_lossy(&stdout).trim(),
        "/explicit/flag.yaml"
    );
}

// -----------------------------------------------------------------------------
// 2. Schema command tests (fallback & socket)
// -----------------------------------------------------------------------------

#[test]
fn test_config_schema_fallback() {
    let mut inputs = DummyInputs;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let (socket_dir, env) = isolated_environment();
    let missing = socket_dir.path().join("missing.yaml");

    let code = execute(
        &args(&["config", "-f", missing.to_str().unwrap(), "schema"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    let output = String::from_utf8_lossy(&stdout);
    assert!(output.contains("\"apiVersion\": \"kubesolo.io/v1alpha1\""));
    assert!(output.contains("\"settings\":"));
    assert!(output.contains("\"network.mtu\""));
}

// -----------------------------------------------------------------------------
// 3. Validate command tests (direct file fallback)
// -----------------------------------------------------------------------------

#[test]
fn test_config_validate_direct_file() {
    let tmp = tempfile::tempdir().unwrap();
    let valid_file = tmp.path().join("valid.yaml");
    let invalid_file = tmp.path().join("invalid.yaml");

    let cfg = Config::default();
    write_document(&valid_file, &cfg).unwrap();

    fs::write(&invalid_file, b"network:\n  mtu: not_a_number\n").unwrap();

    let mut inputs = DummyInputs;
    let (socket_dir, env) = isolated_environment();
    let missing = socket_dir.path().join("missing.yaml");
    let missing = missing.to_str().unwrap();

    // Valid file
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = execute(
        &args(&[
            "config",
            "-f",
            missing,
            "validate",
            valid_file.to_str().unwrap(),
        ]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(
        String::from_utf8_lossy(&stdout).trim(),
        "Configuration is valid"
    );

    // Invalid file
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&[
            "config",
            "-f",
            missing,
            "validate",
            invalid_file.to_str().unwrap(),
        ]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&stderr).contains("error:"));

    // Non-existent file
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&[
            "config",
            "-f",
            missing,
            "validate",
            "/nonexistent/config.yaml",
        ]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&stderr).contains("error: configuration file not found"));
}

// -----------------------------------------------------------------------------
// 4. Get command tests (full redacted, individual scalar & object keys, missing)
// -----------------------------------------------------------------------------

#[test]
fn test_config_get_direct_file() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("config.yaml");

    let mut cfg = Config::default();
    cfg.network.node_ip = "192.168.1.100".into();
    cfg.network.mtu = 1400;
    cfg.portainer.edge_key = "secret_key_123".into();
    write_document(&file, &cfg).unwrap();

    let mut inputs = DummyInputs;
    let (_socket_dir, env) = isolated_environment();

    // Full config: redacted secrets
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = execute(
        &args(&["config", "-f", file.to_str().unwrap(), "get"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    let output = String::from_utf8_lossy(&stdout);
    assert!(output.contains("nodeIP: 192.168.1.100"));
    assert!(output.contains("edgeKey: '***'") || output.contains("edgeKey: \"***\""));
    assert!(!output.contains("secret_key_123"));

    // Individual scalar key
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&[
            "config",
            "-f",
            file.to_str().unwrap(),
            "get",
            "network.nodeIP",
        ]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "192.168.1.100");

    // Integer scalar key
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&["config", "-f", file.to_str().unwrap(), "get", "network.mtu"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "1400");

    // Unknown key
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&[
            "config",
            "-f",
            file.to_str().unwrap(),
            "get",
            "nonexistent.key",
        ]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 1);
    assert!(
        String::from_utf8_lossy(&stderr).contains("error: setting \"nonexistent.key\" not found")
    );
}

// -----------------------------------------------------------------------------
// 5. Set command tests (direct file fallback, validation & restart warning)
// -----------------------------------------------------------------------------

#[test]
fn test_config_set_direct_file() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("config.yaml");

    let cfg = Config::default();
    write_document(&file, &cfg).unwrap();

    let mut inputs = DummyInputs;
    let (_socket_dir, env) = isolated_environment();

    // Set network.mtu 1400
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = execute(
        &args(&[
            "config",
            "-f",
            file.to_str().unwrap(),
            "set",
            "network.mtu",
            "1400",
        ]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert!(
        String::from_utf8_lossy(&stderr)
            .contains("Warning: Restart required for changes to take effect")
    );

    // Verify it took effect
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&["config", "-f", file.to_str().unwrap(), "get", "network.mtu"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "1400");

    // Invalid value type
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&[
            "config",
            "-f",
            file.to_str().unwrap(),
            "set",
            "network.mtu",
            "not_int",
        ]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&stderr).contains("error:"));

    // Unknown setting
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&[
            "config",
            "-f",
            file.to_str().unwrap(),
            "set",
            "invalid.key",
            "val",
        ]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&stderr).contains("error: setting \"invalid.key\" not found"));
}

// -----------------------------------------------------------------------------
// 6. Edit command tests (mock editor, unchanged, modified, error)
// -----------------------------------------------------------------------------

#[test]
fn test_config_edit_direct_file() {
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("config.yaml");

    let cfg = Config::default();
    write_document(&file, &cfg).unwrap();

    let mut inputs = DummyInputs;
    let (_socket_dir, mut env) = isolated_environment();

    // Mock editor 1: true (does nothing, leaves file unchanged)
    env.insert("EDITOR".into(), "true".into());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = execute(
        &args(&["config", "-f", file.to_str().unwrap(), "edit"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(
        String::from_utf8_lossy(&stdout).trim(),
        "Configuration unchanged"
    );

    // Mock editor 2: false (exits non-zero)
    env.insert("EDITOR".into(), "false".into());
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&["config", "-f", file.to_str().unwrap(), "edit"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&stderr).contains("error: editor exited with non-zero status"));

    // Mock editor 3: custom script that modifies YAML
    let script = tmp.path().join("editor.sh");
    fs::write(
        &script,
        b"#!/bin/sh\nsed -i '' 's/mtu: 0/mtu: 1350/g' \"$1\" 2>/dev/null || sed -i 's/mtu: 0/mtu: 1350/g' \"$1\"\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    env.insert("EDITOR".into(), script.to_str().unwrap().into());
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&["config", "-f", file.to_str().unwrap(), "edit"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert!(
        String::from_utf8_lossy(&stderr)
            .contains("Warning: Restart required for changes to take effect")
    );

    // Verify change took effect in file
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&["config", "-f", file.to_str().unwrap(), "get", "network.mtu"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "1350");
}

// -----------------------------------------------------------------------------
// 7. Socket-backed operations tests (mock server)
// -----------------------------------------------------------------------------

#[test]
fn test_config_commands_via_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("config.sock");
    let config_path = tmp.path().join("config.yaml");

    let mut initial_config = Config::default();
    initial_config.api.enabled = true;
    initial_config.api.socket_path = socket_path.to_str().unwrap().to_string();
    write_document(&config_path, &initial_config).unwrap();

    let listener = UnixListener::bind(&socket_path).unwrap();

    // Spawn simple mock server
    let server_handle = std::thread::spawn(move || {
        // Handle 1: GET /api/v1/config/schema
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            if req.contains("GET /api/v1/config/schema") {
                let body = "{\"apiVersion\":\"kubesolo.io/v1alpha1\",\"mock\":true}\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
            }
        }

        // Handle 2: GET /api/v1/config followed by PATCH
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            if req.contains("GET /api/v1/config") {
                let body = "{\"config\":{\"network\":{\"mtu\":1500}},\"restartRequired\":false}\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nETag: \"etag-123\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
            }
        }

        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            if req.contains("PATCH /api/v1/config") {
                assert!(req.contains("If-Match: \"etag-123\""));
                assert!(req.contains("\"mtu\":1420"));
                let body = "{\"config\":{\"network\":{\"mtu\":1420}},\"changed\":[\"network.mtu\"],\"restartRequired\":true}\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nETag: \"etag-456\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
            }
        }
    });

    let mut inputs = DummyInputs;
    let env = BTreeMap::new();

    // 1. Schema via socket (auto resolved via config.yaml api.socketPath)
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = execute(
        &args(&["config", "-f", config_path.to_str().unwrap(), "schema"]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert!(String::from_utf8_lossy(&stdout).contains("\"mock\":true"));

    // 2. Set via socket (triggers GET ETag, then PATCH with If-Match and restartRequired warning)
    stdout.clear();
    stderr.clear();
    let code = execute(
        &args(&[
            "config",
            "-f",
            config_path.to_str().unwrap(),
            "set",
            "network.mtu",
            "1420",
        ]),
        &env,
        "v0.1.0",
        &mut inputs,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 0);
    assert!(
        String::from_utf8_lossy(&stderr)
            .contains("Warning: Restart required for changes to take effect")
    );

    server_handle.join().unwrap();
}

// Keep every direct-file test away from a real host API.
fn isolated_environment() -> (tempfile::TempDir, BTreeMap<String, String>) {
    let dir = tempfile::tempdir().unwrap();
    let env = BTreeMap::from([(
        "KUBESOLO_API_SOCKET_PATH".into(),
        dir.path().join("absent.sock").to_str().unwrap().into(),
    )]);
    (dir, env)
}

#[test]
fn empty_config_environment_uses_default_and_explicit_file_wins() {
    let env = BTreeMap::from([("KUBESOLO_CONFIG".into(), String::new())]);
    assert_eq!(
        dioramactl::resolve_config_path(None, &env),
        std::path::Path::new("/etc/diorama/config.yaml")
    );
    assert_eq!(
        dioramactl::resolve_config_path(Some(std::path::Path::new("/explicit")), &env),
        std::path::Path::new("/explicit")
    );
}

#[test]
fn keyed_secret_output_is_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.yaml");
    let mut cfg = Config::default();
    cfg.portainer.edge_key = "private-key".into();
    write_document(&file, &cfg).unwrap();
    let (_socket_dir, env) = isolated_environment();
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        execute(
            &args(&[
                "config",
                "-f",
                file.to_str().unwrap(),
                "get",
                "portainer.edgeKey"
            ]),
            &env,
            "test",
            &mut DummyInputs,
            &mut out,
            &mut err
        )
        .unwrap(),
        0
    );
    assert_eq!(String::from_utf8(out).unwrap().trim(), "***");
    assert_eq!(
        diorama_config::read_file(&file)
            .unwrap()
            .unwrap()
            .config
            .portainer
            .edge_key,
        "private-key"
    );
}

#[test]
fn api_get_failures_preserve_file_and_do_not_open_editor() {
    for action in ["set", "edit"] {
        for status in [403, 500] {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("config.yaml");
            let mut config = Config::default();
            config.api.enabled = true;
            write_document(&file, &config).unwrap();
            let before = fs::read(&file).unwrap();
            let socket = dir.path().join("api.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0; 4096];
                assert!(stream.read(&mut buf).unwrap() > 0);
                write!(
                    stream,
                    "HTTP/1.1 {status} Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            });
            let env = BTreeMap::from([
                (
                    "KUBESOLO_API_SOCKET_PATH".into(),
                    socket.to_str().unwrap().into(),
                ),
                ("EDITOR".into(), "/nonexistent-editor".into()),
            ]);
            let mut argv = args(&["config", "-f", file.to_str().unwrap(), action]);
            if action == "set" {
                argv.extend(args(&["network.mtu", "1400"]));
            }
            let mut out = Vec::new();
            let mut err = Vec::new();
            assert_eq!(
                execute(&argv, &env, "test", &mut DummyInputs, &mut out, &mut err).unwrap(),
                1
            );
            assert!(
                String::from_utf8(err)
                    .unwrap()
                    .contains(&status.to_string())
            );
            assert_eq!(fs::read(&file).unwrap(), before);
            server.join().unwrap();
        }
    }
}

#[test]
fn malformed_successful_api_document_is_not_echoed_in_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.yaml");
    let socket = dir.path().join("api.sock");
    let mut cfg = Config::default();
    cfg.api.enabled = true;
    write_document(&file, &cfg).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        let body = r#"{"config":{"portainer":{"edgeKey":"private-review-marker"},"network":{"mtu":"invalid"}}}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let env = BTreeMap::from([(
        "KUBESOLO_API_SOCKET_PATH".into(),
        socket.to_str().unwrap().into(),
    )]);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        execute(
            &args(&["config", "-f", file.to_str().unwrap(), "get"]),
            &env,
            "test",
            &mut DummyInputs,
            &mut stdout,
            &mut stderr
        )
        .unwrap(),
        1
    );
    let diagnostic = String::from_utf8(stderr).unwrap();
    assert!(diagnostic.contains("invalid configuration document"));
    assert!(!diagnostic.contains("private-review-marker"));
    assert_eq!(stdout, <[u8; 0]>::default());
    server.join().unwrap();
}

#[test]
fn disabled_api_and_missing_config_do_not_select_host_socket() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.yaml");
    let socket = dir.path().join("api.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    let env = BTreeMap::from([(
        "KUBESOLO_API_SOCKET_PATH".into(),
        socket.to_str().unwrap().into(),
    )]);
    write_document(&file, &Config::default()).unwrap();
    assert!(
        dioramactl::resolve_socket_path(&file, &env)
            .unwrap()
            .is_none()
    );
    assert!(
        dioramactl::resolve_socket_path(&dir.path().join("absent.yaml"), &env)
            .unwrap()
            .is_none()
    );
    fs::write(&file, "network: [broken").unwrap();
    assert!(dioramactl::resolve_socket_path(&file, &env).is_err());
}

#[test]
fn direct_file_set_rejects_redaction_placeholder() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.yaml");
    let mut cfg = Config::default();
    cfg.portainer.edge_key = "private-key".into();
    write_document(&file, &cfg).unwrap();
    let before = fs::read(&file).unwrap();
    let (_socket_dir, env) = isolated_environment();
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        execute(
            &args(&[
                "config",
                "-f",
                file.to_str().unwrap(),
                "set",
                "portainer.edgeKey",
                "***"
            ]),
            &env,
            "test",
            &mut DummyInputs,
            &mut out,
            &mut err
        )
        .unwrap(),
        1
    );
    assert_eq!(fs::read(file).unwrap(), before);
}

#[test]
fn editor_arguments_work_and_failed_edits_are_recoverable() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.yaml");
    write_document(&file, &Config::default()).unwrap();
    let before = fs::read(&file).unwrap();
    let (_socket_dir, mut env) = isolated_environment();
    env.insert("EDITOR".into(), String::new());
    env.insert("VISUAL".into(), "true --".into());
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        execute(
            &args(&["config", "-f", file.to_str().unwrap(), "edit"]),
            &env,
            "test",
            &mut DummyInputs,
            &mut out,
            &mut err
        )
        .unwrap(),
        0
    );
    let editor = dir.path().join("editor with spaces");
    fs::write(&editor, "#!/bin/sh\nprintf 'network: [broken' > \"$1\"\n").unwrap();
    fs::set_permissions(&editor, fs::Permissions::from_mode(0o755)).unwrap();
    env.insert("EDITOR".into(), format!("'{}'", editor.display()));
    err.clear();
    assert_eq!(
        execute(
            &args(&["config", "-f", file.to_str().unwrap(), "edit"]),
            &env,
            "test",
            &mut DummyInputs,
            &mut out,
            &mut err
        )
        .unwrap(),
        1
    );
    let diagnostic = String::from_utf8(err).unwrap();
    let retained = diagnostic
        .lines()
        .find_map(|line| line.strip_prefix("Edited configuration retained at "))
        .unwrap();
    assert_eq!(fs::read_to_string(retained).unwrap(), "network: [broken");
    assert_eq!(
        fs::metadata(retained).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read(file).unwrap(), before);
    fs::remove_file(retained).unwrap();
}
