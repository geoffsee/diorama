use crate::CheckInputs;
use crate::contract::ConfigOptions;
use diorama_config::{
    API_VERSION, Config, FIELDS, HostContext, apply_merge_patch, apply_put_replacement,
    describe_settings, has_redacted_secrets, parse_setting, read_file, redact_secrets,
    render_effective_yaml, write_document,
};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

const DEFAULT_CONFIG_PATH: &str = "/etc/diorama/config.yaml";
const DEFAULT_DATA_PATH: &str = "/var/lib/diorama";
const DEFAULT_SOCKET_NAME: &str = "config.sock";
const RESTART_WARNING: &str = "Warning: Restart required for changes to take effect\n";

/// Resolves the configuration file path.
/// Priority: explicit `-f`/`--file`, then `$DIORAMA_CONFIG`, then `/etc/diorama/config.yaml`.
#[must_use]
pub fn resolve_config_path(
    explicit_file: Option<&Path>,
    environment: &BTreeMap<String, String>,
) -> PathBuf {
    if let Some(path) = explicit_file {
        path.to_path_buf()
    } else if let Some(env_path) = environment.get("DIORAMA_CONFIG") {
        if env_path.is_empty() {
            PathBuf::from(DEFAULT_CONFIG_PATH)
        } else {
            PathBuf::from(env_path)
        }
    } else {
        PathBuf::from(DEFAULT_CONFIG_PATH)
    }
}

/// Resolves the Unix domain socket path.
/// Priority: `$DIORAMA_API_SOCKET_PATH`, then resolved config `api.socket_path`,
/// then if stored config has `path`, `<path>/config.sock`, then `/var/lib/diorama/config.sock`.
pub fn resolve_socket_path(
    config_path: &Path,
    environment: &BTreeMap<String, String>,
) -> io::Result<Option<PathBuf>> {
    let Some(decoded) = read_file(config_path)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
    else {
        return Ok(None);
    };
    if !decoded.config.api.enabled {
        return Ok(None);
    }
    if let Some(env_socket) = environment.get("DIORAMA_API_SOCKET_PATH")
        && !env_socket.is_empty()
    {
        return Ok(Some(PathBuf::from(env_socket)));
    }

    if !decoded.config.api.socket_path.is_empty() {
        return Ok(Some(PathBuf::from(&decoded.config.api.socket_path)));
    }
    if !decoded.config.path.is_empty() {
        return Ok(Some(
            Path::new(&decoded.config.path).join(DEFAULT_SOCKET_NAME),
        ));
    }
    Ok(Some(Path::new(DEFAULT_DATA_PATH).join(DEFAULT_SOCKET_NAME)))
}

struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

/// Performs a synchronous HTTP/1.1 request over a Unix domain socket.
/// Returns `None` if the socket cannot be connected (e.g. `NotFound` or `ConnectionRefused`).
fn socket_request(
    socket_path: Option<&Path>,
    method: &str,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> io::Result<Option<HttpResponse>> {
    let Some(socket_path) = socket_path else {
        return Ok(None);
    };
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(s) => s,
        Err(err)
            if err.kind() == io::ErrorKind::NotFound
                || err.kind() == io::ErrorKind::ConnectionRefused =>
        {
            return Ok(None);
        },
        Err(err) => return Err(err),
    };
    let timeout = Some(std::time::Duration::from_secs(30));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;

    let mut request =
        format!("{method} {uri} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    for (k, v) in headers {
        request.push_str(k);
        request.push_str(": ");
        request.push_str(v);
        request.push_str("\r\n");
    }
    let _ = write!(request, "Content-Length: {}\r\n\r\n", body.len());
    request.push_str(body);

    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response_bytes = Vec::new();
    stream.read_to_end(&mut response_bytes)?;

    let Some(header_end) = response_bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete HTTP response from config socket",
        ));
    };

    let header_str = std::str::from_utf8(&response_bytes[..header_end]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid utf-8 headers: {e}"),
        )
    })?;
    let raw_body = std::str::from_utf8(&response_bytes[header_end + 4..]).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid utf-8 body: {e}"),
        )
    })?;

    let mut lines = header_str.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status line"))?;

    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP status line"))?;

    let mut parsed_headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            parsed_headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    Ok(Some(HttpResponse {
        status,
        headers: parsed_headers,
        body: raw_body.to_string(),
    }))
}

/// Executes `dioramactl config` subcommands.
pub fn execute_config(
    options: &ConfigOptions,
    _inputs: &mut dyn CheckInputs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let Some(subcommand) = options.subcommand.as_deref() else {
        write!(stdout, "{}", crate::help(crate::HelpTopic::Config))?;
        return Ok(0);
    };

    let config_path = resolve_config_path(options.file.as_deref(), &options.environment);
    if subcommand == "path" {
        return handle_path(&config_path, stdout);
    }
    let socket_path = match resolve_socket_path(&config_path, &options.environment) {
        Ok(path) => path,
        Err(e) => {
            writeln!(
                stderr,
                "error: failed to resolve configuration backend: {e}"
            )?;
            return Ok(1);
        },
    };

    match subcommand {
        "path" => handle_path(&config_path, stdout),
        "schema" => handle_schema(socket_path.as_deref(), stdout, stderr),
        "validate" => handle_validate(
            options,
            &config_path,
            socket_path.as_deref(),
            stdout,
            stderr,
        ),
        "get" => handle_get(
            options,
            &config_path,
            socket_path.as_deref(),
            stdout,
            stderr,
        ),
        "set" => handle_set(
            options,
            &config_path,
            socket_path.as_deref(),
            stdout,
            stderr,
        ),
        "edit" => handle_edit(
            options,
            &config_path,
            socket_path.as_deref(),
            stdout,
            stderr,
        ),
        other => {
            writeln!(
                stderr,
                "error: unknown config subcommand: '{other}'\nSee 'dioramactl config --help' for usage."
            )?;
            Ok(1)
        },
    }
}

fn handle_path(config_path: &Path, stdout: &mut dyn Write) -> io::Result<u8> {
    writeln!(stdout, "{}", config_path.display())?;
    Ok(0)
}

fn handle_schema(
    socket_path: Option<&Path>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    if let Some(resp) = socket_request(socket_path, "GET", "/api/v1/config/schema", "", &[])? {
        if resp.status == 200 {
            write!(stdout, "{}", resp.body)?;
            if !resp.body.ends_with('\n') {
                writeln!(stdout)?;
            }
            return Ok(0);
        }
        writeln!(
            stderr,
            "error: API returned status {}: {}",
            resp.status,
            extract_error_message(&resp.body)
        )?;
        return Ok(1);
    }

    // Direct fallback
    let schema = serde_json::json!({
        "apiVersion": API_VERSION,
        "settings": describe_settings(),
    });
    let formatted = serde_json::to_string_pretty(&schema)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    writeln!(stdout, "{formatted}")?;
    Ok(0)
}

fn handle_validate(
    options: &ConfigOptions,
    config_path: &Path,
    socket_path: Option<&Path>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let target_file = options
        .key
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| options.file.clone())
        .unwrap_or_else(|| config_path.to_path_buf());

    if !target_file.exists() {
        writeln!(
            stderr,
            "error: configuration file not found: {}",
            target_file.display()
        )?;
        return Ok(1);
    }

    let content = match fs::read_to_string(&target_file) {
        Ok(c) => c,
        Err(e) => {
            writeln!(
                stderr,
                "error: failed to read {}: {e}",
                target_file.display()
            )?;
            return Ok(1);
        },
    };

    let decoded = match diorama_config::decode(&content) {
        Ok(d) => d,
        Err(e) => {
            writeln!(stderr, "error: {e}")?;
            return Ok(1);
        },
    };

    let json_doc = match serde_json::to_string(&decoded.config) {
        Ok(s) => s,
        Err(e) => {
            writeln!(stderr, "error: failed to serialize config to JSON: {e}")?;
            return Ok(1);
        },
    };

    if let Some(resp) = socket_request(
        socket_path,
        "POST",
        "/api/v1/config:validate",
        &json_doc,
        &[("Content-Type", "application/json")],
    )? {
        if resp.status == 200 {
            writeln!(stdout, "Configuration is valid")?;
            return Ok(0);
        }
        let msg = extract_error_message(&resp.body);
        writeln!(stderr, "error: {msg}")?;
        return Ok(1);
    }

    // Direct-file fallback validation
    let host = HostContext::detect();
    if let Err(e) = decoded.config.validate(&host) {
        writeln!(stderr, "error: {e}")?;
        return Ok(1);
    }

    writeln!(stdout, "Configuration is valid")?;
    Ok(0)
}

fn handle_get(
    options: &ConfigOptions,
    config_path: &Path,
    socket_path: Option<&Path>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let config = read_config_for_display(socket_path, config_path, stderr)?;
    let Some(mut config) = config else {
        return Ok(1);
    };

    if let Some(ref key) = options.key {
        handle_get_key(key, &config, stdout, stderr)
    } else {
        redact_secrets(&mut config);
        let yaml = match render_effective_yaml(&config) {
            Ok(y) => y,
            Err(e) => {
                writeln!(stderr, "error: failed to render configuration YAML: {e}")?;
                return Ok(1);
            },
        };
        write!(stdout, "{yaml}")?;
        if !yaml.ends_with('\n') {
            writeln!(stdout)?;
        }
        Ok(0)
    }
}

fn handle_get_key(
    key: &str,
    config: &Config,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    if !FIELDS.iter().any(|f| f.path == key) {
        writeln!(stderr, "error: setting \"{key}\" not found")?;
        return Ok(1);
    }

    let mut display_config = config.clone();
    redact_secrets(&mut display_config);
    let json_val = match serde_json::to_value(display_config) {
        Ok(v) => v,
        Err(e) => {
            writeln!(stderr, "error: {e}")?;
            return Ok(1);
        },
    };

    let pointer = format!("/{}", key.replace('.', "/"));
    let val = json_val.pointer(&pointer);

    match val {
        None | Some(Value::Null) => {
            writeln!(stderr, "error: setting \"{key}\" not found")?;
            Ok(1)
        },
        Some(Value::String(s)) => {
            writeln!(stdout, "{s}")?;
            Ok(0)
        },
        Some(Value::Bool(b)) => {
            writeln!(stdout, "{b}")?;
            Ok(0)
        },
        Some(Value::Number(n)) => {
            writeln!(stdout, "{n}")?;
            Ok(0)
        },
        Some(other) => {
            let formatted = serde_json::to_string_pretty(other)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            writeln!(stdout, "{formatted}")?;
            Ok(0)
        },
    }
}

fn handle_set(
    options: &ConfigOptions,
    config_path: &Path,
    socket_path: Option<&Path>,
    _stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let (Some(key), Some(value_str)) = (options.key.as_deref(), options.value.as_deref()) else {
        writeln!(
            stderr,
            "error: 'set' requires both a key and a value\nUsage: dioramactl config set <key> <value>"
        )?;
        return Ok(1);
    };

    if !FIELDS.iter().any(|f| f.path == key) {
        writeln!(stderr, "error: setting \"{key}\" not found")?;
        return Ok(1);
    }

    let parsed_val = match parse_setting(key, value_str) {
        Ok(v) => v,
        Err(e) => {
            writeln!(stderr, "error: {e}")?;
            return Ok(1);
        },
    };

    let patch = build_nested_json(key, parsed_val);
    let patch_json = match serde_json::to_string(&patch) {
        Ok(s) => s,
        Err(e) => {
            writeln!(stderr, "error: failed to serialize patch: {e}")?;
            return Ok(1);
        },
    };

    if let Some(code) = try_socket_set(socket_path, &patch_json, stderr)? {
        return Ok(code);
    }

    fallback_file_set(config_path, &patch, stderr)
}

fn try_socket_set(
    socket_path: Option<&Path>,
    patch_json: &str,
    stderr: &mut dyn Write,
) -> io::Result<Option<u8>> {
    let Some(get_resp) = socket_request(socket_path, "GET", "/api/v1/config", "", &[])? else {
        return Ok(None);
    };
    if get_resp.status != 200 {
        writeln!(
            stderr,
            "error: API returned status {}: {}",
            get_resp.status,
            extract_error_message(&get_resp.body)
        )?;
        return Ok(Some(1));
    }

    let etag = get_resp.headers.get("etag").cloned().unwrap_or_default();
    let mut headers = vec![("Content-Type", "application/merge-patch+json")];
    if !etag.is_empty() {
        headers.push(("If-Match", &etag));
    }

    let Some(patch_resp) =
        socket_request(socket_path, "PATCH", "/api/v1/config", patch_json, &headers)?
    else {
        writeln!(stderr, "error: config API became unavailable during update")?;
        return Ok(Some(1));
    };

    if patch_resp.status == 200 {
        if check_restart_required(&patch_resp.body) {
            write!(stderr, "{RESTART_WARNING}")?;
        }
        return Ok(Some(0));
    }

    let msg = extract_error_message(&patch_resp.body);
    writeln!(stderr, "error: {msg}")?;
    Ok(Some(1))
}

fn fallback_file_set(config_path: &Path, patch: &Value, stderr: &mut dyn Write) -> io::Result<u8> {
    if has_redacted_secrets(patch) {
        writeln!(
            stderr,
            "error: redacted secret placeholders cannot be saved"
        )?;
        return Ok(1);
    }
    let existing = match read_file(config_path) {
        Ok(Some(decoded)) => decoded.config,
        Ok(None) => Config::default(),
        Err(e) => {
            writeln!(stderr, "error: failed to read existing config: {e}")?;
            return Ok(1);
        },
    };

    let candidate = match apply_merge_patch(&existing, patch) {
        Ok(c) => c,
        Err(e) => {
            writeln!(stderr, "error: {e}")?;
            return Ok(1);
        },
    };

    let host = HostContext::detect();
    if let Err(e) = candidate.clone().validate(&host) {
        writeln!(stderr, "error: {e}")?;
        return Ok(1);
    }

    if let Err(e) = write_document(config_path, &candidate) {
        writeln!(stderr, "error: failed to write configuration: {e}")?;
        return Ok(1);
    }

    write!(stderr, "{RESTART_WARNING}")?;
    Ok(0)
}

fn handle_edit(
    options: &ConfigOptions,
    config_path: &Path,
    socket_path: Option<&Path>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    let (initial_config, etag) = read_config_for_edit(socket_path, config_path, stderr)?;
    let Some(initial_config) = initial_config else {
        return Ok(1);
    };

    let original_yaml = match render_effective_yaml(&initial_config) {
        Ok(y) => y,
        Err(e) => {
            writeln!(stderr, "error: failed to render configuration YAML: {e}")?;
            return Ok(1);
        },
    };

    let temp_file = tempfile::Builder::new()
        .prefix("diorama-config-")
        .suffix(".yaml")
        .tempfile()?;

    #[cfg(unix)]
    {
        fs::set_permissions(temp_file.path(), fs::Permissions::from_mode(0o600))?;
    }

    fs::write(temp_file.path(), original_yaml.as_bytes())?;

    if !launch_editor(options, temp_file.path(), stderr)? {
        return Ok(1);
    }

    let modified_content = fs::read_to_string(temp_file.path())?;
    if modified_content == original_yaml {
        writeln!(stdout, "Configuration unchanged")?;
        return Ok(0);
    }

    let decoded = match diorama_config::decode(&modified_content) {
        Ok(d) => d,
        Err(e) => {
            writeln!(stderr, "error: invalid configuration YAML: {e}")?;
            preserve_edit(temp_file, stderr)?;
            return Ok(1);
        },
    };

    let host = HostContext::detect();
    if let Err(e) = decoded.config.clone().validate(&host) {
        writeln!(stderr, "error: validation failed: {e}")?;
        preserve_edit(temp_file, stderr)?;
        return Ok(1);
    }

    let result = save_edited_config(
        config_path,
        socket_path,
        &initial_config,
        &decoded.config,
        etag.as_deref(),
        stderr,
    );
    if !matches!(result, Ok(0)) {
        preserve_edit(temp_file, stderr)?;
    }
    result
}

fn preserve_edit(temp_file: tempfile::NamedTempFile, stderr: &mut dyn Write) -> io::Result<()> {
    let (_file, path) = temp_file.keep().map_err(|e| e.error)?;
    writeln!(
        stderr,
        "Edited configuration retained at {}",
        path.display()
    )
}

fn read_config_for_edit(
    socket_path: Option<&Path>,
    config_path: &Path,
    stderr: &mut dyn Write,
) -> io::Result<(Option<Config>, Option<String>)> {
    if let Some(resp) = socket_request(
        socket_path,
        "GET",
        "/api/v1/config?showSecrets=true",
        "",
        &[],
    )? {
        if resp.status != 200 {
            writeln!(
                stderr,
                "error: API returned status {}: {}",
                resp.status,
                extract_error_message(&resp.body)
            )?;
            return Ok((None, None));
        }
        let etag = Some(resp.headers.get("etag").cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "config API response is missing ETag",
            )
        })?);
        let parsed: Value = serde_json::from_str(&resp.body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let cfg: Config = serde_json::from_value(parsed["config"].clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        return Ok((Some(cfg), etag));
    }

    match read_file(config_path) {
        Ok(Some(decoded)) => Ok((Some(decoded.config), None)),
        Ok(None) => Ok((Some(Config::default()), None)),
        Err(e) => {
            writeln!(
                stderr,
                "error: failed to read {}: {e}",
                config_path.display()
            )?;
            Ok((None, None))
        },
    }
}

fn launch_editor(
    options: &ConfigOptions,
    temp_file_path: &Path,
    stderr: &mut dyn Write,
) -> io::Result<bool> {
    let editor = options
        .environment
        .get("EDITOR")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .or_else(|| {
            options
                .environment
                .get("VISUAL")
                .filter(|value| !value.trim().is_empty())
                .cloned()
        })
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| {
            std::env::var("VISUAL")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| "vi".to_string());

    let words = shlex::split(&editor)
        .filter(|words| !words.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid editor command quoting",
            )
        })?;
    let status = std::process::Command::new(&words[0])
        .args(&words[1..])
        .arg(temp_file_path)
        .status();

    let exit_status = match status {
        Ok(s) => s,
        Err(e) => {
            if editor == "vi" {
                if let Ok(s) = std::process::Command::new("nano")
                    .arg(temp_file_path)
                    .status()
                {
                    s
                } else {
                    writeln!(stderr, "error: failed to launch editor '{editor}': {e}")?;
                    return Ok(false);
                }
            } else {
                writeln!(stderr, "error: failed to launch editor '{editor}': {e}")?;
                return Ok(false);
            }
        },
    };

    if !exit_status.success() {
        writeln!(
            stderr,
            "error: editor exited with non-zero status: {exit_status}"
        )?;
        return Ok(false);
    }
    Ok(true)
}

fn save_edited_config(
    config_path: &Path,
    socket_path: Option<&Path>,
    initial_config: &Config,
    new_config: &Config,
    etag: Option<&str>,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    if has_redacted_secrets(&serde_json::to_value(new_config).map_err(io::Error::other)?) {
        writeln!(
            stderr,
            "error: redacted secret placeholders cannot be saved"
        )?;
        return Ok(1);
    }
    if let Some(etag_val) = etag {
        let json_val = match serde_json::to_value(new_config) {
            Ok(v) => v,
            Err(e) => {
                writeln!(stderr, "error: {e}")?;
                return Ok(1);
            },
        };
        let candidate_doc = match apply_put_replacement(initial_config, &json_val) {
            Ok(c) => c,
            Err(e) => {
                writeln!(stderr, "error: {e}")?;
                return Ok(1);
            },
        };
        let body_json = serde_json::to_string(&candidate_doc).unwrap();
        let headers = [("Content-Type", "application/json"), ("If-Match", etag_val)];
        if let Some(resp) =
            socket_request(socket_path, "PUT", "/api/v1/config", &body_json, &headers)?
        {
            if resp.status == 200 {
                if check_restart_required(&resp.body) {
                    write!(stderr, "{RESTART_WARNING}")?;
                }
                return Ok(0);
            }
            let msg = extract_error_message(&resp.body);
            writeln!(stderr, "error: {msg}")?;
            return Ok(1);
        }
        writeln!(stderr, "error: config API became unavailable during edit")?;
        return Ok(1);
    }

    let current = read_file(config_path)
        .map_err(io::Error::other)?
        .map_or_else(Config::default, |decoded| decoded.config);
    if &current != initial_config {
        writeln!(
            stderr,
            "error: configuration changed while editing; reload before saving"
        )?;
        return Ok(1);
    }
    if let Err(e) = write_document(config_path, new_config) {
        writeln!(stderr, "error: failed to write configuration: {e}")?;
        return Ok(1);
    }

    write!(stderr, "{RESTART_WARNING}")?;
    Ok(0)
}

fn read_config_for_display(
    socket_path: Option<&Path>,
    config_path: &Path,
    stderr: &mut dyn Write,
) -> io::Result<Option<Config>> {
    if let Some(resp) = socket_request(socket_path, "GET", "/api/v1/config", "", &[])? {
        if resp.status == 200 {
            if let Ok(val) = serde_json::from_str::<Value>(&resp.body)
                && let Ok(cfg) = serde_json::from_value::<Config>(val["config"].clone())
            {
                return Ok(Some(cfg));
            }
            writeln!(
                stderr,
                "error: config API returned an invalid configuration document"
            )?;
            return Ok(None);
        }
        let msg = extract_error_message(&resp.body);
        writeln!(stderr, "error: {msg}")?;
        return Ok(None);
    }

    // Fallback: read directly from config file
    match read_file(config_path) {
        Ok(Some(decoded)) => Ok(Some(decoded.config)),
        Ok(None) => Ok(Some(Config::default())),
        Err(e) => {
            writeln!(
                stderr,
                "error: failed to read {}: {e}",
                config_path.display()
            )?;
            Ok(None)
        },
    }
}

fn build_nested_json(path: &str, value: Value) -> Value {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = value;
    for part in parts.into_iter().rev() {
        let mut map = serde_json::Map::new();
        map.insert(part.to_string(), current);
        current = Value::Object(map);
    }
    current
}

fn check_restart_required(body: &str) -> bool {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("restartRequired").and_then(Value::as_bool))
        == Some(true)
}

fn extract_error_message(body: &str) -> String {
    if let Ok(val) = serde_json::from_str::<Value>(body)
        && let Some(err_str) = val.get("error").and_then(Value::as_str)
    {
        return err_str.to_string();
    }
    body.trim().to_string()
}

#[cfg(test)]
mod review_tests {
    use super::*;

    #[test]
    fn edit_never_falls_back_after_api_selection_or_overwrites_stale_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.yaml");
        let initial = Config::default();
        let mut concurrent = initial.clone();
        concurrent.network.mtu = 1400;
        write_document(&file, &concurrent).unwrap();
        let before = fs::read(&file).unwrap();
        let mut edited = initial.clone();
        edited.network.mtu = 1500;
        assert_eq!(
            save_edited_config(
                &file,
                Some(&dir.path().join("absent.sock")),
                &initial,
                &edited,
                Some("old-etag"),
                &mut Vec::new()
            )
            .unwrap(),
            1
        );
        assert_eq!(fs::read(&file).unwrap(), before);
        assert_eq!(
            save_edited_config(&file, None, &initial, &edited, None, &mut Vec::new()).unwrap(),
            1
        );
        assert_eq!(fs::read(&file).unwrap(), before);
        edited.portainer.edge_key = "***".into();
        assert_eq!(
            save_edited_config(&file, None, &concurrent, &edited, None, &mut Vec::new()).unwrap(),
            1
        );
        assert_eq!(fs::read(file).unwrap(), before);
    }
}
