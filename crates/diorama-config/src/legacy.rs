//! Legacy service argument extraction and conversion to versioned YAML.
//!
//! Contract:
//! - Extracts known `diorama` flags from legacy service definitions.
//! - Foreign flags (such as sysvinit `start-stop-daemon --start --quiet --pidfile`) are safely ignored.
//! - Shell quotes (`"..."`, `'...'`) are stripped from values.
//! - Supports `--no-<flag>` boolean negations (e.g. `--no-local-storage`).
//! - If `--config` is already present, migration is a no-op (already migrated).
//! - Resolves extracted flags with default configuration and renders clean `diorama` YAML.

use std::collections::BTreeMap;
use std::path::Path;

use regex::Regex;

use crate::{
    Config, ConfigError, DEFAULT_CONFIG_PATH, ExplicitFlags, FIELDS, FieldType, HostContext,
    INPUT_BINDINGS, PersistenceError, render_effective_yaml, resolve_layers, write_document,
};

/// Regular expression pattern matching service arguments:
/// `--[a-z0-9][a-z0-9-]*(?:=(?:"[^"]*"|'[^']*'|[^\s"']+))?`
const SERVICE_FLAG_REGEX: &str =
    r#"--[a-z0-9][a-z0-9-]*(?:=(?:"[^"]*"|'[^']*'|[^\t\n\x0B\x0C\r "']+))?"#;

/// Strips surrounding double or single shell quotes from a flag value if present.
pub fn unquote_shell_value(val: &str) -> String {
    let s = val.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Checks if a service content line or definition already contains `--config`.
pub fn has_config_flag(content: &str) -> bool {
    let re = Regex::new(SERVICE_FLAG_REGEX).expect("valid regex");
    for mat in argument_lines(content)
        .into_iter()
        .flat_map(|(_, line)| re.find_iter(line))
    {
        let flag_str = mat.as_str();
        let name_part = flag_str
            .strip_prefix("--")
            .unwrap_or(flag_str)
            .split_once('=')
            .map_or(flag_str.strip_prefix("--").unwrap_or(flag_str), |(k, _)| k);
        if name_part == "config" {
            return true;
        }
    }
    false
}

/// Resolve a single literal absolute config argument from active service command fields.
/// Runtime expansions and ambiguous arguments cannot establish an offline verification path.
pub fn service_config_path(content: &str) -> Result<std::path::PathBuf, String> {
    let re = Regex::new(r#"(?:^|[\t\n\x0B\x0C\r ]|=)(?:"--config=([^"]*)"|'--config=([^']*)'|--config(?:=|[\t\n\x0B\x0C\r ]+)("[^"]*"|'[^']*'|[^\t\n\x0B\x0C\r "']+)|--config(?:[\t\n\x0B\x0C\r ]|$))"#)
        .expect("valid regex");
    let mut paths = Vec::new();
    for (_, line) in argument_lines(content) {
        let trimmed = line.trim();
        // These shell assignments quote an argument list, not an individual argument.
        let arguments = match trimmed.split_once('=') {
            Some(("command_args" | "DAEMON_ARGS", args)) => unquote_shell_value(args),
            _ => trimmed.to_string(),
        };
        for capture in re.captures_iter(&arguments) {
            let matched = capture.get(0).unwrap();
            if arguments[matched.end()..]
                .chars()
                .next()
                .is_some_and(|c| !c.is_whitespace())
            {
                return Err(
                    "concatenated --config argument cannot establish a literal path".into(),
                );
            }
            let value = capture
                .get(1)
                .or_else(|| capture.get(2))
                .or_else(|| capture.get(3))
                .ok_or("missing --config argument")?;
            if capture.get(3).is_some() && !value.as_str().starts_with(['\'', '"']) {
                let remainder = arguments[matched.end()..].trim();
                if !remainder.is_empty() && !remainder.starts_with("--") {
                    return Err("ambiguous unquoted --config argument".into());
                }
            }
            paths.push(unquote_shell_value(value.as_str()));
        }
    }
    let [value] = paths.as_slice() else {
        return Err("service requires exactly one literal --config path".into());
    };
    let path = std::path::PathBuf::from(value);
    if !path.is_absolute() || value.contains(['$', '%', '`', '\\']) {
        return Err("service --config path must be absolute without runtime expansions".into());
    }
    Ok(path)
}

/// Information about a known `diorama` flag definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlagKind {
    Bool,
    Other,
}

fn lookup_flag(name: &str) -> Option<(&'static str, FlagKind)> {
    if name == "full" {
        return Some(("full", FlagKind::Bool));
    }
    for binding in INPUT_BINDINGS {
        if let Some(flag) = binding.flag
            && flag == name
        {
            let field = FIELDS.iter().find(|f| f.path == binding.path);
            let kind = match field.map(|f| f.kind) {
                Some(FieldType::Boolean | FieldType::OptionalBool) => FlagKind::Bool,
                _ => FlagKind::Other,
            };
            return Some((flag, kind));
        }
    }
    None
}

/// Extracted legacy flags representation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtractedFlags {
    /// Explicit flag mappings: flag name -> string value
    pub flags: BTreeMap<String, String>,
    /// Nonboolean arguments with no unambiguous value; conversion must reject them.
    pub missing_values: Vec<String>,
}

/// A recognized argument and its complete serialized token range.
struct LegacyArgument {
    range: std::ops::Range<usize>,
    key: String,
    value: String,
    missing_value: bool,
}

fn legacy_arguments(line: &str) -> Vec<LegacyArgument> {
    let re = Regex::new(r#"--[a-z0-9][a-z0-9-]*(?:=(?:"[^"]*"|'[^']*'|[^\t\n\x0B\x0C\r "']*))?"#)
        .expect("valid regex");
    let value_re = Regex::new(r#"^[\t\n\x0B\x0C\r ]+("[^"]*"|'[^']*'|[^\t\n\x0B\x0C\r "'\\]+)"#)
        .expect("valid regex");
    let mut arguments = Vec::new();
    let mut consumed = 0;
    for mat in re.find_iter(line) {
        if mat.start() < consumed {
            continue;
        }
        let raw = mat.as_str().strip_prefix("--").unwrap();
        let (name, explicit) = raw
            .split_once('=')
            .map_or((raw, None), |(k, v)| (k, Some(v)));
        let (canonical, kind, negated) = if let Some((key, kind)) = lookup_flag(name) {
            (key, kind, false)
        } else if let Some(key) = name.strip_prefix("no-")
            && let Some((key, FlagKind::Bool)) = lookup_flag(key)
        {
            (key, FlagKind::Bool, true)
        } else {
            continue;
        };
        let mut range = mat.range();
        let mut missing_value = false;
        let value = if negated {
            "false".into()
        } else if let Some(value) = explicit {
            unquote_shell_value(value)
        } else if kind == FlagKind::Bool {
            "true".into()
        } else if let Some(capture) = value_re.captures(&line[mat.end()..])
            && !capture[1].starts_with("--")
        {
            range.end += capture.get(0).unwrap().end();
            unquote_shell_value(&capture[1])
        } else {
            missing_value = true;
            String::new()
        };
        // Expansions and escapes depend on the service manager's runtime context.
        if value.contains(['$', '%', '`', '\\']) {
            missing_value = true;
        }
        // Include surrounding whole-token quotes, but leave an assignment's outer quotes intact.
        if range.start > 0 && (range.start < 2 || line.as_bytes()[range.start - 2] != b'=') {
            let quote = line.as_bytes()[range.start - 1];
            if matches!(quote, b'\'' | b'"') {
                if line.as_bytes().get(range.end) == Some(&quote) {
                    range.start -= 1;
                    range.end += 1;
                } else {
                    // Refuse partial tokens rather than persisting a truncated value.
                    missing_value = true;
                }
            }
        }
        consumed = range.end;
        arguments.push(LegacyArgument {
            range,
            key: canonical.into(),
            value,
            missing_value,
        });
    }
    arguments
}

// Select executable/argument fields rather than descriptions, comments or daemon metadata.
fn argument_lines(content: &str) -> Vec<(usize, &str)> {
    let mut offset = 0;
    let mut continuing = false;
    let mut result = Vec::new();
    for line in content.split_inclusive('\n') {
        let trimmed = line.trim();
        let active = !trimmed.starts_with('#')
            && (trimmed.starts_with("ExecStart=")
                || trimmed.starts_with("command_args=")
                || trimmed.starts_with("DAEMON_ARGS=")
                || trimmed.starts_with("exec ")
                || trimmed.starts_with("diorama ")
                || trimmed.starts_with("start-stop-daemon ")
                || continuing
                || trimmed.starts_with("--")
                || trimmed.starts_with("'--")
                || trimmed.starts_with("\"--"));
        if active {
            result.push((offset, line));
        }
        continuing = active && trimmed.ends_with('\\');
        offset += line.len();
    }
    result
}

/// Extracts typed flags from execution/argument fields, preserving explicit empty values.
pub fn extract_service_flags(content: &str) -> ExtractedFlags {
    let mut flags = BTreeMap::new();
    let mut missing_values = Vec::new();
    for (_, line) in argument_lines(content) {
        for argument in legacy_arguments(line) {
            if argument.missing_value {
                missing_values.push(argument.key.clone());
            }
            flags.entry(argument.key).or_insert(argument.value);
        }
    }
    ExtractedFlags {
        flags,
        missing_values,
    }
}

/// Replaces complete legacy argument tokens at their original execution/argument position.
pub fn rewrite_service_content(content: &str, config_path: &str) -> String {
    let mut replacements = Vec::new();
    let mut inserted = false;
    for (offset, line) in argument_lines(content) {
        let assignment = line.trim_start().starts_with("command_args=")
            || line.trim_start().starts_with("DAEMON_ARGS=");
        for argument in legacy_arguments(line) {
            let replacement = if inserted {
                String::new()
            } else {
                inserted = true;
                let flag = format!("--config={config_path}");
                if config_path
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
                {
                    flag
                } else if assignment {
                    // Store a quoted argument inside the existing double-quoted shell assignment.
                    format!("'{}'", flag.replace('\'', "'\\''"))
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace('$', "\\$")
                        .replace('`', "\\`")
                } else if line.trim_start().starts_with("ExecStart=") {
                    format!(
                        "\"{}\"",
                        flag.replace('\\', "\\\\")
                            .replace('"', "\\\"")
                            .replace('%', "%%")
                            .replace('$', "$$")
                    )
                } else {
                    format!("'{}'", flag.replace('\'', "'\\''"))
                }
            };
            replacements.push((
                offset + argument.range.start..offset + argument.range.end,
                replacement,
            ));
        }
    }
    let mut result = content.to_string();
    for (range, replacement) in replacements.into_iter().rev() {
        result.replace_range(range, &replacement);
    }
    result
}

/// Converts extracted legacy service flags into a validated `Config` model.
///
/// Does not read environment or host context by default unless provided.
pub fn flags_to_config(
    extracted: &ExtractedFlags,
    host: Option<&HostContext>,
) -> Result<Config, ConfigError> {
    if let Some(key) = extracted.missing_values.first() {
        return Err(ConfigError {
            kind: crate::ErrorKind::Syntax,
            path: format!("--{key}"),
            message: "missing legacy flag value".into(),
        });
    }
    let default_host = HostContext::detect();
    let host_ctx = host.unwrap_or(&default_host);
    let explicit = ExplicitFlags(extracted.flags.clone());
    let resolved = resolve_layers(
        None,
        &BTreeMap::new(),
        &explicit,
        crate::EnvironmentMode::Omit,
        host_ctx,
    )?;
    Ok(resolved.validated.into_config())
}

/// Converts extracted flags directly into rendered `diorama` YAML string.
pub fn render_config_from_flags(
    extracted: &ExtractedFlags,
    host: Option<&HostContext>,
) -> Result<String, ConfigError> {
    let config = flags_to_config(extracted, host)?;
    render_effective_yaml(&config)
}

/// Outcome of a service configuration migration attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// Already migrated because `--config` is present in the service definition.
    AlreadyMigratedService,
    /// Destination config file already exists; skipped to prevent overwrite.
    DestinationConfigExists,
    /// No legacy flags found in service definition; nothing to migrate.
    NoLegacyFlags,
    /// Successfully migrated flags into configuration file.
    Migrated {
        destination: String,
        backup_created: bool,
    },
}

/// Migrates legacy service arguments into the specified config file (default `/etc/diorama/config.yaml`).
///
/// Follows safety guarantees:
/// 1. If service definition already specifies `--config`, skips (returns `AlreadyMigratedService`).
/// 2. If destination configuration file already exists, skips to avoid overwriting existing valid config
///    (returns `DestinationConfigExists`).
/// 3. If no legacy flags are present in service definition, returns `NoLegacyFlags`.
/// 4. Converts extracted flags to YAML and writes atomically using `write_document` (mode `0600`).
pub fn migrate_service_flags(
    service_content: &str,
    destination_path: Option<&Path>,
    host: Option<&HostContext>,
) -> Result<MigrationOutcome, PersistenceError> {
    let dest = destination_path.unwrap_or_else(|| Path::new(DEFAULT_CONFIG_PATH));

    // 1. Check if already migrated
    if has_config_flag(service_content) {
        return Ok(MigrationOutcome::AlreadyMigratedService);
    }

    // 2. Check if destination config file already exists
    if std::fs::symlink_metadata(dest).is_ok() {
        return Ok(MigrationOutcome::DestinationConfigExists);
    }

    // 3. Extract legacy flags
    let extracted = extract_service_flags(service_content);
    if extracted.flags.is_empty() {
        return Ok(MigrationOutcome::NoLegacyFlags);
    }

    // 4. Convert flags to Config model
    let config = flags_to_config(&extracted, host).map_err(|source| PersistenceError {
        stage: crate::PersistenceStage::Render,
        path: dest.to_owned(),
        committed: false,
        source: crate::PersistenceSource::Render(source),
        cleanup_failures: Vec::new(),
    })?;

    // 5. Atomic write with 0600 permissions
    let outcome = write_document(dest, &config)?;

    Ok(MigrationOutcome::Migrated {
        destination: dest.display().to_string(),
        backup_created: outcome.backup_created,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unquote_shell_value() {
        assert_eq!(unquote_shell_value("\"hello\""), "hello");
        assert_eq!(unquote_shell_value("'world'"), "world");
        assert_eq!(unquote_shell_value("\"\""), "");
        assert_eq!(unquote_shell_value("''"), "");
        assert_eq!(unquote_shell_value("plain"), "plain");
        assert_eq!(unquote_shell_value("  \"spaced\"  "), "spaced");
        assert_eq!(
            unquote_shell_value("\"nested 'quotes'\""),
            "nested 'quotes'"
        );
    }

    #[test]
    fn test_has_config_flag() {
        assert!(has_config_flag("diorama --config=/etc/diorama/config.yaml"));
        assert!(has_config_flag(
            "ExecStart=/usr/local/bin/diorama --config=\"/custom/path.yaml\""
        ));
        assert!(!has_config_flag(
            "ExecStart=/usr/local/bin/diorama --node-ip=1.2.3.4"
        ));
        assert!(!has_config_flag(
            "start-stop-daemon --start --exec /usr/local/bin/diorama"
        ));
    }

    #[test]
    fn test_extract_service_flags_various_formats() {
        let content = r#"
[Service]
ExecStart=/usr/local/bin/diorama \
  --path=/data/diorama \
  --debug \
  --node-ip="192.168.1.50" \
  --mtu=1400 \
  --no-local-storage \
  --portainer-edge-id='edge-123' \
  --portainer-edge-key="secret-key-abc"
"#;
        let extracted = extract_service_flags(content);
        assert_eq!(
            extracted.flags.get("path").map(String::as_str),
            Some("/data/diorama")
        );
        assert_eq!(
            extracted.flags.get("debug").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            extracted.flags.get("node-ip").map(String::as_str),
            Some("192.168.1.50")
        );
        assert_eq!(extracted.flags.get("mtu").map(String::as_str), Some("1400"));
        assert_eq!(
            extracted.flags.get("local-storage").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            extracted.flags.get("portainer-edge-id").map(String::as_str),
            Some("edge-123")
        );
        assert_eq!(
            extracted
                .flags
                .get("portainer-edge-key")
                .map(String::as_str),
            Some("secret-key-abc")
        );
    }

    #[test]
    fn test_extract_ignores_foreign_init_flags() {
        // SysVinit start-stop-daemon line
        let content = r"
start-stop-daemon --start --quiet --pidfile /var/run/diorama.pid \
  --make-pidfile --background --exec /usr/local/bin/diorama -- \
  --node-ip=10.0.0.1 --debug
";
        let extracted = extract_service_flags(content);
        // Only diorama flags captured
        assert_eq!(extracted.flags.len(), 2);
        assert_eq!(
            extracted.flags.get("node-ip").map(String::as_str),
            Some("10.0.0.1")
        );
        assert_eq!(
            extracted.flags.get("debug").map(String::as_str),
            Some("true")
        );
        assert!(!extracted.flags.contains_key("start"));
        assert!(!extracted.flags.contains_key("pidfile"));
        assert!(!extracted.flags.contains_key("exec"));
        assert!(!extracted.flags.contains_key("background"));
    }

    #[test]
    fn test_extract_first_occurrence_wins() {
        let content = "--node-ip=1.1.1.1 --mtu=1400 --node-ip=2.2.2.2";
        let extracted = extract_service_flags(content);
        assert_eq!(
            extracted.flags.get("node-ip").map(String::as_str),
            Some("1.1.1.1")
        );
        assert_eq!(extracted.flags.get("mtu").map(String::as_str), Some("1400"));
    }

    #[test]
    fn test_render_config_from_flags() {
        let content = "--node-ip=10.10.10.10 --debug --path=/var/lib/mydiorama";
        let extracted = extract_service_flags(content);
        let yaml = render_config_from_flags(&extracted, None).expect("valid rendering");
        assert!(yaml.contains("apiVersion: diorama.io/v1alpha1"));
        assert!(yaml.contains("kind: Config"));
        assert!(yaml.contains("path: /var/lib/mydiorama"));
        assert!(yaml.contains("debug: true"));
        assert!(yaml.contains("nodeIP: 10.10.10.10"));
    }

    #[test]
    fn test_migration_destination_exists_skips() {
        let dir =
            std::env::temp_dir().join(format!("diorama-test-mig-exists-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let config_file = dir.join("config.yaml");
        std::fs::write(&config_file, "existing config").unwrap();

        let service = "ExecStart=/usr/local/bin/diorama --node-ip=1.2.3.4";
        let outcome = migrate_service_flags(service, Some(&config_file), None).unwrap();
        assert_eq!(outcome, MigrationOutcome::DestinationConfigExists);

        // Original content unchanged
        assert_eq!(
            std::fs::read_to_string(&config_file).unwrap(),
            "existing config"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_migration_already_migrated_service_skips() {
        let dir =
            std::env::temp_dir().join(format!("diorama-test-mig-already-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let config_file = dir.join("config.yaml");

        let service = "ExecStart=/usr/local/bin/diorama --config=/etc/diorama/config.yaml";
        let outcome = migrate_service_flags(service, Some(&config_file), None).unwrap();
        assert_eq!(outcome, MigrationOutcome::AlreadyMigratedService);
        assert!(!config_file.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_migration_writes_atomic_0600() {
        let dir =
            std::env::temp_dir().join(format!("diorama-test-mig-atomic-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let config_file = dir.join("config.yaml");

        let service = "ExecStart=/usr/local/bin/diorama --node-ip=10.0.0.5 --debug";
        let outcome = migrate_service_flags(service, Some(&config_file), None).unwrap();
        assert_eq!(
            outcome,
            MigrationOutcome::Migrated {
                destination: config_file.display().to_string(),
                backup_created: false
            }
        );

        assert!(config_file.exists());
        let content = std::fs::read_to_string(&config_file).unwrap();
        assert!(content.contains("nodeIP: 10.0.0.5"));
        assert!(content.contains("debug: true"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&config_file).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
