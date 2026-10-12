//! Kubeconfig management: identity resolution, backup, parsing, and merging.
use crate::CheckInputs;
use crate::contract::KubeconfigOptions;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[cfg(unix)]
use diorama_supervisor::rustix;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

/// Resolved invoking user identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokingUser {
    pub username: String,
    pub home_dir: PathBuf,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

/// Resolves the invoking user from environment variables and `/etc/passwd`.
///
/// Priority:
/// 1. `SUDO_USER` (if present and != "root"):
///    - `SUDO_UID` / `SUDO_GID` from env if present.
///    - Read `/etc/passwd` to look up home directory and fallback UID/GID.
///    - If not in `/etc/passwd`, home defaults to `/home/<SUDO_USER>`.
/// 2. `DOAS_USER` (if present and != "root"):
///    - Read `/etc/passwd` for UID, GID, and home directory.
///    - If not in `/etc/passwd`, home defaults to `/home/<DOAS_USER>`.
/// 3. Normal user or root fallback:
///    - `HOME` env variable (fallback `/root` if empty/unset).
///    - `USER` env variable (fallback `root` if empty/unset).
///    - Current process effective UID / GID on Unix.
///
/// Under no circumstances is `/proc/self/loginuid` accessed or guessed.
pub fn resolve_invoking_user(environment: &BTreeMap<String, String>) -> InvokingUser {
    let passwd_content = fs::read_to_string("/etc/passwd").unwrap_or_default();
    resolve_invoking_user_with_passwd(environment, &passwd_content)
}

/// Pure helper for resolving invoking user with explicit passwd file content (useful for tests).
#[allow(clippy::similar_names)]
pub fn resolve_invoking_user_with_passwd(
    environment: &BTreeMap<String, String>,
    passwd_content: &str,
) -> InvokingUser {
    if let Some(sudo_user) = environment.get("SUDO_USER")
        && !sudo_user.is_empty()
        && sudo_user != "root"
    {
        let env_uid = environment
            .get("SUDO_UID")
            .and_then(|s| s.parse::<u32>().ok());
        let env_gid = environment
            .get("SUDO_GID")
            .and_then(|s| s.parse::<u32>().ok());

        let passwd_info = lookup_passwd(passwd_content, sudo_user);
        let uid = env_uid.or_else(|| passwd_info.as_ref().map(|p| p.uid));
        let gid = env_gid.or_else(|| passwd_info.as_ref().map(|p| p.gid));
        let home_dir =
            passwd_info.map_or_else(|| PathBuf::from(format!("/home/{sudo_user}")), |p| p.home);

        return InvokingUser {
            username: sudo_user.clone(),
            home_dir,
            uid,
            gid,
        };
    }

    if let Some(doas_user) = environment.get("DOAS_USER")
        && !doas_user.is_empty()
        && doas_user != "root"
    {
        let passwd_info = lookup_passwd(passwd_content, doas_user);
        let uid = passwd_info.as_ref().map(|p| p.uid);
        let gid = passwd_info.as_ref().map(|p| p.gid);
        let home_dir =
            passwd_info.map_or_else(|| PathBuf::from(format!("/home/{doas_user}")), |p| p.home);

        return InvokingUser {
            username: doas_user.clone(),
            home_dir,
            uid,
            gid,
        };
    }

    // Default / fallback to current process user
    let username = environment
        .get("USER")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "root".to_string());

    let home_dir = environment
        .get("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| {
            if username == "root" {
                PathBuf::from("/root")
            } else {
                PathBuf::from(format!("/home/{username}"))
            }
        });

    #[cfg(unix)]
    let (proc_uid, proc_gid) = current_process_uid_gid();
    #[cfg(unix)]
    let (uid, gid) = (Some(proc_uid), Some(proc_gid));
    #[cfg(not(unix))]
    let (uid, gid) = (None, None);

    InvokingUser {
        username,
        home_dir,
        uid,
        gid,
    }
}

struct PasswdEntry {
    uid: u32,
    gid: u32,
    home: PathBuf,
}

fn lookup_passwd(content: &str, target_user: &str) -> Option<PasswdEntry> {
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 && fields[0] == target_user {
            let uid = fields[2].parse::<u32>().ok()?;
            let gid = fields[3].parse::<u32>().ok()?;
            let home = PathBuf::from(fields[5]);
            return Some(PasswdEntry { uid, gid, home });
        }
    }
    None
}

/// Helper to get current process effective UID and GID.
#[cfg(unix)]
fn current_process_uid_gid() -> (u32, u32) {
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    (uid, gid)
}

/// Resolves standard target destination path for `dioramactl kubeconfig`.
/// If `output` is specified, it is used (expanding leading `~` to user's home).
/// Otherwise, defaults to `<user_home>/.kube/config`.
pub fn resolve_destination(user: &InvokingUser, output: Option<&Path>) -> PathBuf {
    if let Some(out) = output {
        expand_tilde(out, &user.home_dir)
    } else {
        user.home_dir.join(".kube").join("config")
    }
}

fn expand_tilde(path: &Path, home: &Path) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        home.join(stripped)
    } else {
        path.to_path_buf()
    }
}

/// Formats UTC `SystemTime` as YYYYMMDDHHMMSS for backup suffix.
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
pub fn format_backup_timestamp(now: SystemTime) -> String {
    let dur = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();

    // Pure Rust civil time computation
    let days = (secs / 86_400) as i64;
    let rem_secs = (secs % 86_400) as u32;

    let hour = rem_secs / 3600;
    let min = (rem_secs % 3600) / 60;
    let sec = rem_secs % 60;

    // Euclidean affine transform from day count to civil date (Howard Hinnant algorithm)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}{m:02}{d:02}{hour:02}{min:02}{sec:02}")
}

/// Creates a pre-merge backup if destination exists.
/// Returns `Some(backup_path)` if created, or None if destination did not exist.
pub fn create_premerge_backup(dest: &Path, now: SystemTime) -> io::Result<Option<PathBuf>> {
    let metadata = match fs::symlink_metadata(dest) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "kubeconfig destination must be a regular file, not a symlink",
            ));
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let _ = metadata;
    let ts = format_backup_timestamp(now);
    let backup_name = format!(
        "{}.backup-{}",
        dest.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("config"),
        ts
    );
    let mut backup_path = dest
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(backup_name);

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    let mut source = options.open(dest)?;
    let mut backup =
        tempfile::NamedTempFile::new_in(dest.parent().unwrap_or_else(|| Path::new(".")))?;
    io::copy(&mut source, &mut backup)?;
    backup.as_file().sync_all()?;
    let base_path = backup_path.clone();
    for suffix in 0u64.. {
        match backup.persist_noclobber(&backup_path) {
            Ok(_) => break,
            Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => {
                backup = e.file;
                backup_path = PathBuf::from(format!("{}-{}", base_path.display(), suffix + 1));
            },
            Err(e) => return Err(e.error),
        }
    }
    Ok(Some(backup_path))
}

/// Atomic write with 0600 mode, ensures parent dir exists with 0700 mode,
/// and applies chown to invoking user if running with root privileges.
fn validate_destination_parent(path: &Path, user: &InvokingUser) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match fs::symlink_metadata(parent) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "kubeconfig parent must be a directory, not a symlink",
                ));
            }
            #[cfg(unix)]
            if let Some(uid) = user.uid
                && metadata.uid() != uid
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "kubeconfig parent is not owned by the invoking user",
                ));
            }
            Ok(())
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Publishes only into an invoking-user-owned directory without following a parent symlink.
pub fn atomic_write_secure(path: &Path, data: &[u8], user: &InvokingUser) -> io::Result<()> {
    validate_destination_parent(path, user)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    if !parent.exists() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(parent)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(parent, perms)?;
            if rustix::process::geteuid().is_root() {
                let dir = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::DIRECTORY)
                            .bits()
                            .cast_signed(),
                    )
                    .open(parent)?;
                rustix::fs::fchown(
                    &dir,
                    user.uid.map(rustix::fs::Uid::from_raw),
                    user.gid.map(rustix::fs::Gid::from_raw),
                )?;
            }
        }
    }

    validate_destination_parent(path, user)?;
    let mut temp = tempfile::Builder::new().tempfile_in(parent)?;

    #[cfg(unix)]
    {
        let mut perms = temp.as_file().metadata()?.permissions();
        perms.set_mode(0o600);
        temp.as_file_mut().set_permissions(perms)?;
    }

    temp.write_all(data)?;
    temp.flush()?;
    #[cfg(unix)]
    if rustix::process::geteuid().is_root() {
        rustix::fs::fchown(
            temp.as_file(),
            user.uid.map(rustix::fs::Uid::from_raw),
            user.gid.map(rustix::fs::Gid::from_raw),
        )?;
    }
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| e.error)?;

    Ok(())
}

/// Chown only the specified owned file without following a final symlink.
#[allow(clippy::collapsible_if, clippy::excessive_nesting)]
pub fn chown_invoking_user(path: &Path, user: &InvokingUser) -> io::Result<()> {
    #[cfg(unix)]
    {
        let (current_uid, _) = current_process_uid_gid();
        if current_uid == 0
            && let (Some(target_uid), Some(target_gid)) = (user.uid, user.gid)
            && target_uid != 0
        {
            let uid = Some(rustix::fs::Uid::from_raw(target_uid));
            let gid = Some(rustix::fs::Gid::from_raw(target_gid));

            rustix::fs::chownat(
                rustix::fs::CWD,
                path,
                uid,
                gid,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, user);
    }
    Ok(())
}

/// Locates admin kubeconfig file inside the given data directory.
/// Checks:
/// 1. `<data_path>/pki/admin/admin.kubeconfig`
/// 2. `<data_path>/pki/admin.kubeconfig`
/// 3. `<data_path>/admin.kubeconfig`
pub fn locate_admin_kubeconfig(data_path: &Path) -> io::Result<PathBuf> {
    let p1 = data_path.join("pki").join("admin").join("admin.kubeconfig");
    if p1.is_file() {
        return Ok(p1);
    }
    let p2 = data_path.join("pki").join("admin.kubeconfig");
    if p2.is_file() {
        return Ok(p2);
    }
    let p3 = data_path.join("admin.kubeconfig");
    if p3.is_file() {
        return Ok(p3);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "admin kubeconfig not found in {}. Ensure the cluster has been initialized",
            data_path.display()
        ),
    ))
}

/// Parse a kubeconfig YAML or JSON string into a structured `serde_json::Value`.
pub fn parse_kubeconfig_content(content: &str) -> io::Result<Value> {
    let value = diorama_config::decode_yaml_value(content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if !value.is_object() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kubeconfig must be a mapping",
        ));
    }
    Ok(value)
}

/// Merges incoming kubeconfig into destination kubeconfig.
/// Preserves all existing unrelated clusters, contexts, users, preferences, and extra keys.
/// Updates or adds clusters/contexts/users with matching name.
/// Sets `current-context` to incoming kubeconfig's `current-context`.
pub fn merge_kubeconfigs(target: &mut Value, incoming: &Value) {
    let Value::Object(target_obj) = target else {
        return;
    };

    let Value::Object(incoming_obj) = incoming else {
        return;
    };

    if !target_obj.contains_key("apiVersion") {
        if let Some(v) = incoming_obj.get("apiVersion") {
            target_obj.insert("apiVersion".to_string(), v.clone());
        } else {
            target_obj.insert("apiVersion".to_string(), Value::String("v1".to_string()));
        }
    }
    if !target_obj.contains_key("kind") {
        if let Some(v) = incoming_obj.get("kind") {
            target_obj.insert("kind".to_string(), v.clone());
        } else {
            target_obj.insert("kind".to_string(), Value::String("Config".to_string()));
        }
    }
    if !target_obj.contains_key("preferences") {
        target_obj.insert(
            "preferences".to_string(),
            Value::Object(serde_json::Map::new()),
        );
    }

    // Merge named list entries: clusters, contexts, users
    for list_key in ["clusters", "contexts", "users"] {
        merge_named_list(target_obj, incoming_obj, list_key);
    }

    // Set current-context
    if let Some(ctx) = incoming_obj.get("current-context") {
        target_obj.insert("current-context".to_string(), ctx.clone());
    }
}

fn merge_named_list(
    target_obj: &mut serde_json::Map<String, Value>,
    incoming_obj: &serde_json::Map<String, Value>,
    list_key: &str,
) {
    let incoming_items = incoming_obj
        .get(list_key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let existing_items = target_obj
        .entry(list_key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut();

    let Some(existing) = existing_items else {
        return;
    };

    for incoming_entry in incoming_items {
        let incoming_name = incoming_entry.get("name").and_then(Value::as_str);

        if let Some(name) = incoming_name {
            if let Some(exist) = existing
                .iter_mut()
                .find(|e| e.get("name").and_then(Value::as_str) == Some(name))
            {
                *exist = incoming_entry;
            } else {
                existing.push(incoming_entry);
            }
        } else {
            existing.push(incoming_entry);
        }
    }
}

/// Serializes the complete kubeconfig as JSON, a YAML-compatible representation.
pub fn serialize_kubeconfig(val: &Value) -> String {
    format!("{val:#}\n")
}

/// Executes `dioramactl kubeconfig` commands: view, fetch, merge, or root.
pub fn execute_kubeconfig(
    options: &KubeconfigOptions,
    inputs: &mut dyn CheckInputs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    execute_kubeconfig_with_env(options, inputs, &BTreeMap::new(), stdout, stderr)
}

/// Executes `dioramactl kubeconfig` with explicit environment for identity resolution.
pub fn execute_kubeconfig_with_env(
    options: &KubeconfigOptions,
    inputs: &mut dyn CheckInputs,
    environment: &BTreeMap<String, String>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    execute_kubeconfig_with_engine(
        options,
        inputs,
        &mut crate::endpoints::DockerPortInspector,
        environment,
        stdout,
        stderr,
    )
}

/// Executes kubeconfig commands with an injected container port inspector.
pub fn execute_kubeconfig_with_engine(
    options: &KubeconfigOptions,
    _inputs: &mut dyn CheckInputs,
    engine: &mut dyn crate::endpoints::EnginePortInspector,
    environment: &BTreeMap<String, String>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    // If environment is empty, inspect actual process environment

    let env_map = if environment.is_empty() {
        std::env::vars().collect::<BTreeMap<_, _>>()
    } else {
        environment.clone()
    };

    if matches!(options.subcommand.as_deref(), Some("route" | "remove")) {
        return crate::endpoints::execute_endpoint_command(
            options, engine, &env_map, stdout, stderr,
        );
    }
    let user = resolve_invoking_user(&env_map);
    let admin_kubeconfig_path = match locate_admin_kubeconfig(&options.path) {
        Ok(path) => path,
        Err(err) => {
            writeln!(stderr, "error: {err}")?;
            return Ok(1);
        },
    };
    let admin_content = match fs::read_to_string(&admin_kubeconfig_path) {
        Ok(c) => c,
        Err(err) => {
            writeln!(stderr, "error: failed to read admin kubeconfig: {err}")?;
            return Ok(1);
        },
    };

    match options.subcommand.as_deref() {
        Some("view") => {
            stdout.write_all(admin_content.as_bytes())?;
            if !admin_content.ends_with('\n') {
                stdout.write_all(b"\n")?;
            }
            Ok(0)
        },
        Some("fetch" | "merge") => {
            let dest_path = resolve_destination(&user, options.output.as_deref());
            validate_destination_parent(&dest_path, &user)?;

            // Pre-merge backup if destination exists
            if let Some(backup_path) = create_premerge_backup(&dest_path, SystemTime::now())? {
                writeln!(
                    stderr,
                    "Created backup of existing kubeconfig at {}",
                    backup_path.display()
                )?;
            }

            let mut current_cfg = if dest_path.is_file() {
                let mut options = fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
                let mut existing_content = String::new();
                options
                    .open(&dest_path)?
                    .read_to_string(&mut existing_content)?;
                parse_kubeconfig_content(&existing_content)?
            } else {
                Value::Object(serde_json::Map::new())
            };

            let admin_val = parse_kubeconfig_content(&admin_content)?;
            merge_kubeconfigs(&mut current_cfg, &admin_val);

            let merged_yaml = serialize_kubeconfig(&current_cfg);
            atomic_write_secure(&dest_path, merged_yaml.as_bytes(), &user)?;

            writeln!(
                stdout,
                "Kubeconfig successfully written to {}",
                dest_path.display()
            )?;
            Ok(0)
        },
        None => {
            // Root kubeconfig command
            if let Some(ref out) = options.output {
                let dest_path = expand_tilde(out, &user.home_dir);
                atomic_write_secure(&dest_path, admin_content.as_bytes(), &user)?;
                writeln!(stdout, "Kubeconfig written to {}", dest_path.display())?;
            } else {
                stdout.write_all(admin_content.as_bytes())?;
                if !admin_content.ends_with('\n') {
                    stdout.write_all(b"\n")?;
                }
            }
            Ok(0)
        },
        Some(unknown) => {
            writeln!(
                stderr,
                "error: unknown subcommand '{unknown}' for kubeconfig"
            )?;
            Ok(1)
        },
    }
}
