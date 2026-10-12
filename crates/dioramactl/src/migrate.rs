//! Service file detection, legacy flag migration, backup preservation, and service unit update.
//!
//! Upstream contract (`internal/cli/cmd_upgrade.go` & `internal/cli/migrate_config.go`):
//! - Gate D02 / `MinConfigFileVersion` (`v1.3.0`):
//!   If upgrading to or installing a version `< v1.3.0`, `--config` is not supported by that binary.
//!   Keep legacy flags in the service definition.
//!   If version is unparseable or `>= v1.3.0`, configuration file conversion is allowed.
//! - Service file paths by init system:
//!   - Systemd: `/etc/systemd/system/diorama.service`
//!   - `OpenRC`: `/etc/init.d/diorama`
//!   - `SysVinit`: `/etc/init.d/diorama`
//!   - Upstart: `/etc/init/diorama.conf`
//!   - Runit: `/etc/runit/sv/diorama/run`
//!   - S6: `/etc/s6/sv/diorama/run`
//! - Safe persistence & atomic backups:
//!   - Failed migration must NEVER overwrite valid configuration.
//!   - If `/etc/diorama/config.yaml` already exists, skip migration (already migrated).
//!   - If service file already has `--config`, skip migration.
//!   - Service file backup is created at `<service-path>.bak`.
//!   - Writes `/etc/diorama/config.yaml` with mode `0600`.
//!   - Replaces service unit command line with `--config=/etc/diorama/config.yaml`.
//!   - Emits operator notification:
//!     "Settings moved to a configuration file: /etc/diorama/config.yaml"
//!     "previous service definition kept at <service-path>.bak"
//!     "Restart required for changes to take effect."

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub use diorama_config::legacy::rewrite_service_content;
use diorama_config::legacy::{extract_service_flags, flags_to_config, has_config_flag};
use diorama_config::semver::supports_config_file;
use diorama_config::{DEFAULT_CONFIG_PATH, HostContext};
use diorama_platform::InitSystem;

/// Returns the standard service file path for a given init system.
pub fn service_file_path(init: InitSystem) -> Option<&'static str> {
    match init {
        InitSystem::Systemd => Some("/etc/systemd/system/diorama.service"),
        InitSystem::OpenRc | InitSystem::SysV => Some("/etc/init.d/diorama"),
        InitSystem::Upstart => Some("/etc/init/diorama.conf"),
        InitSystem::Runit => Some("/etc/runit/sv/diorama/run"),
        InitSystem::S6 => Some("/etc/s6/sv/diorama/run"),
        InitSystem::Unknown => None,
    }
}

/// Result of performing a service file migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceMigrationResult {
    /// Target version does not support config file (`< v1.3.0`). Kept legacy flags.
    VersionGateSkipped { target_version: String },
    /// Config file already exists. Migration skipped to avoid overwriting valid configuration.
    DestinationConfigExists { config_path: PathBuf },
    /// Service file already specifies `--config`. No action needed.
    AlreadyMigrated { service_path: PathBuf },
    /// No legacy flags found in service file or service file not found.
    NoLegacyFlags,
    /// Successfully converted legacy flags to config file and updated service unit.
    Migrated {
        config_path: PathBuf,
        service_path: PathBuf,
        service_backup_path: PathBuf,
        config_backup_created: bool,
    },
}

/// Executes safe migration of legacy service flags to versioned YAML file and updates service file.
///
/// Enforces:
/// 1. Version gate: if `target_version < v1.3.0`, skip config file migration (keeps flags).
/// 2. If destination config file already exists, skips migration (preserves valid config).
/// 3. If service definition already contains `--config`, skips migration.
/// 4. Extracts legacy flags and converts to YAML.
/// 5. Writes `/etc/diorama/config.yaml` atomically with mode `0600`.
/// 6. Creates service unit backup `<service-path>.bak`.
/// 7. Updates service unit file with `--config=/etc/diorama/config.yaml`.
/// 8. Emits notifications to stderr/stdout about file movement, backup, and restart requirement.
pub fn migrate_legacy_service(
    service_path: &Path,
    destination_config_path: Option<&Path>,
    target_version: &str,
    host: Option<&HostContext>,
    stderr: &mut dyn Write,
) -> io::Result<ServiceMigrationResult> {
    // 1. Version gate check (Gate D02: MinConfigFileVersion = v1.3.0)
    if !supports_config_file(target_version) {
        writeln!(
            stderr,
            "Notice: Target version '{target_version}' does not support --config (< v1.3.0); keeping service arguments."
        )?;
        return Ok(ServiceMigrationResult::VersionGateSkipped {
            target_version: target_version.to_string(),
        });
    }

    let dest_config = destination_config_path.unwrap_or_else(|| Path::new(DEFAULT_CONFIG_PATH));

    // 2. If destination config exists, skip migration to avoid overwriting valid configuration
    let mut pending_name = service_path.as_os_str().to_owned();
    pending_name.push(".migration-pending");
    let pending_path = PathBuf::from(pending_name);
    if fs::symlink_metadata(dest_config).is_ok()
        && !(fs::symlink_metadata(&pending_path).is_ok_and(|m| m.is_file())
            && fs::symlink_metadata(dest_config).is_ok_and(|m| m.is_file())
            && fs::read(&pending_path)? == fs::read(dest_config)?)
    {
        return Ok(ServiceMigrationResult::DestinationConfigExists {
            config_path: dest_config.to_path_buf(),
        });
    }

    // Read service file
    let service_content = match fs::read_to_string(service_path) {
        Ok(c) => c,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(ServiceMigrationResult::NoLegacyFlags);
        },
        Err(err) => return Err(err),
    };

    // 3. If service definition already has --config, skip migration
    if has_config_flag(&service_content) {
        return Ok(ServiceMigrationResult::AlreadyMigrated {
            service_path: service_path.to_path_buf(),
        });
    }

    // 4. Extract legacy flags
    let extracted = extract_service_flags(&service_content);
    if extracted.flags.is_empty() {
        return Ok(ServiceMigrationResult::NoLegacyFlags);
    }

    // 5. Convert flags to validated Config model
    let config = flags_to_config(&extracted, host).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to convert legacy flags to configuration: {err}"),
        )
    })?;

    let service_backup_path =
        persist_migration(service_path, dest_config, &service_content, &config)?;

    // 9. Operator notifications
    writeln!(
        stderr,
        "Settings moved to a configuration file: {}",
        dest_config.display()
    )?;
    writeln!(
        stderr,
        "previous service definition kept at {}",
        service_backup_path.display()
    )?;
    writeln!(stderr, "Restart required for changes to take effect.")?;

    Ok(ServiceMigrationResult::Migrated {
        config_path: dest_config.to_path_buf(),
        service_path: service_path.to_path_buf(),
        service_backup_path,
        config_backup_created: false,
    })
}

/// Detects init system on host and runs service migration if a service file is present.
pub fn execute_legacy_migration(
    init_system: InitSystem,
    destination_config_path: Option<&Path>,
    target_version: &str,
    host: Option<&HostContext>,
    stderr: &mut dyn Write,
) -> io::Result<ServiceMigrationResult> {
    let Some(srv_path_str) = service_file_path(init_system) else {
        return Ok(ServiceMigrationResult::NoLegacyFlags);
    };
    let srv_path = Path::new(srv_path_str);
    if !srv_path.exists() {
        return Ok(ServiceMigrationResult::NoLegacyFlags);
    }
    migrate_legacy_service(
        srv_path,
        destination_config_path,
        target_version,
        host,
        stderr,
    )
}

fn persist_migration(
    service_path: &Path,
    dest_config: &Path,
    service_content: &str,
    config: &diorama_config::Config,
) -> io::Result<PathBuf> {
    let updated_service =
        rewrite_service_content(service_content, &dest_config.display().to_string());
    if updated_service == service_content || !has_config_flag(&updated_service) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "could not identify service execution arguments",
        ));
    }
    let parent = service_path.parent().unwrap_or_else(|| Path::new("."));
    let service_meta = fs::symlink_metadata(service_path)?;
    if !service_meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service definition must be a regular file",
        ));
    }
    let mut backup_service_path = service_path.as_os_str().to_owned();
    backup_service_path.push(".bak");
    let service_backup_path = PathBuf::from(backup_service_path);
    preserve_or_create(&service_backup_path, service_content.as_bytes())?;
    let mut staged_service = tempfile::NamedTempFile::new_in(parent)?;
    staged_service.write_all(updated_service.as_bytes())?;
    staged_service
        .as_file()
        .set_permissions(service_meta.permissions())?;
    staged_service.as_file().sync_all()?;

    let yaml = diorama_config::render_effective_yaml(config)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    // A durable pending marker permits completion after interruption between the two renames.
    let mut marker_name = service_path.as_os_str().to_owned();
    marker_name.push(".migration-pending");
    let marker_path = PathBuf::from(marker_name);
    preserve_or_create(&marker_path, yaml.as_bytes())?;
    fs::File::open(parent)?.sync_all()?;
    let config_parent = dest_config.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(config_parent)?;
    let mut staged_config = tempfile::NamedTempFile::new_in(config_parent)?;
    staged_config.write_all(yaml.as_bytes())?;
    staged_config.as_file().sync_all()?;
    match staged_config.persist_noclobber(dest_config) {
        Ok(_) => {},
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(dest_config)?.is_file()
                || fs::read(dest_config)? != yaml.as_bytes()
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "destination changed during migration; preserving it",
                ));
            }
        },
        Err(e) => return Err(e.error),
    }
    fs::File::open(config_parent)?.sync_all()?;
    if let Err(e) = staged_service.persist(service_path) {
        // Leave the marker and validated document so the same migration can resume safely.
        return Err(e.error);
    }
    fs::File::open(parent)?.sync_all()?;
    fs::remove_file(marker_path)?;
    Ok(service_backup_path)
}

fn preserve_or_create(path: &Path, bytes: &[u8]) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && fs::read(path)? == bytes => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "conflicting backup or migration marker; preserving it",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut staging =
                tempfile::NamedTempFile::new_in(path.parent().unwrap_or_else(|| Path::new(".")))?;
            staging.write_all(bytes)?;
            staging.as_file().sync_all()?;
            staging.persist_noclobber(path).map_err(|e| e.error)?;
            Ok(())
        },
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_file_paths() {
        assert_eq!(
            service_file_path(InitSystem::Systemd),
            Some("/etc/systemd/system/diorama.service")
        );
        assert_eq!(
            service_file_path(InitSystem::OpenRc),
            Some("/etc/init.d/diorama")
        );
        assert_eq!(
            service_file_path(InitSystem::SysV),
            Some("/etc/init.d/diorama")
        );
        assert_eq!(
            service_file_path(InitSystem::Upstart),
            Some("/etc/init/diorama.conf")
        );
        assert_eq!(
            service_file_path(InitSystem::Runit),
            Some("/etc/runit/sv/diorama/run")
        );
        assert_eq!(
            service_file_path(InitSystem::S6),
            Some("/etc/s6/sv/diorama/run")
        );
        assert_eq!(service_file_path(InitSystem::Unknown), None);
    }

    #[test]
    fn test_rewrite_service_content() {
        let content = "ExecStart=/usr/local/bin/diorama --node-ip=1.2.3.4 --debug\n";
        let rewritten = rewrite_service_content(content, "/etc/diorama/config.yaml");
        assert!(rewritten.contains("--config=/etc/diorama/config.yaml"));
        assert!(!rewritten.contains("--node-ip=1.2.3.4"));
        assert!(!rewritten.contains("--debug"));
    }

    #[test]
    fn test_version_gate_preserves_legacy_flags_for_old_version() {
        let mut stderr = Vec::new();
        let service_path = Path::new("/nonexistent/kubesolo.service");
        let result =
            migrate_legacy_service(service_path, None, "v1.2.0", None, &mut stderr).unwrap();

        assert_eq!(
            result,
            ServiceMigrationResult::VersionGateSkipped {
                target_version: "v1.2.0".to_string()
            }
        );
        let out = String::from_utf8_lossy(&stderr);
        assert!(out.contains("does not support --config (< v1.3.0)"));
    }

    #[test]
    fn test_migrate_legacy_service_workflow() {
        let dir = std::env::temp_dir().join(format!("diorama-mig-srv-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let service_file = dir.join("kubesolo.service");
        let config_file = dir.join("config.yaml");

        let initial_service = r"[Unit]
Description=KubeSolo
[Service]
ExecStart=/usr/local/bin/diorama --node-ip=10.0.0.100 --debug --path=/var/lib/mykubesolo
Restart=always
";
        fs::write(&service_file, initial_service).unwrap();

        let mut stderr = Vec::new();
        let result = migrate_legacy_service(
            &service_file,
            Some(&config_file),
            "v1.3.0",
            None,
            &mut stderr,
        )
        .unwrap();

        let service_backup = dir.join("kubesolo.service.bak");
        assert_eq!(
            result,
            ServiceMigrationResult::Migrated {
                config_path: config_file.clone(),
                service_path: service_file.clone(),
                service_backup_path: service_backup.clone(),
                config_backup_created: false,
            }
        );

        // Verify config.yaml was created with correct settings
        assert!(config_file.exists());
        let config_str = fs::read_to_string(&config_file).unwrap();
        assert!(config_str.contains("nodeIP: 10.0.0.100"));
        assert!(config_str.contains("debug: true"));
        assert!(config_str.contains("path: /var/lib/mykubesolo"));

        // Verify service backup was created with exact initial content
        assert!(service_backup.exists());
        assert_eq!(
            fs::read_to_string(&service_backup).unwrap(),
            initial_service
        );

        // Verify service file was updated with --config
        let updated_service = fs::read_to_string(&service_file).unwrap();
        assert!(updated_service.contains(&format!("--config={}", config_file.display())));
        assert!(!updated_service.contains("--node-ip=10.0.0.100"));
        assert!(!updated_service.contains("--debug"));

        // Verify operator notification output
        let stderr_str = String::from_utf8_lossy(&stderr);
        assert!(stderr_str.contains("Settings moved to a configuration file"));
        assert!(stderr_str.contains("previous service definition kept at"));
        assert!(stderr_str.contains("Restart required for changes to take effect."));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_existing_config_skips_and_does_not_overwrite() {
        let dir = std::env::temp_dir().join(format!("diorama-mig-srv-skip-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let service_file = dir.join("kubesolo.service");
        let config_file = dir.join("config.yaml");

        fs::write(&config_file, "original custom yaml").unwrap();
        fs::write(
            &service_file,
            "ExecStart=/usr/local/bin/diorama --node-ip=9.9.9.9",
        )
        .unwrap();

        let mut stderr = Vec::new();
        let result = migrate_legacy_service(
            &service_file,
            Some(&config_file),
            "v1.4.0",
            None,
            &mut stderr,
        )
        .unwrap();

        assert_eq!(
            result,
            ServiceMigrationResult::DestinationConfigExists {
                config_path: config_file.clone()
            }
        );
        // Original config preserved intact
        assert_eq!(
            fs::read_to_string(&config_file).unwrap(),
            "original custom yaml"
        );

        let _ = fs::remove_dir_all(dir);
    }
}
