//! `dioramactl reset` and `dioramactl uninstall`: scoped cleanup of diorama-owned state.
//!
//! Ownership model (relative to the data path, default `/var/lib/diorama`):
//!
//! | Entry            | reset  | uninstall | uninstall `--purge` |
//! | ---------------- | ------ | --------- | ------------------- |
//! | `kine/db`        | remove | keep      | remove              |
//! | `kubelet`        | remove | keep      | remove              |
//! | `containerd/root`, `containerd/state` | remove | keep | remove |
//! | remaining `containerd` inputs | keep | keep | remove          |
//! | `network`        | remove | keep      | remove              |
//! | `pki`            | keep   | keep      | remove              |
//! | `local-path-storage` | keep | keep   | remove              |
//! | `backups`        | keep   | keep      | remove              |
//! | `container.spec` | keep   | keep      | remove              |
//! | anything else    | keep   | keep      | keep                |
//!
//! Only the named entries are ever removed, so neighbouring data in a shared directory is
//! retained. Symlinks (for example `storage/<volume>` pointing at a custom data volume) are
//! unlinked, never followed. Custom volumes and bind mounts outside the data path, external
//! container runtimes and unrelated processes or port holders are never touched. Reset keeps
//! the instance's configuration, service definition, binary and PKI.
//! Cleanup is idempotent and may be re-run after interruption.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use crate::upgrade::{CONTAINER_SPEC_FILE, ContainerSpec, Runner};

/// Disposable entries removed by reset and purge; ordinary uninstall retains data.
pub const RUNTIME_STATE: [&str; 5] = [
    "kine/db",
    "kubelet",
    "containerd/root",
    "containerd/state",
    "network",
];
/// Entries additionally removed by `uninstall --purge`.
pub const PURGE_STATE: [&str; 8] = [
    "pki",
    "local-path-storage",
    "backups",
    CONTAINER_SPEC_FILE,
    "containerd",
    ".upgrade-pending",
    ".upgrade-committing",
    ".upgrade-completed",
];
/// Entries retained unless purging, listed for reporting.
pub const RETAINED_STATE: [&str; 8] = PURGE_STATE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupKind {
    Reset,
    Uninstall { purge: bool, keep_config: bool },
}

/// Exact removal/retention decision for the entries present on disk.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanupPlan {
    pub remove: Vec<PathBuf>,
    pub retain: Vec<PathBuf>,
}

/// Rejects paths that cannot be a dedicated diorama data directory.
pub fn validate_data_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("data path '{}' must be absolute", path.display()));
    }
    let normal: Vec<_> = path
        .components()
        .filter(|c| matches!(c, std::path::Component::Normal(_)))
        .collect();
    if normal.len() < 2
        || path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(format!("refusing unsafe data path '{}'", path.display()));
    }
    Ok(())
}

/// Computes the plan from the owned entries that exist under `data`.
pub fn plan_cleanup(kind: CleanupKind, data: &Path) -> CleanupPlan {
    let purge = matches!(kind, CleanupKind::Uninstall { purge: true, .. });
    let mut plan = CleanupPlan::default();
    let exists = |p: &Path| p.symlink_metadata().is_ok();
    for name in RUNTIME_STATE {
        if purge && name.starts_with("containerd/") {
            continue;
        }
        let p = data.join(name);
        if exists(&p) {
            if matches!(kind, CleanupKind::Uninstall { purge: false, .. }) {
                plan.retain.push(p);
            } else {
                plan.remove.push(p);
            }
        }
    }
    for name in RETAINED_STATE {
        let p = data.join(name);
        if exists(&p) {
            if purge {
                plan.remove.push(p);
            } else {
                plan.retain.push(p);
            }
        }
    }
    plan
}

/// Host-mode side effects.
pub trait CleanupHost {
    fn stop_service(&mut self) -> io::Result<()>;
    fn start_service(&mut self) -> io::Result<()>;
    /// Mount points at or below `root` (never outside it).
    fn mounts_under(&mut self, root: &Path) -> io::Result<Vec<PathBuf>>;
    fn unmount(&mut self, mount: &Path) -> io::Result<()>;
    /// Removes the service definition and binary; returns removed paths.
    fn remove_service_artifacts(&mut self) -> io::Result<Vec<PathBuf>>;
    /// Remove startup registration before deleting state or executable artifacts.
    fn unregister_service(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn lock_cleanup(kind: CleanupKind, data: &Path) -> io::Result<fs::File> {
    let lock = crate::upgrade::lock_installation(data)?;
    if !matches!(kind, CleanupKind::Uninstall { purge: true, .. }) {
        for name in [".upgrade-pending", ".upgrade-committing"] {
            let receipt = data.join(name);
            match receipt.symlink_metadata() {
                Ok(_) => {
                    return Err(io::Error::other(format!(
                        "an interrupted upgrade requires recovery using {}; cleanup refused (explicit purge discards recovery state)",
                        receipt.display()
                    )));
                },
                Err(error) if error.kind() == io::ErrorKind::NotFound => {},
                Err(error) => return Err(error),
            }
        }
    }
    Ok(lock)
}

/// Reads an explicit confirmation; non-interactive EOF is a refusal.
pub fn confirm(prompt: &str, input: &mut dyn BufRead, out: &mut dyn Write) -> io::Result<bool> {
    write!(out, "{prompt} [y/N]: ")?;
    out.flush()?;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Ok(false);
    }
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn remove_entry(path: &Path) -> io::Result<()> {
    match path.symlink_metadata() {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Final report of a cleanup run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub removed: Vec<PathBuf>,
    pub retained: Vec<PathBuf>,
    pub declined: bool,
}

fn announce(
    kind: CleanupKind,
    plan: &CleanupPlan,
    force: bool,
    input: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> io::Result<bool> {
    writeln!(
        stderr,
        "  The following diorama-owned paths will be removed:"
    )?;
    for p in &plan.remove {
        writeln!(stderr, "    - {}", p.display())?;
    }
    for p in &plan.retain {
        writeln!(stderr, "  Retained: {}", p.display())?;
    }
    if force {
        return Ok(true);
    }
    let what = match kind {
        CleanupKind::Reset => "reset cluster state",
        CleanupKind::Uninstall { purge: true, .. } => "uninstall and PURGE all diorama data",
        CleanupKind::Uninstall { purge: false, .. } => "uninstall diorama",
    };
    confirm(&format!("  Really {what}?"), input, stderr)
}

/// Host cleanup. Order: confirm, stop, unmount selected mounts, remove, then (reset) restart.
/// Removal is refused for any owned entry that still contains a mount point.
pub fn run_host_cleanup(
    host: &mut dyn CleanupHost,
    kind: CleanupKind,
    data: &Path,
    force: bool,
    input: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> io::Result<CleanupReport> {
    run_host_cleanup_with_configuration(host, kind, data, None, force, input, stderr)
}

/// Host cleanup with an explicitly selected configuration directory.
/// Library callers without a selected directory perform no configuration I/O.
#[allow(clippy::too_many_arguments)]
pub fn run_host_cleanup_with_configuration(
    host: &mut dyn CleanupHost,
    kind: CleanupKind,
    data: &Path,
    configuration: Option<&Path>,
    force: bool,
    input: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> io::Result<CleanupReport> {
    validate_data_path(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let _lock = lock_cleanup(kind, data)?;
    let mut plan = plan_cleanup(kind, data);
    validate_removal_ancestors(data, &plan)?;
    let selection = configuration.map(|p| ConfigurationSelection::Directory(p.to_path_buf()));
    add_configuration_plan(kind, selection.as_ref(), &mut plan)?;
    if !announce(kind, &plan, force, input, stderr)? {
        writeln!(stderr, "  Aborted; nothing was changed.")?;
        return Ok(CleanupReport {
            retained: plan.retain,
            declined: true,
            ..CleanupReport::default()
        });
    }
    host.stop_service()?;
    for mount in host
        .mounts_under(data)?
        .into_iter()
        .filter(|mount| plan.remove.iter().any(|path| mount.starts_with(path)))
    {
        host.unmount(&mount)?;
    }
    // Defence in depth: never delete through a surviving mount.
    if let Some(left) = host
        .mounts_under(data)?
        .into_iter()
        .find(|mount| plan.remove.iter().any(|path| mount.starts_with(path)))
    {
        return Err(io::Error::other(format!(
            "mount {} is still active; refusing to remove data",
            left.display()
        )));
    }
    let mut report = CleanupReport {
        retained: plan.retain.clone(),
        ..CleanupReport::default()
    };
    if matches!(kind, CleanupKind::Uninstall { .. }) {
        host.unregister_service()?;
    }
    for p in &plan.remove {
        remove_entry(p)?;
        report.removed.push(p.clone());
    }
    if matches!(kind, CleanupKind::Uninstall { .. }) {
        report.removed.extend(host.remove_service_artifacts()?);
        if matches!(kind, CleanupKind::Uninstall { purge: true, .. }) {
            // Only removes the directory when nothing foreign remains in it.
            let _ = fs::remove_dir(data);
        }
    } else {
        host.start_service()?;
        writeln!(stderr, "  [ok] Cluster state reset; service restarted")?;
    }
    Ok(report)
}

/// Container cleanup: addresses only the named container, never the engine's other objects.
#[allow(clippy::too_many_arguments)] // mirrors run_host_cleanup plus the engine and container identity
pub fn run_container_cleanup(
    runner: &mut dyn Runner,
    engine: &str,
    spec: &ContainerSpec,
    kind: CleanupKind,
    data: &Path,
    force: bool,
    input: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> io::Result<CleanupReport> {
    run_container_cleanup_with_configuration(
        runner, engine, spec, kind, data, None, force, input, stderr,
    )
}

/// Configuration ownership established by a directory or an exact file binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigurationSelection {
    Directory(PathBuf),
    File(PathBuf),
}

/// Container cleanup using the same explicit configuration retention policy as host cleanup.
#[allow(clippy::too_many_arguments)]
pub fn run_container_cleanup_with_configuration(
    runner: &mut dyn Runner,
    engine: &str,
    spec: &ContainerSpec,
    kind: CleanupKind,
    data: &Path,
    configuration: Option<&Path>,
    force: bool,
    input: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> io::Result<CleanupReport> {
    let selection = configuration.map(|p| ConfigurationSelection::Directory(p.to_path_buf()));
    run_container_cleanup_with_selection(
        runner,
        engine,
        spec,
        kind,
        data,
        selection.as_ref(),
        force,
        input,
        stderr,
    )
}

/// Container cleanup with configuration ownership scoped to the recorded binding.
#[allow(clippy::too_many_arguments)]
pub fn run_container_cleanup_with_selection(
    runner: &mut dyn Runner,
    engine: &str,
    spec: &ContainerSpec,
    kind: CleanupKind,
    data: &Path,
    configuration: Option<&ConfigurationSelection>,
    force: bool,
    input: &mut dyn BufRead,
    stderr: &mut dyn Write,
) -> io::Result<CleanupReport> {
    validate_data_path(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let _lock = lock_cleanup(kind, data)?;
    let mut plan = plan_cleanup(kind, data);
    validate_removal_ancestors(data, &plan)?;
    add_configuration_plan(kind, configuration, &mut plan)?;
    if !announce(kind, &plan, force, input, stderr)? {
        writeln!(stderr, "  Aborted; nothing was changed.")?;
        return Ok(CleanupReport {
            retained: plan.retain,
            declined: true,
            ..CleanupReport::default()
        });
    }
    let name = spec.name.clone();
    let run = |runner: &mut dyn Runner, args: &[&str]| {
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        runner.run(engine, &args)
    };
    // Only verified absence is idempotent; an Engine or stop failure must not permit deletion.
    let present = match run(runner, &["stop", &name]) {
        Ok(_) => true,
        Err(stop_error) => {
            let names = run(runner, &["ps", "-a", "--format", "{{.Names}}"])?;
            if names.lines().any(|n| n == name) {
                return Err(stop_error);
            }
            false
        },
    };
    if !present && kind == CleanupKind::Reset {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "cannot reset a missing container",
        ));
    }
    let mut report = CleanupReport {
        retained: plan.retain.clone(),
        ..CleanupReport::default()
    };
    match kind {
        CleanupKind::Reset => {
            for p in &plan.remove {
                remove_entry(p)?;
                report.removed.push(p.clone());
            }
            run(runner, &["start", &name])?;
            writeln!(stderr, "  [ok] Cluster state reset; container restarted")?;
        },
        CleanupKind::Uninstall { purge, .. } => {
            if present {
                run(runner, &["rm", &name])?;
            }
            for p in &plan.remove {
                remove_entry(p)?;
                report.removed.push(p.clone());
            }
            if purge {
                let _ = fs::remove_dir(data);
            }
        },
    }
    Ok(report)
}

fn validate_removal_ancestors(data: &Path, plan: &CleanupPlan) -> io::Result<()> {
    crate::upgrade::reject_symlink_state(data, "")?;
    for path in &plan.remove {
        let relative = path.strip_prefix(data).map_err(io::Error::other)?;
        // Unlink a selected symlink itself, but never traverse a symlinked parent.
        if let Some(parent) = relative.parent() {
            crate::upgrade::reject_symlink_state(data, &parent.to_string_lossy())?;
        }
    }
    Ok(())
}

fn add_configuration_plan(
    kind: CleanupKind,
    selection: Option<&ConfigurationSelection>,
    plan: &mut CleanupPlan,
) -> io::Result<()> {
    let (CleanupKind::Uninstall { keep_config, .. }, Some(selection)) = (kind, selection) else {
        return Ok(());
    };
    let (directory, paths) = match selection {
        ConfigurationSelection::Directory(directory) => (
            directory.as_path(),
            vec![
                directory.join("config.yaml"),
                directory.join("config.yaml.bak"),
            ],
        ),
        ConfigurationSelection::File(file) => {
            (file.parent().unwrap_or(Path::new("")), vec![file.clone()])
        },
    };
    validate_configuration_directory(directory)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // Configuration is outside the data root; validate its own parent chain before effects.
    let mut parent = PathBuf::new();
    for component in directory.components() {
        parent.push(component);
        crate::upgrade::reject_symlink_state(&parent, "")?;
    }
    for path in paths {
        match path.symlink_metadata() {
            Ok(meta) if meta.is_dir() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "configuration is a directory",
                ));
            },
            Ok(_) => {
                if keep_config {
                    plan.retain.push(path);
                } else {
                    plan.remove.push(path);
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn validate_configuration_directory(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || !path
            .components()
            .any(|c| matches!(c, std::path::Component::Normal(_)))
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!(
            "refusing unsafe configuration directory '{}'",
            path.display()
        ));
    }
    Ok(())
}

/// Real host: `systemd` or `SysV` service control, `/proc/self/mounts`, `umount`.
#[derive(Debug)]
pub struct SystemHost<'a, R: Runner> {
    pub runner: &'a mut R,
    pub systemd: bool,
    pub service: String,
    pub artifacts: Vec<PathBuf>,
}

impl<R: Runner> SystemHost<'_, R> {
    fn svc(&mut self, verb: &str) -> io::Result<()> {
        let (prog, args) = if self.systemd {
            ("systemctl", vec![verb.to_string(), self.service.clone()])
        } else {
            ("service", vec![self.service.clone(), verb.to_string()])
        };
        self.runner.run(prog, &args).map(|_| ())
    }
}

/// Parses mount points from `/proc/self/mounts` text, deepest first, below `root` only.
pub fn parse_mounts_under(mounts: &str, root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = mounts
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(|m| PathBuf::from(m.replace("\\040", " ")))
        .filter(|m| m.starts_with(root))
        .collect();
    found.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    found
}

impl<R: Runner> CleanupHost for SystemHost<'_, R> {
    fn stop_service(&mut self) -> io::Result<()> {
        self.svc("stop")
    }

    fn start_service(&mut self) -> io::Result<()> {
        self.svc("start")
    }

    fn mounts_under(&mut self, root: &Path) -> io::Result<Vec<PathBuf>> {
        match fs::read_to_string("/proc/self/mounts") {
            Ok(text) => Ok(parse_mounts_under(&text, root)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    fn unmount(&mut self, mount: &Path) -> io::Result<()> {
        self.runner
            .run("umount", &[mount.to_string_lossy().into_owned()])
            .map(|_| ())
    }

    fn remove_service_artifacts(&mut self) -> io::Result<Vec<PathBuf>> {
        let mut removed = Vec::new();
        for p in self.artifacts.clone() {
            if p.symlink_metadata().is_ok() {
                remove_entry(&p)?;
                removed.push(p);
            }
        }
        Ok(removed)
    }
}

/// Detected-init host cleanup using the existing service lifecycle plans.
#[derive(Debug)]
pub struct ServiceHost<'a, R: Runner> {
    host: SystemHost<'a, R>,
    config: crate::service::ServiceConfig,
}

impl<'a, R: Runner> ServiceHost<'a, R> {
    pub fn new(runner: &'a mut R, config: crate::service::ServiceConfig) -> io::Result<Self> {
        use crate::service::{InitBackend, LifecycleAction, plan_lifecycle_action};
        let plan =
            plan_lifecycle_action(LifecycleAction::Uninstall, &config).map_err(io::Error::other)?;
        let mut artifacts = plan.cleanup_paths;
        if config.backend == Some(InitBackend::OpenRc) {
            let relative = format!("etc/conf.d/{}", config.name);
            let conf = config.custom_paths.root_prefix.as_ref().map_or_else(
                || Path::new("/").join(&relative),
                |root| root.join(&relative),
            );
            if !artifacts.contains(&conf) {
                artifacts.push(conf);
            }
        }
        artifacts.push(config.binary_path.clone());
        Ok(Self {
            host: SystemHost {
                runner,
                systemd: config.backend == Some(InitBackend::Systemd),
                service: config.name.clone(),
                artifacts,
            },
            config,
        })
    }

    fn action(&mut self, action: crate::service::LifecycleAction) -> io::Result<()> {
        let plan = crate::service::plan_lifecycle_action(action, &self.config)
            .map_err(io::Error::other)?;
        for mut step in plan.commands {
            if action == crate::service::LifecycleAction::Stop
                && self.config.backend == Some(crate::service::InitBackend::S6)
            {
                // s6-svc -d only requests shutdown; wait for run/finish to exit.
                // https://skarnet.org/software/s6/s6-svc.html
                step.args
                    .splice(0..0, ["-wD".into(), "-T".into(), "30000".into()]);
            }
            self.host.runner.run(&step.program, &step.args)?;
        }
        Ok(())
    }
}

impl<R: Runner> CleanupHost for ServiceHost<'_, R> {
    fn stop_service(&mut self) -> io::Result<()> {
        self.action(crate::service::LifecycleAction::Stop)
    }
    fn start_service(&mut self) -> io::Result<()> {
        self.action(crate::service::LifecycleAction::Start)
    }
    fn mounts_under(&mut self, root: &Path) -> io::Result<Vec<PathBuf>> {
        self.host.mounts_under(root)
    }
    fn unmount(&mut self, mount: &Path) -> io::Result<()> {
        self.host.unmount(mount)
    }
    fn unregister_service(&mut self) -> io::Result<()> {
        let plan = crate::service::plan_lifecycle_action(
            crate::service::LifecycleAction::Uninstall,
            &self.config,
        )
        .map_err(io::Error::other)?;
        // Stop already succeeded before mount checks. Retain all later registration operations.
        for step in plan.commands.into_iter().skip(1) {
            self.host.runner.run(&step.program, &step.args)?;
        }
        Ok(())
    }
    fn remove_service_artifacts(&mut self) -> io::Result<Vec<PathBuf>> {
        use crate::service::InitBackend;
        let removed = self.host.remove_service_artifacts()?;
        // Refresh caches after removing definitions, as well as before removal.
        match self.config.backend {
            Some(InitBackend::Systemd) => {
                self.host
                    .runner
                    .run("systemctl", &["daemon-reload".into()])?;
            },
            Some(InitBackend::Upstart) => {
                self.host
                    .runner
                    .run("initctl", &["reload-configuration".into()])?;
            },
            _ => {},
        }
        Ok(removed)
    }
}

fn detected_service_config() -> io::Result<crate::service::ServiceConfig> {
    let evidence = diorama_platform::discover(&diorama_platform::DiscoveryRequest::default())
        .map_err(io::Error::other)?;
    let init = match diorama_platform::classify(&evidence).init {
        diorama_platform::Observation::Present(init) => init,
        observation => {
            return Err(io::Error::other(format!(
                "init detection failed: {observation:?}"
            )));
        },
    };
    Ok(crate::service::ServiceConfig {
        backend: Some(crate::service::InitBackend::try_from(init).map_err(io::Error::other)?),
        binary_path: PathBuf::from(crate::DEFAULT_INSTALL_PATH),
        ..crate::service::ServiceConfig::default()
    })
}

fn container_configuration_selection(
    spec: &ContainerSpec,
) -> io::Result<Option<ConfigurationSelection>> {
    let mut selected = None;
    for mount in &spec.mounts {
        let mut fields = mount.split(':');
        let source = Path::new(fields.next().unwrap_or(""));
        let target = fields.next().unwrap_or("");
        let selection = match target {
            "/etc/diorama" => ConfigurationSelection::Directory(source.to_path_buf()),
            "/etc/diorama/config.yaml" => ConfigurationSelection::File(source.to_path_buf()),
            _ => continue,
        };
        if !source.is_absolute() || selected.replace(selection).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ambiguous configuration binding; explicit cleanup is required",
            ));
        }
    }
    Ok(selected)
}

/// Shared command entry for reset/uninstall.
pub fn execute_cleanup(
    kind: CleanupKind,
    data: &Path,
    force: bool,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    use crate::upgrade::ProcessRunner;
    let mut runner = ProcessRunner;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let spec_path = data.join(CONTAINER_SPEC_FILE);
    let result = if spec_path.is_file() {
        match fs::read_to_string(&spec_path)
            .map_err(|e| e.to_string())
            .and_then(|t| ContainerSpec::parse(&t))
        {
            Ok(spec) => (if kind == CleanupKind::Reset {
                Ok(None)
            } else {
                container_configuration_selection(&spec)
            })
            .and_then(|configuration| {
                run_container_cleanup_with_selection(
                    &mut runner,
                    "docker",
                    &spec,
                    kind,
                    data,
                    configuration.as_ref(),
                    force,
                    &mut input,
                    stderr,
                )
            }),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    } else {
        detected_service_config().and_then(|config| {
            let mut host = ServiceHost::new(&mut runner, config)?;
            run_host_cleanup_with_configuration(
                &mut host,
                kind,
                data,
                Some(Path::new("/etc/diorama")),
                force,
                &mut input,
                stderr,
            )
        })
    };
    match result {
        Ok(r) if r.declined => Ok(1),
        Ok(_) => Ok(0),
        Err(e) => {
            writeln!(stderr, "  [fail] {e}")?;
            Ok(1)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_configuration_selection_requires_an_explicit_owned_binding() {
        let mut spec = ContainerSpec::default();
        assert_eq!(container_configuration_selection(&spec).unwrap(), None);
        spec.mounts = vec!["/srv/instance/config:/etc/diorama:ro".into()];
        assert_eq!(
            container_configuration_selection(&spec).unwrap(),
            Some(ConfigurationSelection::Directory(PathBuf::from(
                "/srv/instance/config"
            )))
        );
        spec.mounts = vec!["/srv/instance/config.yaml:/etc/diorama/config.yaml:ro".into()];
        assert_eq!(
            container_configuration_selection(&spec).unwrap(),
            Some(ConfigurationSelection::File(PathBuf::from(
                "/srv/instance/config.yaml"
            )))
        );
        spec.mounts = vec!["foreign-volume:/etc/diorama".into()];
        assert!(container_configuration_selection(&spec).is_err());
        spec.mounts = vec!["/srv/foreign.yaml:/etc/diorama/config.yaml".into()];
        assert_eq!(
            container_configuration_selection(&spec).unwrap(),
            Some(ConfigurationSelection::File(PathBuf::from(
                "/srv/foreign.yaml"
            )))
        );
        assert!(validate_configuration_directory(Path::new("/tmp")).is_ok());
        for path in ["/", "relative", "/tmp/../etc"] {
            assert!(validate_configuration_directory(Path::new(path)).is_err());
        }
    }

    #[derive(Debug, Default)]
    struct FakeHost {
        log: Vec<String>,
        mounts: Vec<PathBuf>,
        fail_unmount: bool,
        artifacts: Vec<PathBuf>,
    }

    impl CleanupHost for FakeHost {
        fn stop_service(&mut self) -> io::Result<()> {
            self.log.push("stop".into());
            Ok(())
        }
        fn start_service(&mut self) -> io::Result<()> {
            self.log.push("start".into());
            Ok(())
        }
        fn mounts_under(&mut self, _: &Path) -> io::Result<Vec<PathBuf>> {
            Ok(self.mounts.clone())
        }
        fn unmount(&mut self, m: &Path) -> io::Result<()> {
            self.log.push(format!("umount {}", m.display()));
            if self.fail_unmount {
                return Err(io::Error::other("busy"));
            }
            self.mounts.retain(|x| x != m);
            Ok(())
        }
        fn remove_service_artifacts(&mut self) -> io::Result<Vec<PathBuf>> {
            self.log.push("rm-service".into());
            for a in &self.artifacts {
                let _ = fs::remove_file(a);
            }
            Ok(self.artifacts.clone())
        }
    }

    #[derive(Debug, Default)]
    struct Rec(Vec<String>);
    impl Runner for Rec {
        fn run(&mut self, p: &str, a: &[String]) -> io::Result<String> {
            self.0.push(format!("{p} {}", a.join(" ")));
            Ok(String::new())
        }
    }

    fn tree() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for n in [
            "kine/db",
            "kubelet",
            "containerd/root",
            "containerd/state",
            "containerd/images",
            "containerd/registry",
            "network",
            "pki",
            "local-path-storage",
            "backups",
            "neighbor",
        ] {
            fs::create_dir_all(d.path().join(n)).unwrap();
            fs::write(d.path().join(n).join("f"), n).unwrap();
        }
        fs::write(d.path().join(CONTAINER_SPEC_FILE), "x").unwrap();
        d
    }

    fn names(root: &Path, v: &[PathBuf]) -> Vec<String> {
        let mut n: Vec<_> = v
            .iter()
            .map(|p| p.strip_prefix(root).unwrap().display().to_string())
            .collect();
        n.sort();
        n
    }

    fn exists(root: &Path, n: &str) -> bool {
        root.join(n).symlink_metadata().is_ok()
    }

    #[test]
    fn reset_matrix_removes_runtime_state_keeps_pki_and_volumes() {
        let d = tree();
        let mut h = FakeHost::default();
        let r = run_host_cleanup(
            &mut h,
            CleanupKind::Reset,
            d.path(),
            true,
            &mut io::empty().lock_empty(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            names(d.path(), &r.removed),
            [
                "containerd/root",
                "containerd/state",
                "kine/db",
                "kubelet",
                "network"
            ]
        );
        for keep in [
            "pki",
            "local-path-storage",
            "backups",
            "neighbor",
            "containerd/images",
            "containerd/registry",
            CONTAINER_SPEC_FILE,
        ] {
            assert!(exists(d.path(), keep), "{keep}");
        }
        assert_eq!(h.log, ["stop", "start"]);
    }

    #[test]
    fn uninstall_keeps_pki_and_data_without_purge() {
        let d = tree();
        let mut h = FakeHost {
            artifacts: vec![],
            ..FakeHost::default()
        };
        let r = run_host_cleanup(
            &mut h,
            CleanupKind::Uninstall {
                purge: false,
                keep_config: false,
            },
            d.path(),
            true,
            &mut io::empty().lock_empty(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            names(d.path(), &r.retain_or_empty()),
            [
                "backups",
                "container.spec",
                "containerd",
                "containerd/root",
                "containerd/state",
                "kine/db",
                "kubelet",
                "local-path-storage",
                "network",
                "pki"
            ]
        );
        assert!(exists(d.path(), "pki") && exists(d.path(), "local-path-storage"));
        assert!(exists(d.path(), "kine/db"));
        assert!(h.log.contains(&"rm-service".to_string()) && !h.log.contains(&"start".to_string()));
    }

    #[test]
    fn purge_removes_owned_state_but_not_neighbors() {
        let d = tree();
        let mut h = FakeHost::default();
        run_host_cleanup(
            &mut h,
            CleanupKind::Uninstall {
                purge: true,
                keep_config: false,
            },
            d.path(),
            true,
            &mut io::empty().lock_empty(),
            &mut Vec::new(),
        )
        .unwrap();
        for gone in [
            "kine/db",
            "pki",
            "local-path-storage",
            "backups",
            "containerd",
            CONTAINER_SPEC_FILE,
        ] {
            assert!(!exists(d.path(), gone), "{gone}");
        }
        assert!(exists(d.path(), "neighbor"));
        assert!(d.path().exists(), "non-empty data dir must remain");
    }

    #[test]
    fn purge_does_not_follow_symlinked_custom_volume() {
        let d = tree();
        let vol = tempfile::tempdir().unwrap();
        fs::write(vol.path().join("precious"), "data").unwrap();
        fs::remove_dir_all(d.path().join("local-path-storage")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(vol.path(), d.path().join("local-path-storage")).unwrap();
        let mut h = FakeHost::default();
        run_host_cleanup(
            &mut h,
            CleanupKind::Uninstall {
                purge: true,
                keep_config: false,
            },
            d.path(),
            true,
            &mut io::empty().lock_empty(),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(!exists(d.path(), "local-path-storage"));
        assert!(vol.path().join("precious").is_file());
    }

    #[test]
    fn confirmation_required_and_declined_changes_nothing() {
        for answer in ["", "n\n", "no\n", "\n"] {
            // Each answer is an independent confirmation case. Reusing one lock inode
            // can observe unrelated concurrent test children's inherited fork handles.
            let d = tree();
            let mut h = FakeHost::default();
            let mut input = io::Cursor::new(answer.as_bytes().to_vec());
            let r = run_host_cleanup(
                &mut h,
                CleanupKind::Reset,
                d.path(),
                false,
                &mut input,
                &mut Vec::new(),
            )
            .unwrap();
            assert!(r.declined && h.log.is_empty());
            assert!(exists(d.path(), "kine/db"));
        }
        let d = tree();
        let mut h = FakeHost::default();
        let mut input = io::Cursor::new(b"yes\n".to_vec());
        let r = run_host_cleanup(
            &mut h,
            CleanupKind::Reset,
            d.path(),
            false,
            &mut input,
            &mut Vec::new(),
        )
        .unwrap();
        assert!(!r.declined && !exists(d.path(), "kine/db"));
    }

    #[test]
    fn busy_mount_blocks_removal() {
        let d = tree();
        let mut h = FakeHost {
            mounts: vec![d.path().join("kubelet/pods/x")],
            fail_unmount: true,
            ..FakeHost::default()
        };
        let e = run_host_cleanup(
            &mut h,
            CleanupKind::Reset,
            d.path(),
            true,
            &mut io::empty().lock_empty(),
            &mut Vec::new(),
        );
        assert!(e.is_err());
        assert!(exists(d.path(), "kine/db") && exists(d.path(), "kubelet/f"));
    }

    #[test]
    fn repeated_cleanup_is_idempotent() {
        let d = tree();
        for _ in 0..2 {
            reset_after_test_child_releases_lock(d.path()).unwrap();
        }
        assert!(exists(d.path(), "pki"));
    }

    // Concurrent tests can fork while cleanup owns the lock. A child temporarily
    // retaining the same open-file description outlives cleanup's local guard.
    // Retry only this contention before any host effects; other errors and a
    // persistent owner still fail. Production cleanup remains nonblocking.
    fn reset_after_test_child_releases_lock(data: &Path) -> io::Result<CleanupReport> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut host = FakeHost::default();
        loop {
            match run_host_cleanup(
                &mut host,
                CleanupKind::Reset,
                data,
                true,
                &mut io::empty().lock_empty(),
                &mut Vec::new(),
            ) {
                Err(error)
                    if error.to_string()
                        == "another upgrade or cleanup owns this installation: lock acquisition failed because the operation would block"
                        && std::time::Instant::now() < deadline =>
                {
                    assert!(
                        host.log.is_empty(),
                        "a refused owner must have no host effects"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                },
                result => return result,
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn duplicated_lock_descriptor_blocks_cleanup_until_released() {
        let data = tree();
        let owner = crate::upgrade::lock_installation(data.path()).unwrap();
        let retained = owner.try_clone().unwrap();
        drop(owner);
        let mut host = FakeHost::default();
        let error = run_host_cleanup(
            &mut host,
            CleanupKind::Reset,
            data.path(),
            true,
            &mut io::empty().lock_empty(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("another upgrade or cleanup owns")
        );
        assert_eq!(host.log, Vec::<String>::new());
        assert!(exists(data.path(), "kine/db"));
        drop(retained);
        reset_after_test_child_releases_lock(data.path()).unwrap();
        assert!(!exists(data.path(), "kine/db"));
    }

    #[test]
    fn unsafe_paths_rejected() {
        for p in ["/", "/var", "relative/x", "/var/lib/../etc"] {
            assert!(validate_data_path(Path::new(p)).is_err(), "{p}");
        }
        assert!(validate_data_path(Path::new("/var/lib/diorama")).is_ok());
    }

    #[test]
    fn mount_parsing_is_scoped_deepest_first() {
        let text = "a /var/lib/diorama/kubelet/p tmpfs\nb /var/lib/diorama-other x\nc /var/lib/diorama/kubelet/p/q x\nd /proc proc\n";
        let m = parse_mounts_under(text, Path::new("/var/lib/diorama"));
        assert_eq!(
            m,
            [
                PathBuf::from("/var/lib/diorama/kubelet/p/q"),
                PathBuf::from("/var/lib/diorama/kubelet/p")
            ]
        );
    }

    const SPEC: &str = "name=diorama\nimage=x/diorama:v1.2.0\nmount=/srv/volumes:/data\n";

    #[test]
    fn container_uninstall_touches_only_named_container_and_keeps_custom_volume() {
        let d = tree();
        let vol = tempfile::tempdir().unwrap();
        let mut r = Rec::default();
        let spec = ContainerSpec::parse(SPEC).unwrap();
        run_container_cleanup(
            &mut r,
            "docker",
            &spec,
            CleanupKind::Uninstall {
                purge: false,
                keep_config: false,
            },
            d.path(),
            true,
            &mut io::empty().lock_empty(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(r.0, ["docker stop diorama", "docker rm diorama"]);
        assert!(exists(d.path(), "pki") && exists(d.path(), "kine/db"));
        assert!(vol.path().exists());
    }

    #[test]
    fn container_reset_restarts_container() {
        let d = tree();
        let mut r = Rec::default();
        let spec = ContainerSpec::parse(SPEC).unwrap();
        run_container_cleanup(
            &mut r,
            "docker",
            &spec,
            CleanupKind::Reset,
            d.path(),
            true,
            &mut io::empty().lock_empty(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(r.0, ["docker stop diorama", "docker start diorama"]);
        assert!(exists(d.path(), "pki"));
    }

    trait EmptyLock {
        fn lock_empty(self) -> io::Cursor<Vec<u8>>;
    }
    impl EmptyLock for io::Empty {
        fn lock_empty(self) -> io::Cursor<Vec<u8>> {
            io::Cursor::new(Vec::new())
        }
    }
    trait Retain {
        fn retain_or_empty(&self) -> Vec<PathBuf>;
    }
    impl Retain for CleanupReport {
        fn retain_or_empty(&self) -> Vec<PathBuf> {
            self.retained.clone()
        }
    }
}
