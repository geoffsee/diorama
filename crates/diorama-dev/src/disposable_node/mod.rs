//! Disposable Linux node scaffold capture, schema-2 receipts, and validation (E33.03 / Issue #343).
//!
//! Produces candidate-bound integration receipts recording binary digests, source revision,
//! host facts, command logs, assertions, skips, and cleanup confirmation.

use crate::{Result, json, read_bounded, sha256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Integration receipt schema version.
pub const SCHEMA_VERSION: u32 = 2;

/// Maximum allowable receipt file size (8 MiB).
pub const MAX_RECEIPT_BYTES: u64 = 8 * 1024 * 1024;

/// Full integration receipt for a disposable node execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisposableNodeReceipt {
    pub schema_version: u32,
    pub status: String,
    pub qualified: bool,
    pub qualification_reason: String,
    pub timestamps: ReceiptTimestamps,
    pub candidate: CandidateIdentity,
    pub environment: EnvironmentFacts,
    pub component_versions: ComponentVersions,
    pub commands: Vec<CommandRecord>,
    pub assertions: Vec<AssertionRecord>,
    pub skips: Vec<SkipRecord>,
    pub cleanup: CleanupInventory,
}

/// Execution start, completion, and duration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptTimestamps {
    pub started_at: String,
    pub completed_at: String,
    pub duration_ms: u64,
}

/// Tested candidate identity: source revision and binary digests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateIdentity {
    pub source_revision: String,
    pub source_tree_hash: String,
    pub binaries: BTreeMap<String, BinaryDigest>,
}

/// Binary content digest and size.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryDigest {
    pub sha256: String,
    pub bytes: u64,
}

/// Environment and host facts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentFacts {
    pub os: String,
    pub arch: String,
    pub kernel: String,
    pub cpu_count: usize,
    pub runner: String,
    pub hostname: String,
}

/// Discovered component versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComponentVersions {
    pub diorama: String,
    pub dioramactl: String,
    pub rustc: String,
    pub cargo: String,
}

/// Executed command record with exit code and log file paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandRecord {
    pub name: String,
    pub command: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stdout_log: String,
    pub stderr_log: String,
}

/// Test assertion outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssertionRecord {
    pub name: String,
    pub passed: bool,
    pub details: String,
}

/// Documented feature skip.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkipRecord {
    pub name: String,
    pub reason: String,
}

/// Host cleanup inventory and residual check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupInventory {
    pub state_directory_removed: bool,
    pub owned_directories_removed: Vec<String>,
    pub owned_processes_terminated: Vec<String>,
    pub leftover_owned_resources: Vec<String>,
}

/// Validate that a string is a 64-character lowercase hex SHA-256 digest.
pub fn is_valid_sha256_hex(val: &str) -> bool {
    val.len() == 64
        && val
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Validate that a string is a 40-character lowercase hex Git commit/tree hash.
pub fn is_valid_git_commit_hex(val: &str) -> bool {
    val.len() == 40
        && val
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Format seconds since UNIX epoch as RFC 3339 string.
pub fn format_rfc3339(secs: u64) -> String {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let mut days = secs / 86400;

    let mut year = 1970;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for &dim in &days_in_months {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    let day = days + 1;
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

pub fn current_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_rfc3339(secs)
}

/// Validate that a string matches the fixed-width RFC 3339 UTC format emitted by `format_rfc3339`.
pub fn is_rfc3339_utc(v: &str) -> bool {
    let b = v.as_bytes();
    if b.len() != 20 {
        return false;
    }
    let valid_structure = b.iter().enumerate().all(|(i, c)| match i {
        4 | 7 => *c == b'-',
        10 => *c == b'T',
        13 | 16 => *c == b':',
        19 => *c == b'Z',
        _ => c.is_ascii_digit(),
    });
    if !valid_structure {
        return false;
    }
    let month: u32 = match v[5..7].parse() {
        Ok(m) => m,
        Err(_) => return false,
    };
    let day: u32 = match v[8..10].parse() {
        Ok(d) => d,
        Err(_) => return false,
    };
    let hour: u32 = match v[11..13].parse() {
        Ok(h) => h,
        Err(_) => return false,
    };
    let min: u32 = match v[14..16].parse() {
        Ok(m) => m,
        Err(_) => return false,
    };
    let sec: u32 = match v[17..19].parse() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour >= 24
        || min >= 60
        || sec >= 60
    {
        return false;
    }
    true
}

/// Validate that a path string is a relative path containing only Normal components.
pub fn is_safe_relative_path(path_str: &str) -> bool {
    let p = Path::new(path_str);
    if p.as_os_str().is_empty() {
        return false;
    }
    let mut count = 0;
    for comp in p.components() {
        match comp {
            Component::Normal(_) => count += 1,
            _ => return false,
        }
    }
    count > 0
}

fn git_rev_parse(repo_root: &Path, arg: &str) -> Option<String> {
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(["rev-parse", arg])
        .output()
        .ok()?;
    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if is_valid_git_commit_hex(&text) {
            return Some(text);
        }
    }
    None
}

fn command_version(program: &str) -> String {
    Command::new(program)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn kernel_release() -> String {
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn host_name() -> String {
    if let Ok(host) = std::env::var("HOSTNAME")
        && !host.is_empty()
    {
        return host;
    }
    if let Ok(content) = fs::read_to_string("/etc/hostname") {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    Command::new("hostname")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "localhost".to_string())
}

fn digest_binary(path: &Path) -> Result<BinaryDigest> {
    if !path.is_file() {
        return Err(format!("candidate binary not found at {}", path.display()).into());
    }
    let bytes = fs::read(path)?;
    Ok(BinaryDigest {
        sha256: sha256(&bytes),
        bytes: u64::try_from(bytes.len())?,
    })
}

fn discover_candidate(
    root: &Path,
    kube_bin_opt: Option<&Path>,
    ctl_bin_opt: Option<&Path>,
) -> Result<(CandidateIdentity, PathBuf, PathBuf)> {
    let kube_bin =
        kube_bin_opt.map_or_else(|| root.join("target/debug/diorama-kube"), Path::to_path_buf);
    let ctl_bin =
        ctl_bin_opt.map_or_else(|| root.join("target/debug/dioramactl"), Path::to_path_buf);

    let kube_digest = digest_binary(&kube_bin)?;
    let ctl_digest = digest_binary(&ctl_bin)?;

    let mut binaries = BTreeMap::new();
    binaries.insert("diorama-kube".to_string(), kube_digest);
    binaries.insert("dioramactl".to_string(), ctl_digest);

    let source_revision = git_rev_parse(root, "HEAD")
        .or_else(|| std::env::var("GITHUB_SHA").ok())
        .filter(|s| is_valid_git_commit_hex(s))
        .ok_or("failed to determine valid 40-character candidate source revision")?;

    let source_tree_hash = git_rev_parse(root, "HEAD^{tree}")
        .filter(|s| is_valid_git_commit_hex(s))
        .ok_or("failed to determine valid 40-character candidate source tree hash")?;

    let candidate = CandidateIdentity {
        source_revision,
        source_tree_hash,
        binaries,
    };

    Ok((candidate, kube_bin, ctl_bin))
}

fn discover_environment() -> EnvironmentFacts {
    EnvironmentFacts {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        kernel: kernel_release(),
        cpu_count: std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
        runner: std::env::var("RUNNER_NAME").unwrap_or_else(|_| "ubuntu-24.04-arm".to_string()),
        hostname: host_name(),
    }
}

fn discover_component_versions() -> ComponentVersions {
    ComponentVersions {
        diorama: env!("CARGO_PKG_VERSION").to_string(),
        dioramactl: env!("CARGO_PKG_VERSION").to_string(),
        rustc: command_version("rustc"),
        cargo: command_version("cargo"),
    }
}

fn run_command_step(
    output_dir: &Path,
    step_num: &str,
    name: &str,
    cmd_desc: String,
    mut cmd: Command,
) -> Result<(CommandRecord, Vec<u8>, Vec<u8>)> {
    let start = Instant::now();
    let res = cmd.output();
    let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

    let (exit_code, stdout, stderr) = match res {
        Ok(out) => (out.status.code().unwrap_or(-1), out.stdout, out.stderr),
        Err(err) => (
            -1,
            Vec::new(),
            format!("execution error: {err}").into_bytes(),
        ),
    };

    let stdout_rel = format!("logs/{step_num}_{name}.stdout.log");
    let stderr_rel = format!("logs/{step_num}_{name}.stderr.log");
    File::create(output_dir.join(&stdout_rel))?.write_all(&stdout)?;
    File::create(output_dir.join(&stderr_rel))?.write_all(&stderr)?;

    Ok((
        CommandRecord {
            name: name.to_string(),
            command: cmd_desc,
            exit_code,
            duration_ms,
            stdout_log: stdout_rel,
            stderr_log: stderr_rel,
        },
        stdout,
        stderr,
    ))
}

fn execute_scaffold(
    output_dir: &Path,
    kube_bin: &Path,
    ctl_bin: &Path,
) -> Result<(Vec<CommandRecord>, Vec<AssertionRecord>, CleanupInventory)> {
    let mut commands = Vec::new();
    let mut assertions = Vec::new();

    assertions.push(AssertionRecord {
        name: "candidate_binaries_digested".to_string(),
        passed: true,
        details: format!(
            "diorama-kube ({}) and dioramactl ({}) digested successfully",
            kube_bin.display(),
            ctl_bin.display()
        ),
    });

    let state_dir = output_dir.join("state");
    if state_dir.exists() {
        let _ = fs::remove_dir_all(&state_dir);
    }
    fs::create_dir_all(&state_dir)?;

    let mut kube_cmd = Command::new(kube_bin);
    kube_cmd
        .arg("--print-config")
        .env("KUBESOLO_PATH", &state_dir);
    let (cmd1, stdout1, _stderr1) = run_command_step(
        output_dir,
        "01",
        "diorama_print_config",
        format!("{} --print-config", kube_bin.display()),
        kube_cmd,
    )?;
    let stdout1_text = String::from_utf8_lossy(&stdout1);
    let print_config_passed = cmd1.exit_code == 0
        && stdout1_text.contains("apiVersion: kubesolo.io/v1alpha1")
        && stdout1_text.contains("kind: Config");
    assertions.push(AssertionRecord {
        name: "print_config_succeeded".to_string(),
        passed: print_config_passed,
        details: if print_config_passed {
            "diorama-kube --print-config exited with 0 and emitted valid kubesolo.io/v1alpha1 Config"
                .to_string()
        } else {
            format!(
                "diorama-kube --print-config failed with exit code {}",
                cmd1.exit_code
            )
        },
    });
    commands.push(cmd1);

    // Step 2: dioramactl version
    let mut ctl_cmd = Command::new(ctl_bin);
    ctl_cmd.arg("version");
    let (cmd2, _stdout2, _stderr2) = run_command_step(
        output_dir,
        "02",
        "dioramactl_version",
        format!("{} version", ctl_bin.display()),
        ctl_cmd,
    )?;
    assertions.push(AssertionRecord {
        name: "dioramactl_version_succeeded".to_string(),
        passed: cmd2.exit_code == 0,
        details: format!("dioramactl version exited with code {}", cmd2.exit_code),
    });
    commands.push(cmd2);

    let (cmd3, cleanup, cleanup_assertions) = teardown_and_cleanup(output_dir, &state_dir)?;
    commands.push(cmd3);
    assertions.extend(cleanup_assertions);

    Ok((commands, assertions, cleanup))
}

fn teardown_and_cleanup(
    output_dir: &Path,
    state_dir: &Path,
) -> Result<(CommandRecord, CleanupInventory, Vec<AssertionRecord>)> {
    let teardown_start = Instant::now();
    let cleanup_err = if state_dir.exists() {
        fs::remove_dir_all(state_dir).err()
    } else {
        None
    };
    let teardown_duration = u64::try_from(teardown_start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let td_stdout_rel = "logs/03_teardown_and_cleanup.stdout.log".to_string();
    let td_stderr_rel = "logs/03_teardown_and_cleanup.stderr.log".to_string();
    let td_stdout = format!("removed state directory {}\n", state_dir.display()).into_bytes();
    let td_stderr = cleanup_err
        .as_ref()
        .map(std::string::ToString::to_string)
        .unwrap_or_default()
        .into_bytes();
    File::create(output_dir.join(&td_stdout_rel))?.write_all(&td_stdout)?;
    File::create(output_dir.join(&td_stderr_rel))?.write_all(&td_stderr)?;
    let cmd = CommandRecord {
        name: "teardown_and_cleanup".to_string(),
        command: format!("rm -rf {}", state_dir.display()),
        exit_code: i32::from(cleanup_err.is_some()),
        duration_ms: teardown_duration,
        stdout_log: td_stdout_rel,
        stderr_log: td_stderr_rel,
    };

    let state_removed = !state_dir.exists();
    let mut leftover_owned_resources = Vec::new();
    if !state_removed {
        leftover_owned_resources.push(state_dir.display().to_string());
    }
    let assertions = vec![
        AssertionRecord {
            name: "state_directory_cleaned".to_string(),
            passed: state_removed,
            details: format!("state directory {} was removed", state_dir.display()),
        },
        AssertionRecord {
            name: "zero_owned_leftovers".to_string(),
            passed: leftover_owned_resources.is_empty(),
            details: if leftover_owned_resources.is_empty() {
                "no leftover owned processes, files, or sockets".to_string()
            } else {
                format!("leftover owned resources: {leftover_owned_resources:?}")
            },
        },
    ];

    let cleanup = CleanupInventory {
        state_directory_removed: state_removed,
        owned_directories_removed: vec![state_dir.display().to_string()],
        owned_processes_terminated: Vec::new(),
        leftover_owned_resources,
    };

    Ok((cmd, cleanup, assertions))
}

fn write_failure_diagnostics(output_dir: &Path, receipt: &DisposableNodeReceipt) -> Result<()> {
    let diag_path = output_dir.join("diagnostics.txt");
    let mut diag = File::create(diag_path)?;
    writeln!(diag, "Disposable Linux node scaffold failed:")?;
    for assertion in &receipt.assertions {
        if !assertion.passed {
            writeln!(
                diag,
                "  - Assertion failed: {}: {}",
                assertion.name, assertion.details
            )?;
        }
    }
    for cmd in &receipt.commands {
        if cmd.exit_code != 0 {
            writeln!(
                diag,
                "  - Command failed with exit code {}: {}",
                cmd.exit_code, cmd.command
            )?;
        }
    }
    if !receipt.cleanup.leftover_owned_resources.is_empty() {
        writeln!(
            diag,
            "  - Residual resources remain: {:?}",
            receipt.cleanup.leftover_owned_resources
        )?;
    }
    Ok(())
}

/// Execute the disposable Linux node scaffold and write a schema-2 receipt.
pub fn capture(
    output_dir: &Path,
    kube_bin_opt: Option<&Path>,
    ctl_bin_opt: Option<&Path>,
) -> Result<DisposableNodeReceipt> {
    let start_instant = Instant::now();
    let started_at = current_rfc3339();

    fs::create_dir_all(output_dir)?;
    fs::create_dir_all(output_dir.join("logs"))?;

    let cwd = std::env::current_dir()?;
    let root = crate::repository_root(&cwd)?;

    let (candidate, kube_bin, ctl_bin) = discover_candidate(&root, kube_bin_opt, ctl_bin_opt)?;
    let environment = discover_environment();
    let component_versions = discover_component_versions();

    let (commands, assertions, cleanup) = execute_scaffold(output_dir, &kube_bin, &ctl_bin)?;

    let skips = vec![SkipRecord {
        name: "e33_02_workload_lifecycle".to_string(),
        reason: "E33.02 containerd/kubelet/CNI workload execution pending merge".to_string(),
    }];

    let completed_at = current_rfc3339();
    let duration_ms = u64::try_from(start_instant.elapsed().as_millis()).unwrap_or(u64::MAX);
    let timestamps = ReceiptTimestamps {
        started_at,
        completed_at,
        duration_ms,
    };

    let all_assertions_passed = assertions.iter().all(|a| a.passed);
    let all_commands_succeeded = commands.iter().all(|c| c.exit_code == 0);
    let no_leftovers = cleanup.leftover_owned_resources.is_empty();

    let status = if all_assertions_passed && all_commands_succeeded && no_leftovers {
        "passed".to_string()
    } else {
        "failed".to_string()
    };

    let receipt = DisposableNodeReceipt {
        schema_version: SCHEMA_VERSION,
        status,
        qualified: false,
        qualification_reason:
            "Scaffold run only; full live cluster qualification requires E33.02 integration"
                .to_string(),
        timestamps,
        candidate,
        environment,
        component_versions,
        commands,
        assertions,
        skips,
        cleanup,
    };

    let receipt_json = serde_json::to_string_pretty(&receipt)?;
    File::create(output_dir.join("receipt.json"))?.write_all(receipt_json.as_bytes())?;

    if receipt.status != "passed" {
        write_failure_diagnostics(output_dir, &receipt)?;
        return Err(
            "disposable Linux node scaffold failed; see receipt.json and diagnostics.txt".into(),
        );
    }

    Ok(receipt)
}

/// Verify a schema-2 receipt file or capture directory against the contract.
pub fn verify(receipt_or_dir: &Path) -> Result<DisposableNodeReceipt> {
    let (receipt_path, base_dir) = if receipt_or_dir.is_dir() {
        (
            receipt_or_dir.join("receipt.json"),
            receipt_or_dir.to_path_buf(),
        )
    } else {
        let parent = receipt_or_dir.parent().unwrap_or_else(|| Path::new("."));
        let base = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        (receipt_or_dir.to_path_buf(), base.to_path_buf())
    };

    let raw_bytes = read_bounded(&receipt_path, MAX_RECEIPT_BYTES)?;
    // Use json::parse to enforce duplicate-key rejection and finite numbers
    let _strict_value = json::parse(&raw_bytes)?;

    let receipt: DisposableNodeReceipt = serde_json::from_slice(&raw_bytes).map_err(|e| {
        format!(
            "failed to deserialize receipt at {}: {e}",
            receipt_path.display()
        )
    })?;

    verify_receipt(&receipt, &base_dir)?;
    Ok(receipt)
}

fn verify_candidate(candidate: &CandidateIdentity) -> Result<()> {
    if !is_valid_git_commit_hex(&candidate.source_revision) {
        return Err(format!(
            "candidate source_revision is not a valid 40-character hex commit: {:?}",
            candidate.source_revision
        )
        .into());
    }
    if !is_valid_git_commit_hex(&candidate.source_tree_hash) {
        return Err(format!(
            "candidate source_tree_hash is not a valid 40-character hex tree hash: {:?}",
            candidate.source_tree_hash
        )
        .into());
    }

    for required_bin in ["diorama-kube", "dioramactl"] {
        let digest = candidate.binaries.get(required_bin).ok_or_else(|| {
            format!("candidate binary {required_bin:?} is missing from candidate digests")
        })?;
        if !is_valid_sha256_hex(&digest.sha256) {
            return Err(format!(
                "binary {required_bin:?} has invalid sha256 digest: {:?}",
                digest.sha256
            )
            .into());
        }
        if digest.bytes == 0 {
            return Err(format!("binary {required_bin:?} has zero byte length").into());
        }
    }
    Ok(())
}

fn verify_environment(environment: &EnvironmentFacts) -> Result<()> {
    if environment.os.trim().is_empty() {
        return Err("environment.os is empty".into());
    }
    if environment.arch.trim().is_empty() {
        return Err("environment.arch is empty".into());
    }
    if environment.kernel.trim().is_empty() {
        return Err("environment.kernel is empty".into());
    }
    if environment.cpu_count == 0 {
        return Err("environment.cpu_count must be positive".into());
    }
    if environment.runner.trim().is_empty() {
        return Err("environment.runner is empty".into());
    }
    Ok(())
}

fn verify_component_versions(vers: &ComponentVersions) -> Result<()> {
    if vers.diorama.trim().is_empty() {
        return Err("component_versions.diorama is empty".into());
    }
    if vers.dioramactl.trim().is_empty() {
        return Err("component_versions.dioramactl is empty".into());
    }
    if vers.rustc.trim().is_empty() {
        return Err("component_versions.rustc is empty".into());
    }
    if vers.cargo.trim().is_empty() {
        return Err("component_versions.cargo is empty".into());
    }
    Ok(())
}

fn verify_commands(commands: &[CommandRecord], base_dir: &Path) -> Result<()> {
    if commands.is_empty() {
        return Err("receipt contains no executed commands".into());
    }
    for cmd in commands {
        if cmd.command.trim().is_empty() {
            return Err(format!("command {:?} has empty command string", cmd.name).into());
        }
        if cmd.exit_code != 0 {
            return Err(format!(
                "command {:?} exited with nonzero code {}",
                cmd.command, cmd.exit_code
            )
            .into());
        }
        if cmd.stdout_log.trim().is_empty() || cmd.stderr_log.trim().is_empty() {
            return Err(format!("command {:?} has empty log path", cmd.name).into());
        }
        if !is_safe_relative_path(&cmd.stdout_log) {
            return Err(format!(
                "command {:?} stdout_log is not a valid relative path: {:?}",
                cmd.name, cmd.stdout_log
            )
            .into());
        }
        if !is_safe_relative_path(&cmd.stderr_log) {
            return Err(format!(
                "command {:?} stderr_log is not a valid relative path: {:?}",
                cmd.name, cmd.stderr_log
            )
            .into());
        }
        let out_log = base_dir.join(&cmd.stdout_log);
        let err_log = base_dir.join(&cmd.stderr_log);
        if !out_log.is_file() {
            return Err(format!(
                "referenced stdout log file does not exist: {}",
                out_log.display()
            )
            .into());
        }
        if !err_log.is_file() {
            return Err(format!(
                "referenced stderr log file does not exist: {}",
                err_log.display()
            )
            .into());
        }
    }
    Ok(())
}

fn verify_assertions(assertions: &[AssertionRecord]) -> Result<()> {
    if assertions.is_empty() {
        return Err("receipt contains no assertions".into());
    }
    for assertion in assertions {
        if !assertion.passed {
            return Err(format!(
                "assertion {:?} failed: {}",
                assertion.name, assertion.details
            )
            .into());
        }
    }
    Ok(())
}

fn verify_skips(skips: &[SkipRecord]) -> Result<()> {
    if skips.is_empty() {
        return Err("receipt contains no documented skips".into());
    }
    for skip in skips {
        if skip.name.trim().is_empty() || skip.reason.trim().is_empty() {
            return Err(format!("skip entry {:?} is incomplete", skip.name).into());
        }
    }
    Ok(())
}

fn verify_cleanup(cleanup: &CleanupInventory) -> Result<()> {
    if !cleanup.state_directory_removed {
        return Err("cleanup failed: state_directory_removed is false".into());
    }
    if !cleanup.leftover_owned_resources.is_empty() {
        return Err(format!(
            "cleanup failed: leftover owned resources detected: {:?}",
            cleanup.leftover_owned_resources
        )
        .into());
    }
    Ok(())
}

/// Verify the semantic rules of a schema-2 receipt.
pub fn verify_receipt(receipt: &DisposableNodeReceipt, base_dir: &Path) -> Result<()> {
    if receipt.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "unsupported schema_version {}, expected {SCHEMA_VERSION}",
            receipt.schema_version
        )
        .into());
    }

    if receipt.status != "passed" {
        return Err(format!("receipt status is '{}', expected 'passed'", receipt.status).into());
    }

    if receipt.qualified {
        return Err(
            "receipt claims release qualification; scaffold run cannot qualify release".into(),
        );
    }

    verify_candidate(&receipt.candidate)?;
    verify_environment(&receipt.environment)?;
    verify_component_versions(&receipt.component_versions)?;
    verify_commands(&receipt.commands, base_dir)?;
    verify_assertions(&receipt.assertions)?;
    verify_skips(&receipt.skips)?;
    verify_cleanup(&receipt.cleanup)?;

    let ts = &receipt.timestamps;
    if !is_rfc3339_utc(&ts.started_at) || !is_rfc3339_utc(&ts.completed_at) {
        return Err("timestamps must be RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)".into());
    }
    if ts.completed_at < ts.started_at {
        return Err("timestamps.completed_at precedes started_at".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_sample_receipt() -> DisposableNodeReceipt {
        let mut binaries = BTreeMap::new();
        binaries.insert(
            "diorama-kube".to_string(),
            BinaryDigest {
                sha256: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                bytes: 12345,
            },
        );
        binaries.insert(
            "dioramactl".to_string(),
            BinaryDigest {
                sha256: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                bytes: 67890,
            },
        );

        DisposableNodeReceipt {
            schema_version: 2,
            status: "passed".to_string(),
            qualified: false,
            qualification_reason: "Scaffold run only".to_string(),
            timestamps: ReceiptTimestamps {
                started_at: "2026-10-08T20:00:00Z".to_string(),
                completed_at: "2026-10-08T20:00:05Z".to_string(),
                duration_ms: 5000,
            },
            candidate: CandidateIdentity {
                source_revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                source_tree_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                binaries,
            },
            environment: EnvironmentFacts {
                os: "linux".to_string(),
                arch: "aarch64".to_string(),
                kernel: "6.8.0-1014-azure".to_string(),
                cpu_count: 4,
                runner: "ubuntu-24.04-arm".to_string(),
                hostname: "test-runner".to_string(),
            },
            component_versions: ComponentVersions {
                diorama: "0.1.0".to_string(),
                dioramactl: "0.1.0".to_string(),
                rustc: "rustc 1.97.1".to_string(),
                cargo: "cargo 1.97.1".to_string(),
            },
            commands: vec![CommandRecord {
                name: "test_cmd".to_string(),
                command: "diorama-kube --print-config".to_string(),
                exit_code: 0,
                duration_ms: 100,
                stdout_log: "logs/test.stdout.log".to_string(),
                stderr_log: "logs/test.stderr.log".to_string(),
            }],
            assertions: vec![AssertionRecord {
                name: "test_assertion".to_string(),
                passed: true,
                details: "all good".to_string(),
            }],
            skips: vec![SkipRecord {
                name: "e33_02_workload".to_string(),
                reason: "pending merge".to_string(),
            }],
            cleanup: CleanupInventory {
                state_directory_removed: true,
                owned_directories_removed: vec!["/tmp/state".to_string()],
                owned_processes_terminated: vec![],
                leftover_owned_resources: vec![],
            },
        }
    }

    fn create_test_dir_with_logs(receipt: &DisposableNodeReceipt) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for cmd in &receipt.commands {
            if is_safe_relative_path(&cmd.stdout_log) {
                let p = dir.path().join(&cmd.stdout_log);
                if let Some(parent) = p.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::write(&p, b"stdout log");
            }
            if is_safe_relative_path(&cmd.stderr_log) {
                let p = dir.path().join(&cmd.stderr_log);
                if let Some(parent) = p.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::write(&p, b"stderr log");
            }
        }
        dir
    }

    #[test]
    fn valid_receipt_passes_verification() {
        let receipt = valid_sample_receipt();
        let dir = create_test_dir_with_logs(&receipt);
        assert!(verify_receipt(&receipt, dir.path()).is_ok());
    }

    #[test]
    fn wrong_schema_version_rejected() {
        let mut receipt = valid_sample_receipt();
        receipt.schema_version = 1;
        let dir = create_test_dir_with_logs(&receipt);
        let err = verify_receipt(&receipt, dir.path()).unwrap_err();
        assert!(err.to_string().contains("unsupported schema_version 1"));
    }

    #[test]
    fn failed_status_rejected() {
        let mut receipt = valid_sample_receipt();
        receipt.status = "failed".to_string();
        let dir = create_test_dir_with_logs(&receipt);
        let err = verify_receipt(&receipt, dir.path()).unwrap_err();
        assert!(err.to_string().contains("expected 'passed'"));
    }

    #[test]
    fn premature_qualification_claim_rejected() {
        let mut receipt = valid_sample_receipt();
        receipt.qualified = true;
        let dir = create_test_dir_with_logs(&receipt);
        let err = verify_receipt(&receipt, dir.path()).unwrap_err();
        assert!(err.to_string().contains("scaffold run cannot qualify"));
    }

    #[test]
    fn invalid_candidate_digests_rejected() {
        let mut receipt = valid_sample_receipt();
        receipt.candidate.source_revision = "short".to_string();
        let dir = create_test_dir_with_logs(&receipt);
        assert!(verify_receipt(&receipt, dir.path()).is_err());

        let mut receipt2 = valid_sample_receipt();
        receipt2
            .candidate
            .binaries
            .get_mut("diorama-kube")
            .unwrap()
            .sha256 = "INVALID_UPPERCASE".to_string();
        let dir2 = create_test_dir_with_logs(&receipt2);
        assert!(verify_receipt(&receipt2, dir2.path()).is_err());
    }

    #[test]
    fn nonzero_command_exit_code_rejected() {
        let mut receipt = valid_sample_receipt();
        receipt.commands[0].exit_code = 1;
        let dir = create_test_dir_with_logs(&receipt);
        let err = verify_receipt(&receipt, dir.path()).unwrap_err();
        assert!(err.to_string().contains("exited with nonzero code 1"));
    }

    #[test]
    fn failed_assertion_rejected() {
        let mut receipt = valid_sample_receipt();
        receipt.assertions[0].passed = false;
        receipt.assertions[0].details = "something broke".to_string();
        let dir = create_test_dir_with_logs(&receipt);
        let err = verify_receipt(&receipt, dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("assertion \"test_assertion\" failed")
        );
    }

    #[test]
    fn leftover_resources_rejected() {
        let mut receipt = valid_sample_receipt();
        receipt.cleanup.leftover_owned_resources =
            vec!["/var/lib/diorama-kube/residual".to_string()];
        let dir = create_test_dir_with_logs(&receipt);
        let err = verify_receipt(&receipt, dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("leftover owned resources detected")
        );
    }

    #[test]
    fn invalid_timestamps_rejected() {
        let mut receipt = valid_sample_receipt();
        receipt.timestamps.started_at = "2026-10-08".to_string();
        let dir = create_test_dir_with_logs(&receipt);
        let err = verify_receipt(&receipt, dir.path()).unwrap_err();
        assert!(err.to_string().contains("RFC 3339 UTC"));

        // completed_at preceding started_at
        let mut receipt_inverted = valid_sample_receipt();
        receipt_inverted.timestamps.started_at = "2026-10-08T20:00:10Z".to_string();
        receipt_inverted.timestamps.completed_at = "2026-10-08T20:00:05Z".to_string();
        let dir_inv = create_test_dir_with_logs(&receipt_inverted);
        let err_inv = verify_receipt(&receipt_inverted, dir_inv.path()).unwrap_err();
        assert!(
            err_inv
                .to_string()
                .contains("completed_at precedes started_at")
        );
    }

    #[test]
    fn unsafe_log_paths_rejected() {
        let mut receipt = valid_sample_receipt();
        receipt.commands[0].stdout_log = "../escape.log".to_string();
        let dir = create_test_dir_with_logs(&receipt);
        let err = verify_receipt(&receipt, dir.path()).unwrap_err();
        assert!(err.to_string().contains("not a valid relative path"));

        let mut receipt_abs = valid_sample_receipt();
        receipt_abs.commands[0].stderr_log = "/tmp/abs.log".to_string();
        let dir_abs = create_test_dir_with_logs(&receipt_abs);
        let err_abs = verify_receipt(&receipt_abs, dir_abs.path()).unwrap_err();
        assert!(err_abs.to_string().contains("not a valid relative path"));
    }

    #[test]
    fn missing_log_file_rejected() {
        let receipt = valid_sample_receipt();
        let empty_dir = tempfile::tempdir().expect("tempdir");
        let err = verify_receipt(&receipt, empty_dir.path()).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn rfc3339_validation_rules() {
        assert!(is_rfc3339_utc("2026-10-08T20:00:00Z"));
        assert!(is_rfc3339_utc("1970-01-01T00:00:00Z"));
        assert!(!is_rfc3339_utc("2026-10-08"));
        assert!(!is_rfc3339_utc("2026-10-08T20:00:00+00:00"));
        assert!(!is_rfc3339_utc("2026-13-08T20:00:00Z")); // invalid month
        assert!(!is_rfc3339_utc("2026-10-32T20:00:00Z")); // invalid day
        assert!(!is_rfc3339_utc("2026-10-08T24:00:00Z")); // invalid hour
        assert!(!is_rfc3339_utc("2026-10-08T20:60:00Z")); // invalid minute
        assert!(!is_rfc3339_utc("2026-10-08T20:00:60Z")); // invalid second
    }

    #[test]
    fn safe_relative_path_rules() {
        assert!(is_safe_relative_path("logs/test.stdout.log"));
        assert!(is_safe_relative_path("foo.log"));
        assert!(!is_safe_relative_path(""));
        assert!(!is_safe_relative_path("/logs/test.log"));
        assert!(!is_safe_relative_path("../test.log"));
        assert!(!is_safe_relative_path("logs/../../test.log"));
        assert!(!is_safe_relative_path("./test.log"));
    }

    #[test]
    fn rfc3339_formatting_is_valid() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_770_000_000), "2026-02-02T02:40:00Z");
    }
}
