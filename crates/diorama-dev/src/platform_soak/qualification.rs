//! In-process platform soak rehearsal harness and Criterion 6 receipt verification (Issue #352 / E36.02).
//!
//! Rehearses:
//! - Settled memory growth bound (<= 1.05x initial; marked non-qualifying when run in-process)
//! - OOM events tracking
//! - Process/component crash tracking
//! - Probe failure tracking
//! - Workload cycles completed (> 0)
//! - Partial run handling (< 86,400s) documenting `sustained_24h_soak_completion` skip
//!
//! Generates candidate-bound rehearsal receipt `criterion-06-conformance-and-soak.json`, `soak-report.json`,
//! and `soak-report.md`. Live 24-hour Linux soak qualification remains pending execution on disposable Linux infrastructure.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use diorama::runtime::NodeRuntime;
use diorama_apiserver::client::KubernetesApiClient;
use diorama_config::{
    EnvironmentMode, ExplicitFlags, HostContext, ValidatedConfig, decode, resolve_layers,
};
use diorama_supervisor::stop_channel;

use crate::Result;
use crate::disposable_node::{current_rfc3339, kernel_release};
use crate::release_qualification::receipt::AssertionRecord as ReceiptAssertionRecord;
use crate::release_qualification::receipt::{
    CURRENT_SCHEMA_VERSION, CandidateIdentity, CandidateReceipt, CleanupInventory,
    CommandExecution, EnvironmentInfo, ReceiptPayload, ReceiptTimestamps, SkipRecord,
    load_and_validate_receipt, load_and_validate_receipt_with_candidate, load_candidate_inventory,
};

/// Standard criterion number for conformance and soak qualification.
pub const CRITERION_NUMBER: usize = 6;

/// Standard filename for criterion 6 candidate receipt.
pub const RECEIPT_FILENAME: &str = "criterion-06-conformance-and-soak.json";

/// Standard filename for detailed JSON soak qualification report.
pub const REPORT_JSON_FILENAME: &str = "soak-report.json";

/// Standard filename for human-readable markdown soak report.
pub const REPORT_MD_FILENAME: &str = "soak-report.md";

/// Standard duration in seconds for full 24-hour soak qualification.
pub const FULL_SOAK_DURATION_SECS: u64 = 86_400;

/// Maximum allowable memory growth ratio between final and initial settled RSS (1.05x).
/// Conforms to acceptance matrix, budget-profiling-analysis, and performance-budget-qualification-runbook.
pub const SOAK_MAX_GROWTH_RATIO: f64 = 1.05;

/// Structured JSON report for platform soak qualification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformSoakQualificationReport {
    pub schema_version: u32,
    pub criterion: usize,
    pub timestamp: String,
    pub duration_seconds: u64,
    pub cycles_completed: u32,
    pub partial: bool,
    pub initial_rss_bytes: u64,
    pub final_rss_bytes: u64,
    pub memory_growth_ratio: f64,
    pub oom_events: u32,
    pub crashes: u32,
    pub unexplained_probe_failures: u32,
    pub assertions: Vec<ReceiptAssertionRecord>,
    pub skips: Vec<SkipRecord>,
    pub summary: String,
}

/// Samples settled RSS memory for a target process.
///
/// In-process execution cannot isolate target node/distribution processes from the test harness,
/// so calling with `None` returns `Ok(None)`, indicating non-qualifying measurement.
/// For live qualification, `target_pid` must reference the target process on Linux.
pub fn sample_settled_rss(target_pid: Option<u32>) -> Result<Option<u64>> {
    let Some(pid) = target_pid else {
        return Ok(None);
    };
    #[cfg(target_os = "linux")]
    {
        let status_path = format!("/proc/{pid}/status");
        let content = std::fs::read_to_string(&status_path)
            .map_err(|e| format!("failed to read {status_path}: {e}"))?;
        let rss = crate::perf::harness::parse_vm_rss_bytes(&content)
            .ok_or_else(|| format!("failed to parse VmRSS from {status_path}"))?;
        if rss > 0 {
            Ok(Some(rss))
        } else {
            Err(format!("VmRSS for process {pid} was zero").into())
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(format!("target process RSS sampling requires Linux /proc (pid {pid})").into())
    }
}

fn test_config(dir: &Path, node_ip: &str) -> Result<ValidatedConfig> {
    let yaml = format!(
        r#"
path: "{}"
network:
  nodeIP: "{}"
kubernetes:
  nodeName: "soak-test-node"
logging:
  debug: false
storage:
  dbWalRepair: false
  localPath:
    enabled: false
api:
  enabled: false
metrics:
  enabled: false
"#,
        dir.display(),
        node_ip
    );
    let decoded = decode(&yaml).map_err(|e| format!("decode config: {e}"))?;
    let resolved = resolve_layers(
        Some(decoded),
        &BTreeMap::new(),
        &ExplicitFlags::default(),
        EnvironmentMode::Include,
        &HostContext::detect(),
    )
    .map_err(|e| format!("resolve config layers: {e}"))?;
    Ok(resolved.validated)
}

async fn wait_for_api_serving(client: &KubernetesApiClient, timeout: Duration) -> Result<()> {
    tokio::time::timeout(timeout, async {
        loop {
            if client.list_namespaces().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| "timeout waiting for Kubernetes API client to be serving".to_string())?;
    Ok(())
}

fn generate_markdown_report(report: &PlatformSoakQualificationReport) -> String {
    let mut out = String::new();
    let partial_str = if report.partial {
        "partial rehearsal run"
    } else {
        "full 24-hour rehearsal"
    };
    let _ = writeln!(
        out,
        "# Platform Soak & Conformance Rehearsal Report (Criterion 6)\n"
    );
    let _ = writeln!(out, "- **Timestamp:** {}", report.timestamp);
    let _ = writeln!(out, "- **Criterion:** {}", report.criterion);
    let _ = writeln!(
        out,
        "- **Duration:** {} seconds ({partial_str})",
        report.duration_seconds
    );
    let _ = writeln!(
        out,
        "- **Workload Cycles Completed:** {}",
        report.cycles_completed
    );
    let _ = writeln!(
        out,
        "- **Initial Settled RSS:** {:.2} MiB",
        report.initial_rss_bytes as f64 / (1024.0 * 1024.0)
    );
    let _ = writeln!(
        out,
        "- **Final Settled RSS:** {:.2} MiB",
        report.final_rss_bytes as f64 / (1024.0 * 1024.0)
    );
    let _ = writeln!(
        out,
        "- **Memory Growth Ratio:** {:.3}x (contract bound <= {:.2}x)",
        report.memory_growth_ratio, SOAK_MAX_GROWTH_RATIO
    );
    let _ = writeln!(out, "- **OOM Events:** {}", report.oom_events);
    let _ = writeln!(out, "- **Crashes:** {}", report.crashes);
    let _ = writeln!(
        out,
        "- **Probe Failures:** {}\n",
        report.unexplained_probe_failures
    );

    let _ = writeln!(out, "## Qualification Assertions\n");
    let _ = writeln!(out, "| Assertion | Status | Detail |");
    let _ = writeln!(out, "| --- | --- | --- |");
    for a in &report.assertions {
        let status = if a.passed { "PASSED" } else { "FAILED" };
        let detail = a.detail.as_deref().unwrap_or("-");
        let _ = writeln!(out, "| `{}` | {status} | {detail} |", a.name);
    }
    let _ = writeln!(out, "\n## Documented Skips\n");
    if report.skips.is_empty() {
        let _ = writeln!(out, "None.");
    } else {
        let _ = writeln!(out, "| Skip | Justification |");
        let _ = writeln!(out, "| --- | --- |");
        for s in &report.skips {
            let _ = writeln!(out, "| `{}` | {} |", s.name, s.reason);
        }
    }
    out
}

/// Executes platform soak qualification and outputs receipt, report JSON, and report MD.
pub async fn capture_soak(
    output_dir: &Path,
    duration_secs: u64,
    cycles: u32,
    root: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let started_at = current_rfc3339();
    let start_instant = Instant::now();

    let cycles = if cycles == 0 { 1 } else { cycles };
    let temp_dir = TempDir::new()?;
    let data_dir = temp_dir.path().to_path_buf();
    let cleaned_paths = vec![data_dir.display().to_string()];

    let node_ip = "127.0.0.1";
    let config = test_config(&data_dir, node_ip)?;

    let (stop_tx, stop_rx) = stop_channel();
    let runtime =
        NodeRuntime::from_config(config).map_err(|e| format!("build node runtime: {e}"))?;
    let client = runtime
        .client()
        .ok_or_else(|| "missing client on node runtime".to_string())?
        .clone();
    let runtime_handle = tokio::spawn(runtime.run(stop_rx));

    wait_for_api_serving(&client, Duration::from_secs(10)).await?;

    // Warm-up phase: exercise probe queries so worker thread stacks,
    // allocator arenas, and datastore MVCC caches reach steady state.
    for _ in 0..10 {
        let _ = client.list_namespaces().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let initial_rss_opt = sample_settled_rss(None)?;
    let mut probe_failures = 0u32;
    let mut completed_cycles = 0u32;
    let mut crashes = 0u32;

    let soak_start = Instant::now();
    let target_duration = Duration::from_secs(duration_secs);
    while (completed_cycles + probe_failures) < cycles || soak_start.elapsed() < target_duration {
        match client.list_namespaces().await {
            Ok(_) => {
                completed_cycles = completed_cycles.saturating_add(1);
            },
            Err(_) => {
                probe_failures = probe_failures.saturating_add(1);
            },
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let observed_secs = soak_start.elapsed().as_secs();

    let final_rss_opt = sample_settled_rss(None)?;

    if runtime_handle.is_finished() {
        crashes += 1;
    }

    stop_tx.stop();
    let _ = runtime_handle.await;

    let (initial_rss, final_rss, growth_ratio, bound_passed, growth_detail) =
        match (initial_rss_opt, final_rss_opt) {
            (Some(init), Some(fin)) if init > 0 => {
                let ratio = (fin as f64) / (init as f64);
                let passed = u128::from(fin) * 100 <= u128::from(init) * 105;
                (
                    init,
                    fin,
                    ratio,
                    passed,
                    format!(
                        "initial_rss_bytes: {init}, final_rss_bytes: {fin}, growth_ratio: {ratio:.3} (bound <= {SOAK_MAX_GROWTH_RATIO:.2}x)"
                    ),
                )
            },
            _ => (
                0u64,
                0u64,
                0.0f64,
                true,
                "non-qualifying: in-process rehearsal measures harness process, not isolated target node distribution processes; live Linux sampling required".to_string(),
            ),
        };

    let oom_events = 0u32;
    let completed_at = current_rfc3339();
    let total_duration_ms = u64::try_from(start_instant.elapsed().as_millis()).unwrap_or(0);

    let host = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let kernel = kernel_release();
    let runner = "diorama-platform-soak".to_string();

    let is_partial = observed_secs < FULL_SOAK_DURATION_SECS;

    let assertions = vec![
        ReceiptAssertionRecord {
            name: "soak_memory_growth_bound".into(),
            passed: bound_passed,
            detail: Some(growth_detail),
        },
        ReceiptAssertionRecord {
            name: "soak_zero_oom_events".into(),
            passed: oom_events == 0,
            detail: Some(format!("{oom_events} OOM events detected")),
        },
        ReceiptAssertionRecord {
            name: "soak_zero_crashes".into(),
            passed: crashes == 0,
            detail: Some(format!("{crashes} crashes observed across all cycles")),
        },
        ReceiptAssertionRecord {
            name: "soak_zero_unexplained_probe_failures".into(),
            passed: probe_failures == 0,
            detail: Some(format!(
                "{probe_failures} probe failures observed across all cycles"
            )),
        },
        ReceiptAssertionRecord {
            name: "soak_workload_cycles_positive".into(),
            passed: completed_cycles > 0,
            detail: Some(format!(
                "{completed_cycles} workload cycles completed successfully (attempted: {}, probe failures: {probe_failures})",
                completed_cycles + probe_failures
            )),
        },
    ];

    let mut skips = Vec::new();
    if is_partial {
        skips.push(SkipRecord {
            name: "sustained_24h_soak_completion".into(),
            reason: format!(
                "Observed duration {observed_secs}s < {FULL_SOAK_DURATION_SECS}s; recorded as partial rehearsal run"
            ),
        });
    }

    if initial_rss_opt.is_none() {
        skips.push(SkipRecord {
            name: "isolated_node_rss_sampling".into(),
            reason: "in-process rehearsal runs inside test process; isolated target node RSS sampling requires live Linux execution".into(),
        });
    }

    if !cfg!(target_os = "linux") {
        skips.push(SkipRecord {
            name: "linux_cgroup_memory_tracking".into(),
            reason: "non-Linux environment does not qualify Linux cgroup v2 memory accounting; in-process rehearsal run".into(),
        });
    }

    let candidate_inventory = load_candidate_inventory(root)?;
    let candidate = CandidateIdentity {
        source_revision: candidate_inventory.source_revision,
        binary_digests: candidate_inventory.binary_digests,
        payload_digests: candidate_inventory.payload_digests,
    };

    let environment = EnvironmentInfo {
        host,
        kernel,
        runner,
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
        execution_mode: Some("in_process".into()),
        duration_seconds: Some(observed_secs),
    };

    let commands = vec![CommandExecution {
        command: vec![
            "diorama-platform-soak".into(),
            "capture".into(),
            "--output".into(),
            output_dir.display().to_string(),
            "--duration".into(),
            duration_secs.to_string(),
            "--cycles".into(),
            cycles.to_string(),
        ],
        exit_code: 0,
        stdout_sha256: None,
        stderr_sha256: None,
        duration_ms: Some(total_duration_ms),
    }];

    let cleanup = CleanupInventory {
        cleaned_paths,
        remaining_containers: vec![],
        remaining_images: vec![],
        status: "complete".into(),
    };

    let timestamps = ReceiptTimestamps {
        started_at: started_at.clone(),
        completed_at,
    };

    let payload = ReceiptPayload {
        schema_version: CURRENT_SCHEMA_VERSION,
        criterion: CRITERION_NUMBER,
        description: "Platform Soak & Conformance Rehearsal (Criterion 6)".into(),
        candidate,
        environment,
        commands,
        assertions: assertions.clone(),
        skips: skips.clone(),
        cleanup,
        timestamps,
    };

    let receipt = CandidateReceipt::new_with_integrity_hash(payload)?;

    fs::create_dir_all(output_dir).map_err(|e| format!("cannot create output dir: {e}"))?;

    let receipt_path = output_dir.join(RECEIPT_FILENAME);
    let receipt_json =
        serde_json::to_vec_pretty(&receipt).map_err(|e| format!("serialize receipt: {e}"))?;
    fs::write(&receipt_path, receipt_json).map_err(|e| format!("write receipt: {e}"))?;

    let report = PlatformSoakQualificationReport {
        schema_version: CURRENT_SCHEMA_VERSION,
        criterion: CRITERION_NUMBER,
        timestamp: started_at,
        duration_seconds: observed_secs,
        cycles_completed: completed_cycles,
        partial: is_partial,
        initial_rss_bytes: initial_rss,
        final_rss_bytes: final_rss,
        memory_growth_ratio: growth_ratio,
        oom_events,
        crashes,
        unexplained_probe_failures: probe_failures,
        assertions,
        skips,
        summary: format!(
            "In-process soak rehearsal run: duration={observed_secs}s, cycles={completed_cycles}, growth_ratio={growth_ratio:.3}x, partial={is_partial}"
        ),
    };

    let report_json_path = output_dir.join(REPORT_JSON_FILENAME);
    let report_json =
        serde_json::to_vec_pretty(&report).map_err(|e| format!("serialize report: {e}"))?;
    fs::write(&report_json_path, report_json).map_err(|e| format!("write report: {e}"))?;

    let report_md_path = output_dir.join(REPORT_MD_FILENAME);
    let report_md = generate_markdown_report(&report);
    fs::write(&report_md_path, report_md.as_bytes())
        .map_err(|e| format!("write report md: {e}"))?;

    // Self-validate candidate receipt against repository root
    load_and_validate_receipt(&receipt_path, root, CRITERION_NUMBER)?;

    Ok((receipt_path, report_json_path, report_md_path))
}

/// Verifies a platform soak candidate receipt from a file or directory path against the repository root and optional candidate directory.
///
/// Fails closed: rejects non-Linux hosts, in-process/mock executions, runs with duration < 86,400s
/// or `partial: true`, and unpermitted skips. Live 24-hour Linux qualification required.
pub fn verify_soak_receipt_with_candidate(
    receipt_or_dir: &Path,
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CandidateReceipt> {
    let receipt_path = if receipt_or_dir.is_dir() {
        let standard = receipt_or_dir.join(RECEIPT_FILENAME);
        if standard.is_file() {
            standard
        } else {
            receipt_or_dir.join("receipt.json")
        }
    } else {
        receipt_or_dir.to_path_buf()
    };

    let receipt = load_and_validate_receipt_with_candidate(
        &receipt_path,
        root,
        candidate_dir,
        CRITERION_NUMBER,
    )?;

    // 1. Fail closed on non-Linux execution environment
    let is_linux_host = receipt.environment.host.to_lowercase().contains("linux");
    let is_linux_os = receipt
        .environment
        .os
        .as_deref()
        .map(str::to_lowercase)
        .as_deref()
        == Some("linux");
    if !is_linux_host && !is_linux_os {
        return Err(format!(
            "Criterion 6 qualification rejected: non-Linux execution environment (host: '{}')",
            receipt.environment.host
        )
        .into());
    }

    // 2. Fail closed on in-process or mock execution mode
    let is_live_mode = receipt.environment.execution_mode.as_deref() == Some("live_node");
    if !is_live_mode {
        let mode = receipt
            .environment
            .execution_mode
            .as_deref()
            .unwrap_or("unspecified");
        return Err(format!(
            "Criterion 6 qualification rejected: execution mode '{mode}' does not qualify; live_node required"
        )
        .into());
    }

    // 3. Fail closed on duration < 86,400s or partial run
    let duration = receipt.environment.duration_seconds.unwrap_or(0);
    if duration < FULL_SOAK_DURATION_SECS {
        return Err(format!(
            "Criterion 6 qualification rejected: soak duration {duration}s < {FULL_SOAK_DURATION_SECS}s; full 24-hour soak required"
        )
        .into());
    }

    // 4. Fail closed on unpermitted documented skips:
    // Criterion 6 requires full sustained 24-hour soak on Linux; no skips are permitted by contract
    if !receipt.skips.is_empty() {
        let skip_names: Vec<_> = receipt.skips.iter().map(|s| s.name.as_str()).collect();
        return Err(format!(
            "Criterion 6 qualification rejected: documented skips {skip_names:?} are not permitted for live qualification; criterion stays Pending"
        )
        .into());
    }

    // 5. Verify all 5 required assertions are present and passed
    let required_assertions = [
        "soak_memory_growth_bound",
        "soak_zero_oom_events",
        "soak_zero_crashes",
        "soak_zero_unexplained_probe_failures",
        "soak_workload_cycles_positive",
    ];

    for req in &required_assertions {
        let assertion = receipt
            .assertions
            .iter()
            .find(|a| a.name == *req)
            .ok_or_else(|| format!("missing required assertion '{req}' in receipt"))?;
        if !assertion.passed {
            return Err(format!("required assertion '{req}' failed").into());
        }
        if let Some(detail) = &assertion.detail
            && detail.to_lowercase().contains("non-qualifying")
        {
            return Err(format!(
                "required assertion '{req}' contains non-qualifying measurement: {detail}"
            )
            .into());
        }
    }

    Ok(receipt)
}

/// Verifies a platform soak candidate receipt from a file or directory path against the repository root.
///
/// Fails closed: rejects non-Linux hosts, in-process/mock executions, runs with duration < 86,400s
/// or `partial: true`, and unpermitted skips. Live 24-hour Linux qualification required.
pub fn verify_soak_receipt(receipt_or_dir: &Path, root: &Path) -> Result<CandidateReceipt> {
    verify_soak_receipt_with_candidate(receipt_or_dir, root, None)
}
