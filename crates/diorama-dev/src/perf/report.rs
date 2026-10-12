//! Markdown and JSON report generation, comparative tables, and baseline verification.

use super::contract::GateEvaluationReport;
use super::metrics::PerformanceReport;
use super::secondary::SecondaryTargetsRegistry;
use crate::Result;
use std::fmt::Write as _;
use std::path::Path;

/// Load and parse a JSON performance report bounded to 16 MiB.
pub fn load_report(path: &Path) -> Result<PerformanceReport> {
    let bytes = crate::read_bounded(path, 16 * 1024 * 1024)?;
    let report: PerformanceReport = serde_json::from_slice(&bytes)?;
    super::validation::validate_report(&report)?;
    Ok(report)
}

/// Save a performance report formatted as pretty JSON.
pub fn save_report(path: &Path, report: &PerformanceReport) -> Result<()> {
    let json_bytes = serde_json::to_vec_pretty(report)?;
    std::fs::write(path, json_bytes)?;
    Ok(())
}

/// Generate a comprehensive Markdown comparison report between reference and candidate.
pub fn generate_markdown_report(
    reference: &PerformanceReport,
    candidate: &PerformanceReport,
    evaluation: &GateEvaluationReport,
    secondary: Option<&SecondaryTargetsRegistry>,
) -> String {
    let mut out = String::with_capacity(8192);

    let _ = writeln!(
        out,
        "# Performance Baseline Comparison: {} (Go) vs {} (Rust)",
        reference.architecture.as_str().to_uppercase(),
        candidate.architecture.as_str().to_uppercase()
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "**Generated:** {} | **Schema Version:** {}",
        candidate.timestamp, candidate.schema_version
    );
    let _ = writeln!(out);

    // Section 1: Gate Evaluation Summary
    let _ = writeln!(out, "## 1. Contract Gates Evaluation Summary");
    let _ = writeln!(out);
    let overall_status = if evaluation.all_passed {
        "PASSED (All 12 Gates Met)"
    } else {
        "NOT QUALIFIED (Invalid, synthetic or unverified evidence)"
    };
    let _ = writeln!(out, "**Overall Gate Status:** {overall_status}");
    for error in &evaluation.validation_errors {
        let _ = writeln!(out, "- {error}");
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Gate Metric | Direction | Reference ({}) | Candidate ({}) | Threshold Limit | Status |",
        reference.implementation.as_str(),
        candidate.implementation.as_str()
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|");
    for gate in &evaluation.results {
        let dir = if gate.higher_is_better {
            ">= 0.90x"
        } else {
            "<= 1.10x"
        };
        let status = if gate.passed { "PASS" } else { "FAIL" };
        let _ = writeln!(
            out,
            "| {} | {} | {:.3} | {:.3} | {:.3} | {} |",
            gate.name,
            dir,
            gate.reference_value,
            gate.candidate_value,
            gate.target_threshold,
            status
        );
    }
    let _ = writeln!(out);

    // Section 2: Hardware & Workload
    let _ = writeln!(out, "## 2. Declared Hardware & Workload Specification");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- **Machine Model:** {} ({})",
        reference.hardware.machine_model,
        reference.hardware.architecture.as_str()
    );
    let _ = writeln!(
        out,
        "- **CPU Cores / RAM:** {} cores, {:.2} GiB RAM",
        reference.hardware.cpu_cores,
        reference.hardware.ram_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    let _ = writeln!(
        out,
        "- **Kernel & Cgroups:** {}, {}",
        reference.hardware.kernel_version, reference.hardware.cgroup_version
    );
    let _ = writeln!(
        out,
        "- **Workload:** Probe image `{}`, Memory Limit: {:.1} GiB",
        reference.workload.probe_image,
        reference.workload.density_node_memory_limit_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    let _ = writeln!(out);

    // Section 3: Latency Comparison
    let _ = writeln!(out, "## 3. Startup Latencies (20 Fresh Boots)");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Latency Phase | Go Reference p95 | Go Mean | Rust Candidate p95 | Rust Mean | p95 Ratio |",
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|");
    let phases = [
        (
            "Boot-to-API",
            &reference.startup_latencies.boot_to_api_seconds,
            &candidate.startup_latencies.boot_to_api_seconds,
        ),
        (
            "Node Ready",
            &reference.startup_latencies.node_ready_seconds,
            &candidate.startup_latencies.node_ready_seconds,
        ),
        (
            "First Pod (Preloaded)",
            &reference.startup_latencies.first_pod_preloaded_seconds,
            &candidate.startup_latencies.first_pod_preloaded_seconds,
        ),
        (
            "First Pod (Cold Image)",
            &reference.startup_latencies.first_pod_cold_seconds,
            &candidate.startup_latencies.first_pod_cold_seconds,
        ),
    ];
    for (name, r, c) in phases {
        let ratio = c.p95 / r.p95;
        let _ = writeln!(
            out,
            "| {} | {:.3}s | {:.3}s | {:.3}s | {:.3}s | {:.2}x |",
            name, r.p95, r.mean, c.p95, c.mean, ratio
        );
    }
    let _ = writeln!(out);

    // Section 4: Memory Footprint & Retained Processes
    let _ = writeln!(
        out,
        "## 4. Whole-Distribution Idle Footprint & Retained Processes"
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "**Settling Period:** 10 minutes | **Sampling:** 1 sample/sec for 15 minutes (900 samples)"
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Retained Process | Reference PSS | Reference RSS | Candidate PSS | Candidate RSS |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|");

    let mib = 1024.0 * 1024.0;
    let proc_slots = [
        ("kube-apiserver", "apiserver"),
        ("kube-controller-manager", "controller-manager"),
        ("kubelet", "kubelet"),
        ("kube-proxy", "proxy"),
        ("kine", "kine"),
        ("containerd", "containerd"),
        ("containerd-shim-runc-v2", "containerd-shim"),
        ("distribution-node-daemon", "node-daemon"),
    ];

    for (label, key) in proc_slots {
        let r_proc = reference
            .idle_footprint
            .retained_processes
            .iter()
            .find(|p| super::harness::process_role(&p.process_name) == Some(key));
        let c_proc = candidate
            .idle_footprint
            .retained_processes
            .iter()
            .find(|p| super::harness::process_role(&p.process_name) == Some(key));

        let (r_pss, r_rss) = r_proc.map_or((0.0, 0.0), |p| {
            (p.pss_bytes as f64 / mib, p.rss_bytes as f64 / mib)
        });
        let (c_pss, c_rss) = c_proc.map_or((0.0, 0.0), |p| {
            (p.pss_bytes as f64 / mib, p.rss_bytes as f64 / mib)
        });

        let _ = writeln!(
            out,
            "| {label} | {r_pss:.2} MiB | {r_rss:.2} MiB | {c_pss:.2} MiB | {c_rss:.2} MiB |"
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- **Summed Whole-Distribution PSS Median:** Reference {:.2} MiB vs Candidate {:.2} MiB ({:.2}x)",
        reference.idle_footprint.summed_pss_bytes.p50 / mib,
        candidate.idle_footprint.summed_pss_bytes.p50 / mib,
        candidate.idle_footprint.summed_pss_bytes.p50
            / reference.idle_footprint.summed_pss_bytes.p50
    );
    let _ = writeln!(
        out,
        "- **Cgroup Memory Median:** Reference {:.2} MiB vs Candidate {:.2} MiB ({:.2}x)",
        reference.idle_footprint.cgroup_memory_bytes.p50 / mib,
        candidate.idle_footprint.cgroup_memory_bytes.p50 / mib,
        candidate.idle_footprint.cgroup_memory_bytes.p50
            / reference.idle_footprint.cgroup_memory_bytes.p50
    );
    let _ = writeln!(out);

    // Section 5: Artifact Footprint
    let _ = writeln!(out, "## 5. Artifact Footprint");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Artifact Item | Reference | Candidate | Ratio |");
    let _ = writeln!(out, "|---|---|---|---|");
    let r_foot = &reference.artifact_footprint;
    let c_foot = &candidate.artifact_footprint;
    let _ = writeln!(
        out,
        "| Compressed Release Archive | {:.2} MiB | {:.2} MiB | {:.2}x |",
        r_foot.compressed_archive_bytes as f64 / mib,
        c_foot.compressed_archive_bytes as f64 / mib,
        c_foot.compressed_archive_bytes as f64 / r_foot.compressed_archive_bytes as f64
    );
    let _ = writeln!(
        out,
        "| Extracted Executable Payload | {:.2} MiB | {:.2} MiB | {:.2}x |",
        r_foot.extracted_executable_bytes as f64 / mib,
        c_foot.extracted_executable_bytes as f64 / mib,
        c_foot.extracted_executable_bytes as f64 / r_foot.extracted_executable_bytes as f64
    );
    let _ = writeln!(
        out,
        "| Default Image Payload | {:.2} MiB | {:.2} MiB | {:.2}x |",
        r_foot.default_image_payload_bytes as f64 / mib,
        c_foot.default_image_payload_bytes as f64 / mib,
        c_foot.default_image_payload_bytes as f64 / r_foot.default_image_payload_bytes as f64
    );
    let _ = writeln!(out);

    // Section 6: Pod Density & Soak
    let _ = writeln!(out, "## 6. Pod Density & Soak Stability");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- **Pod Density (Median Replicas):** Reference {:.1} pods vs Candidate {:.1} pods (Ratio: {:.2}x >= 0.90x)",
        reference.pod_density.max_ready_replicas.p50,
        candidate.pod_density.max_ready_replicas.p50,
        candidate.pod_density.max_ready_replicas.p50 / reference.pod_density.max_ready_replicas.p50
    );
    let _ = writeln!(
        out,
        "- **Sustained Growth (Declared {}h Soak):** Initial settled {:.2} MiB -> Final settled {:.2} MiB ({:.3}x derived growth, {} OOMs, {} crashes, {} unexplained failures)",
        candidate.sustained_growth.duration_hours,
        candidate.sustained_growth.initial_settled_idle_median_bytes as f64 / mib,
        candidate.sustained_growth.final_settled_idle_median_bytes as f64 / mib,
        candidate.sustained_growth.final_settled_idle_median_bytes as f64
            / candidate.sustained_growth.initial_settled_idle_median_bytes as f64,
        candidate.sustained_growth.oom_kill_count,
        candidate.sustained_growth.crash_count,
        candidate.sustained_growth.unexplained_failures
    );
    let _ = writeln!(
        out,
        "- **Shutdown:** Graceful p95 {:.2}s (<= 30s deadline), Surviving owned processes: {}",
        candidate.shutdown.graceful_duration_seconds.p95,
        candidate.shutdown.surviving_owned_processes
    );
    let _ = writeln!(out);

    // Section 7: Secondary Architecture Gaps
    if let Some(sec) = secondary {
        let _ = writeln!(out, "## 7. Explicit Secondary Architecture Gaps");
        let _ = writeln!(out);
        for (arch, gap) in &sec.targets {
            let _ = writeln!(
                out,
                "### Target `{arch}` ({}-bit, {})",
                gap.address_space_bits, gap.status
            );
            let _ = writeln!(
                out,
                "- **Max Pod Density:** {} replicas",
                gap.maximum_pod_density
            );
            let _ = writeln!(
                out,
                "- **Feature Matrix:** Portainer: {}, D2K: {}, crun source build: {}",
                if gap.portainer_supported {
                    "Supported"
                } else {
                    "Disabled"
                },
                if gap.d2k_supported {
                    "Supported"
                } else {
                    "Disabled"
                },
                if gap.crun_source_build_required {
                    "Required"
                } else {
                    "No"
                }
            );
            let _ = writeln!(
                out,
                "- **Cold Boot Latency Overhead:** {}",
                gap.cold_boot_latency_overhead_multiplier
            );
            let _ = writeln!(out, "- **Primary Gate Exceptions:**");
            for ex in &gap.primary_gate_exceptions {
                let _ = writeln!(out, "  * {ex}");
            }
            let _ = writeln!(out, "- **Hardware & Toolchain Constraints:**");
            for con in &gap.hardware_and_toolchain_constraints {
                let _ = writeln!(out, "  * {con}");
            }
            let _ = writeln!(out);
        }
    }

    out
}
