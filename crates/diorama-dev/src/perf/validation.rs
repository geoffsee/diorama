//! Reject incomplete, inconsistent and unmatched performance inputs before arithmetic.
use super::metrics::{ImplementationKind, PerformanceReport, VarianceSummary};
use crate::Result;

fn summary(name: &str, value: &VarianceSummary, count: usize) -> Result<()> {
    let recomputed = VarianceSummary::from_samples(value.samples.clone())
        .ok_or_else(|| format!("{name}: samples must be finite, nonnegative and nonempty"))?;
    if value.count != count || value.count != recomputed.count {
        return Err(format!("{name}: requires {count} raw samples matching count").into());
    }
    let supplied = [
        value.min,
        value.max,
        value.mean,
        value.variance,
        value.std_dev,
        value.p50,
        value.p90,
        value.p95,
    ];
    let derived = [
        recomputed.min,
        recomputed.max,
        recomputed.mean,
        recomputed.variance,
        recomputed.std_dev,
        recomputed.p50,
        recomputed.p90,
        recomputed.p95,
    ];
    if supplied
        .iter()
        .zip(derived)
        .any(|(a, b)| !a.is_finite() || (*a - b).abs() > 1e-9 * b.abs().max(1.0))
    {
        return Err(format!("{name}: cached statistics disagree with raw samples").into());
    }
    Ok(())
}

/// Structural validation permits synthetic arithmetic examples, but never qualification.
#[allow(clippy::float_cmp)] // A readiness fraction must be exactly 100%, not approximately.
pub fn validate_report(report: &PerformanceReport) -> Result<()> {
    if report.schema_version != 1 {
        return Err("unsupported performance report schema".into());
    }
    for (name, value, count) in [
        ("boot", &report.startup_latencies.boot_to_api_seconds, 20),
        (
            "node-ready",
            &report.startup_latencies.node_ready_seconds,
            20,
        ),
        (
            "first-pod-preloaded",
            &report.startup_latencies.first_pod_preloaded_seconds,
            20,
        ),
        (
            "first-pod-cold",
            &report.startup_latencies.first_pod_cold_seconds,
            20,
        ),
        (
            "idle-pss run-p95",
            &report.idle_footprint.summed_pss_bytes,
            5,
        ),
        (
            "idle-cgroup run-p95",
            &report.idle_footprint.cgroup_memory_bytes,
            5,
        ),
        ("density", &report.pod_density.max_ready_replicas, 5),
        (
            "graceful-shutdown",
            &report.shutdown.graceful_duration_seconds,
            20,
        ),
        (
            "escalated-shutdown",
            &report.shutdown.escalation_duration_seconds,
            20,
        ),
    ] {
        summary(name, value, count)?;
    }
    if report.hardware.architecture != report.architecture
        || !report.architecture.is_primary()
        || report.hardware.cpu_cores == 0
        || report.hardware.ram_bytes == 0
        || report.hardware.os.is_empty()
        || report.hardware.kernel_version.is_empty()
        || report.hardware.machine_model.is_empty()
        || report.hardware.storage_type.is_empty()
    {
        return Err("missing or inconsistent primary architecture/environment".into());
    }
    if report.workload.settle_duration_seconds != 600
        || report.workload.sample_interval_seconds != 1
        || report.workload.sample_duration_seconds != 900
        || report.idle_footprint.settle_minutes != 10
        || report.idle_footprint.sampling_minutes != 15
        || report.idle_footprint.sample_count != 900
        || report.workload.density_node_memory_limit_bytes == 0
        || report.pod_density.node_memory_limit_bytes
            != report.workload.density_node_memory_limit_bytes
        || report.pod_density.hold_duration_seconds < 600
    {
        return Err("workload/timing/counts violate the performance sampling contract".into());
    }
    if !report.pod_density.probe_success_rate.is_finite()
        || report.pod_density.probe_success_rate != 1.0
    {
        return Err("density requires successful probes throughout the hold".into());
    }
    if report.workload.probe_image.is_empty()
        || report.workload.probe_digest.is_empty()
        || report.workload.probe_resource_cpu.is_empty()
        || report.workload.probe_resource_memory.is_empty()
        || report.workload.probe_interval_seconds == 0
    {
        return Err("missing pinned workload identity/resource limits".into());
    }
    if report.startup_latencies.boot_to_api_seconds.min < 0.0
        || report.startup_latencies.node_ready_seconds.min < 0.0
        || report.startup_latencies.first_pod_preloaded_seconds.min < 0.0
        || report.startup_latencies.first_pod_cold_seconds.min < 0.0
    {
        return Err("startup latency must be nonnegative".into());
    }
    super::harness::verify_retained_process_coverage(report)?;
    let mut total_retained_pss = 0u64;
    for p in &report.idle_footprint.retained_processes {
        if p.pss_bytes == 0 || p.rss_bytes == 0 {
            return Err(format!(
                "retained process '{}' must record strictly positive PSS and RSS memory",
                p.process_name
            )
            .into());
        }
        if p.pss_bytes > p.rss_bytes {
            return Err(format!(
                "retained process '{}' PSS cannot exceed RSS",
                p.process_name
            )
            .into());
        }
        total_retained_pss = total_retained_pss.saturating_add(p.pss_bytes);
    }
    if report.idle_footprint.summed_pss_bytes.p50 < 200_000_000.0
        && total_retained_pss >= 200_000_000
    {
        return Err(
            "unmeasured footprint claim: idle PSS cannot claim sub-200-MB without backing retained process measurements"
                .into(),
        );
    }
    let artifact = &report.artifact_footprint;
    if artifact.compressed_archive_bytes == 0
        || artifact.extracted_executable_bytes == 0
        || artifact.default_image_payload_bytes == 0
    {
        return Err("missing whole-distribution artifact accounting".into());
    }
    Ok(())
}

/// Compare the declared environment and retained payload, allowing only implementation revisions
/// and compilers to differ. Live libc/filesystem/variant provenance is not represented yet and
/// is therefore never qualified by this schema.
pub fn validate_pair(reference: &PerformanceReport, candidate: &PerformanceReport) -> Result<()> {
    validate_report(reference)?;
    validate_report(candidate)?;
    if reference.implementation != ImplementationKind::Go
        || candidate.implementation != ImplementationKind::Rust
    {
        return Err("pair requires a Go reference and Rust candidate".into());
    }
    if reference.architecture != candidate.architecture
        || reference.hardware != candidate.hardware
        || reference.workload != candidate.workload
        || reference.idle_footprint.memory_accounting_mode
            != candidate.idle_footprint.memory_accounting_mode
    {
        return Err("reference and candidate must use identical architecture, hardware, workload and accounting".into());
    }
    let mut reference_versions = reference.versions.clone();
    let mut candidate_versions = candidate.versions.clone();
    reference_versions.distribution_revision.clear();
    reference_versions.compiler_version.clear();
    candidate_versions.distribution_revision.clear();
    candidate_versions.compiler_version.clear();
    if reference_versions != candidate_versions {
        return Err("reference and candidate retained component versions differ".into());
    }
    Ok(())
}
