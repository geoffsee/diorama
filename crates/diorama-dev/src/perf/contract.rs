//! Contract gate evaluation comparing candidate against reference baselines.

use super::metrics::PerformanceReport;
use serde::{Deserialize, Serialize};

/// Direction and threshold rule for an individual gate.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GateResult {
    pub name: String,
    pub reference_value: f64,
    pub candidate_value: f64,
    pub threshold_multiplier: f64,
    pub target_threshold: f64,
    pub higher_is_better: bool,
    pub passed: bool,
    pub details: String,
}

/// Comprehensive evaluation result comparing a candidate report against reference baseline.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GateEvaluationReport {
    pub architecture: String,
    pub reference_id: String,
    pub candidate_id: String,
    pub all_passed: bool,
    pub validation_errors: Vec<String>,
    pub results: Vec<GateResult>,
}

/// Committed platform contract thresholds and deadlines.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ContractThresholds {
    pub boot_to_api_p95_multiplier: f64,
    pub node_ready_p95_multiplier: f64,
    pub first_pod_preloaded_p95_multiplier: f64,
    pub first_pod_cold_p95_multiplier: f64,
    pub idle_pss_median_multiplier: f64,
    pub idle_cgroup_median_multiplier: f64,
    pub compressed_archive_multiplier: f64,
    pub extracted_executables_multiplier: f64,
    pub image_payload_multiplier: f64,
    pub pod_density_median_multiplier: f64,
    pub sustained_growth_median_multiplier: f64,
    pub shutdown_graceful_deadline_seconds: f64,
    pub shutdown_escalation_deadline_seconds: f64,
}

impl Default for ContractThresholds {
    fn default() -> Self {
        Self {
            boot_to_api_p95_multiplier: 1.10,
            node_ready_p95_multiplier: 1.10,
            first_pod_preloaded_p95_multiplier: 1.10,
            first_pod_cold_p95_multiplier: 1.10,
            idle_pss_median_multiplier: 1.10,
            idle_cgroup_median_multiplier: 1.10,
            compressed_archive_multiplier: 1.10,
            extracted_executables_multiplier: 1.10,
            image_payload_multiplier: 1.10,
            pod_density_median_multiplier: 0.90,
            sustained_growth_median_multiplier: 1.10,
            shutdown_graceful_deadline_seconds: 30.0,
            shutdown_escalation_deadline_seconds: 35.0,
        }
    }
}

impl ContractThresholds {
    /// Validates that thresholds are finite and do not relax the committed policy.
    pub fn validate(&self) -> Result<(), String> {
        let multipliers = [
            (
                "boot_to_api_p95_multiplier",
                self.boot_to_api_p95_multiplier,
                1.10,
                false,
            ),
            (
                "node_ready_p95_multiplier",
                self.node_ready_p95_multiplier,
                1.10,
                false,
            ),
            (
                "first_pod_preloaded_p95_multiplier",
                self.first_pod_preloaded_p95_multiplier,
                1.10,
                false,
            ),
            (
                "first_pod_cold_p95_multiplier",
                self.first_pod_cold_p95_multiplier,
                1.10,
                false,
            ),
            (
                "idle_pss_median_multiplier",
                self.idle_pss_median_multiplier,
                1.10,
                false,
            ),
            (
                "idle_cgroup_median_multiplier",
                self.idle_cgroup_median_multiplier,
                1.10,
                false,
            ),
            (
                "compressed_archive_multiplier",
                self.compressed_archive_multiplier,
                1.10,
                false,
            ),
            (
                "extracted_executables_multiplier",
                self.extracted_executables_multiplier,
                1.10,
                false,
            ),
            (
                "image_payload_multiplier",
                self.image_payload_multiplier,
                1.10,
                false,
            ),
            (
                "pod_density_median_multiplier",
                self.pod_density_median_multiplier,
                0.90,
                true,
            ),
            (
                "sustained_growth_median_multiplier",
                self.sustained_growth_median_multiplier,
                1.10,
                false,
            ),
        ];

        for (name, val, committed, higher_is_better) in multipliers {
            if !val.is_finite() || val <= 0.0 {
                return Err(format!(
                    "{name} must be a positive finite number, got {val}"
                ));
            }
            if higher_is_better {
                if val < committed {
                    return Err(format!(
                        "{name} cannot be relaxed below {committed}, got {val}"
                    ));
                }
            } else if val > committed {
                return Err(format!(
                    "{name} cannot be relaxed above {committed}, got {val}"
                ));
            }
        }

        if !self.shutdown_graceful_deadline_seconds.is_finite()
            || self.shutdown_graceful_deadline_seconds <= 0.0
            || self.shutdown_graceful_deadline_seconds > 30.0
        {
            return Err(format!(
                "shutdown_graceful_deadline_seconds cannot be relaxed above 30.0s, got {}",
                self.shutdown_graceful_deadline_seconds
            ));
        }

        if !self.shutdown_escalation_deadline_seconds.is_finite()
            || self.shutdown_escalation_deadline_seconds <= 0.0
            || self.shutdown_escalation_deadline_seconds > 35.0
        {
            return Err(format!(
                "shutdown_escalation_deadline_seconds cannot be relaxed above 35.0s, got {}",
                self.shutdown_escalation_deadline_seconds
            ));
        }

        Ok(())
    }
}

impl GateEvaluationReport {
    /// Returns true if all 12 arithmetic engineering gates passed according to committed thresholds.
    /// Note: `all_passed` remains false unless live-capture provenance is authenticated.
    pub fn arithmetic_all_passed(&self) -> bool {
        self.results.len() == 12 && self.results.iter().all(|g| g.passed)
    }

    /// Evaluate all measurable engineering gates from the compatibility contract.
    pub fn evaluate(reference: &PerformanceReport, candidate: &PerformanceReport) -> Self {
        Self::evaluate_with_thresholds(reference, candidate, &ContractThresholds::default())
    }

    /// Evaluate all measurable engineering gates using specified contract thresholds.
    pub fn evaluate_with_thresholds(
        reference: &PerformanceReport,
        candidate: &PerformanceReport,
        thresholds: &ContractThresholds,
    ) -> Self {
        if let Err(error) = super::validation::validate_pair(reference, candidate) {
            return Self {
                architecture: candidate.architecture.as_str().into(),
                reference_id: reference.id.clone(),
                candidate_id: candidate.id.clone(),
                all_passed: false,
                results: Vec::new(),
                validation_errors: vec![error.to_string()],
            };
        }
        let mut results = Vec::new();

        // 1. Boot-to-API latency: candidate nearest-rank p95 <= threshold * ref p95
        let ref_boot = reference.startup_latencies.boot_to_api_seconds.p95;
        let cand_boot = candidate.startup_latencies.boot_to_api_seconds.p95;
        let boot_thresh = thresholds.boot_to_api_p95_multiplier * ref_boot;
        results.push(GateResult {
            name: "Boot-to-API Latency (p95)".to_string(),
            reference_value: ref_boot,
            candidate_value: cand_boot,
            threshold_multiplier: thresholds.boot_to_api_p95_multiplier,
            target_threshold: boot_thresh,
            higher_is_better: false,
            passed: cand_boot <= boot_thresh,
            details: format!(
                "Candidate p95 ({cand_boot:.3}s) vs Reference p95 ({ref_boot:.3}s); limit: {boot_thresh:.3}s"
            ),
        });

        // 2. Node Ready latency: candidate p95 <= threshold * ref p95
        let ref_node = reference.startup_latencies.node_ready_seconds.p95;
        let cand_node = candidate.startup_latencies.node_ready_seconds.p95;
        let node_thresh = thresholds.node_ready_p95_multiplier * ref_node;
        results.push(GateResult {
            name: "Node Ready Latency (p95)".to_string(),
            reference_value: ref_node,
            candidate_value: cand_node,
            threshold_multiplier: thresholds.node_ready_p95_multiplier,
            target_threshold: node_thresh,
            higher_is_better: false,
            passed: cand_node <= node_thresh,
            details: format!(
                "Candidate p95 ({cand_node:.3}s) vs Reference p95 ({ref_node:.3}s); limit: {node_thresh:.3}s"
            ),
        });

        // 3. First Pod (preloaded): candidate p95 <= threshold * ref p95
        let ref_first_pre = reference.startup_latencies.first_pod_preloaded_seconds.p95;
        let cand_first_pre = candidate.startup_latencies.first_pod_preloaded_seconds.p95;
        let first_pre_thresh = thresholds.first_pod_preloaded_p95_multiplier * ref_first_pre;
        results.push(GateResult {
            name: "First Pod Latency (Preloaded, p95)".to_string(),
            reference_value: ref_first_pre,
            candidate_value: cand_first_pre,
            threshold_multiplier: thresholds.first_pod_preloaded_p95_multiplier,
            target_threshold: first_pre_thresh,
            higher_is_better: false,
            passed: cand_first_pre <= first_pre_thresh,
            details: format!(
                "Candidate p95 ({cand_first_pre:.3}s) vs Reference p95 ({ref_first_pre:.3}s); limit: {first_pre_thresh:.3}s"
            ),
        });

        // 4. First Pod (cold): candidate p95 <= threshold * ref p95
        let ref_first_cold = reference.startup_latencies.first_pod_cold_seconds.p95;
        let cand_first_cold = candidate.startup_latencies.first_pod_cold_seconds.p95;
        let first_cold_thresh = thresholds.first_pod_cold_p95_multiplier * ref_first_cold;
        results.push(GateResult {
            name: "First Pod Latency (Cold Image, p95)".to_string(),
            reference_value: ref_first_cold,
            candidate_value: cand_first_cold,
            threshold_multiplier: thresholds.first_pod_cold_p95_multiplier,
            target_threshold: first_cold_thresh,
            higher_is_better: false,
            passed: cand_first_cold <= first_cold_thresh,
            details: format!(
                "Candidate p95 ({cand_first_cold:.3}s) vs Reference p95 ({ref_first_cold:.3}s); limit: {first_cold_thresh:.3}s"
            ),
        });

        // 5. Idle footprint: Median of per-run p95 PSS <= threshold * ref
        let ref_pss = reference.idle_footprint.summed_pss_bytes.p50;
        let cand_pss = candidate.idle_footprint.summed_pss_bytes.p50;
        let pss_thresh = thresholds.idle_pss_median_multiplier * ref_pss;
        results.push(GateResult {
            name: "Idle Footprint (Summed PSS, Median)".to_string(),
            reference_value: ref_pss,
            candidate_value: cand_pss,
            threshold_multiplier: thresholds.idle_pss_median_multiplier,
            target_threshold: pss_thresh,
            higher_is_better: false,
            passed: cand_pss <= pss_thresh,
            details: format!(
                "Candidate median ({cand_pss:.0} bytes) vs Reference ({ref_pss:.0} bytes); limit: {pss_thresh:.0} bytes"
            ),
        });

        // 6. Idle footprint: Cgroup memory median <= threshold * ref
        let ref_cg = reference.idle_footprint.cgroup_memory_bytes.p50;
        let cand_cg = candidate.idle_footprint.cgroup_memory_bytes.p50;
        let cg_thresh = thresholds.idle_cgroup_median_multiplier * ref_cg;
        results.push(GateResult {
            name: "Idle Footprint (Cgroup Memory, Median)".to_string(),
            reference_value: ref_cg,
            candidate_value: cand_cg,
            threshold_multiplier: thresholds.idle_cgroup_median_multiplier,
            target_threshold: cg_thresh,
            higher_is_better: false,
            passed: cand_cg <= cg_thresh,
            details: format!(
                "Candidate cgroup median ({cand_cg:.0} bytes) vs Reference ({ref_cg:.0} bytes); limit: {cg_thresh:.0} bytes"
            ),
        });

        // 7. Distribution size: compressed release archive bytes <= threshold * ref
        let ref_arch = reference.artifact_footprint.compressed_archive_bytes as f64;
        let cand_arch = candidate.artifact_footprint.compressed_archive_bytes as f64;
        let arch_thresh = thresholds.compressed_archive_multiplier * ref_arch;
        results.push(GateResult {
            name: "Distribution Size (Compressed Archive)".to_string(),
            reference_value: ref_arch,
            candidate_value: cand_arch,
            threshold_multiplier: thresholds.compressed_archive_multiplier,
            target_threshold: arch_thresh,
            higher_is_better: false,
            passed: cand_arch <= arch_thresh,
            details: format!(
                "Candidate archive ({cand_arch:.0} bytes) vs Reference ({ref_arch:.0} bytes); limit: {arch_thresh:.0} bytes"
            ),
        });

        // 8. Distribution size: extracted executable/helpers bytes <= threshold * ref
        let ref_exec = reference.artifact_footprint.extracted_executable_bytes as f64;
        let cand_exec = candidate.artifact_footprint.extracted_executable_bytes as f64;
        let exec_thresh = thresholds.extracted_executables_multiplier * ref_exec;
        results.push(GateResult {
            name: "Distribution Size (Extracted Executables)".to_string(),
            reference_value: ref_exec,
            candidate_value: cand_exec,
            threshold_multiplier: thresholds.extracted_executables_multiplier,
            target_threshold: exec_thresh,
            higher_is_better: false,
            passed: cand_exec <= exec_thresh,
            details: format!(
                "Candidate executables ({cand_exec:.0} bytes) vs Reference ({ref_exec:.0} bytes); limit: {exec_thresh:.0} bytes"
            ),
        });

        // 9. Distribution size: default image payload bytes <= threshold * ref
        let ref_payload = reference.artifact_footprint.default_image_payload_bytes as f64;
        let cand_payload = candidate.artifact_footprint.default_image_payload_bytes as f64;
        let payload_thresh = thresholds.image_payload_multiplier * ref_payload;
        results.push(GateResult {
            name: "Distribution Size (Default Image Payload)".to_string(),
            reference_value: ref_payload,
            candidate_value: cand_payload,
            threshold_multiplier: thresholds.image_payload_multiplier,
            target_threshold: payload_thresh,
            higher_is_better: false,
            passed: cand_payload <= payload_thresh,
            details: format!(
                "Candidate images ({cand_payload:.0} bytes) vs Reference ({ref_payload:.0} bytes); limit: {payload_thresh:.0} bytes"
            ),
        });

        // 10. Pod density: Median capacity >= threshold * reference (HIGHER IS BETTER)
        let ref_density = reference.pod_density.max_ready_replicas.p50;
        let cand_density = candidate.pod_density.max_ready_replicas.p50;
        let density_thresh = thresholds.pod_density_median_multiplier * ref_density;
        results.push(GateResult {
            name: "Pod Density Capacity (Median Replicas)".to_string(),
            reference_value: ref_density,
            candidate_value: cand_density,
            threshold_multiplier: thresholds.pod_density_median_multiplier,
            target_threshold: density_thresh,
            higher_is_better: true,
            passed: cand_density >= density_thresh,
            details: format!(
                "Candidate density ({cand_density:.1} pods) vs Reference ({ref_density:.1} pods); minimum: {density_thresh:.1} pods"
            ),
        });

        // 11. Sustained growth: final median <= threshold * initial median, 0 OOMs, 0 crashes
        let init_mem = candidate.sustained_growth.initial_settled_idle_median_bytes as f64;
        let final_mem = candidate.sustained_growth.final_settled_idle_median_bytes as f64;
        let growth_ratio = final_mem / init_mem;
        let growth_limit = init_mem * thresholds.sustained_growth_median_multiplier;
        let growth_passed = init_mem > 0.0
            && candidate.sustained_growth.duration_hours >= 24
            && growth_ratio <= thresholds.sustained_growth_median_multiplier
            && candidate.sustained_growth.oom_kill_count == 0
            && candidate.sustained_growth.crash_count == 0
            && candidate.sustained_growth.unexplained_failures == 0;
        results.push(GateResult {
            name: "Sustained Growth (24h Soak)".to_string(),
            reference_value: init_mem,
            candidate_value: final_mem,
            threshold_multiplier: thresholds.sustained_growth_median_multiplier,
            target_threshold: growth_limit,
            higher_is_better: false,
            passed: growth_passed,
            details: format!(
                "Initial {init_mem:.0} bytes -> Final {final_mem:.0} bytes ({growth_ratio:.3}x), {}h, {} OOMs, {} crashes, {} unexplained failures",
                candidate.sustained_growth.duration_hours, candidate.sustained_growth.oom_kill_count,
                candidate.sustained_growth.crash_count, candidate.sustained_growth.unexplained_failures
            ),
        });

        // 12. Shutdown: graceful <= deadline, escalation <= deadline, 0 surviving processes
        let graceful_p95 = candidate.shutdown.graceful_duration_seconds.p95;
        let surviving = candidate.shutdown.surviving_owned_processes;
        let graceful_limit = thresholds.shutdown_graceful_deadline_seconds;
        let escalation_limit = thresholds.shutdown_escalation_deadline_seconds;
        let shutdown_passed = graceful_p95 <= graceful_limit
            && candidate.shutdown.escalation_duration_seconds.p95 <= escalation_limit
            && candidate.shutdown.graceful_duration_seconds.max <= graceful_limit
            && candidate.shutdown.escalation_duration_seconds.max <= escalation_limit
            && surviving == 0
            && candidate.shutdown.unrelated_processes_killed == 0;
        results.push(GateResult {
            name: "Shutdown & Process Cleanup".to_string(),
            reference_value: graceful_limit,
            candidate_value: graceful_p95,
            threshold_multiplier: 1.0,
            target_threshold: graceful_limit,
            higher_is_better: false,
            passed: shutdown_passed,
            details: format!(
                "Graceful p95: {graceful_p95:.2}s <= {graceful_limit:.0}s, Escalation p95: {:.2}s <= {escalation_limit:.0}s, Surviving owned processes: {surviving}",
                candidate.shutdown.escalation_duration_seconds.p95
            ),
        });

        // Raw 900-sample run captures, soak logs, process receipts, libc/filesystem/variant
        // identity and source hashes have no verified importer in this slice. Fail closed
        // even if a caller labels supplied numbers as live data. This is arithmetic only.
        let validation_errors = vec![format!(
            "Not qualified: reference {:?}, candidate {:?}; verified live-capture provenance/import is not implemented",
            reference.evidence_kind, candidate.evidence_kind
        )];
        let all_passed = false;
        Self {
            architecture: candidate.architecture.as_str().to_string(),
            reference_id: reference.id.clone(),
            candidate_id: candidate.id.clone(),
            all_passed,
            validation_errors,
            results,
        }
    }
}
