//! Budget comparison, component profiling breakdown, regression analysis, and scope decisions.

use super::metrics::{Architecture, PerformanceReport};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// Budget domain categories from the E01 contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetDomain {
    Startup,
    IdleMemory,
    BinaryDistribution,
    ResilienceAndDensity,
}

impl BudgetDomain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "Startup Latency",
            Self::IdleMemory => "Idle Memory Footprint",
            Self::BinaryDistribution => "Binary Distribution Size",
            Self::ResilienceAndDensity => "Pod Density & Lifecycle Resilience",
        }
    }
}

/// Comparison of an individual candidate metric against baseline and E01 budget threshold.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BudgetMetricComparison {
    pub name: String,
    pub domain: BudgetDomain,
    pub reference_value: f64,
    pub candidate_value: f64,
    pub threshold_multiplier: f64,
    pub target_threshold: f64,
    pub delta: f64,
    pub ratio: f64,
    pub higher_is_better: bool,
    pub is_regression: bool,
    pub within_budget: bool,
    pub unit: String,
    pub details: String,
}

/// Process memory profiling entry with relative share.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ProcessMemoryProfile {
    pub role: String,
    pub process_name: String,
    pub pss_bytes: u64,
    pub rss_bytes: u64,
    pub pss_fraction_percent: f64,
}

/// Component binary profiling entry with relative share.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ComponentBinaryProfile {
    pub component_name: String,
    pub size_bytes: u64,
    pub fraction_percent: f64,
}

/// Input comparison for an optimization hypothesis; parity requires independent receipts.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ScopedOptimization {
    pub title: String,
    pub domain: BudgetDomain,
    pub before_description: String,
    pub before_metric_value: f64,
    pub after_description: String,
    pub after_metric_value: f64,
    pub reduction_percent: f64,
    pub unit: String,
    pub parity_invariants_verified: Vec<String>,
}

/// Documented explicit budget scope decision with empirical justification.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BudgetScopeDecision {
    pub decision_id: String,
    pub title: String,
    pub status: String,
    pub empirical_evidence: String,
    pub contract_justification: String,
}

/// Comprehensive budget profile analysis report.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BudgetProfileReport {
    pub architecture: Architecture,
    pub reference_id: String,
    pub candidate_id: String,
    pub metrics: Vec<BudgetMetricComparison>,
    pub process_profiles: Vec<ProcessMemoryProfile>,
    pub binary_profiles: Vec<ComponentBinaryProfile>,
    pub optimizations: Vec<ScopedOptimization>,
    pub scope_decisions: Vec<BudgetScopeDecision>,
    pub total_regressions_detected: usize,
    pub all_budgets_satisfied: bool,
}

impl BudgetProfileReport {
    /// Analyze candidate against reference report, comparing to E01 budgets and profiling component shares.
    pub fn analyze(reference: &PerformanceReport, candidate: &PerformanceReport) -> Result<Self> {
        super::validation::validate_pair(reference, candidate)?;
        verify_optimization_parity(candidate)?;

        let evaluation = super::contract::GateEvaluationReport::evaluate(reference, candidate);
        let metrics: Vec<_> = evaluation
            .results
            .into_iter()
            .map(|gate| {
                // Presentation adds grouping and units; thresholds and outcomes have one owner.
                let (domain, unit) = if gate.name.contains("Latency") {
                    (BudgetDomain::Startup, "s")
                } else if gate.name.starts_with("Idle Footprint") {
                    (BudgetDomain::IdleMemory, "bytes")
                } else if gate.name.starts_with("Distribution Size") {
                    (BudgetDomain::BinaryDistribution, "bytes")
                } else if gate.name.starts_with("Pod Density") {
                    (BudgetDomain::ResilienceAndDensity, "pods")
                } else if gate.name.starts_with("Sustained Growth") {
                    (BudgetDomain::ResilienceAndDensity, "bytes")
                } else {
                    (BudgetDomain::ResilienceAndDensity, "s")
                };
                let is_regression = if gate.name.starts_with("Sustained Growth") {
                    !gate.passed
                } else if gate.higher_is_better {
                    gate.candidate_value < gate.reference_value
                } else {
                    gate.candidate_value > gate.reference_value
                };
                BudgetMetricComparison {
                    name: gate.name,
                    domain,
                    reference_value: gate.reference_value,
                    candidate_value: gate.candidate_value,
                    threshold_multiplier: gate.threshold_multiplier,
                    target_threshold: gate.target_threshold,
                    delta: gate.candidate_value - gate.reference_value,
                    ratio: if gate.reference_value > 0.0 {
                        gate.candidate_value / gate.reference_value
                    } else {
                        1.0
                    },
                    higher_is_better: gate.higher_is_better,
                    is_regression,
                    within_budget: gate.passed,
                    unit: unit.into(),
                    details: gate.details,
                }
            })
            .collect();

        let total_regressions_detected = metrics.iter().filter(|m| m.is_regression).count();
        let all_budgets_satisfied = metrics.iter().all(|m| m.within_budget);

        // Component Process Memory Profiling
        let total_cand_pss: u64 = candidate
            .idle_footprint
            .retained_processes
            .iter()
            .map(|p| p.pss_bytes)
            .sum();

        let mut process_profiles = Vec::new();
        for p in &candidate.idle_footprint.retained_processes {
            let role = super::harness::process_role(&p.process_name)
                .unwrap_or("unknown")
                .to_string();
            let pss_fraction_percent = if total_cand_pss > 0 {
                (p.pss_bytes as f64 / total_cand_pss as f64) * 100.0
            } else {
                0.0
            };
            process_profiles.push(ProcessMemoryProfile {
                role,
                process_name: p.process_name.clone(),
                pss_bytes: p.pss_bytes,
                rss_bytes: p.rss_bytes,
                pss_fraction_percent,
            });
        }
        process_profiles.sort_by_key(|b| std::cmp::Reverse(b.pss_bytes));

        // Component Binary Size Profiling
        let total_cand_extracted: u64 = candidate
            .artifact_footprint
            .component_binary_sizes
            .values()
            .sum();
        let mut binary_profiles = Vec::new();
        for (name, &size) in &candidate.artifact_footprint.component_binary_sizes {
            let fraction_percent = if total_cand_extracted > 0 {
                (size as f64 / total_cand_extracted as f64) * 100.0
            } else {
                0.0
            };
            binary_profiles.push(ComponentBinaryProfile {
                component_name: name.clone(),
                size_bytes: size,
                fraction_percent,
            });
        }
        binary_profiles.sort_by_key(|b| std::cmp::Reverse(b.size_bytes));

        // Scoped Optimizations with Before/After Justifications
        let optimizations = default_scoped_optimizations(reference, candidate);

        // Explicit Budget Scope Decisions
        let scope_decisions = default_budget_scope_decisions(reference, candidate);

        Ok(Self {
            architecture: candidate.architecture,
            reference_id: reference.id.clone(),
            candidate_id: candidate.id.clone(),
            metrics,
            process_profiles,
            binary_profiles,
            optimizations,
            scope_decisions,
            total_regressions_detected,
            all_budgets_satisfied,
        })
    }
}

/// Verify that optimizations do not sacrifice compatibility or reintroduce removed edge defaults.
pub fn verify_optimization_parity(candidate: &PerformanceReport) -> Result<()> {
    super::harness::verify_retained_process_coverage(candidate)?;

    if (candidate.pod_density.probe_success_rate - 1.0).abs() > f64::EPSILON {
        return Err("parity violation: probe success rate must be 1.0 under sustained hold".into());
    }

    if candidate.sustained_growth.crash_count != 0
        || candidate.sustained_growth.oom_kill_count != 0
        || candidate.sustained_growth.unexplained_failures != 0
    {
        return Err("parity violation: soak stability observed crashes, OOM kills or unexplained probe failures".into());
    }

    if candidate.shutdown.surviving_owned_processes != 0
        || candidate.shutdown.unrelated_processes_killed != 0
    {
        return Err("parity violation: shutdown left surviving processes or killed unrelated host processes".into());
    }

    // Verify all canonical roles are covered with nonzero memory
    for required in super::harness::REQUIRED_RETAINED_PROCESSES {
        let has_role = candidate.idle_footprint.retained_processes.iter().any(|p| {
            super::harness::process_role(&p.process_name) == Some(required) && p.pss_bytes > 0
        });
        if !has_role {
            return Err(format!(
                "parity violation: required role '{required}' has zero or missing memory"
            )
            .into());
        }
    }

    Ok(())
}

fn default_scoped_optimizations(
    reference: &PerformanceReport,
    candidate: &PerformanceReport,
) -> Vec<ScopedOptimization> {
    let mut opts = Vec::new();

    // 1. Rust Node Daemon Memory Reduction
    let ref_daemon_mem = reference
        .idle_footprint
        .retained_processes
        .iter()
        .find(|p| super::harness::process_role(&p.process_name) == Some("node-daemon"))
        .map_or(0, |p| p.pss_bytes) as f64;
    let cand_daemon_mem = candidate
        .idle_footprint
        .retained_processes
        .iter()
        .find(|p| super::harness::process_role(&p.process_name) == Some("node-daemon"))
        .map_or(0, |p| p.pss_bytes) as f64;
    let mem_reduction = if ref_daemon_mem > 0.0 {
        ((ref_daemon_mem - cand_daemon_mem) / ref_daemon_mem) * 100.0
    } else {
        0.0
    };
    opts.push(ScopedOptimization {
        title: "Node Daemon Idle Memory Optimization (Rust diorama-kube vs Go kubesolo)"
            .to_string(),
        domain: BudgetDomain::IdleMemory,
        before_description: format!(
            "Go kubesolo-node-daemon PSS: {:.2} MiB",
            ref_daemon_mem / (1024.0 * 1024.0)
        ),
        before_metric_value: ref_daemon_mem,
        after_description: format!(
            "Rust diorama-kube-node-daemon PSS: {:.2} MiB",
            cand_daemon_mem / (1024.0 * 1024.0)
        ),
        after_metric_value: cand_daemon_mem,
        reduction_percent: mem_reduction,
        unit: "bytes".to_string(),
        parity_invariants_verified: Vec::new(),
    });

    // 2. Rust Node Daemon Executable Size Reduction
    let ref_daemon_bin = reference
        .artifact_footprint
        .component_binary_sizes
        .get("kubesolo")
        .copied()
        .unwrap_or(0) as f64;
    let cand_daemon_bin = candidate
        .artifact_footprint
        .component_binary_sizes
        .get("diorama-kube")
        .copied()
        .unwrap_or(0) as f64;
    let bin_reduction = if ref_daemon_bin > 0.0 {
        ((ref_daemon_bin - cand_daemon_bin) / ref_daemon_bin) * 100.0
    } else {
        0.0
    };
    opts.push(ScopedOptimization {
        title: "Node Executable Distribution Size (Rust diorama-kube vs Go kubesolo)".to_string(),
        domain: BudgetDomain::BinaryDistribution,
        before_description: format!(
            "Go kubesolo binary: {:.2} MiB",
            ref_daemon_bin / (1024.0 * 1024.0)
        ),
        before_metric_value: ref_daemon_bin,
        after_description: format!(
            "Rust diorama-kube binary: {:.2} MiB",
            cand_daemon_bin / (1024.0 * 1024.0)
        ),
        after_metric_value: cand_daemon_bin,
        reduction_percent: bin_reduction,
        unit: "bytes".to_string(),
        parity_invariants_verified: Vec::new(),
    });

    // 3. Distribution Archive Compression (zstd multithreaded)
    let ref_archive = reference.artifact_footprint.compressed_archive_bytes as f64;
    let cand_archive = candidate.artifact_footprint.compressed_archive_bytes as f64;
    let archive_reduction = if ref_archive > 0.0 {
        ((ref_archive - cand_archive) / ref_archive) * 100.0
    } else {
        0.0
    };
    opts.push(ScopedOptimization {
        title: "Release Archive Compression Comparison (mechanism unverified)".to_string(),
        domain: BudgetDomain::BinaryDistribution,
        before_description: format!(
            "Reference archive input: {:.2} MiB",
            ref_archive / (1024.0 * 1024.0)
        ),
        before_metric_value: ref_archive,
        after_description: format!(
            "Candidate archive input: {:.2} MiB",
            cand_archive / (1024.0 * 1024.0)
        ),
        after_metric_value: cand_archive,
        reduction_percent: archive_reduction,
        unit: "bytes".to_string(),
        parity_invariants_verified: Vec::new(),
    });

    // 4. Asynchronous Supervisor Readiness & Startup Latency
    let ref_boot = reference.startup_latencies.boot_to_api_seconds.p95;
    let cand_boot = candidate.startup_latencies.boot_to_api_seconds.p95;
    let boot_improvement = if ref_boot > 0.0 {
        ((ref_boot - cand_boot) / ref_boot) * 100.0
    } else {
        0.0
    };
    opts.push(ScopedOptimization {
        title: "Boot-to-API Comparison (sequencing unverified)".to_string(),
        domain: BudgetDomain::Startup,
        before_description: format!("Reference boot-to-API p95: {ref_boot:.3}s"),
        before_metric_value: ref_boot,
        after_description: format!("Candidate boot-to-API p95: {cand_boot:.3}s"),
        after_metric_value: cand_boot,
        reduction_percent: boot_improvement,
        unit: "seconds".to_string(),
        parity_invariants_verified: Vec::new(),
    });

    opts
}

fn default_budget_scope_decisions(
    reference: &PerformanceReport,
    candidate: &PerformanceReport,
) -> Vec<BudgetScopeDecision> {
    let apiserver_pss = candidate
        .idle_footprint
        .retained_processes
        .iter()
        .find(|p| p.process_name.contains("apiserver"))
        .map_or(0, |p| p.pss_bytes);
    let total_pss = candidate.idle_footprint.summed_pss_bytes.p50;
    let cold_p95 = candidate.startup_latencies.first_pod_cold_seconds.p95;

    vec![
        BudgetScopeDecision {
            decision_id: "DEC-01-SUB200MB-REFUSAL".to_string(),
            title: "Refusal of Unmeasured Sub-200MB Memory Claim".to_string(),
            status: "Enforced & Documented".to_string(),
            empirical_evidence: format!(
                "Supervised kube-apiserver alone consumes {:.1} MiB PSS (ratio to separate summed-PSS median: {:.1}%; not an additive share). \
                Total candidate node idle PSS is {:.1} MiB across all 8 required supervised processes. \
                These input values do not establish live memory usage; sub-200MB claims require independent matched captures.",
                apiserver_pss as f64 / (1024.0 * 1024.0),
                (apiserver_pss as f64 / total_pss.max(1.0)) * 100.0,
                total_pss / (1024.0 * 1024.0),
            ),
            contract_justification: "Compatibility contract (line 221) mandates: 'No sub-200-MB or under-60-second claim is accepted from README marketing alone.' \
                All 8 retained processes (apiserver, controller-manager, kubelet, proxy, kine, containerd, containerd-shim, node-daemon) must be honestly accounted for.".to_string(),
        },
        BudgetScopeDecision {
            decision_id: "DEC-02-NO-LOW-MEMORY-EDGE-OVERRIDES".to_string(),
            title: "Preservation of Upstream Defaults without Low-Memory Edge Overrides (D09 / KS-68)".to_string(),
            status: "Enforced & Documented".to_string(),
            empirical_evidence: "Upstream commit 35d1093 / PR #166 (KS-68) explicitly removed low-memory overrides that previously caused reconciliation stalls, \
                pod eviction thrashing, and controller memory leaks. Diorama strictly retains upstream v1.35.7 reconciliation defaults, standard 0s EndpointSlice batching, \
                and unchoked controller loops.".to_string(),
            contract_justification: "Deviation D09 prohibits resurrecting removed edge memory overrides, omitting required controllers, or altering core sync intervals \
                to artificially deflate benchmark numbers. Diorama accepts honest whole-distribution memory measurements rather than sacrificing compatibility.".to_string(),
        },
        BudgetScopeDecision {
            decision_id: "DEC-03-UNDER-60S-STARTUP-REFUSAL".to_string(),
            title: "Refusal of Unmeasured Under-60s Startup Marketing Claims".to_string(),
            status: "Enforced & Documented".to_string(),
            empirical_evidence: format!(
                "Input cold first-pod startup p95 is {:.2}s ({}) versus reference {:.2}s. \
                The 600-second configurable startup timeout in diorama-config is an operational safety limit for degraded environments, not a measured boot target.",
                cold_p95,
                candidate.architecture.as_str(),
                reference.startup_latencies.first_pod_cold_seconds.p95,
            ),
            contract_justification: "Compatibility contract (lines 243-244) establishes: 'The 600-second configurable per-component startup timeout is a compatibility default, \
                not an acceptable measured boot target or a global startup deadline.' Benchmark reports must reflect measured monotonic latencies, not timeout defaults.".to_string(),
        },
        BudgetScopeDecision {
            decision_id: "DEC-04-IMAGE-PAYLOAD-SEPARATION".to_string(),
            title: "Explicit Separation of Container Image Payload from Executables".to_string(),
            status: "Enforced & Documented".to_string(),
            empirical_evidence: format!(
                "Candidate executable binaries total {:.1} MiB uncompressed, compressed archive is {:.1} MiB, and default offline container images total {:.1} MiB. \
                Core container images (CoreDNS, Pause, Local-Path, Busybox, Portainer, D2K) are required for offline air-gapped operation and must not be counted as code bloat.",
                candidate.artifact_footprint.extracted_executable_bytes as f64 / (1024.0 * 1024.0),
                candidate.artifact_footprint.compressed_archive_bytes as f64 / (1024.0 * 1024.0),
                candidate.artifact_footprint.default_image_payload_bytes as f64 / (1024.0 * 1024.0),
            ),
            contract_justification: "Acceptance matrix and E06/E27/E29 contract specify: 'Exact compressed release archive bytes; extracted executable/helper bytes; \
                required default image payload bytes measured separately.' Image bytes are tracked as independent distribution assets.".to_string(),
        },
        BudgetScopeDecision {
            decision_id: "DEC-05-SECONDARY-TARGET-GAPS".to_string(),
            title: "Fail-Closed Qualification for Secondary Architecture Gaps (armv7, riscv64)".to_string(),
            status: "Enforced & Documented".to_string(),
            empirical_evidence: "armv7 (32-bit address space, crun source build required) and riscv64 (Portainer/D2K disabled by platform contract) have no verified \
                hardware captures. Pod density is recorded as 0 and startup latencies as unmeasured.".to_string(),
            contract_justification: "Secondary architecture gaps must remain explicit; no relaxed latency multipliers or density exemptions are permitted. \
                Qualification fails closed until dedicated hardware evidence is captured.".to_string(),
        },
    ]
}

/// Generate a comprehensive Markdown budget profiling and scope decisions report.
pub fn generate_budget_markdown_report(report: &BudgetProfileReport) -> String {
    let mut out = String::with_capacity(8192);

    let mib = 1024.0 * 1024.0;
    let _ = writeln!(
        out,
        "# Budget Profiling & Scope Decision Analysis: {} Candidate vs Reference",
        report.architecture.as_str().to_uppercase()
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "**Reference ID:** `{}` | **Candidate ID:** `{}`",
        report.reference_id, report.candidate_id
    );
    let _ = writeln!(out);

    // Section 1: Executive Summary
    let _ = writeln!(out, "## 1. Executive Summary & E01 Budget Evaluation");
    let _ = writeln!(out);
    let overall_budget_status = if report.all_budgets_satisfied {
        "ALL 12 GATES SATISFIED WITHIN E01 CONTRACT BUDGETS (<= 1.10x / >= 0.90x)"
    } else {
        "BUDGET REGRESSIONS DETECTED"
    };
    let _ = writeln!(out, "**Budget Compliance:** {overall_budget_status}");
    let _ = writeln!(
        out,
        "- **Total Regressions Detected Against Reference:** {}",
        report.total_regressions_detected
    );
    let _ = writeln!(
        out,
        "- **Evidence Qualification Status:** NOT QUALIFIED (synthetic fixture baseline; live hardware capture importer pending)"
    );
    let _ = writeln!(out);

    // Section 2: Metric-by-Metric Budget Comparison Table
    let _ = writeln!(out, "## 2. Metric-by-Metric Budget Comparison");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Domain | Metric | Direction | Reference | Candidate | Limit (Threshold) | Ratio | Budget Status |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|---|");
    for m in &report.metrics {
        let dir = if m.higher_is_better {
            ">= 0.90x"
        } else {
            "<= 1.10x"
        };
        let status = if m.within_budget { "PASS" } else { "EXCEEDED" };
        let (ref_fmt, cand_fmt, lim_fmt) = if m.unit == "bytes" {
            (
                format!("{:.2} MiB", m.reference_value / mib),
                format!("{:.2} MiB", m.candidate_value / mib),
                format!("{:.2} MiB", m.target_threshold / mib),
            )
        } else if m.unit == "s" {
            (
                format!("{:.3}s", m.reference_value),
                format!("{:.3}s", m.candidate_value),
                format!("{:.3}s", m.target_threshold),
            )
        } else {
            (
                format!("{:.1} {}", m.reference_value, m.unit),
                format!("{:.1} {}", m.candidate_value, m.unit),
                format!("{:.1} {}", m.target_threshold, m.unit),
            )
        };
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {:.3}x | {} |",
            m.domain.as_str(),
            m.name,
            dir,
            ref_fmt,
            cand_fmt,
            lim_fmt,
            m.ratio,
            status
        );
    }
    let _ = writeln!(out);

    // Section 3: Retained Process Memory Profiling
    let _ = writeln!(out, "## 3. Retained Process Memory Profiling Breakdown");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "All 8 required supervised processes are accounted for without omission:"
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Rank | Process Role | Executable Name | PSS (MiB) | RSS (MiB) | % of Retained Role Sum |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|");
    for (i, p) in report.process_profiles.iter().enumerate() {
        let _ = writeln!(
            out,
            "| {} | `{}` | `{}` | {:.2} MiB | {:.2} MiB | {:.1}% |",
            i + 1,
            p.role,
            p.process_name,
            p.pss_bytes as f64 / mib,
            p.rss_bytes as f64 / mib,
            p.pss_fraction_percent
        );
    }
    let _ = writeln!(out);
    if let Some(top) = report.process_profiles.first() {
        let _ = writeln!(
            out,
            "> `{}` has the largest retained-process PSS input: {:.2} MiB ({:.1}% of the role sum).",
            top.process_name,
            top.pss_bytes as f64 / mib,
            top.pss_fraction_percent
        );
    }

    // Section 4: Component Binary Footprint Profiling
    let _ = writeln!(out, "## 4. Component Binary Footprint Profiling");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Rank | Component Binary | Size (MiB) | % of Listed Binary Sum |"
    );
    let _ = writeln!(out, "|---|---|---|---|");
    for (i, b) in report.binary_profiles.iter().enumerate() {
        let _ = writeln!(
            out,
            "| {} | `{}` | {:.2} MiB | {:.1}% |",
            i + 1,
            b.component_name,
            b.size_bytes as f64 / mib,
            b.fraction_percent
        );
    }
    let _ = writeln!(out);

    // Section 5: Scoped Optimizations with Before/After Justifications
    let _ = writeln!(
        out,
        "## 5. Scoped Optimizations with Before/After Justifications"
    );
    let _ = writeln!(out);
    for opt in &report.optimizations {
        let _ = writeln!(out, "### {}", opt.title);
        let _ = writeln!(out);
        let _ = writeln!(out, "- **Domain:** {}", opt.domain.as_str());
        let _ = writeln!(
            out,
            "- **Before (Go Reference):** {}",
            opt.before_description
        );
        let _ = writeln!(
            out,
            "- **After (Rust Candidate):** {}",
            opt.after_description
        );
        let _ = writeln!(
            out,
            "- **Input Difference (causal attribution unverified):** {:.2}%",
            opt.reduction_percent
        );
        let _ = writeln!(
            out,
            "- **Parity:** Unverified; independent protocol, lifecycle and artifact receipts are required."
        );
        for inv in &opt.parity_invariants_verified {
            let _ = writeln!(out, "  * {inv}");
        }
        let _ = writeln!(out);
    }

    // Section 6: Explicit Budget Scope Decisions
    let _ = writeln!(out, "## 6. Explicit Budget Scope Decisions with Evidence");
    let _ = writeln!(out);
    for dec in &report.scope_decisions {
        let _ = writeln!(out, "### [{}] {}", dec.decision_id, dec.title);
        let _ = writeln!(out);
        let _ = writeln!(out, "- **Status:** {}", dec.status);
        let _ = writeln!(out, "- **Empirical Evidence:** {}", dec.empirical_evidence);
        let _ = writeln!(
            out,
            "- **Contract Justification:** {}",
            dec.contract_justification
        );
        let _ = writeln!(out);
    }

    out
}
