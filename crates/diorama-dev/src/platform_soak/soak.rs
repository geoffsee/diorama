//! Sustained 24-hour soak and memory growth evaluation.
//!
//! Evaluates sustained workload execution over 24 hours with alternating active workload
//! and idle cycles. Asserts the compatibility contract bound:
//! - Final settled median memory <= 1.10 x initial settled median memory
//! - Zero OOM events
//! - Zero process crashes
//! - Zero unexplained probe failures

use serde::{Deserialize, Serialize};

/// Maximum permissible ratio between final and initial settled idle memory.
pub const SOAK_MAX_GROWTH_RATIO: f64 = 1.10;

/// Required soak duration in hours.
pub const SOAK_REQUIRED_HOURS: u32 = 24;

/// Sustained soak measurement record for an evaluation run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SustainedSoakRecord {
    pub target_architecture: String,
    pub declared_duration_hours: u32,
    pub actual_duration_seconds: u64,
    pub workload_cycles_completed: u32,
    pub initial_settled_idle_rss_bytes: u64,
    pub final_settled_idle_rss_bytes: u64,
    pub derived_growth_ratio: f64,
    pub oom_count: u32,
    pub crash_count: u32,
    pub unexplained_probe_failures: u32,
    pub passed: bool,
    pub details: Vec<String>,
}

/// Primary architectures required for sustained soak qualification.
pub const PRIMARY_SOAK_ARCHITECTURES: [&str; 4] = ["amd64", "arm64", "armv7", "riscv64"];

/// Summary of sustained soak evaluations across tested platforms.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SustainedSoakSummary {
    pub records: Vec<SustainedSoakRecord>,
    pub all_passed: bool,
}

impl SustainedSoakSummary {
    /// Evaluate a soak record against strict contractual bounds.
    pub fn evaluate_record(
        target_architecture: &str,
        actual_duration_seconds: u64,
        workload_cycles: u32,
        initial_rss_bytes: u64,
        final_rss_bytes: u64,
        oom_count: u32,
        crash_count: u32,
        probe_failures: u32,
    ) -> Result<SustainedSoakRecord, String> {
        let mut details = Vec::new();
        let mut passed = true;

        if initial_rss_bytes == 0 || final_rss_bytes == 0 || workload_cycles == 0 {
            return Err(
                "initial/final settled idle RSS and workload cycles must be positive".into(),
            );
        }

        let growth_ratio = (final_rss_bytes as f64) / (initial_rss_bytes as f64);

        let required_seconds = u64::from(SOAK_REQUIRED_HOURS) * 3600;
        if actual_duration_seconds < required_seconds {
            passed = false;
            details.push(format!(
                "Soak duration {actual_duration_seconds}s is less than required 24h ({required_seconds}s)"
            ));
        } else {
            details.push(format!(
                "Completed declared {SOAK_REQUIRED_HOURS}h soak duration ({actual_duration_seconds}s, {workload_cycles} workload cycles)"
            ));
        }

        let initial_mib = (initial_rss_bytes as f64) / (1024.0 * 1024.0);
        let final_mib = (final_rss_bytes as f64) / (1024.0 * 1024.0);

        if u128::from(final_rss_bytes) * 10 > u128::from(initial_rss_bytes) * 11 {
            passed = false;
            details.push(format!(
                "Memory growth ratio {growth_ratio:.3}x exceeds bound {SOAK_MAX_GROWTH_RATIO:.2}x (Initial: {initial_mib:.1} MiB, Final: {final_mib:.1} MiB)"
            ));
        } else {
            details.push(format!(
                "Memory growth ratio {growth_ratio:.3}x within bound {SOAK_MAX_GROWTH_RATIO:.2}x (Initial: {initial_mib:.1} MiB, Final: {final_mib:.1} MiB)"
            ));
        }

        if oom_count > 0 {
            passed = false;
            details.push(format!("Observed {oom_count} OOM kill events; expected 0"));
        } else {
            details.push("Zero OOM events observed".into());
        }

        if crash_count > 0 {
            passed = false;
            details.push(format!(
                "Observed {crash_count} process crashes; expected 0"
            ));
        } else {
            details.push("Zero process crashes observed".into());
        }

        if probe_failures > 0 {
            passed = false;
            details.push(format!(
                "Observed {probe_failures} unexplained probe failures; expected 0"
            ));
        } else {
            details.push("Zero unexplained probe failures observed".into());
        }

        if !passed {
            return Err(format!(
                "soak test bounds violated for {target_architecture}: {}",
                details.join("; ")
            ));
        }

        Ok(SustainedSoakRecord {
            target_architecture: target_architecture.to_string(),
            declared_duration_hours: SOAK_REQUIRED_HOURS,
            actual_duration_seconds,
            workload_cycles_completed: workload_cycles,
            initial_settled_idle_rss_bytes: initial_rss_bytes,
            final_settled_idle_rss_bytes: final_rss_bytes,
            derived_growth_ratio: growth_ratio,
            oom_count,
            crash_count,
            unexplained_probe_failures: probe_failures,
            passed,
            details,
        })
    }

    /// Independently validate and recompute soak records against contractual bounds.
    ///
    /// Recomputes growth ratios from initial and final settled RSS values, validates duration,
    /// verifies complete primary architecture coverage, and confirms zero OOMs, crashes, or probe failures.
    pub fn validate_records(records: &[SustainedSoakRecord]) -> Result<(), String> {
        let required_seconds = u64::from(SOAK_REQUIRED_HOURS) * 3600;
        let mut seen = std::collections::HashSet::new();

        for arch in &PRIMARY_SOAK_ARCHITECTURES {
            let found = records.iter().find(|r| r.target_architecture == *arch);
            match found {
                Some(record) => {
                    if !seen.insert(*arch) {
                        return Err(format!("duplicate soak record for architecture '{arch}'"));
                    }
                    if record.initial_settled_idle_rss_bytes == 0 {
                        return Err(format!(
                            "initial settled idle RSS cannot be zero for '{arch}'"
                        ));
                    }
                    if record.final_settled_idle_rss_bytes == 0 {
                        return Err(format!(
                            "final settled idle RSS cannot be zero for '{arch}'"
                        ));
                    }
                    if record.actual_duration_seconds < required_seconds {
                        return Err(format!(
                            "soak duration {}s for '{arch}' is less than required 24h ({required_seconds}s)",
                            record.actual_duration_seconds
                        ));
                    }
                    if record.workload_cycles_completed == 0 {
                        return Err(format!(
                            "workload cycles completed cannot be zero for '{arch}'"
                        ));
                    }
                    if record.declared_duration_hours != SOAK_REQUIRED_HOURS
                        || !record.derived_growth_ratio.is_finite()
                    {
                        return Err(format!(
                            "invalid declared duration or non-finite ratio for '{arch}'"
                        ));
                    }

                    let recomputed_ratio = (record.final_settled_idle_rss_bytes as f64)
                        / (record.initial_settled_idle_rss_bytes as f64);
                    if record.derived_growth_ratio.to_bits() != recomputed_ratio.to_bits() {
                        return Err(format!(
                            "derived growth ratio {:.4} does not match recomputed ratio {:.4} for '{arch}'",
                            record.derived_growth_ratio, recomputed_ratio
                        ));
                    }
                    if u128::from(record.final_settled_idle_rss_bytes) * 10
                        > u128::from(record.initial_settled_idle_rss_bytes) * 11
                    {
                        return Err(format!(
                            "recomputed memory growth ratio {recomputed_ratio:.3}x exceeds bound {SOAK_MAX_GROWTH_RATIO:.2}x for '{arch}'"
                        ));
                    }
                    if record.oom_count > 0 {
                        return Err(format!(
                            "observed {} OOM events for '{arch}'; expected 0",
                            record.oom_count
                        ));
                    }
                    if record.crash_count > 0 {
                        return Err(format!(
                            "observed {} crashes for '{arch}'; expected 0",
                            record.crash_count
                        ));
                    }
                    if record.unexplained_probe_failures > 0 {
                        return Err(format!(
                            "observed {} unexplained probe failures for '{arch}'; expected 0",
                            record.unexplained_probe_failures
                        ));
                    }
                    if !record.passed {
                        return Err(format!("soak record for '{arch}' is marked failed"));
                    }
                },
                None => {
                    return Err(format!(
                        "missing required primary architecture soak record: '{arch}'"
                    ));
                },
            }
        }

        if records.len() != PRIMARY_SOAK_ARCHITECTURES.len() {
            return Err(format!(
                "expected exactly {} soak records for primary architectures, found {}",
                PRIMARY_SOAK_ARCHITECTURES.len(),
                records.len()
            ));
        }

        Ok(())
    }

    /// Synthetic arithmetic fixtures; these values are not measured candidate profiles.
    #[must_use]
    pub fn canonical_soak_records() -> Vec<SustainedSoakRecord> {
        let amd64 = Self::evaluate_record(
            "amd64",
            86400,
            48,
            450 * 1024 * 1024, // 450 MiB initial
            472 * 1024 * 1024, // 472 MiB final (~1.049x growth <= 1.10x)
            0,
            0,
            0,
        )
        .expect("amd64 canonical soak profile must satisfy bounds");

        let arm64 = Self::evaluate_record(
            "arm64",
            86400,
            48,
            440 * 1024 * 1024, // 440 MiB initial
            462 * 1024 * 1024, // 462 MiB final (~1.050x growth <= 1.10x)
            0,
            0,
            0,
        )
        .expect("arm64 canonical soak profile must satisfy bounds");

        let armv7 = Self::evaluate_record(
            "armv7",
            86400,
            48,
            380 * 1024 * 1024, // 380 MiB initial
            396 * 1024 * 1024, // 396 MiB final (~1.042x growth <= 1.10x)
            0,
            0,
            0,
        )
        .expect("armv7 canonical soak profile must satisfy bounds");

        let riscv64 = Self::evaluate_record(
            "riscv64",
            86400,
            48,
            410 * 1024 * 1024, // 410 MiB initial
            430 * 1024 * 1024, // 430 MiB final (~1.049x growth <= 1.10x)
            0,
            0,
            0,
        )
        .expect("riscv64 canonical soak profile must satisfy bounds");

        vec![amd64, arm64, armv7, riscv64]
    }
}
