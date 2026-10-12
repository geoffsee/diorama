//! Versioned platform coverage and sustained soak qualification report.
//!
//! Generates structured JSON and human-readable Markdown reports mapping all environments,
//! candidate digests, soak bounds, restart bounds, and per-epic regressions.

use serde::{Deserialize, Serialize};
use std::fmt::Write;

use super::candidate::CandidateVerificationSummary;
use super::matrix::{DimensionCategory, EnvironmentRecord, MatrixCompleteness, SupportStatus};
use super::regressions::{EpicRegressionRecord, HistoricalRegression, RegressionSuite};
use super::restart::{RestartCase, RestartSummary};
use super::soak::{SOAK_MAX_GROWTH_RATIO, SustainedSoakRecord, SustainedSoakSummary};

/// Errors encountered during platform and soak report validation.
#[derive(Debug)]
pub enum PlatformSoakError {
    VersionMismatch { expected: String, actual: String },
    MatrixIncomplete(String),
    CandidateDigestMismatch(String),
    SoakBoundExceeded(String),
    RestartBoundExceeded(String),
    RegressionFailed(String),
    Serialization(String),
}

impl std::fmt::Display for PlatformSoakError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VersionMismatch { expected, actual } => {
                write!(f, "version mismatch: expected {expected}, actual {actual}")
            },
            Self::MatrixIncomplete(msg) => write!(f, "matrix completeness violation: {msg}"),
            Self::CandidateDigestMismatch(msg) => write!(f, "candidate digest mismatch: {msg}"),
            Self::SoakBoundExceeded(msg) => write!(f, "soak bound exceeded: {msg}"),
            Self::RestartBoundExceeded(msg) => write!(f, "restart bound exceeded: {msg}"),
            Self::RegressionFailed(msg) => write!(f, "regression failure: {msg}"),
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

impl std::error::Error for PlatformSoakError {}

/// Comprehensive platform coverage, candidate verification, and sustained soak report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlatformSoakReport {
    pub schema_version: u32,
    pub product: String,
    pub version: String,
    pub evidence_kind: String,
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_integrity_hash: Option<String>,
    pub environments: Vec<EnvironmentRecord>,
    pub candidate_verification: CandidateVerificationSummary,
    pub soak_results: Vec<SustainedSoakRecord>,
    pub restart_results: Vec<RestartCase>,
    pub historical_regressions: Vec<HistoricalRegression>,
    pub epic_regressions: Vec<EpicRegressionRecord>,
    pub overall_qualified: bool,
}

impl PlatformSoakReport {
    /// Validate the qualification report fail-closed against all contractual requirements.
    pub fn validate(&self, expected_version: Option<&str>) -> Result<(), PlatformSoakError> {
        self.validate_fixture(expected_version)?;
        let is_bound = (self.evidence_kind == "CandidateReceiptBound"
            || self.evidence_kind == "candidate_receipt_bound")
            && self.receipt_id.is_some()
            && self.receipt_integrity_hash.is_some()
            && self.overall_qualified;
        if is_bound
            && !self.soak_results.is_empty()
            && self.soak_results.iter().all(|r| r.passed)
            && !self.restart_results.is_empty()
            && self.restart_results.iter().all(|r| r.passed)
            && !self.historical_regressions.is_empty()
            && !self.epic_regressions.is_empty()
        {
            return Ok(());
        }
        Err(PlatformSoakError::RegressionFailed(
            "C14 qualification is not implemented; synthetic fixtures cannot qualify".into(),
        ))
    }

    /// Check synthetic record consistency, without accepting execution evidence.
    pub fn validate_fixture(
        &self,
        expected_version: Option<&str>,
    ) -> Result<(), PlatformSoakError> {
        let is_bound = (self.evidence_kind == "CandidateReceiptBound"
            || self.evidence_kind == "candidate_receipt_bound")
            && self.receipt_id.is_some()
            && self.receipt_integrity_hash.is_some();

        if self.schema_version != 2
            || self.product != "diorama-kube"
            || self.version.is_empty()
            || (!is_bound && (self.evidence_kind != "SyntheticFixture" || self.overall_qualified))
            || (is_bound && !self.overall_qualified)
            || self
                .timestamp
                .strip_prefix("unix:")
                .and_then(|value| value.parse::<u64>().ok())
                .is_none_or(|value| value == 0)
        {
            return Err(PlatformSoakError::Serialization(
                "invalid unqualified fixture metadata".into(),
            ));
        }
        // 1. Version check
        if let Some(expected) = expected_version
            && self.version != expected
        {
            return Err(PlatformSoakError::VersionMismatch {
                expected: expected.to_string(),
                actual: self.version.clone(),
            });
        }

        // 2. Matrix completeness: zero silent omissions
        MatrixCompleteness::validate(&self.environments)
            .map_err(PlatformSoakError::MatrixIncomplete)?;

        // 3. Candidate digests matching
        if !is_bound {
            self.candidate_verification
                .validate_unobserved_fixture()
                .map_err(PlatformSoakError::CandidateDigestMismatch)?;
        } else if !self.candidate_verification.all_matched
            || self.candidate_verification.mismatched_artifacts != 0
        {
            return Err(PlatformSoakError::CandidateDigestMismatch(
                "candidate digests do not all match in bound soak report".into(),
            ));
        }

        // 4. Soak bounds: independent recomputation of ratios, durations, cycles, positive memory, and complete architecture set
        SustainedSoakSummary::validate_records(&self.soak_results)
            .map_err(PlatformSoakError::SoakBoundExceeded)?;

        // 5. Restart bounds: independent timing and state preservation bounds for all required restart cases
        RestartSummary::validate_cases(&self.restart_results)
            .map_err(PlatformSoakError::RestartBoundExceeded)?;

        // 6. Historical regressions: exactly 10 historical regressions
        RegressionSuite::validate_historical(&self.historical_regressions)
            .map_err(PlatformSoakError::RegressionFailed)?;

        // 7. Per-epic regressions: exactly 30 parent epics (E01-E30) qualified
        RegressionSuite::validate_epics(&self.epic_regressions)
            .map_err(PlatformSoakError::RegressionFailed)?;

        // 8. Overall qualification consistency
        if !is_bound && self.overall_qualified {
            return Err(PlatformSoakError::RegressionFailed(
                "synthetic fixture cannot be qualified".into(),
            ));
        }

        Ok(())
    }

    /// Formats the report as clean, GitHub-flavored Markdown.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        if self.validate_fixture(None).is_err() {
            return "# Invalid Platform Fixture\n\nNOT QUALIFIED: report consistency validation failed.\n".into();
        }
        let is_bound = (self.evidence_kind == "CandidateReceiptBound"
            || self.evidence_kind == "candidate_receipt_bound")
            && self.receipt_id.is_some()
            && self.receipt_integrity_hash.is_some();

        let mut out = String::with_capacity(8192);

        let _ = writeln!(
            out,
            "# Platform Coverage and Sustained-Soak Qualification Report\n"
        );
        let _ = writeln!(out, "**Product:** `{}`", self.product);
        let _ = writeln!(out, "**Version:** `{}`", self.version);
        let _ = writeln!(out, "**Evidence Kind:** `{}`", self.evidence_kind);
        let _ = writeln!(out, "**Timestamp:** `{}`", self.timestamp);
        if let (Some(receipt_id), Some(hash)) = (&self.receipt_id, &self.receipt_integrity_hash) {
            let _ = writeln!(out, "- **Receipt ID**: `{receipt_id}`");
            let _ = writeln!(out, "- **Receipt Integrity Hash**: `{hash}`");
        }
        let _ = writeln!(
            out,
            "**Overall Status:** {}\n",
            if is_bound && self.overall_qualified {
                "PASS (Qualified)"
            } else {
                "NOT QUALIFIED (Synthetic fixture)"
            }
        );

        out.push_str("## 1. Executive Summary\n\n");
        let _ = writeln!(
            out,
            "Synthetic record consistency only. No installations, candidate bytes, 24-hour workloads, \
             restarts or historical/per-epic execution have been observed by this report. \
             Numerical PASS values below exercise fixture arithmetic; they are not execution results. \
             Gate C14 and Issue #120 remain unqualified."
        );

        out.push_str("\n## 2. Platform & Environment Matrix\n\n");
        out.push_str("Promised environments are listed as synthetic plans or explicit unsupported decisions, not passing execution.\n\n");

        let categories = [
            DimensionCategory::NodeVariantCell,
            DimensionCategory::ManagementTarget,
            DimensionCategory::OciContainerImage,
            DimensionCategory::RuntimeProvider,
            DimensionCategory::RuntimeBuildMode,
            DimensionCategory::InitSystem,
            DimensionCategory::ContainerRunMode,
            DimensionCategory::HostCapability,
            DimensionCategory::DeliveryMode,
            DimensionCategory::RuntimeOwnership,
            DimensionCategory::AddonComponent,
        ];

        for cat in categories {
            let _ = writeln!(out, "### {}\n", cat.display_name());
            out.push_str("| Environment ID | Name | Support Status | Result | Details |\n");
            out.push_str("| --- | --- | --- | --- | --- |\n");

            for rec in self.environments.iter().filter(|r| r.dimension == cat) {
                let status_str = match &rec.support_status {
                    SupportStatus::Supported => "Supported".to_string(),
                    SupportStatus::Unsupported { rationale } => format!("Unsupported: {rationale}"),
                };
                let result_str = match &rec.result {
                    super::matrix::EnvironmentResult::Verified => "Verified",
                    super::matrix::EnvironmentResult::Simulated { .. } => "Simulated",
                    super::matrix::EnvironmentResult::Unsupported { .. } => "Excluded",
                };
                let _ = writeln!(
                    out,
                    "| `{}` | {} | {} | {} | {} |",
                    rec.id, rec.name, status_str, result_str, rec.details
                );
            }
            out.push('\n');
        }

        out.push_str("## 3. Candidate Digest Verification\n\n");
        let _ = writeln!(
            out,
            "- **Total Candidate Artifacts Checked:** {}",
            self.candidate_verification.total_artifacts
        );
        let _ = writeln!(
            out,
            "- **Matched Artifacts:** {}",
            self.candidate_verification.matched_artifacts
        );
        let _ = writeln!(
            out,
            "- **Mismatched Artifacts:** {}",
            self.candidate_verification.mismatched_artifacts
        );
        let _ = writeln!(
            out,
            "- **All Candidate Digests Matched:** {}\n",
            self.candidate_verification.all_matched
        );

        out.push_str("| Artifact Name | Type | Expected SHA-256 | Matches |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for art in &self.candidate_verification.artifacts {
            let _ = writeln!(
                out,
                "| `{}` | {} | `{}` | {} |",
                art.name,
                art.artifact_type,
                if art.expected_sha256.len() > 16 {
                    format!("{}...", &art.expected_sha256[..16])
                } else {
                    art.expected_sha256.clone()
                },
                if art.matches { "YES" } else { "NO (MISMATCH)" }
            );
        }

        out.push_str("\n## 4. Sustained 24-Hour Soak & Memory Stability\n\n");
        out.push_str(
            "Contract bound: Final settled idle memory <= 1.10x initial settled idle memory, \
             0 OOM kills, 0 process crashes, 0 unexplained probe failures over 24 hours.\n\n",
        );

        for soak in &self.soak_results {
            let init_mib = (soak.initial_settled_idle_rss_bytes as f64) / (1024.0 * 1024.0);
            let final_mib = (soak.final_settled_idle_rss_bytes as f64) / (1024.0 * 1024.0);
            let _ = writeln!(
                out,
                "### Architecture: `{}`\n\
                 - **Declared Duration:** {}h (Actual: {}s)\n\
                 - **Workload Cycles Completed:** {}\n\
                 - **Initial Settled Idle Memory:** {:.2} MiB\n\
                 - **Final Settled Idle Memory:** {:.2} MiB\n\
                 - **Derived Growth Ratio:** {:.3}x (Limit: {:.2}x)\n\
                 - **OOM Kill Count:** {}\n\
                 - **Process Crash Count:** {}\n\
                 - **Unexplained Probe Failures:** {}\n\
                 - **Result:** {}\n",
                soak.target_architecture,
                soak.declared_duration_hours,
                soak.actual_duration_seconds,
                soak.workload_cycles_completed,
                init_mib,
                final_mib,
                soak.derived_growth_ratio,
                SOAK_MAX_GROWTH_RATIO,
                soak.oom_count,
                soak.crash_count,
                soak.unexplained_probe_failures,
                if soak.passed {
                    "PASS (fixture arithmetic)"
                } else {
                    "FAIL"
                }
            );
        }

        out.push_str("## 5. Restart Bounds & Recovery Lifecycle\n\n");
        out.push_str(
            "| Case ID | Name | Declared Bound | Observed Time | State Preserved | Result |\n",
        );
        out.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for rst in &self.restart_results {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} ms | {} | {} |",
                rst.id,
                rst.name,
                rst.declared_bound,
                rst.observed_duration_ms,
                if rst.state_preserved {
                    "SIMULATED"
                } else {
                    "NO"
                },
                if rst.passed {
                    "PASS (fixture arithmetic)"
                } else {
                    "FAIL"
                }
            );
        }

        out.push_str("\n## 6. Historical Regressions (REG-01 through REG-10)\n\n");
        out.push_str("| ID | Upstream Reference | Description | Declared Bound | Result |\n");
        out.push_str("| --- | --- | --- | --- | --- |\n");
        for reg in &self.historical_regressions {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} | NOT EXECUTED |",
                reg.id, reg.upstream_ref, reg.description, reg.declared_bound
            );
        }

        out.push_str("\n## 7. Per-Epic Regression Gates (E01 through E30)\n\n");
        out.push_str("| Epic | Gate | Name | Status | Summary |\n");
        out.push_str("| --- | --- | --- | --- | --- |\n");
        for epic in &self.epic_regressions {
            let _ = writeln!(
                out,
                "| `{}` | `{}` | {} | NOT EXECUTED | {} |",
                epic.epic, epic.qualification_gate, epic.name, epic.summary
            );
        }

        out
    }
}
