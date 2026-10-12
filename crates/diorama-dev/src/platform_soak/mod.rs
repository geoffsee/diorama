//! Platform coverage, candidate digest verification, and sustained-soak qualification.
//!
//! Provides exhaustive mapping of the accepted platform, runtime, variant, and container
//! matrix (Issue #120 / Gate C14 / E28.03), candidate digest matching against release
//! manifests, 24-hour sustained soak memory growth verification, clean/crash restart
//! bound checks, and historical/per-epic regression tracking.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::similar_names
)]

pub mod candidate;
pub mod matrix;
pub mod qualification;
pub mod regressions;
pub mod report;
pub mod restart;
pub mod runner;
pub mod soak;

pub use candidate::{CandidateArtifactRecord, CandidateVerificationSummary, ObservedArtifact};
pub use matrix::{
    DimensionCategory, EnvironmentMapping, EnvironmentRecord, EnvironmentResult,
    MatrixCompleteness, SupportStatus,
};
pub use qualification::{
    CRITERION_NUMBER, FULL_SOAK_DURATION_SECS, PlatformSoakQualificationReport,
    RECEIPT_FILENAME as SOAK_RECEIPT_FILENAME, REPORT_JSON_FILENAME as SOAK_REPORT_JSON_FILENAME,
    REPORT_MD_FILENAME as SOAK_REPORT_MD_FILENAME, SOAK_MAX_GROWTH_RATIO, capture_soak,
    sample_settled_rss, verify_soak_receipt, verify_soak_receipt_with_candidate,
};
pub use regressions::{EpicRegressionRecord, HistoricalRegression, RegressionSuite};
pub use report::{PlatformSoakError, PlatformSoakReport};
pub use restart::{RestartCase, RestartSummary};
pub use runner::PlatformSoakRunner;
pub use soak::{SustainedSoakRecord, SustainedSoakSummary};
