//! Roadmap #263 completion criteria and candidate-bound qualification evidence.
//!
//! Evaluates criteria satisfaction against validated candidate-bound receipts.
//! Receipts must match current candidate inventory, satisfy SHA-256 payload integrity,
//! report exit code 0 for all commands, verify passed assertions, justify all skips,
//! and confirm complete cleanup with no leaked resources.

use crate::Result;
use crate::release_qualification::receipt::{self, DEFAULT_RECEIPTS_DIR};
use std::path::{Path, PathBuf};

/// Status and evidence report for one Roadmap #263 completion criterion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriterionStatus {
    pub number: usize,
    pub name: &'static str,
    pub satisfied: bool,
    pub summary: String,
}

/// Computes the standardized receipt filename for a criterion.
pub fn receipt_filename(number: usize, slug: &str) -> String {
    format!("criterion-{number:02}-{slug}.json")
}

/// Resolves the qualification receipts directory with optional candidate directory.
pub fn receipts_dir_with_candidate(root: &Path, candidate_dir: Option<&Path>) -> PathBuf {
    if let Some(dir) = std::env::var_os("DIORAMA_RECEIPTS_DIR") {
        PathBuf::from(dir)
    } else if let Some(candidate) = candidate_dir {
        let candidate_path = if candidate.is_absolute() || candidate.exists() {
            candidate.to_path_buf()
        } else {
            root.join(candidate)
        };
        if candidate_path.join("receipts").is_dir() {
            candidate_path.join("receipts")
        } else {
            candidate_path
        }
    } else if root.join("receipts").is_dir() {
        root.join("receipts")
    } else {
        root.join(DEFAULT_RECEIPTS_DIR)
    }
}

/// Resolves the qualification receipts directory.
pub fn receipts_dir(root: &Path) -> PathBuf {
    receipts_dir_with_candidate(root, None)
}

/// Resolves the candidate receipt path for a specific criterion with optional candidate directory.
pub fn resolve_receipt_path_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
    number: usize,
    slug: &str,
) -> PathBuf {
    if let Some(path) = std::env::var_os(format!("DIORAMA_RECEIPT_PATH_{number}")) {
        PathBuf::from(path)
    } else {
        receipts_dir_with_candidate(root, candidate_dir).join(receipt_filename(number, slug))
    }
}

/// Resolves the candidate receipt path for a specific criterion.
pub fn resolve_receipt_path(root: &Path, number: usize, slug: &str) -> PathBuf {
    resolve_receipt_path_with_candidate(root, None, number, slug)
}

/// Evaluates a completion criterion against its candidate-bound qualification receipt with optional candidate directory.
pub fn evaluate_criterion_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
    number: usize,
    name: &'static str,
    slug: &'static str,
    fallback_evidence: &'static str,
) -> Result<CriterionStatus> {
    let receipt_path = resolve_receipt_path_with_candidate(root, candidate_dir, number, slug);
    let filename = receipt_path
        .file_name()
        .and_then(|n| n.to_str())
        .map_or_else(|| receipt_filename(number, slug), String::from);

    if !receipt_path.exists() {
        return Ok(CriterionStatus {
            number,
            name,
            satisfied: false,
            summary: format!(
                "Pending: missing receipt '{filename}'; {fallback_evidence}; \
                 validated current candidate-bound receipts unavailable"
            ),
        });
    }

    match receipt::load_and_validate_receipt_with_candidate(
        &receipt_path,
        root,
        candidate_dir,
        number,
    ) {
        Ok(valid_receipt) => Ok(CriterionStatus {
            number,
            name,
            satisfied: true,
            summary: format!(
                "Satisfied: validated candidate-bound receipt '{filename}' ({})",
                valid_receipt.description
            ),
        }),
        Err(err) => Ok(CriterionStatus {
            number,
            name,
            satisfied: false,
            summary: format!(
                "Pending: unqualified receipt '{filename}': {err}; \
                 validated current candidate-bound receipts unavailable"
            ),
        }),
    }
}

/// Evaluates a completion criterion against its candidate-bound qualification receipt.
pub fn evaluate_criterion(
    root: &Path,
    number: usize,
    name: &'static str,
    slug: &'static str,
    fallback_evidence: &'static str,
) -> Result<CriterionStatus> {
    evaluate_criterion_with_candidate(root, None, number, name, slug, fallback_evidence)
}

/// Evaluates Epic Ledgers Audit (E01–E30) with optional candidate directory.
pub fn check_criterion_1_epic_ledgers_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CriterionStatus> {
    evaluate_criterion_with_candidate(
        root,
        candidate_dir,
        1,
        "Epic Ledgers Audit (E01–E30)",
        "epic-ledgers",
        "independent evidence for every required deliverable",
    )
}

/// Evaluates Epic Ledgers Audit (E01–E30).
pub fn check_criterion_1_epic_ledgers(root: &Path) -> Result<CriterionStatus> {
    check_criterion_1_epic_ledgers_with_candidate(root, None)
}

/// Evaluates production component-boundary and datastore mTLS qualification evidence with optional candidate directory.
pub fn check_criterion_2_supervised_boundary_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CriterionStatus> {
    evaluate_criterion_with_candidate(
        root,
        candidate_dir,
        2,
        "Supervised Boundary & Datastore mTLS",
        "supervised-boundary",
        "production startup and positive/negative live transport checks",
    )
}

/// Evaluates production component-boundary and datastore mTLS qualification evidence.
pub fn check_criterion_2_supervised_boundary(root: &Path) -> Result<CriterionStatus> {
    check_criterion_2_supervised_boundary_with_candidate(root, None)
}

/// Evaluates target architecture matrix qualification evidence with optional candidate directory.
pub fn check_criterion_3_target_matrix_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CriterionStatus> {
    evaluate_criterion_with_candidate(
        root,
        candidate_dir,
        3,
        "Target Architecture Matrix",
        "target-matrix",
        "16 node cells, four OCI architectures and four management targets",
    )
}

/// Evaluates target architecture matrix qualification evidence.
pub fn check_criterion_3_target_matrix(root: &Path) -> Result<CriterionStatus> {
    check_criterion_3_target_matrix_with_candidate(root, None)
}

/// Evaluates live addon, egress and authentication qualification evidence with optional candidate directory.
pub fn check_criterion_4_addons_and_egress_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CriterionStatus> {
    evaluate_criterion_with_candidate(
        root,
        candidate_dir,
        4,
        "Addons, Egress & D2K Authentication",
        "addons-and-egress",
        "egress-denied image acquisition and positive/negative D2K authentication",
    )
}

/// Evaluates live addon, egress and authentication qualification evidence.
pub fn check_criterion_4_addons_and_egress(root: &Path) -> Result<CriterionStatus> {
    check_criterion_4_addons_and_egress_with_candidate(root, None)
}

/// Evaluates host/container lifecycle and state retention qualification evidence with optional candidate directory.
pub fn check_criterion_5_lifecycle_and_storage_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CriterionStatus> {
    let slug = "lifecycle-and-storage";
    let receipt_path = resolve_receipt_path_with_candidate(root, candidate_dir, 5, slug);
    let filename = receipt_path
        .file_name()
        .and_then(|n| n.to_str())
        .map_or_else(|| receipt_filename(5, slug), String::from);

    if !receipt_path.exists() {
        return Ok(CriterionStatus {
            number: 5,
            name: "Lifecycle & State Retention",
            satisfied: false,
            summary: format!(
                "Pending: missing receipt '{filename}'; install, reboot, recreate, interruption and retention matrices; \
                 validated current candidate-bound receipts unavailable"
            ),
        });
    }

    match crate::recovery_rehearsal::verify_recovery_receipt_with_candidate(
        &receipt_path,
        root,
        candidate_dir,
    ) {
        Ok(valid_receipt) => Ok(CriterionStatus {
            number: 5,
            name: "Lifecycle & State Retention",
            satisfied: true,
            summary: format!(
                "Satisfied: validated candidate-bound receipt '{filename}' ({})",
                valid_receipt.description
            ),
        }),
        Err(err) => Ok(CriterionStatus {
            number: 5,
            name: "Lifecycle & State Retention",
            satisfied: false,
            summary: format!(
                "Pending: unqualified receipt '{filename}': {err}; \
                 validated current candidate-bound receipts unavailable"
            ),
        }),
    }
}

/// Evaluates host/container lifecycle and state retention qualification evidence.
pub fn check_criterion_5_lifecycle_and_storage(root: &Path) -> Result<CriterionStatus> {
    check_criterion_5_lifecycle_and_storage_with_candidate(root, None)
}

/// Evaluates live conformance, recovery and soak qualification evidence with optional candidate directory.
pub fn check_criterion_6_conformance_and_soak_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CriterionStatus> {
    let slug = "conformance-and-soak";
    let receipt_path = resolve_receipt_path_with_candidate(root, candidate_dir, 6, slug);
    let filename = receipt_path
        .file_name()
        .and_then(|n| n.to_str())
        .map_or_else(|| receipt_filename(6, slug), String::from);

    if !receipt_path.exists() {
        return Ok(CriterionStatus {
            number: 6,
            name: "Conformance & Recovery Qualification",
            satisfied: false,
            summary: format!(
                "Pending: missing receipt '{filename}'; fresh live conformance, restart and platform soak results; \
                 validated current candidate-bound receipts unavailable"
            ),
        });
    }

    match crate::platform_soak::verify_soak_receipt_with_candidate(
        &receipt_path,
        root,
        candidate_dir,
    ) {
        Ok(valid_receipt) => Ok(CriterionStatus {
            number: 6,
            name: "Conformance & Recovery Qualification",
            satisfied: true,
            summary: format!(
                "Satisfied: validated candidate-bound receipt '{filename}' ({})",
                valid_receipt.description
            ),
        }),
        Err(err) => Ok(CriterionStatus {
            number: 6,
            name: "Conformance & Recovery Qualification",
            satisfied: false,
            summary: format!(
                "Pending: unqualified receipt '{filename}': {err}; \
                 validated current candidate-bound receipts unavailable"
            ),
        }),
    }
}

/// Evaluates live conformance, recovery and soak qualification evidence.
pub fn check_criterion_6_conformance_and_soak(root: &Path) -> Result<CriterionStatus> {
    check_criterion_6_conformance_and_soak_with_candidate(root, None)
}

/// Evaluates live performance and memory budgets qualification evidence with optional candidate directory.
pub fn check_criterion_7_performance_budgets_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CriterionStatus> {
    evaluate_criterion_with_candidate(
        root,
        candidate_dir,
        7,
        "Performance & Memory Budgets",
        "performance-budgets",
        "matched live amd64/arm64 budgets, 24-hour settled memory and shutdown",
    )
}

/// Evaluates live performance and memory budgets qualification evidence.
pub fn check_criterion_7_performance_budgets(root: &Path) -> Result<CriterionStatus> {
    check_criterion_7_performance_budgets_with_candidate(root, None)
}

/// Evaluates Go-to-Rust state migration and recovery rehearsal qualification evidence with optional candidate directory.
pub fn check_criterion_8_state_migration_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CriterionStatus> {
    evaluate_criterion_with_candidate(
        root,
        candidate_dir,
        8,
        "Go-to-Rust Migration & Recovery Rehearsal",
        "state-migration",
        "supported-version live migration and interrupted recovery",
    )
}

/// Evaluates Go-to-Rust state migration and recovery rehearsal qualification evidence.
pub fn check_criterion_8_state_migration(root: &Path) -> Result<CriterionStatus> {
    check_criterion_8_state_migration_with_candidate(root, None)
}

/// Evaluates language policy and final CI toolchain compliance qualification evidence with optional candidate directory.
pub fn check_criterion_9_language_and_policy_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CriterionStatus> {
    evaluate_criterion_with_candidate(
        root,
        candidate_dir,
        9,
        "Language Policy & Toolchain Compliance",
        "language-and-policy",
        "final source/artifact debug, release, audit, drift and integration checks",
    )
}

/// Evaluates language policy and final CI toolchain compliance qualification evidence.
pub fn check_criterion_9_language_and_policy(root: &Path) -> Result<CriterionStatus> {
    check_criterion_9_language_and_policy_with_candidate(root, None)
}

/// Evaluates cryptographic artifact digest bindings and provenance qualification evidence with optional candidate directory.
pub fn check_criterion_10_artifact_digest_bindings_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CriterionStatus> {
    evaluate_criterion_with_candidate(
        root,
        candidate_dir,
        10,
        "Cryptographic Digest Bindings & Provenance",
        "artifact-digest-bindings",
        "actual prepared inputs, complete candidate inventory \
         and all qualification report bindings",
    )
}

/// Evaluates cryptographic artifact digest bindings and provenance qualification evidence.
pub fn check_criterion_10_artifact_digest_bindings(root: &Path) -> Result<CriterionStatus> {
    check_criterion_10_artifact_digest_bindings_with_candidate(root, None)
}

/// Evaluates operator handoff rehearsal and release publication qualification evidence with optional candidate directory.
pub fn check_criterion_11_operator_handoff_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CriterionStatus> {
    let slug = "operator-handoff";
    let receipt_path = resolve_receipt_path_with_candidate(root, candidate_dir, 11, slug);
    let filename = receipt_path
        .file_name()
        .and_then(|n| n.to_str())
        .map_or_else(|| receipt_filename(11, slug), String::from);

    if !receipt_path.exists() {
        return Ok(CriterionStatus {
            number: 11,
            name: "Operator Documentation & Release Qualification",
            satisfied: false,
            summary: format!(
                "Pending: missing receipt '{filename}'; fresh operator rehearsal, exact artifacts and trusted publication; \
                 validated current candidate-bound receipts unavailable"
            ),
        });
    }

    match crate::operator_rehearsal::verify_operator_rehearsal_receipt(&receipt_path, root) {
        Ok(valid_receipt) => Ok(CriterionStatus {
            number: 11,
            name: "Operator Documentation & Release Qualification",
            satisfied: true,
            summary: format!(
                "Satisfied: validated candidate-bound receipt '{filename}' ({})",
                valid_receipt.description
            ),
        }),
        Err(e) => Ok(CriterionStatus {
            number: 11,
            name: "Operator Documentation & Release Qualification",
            satisfied: false,
            summary: format!("Rejected: {filename} failed candidate verification ({e})"),
        }),
    }
}

/// Evaluates operator handoff rehearsal and release publication qualification evidence.
pub fn check_criterion_11_operator_handoff(root: &Path) -> Result<CriterionStatus> {
    check_criterion_11_operator_handoff_with_candidate(root, None)
}

/// Reports all 11 criteria evaluated against candidate-bound receipts with optional candidate directory.
pub fn verify_all_criteria_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<Vec<CriterionStatus>> {
    Ok(vec![
        check_criterion_1_epic_ledgers_with_candidate(root, candidate_dir)?,
        check_criterion_2_supervised_boundary_with_candidate(root, candidate_dir)?,
        check_criterion_3_target_matrix_with_candidate(root, candidate_dir)?,
        check_criterion_4_addons_and_egress_with_candidate(root, candidate_dir)?,
        check_criterion_5_lifecycle_and_storage_with_candidate(root, candidate_dir)?,
        check_criterion_6_conformance_and_soak_with_candidate(root, candidate_dir)?,
        check_criterion_7_performance_budgets_with_candidate(root, candidate_dir)?,
        check_criterion_8_state_migration_with_candidate(root, candidate_dir)?,
        check_criterion_9_language_and_policy_with_candidate(root, candidate_dir)?,
        check_criterion_10_artifact_digest_bindings_with_candidate(root, candidate_dir)?,
        check_criterion_11_operator_handoff_with_candidate(root, candidate_dir)?,
    ])
}

/// Reports all 11 criteria evaluated against candidate-bound receipts.
pub fn verify_all_criteria(root: &Path) -> Result<Vec<CriterionStatus>> {
    verify_all_criteria_with_candidate(root, None)
}
