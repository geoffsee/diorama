//! Explicitly unqualified fixture evidence; production verification fails closed.
use crate::{
    Result,
    conformance::{QualificationReport, QualificationRunner},
    perf::{GateEvaluationReport, PerformanceReport, load_report},
    platform_soak::PlatformSoakReport,
    provenance::LicenseInventory,
    release::{
        attribution::{AttributionRecord, verify_attribution_completeness},
        cell_build::{
            CellInventory, CleanupReceipt, verify_cell_inventory, verify_cleanup_receipt,
        },
        manifest::{assemble_checksum_manifest, sha256_hex, verify_checksum_inventory},
        notes::ReleaseNotes,
    },
    release_qualification::receipt::CandidateReceipt,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
const STATUS: &str = "UNQUALIFIED_FIXTURE_ONLY";
const FIXTURE_README: &str = "# Release fixture diagnostics\n\nUNQUALIFIED_FIXTURE_ONLY. C13/C14/C16/C17 remain pending. No release archives or management binaries are fabricated or bound here; no OCI artifact hashes are synthesized. Performance sources are synthetic observations, conformance is in-process, and no live state transition or downtime was observed. License records are inventory drafts, not a legal compliance certification.\n\nVerify diagnostic consistency with `cargo run --locked -p diorama-dev --bin diorama-release -- verify-fixtures docs/release`. Production `verify` always fails closed until a verified current-source live evidence importer exists.\n";
const SOURCES: [&str; 4] = [
    "amd64-reference-go.json",
    "amd64-candidate-rust.json",
    "arm64-reference-go.json",
    "arm64-candidate-rust.json",
];
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerfQualificationDocument {
    pub schema_version: u32,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_integrity_hash: Option<String>,
    pub amd64_evaluation: GateEvaluationReport,
    pub arm64_evaluation: GateEvaluationReport,
}
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateEvidence {
    pub schema_version: u32,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_integrity_hash: Option<String>,
    pub observed_transitions: Vec<String>,
    pub qualified: bool,
    pub note: String,
}
fn state_unobserved() -> StateEvidence {
    StateEvidence {
        schema_version: 2,
        status: STATUS.into(),
        receipt_id: None,
        receipt_integrity_hash: None,
        observed_transitions: vec![],
        qualified: false,
        note: "No live retained-node/Kine transition, PKI/PV reconciliation or downtime measurement was executed. C16/C17 remain pending; rehearsal fixtures are not production migration evidence.".into(),
    }
}
fn metadata(root: &Path) -> Result<String> {
    let output = Command::new("cargo")
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?)
}
fn performance(dir: &Path) -> Result<PerfQualificationDocument> {
    let reports = SOURCES
        .iter()
        .map(|name| load_report(&dir.join(name)))
        .collect::<Result<Vec<PerformanceReport>>>()?;
    for report in &reports {
        crate::perf::validation::validate_report(report)?;
    }
    let amd64_evaluation = GateEvaluationReport::evaluate(&reports[0], &reports[1]);
    let arm64_evaluation = GateEvaluationReport::evaluate(&reports[2], &reports[3]);
    if reports[0].architecture != crate::perf::Architecture::Amd64
        || reports[2].architecture != crate::perf::Architecture::Arm64
        || !amd64_evaluation.arithmetic_all_passed()
        || !arm64_evaluation.arithmetic_all_passed()
    {
        return Err("invalid paired fixture performance observations".into());
    }
    Ok(PerfQualificationDocument {
        schema_version: 2,
        status: STATUS.into(),
        receipt_id: None,
        receipt_integrity_hash: None,
        amd64_evaluation,
        arm64_evaluation,
    })
}
/// Resolves an artifact name to an existing path within the release directory.
pub fn resolve_artifact_path(dir: &Path, name: &str) -> Option<PathBuf> {
    let direct = dir.join(name);
    if direct.is_file() {
        return Some(direct);
    }
    if let Some(stripped) = name.strip_prefix("docs/release/") {
        let p = dir.join(stripped);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Some(stripped) = name.strip_prefix("bin/") {
        let p = dir.join(stripped);
        if p.is_file() {
            return Some(p);
        }
    }
    let in_bin = dir.join("bin").join(name);
    if in_bin.is_file() {
        return Some(in_bin);
    }
    if let Some(file_name) = Path::new(name).file_name() {
        let p = dir.join(file_name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Discovers candidate receipt path for a given criterion number and slug.
pub fn find_receipt_path(dir: &Path, number: usize, slug: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var(format!("DIORAMA_RECEIPT_PATH_{number}")) {
        let p = PathBuf::from(path);
        if p.is_file() {
            return Some(p);
        }
    }
    let filename = crate::release_qualification::criteria::receipt_filename(number, slug);
    let candidates = [
        dir.join("receipts").join(&filename),
        dir.join(&filename),
        dir.join("docs/release/receipts").join(&filename),
        crate::release_qualification::criteria::resolve_receipt_path(dir, number, slug),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

/// Discovers candidate receipt path for release verification, restricted strictly to `dir/receipts` without environment overrides.
pub fn find_verification_receipt_path(dir: &Path, number: usize, slug: &str) -> Option<PathBuf> {
    let filename = crate::release_qualification::criteria::receipt_filename(number, slug);
    let path = dir.join("receipts").join(filename);
    if path.is_file() { Some(path) } else { None }
}

/// Verifies that candidate artifacts present on disk match candidate digest bindings in the receipt.
pub fn verify_report_candidate_digests(
    report_name: &str,
    receipt: &CandidateReceipt,
    dir: &Path,
) -> Result<()> {
    for (name, expected_digest) in receipt
        .candidate
        .binary_digests
        .iter()
        .chain(receipt.candidate.payload_digests.iter())
    {
        let path = resolve_artifact_path(dir, name).ok_or_else(|| {
            format!(
                "candidate artifact '{name}' bound in {report_name} receipt not found in release directory"
            )
        })?;
        let bytes = fs::read(&path)?;
        let observed = sha256_hex(&bytes);
        if &observed != expected_digest {
            return Err(format!(
                "digest mismatch in {report_name} for '{name}': expected '{expected_digest}', observed '{observed}'"
            )
            .into());
        }
    }
    Ok(())
}

/// Regenerates release qualification reports bound to validated candidate receipts.
#[allow(clippy::too_many_lines)]
pub async fn regenerate_release_reports(root: &Path, dir: &Path) -> Result<()> {
    let r6_path = find_receipt_path(dir, 6, "conformance-and-soak")
        .or_else(|| find_receipt_path(root, 6, "conformance-and-soak"))
        .ok_or("candidate qualification receipt for criterion 6 not found")?;
    let r7_path = find_receipt_path(dir, 7, "performance-budgets")
        .or_else(|| find_receipt_path(root, 7, "performance-budgets"))
        .ok_or("candidate qualification receipt for criterion 7 not found")?;
    let r8_path = find_receipt_path(dir, 8, "state-migration")
        .or_else(|| find_receipt_path(root, 8, "state-migration"))
        .ok_or("candidate qualification receipt for criterion 8 not found")?;
    let r10_path = find_receipt_path(dir, 10, "artifact-digest-bindings")
        .or_else(|| find_receipt_path(root, 10, "artifact-digest-bindings"))
        .ok_or("candidate qualification receipt for criterion 10 not found")?;

    let r6 = crate::release_qualification::receipt::load_receipt_from_path(&r6_path)?;
    let r7 = crate::release_qualification::receipt::load_receipt_from_path(&r7_path)?;
    let r8 = crate::release_qualification::receipt::load_receipt_from_path(&r8_path)?;
    let r10 = crate::release_qualification::receipt::load_receipt_from_path(&r10_path)?;

    let inventory = crate::release_qualification::receipt::load_candidate_inventory(dir)
        .or_else(|_| crate::release_qualification::receipt::load_candidate_inventory(root))?;

    crate::release_qualification::receipt::validate_candidate_receipt(&r6, &inventory, 6)?;
    crate::release_qualification::receipt::validate_candidate_receipt(&r7, &inventory, 7)?;
    crate::release_qualification::receipt::validate_candidate_receipt(&r8, &inventory, 8)?;
    crate::release_qualification::receipt::validate_candidate_receipt(&r10, &inventory, 10)?;

    verify_report_candidate_digests("conformance", &r6, dir)?;
    verify_report_candidate_digests("soak", &r6, dir)?;
    verify_report_candidate_digests("performance", &r7, dir)?;
    verify_report_candidate_digests("state transition", &r8, dir)?;
    verify_report_candidate_digests("attribution", &r10, dir)?;

    // Ensure receipts are present in dir/receipts
    let target_receipts = dir.join("receipts");
    fs::create_dir_all(&target_receipts)?;
    for src in [&r6_path, &r7_path, &r8_path, &r10_path] {
        let filename = src.file_name().ok_or("invalid receipt filename")?;
        let dest = target_receipts.join(filename);
        if src != &dest {
            fs::copy(src, dest)?;
        }
    }

    // 1. Conformance
    let conf_path = dir.join("conformance-qualification-report.json");
    if !conf_path.is_file() {
        return Err(
            "cannot regenerate release reports: backing conformance qualification report is absent"
                .into(),
        );
    }
    let mut conformance: QualificationReport = serde_json::from_slice(&fs::read(&conf_path)?)?;
    if conformance.evidence_kind == "synthetic_fixture" {
        return Err("cannot regenerate release reports: backing conformance report is synthetic fixture evidence".into());
    }
    if conformance.evidence_kind != "candidate_receipt_bound" {
        return Err("cannot regenerate release reports: backing conformance report is not candidate_receipt_bound".into());
    }
    conformance.receipt_id = Some(crate::release_qualification::criteria::receipt_filename(
        6,
        "conformance-and-soak",
    ));
    conformance.receipt_integrity_hash = Some(r6.integrity_hash.clone());
    conformance
        .verify_qualification()
        .map_err(|e| format!("conformance qualification verification failed: {e}"))?;
    fs::write(
        dir.join("conformance-qualification-report.json"),
        conformance.to_json()?,
    )?;
    fs::write(
        dir.join("conformance-qualification-report.md"),
        conformance.to_markdown(),
    )?;

    // 2. Platform Soak
    let soak_path = dir.join("platform-soak-report.json");
    if !soak_path.is_file() {
        return Err(
            "cannot regenerate release reports: backing platform soak report is absent".into(),
        );
    }
    let mut soak: PlatformSoakReport = serde_json::from_slice(&fs::read(&soak_path)?)?;
    if soak.evidence_kind == "SyntheticFixture" || !soak.overall_qualified {
        return Err("cannot regenerate release reports: backing platform soak report is synthetic fixture evidence".into());
    }
    if soak.evidence_kind != "CandidateReceiptBound"
        && soak.evidence_kind != "candidate_receipt_bound"
    {
        return Err("cannot regenerate release reports: backing platform soak report is not CandidateReceiptBound".into());
    }
    soak.receipt_id = Some(crate::release_qualification::criteria::receipt_filename(
        6,
        "conformance-and-soak",
    ));
    soak.receipt_integrity_hash = Some(r6.integrity_hash.clone());
    soak.validate(None)
        .map_err(|e| format!("platform soak report validation failed: {e}"))?;
    fs::write(
        dir.join("platform-soak-report.json"),
        serde_json::to_vec_pretty(&soak)?,
    )?;
    fs::write(dir.join("platform-soak-report.md"), soak.to_markdown())?;

    // 3. Performance
    for name in SOURCES {
        if !dir.join(name).is_file() {
            return Err(format!("cannot regenerate release reports: performance observation source report '{name}' is absent").into());
        }
    }
    let perf_path = dir.join("performance-qualification-report.json");
    if !perf_path.is_file() {
        return Err(
            "cannot regenerate release reports: backing performance qualification report is absent"
                .into(),
        );
    }
    let existing_perf: PerfQualificationDocument = serde_json::from_slice(&fs::read(&perf_path)?)?;
    if existing_perf.status == STATUS {
        return Err("cannot regenerate release reports: backing performance report is synthetic fixture evidence".into());
    }
    let mut perf = performance(dir)?;
    perf.status = "CANDIDATE_RECEIPT_BOUND".into();
    perf.receipt_id = Some(crate::release_qualification::criteria::receipt_filename(
        7,
        "performance-budgets",
    ));
    perf.receipt_integrity_hash = Some(r7.integrity_hash.clone());
    fs::write(perf_path, serde_json::to_vec_pretty(&perf)?)?;

    // 4. State Transition
    let state_path = dir.join("state-transition-qualification-report.json");
    if !state_path.is_file() {
        return Err("cannot regenerate release reports: backing state transition qualification report is absent".into());
    }
    let existing_state: StateEvidence = serde_json::from_slice(&fs::read(&state_path)?)?;
    if existing_state.status == STATUS || !existing_state.qualified {
        return Err("cannot regenerate release reports: backing state transition report is synthetic fixture evidence".into());
    }
    let observed_transitions: Vec<String> = r8
        .assertions
        .iter()
        .filter(|a| a.passed)
        .map(|a| a.name.clone())
        .collect();
    if observed_transitions.is_empty() || !r8.assertions.iter().all(|a| a.passed) {
        return Err("cannot regenerate state transition report: criterion 8 receipt assertions do not qualify".into());
    }
    let state = StateEvidence {
        schema_version: 2,
        status: "CANDIDATE_RECEIPT_BOUND".into(),
        receipt_id: Some(crate::release_qualification::criteria::receipt_filename(
            8,
            "state-migration",
        )),
        receipt_integrity_hash: Some(r8.integrity_hash.clone()),
        observed_transitions,
        qualified: true,
        note: "Production Go-to-Rust state migration, Kine transition and interrupted recovery qualified via candidate receipt.".into(),
    };
    fs::write(state_path, serde_json::to_vec_pretty(&state)?)?;

    // 5. Attribution
    let licenses_path = dir.join("licenses.json");
    if !licenses_path.is_file() {
        return Err(
            "cannot regenerate release reports: backing licenses inventory is absent".into(),
        );
    }
    let mut attribution = AttributionRecord::build(&metadata(root)?)?;
    verify_attribution_completeness(&attribution)?;
    attribution.receipt_id = Some(crate::release_qualification::criteria::receipt_filename(
        10,
        "artifact-digest-bindings",
    ));
    attribution.receipt_integrity_hash = Some(r10.integrity_hash.clone());
    fs::write(
        licenses_path,
        serde_json::to_vec_pretty(&attribution.to_license_inventory())?,
    )?;
    fs::write(dir.join("attribution.md"), attribution.to_markdown())?;

    Ok(())
}

/// Production assembly requires validated candidate qualification receipts.
pub async fn assemble_release_evidence(root: &Path, target: &Path) -> Result<()> {
    let r6_path = find_receipt_path(target, 6, "conformance-and-soak")
        .or_else(|| find_receipt_path(root, 6, "conformance-and-soak"));
    let r7_path = find_receipt_path(target, 7, "performance-budgets")
        .or_else(|| find_receipt_path(root, 7, "performance-budgets"));
    let r8_path = find_receipt_path(target, 8, "state-migration")
        .or_else(|| find_receipt_path(root, 8, "state-migration"));
    let r10_path = find_receipt_path(target, 10, "artifact-digest-bindings")
        .or_else(|| find_receipt_path(root, 10, "artifact-digest-bindings"));

    if r6_path.is_none() || r7_path.is_none() || r8_path.is_none() || r10_path.is_none() {
        return Err("production release assembly unavailable: candidate qualification receipts for criteria 6, 7, 8, and 10 not found; C13/C14/C16/C17 remain pending".into());
    }

    fs::create_dir_all(target)?;

    let target_receipts = target.join("receipts");
    fs::create_dir_all(&target_receipts)?;
    for src in [&r6_path, &r7_path, &r8_path, &r10_path]
        .into_iter()
        .flatten()
    {
        let filename = src.file_name().ok_or("invalid receipt filename")?;
        let dst = target_receipts.join(filename);
        if src != &dst {
            fs::copy(src, dst)?;
        }
    }

    let inventory_source = root.join("docs/release/cell-inventory.json");
    if inventory_source.exists() && !target.join("cell-inventory.json").exists() {
        fs::copy(&inventory_source, target.join("cell-inventory.json"))?;
    }
    let cleanup_source = root.join("docs/release/cleanup-receipt.json");
    if cleanup_source.exists() && !target.join("cleanup-receipt.json").exists() {
        fs::copy(&cleanup_source, target.join("cleanup-receipt.json"))?;
    }
    let readme_source = root.join("docs/release/README.md");
    if readme_source.exists() && !target.join("README.md").exists() {
        fs::copy(&readme_source, target.join("README.md"))?;
    }
    fs::write(
        target.join("release-notes.md"),
        ReleaseNotes::build().to_markdown(),
    )?;

    regenerate_release_reports(root, target).await?;
    fs::write(
        target.join("SHA256SUMS"),
        assemble_checksum_manifest(target)?,
    )?;

    verify_release_evidence(target)
}
/// Materialize fixture diagnostics without fabricated package digests or transitions.
pub async fn assemble_fixture_evidence(root: &Path, target: &Path) -> Result<()> {
    if target.exists() && fs::read_dir(target)?.next().is_some() {
        return Err("fixture output must be empty".into());
    }
    fs::create_dir_all(target)?;
    for name in SOURCES {
        fs::copy(
            root.join("tools/perf/fixtures").join(name),
            target.join(name),
        )?;
    }
    let perf = performance(target)?;
    fs::write(
        target.join("performance-qualification-report.json"),
        serde_json::to_vec_pretty(&perf)?,
    )?;
    let conformance = QualificationRunner::new().run_fixture().await?;
    fs::write(
        target.join("conformance-qualification-report.json"),
        conformance.to_json()?,
    )?;
    fs::write(
        target.join("conformance-qualification-report.md"),
        conformance.to_markdown(),
    )?;
    fs::write(
        target.join("state-transition-qualification-report.json"),
        serde_json::to_vec_pretty(&state_unobserved())?,
    )?;
    let attribution = AttributionRecord::build(&metadata(root)?)?;
    verify_attribution_completeness(&attribution)?;
    fs::write(
        target.join("licenses.json"),
        serde_json::to_vec_pretty(&attribution.to_license_inventory())?,
    )?;
    fs::write(target.join("attribution.md"), attribution.to_markdown())?;
    fs::write(
        target.join("release-notes.md"),
        ReleaseNotes::build().to_markdown(),
    )?;
    fs::write(target.join("README.md"), FIXTURE_README)?;
    let inventory_source = root.join("docs/release/cell-inventory.json");
    if inventory_source.exists() {
        fs::copy(&inventory_source, target.join("cell-inventory.json"))?;
    }
    let cleanup_source = root.join("docs/release/cleanup-receipt.json");
    if cleanup_source.exists() {
        fs::copy(&cleanup_source, target.join("cleanup-receipt.json"))?;
    }
    fs::write(
        target.join("SHA256SUMS"),
        assemble_checksum_manifest(target)?,
    )?;
    verify_fixture_evidence(root, target)
}
/// Checks diagnostic integrity against raw observations and the current locked inventory.
pub fn verify_fixture_evidence(root: &Path, dir: &Path) -> Result<()> {
    verify_checksum_inventory(&fs::read_to_string(dir.join("SHA256SUMS"))?, dir)?;
    let expected_perf = performance(dir)?;
    // Compare the canonical rendered result to avoid accepting caller pass flags,
    // and avoid lossy JSON float parsing changing a recomputed threshold.
    if fs::read(dir.join("performance-qualification-report.json"))?
        != serde_json::to_vec_pretty(&expected_perf)?
    {
        return Err("performance evaluations disagree with recomputed source reports".into());
    }
    let conf: QualificationReport = serde_json::from_slice(&fs::read(
        dir.join("conformance-qualification-report.json"),
    )?)?;
    conf.verify_fixture()?;
    if fs::read_to_string(dir.join("conformance-qualification-report.md"))? != conf.to_markdown() {
        return Err("conformance text disagrees with fixture report".into());
    }
    let state: StateEvidence = serde_json::from_slice(&fs::read(
        dir.join("state-transition-qualification-report.json"),
    )?)?;
    if state != state_unobserved() {
        return Err("unobserved fixture must not claim successful state transitions".into());
    }
    let expected = AttributionRecord::build(&metadata(root)?)?;
    verify_attribution_completeness(&expected)?;
    let inventory: LicenseInventory =
        serde_json::from_slice(&fs::read(dir.join("licenses.json"))?)?;
    if inventory != expected.to_license_inventory()
        || fs::read_to_string(dir.join("attribution.md"))? != expected.to_markdown()
    {
        return Err(
            "published attribution does not match locked component/dependency inventory".into(),
        );
    }
    if fs::read_to_string(dir.join("release-notes.md"))? != ReleaseNotes::build().to_markdown() {
        return Err("release notes disagree with unqualified candidate disclosures".into());
    }
    if fs::read_to_string(dir.join("README.md"))? != FIXTURE_README {
        return Err("fixture overview must match canonical unqualified disclosures".into());
    }
    if dir.join("cell-inventory.json").exists() {
        let cell_inv: CellInventory =
            serde_json::from_slice(&fs::read(dir.join("cell-inventory.json"))?)?;
        verify_cell_inventory(&cell_inv)?;
    }
    if dir.join("cleanup-receipt.json").exists() {
        let cleanup: CleanupReceipt =
            serde_json::from_slice(&fs::read(dir.join("cleanup-receipt.json"))?)?;
        verify_cleanup_receipt(&cleanup)?;
    }
    verify_kubeconfig_dual_format_accommodation()
}
fn check_file_path_for_foreign_targets(
    path: &Path,
    dir: &Path,
    foreign_targets: &[String],
) -> Result<()> {
    let Ok(rel_path) = path.strip_prefix(dir) else {
        return Ok(());
    };
    let file_name_lower = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    for target in foreign_targets {
        let target_lower = target.to_ascii_lowercase();
        if file_name_lower == target_lower {
            return Err(format!(
                "unbuildable foreign target '{target}' must not exist in release directory"
            )
            .into());
        }
        let comp_matched = rel_path
            .components()
            .any(|comp| comp.as_os_str().to_string_lossy().to_ascii_lowercase() == target_lower);
        if comp_matched {
            return Err(format!(
                "unbuildable foreign target '{target}' must not exist in release directory"
            )
            .into());
        }
    }
    Ok(())
}

fn check_sums_line_for_foreign_targets(line: &str, foreign_targets: &[String]) -> Result<()> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let entry_path = if trimmed.len() > 66
        && (trimmed.as_bytes()[64] == b' ' || trimmed.as_bytes()[64] == b'*')
    {
        trimmed[65..].trim_start()
    } else {
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            return Ok(());
        }
        parts[1]
    };

    let normalized = entry_path.replace('\\', "/");
    let clean_path = normalized.strip_prefix("./").unwrap_or(&normalized);

    for target in foreign_targets {
        let target_lower = target.to_ascii_lowercase();
        if clean_path.to_ascii_lowercase() == target_lower {
            return Err(format!(
                "unbuildable foreign target '{target}' must not appear in SHA256SUMS"
            )
            .into());
        }
        let comp_matched = clean_path
            .split('/')
            .any(|comp| comp.trim().to_ascii_lowercase() == target_lower);
        if comp_matched {
            return Err(format!(
                "unbuildable foreign target '{target}' must not appear in SHA256SUMS"
            )
            .into());
        }
    }
    Ok(())
}

fn verify_foreign_cell_targets(dir: &Path, cell_inv: &CellInventory) -> Result<()> {
    let foreign_targets: Vec<String> = cell_inv
        .node_cells
        .iter()
        .chain(cell_inv.management_targets.iter())
        .filter(|t| t.status == "unbuildable_foreign_target")
        .map(|t| t.target_name.clone())
        .collect();

    if foreign_targets.is_empty() {
        return Ok(());
    }

    // 1. Walk entire release directory recursively (symlink-safe, do NOT follow symlinks)
    let mut dirs_to_visit = vec![dir.to_path_buf()];
    while let Some(current_dir) = dirs_to_visit.pop() {
        for entry in fs::read_dir(&current_dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;

            check_file_path_for_foreign_targets(&path, dir, &foreign_targets)?;

            // Recurse into directories (but do NOT follow symlinks)
            if file_type.is_dir() && !file_type.is_symlink() {
                dirs_to_visit.push(path);
            }
        }
    }

    // 2. Parse SHA256SUMS entries properly (normalized path components, not .ends_with string matching)
    let sums_path = dir.join("SHA256SUMS");
    if sums_path.is_file() {
        let sums_text = fs::read_to_string(&sums_path)?;
        for line in sums_text.lines() {
            check_sums_line_for_foreign_targets(line, &foreign_targets)?;
        }
    }

    Ok(())
}

/// Release evidence verification fails closed unless bound to validated candidate receipts.
#[allow(clippy::too_many_lines)]
pub fn verify_release_evidence(dir: &Path) -> Result<()> {
    if !dir.join("cell-inventory.json").is_file() {
        return Err("missing cell-inventory.json in release directory".into());
    }
    let cell_inv: CellInventory =
        serde_json::from_slice(&fs::read(dir.join("cell-inventory.json"))?)?;
    verify_cell_inventory(&cell_inv)?;
    verify_foreign_cell_targets(dir, &cell_inv)?;

    if dir.join("cleanup-receipt.json").exists() {
        let cleanup: CleanupReceipt =
            serde_json::from_slice(&fs::read(dir.join("cleanup-receipt.json"))?)?;
        verify_cleanup_receipt(&cleanup)?;
    }

    if !dir.join("SHA256SUMS").is_file() {
        return Err("missing SHA256SUMS in release directory".into());
    }
    verify_checksum_inventory(&fs::read_to_string(dir.join("SHA256SUMS"))?, dir)?;
    verify_kubeconfig_dual_format_accommodation()?;

    for name in SOURCES {
        if !dir.join(name).is_file() {
            return Err(format!(
                "missing performance evaluation source input '{name}' in release directory"
            )
            .into());
        }
    }

    let r6_path = find_verification_receipt_path(dir, 6, "conformance-and-soak")
        .ok_or("production release qualification unavailable: candidate qualification receipts for criteria 6, 7, 8, and 10 not found; C13/C14/C16/C17 remain pending")?;
    let r7_path = find_verification_receipt_path(dir, 7, "performance-budgets")
        .ok_or("production release qualification unavailable: candidate qualification receipts for criteria 6, 7, 8, and 10 not found; C13/C14/C16/C17 remain pending")?;
    let r8_path = find_verification_receipt_path(dir, 8, "state-migration")
        .ok_or("production release qualification unavailable: candidate qualification receipts for criteria 6, 7, 8, and 10 not found; C13/C14/C16/C17 remain pending")?;
    let r10_path = find_verification_receipt_path(dir, 10, "artifact-digest-bindings")
        .ok_or("production release qualification unavailable: candidate qualification receipts for criteria 6, 7, 8, and 10 not found; C13/C14/C16/C17 remain pending")?;

    let r6 = crate::release_qualification::receipt::load_receipt_from_path(&r6_path)?;
    let r7 = crate::release_qualification::receipt::load_receipt_from_path(&r7_path)?;
    let r8 = crate::release_qualification::receipt::load_receipt_from_path(&r8_path)?;
    let r10 = crate::release_qualification::receipt::load_receipt_from_path(&r10_path)?;

    let inventory =
        crate::release_qualification::receipt::load_candidate_inventory_from_release_dir(dir)?;

    crate::release_qualification::receipt::validate_candidate_receipt(&r6, &inventory, 6)?;
    crate::release_qualification::receipt::validate_candidate_receipt(&r7, &inventory, 7)?;
    crate::release_qualification::receipt::validate_candidate_receipt(&r8, &inventory, 8)?;
    crate::release_qualification::receipt::validate_candidate_receipt(&r10, &inventory, 10)?;

    verify_report_candidate_digests("conformance", &r6, dir)?;
    verify_report_candidate_digests("soak", &r6, dir)?;
    verify_report_candidate_digests("performance", &r7, dir)?;
    verify_report_candidate_digests("state transition", &r8, dir)?;
    verify_report_candidate_digests("attribution", &r10, dir)?;

    // 1. Conformance report
    let conf_path = dir.join("conformance-qualification-report.json");
    if !conf_path.is_file() {
        return Err("missing conformance-qualification-report.json".into());
    }
    let conf: QualificationReport = serde_json::from_slice(&fs::read(&conf_path)?)?;
    conf.verify_qualification()
        .map_err(|e| format!("conformance qualification verification failed: {e}"))?;
    if conf.evidence_kind != "candidate_receipt_bound" {
        return Err("conformance report evidence_kind must be candidate_receipt_bound".into());
    }
    if conf.receipt_id.as_deref()
        != Some(&crate::release_qualification::criteria::receipt_filename(
            6,
            "conformance-and-soak",
        ))
    {
        return Err("conformance report receipt_id mismatch".into());
    }
    if conf.receipt_integrity_hash.as_deref() != Some(&r6.integrity_hash) {
        return Err("conformance report receipt_integrity_hash mismatch".into());
    }
    if dir.join("conformance-qualification-report.md").is_file() {
        let conf_md = fs::read_to_string(dir.join("conformance-qualification-report.md"))?;
        if conf_md != conf.to_markdown() {
            return Err("conformance markdown text disagrees with qualification report".into());
        }
    }

    // 2. Platform soak report
    let soak_path = dir.join("platform-soak-report.json");
    if !soak_path.is_file() {
        return Err("missing platform-soak-report.json".into());
    }
    let soak: PlatformSoakReport = serde_json::from_slice(&fs::read(&soak_path)?)?;
    soak.validate_fixture(None)
        .map_err(|e| format!("platform soak report validation failed: {e}"))?;
    if !soak.overall_qualified {
        return Err("platform soak report overall_qualified must be true".into());
    }
    if soak.evidence_kind != "CandidateReceiptBound"
        && soak.evidence_kind != "candidate_receipt_bound"
    {
        return Err("platform soak report evidence_kind must be CandidateReceiptBound".into());
    }
    if soak.receipt_id.as_deref()
        != Some(&crate::release_qualification::criteria::receipt_filename(
            6,
            "conformance-and-soak",
        ))
    {
        return Err("platform soak report receipt_id mismatch".into());
    }
    if soak.receipt_integrity_hash.as_deref() != Some(&r6.integrity_hash) {
        return Err("platform soak report receipt_integrity_hash mismatch".into());
    }
    if dir.join("platform-soak-report.md").is_file() {
        let soak_md = fs::read_to_string(dir.join("platform-soak-report.md"))?;
        if soak_md != soak.to_markdown() {
            return Err("platform soak markdown text disagrees with report".into());
        }
    }

    // 3. Performance report
    let perf_path = dir.join("performance-qualification-report.json");
    if !perf_path.is_file() {
        return Err("missing performance-qualification-report.json".into());
    }
    let perf: PerfQualificationDocument = serde_json::from_slice(&fs::read(&perf_path)?)?;
    if perf.status != "CANDIDATE_RECEIPT_BOUND" {
        return Err("performance report status must be CANDIDATE_RECEIPT_BOUND".into());
    }
    if perf.receipt_id.as_deref()
        != Some(&crate::release_qualification::criteria::receipt_filename(
            7,
            "performance-budgets",
        ))
    {
        return Err("performance report receipt_id mismatch".into());
    }
    if perf.receipt_integrity_hash.as_deref() != Some(&r7.integrity_hash) {
        return Err("performance report receipt_integrity_hash mismatch".into());
    }
    if !perf.amd64_evaluation.arithmetic_all_passed()
        || !perf.arm64_evaluation.arithmetic_all_passed()
    {
        return Err("performance report evaluation gates did not pass".into());
    }
    let expected_raw = performance(dir)?;
    let expected_amd64: GateEvaluationReport =
        serde_json::from_slice(&serde_json::to_vec(&expected_raw.amd64_evaluation)?)?;
    let expected_arm64: GateEvaluationReport =
        serde_json::from_slice(&serde_json::to_vec(&expected_raw.arm64_evaluation)?)?;
    if perf.amd64_evaluation != expected_amd64 || perf.arm64_evaluation != expected_arm64 {
        return Err("performance evaluations disagree with recomputed source reports".into());
    }

    // 4. State transition report
    let state_path = dir.join("state-transition-qualification-report.json");
    if !state_path.is_file() {
        return Err("missing state-transition-qualification-report.json".into());
    }
    let state: StateEvidence = serde_json::from_slice(&fs::read(&state_path)?)?;
    if state.status != "CANDIDATE_RECEIPT_BOUND" || !state.qualified {
        return Err("state transition report must be CANDIDATE_RECEIPT_BOUND and qualified".into());
    }
    if state.receipt_id.as_deref()
        != Some(&crate::release_qualification::criteria::receipt_filename(
            8,
            "state-migration",
        ))
    {
        return Err("state transition report receipt_id mismatch".into());
    }
    if state.receipt_integrity_hash.as_deref() != Some(&r8.integrity_hash) {
        return Err("state transition report receipt_integrity_hash mismatch".into());
    }
    if state.observed_transitions.is_empty() {
        return Err("state transition report observed_transitions cannot be empty".into());
    }

    // 5. Attribution
    let licenses_path = dir.join("licenses.json");
    if !licenses_path.is_file() {
        return Err("missing licenses.json".into());
    }
    let inventory_lic: LicenseInventory = serde_json::from_slice(&fs::read(&licenses_path)?)?;
    if inventory_lic.receipt_id.as_deref()
        != Some(&crate::release_qualification::criteria::receipt_filename(
            10,
            "artifact-digest-bindings",
        ))
    {
        return Err("license inventory receipt_id mismatch".into());
    }
    if inventory_lic.receipt_integrity_hash.as_deref() != Some(&r10.integrity_hash) {
        return Err("license inventory receipt_integrity_hash mismatch".into());
    }
    if inventory_lic.rust_dependencies.is_empty() {
        return Err("license inventory rust_dependencies cannot be empty".into());
    }
    if dir.join("attribution.md").is_file() {
        let attr_md = fs::read_to_string(dir.join("attribution.md"))?;
        if !attr_md.contains("CANDIDATE_RECEIPT_BOUND") {
            return Err("attribution markdown must declare CANDIDATE_RECEIPT_BOUND".into());
        }
        if !attr_md.contains(&r10.integrity_hash) {
            return Err("attribution markdown must contain receipt integrity hash".into());
        }
    }

    if dir.join("release-notes.md").is_file() {
        let notes = fs::read_to_string(dir.join("release-notes.md"))?;
        if notes != ReleaseNotes::build().to_markdown() {
            return Err("release notes disagree with expected notes".into());
        }
    }

    Ok(())
}

/// Validate the kubeconfig parser's YAML and JSON accommodation without live claims.
pub fn verify_kubeconfig_dual_format_accommodation() -> Result<()> {
    let value = serde_json::json!({"apiVersion":"v1","kind":"Config","clusters":[{"name":"diorama","cluster":{"server":"https://127.0.0.1:6443","certificate-authority-data":"Y2E="}}],"users":[{"name":"admin","user":{"client-certificate-data":"Y2VydA==","client-key-data":"a2V5"}}],"contexts":[{"name":"admin","context":{"cluster":"diorama","user":"admin"}}],"current-context":"admin"});
    let json = serde_json::to_vec(&value)?;
    let yaml = b"apiVersion: v1\nkind: Config\nclusters:\n- name: diorama\n  cluster:\n    server: https://127.0.0.1:6443\n    certificate-authority-data: Y2E=\nusers:\n- name: admin\n  user:\n    client-certificate-data: Y2VydA==\n    client-key-data: a2V5\ncontexts:\n- name: admin\n  context:\n    cluster: diorama\n    user: admin\ncurrent-context: admin\n";
    let left = crate::state_transition::parse_kubeconfig(&json)?;
    let right = crate::state_transition::parse_kubeconfig(yaml)?;
    if left.server != right.server
        || left.cluster_name != right.cluster_name
        || left.user_name != right.user_name
        || left.current_context != right.current_context
        || left.ca_cert_bytes != right.ca_cert_bytes
        || left.client_cert_bytes != right.client_cert_bytes
        || left.client_key_bytes != right.client_key_bytes
    {
        return Err("YAML and JSON kubeconfig parsing differs".into());
    }
    Ok(())
}
