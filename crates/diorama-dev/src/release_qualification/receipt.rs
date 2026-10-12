//! Candidate-bound qualification receipt schema and trusted reader (Issue #348).
//!
//! Enforces:
//! - Strict schema deserialization with bounded input (`MAX_RECEIPT_BYTES` = 8 MiB).
//! - Rejection of duplicate JSON keys and nonfinite numbers via strict JSON visitor.
//! - Rejection of file symlinks and oversized streams via `crate::read_bounded`.
//! - Verification of candidate identity against current candidate inventory.
//! - Tamper-evident SHA-256 payload integrity hash binding over the canonical receipt payload.
//! - Verification of command exit codes, assertion statuses, non-empty skip reasons,
//!   and clean container/image cleanup inventories.

use crate::release_qualification::digest_bindings;
use crate::{Result, json, read_bounded, sha256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Maximum allowable receipt file size in bytes (8 MiB).
pub const MAX_RECEIPT_BYTES: u64 = 8 * 1024 * 1024;

/// Current version of the candidate-bound qualification receipt schema.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Default relative directory for qualification receipts in the repository.
pub const DEFAULT_RECEIPTS_DIR: &str = "docs/release/receipts";

/// Candidate identity binding recorded in a qualification receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateIdentity {
    /// 40-character lowercase hexadecimal Git commit hash of the candidate checkout.
    pub source_revision: String,
    /// Map of candidate binary artifact names/paths to lowercase SHA-256 hex digests.
    pub binary_digests: BTreeMap<String, String>,
    /// Map of candidate payload/asset names/paths to lowercase SHA-256 hex digests.
    pub payload_digests: BTreeMap<String, String>,
}

/// Execution environment information.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentInfo {
    /// Operating system and CPU architecture (e.g. "linux-arm64").
    pub host: String,
    /// Linux kernel version string (e.g. "6.6.137-linux").
    pub kernel: String,
    /// Runner identifier or platform environment (e.g. "github-hosted-ubuntu-24.04-arm").
    pub runner: String,
    /// Operating system (e.g. "linux", "macos").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// CPU architecture (e.g. "`x86_64`", "aarch64").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Execution mode (e.g. "`in_process`", "`live_node`").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_mode: Option<String>,
    /// Execution duration in seconds, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_seconds: Option<u64>,
}

/// Record of an executed command during qualification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandExecution {
    /// Executed command arguments.
    pub command: Vec<String>,
    /// Process exit code. Zero indicates success.
    pub exit_code: i32,
    /// Optional SHA-256 digest of captured stdout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_sha256: Option<String>,
    /// Optional SHA-256 digest of captured stderr.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_sha256: Option<String>,
    /// Optional execution duration in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Verification assertion outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionRecord {
    /// Distinct identifier or description of the assertion.
    pub name: String,
    /// Whether the assertion passed.
    pub passed: bool,
    /// Optional failure details or observation note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Record of a deliberate or conditional test skip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkipRecord {
    /// Name of the skipped item or test case.
    pub name: String,
    /// Non-empty explanation of why this check was skipped.
    pub reason: String,
}

/// Post-execution cleanup inventory confirming absence of leaked resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupInventory {
    /// List of filesystem paths cleaned up.
    pub cleaned_paths: Vec<String>,
    /// List of remaining container IDs or names. Must be empty for clean execution.
    pub remaining_containers: Vec<String>,
    /// List of remaining container images. Must be empty for clean execution.
    pub remaining_images: Vec<String>,
    /// Status of the cleanup process (must be "complete").
    pub status: String,
}

/// Timestamps recording the execution window in RFC 3339 format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptTimestamps {
    /// Execution start time (RFC 3339).
    pub started_at: String,
    /// Execution completion time (RFC 3339).
    pub completed_at: String,
}

/// Unsigned canonical payload of a candidate-bound qualification receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPayload {
    /// Schema version integer (must match `CURRENT_SCHEMA_VERSION`).
    pub schema_version: u32,
    /// Criterion number (1–11) qualified by this receipt.
    pub criterion: usize,
    /// Human-readable description of the qualification test run.
    pub description: String,
    /// Identity binding to candidate binaries, payloads, and source revision.
    pub candidate: CandidateIdentity,
    /// Host, kernel, and runner execution environment.
    pub environment: EnvironmentInfo,
    /// All commands executed with their exit codes.
    pub commands: Vec<CommandExecution>,
    /// Specific assertions verified during qualification.
    pub assertions: Vec<AssertionRecord>,
    /// Documented skips with mandatory reasons.
    pub skips: Vec<SkipRecord>,
    /// Confirmed host and container cleanup inventory.
    pub cleanup: CleanupInventory,
    /// Execution timing boundaries.
    pub timestamps: ReceiptTimestamps,
}

/// Candidate-bound qualification receipt with SHA-256 payload integrity hash binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateReceipt {
    /// Schema version integer (must match `CURRENT_SCHEMA_VERSION`).
    pub schema_version: u32,
    /// Criterion number (1–11) qualified by this receipt.
    pub criterion: usize,
    /// Human-readable description of the qualification test run.
    pub description: String,
    /// Identity binding to candidate binaries, payloads, and source revision.
    pub candidate: CandidateIdentity,
    /// Host, kernel, and runner execution environment.
    pub environment: EnvironmentInfo,
    /// All commands executed with their exit codes.
    pub commands: Vec<CommandExecution>,
    /// Specific assertions verified during qualification.
    pub assertions: Vec<AssertionRecord>,
    /// Documented skips with mandatory reasons.
    pub skips: Vec<SkipRecord>,
    /// Confirmed host and container cleanup inventory.
    pub cleanup: CleanupInventory,
    /// Execution timing boundaries.
    pub timestamps: ReceiptTimestamps,
    /// SHA-256 hexadecimal hash over the canonical JSON serialized payload.
    pub integrity_hash: String,
}

/// Inventory of authoritative candidate artifacts against which receipts are validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateInventory {
    /// Expected Git commit hash of the candidate checkout.
    pub source_revision: String,
    /// Expected candidate binary artifact digests.
    pub binary_digests: BTreeMap<String, String>,
    /// Expected candidate payload digests.
    pub payload_digests: BTreeMap<String, String>,
}

impl CandidateInventory {
    /// Constructs a `CandidateIdentity` from this candidate inventory.
    pub fn to_candidate_identity(&self) -> CandidateIdentity {
        CandidateIdentity {
            source_revision: self.source_revision.clone(),
            binary_digests: self.binary_digests.clone(),
            payload_digests: self.payload_digests.clone(),
        }
    }
}

/// Computes the SHA-256 integrity hash for a receipt payload using canonical JSON serialization.
pub fn compute_payload_integrity_hash(payload: &ReceiptPayload) -> Result<String> {
    let bytes = serde_json::to_vec(payload)
        .map_err(|e| format!("failed to serialize receipt payload for integrity hash: {e}"))?;
    Ok(sha256(&bytes))
}

impl CandidateReceipt {
    /// Extracts the unsigned payload representation.
    pub fn payload(&self) -> ReceiptPayload {
        ReceiptPayload {
            schema_version: self.schema_version,
            criterion: self.criterion,
            description: self.description.clone(),
            candidate: self.candidate.clone(),
            environment: self.environment.clone(),
            commands: self.commands.clone(),
            assertions: self.assertions.clone(),
            skips: self.skips.clone(),
            cleanup: self.cleanup.clone(),
            timestamps: self.timestamps.clone(),
        }
    }

    /// Computes the expected SHA-256 integrity hash for this receipt's payload.
    pub fn compute_integrity_hash(&self) -> Result<String> {
        compute_payload_integrity_hash(&self.payload())
    }

    /// Creates a `CandidateReceipt` bound with a SHA-256 integrity hash computed over `payload`.
    pub fn new_with_integrity_hash(payload: ReceiptPayload) -> Result<Self> {
        let integrity_hash = compute_payload_integrity_hash(&payload)?;
        Ok(Self {
            schema_version: payload.schema_version,
            criterion: payload.criterion,
            description: payload.description,
            candidate: payload.candidate,
            environment: payload.environment,
            commands: payload.commands,
            assertions: payload.assertions,
            skips: payload.skips,
            cleanup: payload.cleanup,
            timestamps: payload.timestamps,
            integrity_hash,
        })
    }

    /// Backwards-compatible alias for [`Self::new_with_integrity_hash`].
    pub fn new_signed(payload: ReceiptPayload) -> Result<Self> {
        Self::new_with_integrity_hash(payload)
    }

    /// Verifies the SHA-256 payload integrity hash binding of this receipt.
    pub fn verify_integrity(&self) -> Result<()> {
        if self.integrity_hash.trim().is_empty() {
            return Err("receipt integrity_hash cannot be empty".into());
        }
        if !digest_bindings::is_valid_sha256_hex(&self.integrity_hash) {
            return Err(format!(
                "invalid sha256 hex in receipt integrity_hash: '{}'",
                self.integrity_hash
            )
            .into());
        }
        let expected = self.compute_integrity_hash()?;
        if self.integrity_hash != expected {
            return Err(format!(
                "receipt integrity hash mismatch: expected '{expected}', observed '{}'",
                self.integrity_hash
            )
            .into());
        }
        Ok(())
    }
}

/// Parses receipt bytes with duplicate-key rejection and strict schema enforcement.
pub fn parse_receipt_bytes(raw: &[u8]) -> Result<CandidateReceipt> {
    let value = json::parse(raw)?;
    let receipt: CandidateReceipt = serde_json::from_value(value)
        .map_err(|e| format!("receipt schema validation error: {e}"))?;
    Ok(receipt)
}

/// Reads a receipt from a filesystem path bounded to `MAX_RECEIPT_BYTES` with symlinks rejected.
pub fn load_receipt_from_path(path: &Path) -> Result<CandidateReceipt> {
    let bytes = read_bounded(path, MAX_RECEIPT_BYTES)
        .map_err(|e| format!("failed to read receipt file at {}: {e}", path.display()))?;
    let receipt = parse_receipt_bytes(&bytes)
        .map_err(|e| format!("invalid receipt in {}: {e}", path.display()))?;
    Ok(receipt)
}

fn extract_output_digest(record: &serde_json::Value) -> Option<(String, String)> {
    let output = record.get("output")?.as_object()?;
    let filename = output.get("filename")?.as_str()?;
    let sha256 = output.get("sha256")?.as_str()?;
    Some((filename.to_string(), sha256.to_string()))
}

fn extract_inputs(record: &serde_json::Value) -> Vec<(String, String)> {
    let mut results = Vec::new();
    if let Some(inputs) = record.get("inputs").and_then(|v| v.as_array()) {
        for input in inputs {
            if let (Some(path), Some(sha256)) = (
                input.get("path").and_then(|v| v.as_str()),
                input.get("sha256").and_then(|v| v.as_str()),
            ) {
                results.push((path.to_string(), sha256.to_string()));
            }
        }
    }
    results
}

/// Loads candidate inventory directly from a release directory without checking environment overrides.
pub fn load_candidate_inventory_from_release_dir(root: &Path) -> Result<CandidateInventory> {
    let cell_inventory_path = root.join("cell-inventory.json");
    if !cell_inventory_path.is_file() {
        return Err(format!(
            "candidate inventory unavailable: {} not found",
            cell_inventory_path.display()
        )
        .into());
    }

    let bytes = read_bounded(&cell_inventory_path, MAX_RECEIPT_BYTES)?;
    let value = json::parse(&bytes)?;

    let source_revision = value["source_revision"]
        .as_str()
        .ok_or("missing source_revision in cell-inventory.json")?
        .to_string();

    let mut binary_digests = BTreeMap::new();
    let mut payload_digests = BTreeMap::new();

    if let Some(cells) = value["node_cells"].as_array() {
        for cell in cells {
            if let Some((name, digest)) = extract_output_digest(cell) {
                binary_digests.insert(name, digest);
            }
            for (path, digest) in extract_inputs(cell) {
                if path.starts_with("bin/") || path.ends_with(".tar.gz") {
                    binary_digests.insert(path, digest);
                } else {
                    payload_digests.insert(path, digest);
                }
            }
        }
    }

    if let Some(targets) = value["management_targets"].as_array() {
        for target in targets {
            if let Some((name, digest)) = extract_output_digest(target) {
                binary_digests.insert(name, digest);
            }
            for (path, digest) in extract_inputs(target) {
                payload_digests.insert(path, digest);
            }
        }
    }

    // Incorporate SHA256SUMS items as well if present
    let sums_path = root.join("SHA256SUMS");
    if sums_path.is_file() {
        let sums_bytes = read_bounded(&sums_path, 1024 * 1024)?;
        let sums_text =
            std::str::from_utf8(&sums_bytes).map_err(|e| format!("non-UTF8 SHA256SUMS: {e}"))?;
        for line in sums_text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 && digest_bindings::is_valid_sha256_hex(parts[0]) {
                let digest = parts[0].to_string();
                let filename = parts[1].to_string();
                // Filter out self-referencing / report / receipt files to avoid circular hash dependency
                if filename == "SHA256SUMS"
                    || filename == "licenses.json"
                    || filename == "attribution.md"
                    || filename.starts_with("receipts/")
                    || filename.starts_with("criterion-")
                    || filename.starts_with("conformance-qualification-report")
                    || filename.starts_with("performance-qualification-report")
                    || filename.starts_with("state-transition-qualification-report")
                    || filename.starts_with("platform-soak-report")
                {
                    continue;
                }
                if !binary_digests.contains_key(&filename) {
                    payload_digests.insert(filename, digest);
                }
            }
        }
    }

    Ok(CandidateInventory {
        source_revision,
        binary_digests,
        payload_digests,
    })
}

/// Loads the current candidate inventory from repository metadata or an optional candidate directory.
pub fn load_candidate_inventory_with_candidate(
    root: &Path,
    candidate_dir: Option<&Path>,
) -> Result<CandidateInventory> {
    if let Some(explicit_path) = std::env::var_os("DIORAMA_CANDIDATE_INVENTORY_PATH") {
        let explicit = PathBuf::from(explicit_path);
        let bytes = read_bounded(&explicit, MAX_RECEIPT_BYTES)?;
        let value = json::parse(&bytes)?;
        let inventory: CandidateInventory = serde_json::from_value(value)
            .map_err(|e| format!("invalid candidate inventory at {}: {e}", explicit.display()))?;
        return Ok(inventory);
    }

    if let Some(candidate) = candidate_dir {
        let candidate_path = if candidate.is_absolute() || candidate.exists() {
            candidate.to_path_buf()
        } else {
            root.join(candidate)
        };
        if candidate_path.join("cell-inventory.json").is_file() {
            return load_candidate_inventory_from_release_dir(&candidate_path);
        } else if candidate_path.is_file() {
            let bytes = read_bounded(&candidate_path, MAX_RECEIPT_BYTES)?;
            let value = json::parse(&bytes)?;
            let inventory: CandidateInventory = serde_json::from_value(value).map_err(|e| {
                format!(
                    "invalid candidate inventory at {}: {e}",
                    candidate_path.display()
                )
            })?;
            return Ok(inventory);
        } else if candidate_path
            .join("docs/release/cell-inventory.json")
            .is_file()
        {
            return load_candidate_inventory_from_release_dir(&candidate_path.join("docs/release"));
        }
        return Err(format!(
            "candidate inventory unavailable: no cell-inventory.json or inventory file at {}",
            candidate_path.display()
        )
        .into());
    }

    if root.join("cell-inventory.json").is_file() {
        load_candidate_inventory_from_release_dir(root)
    } else if root.join("docs/release/cell-inventory.json").is_file() {
        load_candidate_inventory_from_release_dir(&root.join("docs/release"))
    } else {
        load_candidate_inventory_from_release_dir(root)
    }
}

/// Loads the current candidate inventory from repository metadata.
pub fn load_candidate_inventory(root: &Path) -> Result<CandidateInventory> {
    load_candidate_inventory_with_candidate(root, None)
}

fn validate_metadata_and_env(receipt: &CandidateReceipt, expected_criterion: usize) -> Result<()> {
    if receipt.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(format!(
            "unsupported receipt schema version: expected {CURRENT_SCHEMA_VERSION}, got {}",
            receipt.schema_version
        )
        .into());
    }
    if receipt.criterion != expected_criterion {
        return Err(format!(
            "criterion mismatch: expected criterion {expected_criterion}, got {}",
            receipt.criterion
        )
        .into());
    }
    if receipt.description.trim().is_empty() {
        return Err("receipt description cannot be empty".into());
    }
    if receipt.environment.host.trim().is_empty() {
        return Err("receipt environment host cannot be empty".into());
    }
    if receipt.environment.kernel.trim().is_empty() {
        return Err("receipt environment kernel cannot be empty".into());
    }
    if receipt.environment.runner.trim().is_empty() {
        return Err("receipt environment runner cannot be empty".into());
    }
    if receipt.timestamps.started_at.trim().is_empty() {
        return Err("receipt started_at timestamp cannot be empty".into());
    }
    if receipt.timestamps.completed_at.trim().is_empty() {
        return Err("receipt completed_at timestamp cannot be empty".into());
    }
    Ok(())
}

fn validate_candidate_inventory_binding(
    candidate: &CandidateIdentity,
    inventory: &CandidateInventory,
) -> Result<()> {
    if !digest_bindings::is_valid_git_commit_hex(&candidate.source_revision) {
        return Err(format!(
            "invalid git commit hex in candidate source_revision: '{}'",
            candidate.source_revision
        )
        .into());
    }
    if candidate.source_revision != inventory.source_revision {
        return Err(format!(
            "candidate source revision mismatch: receipt has '{}', current inventory has '{}'",
            candidate.source_revision, inventory.source_revision
        )
        .into());
    }
    if candidate.binary_digests.is_empty() {
        return Err("candidate binary_digests cannot be empty".into());
    }
    for (name, digest) in &candidate.binary_digests {
        if name.trim().is_empty() {
            return Err("candidate binary name cannot be empty".into());
        }
        if !digest_bindings::is_valid_sha256_hex(digest) {
            return Err(
                format!("invalid sha256 hex for candidate binary '{name}': '{digest}'").into(),
            );
        }
        match inventory.binary_digests.get(name) {
            Some(expected_digest) => {
                if digest != expected_digest {
                    return Err(format!(
                        "candidate binary digest mismatch for '{name}': receipt declares '{digest}', current inventory has '{expected_digest}'"
                    )
                    .into());
                }
            },
            None => {
                return Err(format!(
                    "candidate receipt references unknown binary '{name}' not found in candidate inventory"
                )
                .into());
            },
        }
    }
    for (name, digest) in &candidate.payload_digests {
        if name.trim().is_empty() {
            return Err("candidate payload name cannot be empty".into());
        }
        if !digest_bindings::is_valid_sha256_hex(digest) {
            return Err(
                format!("invalid sha256 hex for candidate payload '{name}': '{digest}'").into(),
            );
        }
        match inventory.payload_digests.get(name) {
            Some(expected_digest) => {
                if digest != expected_digest {
                    return Err(format!(
                        "candidate payload digest mismatch for '{name}': receipt declares '{digest}', current inventory has '{expected_digest}'"
                    )
                    .into());
                }
            },
            None => {
                return Err(format!(
                    "candidate receipt references unknown payload '{name}' not found in candidate inventory"
                )
                .into());
            },
        }
    }
    Ok(())
}

fn validate_commands(commands: &[CommandExecution]) -> Result<()> {
    for (idx, cmd) in commands.iter().enumerate() {
        if cmd.command.is_empty() {
            return Err(format!("receipt command #{idx} argv cannot be empty").into());
        }
        if cmd.exit_code != 0 {
            return Err(format!(
                "receipt command execution failed with exit code {}: '{}'",
                cmd.exit_code,
                cmd.command.join(" ")
            )
            .into());
        }
        if let Some(sha) = &cmd.stdout_sha256
            && !digest_bindings::is_valid_sha256_hex(sha)
        {
            return Err(format!("invalid stdout_sha256 in command #{idx}: '{sha}'").into());
        }
        if let Some(sha) = &cmd.stderr_sha256
            && !digest_bindings::is_valid_sha256_hex(sha)
        {
            return Err(format!("invalid stderr_sha256 in command #{idx}: '{sha}'").into());
        }
    }
    Ok(())
}

fn validate_assertions_and_skips(
    assertions: &[AssertionRecord],
    skips: &[SkipRecord],
) -> Result<()> {
    if assertions.is_empty() {
        return Err("receipt assertions cannot be empty".into());
    }
    for (idx, assertion) in assertions.iter().enumerate() {
        if assertion.name.trim().is_empty() {
            return Err(format!("receipt assertion #{idx} name cannot be empty").into());
        }
        if !assertion.passed {
            let detail = assertion
                .detail
                .as_deref()
                .unwrap_or("assertion reported failure");
            return Err(format!("receipt assertion '{}' failed: {detail}", assertion.name).into());
        }
    }

    for (idx, skip) in skips.iter().enumerate() {
        if skip.name.trim().is_empty() {
            return Err(format!("receipt skip #{idx} name cannot be empty").into());
        }
        if skip.reason.trim().is_empty() {
            return Err(format!("receipt skip '{}' missing reason", skip.name).into());
        }
    }
    Ok(())
}

fn validate_cleanup(cleanup: &CleanupInventory) -> Result<()> {
    if cleanup.status != "complete" {
        return Err(format!(
            "receipt cleanup status is '{}', expected 'complete'",
            cleanup.status
        )
        .into());
    }
    if !cleanup.remaining_containers.is_empty() {
        return Err(format!(
            "receipt cleanup unconfirmed: remaining containers not empty: {:?}",
            cleanup.remaining_containers
        )
        .into());
    }
    if !cleanup.remaining_images.is_empty() {
        return Err(format!(
            "receipt cleanup unconfirmed: remaining images not empty: {:?}",
            cleanup.remaining_images
        )
        .into());
    }
    Ok(())
}

/// Validates a receipt against an authoritative candidate inventory and criterion requirements.
pub fn validate_candidate_receipt(
    receipt: &CandidateReceipt,
    inventory: &CandidateInventory,
    expected_criterion: usize,
) -> Result<()> {
    validate_metadata_and_env(receipt, expected_criterion)?;
    validate_candidate_inventory_binding(&receipt.candidate, inventory)?;
    receipt.verify_integrity()?;
    validate_commands(&receipt.commands)?;
    validate_assertions_and_skips(&receipt.assertions, &receipt.skips)?;
    validate_cleanup(&receipt.cleanup)?;
    Ok(())
}

/// Loads and validates a receipt file against a repository root and optional candidate directory.
pub fn load_and_validate_receipt_with_candidate(
    receipt_path: &Path,
    root: &Path,
    candidate_dir: Option<&Path>,
    expected_criterion: usize,
) -> Result<CandidateReceipt> {
    let inventory = load_candidate_inventory_with_candidate(root, candidate_dir)?;
    load_and_validate_receipt_with_inventory(receipt_path, &inventory, expected_criterion)
}

/// Loads and validates a receipt file against a repository root.
pub fn load_and_validate_receipt(
    receipt_path: &Path,
    root: &Path,
    expected_criterion: usize,
) -> Result<CandidateReceipt> {
    load_and_validate_receipt_with_candidate(receipt_path, root, None, expected_criterion)
}

/// Loads and validates a receipt file against an explicit candidate inventory.
pub fn load_and_validate_receipt_with_inventory(
    receipt_path: &Path,
    inventory: &CandidateInventory,
    expected_criterion: usize,
) -> Result<CandidateReceipt> {
    let receipt = load_receipt_from_path(receipt_path)?;
    validate_candidate_receipt(&receipt, inventory, expected_criterion)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inventory() -> CandidateInventory {
        CandidateInventory {
            source_revision: "2ef1c4787989f11f868f81bb84ae2afd4a49a81d".into(),
            binary_digests: BTreeMap::from([(
                "diorama-kube".into(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            )]),
            payload_digests: BTreeMap::from([(
                "bundle.manifest".into(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            )]),
        }
    }

    fn sample_payload(criterion: usize) -> ReceiptPayload {
        ReceiptPayload {
            schema_version: 1,
            criterion,
            description: "Sample valid qualification run".into(),
            candidate: CandidateIdentity {
                source_revision: "2ef1c4787989f11f868f81bb84ae2afd4a49a81d".into(),
                binary_digests: BTreeMap::from([(
                    "diorama-kube".into(),
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                )]),
                payload_digests: BTreeMap::from([(
                    "bundle.manifest".into(),
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                )]),
            },
            environment: EnvironmentInfo {
                host: "linux-arm64".into(),
                kernel: "6.6.137".into(),
                runner: "github-hosted-ubuntu-24.04-arm".into(),
                ..Default::default()
            },
            commands: vec![CommandExecution {
                command: vec!["diorama-kube".into(), "--version".into()],
                exit_code: 0,
                stdout_sha256: None,
                stderr_sha256: None,
                duration_ms: Some(15),
            }],
            assertions: vec![AssertionRecord {
                name: "startup_verified".into(),
                passed: true,
                detail: Some("clean startup confirmed".into()),
            }],
            skips: vec![SkipRecord {
                name: "musl_dynamic".into(),
                reason: "glibc host platform".into(),
            }],
            cleanup: CleanupInventory {
                cleaned_paths: vec!["/tmp/test".into()],
                remaining_containers: vec![],
                remaining_images: vec![],
                status: "complete".into(),
            },
            timestamps: ReceiptTimestamps {
                started_at: "2026-10-08T12:00:00Z".into(),
                completed_at: "2026-10-08T12:01:00Z".into(),
            },
        }
    }

    #[test]
    fn valid_receipt_passes_validation() -> Result<()> {
        let payload = sample_payload(1);
        let receipt = CandidateReceipt::new_signed(payload)?;
        let inventory = sample_inventory();
        validate_candidate_receipt(&receipt, &inventory, 1)?;
        Ok(())
    }

    #[test]
    fn integrity_hash_mismatch_is_rejected() -> Result<()> {
        let payload = sample_payload(1);
        let mut receipt = CandidateReceipt::new_signed(payload)?;
        receipt.integrity_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".into();
        let inventory = sample_inventory();
        let err = validate_candidate_receipt(&receipt, &inventory, 1).unwrap_err();
        assert!(err.to_string().contains("integrity hash mismatch"));
        Ok(())
    }

    #[test]
    fn command_exit_failure_is_rejected() -> Result<()> {
        let mut payload = sample_payload(1);
        payload.commands[0].exit_code = 1;
        let receipt = CandidateReceipt::new_signed(payload)?;
        let inventory = sample_inventory();
        let err = validate_candidate_receipt(&receipt, &inventory, 1).unwrap_err();
        assert!(err.to_string().contains("failed with exit code 1"));
        Ok(())
    }

    #[test]
    fn assertion_failure_is_rejected() -> Result<()> {
        let mut payload = sample_payload(1);
        payload.assertions[0].passed = false;
        let receipt = CandidateReceipt::new_signed(payload)?;
        let inventory = sample_inventory();
        let err = validate_candidate_receipt(&receipt, &inventory, 1).unwrap_err();
        assert!(err.to_string().contains("failed"));
        Ok(())
    }

    #[test]
    fn skip_without_reason_is_rejected() -> Result<()> {
        let mut payload = sample_payload(1);
        payload.skips[0].reason = "   ".into();
        let receipt = CandidateReceipt::new_signed(payload)?;
        let inventory = sample_inventory();
        let err = validate_candidate_receipt(&receipt, &inventory, 1).unwrap_err();
        assert!(err.to_string().contains("missing reason"));
        Ok(())
    }

    #[test]
    fn remaining_containers_in_cleanup_is_rejected() -> Result<()> {
        let mut payload = sample_payload(1);
        payload.cleanup.remaining_containers = vec!["leaked-cnt-1".into()];
        let receipt = CandidateReceipt::new_signed(payload)?;
        let inventory = sample_inventory();
        let err = validate_candidate_receipt(&receipt, &inventory, 1).unwrap_err();
        assert!(err.to_string().contains("remaining containers not empty"));
        Ok(())
    }

    #[test]
    fn schema_version_mismatch_is_rejected() -> Result<()> {
        let mut payload = sample_payload(1);
        payload.schema_version = 2;
        let receipt = CandidateReceipt::new_signed(payload)?;
        let inventory = sample_inventory();
        let err = validate_candidate_receipt(&receipt, &inventory, 1).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported receipt schema version")
        );
        Ok(())
    }

    #[test]
    fn criterion_number_mismatch_is_rejected() -> Result<()> {
        let payload = sample_payload(1);
        let receipt = CandidateReceipt::new_signed(payload)?;
        let inventory = sample_inventory();
        let err = validate_candidate_receipt(&receipt, &inventory, 2).unwrap_err();
        assert!(err.to_string().contains("criterion mismatch"));
        Ok(())
    }

    #[test]
    fn empty_description_is_rejected() -> Result<()> {
        let mut payload = sample_payload(1);
        payload.description = "   ".into();
        let receipt = CandidateReceipt::new_signed(payload)?;
        let inventory = sample_inventory();
        let err = validate_candidate_receipt(&receipt, &inventory, 1).unwrap_err();
        assert!(err.to_string().contains("description cannot be empty"));
        Ok(())
    }

    #[test]
    fn empty_environment_fields_are_rejected() -> Result<()> {
        let mut p1 = sample_payload(1);
        p1.environment.host = String::new();
        let err1 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p1)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(
            err1.to_string()
                .contains("environment host cannot be empty")
        );

        let mut p2 = sample_payload(1);
        p2.environment.kernel = String::new();
        let err2 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p2)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(
            err2.to_string()
                .contains("environment kernel cannot be empty")
        );

        let mut p3 = sample_payload(1);
        p3.environment.runner = String::new();
        let err3 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p3)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(
            err3.to_string()
                .contains("environment runner cannot be empty")
        );
        Ok(())
    }

    #[test]
    fn empty_timestamps_are_rejected() -> Result<()> {
        let mut p1 = sample_payload(1);
        p1.timestamps.started_at = String::new();
        let err1 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p1)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(
            err1.to_string()
                .contains("started_at timestamp cannot be empty")
        );

        let mut p2 = sample_payload(1);
        p2.timestamps.completed_at = String::new();
        let err2 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p2)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(
            err2.to_string()
                .contains("completed_at timestamp cannot be empty")
        );
        Ok(())
    }

    #[test]
    fn invalid_candidate_source_revision_is_rejected() -> Result<()> {
        let mut p1 = sample_payload(1);
        p1.candidate.source_revision = "invalid-sha".into();
        let err1 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p1)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(err1.to_string().contains("invalid git commit hex"));

        let mut p2 = sample_payload(1);
        p2.candidate.source_revision = "0000000000000000000000000000000000000000".into();
        let err2 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p2)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(
            err2.to_string()
                .contains("candidate source revision mismatch")
        );
        Ok(())
    }

    #[test]
    fn binary_and_payload_digest_checks_are_enforced() -> Result<()> {
        let mut p1 = sample_payload(1);
        p1.candidate.binary_digests.clear();
        let err1 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p1)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(err1.to_string().contains("binary_digests cannot be empty"));

        let mut p2 = sample_payload(1);
        p2.candidate
            .binary_digests
            .insert("diorama-kube".into(), "badhex".into());
        let err2 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p2)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(err2.to_string().contains("invalid sha256 hex"));

        let mut p3 = sample_payload(1);
        p3.candidate.binary_digests.insert(
            "unknown-bin".into(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        );
        let err3 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p3)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(err3.to_string().contains("unknown binary 'unknown-bin'"));

        let mut p4 = sample_payload(1);
        p4.candidate.binary_digests.insert(
            "diorama-kube".into(),
            "0000000000000000000000000000000000000000000000000000000000000000".into(),
        );
        let err4 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p4)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(
            err4.to_string()
                .contains("candidate binary digest mismatch")
        );

        let mut p5 = sample_payload(1);
        p5.candidate.payload_digests.insert(
            "unknown-payload".into(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        );
        let err5 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p5)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(
            err5.to_string()
                .contains("unknown payload 'unknown-payload'")
        );
        Ok(())
    }

    #[test]
    fn command_argv_and_hashes_are_validated() -> Result<()> {
        let mut p1 = sample_payload(1);
        p1.commands[0].command.clear();
        let err1 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p1)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(err1.to_string().contains("argv cannot be empty"));

        let mut p2 = sample_payload(1);
        p2.commands[0].stdout_sha256 = Some("badhex".into());
        let err2 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p2)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(err2.to_string().contains("invalid stdout_sha256"));

        let mut p3 = sample_payload(1);
        p3.commands[0].stderr_sha256 = Some("badhex".into());
        let err3 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p3)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(err3.to_string().contains("invalid stderr_sha256"));
        Ok(())
    }

    #[test]
    fn assertions_and_cleanup_requirements_are_enforced() -> Result<()> {
        let mut p1 = sample_payload(1);
        p1.assertions.clear();
        let err1 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p1)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(err1.to_string().contains("assertions cannot be empty"));

        let mut p2 = sample_payload(1);
        p2.assertions[0].name = "   ".into();
        let err2 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p2)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(
            err2.to_string()
                .contains("assertion #0 name cannot be empty")
        );

        let mut p3 = sample_payload(1);
        p3.skips[0].name = "   ".into();
        let err3 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p3)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(err3.to_string().contains("skip #0 name cannot be empty"));

        let mut p4 = sample_payload(1);
        p4.cleanup.status = "partial".into();
        let err4 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p4)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(err4.to_string().contains("cleanup status is 'partial'"));

        let mut p5 = sample_payload(1);
        p5.cleanup.remaining_images = vec!["leaked-img-1".into()];
        let err5 =
            validate_candidate_receipt(&CandidateReceipt::new_signed(p5)?, &sample_inventory(), 1)
                .unwrap_err();
        assert!(err5.to_string().contains("remaining images not empty"));
        Ok(())
    }

    #[test]
    fn candidate_dir_lookup_fails_closed_when_inventory_absent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let err = load_candidate_inventory_with_candidate(Path::new("."), Some(temp_dir.path()))
            .unwrap_err();
        assert!(err.to_string().contains("candidate inventory unavailable"));
    }
}
