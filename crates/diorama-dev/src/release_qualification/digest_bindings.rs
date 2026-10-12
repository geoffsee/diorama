//! Cryptographic artifact digest bindings and checksum verification.
//!
//! Enforces:
//! - Valid SHA256 hex digests for all upstream generator inputs (`tools/upstream/inputs.json`).
//! - Valid Git commit hashes and tags for all upstream source repositories (`docs/architecture/upstream-inputs.json`).
//! - Valid `AssetId` and references across the asset catalog (`diorama_assets::catalog()`).
//! - Cryptographic integrity and tamper detection for candidate distribution artifacts and checksum manifests (`SHA256SUMS`).

use crate::Result;
use diorama_assets::{ReleasePackager, catalog};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::Path;

const EXPECTED_BASELINE: &str = "2ef1c4787989f11f868f81bb84ae2afd4a49a81d";

/// Validate a 64-character lowercase hexadecimal SHA-256 string.
pub fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Validate a 40-character lowercase hexadecimal Git commit hash.
pub fn is_valid_git_commit_hex(value: &str) -> bool {
    value.len() == 40
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[derive(Deserialize)]
struct UpstreamInputsDocument {
    sources: Vec<UpstreamInputEntry>,
}

#[derive(Deserialize)]
struct UpstreamInputEntry {
    id: String,
    #[serde(default)]
    path: Option<String>,
    url: String,
    sha256: String,
    bytes: u64,
}

/// Verifies that all upstream generator inputs in `tools/upstream/inputs.json`
/// declare syntactically valid SHA-256 strings and positive sizes.
/// This metadata-only check neither reads prepared input bytes nor verifies their provenance.
pub fn check_upstream_input_metadata(root: &Path) -> Result<usize> {
    let path = root.join("tools/upstream/inputs.json");
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read upstream inputs at {}: {e}", path.display()))?;

    let doc: UpstreamInputsDocument = serde_json::from_str(&content)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;

    if doc.sources.is_empty() {
        return Err("upstream inputs source list cannot be empty".into());
    }

    for source in &doc.sources {
        if source.id.is_empty() {
            return Err(format!("empty id in upstream input source at {}", path.display()).into());
        }
        if let Some(p) = &source.path
            && p.is_empty()
        {
            return Err(format!("empty path in upstream input source {}", source.id).into());
        }
        if source.url.is_empty() {
            return Err(format!("empty url in upstream input source {}", source.id).into());
        }
        if !is_valid_sha256_hex(&source.sha256) {
            return Err(format!(
                "invalid sha256 hex digest for upstream input {}: {}",
                source.id, source.sha256
            )
            .into());
        }
        if source.bytes == 0 {
            return Err(
                format!("zero byte length declared for upstream input {}", source.id).into(),
            );
        }
    }

    Ok(doc.sources.len())
}

#[derive(Deserialize)]
struct ProvenanceDocument {
    baseline: String,
    sources: Vec<ProvenanceSourceEntry>,
}

#[derive(Deserialize)]
struct ProvenanceSourceEntry {
    repository: String,
    tag: String,
    commit: String,
}

/// Checks that `docs/architecture/upstream-inputs.json` declares the expected
/// baseline and syntactically valid commits. It does not fetch or verify repositories.
pub fn check_upstream_provenance_metadata(root: &Path) -> Result<usize> {
    let path = root.join("docs/architecture/upstream-inputs.json");
    let content = fs::read_to_string(&path).map_err(|e| {
        format!(
            "failed to read upstream provenance at {}: {e}",
            path.display()
        )
    })?;

    let doc: ProvenanceDocument = serde_json::from_str(&content)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;

    if doc.baseline != EXPECTED_BASELINE {
        return Err(format!(
            "baseline commit mismatch in {}: expected {EXPECTED_BASELINE}, got {}",
            path.display(),
            doc.baseline
        )
        .into());
    }

    if doc.sources.is_empty() {
        return Err("upstream provenance source list cannot be empty".into());
    }

    for source in &doc.sources {
        if source.repository.is_empty() {
            return Err("empty repository name in upstream provenance".into());
        }
        if source.tag.is_empty() {
            return Err(format!(
                "empty tag for repository {} in upstream provenance",
                source.repository
            )
            .into());
        }
        if !is_valid_git_commit_hex(&source.commit) {
            return Err(format!(
                "invalid git commit hash for repository {} ({}): {}",
                source.repository, source.tag, source.commit
            )
            .into());
        }
    }

    Ok(doc.sources.len())
}

/// Checks nonempty catalog reference metadata without acquiring or hashing assets.
pub fn check_catalog_metadata() -> Result<usize> {
    let items = catalog();
    if items.is_empty() {
        return Err("asset catalog is empty".into());
    }

    for item in items {
        if item.reference.is_empty() {
            return Err(format!("empty reference for catalog asset {:?}", item.id).into());
        }
    }

    Ok(items.len())
}

/// Verifies candidate release artifacts against an expected checksum map or `SHA256SUMS`.
/// Strictly fails closed upon missing files, unlisted files, or digest mismatches.
pub fn verify_artifacts_integrity(
    dist_dir: &Path,
    expected_checksums: &BTreeMap<String, String>,
) -> Result<usize> {
    if expected_checksums.is_empty() {
        return Err("expected checksums map cannot be empty".into());
    }

    if !fs::symlink_metadata(dist_dir)?.file_type().is_dir() {
        return Err("distribution root must be a regular directory, not a symlink".into());
    }
    for filename in expected_checksums.keys() {
        let path = Path::new(filename);
        if filename.is_empty()
            || filename.contains(['/', '\\'])
            || path.components().count() != 1
            || !matches!(
                path.components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err(format!("invalid artifact name: {filename}").into());
        }
    }
    let mut observed_names = BTreeSet::new();
    for entry in fs::read_dir(dist_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(format!("nonregular artifact: {}", entry.path().display()).into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "non-UTF-8 artifact name")?;
        observed_names.insert(name);
    }
    if observed_names != expected_checksums.keys().cloned().collect() {
        return Err("distribution artifact inventory mismatch: missing or unlisted files".into());
    }

    // Check each expected file exists and matches observed SHA-256
    for (filename, expected_digest) in expected_checksums {
        if !is_valid_sha256_hex(expected_digest) {
            return Err(format!(
                "invalid expected sha256 format for {filename}: {expected_digest}"
            )
            .into());
        }

        let file_path = dist_dir.join(filename);
        if !file_path.is_file() {
            return Err(
                format!("missing expected release artifact: {}", file_path.display()).into(),
            );
        }

        let observed_digest = hash_regular_artifact(&file_path)?;

        if &observed_digest != expected_digest {
            return Err(format!(
                "cryptographic digest mismatch for {filename}: expected {expected_digest}, observed {observed_digest}"
            )
            .into());
        }
    }

    Ok(expected_checksums.len())
}

fn hash_regular_artifact(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(i32::try_from(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits(),
        )?);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(format!("nonregular artifact: {}", path.display()).into());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(ReleasePackager::hex_digest(&digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_sha256_validation() {
        assert!(is_valid_sha256_hex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        // uppercase rejected
        assert!(!is_valid_sha256_hex(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        ));
        // wrong length
        assert!(!is_valid_sha256_hex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
        ));
        // non-hex
        assert!(!is_valid_sha256_hex(
            "z3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn test_valid_git_commit_validation() {
        assert!(is_valid_git_commit_hex(
            "2ef1c4787989f11f868f81bb84ae2afd4a49a81d"
        ));
        assert!(!is_valid_git_commit_hex(
            "2EF1C4787989F11F868F81BB84AE2AFD4A49A81D"
        ));
        assert!(!is_valid_git_commit_hex("short"));
    }

    #[test]
    fn test_tamper_detection_fails_closed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let file1 = temp.path().join("artifact1.tar.gz");
        let file2 = temp.path().join("artifact2.tar.gz");

        fs::write(&file1, b"original content 1")?;
        fs::write(&file2, b"original content 2")?;

        let mut checksums = BTreeMap::new();
        checksums.insert(
            "artifact1.tar.gz".into(),
            ReleasePackager::sha256_hex(b"original content 1"),
        );
        checksums.insert(
            "artifact2.tar.gz".into(),
            ReleasePackager::sha256_hex(b"original content 2"),
        );

        // Valid should pass
        let verified = verify_artifacts_integrity(temp.path(), &checksums)?;
        assert_eq!(verified, 2);

        // Tampered content must fail
        fs::write(&file1, b"tampered content 1")?;
        let err = verify_artifacts_integrity(temp.path(), &checksums).unwrap_err();
        assert!(err.to_string().contains("digest mismatch"));

        Ok(())
    }
}
