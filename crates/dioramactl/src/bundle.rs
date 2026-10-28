//! Offline bundle builder. Emits `bundle.manifest` and a target-specific
//! `<prefix>-<version>-linux-<arch>[-musl]-offline.tar.gz` archive that the
//! offline install path in [`crate::install`] consumes. Local files only; no
//! network access.

use crate::install::{
    BUNDLE_MANIFEST, BundleEntry, BundleManifest, arch_name, audit_archive, check_elf, libc_name,
    safe_relative, sha256_hex, verify_staged_bundle,
};
use diorama_assets::{Architecture, Libc, Matrix, Variant};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Archive filename prefix shared with the install path's parser.
pub const BUNDLE_PREFIX: &str = crate::artifact::ARCHIVE_PREFIX;

/// One input file placed in the bundle at `relative`.
#[derive(Clone, Debug)]
pub struct BundleInput {
    pub source: PathBuf,
    pub relative: String,
    /// Executables must be ELF files for the target architecture.
    pub executable: bool,
}

/// Bundle build request.
#[derive(Clone, Debug)]
pub struct BundleSpec {
    pub version: String,
    pub architecture: Architecture,
    pub libc: Libc,
    pub inputs: Vec<BundleInput>,
    pub output_dir: PathBuf,
}

/// Builds and self-verifies the bundle, returning the archive path.
///
/// Work happens in a private staging directory; the archive is renamed into
/// `output_dir` only after the staged tree and the archive pass the same
/// checks the installer applies.
pub fn build_offline_bundle(spec: &BundleSpec) -> Result<PathBuf, String> {
    if spec.version.is_empty() || spec.version.contains(['/', '\n', ' ']) {
        return Err(format!("invalid bundle version '{}'", spec.version));
    }
    if spec.inputs.is_empty() {
        return Err("bundle has no input files".to_string());
    }
    let cell = Matrix::NODE_VARIANTS
        .iter()
        .find(|c| {
            c.architecture == spec.architecture
                && c.libc == spec.libc
                && c.variant == Variant::Offline
        })
        .ok_or("no offline bundle exists for this target")?;
    let filename = cell.archive_filename(BUNDLE_PREFIX, &spec.version);

    fs::create_dir_all(&spec.output_dir).map_err(|e| e.to_string())?;
    let staging = tempfile::TempDir::new_in(&spec.output_dir).map_err(|e| e.to_string())?;
    let root = staging.path().join("tree");
    fs::create_dir(&root).map_err(|e| e.to_string())?;

    let mut seen = BTreeSet::new();
    let mut entries = Vec::new();
    for input in &spec.inputs {
        let rel = safe_relative(&input.relative)?;
        if rel == Path::new(BUNDLE_MANIFEST) || !seen.insert(rel.clone()) {
            return Err(format!(
                "duplicate or reserved bundle path '{}'",
                input.relative
            ));
        }
        if !input.source.is_file() {
            return Err(format!("{} is not a regular file", input.source.display()));
        }
        if input.executable {
            check_elf(&input.source, spec.architecture)?;
        }
        let dest = root.join(&rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::copy(&input.source, &dest).map_err(|e| format!("{}: {e}", input.source.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if input.executable { 0o755 } else { 0o644 };
            fs::set_permissions(&dest, fs::Permissions::from_mode(mode))
                .map_err(|e| format!("{}: {e}", dest.display()))?;
        }
        entries.push(BundleEntry {
            sha256: sha256_hex(&dest).map_err(|e| e.to_string())?,
            path: rel,
            executable: input.executable,
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = BundleManifest {
        version: spec.version.clone(),
        os: "linux".to_string(),
        arch: arch_name(spec.architecture).to_string(),
        libc: libc_name(spec.libc).to_string(),
        entries,
    };
    fs::write(root.join(BUNDLE_MANIFEST), manifest.render()).map_err(|e| e.to_string())?;
    verify_staged_bundle(&root, spec.architecture, spec.libc)?;

    let archive = staging.path().join(&filename);
    let status = Command::new("tar")
        .env("COPYFILE_DISABLE", "1")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&root)
        .arg(".")
        .status()
        .map_err(|e| format!("tar command failed: {e}"))?;
    if !status.success() {
        return Err(format!("tar exited with status {status}"));
    }
    audit_archive(&archive)?;
    let final_path = spec.output_dir.join(&filename);
    fs::rename(&archive, &final_path).map_err(|e| e.to_string())?;
    Ok(final_path)
}
