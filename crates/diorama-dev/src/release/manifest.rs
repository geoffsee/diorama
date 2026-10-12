//! Checksum binding for observed release bytes. Metadata is not qualification.
use crate::{Result, platform_soak::CandidateVerificationSummary};
use diorama_assets::ReleasePackageManifest;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    path::{Component, Path},
};
pub const DISTRIBUTION_VERSION: &str = "0.1.0";
pub const NODE_PREFIX: &str = "diorama-kube";
pub const MANAGEMENT_PREFIX: &str = "dioramactl";
pub fn sha256_hex(bytes: &[u8]) -> String {
    crate::sha256(bytes)
}
/// Read a prepared manifest; hashes/sizes are never synthesized from target names.
pub fn build_release_package_manifest(release_dir: &Path) -> Result<ReleasePackageManifest> {
    let manifest =
        serde_json::from_slice(&std::fs::read(release_dir.join("release-manifest.json"))?)?;
    verify_observed_artifacts(release_dir, &manifest)?;
    Ok(manifest)
}
/// Verify actual node, management and OCI descriptor bytes using the shared observer.
pub fn verify_observed_artifacts(dir: &Path, manifest: &ReleasePackageManifest) -> Result<()> {
    CandidateVerificationSummary::verify_files(manifest, dir, DISTRIBUTION_VERSION)?;
    Ok(())
}
/// Bind every regular file recursively. Links and special files are rejected.
pub fn assemble_checksum_manifest(dir: &Path) -> Result<String> {
    let names = regular_files(dir)?;
    let mut output = String::new();
    for name in names {
        writeln!(
            output,
            "{}  {name}",
            sha256_hex(&std::fs::read(dir.join(&name))?)
        )?;
    }
    Ok(output)
}
fn regular_files(dir: &Path) -> Result<BTreeSet<String>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeSet<String>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let kind = std::fs::symlink_metadata(&path)?.file_type();
            if kind.is_dir() {
                walk(root, &path, out)?;
            } else if kind.is_file() {
                let name = path
                    .strip_prefix(root)?
                    .components()
                    .map(|component| match component {
                        Component::Normal(part) => part.to_str().ok_or("non-UTF8 release filename"),
                        _ => Err("invalid release path component"),
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?
                    .join("/");
                if name == "SHA256SUMS" {
                    continue;
                }
                if name.contains(['\n', '\r', '\\']) {
                    return Err("invalid release filename".into());
                }
                out.insert(name);
            } else {
                return Err(format!("release contains non-regular file {}", path.display()).into());
            }
        }
        Ok(())
    }
    let mut names = BTreeSet::new();
    walk(dir, dir, &mut names)?;
    Ok(names)
}
/// Require exact coverage, including all evidence and nested OCI descriptors.
pub fn verify_checksum_inventory(text: &str, dir: &Path) -> Result<()> {
    let mut checksums = BTreeMap::new();
    for line in text.lines() {
        let (digest, name) = line.split_once("  ").ok_or("malformed checksum line")?;
        if digest.len() != 64
            || !digest.bytes().all(|b| b.is_ascii_hexdigit())
            || name.is_empty()
            || name.contains('\\')
            || Path::new(name)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            || checksums
                .insert(name.to_string(), digest.to_string())
                .is_some()
        {
            return Err("invalid or duplicate checksum entry".into());
        }
    }
    let actual = regular_files(dir)?;
    let bound = checksums.keys().cloned().collect::<BTreeSet<_>>();
    if actual != bound {
        return Err("checksum inventory must cover every release file exactly".into());
    }
    for (name, digest) in checksums {
        if sha256_hex(&std::fs::read(dir.join(&name))?) != digest {
            return Err(format!("checksum mismatch for {name}").into());
        }
    }
    Ok(())
}
pub fn verify_checksum_manifest_binding(
    text: &str,
    manifest: &ReleasePackageManifest,
    dir: &Path,
) -> Result<()> {
    verify_checksum_inventory(text, dir)?;
    verify_observed_artifacts(dir, manifest)?;
    Ok(())
}
