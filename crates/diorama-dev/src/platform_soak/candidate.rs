//! Candidate byte observations and digest consistency. This is not execution qualification.
use diorama_assets::{ReleasePackageManifest, ReleasePackager};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path};

/// Observation can only be constructed by independently reading a regular file.
#[derive(Debug)]
pub struct ObservedArtifact {
    name: String,
    sha256: String,
    size_bytes: u64,
}
impl ObservedArtifact {
    pub fn from_file(name: &str, path: &Path) -> Result<Self, String> {
        if !std::fs::symlink_metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .is_file()
        {
            return Err(format!("{} is not a regular file", path.display()));
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // A replacement symlink or FIFO between inspection and open must not
            // redirect the observation or block it before descriptor validation.
            options.custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)
                    .bits()
                    .cast_signed(),
            );
        }
        let mut file = options
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        let mut hash = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            size = size
                .checked_add(count as u64)
                .ok_or("artifact size overflow")?;
        }
        Ok(Self {
            name: name.into(),
            sha256: ReleasePackager::hex_digest(&hash.finalize()),
            size_bytes: size,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateArtifactRecord {
    pub name: String,
    pub artifact_type: String,
    pub expected_sha256: String,
    pub observed_sha256: String,
    pub expected_size_bytes: u64,
    pub size_bytes: u64,
    pub matches: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateVerificationSummary {
    pub total_artifacts: usize,
    pub matched_artifacts: usize,
    pub mismatched_artifacts: usize,
    pub all_matched: bool,
    pub artifacts: Vec<CandidateArtifactRecord>,
}
impl CandidateVerificationSummary {
    pub fn unobserved() -> Self {
        Self {
            total_artifacts: 0,
            matched_artifacts: 0,
            mismatched_artifacts: 0,
            all_matched: false,
            artifacts: vec![],
        }
    }

    /// Fixed local paths: node/management filenames, oci/ASSET/index.json,
    /// and oci/ASSET/sha256/DIGEST.json for every platform manifest descriptor.
    pub fn verify_files(
        manifest: &ReleasePackageManifest,
        root: &Path,
        expected_version: &str,
    ) -> Result<Self, String> {
        let expected = expected_artifacts(manifest, expected_version)?;
        let observed = expected
            .iter()
            .map(|(name, _, _, _, relative)| {
                ObservedArtifact::from_file(name, &root.join(relative))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::verify(manifest, &observed, expected_version)
    }

    pub fn verify(
        manifest: &ReleasePackageManifest,
        observed: &[ObservedArtifact],
        expected_version: &str,
    ) -> Result<Self, String> {
        let expected = expected_artifacts(manifest, expected_version)?;
        let mut by_name = BTreeMap::new();
        for observation in observed {
            if by_name
                .insert(observation.name.as_str(), observation)
                .is_some()
            {
                return Err(format!(
                    "duplicate artifact observation {}",
                    observation.name
                ));
            }
        }
        let mut records = vec![];
        for (name, kind, hash, size, _) in expected {
            let observation = by_name
                .remove(name.as_str())
                .ok_or_else(|| format!("missing artifact observation {name}"))?;
            if observation.sha256 != hash || observation.size_bytes != size {
                return Err(format!("candidate digest mismatch: {name}"));
            }
            records.push(CandidateArtifactRecord {
                name,
                artifact_type: kind,
                expected_sha256: hash,
                observed_sha256: observation.sha256.clone(),
                expected_size_bytes: size,
                size_bytes: observation.size_bytes,
                matches: true,
            });
        }
        if !by_name.is_empty() {
            return Err("unexpected artifact observation".into());
        }
        Ok(Self {
            total_artifacts: records.len(),
            matched_artifacts: records.len(),
            mismatched_artifacts: 0,
            all_matched: true,
            artifacts: records,
        })
    }

    /// Serialized values prove consistency only, never independently observed bytes.
    pub fn validate_unobserved_fixture(&self) -> Result<(), String> {
        if self != &Self::unobserved() {
            return Err("fixture must not claim candidate byte verification".into());
        }
        Ok(())
    }
}

type ExpectedArtifact = (String, String, String, u64, String);
fn expected_artifacts(
    manifest: &ReleasePackageManifest,
    expected_version: &str,
) -> Result<Vec<ExpectedArtifact>, String> {
    ReleasePackager::verify_release_manifest(
        manifest,
        "diorama-kube",
        "dioramactl",
        expected_version,
    )
    .map_err(|e| e.to_string())?;
    let mut expected = vec![];
    for archive in &manifest.node_archives {
        expected.push((
            archive.filename.clone(),
            "NodeArchive".into(),
            archive.sha256.clone(),
            archive.size_bytes,
            archive.filename.clone(),
        ));
    }
    for binary in &manifest.management_binaries {
        expected.push((
            binary.filename.clone(),
            "ManagementBinary".into(),
            binary.sha256.clone(),
            binary.size_bytes,
            binary.filename.clone(),
        ));
    }
    for image in &manifest.oci_images {
        expected.push((
            image.asset_id.clone(),
            "OciImageIndex".into(),
            image.index_digest[7..].into(),
            image.index_size_bytes,
            format!("oci/{}/index.json", image.asset_id),
        ));
        for descriptor in &image.platforms {
            let hash = &descriptor.digest[7..];
            expected.push((
                format!("{}/{}", image.asset_id, descriptor.platform),
                "OciPlatformManifest".into(),
                hash.into(),
                descriptor.size_bytes,
                format!("oci/{}/sha256/{hash}.json", image.asset_id),
            ));
        }
    }
    Ok(expected)
}
