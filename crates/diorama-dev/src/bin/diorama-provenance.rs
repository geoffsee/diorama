//! Generate publication checksums, provenance, license inventory and release manifest
//! for a complete candidate artifact directory. Without an inventory directory,
//! this validates prepared metadata and actual file checksums/sizes only; it does not qualify archive layout.
//! Supplying inventories enables the full publication file and layout checks,
//! which the release workflow requires before any publication files are written.
//!
//! Usage: `diorama-provenance <dist-dir> <version> [repository-root] [inventory-dir]`

use diorama_assets::{
    InventoryRequest, Limits, Manifest, Matrix, NodeTarget, ReleasePackager, Scope,
};
use diorama_dev::provenance::{
    CHECKSUM_FILE, ChecksumManifest, generate_license_inventory, generate_source_provenance,
    verify_publication, verify_publication_artifacts,
};
use diorama_dev::{Result, repository_root};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::{env, fs};

fn prepared_manifest(dist: &Path) -> Result<diorama_assets::ReleasePackageManifest> {
    // Asset inventory and OCI descriptors must come from the prepared candidate;
    // a directory of binary names cannot establish these identities or digests.
    let path = dist.join("release-manifest.json");
    Ok(serde_json::from_slice(&fs::read(&path).map_err(
        |error| {
            format!(
                "missing prepared release manifest {}: {error}",
                path.display()
            )
        },
    )?)?)
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    let dist = PathBuf::from(
        args.next()
            .ok_or("usage: diorama-provenance <dist-dir> <version>")?,
    );
    let version = args
        .next()
        .ok_or("usage: diorama-provenance <dist-dir> <version>")?;
    let root = match args.next() {
        Some(path) => PathBuf::from(path),
        None => repository_root(&env::current_dir()?)?,
    };
    let inventories = args.next().map(PathBuf::from);
    if args.next().is_some() {
        return Err("too many arguments".into());
    }

    let checksums = ChecksumManifest::generate(&dist)?;
    let manifest = prepared_manifest(&dist)?;
    ReleasePackager::verify_release_manifest(&manifest, "diorama-kube", "dioramactl", &version)?;
    let listed: std::collections::BTreeSet<_> = manifest
        .node_archives
        .iter()
        .map(|a| &a.filename)
        .chain(manifest.management_binaries.iter().map(|a| &a.filename))
        .collect();
    if let Some(extra) = checksums
        .entries()
        .keys()
        .find(|name| !listed.contains(name))
    {
        return Err(format!("unrecognized release artifact: {extra}").into());
    }
    verify_publication_artifacts(&dist, &manifest, &checksums, "diorama-kube", "dioramactl")?;
    if let Some(inventories) = inventories {
        verify_publication(
            &dist,
            &manifest,
            &checksums,
            "diorama-kube",
            "dioramactl",
            &|archive| {
                let variant = Matrix::from_cell(archive.cell)?;
                let path = inventories.join(format!("{}.manifest.json", archive.filename));
                let bytes = fs::read(&path).map_err(|error| {
                    format!(
                        "missing or unreadable archive inventory {}: {error}",
                        path.display()
                    )
                })?;
                Ok(
                    Manifest::decode(&bytes, Limits::default())?.validate_inventory(
                        InventoryRequest {
                            target: NodeTarget {
                                architecture: variant.architecture,
                                libc: variant.libc,
                            },
                            variant: variant.variant,
                            scope: Scope::SupervisedBundle,
                        },
                        Limits::default(),
                    )?,
                )
            },
        )?;
    }
    let provenance = generate_source_provenance(
        &fs::read_to_string(root.join("tools/upstream/inputs.json"))?,
        &fs::read_to_string(root.join("docs/architecture/upstream-inputs.json"))?,
        &version,
        &checksums,
    )?;
    let metadata = Command::new("cargo")
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(&root)
        .output()?;
    if !metadata.status.success() {
        return Err("cargo metadata failed".into());
    }
    let licenses = generate_license_inventory(std::str::from_utf8(&metadata.stdout)?)?;

    write(
        &dist,
        "provenance.json",
        &serde_json::to_string_pretty(&provenance)?,
    )?;
    write(
        &dist,
        "licenses.json",
        &serde_json::to_string_pretty(&licenses)?,
    )?;
    write(
        &dist,
        "release-manifest.json",
        &serde_json::to_string_pretty(&manifest)?,
    )?;
    write(&dist, CHECKSUM_FILE, &checksums.render())?;
    checksums.verify(&dist)?;
    Ok(())
}

fn write(dir: &Path, name: &str, content: &str) -> Result<()> {
    fs::write(dir.join(name), format!("{}\n", content.trim_end()))?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("diorama-provenance: {error}");
            ExitCode::FAILURE
        },
    }
}
