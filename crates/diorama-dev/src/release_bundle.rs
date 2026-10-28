//! Release-only acquisition and packaging of complete offline node bundles.

use crate::{Result, read_bounded, run_checked};
use diorama_assets::{
    Architecture, ArchiveLimits, AssetId, AssetLayout, DecodeLimits, ElfLimits, Encoding,
    InventoryRequest, Kind, LayerDecodeLimits, Libc, Limits, Manifest, NodeTarget, Scope, Variant,
    catalog,
};
use dioramactl::bundle::{BundleInput, BundleSpec, build_offline_bundle};
use flate2::{Compression, write::GzEncoder};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
};

const INPUTS: &str = include_str!("../release-inputs.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    url: String,
    sha256: String,
    #[serde(default)]
    files: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageSource {
    id: AssetId,
    reference: String,
    digests: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sources {
    schema_version: u32,
    downloads: BTreeMap<String, Vec<Source>>,
    tools: BTreeMap<String, Source>,
    images: Vec<ImageSource>,
}

fn architecture(name: &str) -> Result<Architecture> {
    match name {
        "amd64" => Ok(Architecture::Amd64),
        "arm64" => Ok(Architecture::Arm64),
        _ => Err("release bundles currently support Linux glibc amd64 and arm64".into()),
    }
}

fn sha256(path: &Path) -> Result<String> {
    let mut input = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let mut hex = String::with_capacity(64);
    for byte in hash.finalize() {
        use std::fmt::Write as _;
        write!(hex, "{byte:02x}")?;
    }
    Ok(hex)
}

fn fetch(source: &Source, path: &Path) -> Result<()> {
    run_checked(
        Command::new("curl")
            .args([
                "--fail",
                "--location",
                "--retry",
                "3",
                "--connect-timeout",
                "30",
                "--max-time",
                "600",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--output",
            ])
            .arg(path)
            .arg(&source.url),
    )?;
    if sha256(path)? != source.sha256 {
        return Err(format!("download checksum mismatch: {}", source.url).into());
    }
    Ok(())
}

fn extract(archive: &Path, directory: &Path) -> Result<()> {
    fs::create_dir_all(directory)?;
    run_checked(
        Command::new("tar")
            .arg("-xzf")
            .arg(archive)
            .arg("-C")
            .arg(directory),
    )
}

fn copy_executable(source: &Path, destination: &Path) -> Result<()> {
    if !source.symlink_metadata()?.is_file() {
        return Err(format!("{} is not a regular executable", source.display()).into());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, destination)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn gzip(source: &Path, destination: &Path) -> Result<()> {
    let mut output = GzEncoder::new(File::create(destination)?, Compression::default());
    io::copy(&mut File::open(source)?, &mut output)?;
    output.finish()?.sync_all()?;
    Ok(())
}

/// Acquire checksum-pinned runtime executables and digest-pinned workload images.
/// The node image is built from the release binary by the workflow afterwards.
pub fn prepare(arch: &str, destination: &Path) -> Result<()> {
    architecture(arch)?;
    let sources: Sources = serde_json::from_str(INPUTS)?;
    if sources.schema_version != 1 {
        return Err("unsupported release input schema".into());
    }
    let scratch = tempfile::tempdir()?;
    let host = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let tool = sources
        .tools
        .get(&host)
        .ok_or("no crane binary for build host")?;
    let archive = scratch.path().join("crane.tar.gz");
    fetch(tool, &archive)?;
    let unpacked = scratch.path().join("tool");
    extract(&archive, &unpacked)?;
    let crane = destination.join("tools/crane");
    copy_executable(&unpacked.join("crane"), &crane)?;

    for (index, source) in sources
        .downloads
        .get(arch)
        .ok_or("missing runtime pins")?
        .iter()
        .enumerate()
    {
        let archive = scratch.path().join(format!("runtime-{index}"));
        fetch(source, &archive)?;
        let unpacked = scratch.path().join(format!("unpacked-{index}"));
        if !source.files.contains_key("") {
            extract(&archive, &unpacked)?;
        }
        for (member, relative) in &source.files {
            let input = if member.is_empty() {
                archive.clone()
            } else {
                unpacked.join(member)
            };
            copy_executable(&input, &destination.join(relative))?;
        }
    }
    fs::create_dir_all(destination.join("images"))?;
    for source in &sources.images {
        let digest = source
            .digests
            .get(arch)
            .ok_or("missing image platform pin")?;
        let repository = source
            .reference
            .rsplit_once(':')
            .ok_or("image has no tag")?
            .0;
        let archive = scratch.path().join("image.tar");
        run_checked(
            Command::new(&crane)
                .args([
                    "mutate",
                    "--platform",
                    &format!("linux/{arch}"),
                    "--tag",
                    &source.reference,
                    "--output",
                ])
                .arg(&archive)
                .arg(format!("{repository}@{digest}")),
        )?;
        gzip(
            &archive,
            &destination.join(AssetLayout::default_relative_path(source.id)),
        )?;
    }
    Ok(())
}

fn canonical_tag(tag: &str) -> String {
    tag.strip_prefix("index.docker.io/")
        .map_or_else(|| tag.to_owned(), |tail| format!("docker.io/{tail}"))
}

/// Build an installer-compatible archive, validating every declared image and executable
/// before publishing it. `assets` contains decoded runtime executables and gzip images.
#[allow(clippy::too_many_lines)]
pub fn package(
    version: &str,
    arch: &str,
    binaries: &Path,
    assets: &Path,
    output: &Path,
) -> Result<PathBuf> {
    let target = NodeTarget {
        architecture: architecture(arch)?,
        libc: Libc::Glibc,
    };
    let staging = tempfile::tempdir()?;
    let mut inputs = Vec::new();
    for name in ["diorama", "dioramactl"] {
        inputs.push(BundleInput {
            source: binaries.join(name),
            relative: format!("bin/{name}"),
            executable: true,
        });
    }
    let mut records = Vec::new();
    for entry in catalog() {
        let id = serde_json::to_value(entry.id)?
            .as_str()
            .ok_or("asset ID is not text")?
            .to_owned();
        let relative = AssetLayout::default_relative_path(entry.id);
        let source = assets.join(relative);
        // Hash the raw runtime file as well as its encoded inventory payload. Host
        // installation can then use the executable without a separate decode step.
        inputs.push(BundleInput {
            source: source.clone(),
            relative: relative.into(),
            executable: entry.kind == Kind::Executable,
        });
        let (encoded, encoded_relative) = if entry.encoding == Encoding::Zstd {
            let encoded = staging.path().join(format!("{id}.zst"));
            let mut compressor = zstd::stream::write::Encoder::new(File::create(&encoded)?, 3)?;
            io::copy(&mut File::open(&source)?, &mut compressor)?;
            compressor.finish()?.sync_all()?;
            let relative = format!("payloads/{id}.zst");
            inputs.push(BundleInput {
                source: encoded.clone(),
                relative: relative.clone(),
                executable: false,
            });
            (encoded, relative)
        } else {
            (source, relative.to_owned())
        };
        records.push(json!({"id":entry.id,"delivery":{
            "kind":"bundled","path":encoded_relative,"encoding":entry.encoding,
            "encoded_bytes":fs::metadata(&encoded)?.len(),"sha256":sha256(&encoded)?
        }}));
    }
    let bytes = serde_json::to_vec_pretty(&json!({
        "schema_version":1,"target":{"os":"linux","architecture":arch,"libc":"glibc"},
        "variant":"offline","scope":"supervised-bundle","assets":records
    }))?;
    let inventory = Manifest::decode(&bytes, Limits::default())?.validate_inventory(
        InventoryRequest {
            target,
            variant: Variant::Offline,
            scope: Scope::SupervisedBundle,
        },
        Limits::default(),
    )?;
    let mut session = inventory.decoding_session(DecodeLimits::default())?;
    for (id, path, encoding, size) in inventory.bundled_assets() {
        let source = &inputs
            .iter()
            .find(|input| input.relative == path)
            .ok_or("missing inventory input")?
            .source;
        let payload = read_bounded(source, size)?;
        match encoding {
            Encoding::Identity => {
                inventory.inspect_identity_elf(id, &payload, ElfLimits::default())?;
            },
            Encoding::Zstd => {
                session.inspect_compressed_elf(id, &payload, ElfLimits::default())?;
            },
            Encoding::Gzip => {
                let image = session.verify_crane_image_layer_digests(
                    id,
                    &payload,
                    ArchiveLimits::default(),
                    LayerDecodeLimits::default(),
                )?;
                let expected = if id == AssetId::ImageDiorama {
                    format!("ghcr.io/geoffsee/diorama:{version}")
                } else {
                    catalog()
                        .iter()
                        .find(|entry| entry.id == id)
                        .ok_or("missing catalog image")?
                        .reference
                        .to_owned()
                };
                let tags = image.archive().repo_tags();
                if tags.len() != 1 || canonical_tag(&tags[0]) != expected {
                    return Err(format!(
                        "{id:?}: expected exactly the image tag {expected}, got {tags:?}"
                    )
                    .into());
                }
            },
        }
    }
    for (relative, contents) in [
        ("asset-inventory.json", bytes.as_slice()),
        ("release-inputs.json", INPUTS.as_bytes()),
    ] {
        let source = staging.path().join(relative);
        fs::write(&source, contents)?;
        inputs.push(BundleInput {
            source,
            relative: relative.into(),
            executable: false,
        });
    }
    build_offline_bundle(&BundleSpec {
        version: version.into(),
        architecture: target.architecture,
        libc: target.libc,
        inputs,
        output_dir: output.into(),
    })
    .map_err(Into::into)
}

#[cfg(test)]
#[path = "release_bundle_tests.rs"]
mod tests;
