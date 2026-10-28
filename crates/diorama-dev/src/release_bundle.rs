//! Release-only acquisition and packaging of complete offline node bundles.

use crate::{Result, read_bounded, run_checked};
use diorama_assets::{
    Architecture, ArchiveLimits, AssetId, AssetLayout, BundleKind, BundleMetadata, Capability,
    DecodeLimits, ElfLimits, Encoding, InventoryRequest, Kind, LayerDecodeLimits, Libc, Limits,
    Manifest, NodeTarget, Scope, Variant, catalog,
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
    local_path_runtime: String,
    local_path_reference: String,
    local_path_license_sha256: String,
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
    if !sources.local_path_runtime.contains("@sha256:")
        || sources.local_path_reference
            != catalog()
                .iter()
                .find(|e| e.id == AssetId::ImageLocalPath)
                .ok_or("missing local-path catalog entry")?
                .reference
        || sources.local_path_license_sha256.len() != 64
    {
        return Err("invalid local-path provenance".into());
    }
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
    for source in sources.images.iter().filter(|s| {
        matches!(
            s.id,
            AssetId::ImageCoredns | AssetId::ImagePause | AssetId::ImageLocalPathHelper
        )
    }) {
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
    kind: BundleKind,
    addon: Option<Capability>,
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
    let bundle = BundleMetadata {
        kind,
        version: version.into(),
        capabilities: if kind == BundleKind::Addon {
            vec![addon.ok_or("addon capability is required")?]
        } else {
            vec![Capability::Core, Capability::LocalStorage]
        },
    };
    bundle.validate()?;
    let staging = tempfile::tempdir()?;
    let mut inputs = Vec::new();
    for name in ["diorama", "dioramactl"]
        .into_iter()
        .filter(|_| kind == BundleKind::Host)
    {
        inputs.push(BundleInput {
            source: binaries.join(name),
            relative: format!("bin/{name}"),
            executable: true,
        });
    }
    if kind == BundleKind::Host {
        inputs.push(BundleInput {
            source: assets.join("bin/ctr"),
            relative: "bin/ctr".into(),
            executable: true,
        });
    }
    let mut records = Vec::new();
    for entry in catalog().iter().filter(|e| bundle.includes(e.id)) {
        let relative = AssetLayout::default_relative_path(entry.id);
        let source = assets.join(relative);
        // The installed executable is also its inventory payload; the outer archive
        // compresses it once, with no second encoded copy to ship or retain.
        inputs.push(BundleInput {
            source: source.clone(),
            relative: relative.into(),
            executable: entry.kind == Kind::Executable,
        });
        let encoding = if entry.kind == Kind::Executable {
            Encoding::Identity
        } else {
            entry.encoding
        };
        records.push(json!({"id":entry.id,"delivery":{
            "kind":"bundled","path":relative,"encoding":encoding,
            "encoded_bytes":fs::metadata(&source)?.len(),"sha256":sha256(&source)?
        }}));
    }
    let bytes = serde_json::to_vec_pretty(&json!({
        "schema_version":2,"bundle":bundle,"target":{"os":"linux","architecture":arch,"libc":"glibc"},
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
                let expected = bundle
                    .image_reference(id)
                    .ok_or("missing image reference")?;
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
    if kind == BundleKind::Addon {
        let addon_name = if addon == Some(Capability::PortainerAgent) {
            "portainer-agent"
        } else {
            "d2k"
        };
        let id = if addon_name == "d2k" {
            AssetId::ImageD2k
        } else {
            AssetId::ImagePortainerAgent
        };
        let settings = diorama_addon::Settings {
            addon: addon_name.into(),
            image: bundle
                .image_reference(id)
                .ok_or("missing installer image")?,
            namespace: if addon_name == "d2k" {
                "d2k"
            } else {
                "portainer"
            }
            .into(),
            node: "replace-with-loaded-node".into(),
        };
        let job = serde_json::to_vec_pretty(&diorama_addon::installation_job(&settings)?)?;
        let source = staging.path().join("install-job.json");
        fs::write(&source, &job)?;
        inputs.push(BundleInput {
            source,
            relative: "install-job.json".into(),
            executable: false,
        });
        fs::create_dir_all(output)?;
        fs::write(
            output.join(format!(
                "diorama-{version}-linux-{arch}-{addon_name}-job.json"
            )),
            &job,
        )?;
    }
    if kind == BundleKind::Host {
        let marker = staging.path().join("offline");
        fs::write(&marker, b"schema-version=2\n")?;
        inputs.push(BundleInput {
            source: marker,
            relative: "images/offline".into(),
            executable: false,
        });
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
    let provenance = assets.join("build-provenance.json");
    if provenance.is_file() {
        inputs.push(BundleInput {
            source: provenance.clone(),
            relative: "build-provenance.json".into(),
            executable: false,
        });
        fs::create_dir_all(output)?;
        fs::copy(
            &provenance,
            output.join(format!("diorama-{version}-linux-{arch}-provenance.json")),
        )?;
    }
    let archive = build_offline_bundle(&BundleSpec {
        version: version.into(),
        architecture: target.architecture,
        libc: target.libc,
        inputs: inputs.clone(),
        output_dir: output.into(),
    })
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    let bytes = fs::metadata(&archive)?.len();
    let ceiling = if arch == "arm64" {
        120_000_000
    } else {
        140_000_000
    };
    if kind == BundleKind::Host {
        enforce_host_ceiling(&archive, ceiling)?;
    }
    let breakdown = inputs
        .iter()
        .map(|i| Ok(json!({"path":i.relative,"bytes":fs::metadata(&i.source)?.len()})))
        .collect::<Result<Vec<_>>>()?;
    fs::write(
        output.join(format!(
            "{}-sizes.json",
            archive
                .file_name()
                .ok_or("missing archive filename")?
                .to_string_lossy()
        )),
        serde_json::to_vec_pretty(
            &json!({"archive_bytes":bytes,"host_ceiling_bytes":ceiling,"assets":breakdown}),
        )?,
    )?;
    Ok(archive)
}

#[cfg(test)]
#[path = "release_bundle_tests.rs"]
mod tests;

fn enforce_host_ceiling(archive: &Path, ceiling: u64) -> Result<()> {
    let bytes = fs::metadata(archive)?.len();
    if bytes > ceiling {
        fs::remove_file(archive)?;
        return Err(format!("host bundle {bytes} bytes exceeds ceiling {ceiling}").into());
    }
    Ok(())
}

/// Build derived images from pinned bases, then export canonical crane archives.
/// A local build registry avoids a dependency on publishing credentials.
#[allow(clippy::too_many_lines)] // Each derived image uses the same pinned build/export sequence.
pub fn build_images(
    version: &str,
    arch: &str,
    installer: &Path,
    assets: &Path,
    engine: &str,
    registry: &str,
) -> Result<()> {
    architecture(arch)?;
    let sources: Sources = serde_json::from_str(INPUTS)?;
    let context = tempfile::tempdir()?;
    fs::create_dir(context.path().join("licenses"))?;
    fs::write(
        context
            .path()
            .join("licenses/local-path-provisioner.LICENSE"),
        include_bytes!("../../../container/licenses/local-path-provisioner.LICENSE"),
    )?;
    if sha256(
        &context
            .path()
            .join("licenses/local-path-provisioner.LICENSE"),
    )? != sources.local_path_license_sha256
    {
        return Err("local-path license checksum mismatch".into());
    }
    copy_executable(installer, &context.path().join("diorama-addon"))?;
    let crane = assets.join("tools/crane");
    let mut provenance = Vec::new();
    for (id, name, recipe) in [
        (
            AssetId::ImageLocalPath,
            "local-path",
            include_str!("../../../container/Dockerfile.local-path"),
        ),
        (
            AssetId::ImagePortainerAgent,
            "portainer-agent",
            include_str!("../../../container/Dockerfile.addon"),
        ),
        (
            AssetId::ImageD2k,
            "d2k",
            include_str!("../../../container/Dockerfile.addon"),
        ),
    ] {
        let source = sources
            .images
            .iter()
            .find(|s| s.id == id)
            .ok_or("missing upstream image")?;
        let repository = source
            .reference
            .rsplit_once(':')
            .ok_or("missing upstream tag")?
            .0;
        let upstream = format!(
            "{repository}@{}",
            source.digests.get(arch).ok_or("missing platform pin")?
        );
        let reference = if id == AssetId::ImageLocalPath {
            sources.local_path_reference.clone()
        } else {
            format!("ghcr.io/geoffsee/diorama-addon-{name}:{version}")
        };
        let local = format!("{registry}/diorama-{name}:{version}");
        fs::write(context.path().join("Dockerfile"), recipe)?;
        run_checked(
            Command::new(engine)
                .args([
                    "build",
                    "--platform",
                    &format!("linux/{arch}"),
                    "--build-arg",
                    &format!("UPSTREAM={upstream}"),
                    "--build-arg",
                    &format!("RUNTIME={}", sources.local_path_runtime),
                    "--tag",
                    &local,
                ])
                .arg(context.path()),
        )?;
        run_checked(Command::new(engine).args(["push", &local]))?;
        let archive = context.path().join("image.tar");
        run_checked(
            Command::new(&crane)
                .args([
                    "mutate",
                    "--insecure",
                    "--platform",
                    &format!("linux/{arch}"),
                    "--tag",
                    &reference,
                    "--output",
                ])
                .arg(&archive)
                .arg(&local),
        )?;
        let destination = assets.join(AssetLayout::default_relative_path(id));
        gzip(&archive, &destination)?;
        if id == AssetId::ImageLocalPath && fs::metadata(&destination)?.len() >= 25_000_000 {
            return Err("local-path provisioner exceeds the 25 MB compressed ceiling".into());
        }
        provenance.push(json!({"image":reference,"upstream":upstream,"runtime":if id == AssetId::ImageLocalPath {Some(&sources.local_path_runtime)} else {None},"recipe_sha256":sha256(&context.path().join("Dockerfile"))?,"archive_sha256":sha256(&destination)?,"archive_bytes":fs::metadata(destination)?.len(),"installer_sha256":sha256(installer)?}));
    }
    fs::write(
        assets.join("build-provenance.json"),
        serde_json::to_vec_pretty(
            &json!({"schema_version":1,"version":version,"architecture":arch,"images":provenance}),
        )?,
    )?;
    Ok(())
}
