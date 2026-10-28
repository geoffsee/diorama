//! Shared pre-mutation validation for new bundles and legacy combined archives.
use diorama_assets::{
    ArchiveLimits, AssetLayout, BundleKind, DeclaredInventory, DecodeLimits, ElfLimits, Encoding,
    InventoryRequest, Kind, LayerDecodeLimits, Limits, Manifest, ParsedNodeArchive, Scope, Variant,
    catalog,
};
use std::{fmt::Write as _, fs, path::Path};

#[allow(clippy::too_many_lines)] // One pre-mutation pass shares decoding budgets across all assets.
pub fn validate(
    root: &Path,
    parsed: &ParsedNodeArchive,
    kind: BundleKind,
) -> Result<Option<DeclaredInventory>, String> {
    let manifest = crate::install::verify_staged_bundle(
        root,
        parsed.variant.architecture,
        parsed.variant.libc,
    )?;
    if manifest.version != parsed.version
        || parsed.prefix != "diorama"
        || parsed.variant.variant != Variant::Offline
    {
        return Err("bundle version, prefix or offline variant does not match its filename".into());
    }
    let path = root.join("asset-inventory.json");
    // Historical local bundles predate the JSON inventory.
    if !path.exists() && parsed.bundle_suffix.is_none() && kind == BundleKind::Host {
        return Ok(None);
    }
    let limits = Limits::default();
    if fs::metadata(&path).map_err(|e| e.to_string())?.len() > limits.manifest_bytes as u64 {
        return Err("asset inventory exceeds limit".into());
    }
    let inventory = Manifest::decode(&fs::read(path).map_err(|e| e.to_string())?, limits)
        .and_then(|m| {
            m.validate_inventory(
                InventoryRequest {
                    target: parsed.variant.node_target(),
                    variant: Variant::Offline,
                    scope: Scope::SupervisedBundle,
                },
                limits,
            )
        })
        .map_err(|e| e.to_string())?;
    match (inventory.bundle(), parsed.bundle_suffix.as_deref()) {
        (Some(bundle), Some(suffix))
            if bundle.version == manifest.version
                && bundle.suffix() == suffix
                && bundle.kind == kind => {},
        (None, None) if kind != BundleKind::Addon => {},
        _ => {
            return Err(format!(
                "bundle kind/version is incompatible with {kind:?} installation; select the matching offline archive"
            ));
        },
    }
    if inventory.bundle().is_none() {
        // Preserve the legacy path: the outer manifest covers host files; container
        // installation separately verifies the selected node image and its layers.
        return Ok(Some(inventory));
    }
    if kind == BundleKind::Addon
        && !manifest
            .entries
            .iter()
            .any(|entry| entry.path == Path::new("install-job.json"))
    {
        return Err("add-on bundle is missing its verified install-job.json".into());
    }
    if kind == BundleKind::Host {
        for name in ["bin/diorama", "bin/dioramactl"]
            .into_iter()
            .chain(inventory.bundle().map(|_| "bin/ctr"))
        {
            if !manifest
                .entries
                .iter()
                .any(|e| e.path == Path::new(name) && e.executable)
            {
                return Err(format!("missing required host executable {name}"));
            }
        }
    }
    let mut session = inventory
        .decoding_session(DecodeLimits::default())
        .map_err(|e| e.to_string())?;
    for (id, path, encoding, size) in inventory.bundled_assets() {
        let source = root.join(path);
        if fs::metadata(&source).map_err(|e| e.to_string())?.len() != size {
            return Err(format!("invalid size for {path}"));
        }
        let payload = fs::read(source).map_err(|e| e.to_string())?;
        match encoding {
            Encoding::Identity => {
                if kind == BundleKind::Host && path != AssetLayout::default_relative_path(id) {
                    return Err(format!(
                        "host inventory must verify the installed executable path: {}",
                        AssetLayout::default_relative_path(id)
                    ));
                }
                inventory
                    .inspect_identity_elf(id, &payload, ElfLimits::default())
                    .map_err(|e| e.to_string())?;
            },
            Encoding::Zstd => {
                let observed = session
                    .inspect_compressed_elf(id, &payload, ElfLimits::default())
                    .map_err(|e| e.to_string())?;
                let raw = root.join(AssetLayout::default_relative_path(id));
                let mut expected = String::with_capacity(64);
                for byte in observed.decoded_observation().decoded_sha256() {
                    write!(expected, "{byte:02x}").map_err(|e| e.to_string())?;
                }
                if crate::install::sha256_hex(&raw).map_err(|e| e.to_string())? != expected {
                    return Err(format!(
                        "raw executable differs from verified payload: {}",
                        raw.display()
                    ));
                }
            },
            Encoding::Gzip => {
                let image = session
                    .verify_crane_image_layer_digests(
                        id,
                        &payload,
                        ArchiveLimits::default(),
                        LayerDecodeLimits::default(),
                    )
                    .map_err(|e| e.to_string())?;
                // Legacy tags retain their historical validation; schema two binds release tags.
                if let Some(bundle) = inventory.bundle() {
                    let expected = bundle
                        .image_reference(id)
                        .ok_or("missing image reference")?;
                    let tags = image.archive().repo_tags();
                    if tags.len() != 1
                        || tags[0].replace("index.docker.io/", "docker.io/") != expected
                    {
                        return Err(format!(
                            "{id:?}: expected image tag {expected}, got {tags:?}"
                        ));
                    }
                }
            },
        }
        if kind == BundleKind::Host
            && catalog()
                .iter()
                .any(|e| e.id == id && e.kind == Kind::Executable)
        {
            let relative = AssetLayout::default_relative_path(id);
            if !manifest
                .entries
                .iter()
                .any(|e| e.path == Path::new(relative) && e.executable)
            {
                return Err(format!("missing executable mode for {relative}"));
            }
        }
    }
    Ok(Some(inventory))
}

pub fn check_optional_images(root: &Path, options: &crate::InstallOptions) -> Result<(), String> {
    for (enabled, path, name) in [
        (options.d2k, "images/d2k.tar.gz", "D2K"),
        (
            options
                .portainer_edge_id
                .as_ref()
                .is_some_and(|v| !v.is_empty()),
            "images/portainer-agent.tar.gz",
            "Portainer Agent",
        ),
    ] {
        if enabled && !root.join(path).is_file() {
            return Err(format!(
                "{name} is enabled but its image is unavailable offline. Install core with the integration disabled, then use dioramactl addon load and the add-on Job manifest."
            ));
        }
    }
    Ok(())
}

/// Copy the archive before auditing and extracting it, so callers cannot swap checked bytes.
pub fn stage(source: &Path, root: &Path) -> Result<(), String> {
    let snapshot = tempfile::tempdir().map_err(|e| e.to_string())?;
    let archive = snapshot.path().join("bundle.tar.gz");
    fs::copy(source, &archive).map_err(|e| e.to_string())?;
    crate::install::audit_archive(&archive)?;
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let status = std::process::Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(root)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("offline bundle extraction failed".into());
    }
    Ok(())
}
