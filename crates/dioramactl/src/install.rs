use crate::CheckInputs;
use crate::artifact::resolve_target;
use crate::contract::InstallOptions;
use diorama_assets::{Architecture, ArtifactNaming};
use diorama_platform::Libc;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// Name of the metadata file every offline bundle carries at its root.
pub const BUNDLE_MANIFEST: &str = "bundle.manifest";

/// One verified bundle entry: a relative path with its expected digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleEntry {
    pub sha256: String,
    pub path: PathBuf,
    pub executable: bool,
}

/// Parsed bundle metadata. Format (one record per line, `#` comments allowed):
///
/// ```text
/// version=v1.1.8
/// os=linux
/// arch=arm64
/// libc=glibc
/// file <sha256> <relative-path>
/// exec <sha256> <relative-path>
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleManifest {
    pub version: String,
    pub os: String,
    pub arch: String,
    pub libc: String,
    pub entries: Vec<BundleEntry>,
}

pub(crate) fn safe_relative(path: &str) -> Result<PathBuf, String> {
    let p = Path::new(path);
    if path.is_empty() || p.is_absolute() {
        return Err(format!("unsafe bundle path '{path}'"));
    }
    for c in p.components() {
        if !matches!(c, Component::Normal(_)) {
            return Err(format!("unsafe bundle path '{path}'"));
        }
    }
    Ok(p.to_path_buf())
}

impl BundleManifest {
    pub fn parse(text: &str) -> Result<Self, String> {
        let (mut version, mut os, mut arch, mut libc) = (None, None, None, None);
        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if let Some((k, v)) = line.split_once('=') {
                let slot = match k {
                    "version" => &mut version,
                    "os" => &mut os,
                    "arch" => &mut arch,
                    "libc" => &mut libc,
                    other => return Err(format!("unknown manifest key '{other}'")),
                };
                *slot = Some(v.to_string());
            } else {
                let mut parts = line.splitn(3, ' ');
                let (role, digest, path) = (parts.next(), parts.next(), parts.next());
                let (Some(role), Some(digest), Some(path)) = (role, digest, path) else {
                    return Err(format!("malformed manifest line '{line}'"));
                };
                let executable = match role {
                    "file" => false,
                    "exec" => true,
                    other => return Err(format!("unknown manifest record '{other}'")),
                };
                if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(format!("invalid sha256 for '{path}'"));
                }
                let rel = safe_relative(path)?;
                if !seen.insert(rel.clone()) {
                    return Err(format!("duplicate manifest entry '{path}'"));
                }
                entries.push(BundleEntry {
                    sha256: digest.to_ascii_lowercase(),
                    path: rel,
                    executable,
                });
            }
        }
        let missing = |n: &str| format!("manifest missing '{n}'");
        Ok(Self {
            version: version.ok_or_else(|| missing("version"))?,
            os: os.ok_or_else(|| missing("os"))?,
            arch: arch.ok_or_else(|| missing("arch"))?,
            libc: libc.ok_or_else(|| missing("libc"))?,
            entries,
        })
    }

    pub fn render(&self) -> String {
        let mut out = format!(
            "version={}\nos={}\narch={}\nlibc={}\n",
            self.version, self.os, self.arch, self.libc
        );
        for e in &self.entries {
            let role = if e.executable { "exec" } else { "file" };
            let _ = std::fmt::Write::write_fmt(
                &mut out,
                format_args!("{role} {} {}\n", e.sha256, e.path.display()),
            );
        }
        out
    }
}

pub(crate) fn arch_name(a: Architecture) -> &'static str {
    match a {
        Architecture::Amd64 => "amd64",
        Architecture::Arm64 => "arm64",
        Architecture::ArmV7 => "arm",
        Architecture::Riscv64 => "riscv64",
    }
}

pub(crate) fn libc_name(l: Libc) -> &'static str {
    match l {
        Libc::Glibc => "glibc",
        Libc::Musl => "musl",
    }
}

fn elf_machine(a: Architecture) -> u16 {
    match a {
        Architecture::Amd64 => 62,
        Architecture::Arm64 => 183,
        Architecture::ArmV7 => 40,
        Architecture::Riscv64 => 243,
    }
}

/// Checks the ELF identity of an executable against the target architecture.
pub(crate) fn check_elf(path: &Path, arch: Architecture) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" {
        return Err(format!("{} is not an ELF executable", path.display()));
    }
    let raw = [bytes[18], bytes[19]];
    let machine = if bytes[5] == 2 {
        u16::from_be_bytes(raw)
    } else {
        u16::from_le_bytes(raw)
    };
    if machine != elf_machine(arch) {
        return Err(format!(
            "{} is built for machine {machine}, expected {}",
            path.display(),
            elf_machine(arch)
        ));
    }
    Ok(())
}

pub(crate) fn sha256_hex(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = io::Read::read(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let mut hex = String::new();
    for b in hasher.finalize() {
        let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{b:02x}"));
    }
    Ok(hex)
}

/// Lists archive members and rejects traversal, absolute paths and links.
pub(crate) fn audit_archive(archive: &Path) -> Result<(), String> {
    let out = Command::new("tar")
        .arg("-tzvf")
        .arg(archive)
        .output()
        .map_err(|e| format!("tar command failed: {e}"))?;
    if !out.status.success() {
        return Err("corrupt or unreadable archive".to_string());
    }
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let kind = line.chars().next().unwrap_or('?');
        if !matches!(kind, '-' | 'd') {
            return Err(format!("unsupported archive member type in '{line}'"));
        }
    }
    let names = Command::new("tar")
        .arg("-tzf")
        .arg(archive)
        .output()
        .map_err(|e| format!("tar command failed: {e}"))?;
    for name in String::from_utf8_lossy(&names.stdout).lines() {
        let name = name.trim_start_matches("./").trim_end_matches('/');
        if name.is_empty() || name == "." {
            continue;
        }
        safe_relative(name)?;
    }
    Ok(())
}

fn copy_archive(source: &Path) -> io::Result<(tempfile::TempDir, PathBuf)> {
    let staging = tempfile::TempDir::new()?;
    let archive = staging.path().join("bundle.tar.gz");
    fs::copy(source, &archive)?;
    Ok((staging, archive))
}

/// Verifies a staged bundle: manifest metadata vs. target, digests, ELF identity,
/// and the absence of unlisted files. Performs no mutation outside `staged`.
pub fn verify_staged_bundle(
    staged: &Path,
    arch: Architecture,
    libc: Libc,
) -> Result<BundleManifest, String> {
    let text = fs::read_to_string(staged.join(BUNDLE_MANIFEST))
        .map_err(|e| format!("missing or unreadable {BUNDLE_MANIFEST}: {e}"))?;
    let manifest = BundleManifest::parse(&text)?;
    if manifest.os != "linux"
        || manifest.arch != arch_name(arch)
        || manifest.libc != libc_name(libc)
    {
        return Err(format!(
            "bundle metadata {}/{}/{} does not match target linux/{}/{}",
            manifest.os,
            manifest.arch,
            manifest.libc,
            arch_name(arch),
            libc_name(libc)
        ));
    }
    let listed: BTreeSet<&PathBuf> = manifest.entries.iter().map(|e| &e.path).collect();
    for entry in &manifest.entries {
        let full = staged.join(&entry.path);
        let actual = sha256_hex(&full)
            .map_err(|e| format!("missing bundle file {}: {e}", entry.path.display()))?;
        if actual != entry.sha256 {
            return Err(format!("digest mismatch for {}", entry.path.display()));
        }
        if entry.executable {
            check_elf(&full, arch)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&full)
                    .map_err(|e| e.to_string())?
                    .permissions()
                    .mode()
                    & 0o7777;
                if mode != 0o755 {
                    return Err(format!(
                        "invalid executable permissions for {}: expected 755, observed {mode:o}",
                        entry.path.display()
                    ));
                }
            }
        }
    }
    let mut stack = vec![staged.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for item in fs::read_dir(&dir).map_err(|e| e.to_string())? {
            let path = item.map_err(|e| e.to_string())?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(staged)
                    .map_err(|e| e.to_string())?
                    .to_path_buf();
                if rel != Path::new(BUNDLE_MANIFEST) && !listed.contains(&rel) {
                    return Err(format!("unlisted file in bundle: {}", rel.display()));
                }
            }
        }
    }
    Ok(manifest)
}

#[cfg(unix)]
fn publish(staged: &Path, target: &Path, manifest: &BundleManifest) -> io::Result<()> {
    use rustix::fs::{Mode, OFlags, mkdirat, open, openat, renameat};
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    fs::create_dir_all(target)?;
    let root = fs::File::from(open(target, directory_flags, Mode::empty())?);
    let source = fs::File::open(staged)?;
    let rels = manifest
        .entries
        .iter()
        .map(|e| e.path.clone())
        .chain(std::iter::once(PathBuf::from(BUNDLE_MANIFEST)));
    // Open every destination parent before publishing any file. Directory handles
    // pin the verified parents, so later pathname/symlink substitution cannot
    // redirect rename into an unrelated directory.
    let mut destinations = Vec::new();
    for rel in rels {
        let mut parent = root.try_clone()?;
        let mut components = rel.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(io::Error::other("unsafe destination path"));
            };
            if components.peek().is_none() {
                destinations.push((rel.clone(), parent, name.to_os_string()));
                break;
            }
            match mkdirat(&parent, name, Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {},
                Err(error) => return Err(error.into()),
            }
            parent = fs::File::from(openat(&parent, name, directory_flags, Mode::empty())?);
        }
    }
    for (rel, parent, name) in destinations {
        renameat(&source, &rel, &parent, &name)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn publish(_staged: &Path, _target: &Path, _manifest: &BundleManifest) -> io::Result<()> {
    Err(io::Error::other("offline host installation requires Unix"))
}

/// Import a platform-checked image from private staging without publishing service files.
fn execute_container_install(
    options: &InstallOptions,
) -> io::Result<crate::container::ContainerInstallResult> {
    use crate::docker_engine::DockerEngine;
    let architecture = DockerEngine::architecture()?;
    install_container_with_engine(options, &mut DockerEngine, architecture)
}

/// Install through a connected Linux engine, using its observed architecture to
/// validate an offline bundle before importing the image or creating resources.
#[allow(clippy::too_many_lines)]
pub fn install_container_with_engine(
    options: &InstallOptions,
    engine: &mut dyn crate::container::ContainerEngineClient,
    engine_arch: Architecture,
) -> io::Result<crate::container::ContainerInstallResult> {
    use crate::container::ContainerInstallParams;
    use crate::container_image::install_selected_container;
    use diorama_assets::{
        DecodeLimits, Delivery, InventoryRequest, Limits, Manifest, Scope, Variant,
    };
    fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }
    let mut extra_env = vec![
        (
            "KUBESOLO_CPU_MANAGER_POLICY".into(),
            options.cpu_manager_policy.clone(),
        ),
        (
            "KUBESOLO_D2K_NAMESPACE".into(),
            options.d2k_namespace.clone(),
        ),
        ("KUBESOLO_DEBUG".into(), options.debug.to_string()),
        (
            "KUBESOLO_LOCAL_STORAGE".into(),
            options.local_storage.to_string(),
        ),
        (
            "KUBESOLO_PPROF_SERVER".into(),
            options.pprof_server.to_string(),
        ),
        (
            "KUBESOLO_PORTAINER_EDGE_ASYNC".into(),
            options.portainer_edge_async.to_string(),
        ),
    ];
    for (key, value) in [
        (
            "KUBESOLO_APISERVER_EXTRA_SANS",
            &options.apiserver_extra_sans,
        ),
        ("KUBESOLO_NODE_IP", &options.node_ip),
        ("KUBESOLO_MTU", &options.mtu),
        ("KUBESOLO_PORTAINER_EDGE_ID", &options.portainer_edge_id),
        ("KUBESOLO_PORTAINER_EDGE_KEY", &options.portainer_edge_key),
        (
            "KUBESOLO_PORTAINER_EDGE_IMAGE",
            &options.portainer_edge_image,
        ),
        (
            "KUBESOLO_CPU_MANAGER_POLICY_OPTIONS",
            &options.cpu_manager_policy_options,
        ),
        ("KUBESOLO_RESERVED_CPUS", &options.reserved_cpus),
        ("KUBESOLO_SYSTEM_RESERVED", &options.system_reserved),
    ] {
        if let Some(value) = value {
            extra_env.push((key.into(), value.clone()));
        }
    }
    let params = ContainerInstallParams {
        instance_name: options.name.clone(),
        image: String::new(),
        mtu: options
            .mtu
            .as_ref()
            .map(|s| s.parse::<u32>().map_err(invalid))
            .transpose()?,
        d2k: options.d2k,
        container_ports: options.container_ports.clone(),
        extra_env,
        apiserver_host_port: None,
        d2k_host_port: None,
    };
    let Some(path) = options.offline_install.as_ref() else {
        return install_selected_container(engine, options, params, None).map_err(invalid);
    };
    // Explicit custom images retain their documented registry-pull behavior.
    if options
        .container_image
        .as_ref()
        .is_some_and(|s| !s.is_empty())
    {
        return install_selected_container(engine, options, params, None).map_err(invalid);
    }
    let parsed =
        ArtifactNaming::parse_node_archive(&path.file_name().unwrap_or_default().to_string_lossy())
            .map_err(invalid)?;
    if parsed.variant.variant != Variant::Offline || parsed.variant.architecture != engine_arch {
        return Err(invalid(
            "offline bundle must match the Linux Docker Engine architecture",
        ));
    }
    let (_snapshot, archive) = copy_archive(path)?;
    audit_archive(&archive).map_err(invalid)?;
    let staged = tempfile::tempdir()?;
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(&archive)
        .arg("-C")
        .arg(staged.path())
        .status()?;
    if !status.success() {
        return Err(invalid("offline container bundle extraction failed"));
    }
    verify_staged_bundle(
        staged.path(),
        parsed.variant.architecture,
        parsed.variant.libc,
    )
    .map_err(invalid)?;
    let limits = Limits::default();
    let inventory_path = staged.path().join("asset-inventory.json");
    if fs::metadata(&inventory_path)?.len() > limits.manifest_bytes as u64 {
        return Err(invalid("asset inventory exceeds the manifest limit"));
    }
    let inventory = Manifest::decode(&fs::read(inventory_path)?, limits)
        .map_err(invalid)?
        .validate_inventory(
            InventoryRequest {
                target: parsed.variant.node_target(),
                variant: Variant::Offline,
                scope: Scope::SupervisedBundle,
            },
            limits,
        )
        .map_err(invalid)?;
    let image_path = inventory
        .assets()
        .find_map(|(id, delivery)| match delivery {
            Delivery::Bundled { path, .. } if id == diorama_assets::AssetId::ImageDiorama => {
                Some(path.clone())
            },
            _ => None,
        })
        .ok_or_else(|| invalid("offline inventory does not declare a bundled node image"))?;
    let image_path = staged.path().join(image_path);
    if fs::metadata(&image_path)?.len() > limits.encoded_asset_bytes {
        return Err(invalid("node image exceeds the encoded asset limit"));
    }
    let bytes = fs::read(image_path)?;
    let mut session = inventory
        .decoding_session(DecodeLimits::default())
        .map_err(invalid)?;
    install_selected_container(engine, options, params, Some((&mut session, &bytes)))
        .map_err(invalid)
}

#[allow(clippy::too_many_lines)] // linear fail-fast workflow with per-step diagnostics
pub fn execute_install(
    options: &InstallOptions,
    inputs: &mut dyn CheckInputs,
    _stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    if options.run_mode == "container" {
        return match execute_container_install(options) {
            Ok(result) => {
                writeln!(
                    stderr,
                    "Started container {} with API port {}; live node readiness is not qualified",
                    result.container_name, result.apiserver_port
                )?;
                Ok(0)
            },
            Err(err) => {
                writeln!(stderr, "error: container installation failed: {err}")?;
                Ok(1)
            },
        };
    }
    if options.run_mode != "service" {
        writeln!(stderr, "error: unsupported run mode '{}'", options.run_mode)?;
        return Ok(1);
    }
    writeln!(
        stderr,
        "\n  dioramactl  install\n\n  > Resolving host target"
    )?;

    let evidence = match inputs.discover() {
        Ok(evidence) => evidence,
        Err(err) => {
            writeln!(
                stderr,
                "  [fail] system detection: {err}; obtain supported host observations before retrying"
            )?;
            return Ok(1);
        },
    };

    let host_target = match resolve_target(None, None, Some(&evidence)) {
        Ok(t) => t,
        Err(err) => {
            writeln!(stderr, "  [fail] system detection: {err}")?;
            return Ok(1);
        },
    };

    let Some(offline_path) = &options.offline_install else {
        writeln!(
            stderr,
            "error: command 'install' is not yet implemented (online install; use --offline-install)"
        )?;
        return Ok(1);
    };

    let filename = offline_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let parsed = match ArtifactNaming::parse_node_archive(&filename) {
        Ok(p) => p,
        Err(err) => {
            writeln!(stderr, "  [fail] bundle validation: {err}")?;
            return Ok(1);
        },
    };

    if parsed.variant.architecture != host_target.architecture
        || parsed.variant.libc != host_target.libc
    {
        writeln!(
            stderr,
            "  [fail] bundle validation: mismatched architecture or libc"
        )?;
        return Ok(1);
    }
    writeln!(stderr, "  [ok] Bundle matches host architecture")?;

    // Everything below up to `publish` touches only a private staging directory.
    let (_archive_staging, checked_archive) = match copy_archive(offline_path) {
        Ok(archive) => archive,
        Err(err) => {
            writeln!(stderr, "  [fail] archive staging: {err}")?;
            return Ok(1);
        },
    };
    if let Err(err) = audit_archive(&checked_archive) {
        writeln!(stderr, "  [fail] bundle validation: {err}")?;
        return Ok(1);
    }
    let target_dir = &options.path;
    let parent = target_dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = match fs::create_dir_all(parent).and_then(|()| tempfile::TempDir::new_in(parent))
    {
        Ok(s) => s,
        Err(err) => {
            writeln!(stderr, "  [fail] extraction: {err}")?;
            return Ok(1);
        },
    };
    match Command::new("tar")
        .arg("-xzf")
        .arg(&checked_archive)
        .arg("-C")
        .arg(staging.path())
        .status()
    {
        Ok(status) if status.success() => {},
        Ok(status) => {
            writeln!(
                stderr,
                "  [fail] extraction: tar exited with status {status}"
            )?;
            return Ok(1);
        },
        Err(err) => {
            writeln!(stderr, "  [fail] extraction: tar command failed: {err}")?;
            return Ok(1);
        },
    }
    let manifest = match verify_staged_bundle(
        staging.path(),
        parsed.variant.architecture,
        parsed.variant.libc,
    ) {
        Ok(m) => m,
        Err(err) => {
            writeln!(
                stderr,
                "  [fail] bundle validation: {err}; no installation changes were made"
            )?;
            return Ok(1);
        },
    };
    if let Err(err) = publish(staging.path(), target_dir, &manifest) {
        writeln!(stderr, "  [fail] extraction: {err}")?;
        return Ok(1);
    }
    writeln!(
        stderr,
        "  [ok] Verified and extracted offline bundle {} ({} files)",
        manifest.version,
        manifest.entries.len()
    )?;
    Ok(0)
}

#[cfg(test)]
mod archive_snapshot_tests {
    use super::*;

    #[test]
    fn replacing_the_input_cannot_change_the_archive_audited_and_extracted() {
        let source = tempfile::tempdir().unwrap();
        let payload = source.path().join("payload");
        fs::write(&payload, b"checked payload").unwrap();
        let archive = source.path().join("input.tar.gz");
        assert!(
            Command::new("tar")
                .arg("-czf")
                .arg(&archive)
                .arg("-C")
                .arg(source.path())
                .arg("payload")
                .status()
                .unwrap()
                .success()
        );
        let (_private_copy, checked) = copy_archive(&archive).unwrap();
        audit_archive(&checked).unwrap();
        fs::remove_file(&archive).unwrap();
        fs::write(&archive, b"replacement is not the audited archive").unwrap();
        let destination = tempfile::tempdir().unwrap();
        assert!(
            Command::new("tar")
                .arg("-xzf")
                .arg(&checked)
                .arg("-C")
                .arg(destination.path())
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            fs::read(destination.path().join("payload")).unwrap(),
            b"checked payload"
        );
    }
}
