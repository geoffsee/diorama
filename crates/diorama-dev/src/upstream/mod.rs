//! Explicit preparation of hash-pinned upstream inputs.
use flate2::read::GzDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tar::Archive;
mod generation;
pub(crate) mod kubernetes;
pub(crate) type Result<T> = crate::Result<T>;
pub(crate) fn fail<T>(message: impl Into<String>) -> Result<T> {
    Err(message.into().into())
}
pub(crate) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace exists")
}
pub(crate) fn digest(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}
pub(crate) fn hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    data.iter()
        .flat_map(|b| {
            [
                char::from(DIGITS[usize::from(b >> 4)]),
                char::from(DIGITS[usize::from(b & 15)]),
            ]
        })
        .collect()
}
pub(crate) fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string: {key}").into())
}
pub(crate) fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array: {key}").into())
}
pub(crate) fn strict_json(data: &[u8]) -> Result<Value> {
    crate::json::parse(data)
}
pub(crate) fn validate_record(record: &Value) -> Result<()> {
    let hash = text(record, "sha256")?;
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || record["bytes"].as_u64().is_none_or(|n| n == 0)
    {
        return fail("invalid input digest or length");
    }
    Ok(())
}
pub(crate) fn validate_bytes(data: &[u8], record: &Value, label: &str) -> Result<()> {
    validate_record(record)?;
    if record["bytes"].as_u64() != Some(u64::try_from(data.len())?)
        || text(record, "sha256")? != digest(data)
    {
        return fail(format!("length or SHA-256 mismatch: {label}"));
    }
    Ok(())
}
pub(crate) fn safe_relative(name: &str) -> Result<Vec<&str>> {
    let parts: Vec<_> = name.trim_end_matches('/').split('/').collect();
    if name.starts_with('/')
        || name.contains('\\')
        || parts.iter().any(|p| matches!(*p, "" | "." | ".."))
    {
        return fail(format!("unsafe relative path: {name}"));
    }
    Ok(parts)
}
pub(crate) fn owned_path(root: &Path, name: &str) -> Result<PathBuf> {
    let mut p = root.to_path_buf();
    for part in safe_relative(name)? {
        p.push(part);
        if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
            return fail(format!(
                "symlink inside selected directory: {}",
                p.display()
            ));
        }
    }
    Ok(p)
}
pub(crate) fn atomic_write(root: &Path, name: &str, data: &[u8], executable: bool) -> Result<()> {
    check_cancelled()?;
    let p = owned_path(root, name)?;
    let parent = p.parent().ok_or("missing parent")?;
    fs::create_dir_all(parent)?;
    let p = owned_path(root, name)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(if executable {
                0o755
            } else {
                0o644
            }))?;
    }
    check_cancelled()?;
    temp.persist(p)?;
    Ok(())
}
pub(crate) fn blob_name(record: &Value) -> Result<String> {
    Ok(format!("blobs/{}", text(record, "sha256")?))
}
pub(crate) fn read_verified(root: &Path, name: &str, record: &Value) -> Result<Vec<u8>> {
    let p = owned_path(root, name)?;
    let data = fs::read(&p).map_err(|e| {
        format!(
            "missing prepared input {}; run fetch explicitly: {e}",
            p.display()
        )
    })?;
    validate_bytes(&data, record, name)?;
    Ok(data)
}
pub(crate) fn manifest(path: &Path) -> Result<Value> {
    let v = strict_json(&fs::read(path)?)?;
    if v["schema_version"].as_u64() != Some(1) {
        return fail("unsupported input manifest version");
    }
    for r in array(&v, "sources")?
        .iter()
        .chain(array(&v, "protoc_archives")?)
    {
        validate_record(r)?;
    }
    for r in array(&v, "sources")? {
        if let Some(p) = r.get("proto_path") {
            safe_relative(p.as_str().ok_or("invalid proto_path")?)?;
        }
    }
    if let Some(names) = v.get("containerd_output_files") {
        for n in names.as_array().ok_or("invalid output inventory")? {
            if safe_relative(n.as_str().ok_or("invalid output name")?)?.len() != 1 {
                return fail("generated output names must be direct children");
            }
        }
    }
    for a in array(&v, "protoc_archives")? {
        for r in array(a, "files")? {
            safe_relative(text(r, "path")?)?;
            validate_record(r)?;
        }
    }
    if let Some(payloads) = v.get("payload_binaries") {
        for r in payloads.as_array().ok_or("invalid payload_binaries")? {
            validate_record(r)?;
            let id = text(r, "id")?;
            if safe_relative(id)?.len() != 1 {
                return fail("payload binary id must be a direct child");
            }
            let platform = text(r, "platform")?;
            if safe_relative(platform)?.len() != 1 {
                return fail("payload binary platform must be a direct child");
            }
            if let Some(archive) = r.get("archive") {
                if r.get("url").is_some() {
                    return fail("payload binary cannot specify both url and archive");
                }
                validate_record(archive)?;
                let url = text(archive, "url")?;
                if !url.starts_with("https://") {
                    return fail("payload archive downloads require HTTPS");
                }
                let member_path = text(archive, "path")?;
                safe_relative(member_path)?;
            } else {
                let url = text(r, "url")?;
                if !url.starts_with("https://") {
                    return fail("payload binary downloads require HTTPS");
                }
            }
        }
    }
    Ok(v)
}
pub(crate) fn host_platform() -> String {
    format!(
        "{}-{}",
        if cfg!(target_os = "macos") {
            "darwin"
        } else {
            std::env::consts::OS
        },
        match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => other,
        }
    )
}
pub(crate) fn compiler_record<'a>(inputs: &'a Value, selected: &str) -> Result<&'a Value> {
    array(inputs, "protoc_archives")?
        .iter()
        .find(|r| r["platform"] == selected)
        .ok_or_else(|| format!("no locked protoc archive for platform {selected}").into())
}
thread_local! {
    static EXECUTION: std::cell::RefCell<Option<crate::process::Cancellation>> = const { std::cell::RefCell::new(None) };
}
/// One latch covers the entire CLI, including hashing and gaps between children.
pub(crate) fn with_execution<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    if EXECUTION.with(|context| context.borrow().is_some()) {
        check_cancelled()?;
        return action();
    }
    let cancellation = crate::process::Cancellation::default();
    let signals = crate::process::SignalGuard::install(cancellation.clone())?;
    EXECUTION.with(|context| *context.borrow_mut() = Some(cancellation.clone()));
    let result = action();
    EXECUTION.with(|context| *context.borrow_mut() = None);
    match result {
        Err(failure) if uncertain(&failure) => Err(Box::new(RunFailure {
            failure,
            _signals: signals,
        })),
        Ok(_) if cancellation.requested() => fail("upstream execution cancelled"),
        other => other,
    }
}
pub(crate) fn check_cancelled() -> Result<()> {
    if EXECUTION.with(|context| {
        context
            .borrow()
            .as_ref()
            .is_some_and(crate::process::Cancellation::requested)
    }) {
        return fail("upstream execution cancelled");
    }
    Ok(())
}
/// Bounded owned process with byte-exact stdout and retained uncertainty.
pub(crate) fn run(command: &mut Command, seconds: u64) -> Result<Vec<u8>> {
    use crate::process::{CommandRequest, Commands, OutputMode};
    use std::fmt::Write as _;
    let Some(cancellation) = EXECUTION.with(|context| context.borrow().clone()) else {
        return with_execution(|| run(command, seconds));
    };
    check_cancelled()?;
    if command.get_envs().next().is_some() {
        return fail("upstream commands require inherited environment without overrides");
    }
    let output = tempfile::tempdir()?;
    let commands = Commands {
        output: output.path().to_owned(),
        cancellation,
    };
    let argv = std::iter::once(command.get_program().to_owned())
        .chain(command.get_args().map(std::ffi::OsStr::to_owned))
        .collect::<Vec<_>>();
    // Unit tests use the independently built CLI; the harness cannot dispatch __exec.
    #[cfg(test)]
    let launcher = Some(PathBuf::from(env!("CARGO_BIN_EXE_diorama-upstream")));
    #[cfg(not(test))]
    let launcher: Option<PathBuf> = None;
    match commands.capture(CommandRequest {
        label: "upstream",
        argv: &argv,
        timeout: Duration::from_secs(seconds),
        input: &[],
        required: true,
        byte_limit: 64 * 1024 * 1024,
        mode: OutputMode::Separate,
        environment: None,
        current_directory: command.get_current_dir(),
        launcher: launcher.as_deref(),
    }) {
        Ok(result) => Ok(result.stdout_bytes),
        Err(mut failure) => {
            if let Ok(bytes) =
                crate::read_bounded(&output.path().join("upstream.stderr"), 64 * 1024 * 1024)
            {
                let _ = write!(
                    failure.message,
                    ": {}",
                    String::from_utf8_lossy(&bytes[..bytes.len().min(65536)])
                );
            }
            if !failure.cleanup_complete {
                let _ = write!(
                    failure.message,
                    "; logs retained at {}",
                    output.keep().display()
                );
            }
            Err(Box::new(failure))
        },
    }
}
#[derive(Debug)]
struct RunFailure {
    failure: crate::Error,
    _signals: crate::process::SignalGuard,
}
impl std::fmt::Display for RunFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.failure.fmt(f)
    }
}
impl std::error::Error for RunFailure {}
pub(crate) fn uncertain(error: &crate::Error) -> bool {
    error.downcast_ref::<RunFailure>().is_some()
        || error
            .downcast_ref::<crate::process::CommandFailure>()
            .is_some_and(|e| !e.cleanup_complete)
}
/// Keep temporary compiler inputs when process absence cannot be confirmed.
pub(crate) fn run_in(
    command: &mut Command,
    seconds: u64,
    work: tempfile::TempDir,
) -> Result<tempfile::TempDir> {
    match run(command, seconds) {
        Ok(_) => Ok(work),
        Err(error) => {
            if uncertain(&error) {
                eprintln!(
                    "retained uncertain command inputs: {}",
                    work.keep().display()
                );
            }
            Err(error)
        },
    }
}
pub(crate) fn archive_members(data: &[u8], record: &Value) -> Result<BTreeMap<String, Vec<u8>>> {
    validate_bytes(data, record, "protoc archive")?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data))?;
    validate_zip_entry_count(data, archive.central_directory_start(), archive.len())?;
    let mut names = BTreeSet::new();
    for i in 0..archive.len() {
        let item = archive.by_index(i)?;
        safe_relative(item.name())?;
        if !names.insert(item.name().to_owned()) {
            return fail("duplicate ZIP member");
        }
        let kind = item.unix_mode().unwrap_or(0) & 0o170_000;
        if !matches!(kind, 0 | 0o100_000 | 0o040_000) {
            return fail("unsupported ZIP member type");
        }
    }
    let mut result = BTreeMap::new();
    for r in array(record, "files")? {
        let name = text(r, "path")?;
        let item = archive.by_name(name)?;
        if Some(item.size()) != r["bytes"].as_u64() {
            return fail("wrong ZIP member size");
        }
        let mut content = Vec::new();
        item.take(
            r["bytes"]
                .as_u64()
                .ok_or("invalid size")?
                .checked_add(1)
                .ok_or("size overflow")?,
        )
        .read_to_end(&mut content)?;
        validate_bytes(&content, r, name)?;
        result.insert(name.to_owned(), content);
    }
    Ok(result)
}
// ZipArchive stores central entries in a name-keyed map. Counting its public iterator alone
// would silently accept duplicate names. Inspect only central record boundaries here; the
// ZIP implementation remains responsible for parsing records, codecs, and CRC validation.
fn validate_zip_entry_count(data: &[u8], start: u64, unique: usize) -> Result<()> {
    let mut position = usize::try_from(start)?;
    let mut count = 0usize;
    while data.get(position..position.saturating_add(4)) == Some(b"PK\x01\x02") {
        let end = position.checked_add(46).ok_or("ZIP header overflow")?;
        let header = data
            .get(position..end)
            .ok_or("truncated ZIP central header")?;
        let mut length = 46usize;
        for offset in [28, 30, 32] {
            length = length
                .checked_add(usize::from(u16::from_le_bytes([
                    header[offset],
                    header[offset + 1],
                ])))
                .ok_or("ZIP record overflow")?;
        }
        position = position.checked_add(length).ok_or("ZIP record overflow")?;
        if position > data.len() {
            return fail("truncated ZIP central record");
        }
        count = count.checked_add(1).ok_or("ZIP entry count overflow")?;
    }
    if count != unique {
        return fail("duplicate ZIP member or inconsistent central directory");
    }
    Ok(())
}
pub(crate) fn verify(
    inputs: &Value,
    cache: &Path,
    selected: &str,
    alternate: Option<&Path>,
) -> Result<PathBuf> {
    for r in array(inputs, "sources")? {
        read_verified(cache, &blob_name(r)?, r)?;
    }
    let compiler = compiler_record(inputs, selected)?;
    archive_members(
        &read_verified(cache, &blob_name(compiler)?, compiler)?,
        compiler,
    )?;
    for r in array(compiler, "files")? {
        read_verified(cache, &format!("protoc/{selected}/{}", text(r, "path")?), r)?;
    }
    let binary = array(compiler, "files")?
        .iter()
        .find(|r| r["path"] == "bin/protoc")
        .ok_or("missing compiler")?;
    let p = if let Some(p) = alternate {
        p.canonicalize()?
    } else {
        owned_path(cache, &format!("protoc/{selected}/bin/protoc"))?
    };
    validate_bytes(&fs::read(&p)?, binary, "compiler")?;
    Ok(p)
}
pub(crate) fn download_url(url: &str, max_bytes: u64, timeout_secs: u64) -> Result<Vec<u8>> {
    if !url.starts_with("https://") {
        return fail("input downloads require HTTPS");
    }
    let temp = tempfile::NamedTempFile::new()?;
    let download = run(
        Command::new("curl")
            .args([
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-time",
                &timeout_secs.to_string(),
                "--max-filesize",
                &max_bytes.to_string(),
                "--user-agent",
                "diorama-upstream/1",
                "--output",
            ])
            .arg(temp.path())
            .arg(url),
        timeout_secs.saturating_add(5),
    );
    if let Err(error) = download {
        if uncertain(&error) {
            let (_, path) = temp.keep()?;
            eprintln!("retained uncertain download: {}", path.display());
        }
        return Err(error);
    }
    let data = fs::read(temp.path())?;
    Ok(data)
}
pub(crate) fn extract_tar_gz_member(
    archive_data: &[u8],
    member_path: &str,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let decoder = GzDecoder::new(archive_data);
    let mut tar = Archive::new(decoder);
    let entries = tar
        .entries()
        .map_err(|e| format!("invalid tar archive: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("invalid tar entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("invalid path in tar: {e}"))?;
        let path_str = path.to_str().ok_or("non-utf8 path in archive")?;
        let clean = path_str.strip_prefix("./").unwrap_or(path_str);
        if clean == member_path {
            if !entry.header().entry_type().is_file() {
                return fail(format!(
                    "archive member {member_path} is not a regular file"
                ));
            }
            let mut content = Vec::new();
            entry
                .take(max_bytes.checked_add(1).ok_or("size overflow")?)
                .read_to_end(&mut content)?;
            return Ok(content);
        }
    }
    fail(format!("member {member_path} not found in archive"))
}
pub(crate) fn fetch(inputs: &Value, cache: &Path, selected: &str) -> Result<()> {
    let compiler = compiler_record(inputs, selected)?;
    for r in array(inputs, "sources")?
        .iter()
        .chain(std::iter::once(compiler))
    {
        let name = blob_name(r)?;
        if owned_path(cache, &name)?.exists() {
            read_verified(cache, &name, r)?;
        } else {
            let url = text(r, "url")?;
            let max_bytes = r["bytes"].as_u64().ok_or("invalid bytes")?;
            let data = download_url(url, max_bytes, 60)?;
            validate_bytes(&data, r, url)?;
            atomic_write(cache, &name, &data, false)?;
        }
    }
    for (name, data) in archive_members(
        &read_verified(cache, &blob_name(compiler)?, compiler)?,
        compiler,
    )? {
        atomic_write(
            cache,
            &format!("protoc/{selected}/{name}"),
            &data,
            name == "bin/protoc",
        )?;
    }
    verify(inputs, cache, selected, None)?;
    Ok(())
}
pub(crate) fn payload_records<'a>(inputs: &'a Value, selected: &str) -> Result<Vec<&'a Value>> {
    let records: Vec<&'a Value> = array(inputs, "payload_binaries")?
        .iter()
        .filter(|r| r.get("platform").and_then(Value::as_str) == Some(selected))
        .collect();
    if records.is_empty() {
        return fail(format!(
            "no locked payload binaries for platform {selected}"
        ));
    }
    Ok(records)
}
pub(crate) fn verify_payloads(inputs: &Value, cache: &Path, selected: &str) -> Result<()> {
    for r in payload_records(inputs, selected)? {
        let id = text(r, "id")?;
        let name = format!("payloads/{selected}/{id}");
        let p = owned_path(cache, &name)?;
        let data = fs::read(&p).map_err(|e| {
            format!(
                "missing prepared payload {}; run fetch-payloads explicitly: {e}",
                p.display()
            )
        })?;
        validate_bytes(&data, r, &format!("payload {id}"))?;
    }
    Ok(())
}
pub(crate) fn fetch_payloads(inputs: &Value, cache: &Path, selected: &str) -> Result<()> {
    for r in payload_records(inputs, selected)? {
        let id = text(r, "id")?;
        let name = format!("payloads/{selected}/{id}");
        let p = owned_path(cache, &name)?;
        if p.exists() {
            let data = fs::read(&p)?;
            validate_bytes(&data, r, &format!("payload {id}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o755))?;
            }
        } else if let Some(archive) = r.get("archive") {
            let archive_blob = blob_name(archive)?;
            let archive_data = if owned_path(cache, &archive_blob)?.exists() {
                read_verified(cache, &archive_blob, archive)?
            } else {
                let url = text(archive, "url")?;
                let max_bytes = archive["bytes"].as_u64().ok_or("invalid archive size")?;
                let data = download_url(url, max_bytes, 300)?;
                validate_bytes(&data, archive, url)?;
                atomic_write(cache, &archive_blob, &data, false)?;
                data
            };
            let member_path = text(archive, "path")?;
            let binary_bytes = r["bytes"].as_u64().ok_or("invalid payload bytes")?;
            let data = extract_tar_gz_member(&archive_data, member_path, binary_bytes)?;
            validate_bytes(
                &data,
                r,
                &format!("payload {id} from archive {member_path}"),
            )?;
            atomic_write(cache, &name, &data, true)?;
        } else {
            let url = text(r, "url")?;
            let max_bytes = r["bytes"].as_u64().ok_or("invalid payload size")?;
            let data = download_url(url, max_bytes, 300)?;
            validate_bytes(&data, r, url)?;
            atomic_write(cache, &name, &data, true)?;
        }
    }
    verify_payloads(inputs, cache, selected)?;
    Ok(())
}
pub fn cli(args: &[String]) -> Result<()> {
    with_execution(|| cli_inner(args))
}
fn cli_inner(args: &[String]) -> Result<()> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        println!(
            "diorama-upstream <fetch|verify|fetch-payloads|verify-payloads|generate-cri|check-cri|generate-containerd|check-containerd|check-kubernetes-bindings>\n  --cache-dir PATH --platform PLATFORM --protoc PATH --generator PATH --output-dir PATH"
        );
        return Ok(());
    }
    let command = args.first().ok_or("expected upstream command")?;
    let mut opts = BTreeMap::new();
    let mut it = args[1..].iter();
    while let Some(k) = it.next() {
        if ![
            "--cache-dir",
            "--platform",
            "--protoc",
            "--generator",
            "--output-dir",
        ]
        .contains(&k.as_str())
            || opts
                .insert(
                    k.as_str(),
                    it.next().ok_or("missing option value")?.as_str(),
                )
                .is_some()
        {
            return fail("unknown or duplicate option");
        }
    }
    let root = root();
    let inputs = manifest(&root.join("tools/upstream/inputs.json"))?;
    let cache = opts
        .get("--cache-dir")
        .map_or_else(|| root.join("target/upstream"), PathBuf::from);
    let platform = opts
        .get("--platform")
        .map_or_else(host_platform, |v| (*v).to_owned());
    let alternate = opts.get("--protoc").map(Path::new);
    let mut result = match command.as_str() {
        "fetch" => {
            fetch(&inputs, &cache, &platform)?;
            json!({"status":"prepared","platform":platform})
        },
        "verify" => {
            verify(&inputs, &cache, &platform, alternate)?;
            json!({"status":"verified","platform":platform})
        },
        "fetch-payloads" => {
            fetch_payloads(&inputs, &cache, &platform)?;
            json!({"status":"payloads-prepared","platform":platform})
        },
        "verify-payloads" => {
            verify_payloads(&inputs, &cache, &platform)?;
            json!({"status":"payloads-verified","platform":platform})
        },
        "check-kubernetes-bindings" => kubernetes::check(&inputs, &cache, &root)?,
        "generate-cri" | "check-cri" | "generate-containerd" | "check-containerd" => {
            let target = command.split_once('-').ok_or("invalid command")?.1;
            let generator = opts.get("--generator").map_or_else(
                || root.join("target/debug/diorama-upstream-codegen"),
                PathBuf::from,
            );
            let output = opts.get("--output-dir").map_or_else(
                || {
                    root.join(if target == "cri" {
                        "crates/diorama-cri/src/generated"
                    } else {
                        "crates/diorama-containerd-api/src/generated"
                    })
                },
                PathBuf::from,
            );
            generation::generate(
                &inputs,
                &cache,
                &platform,
                &generator,
                &output,
                command.starts_with("check-"),
                alternate,
                target,
            )?
        },
        _ => return fail("unknown upstream command"),
    };
    result["input_manifest_sha256"] =
        digest(&fs::read(root.join("tools/upstream/inputs.json"))?).into();
    check_cancelled()?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
#[cfg(test)]
mod tests;
