use crate::CheckInputs;
use crate::artifact::{artifact_archive_name, artifact_download_url, resolve_target};
use crate::contract::DownloadOptions;
use diorama_platform::Libc;
use std::io::{self, Write};
use std::path::Path;

/// Downloads into owned staging, then atomically publishes on the destination
/// filesystem. Failed archive downloads leave existing archives untouched.
pub fn stage_download(
    dest: &Path,
    temp_dir: Option<&Path>,
    fetch: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let staging = match temp_dir {
        Some(parent) => {
            std::fs::create_dir_all(parent)?;
            tempfile::TempDir::new_in(parent)?
        },
        None => tempfile::TempDir::new()?,
    };
    let staged = staging.path().join("bundle");
    fetch(&staged)?;
    let parent = dest
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut published = tempfile::NamedTempFile::new_in(parent)?;
    let mut source = std::fs::File::open(staged)?;
    io::copy(&mut source, &mut published)?;
    published.as_file().sync_all()?;
    published.persist(dest).map_err(|error| error.error)?;
    Ok(())
}

/// Publishes an executable only after a complete copy, permission enforcement,
/// and sync. Partial copies cannot truncate a previously published installer.
pub fn stage_installer(
    dest: &Path,
    copy: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let parent = dest
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut installer = tempfile::NamedTempFile::new_in(parent)?;
    copy(installer.as_file_mut())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        installer
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))?;
    }
    installer.as_file().sync_all()?;
    installer.persist(dest).map_err(|error| error.error)?;
    Ok(())
}

/// Curl bounds connection and stalled-transfer time; private settings arrive on stdin.
pub fn curl_download_command(
    _url: &str,
    dest: &Path,
    _proxy: Option<&str>,
) -> std::process::Command {
    let mut command = std::process::Command::new("curl");
    command
        .args([
            "-fSL",
            "--connect-timeout",
            "30",
            "--speed-limit",
            "1",
            "--speed-time",
            "120",
            "--proto",
            "=https,http",
            "--proto-redir",
            "=https",
            "-o",
        ])
        .arg(dest);
    command
        .args(["--config", "-"])
        .stdin(std::process::Stdio::piped());
    command
}

/// Protected curl configuration passed through stdin, never process arguments.
pub fn curl_download_config(url: &str, proxy: Option<&str>) -> String {
    fn quote(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }
    let mut config = format!("url = \"{}\"\n", quote(url));
    if let Some(proxy) = proxy {
        use std::fmt::Write as _;
        let _ = writeln!(config, "proxy = \"{}\"", quote(proxy));
    }
    config
}

/// Runs curl with URL and proxy material on a private pipe.
pub fn run_curl_download(
    url: &str,
    dest: &Path,
    proxy: Option<&str>,
) -> io::Result<std::process::ExitStatus> {
    let mut child = curl_download_command(url, dest, proxy).spawn()?;
    let result = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing curl stdin"))?
        .write_all(curl_download_config(url, proxy).as_bytes());
    if let Err(error) = result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    child.wait()
}

/// Executes the artifact download workflow: resolves target architecture and libc,
/// calculates archive name and URL, fetches the binary bundle, and stages the management CLI.
pub fn execute_download(
    options: &DownloadOptions,
    inputs: &mut dyn CheckInputs,
    _stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    writeln!(
        stderr,
        "\n  dioramactl  download\n\n  > Resolving target architecture"
    )?;

    // Bundles include the running management executable. Check its platform
    // even for an explicit archive target, before creating any bundle outputs.
    let evidence = match inputs.discover() {
        Ok(evidence) => evidence,
        Err(err) => {
            writeln!(
                stderr,
                "  [fail] architecture detection: {err}; obtain supported host observations before retrying"
            )?;
            return Ok(1);
        },
    };
    let target = if let Some(ref arch_str) = options.arch {
        match resolve_target(Some(arch_str), options.libc, None) {
            Ok(target) => target,
            Err(err) => {
                writeln!(
                    stderr,
                    "  [fail] architecture detection: {err}; obtain supported host observations before retrying"
                )?;
                return Ok(1);
            },
        }
    } else {
        match resolve_target(None, options.libc, Some(&evidence)) {
            Ok(target) => target,
            Err(err) => {
                writeln!(
                    stderr,
                    "  [fail] architecture detection: {err}; obtain supported host observations before retrying"
                )?;
                return Ok(1);
            },
        }
    };

    let executable_target = resolve_target(None, None, Some(&evidence));
    let executable_libc = match evidence.executable.environment.as_str() {
        "gnu" => Some(Libc::Glibc),
        "musl" => Some(Libc::Musl),
        _ => None,
    };
    if !matches!(executable_target, Ok(host) if host.architecture == target.architecture)
        || executable_libc != Some(target.libc)
    {
        writeln!(
            stderr,
            "  [fail] bundle installer does not match the selected Linux architecture and libc ABI; run download with a matching Linux dioramactl executable. No bundle files were created."
        )?;
        return Ok(1);
    }

    let archive_name = artifact_archive_name(&options.version, target, options.offline);
    let download_url = artifact_download_url(
        &options.version,
        &archive_name,
        options.custom_url.as_deref(),
    );

    writeln!(
        stderr,
        "  [ok] Target resolved: {archive_name}\n\n  > Downloading diorama {}",
        options.version
    )?;

    let dest_dir = &options.path;
    let archive_path = dest_dir.join(&archive_name);

    if let Err(err) = inputs.download_file(
        &download_url,
        &archive_path,
        options.proxy.as_deref(),
        options.temp_dir.as_deref(),
    ) {
        writeln!(stderr, "  [fail] download: {err}")?;
        return Ok(1);
    }

    let installer_path = dest_dir.join("dioramactl");
    if let Err(err) = inputs.copy_self(&installer_path) {
        writeln!(stderr, "  [fail] copy installer: {err}")?;
        return Ok(1);
    }

    writeln!(
        stderr,
        "  [ok] Bundle ready in {}\n\n  Next steps:\n  Transfer the files to the target machine, then:\n    sudo ./dioramactl install --offline-install={}\n",
        dest_dir.display(),
        format_args!("./{archive_name}")
    )?;

    Ok(0)
}
