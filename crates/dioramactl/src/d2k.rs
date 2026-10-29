//! Export D2K client credentials without following user-controlled output paths.
use crate::CheckInputs;
use crate::contract::D2kOptions;
use crate::endpoints::{EnginePortInspector, resolve_published_endpoint};
use crate::kubeconfig::{InvokingUser, resolve_invoking_user};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

const D2K_PORT: u16 = 2376;
const FILES: &[(&str, &str)] = &[
    ("ca.crt", "ca.pem"),
    ("d2k-client.crt", "cert.pem"),
    ("d2k-client.key", "key.pem"),
];

trait Docker {
    fn available(&self) -> bool;
    fn copy(&mut self, container: &str, source: &str) -> io::Result<Vec<u8>>;
    fn configure(&mut self, name: &str, endpoint: &str, user: &InvokingUser) -> io::Result<()>;
}

struct DockerCli;
impl Docker for DockerCli {
    fn available(&self) -> bool {
        Command::new("docker")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn copy(&mut self, container: &str, source: &str) -> io::Result<Vec<u8>> {
        // Docker never writes into the invoking user's replaceable export directory.
        let staging = tempfile::tempdir()?;
        let destination = staging.path().join("credential");
        let output = Command::new("docker")
            .args(["cp", &format!("{container}:{source}")])
            .arg(&destination)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other("Docker credential copy failed"));
        }
        let metadata = fs::symlink_metadata(&destination)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(io::Error::other("Docker credential is not a regular file"));
        }
        fs::read(destination)
    }

    fn configure(&mut self, name: &str, endpoint: &str, user: &InvokingUser) -> io::Result<()> {
        let command = |args: &[&str]| {
            let mut command = Command::new("docker");
            command
                .args(args)
                .env("HOME", &user.home_dir)
                .env("DOCKER_CONFIG", user.home_dir.join(".docker"));
            #[cfg(unix)]
            if diorama_supervisor::rustix::process::geteuid().is_root() {
                use std::os::unix::process::CommandExt;
                if let (Some(uid), Some(gid)) = (user.uid, user.gid) {
                    command.uid(uid).gid(gid);
                } else {
                    return Err(io::Error::other("invoking user identity is unavailable"));
                }
            }
            command.output()
        };
        let exists = command(&["context", "inspect", name])?.status.success();
        let action = if exists { "update" } else { "create" };
        let output = command(&[
            "context",
            action,
            name,
            "--description",
            "diorama D2K",
            "--docker",
            endpoint,
        ])?;
        if !output.status.success() {
            return Err(io::Error::other("Docker context synchronization failed"));
        }
        Ok(())
    }
}

/// An empty injection map selects the actual CLI environment; explicit maps stay isolated.
fn environment_or_process(environment: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    if environment.is_empty() {
        std::env::vars_os()
            .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
            .collect()
    } else {
        environment.clone()
    }
}

pub fn execute_d2k(
    options: &D2kOptions,
    _inputs: &mut dyn CheckInputs,
    engine: &mut dyn EnginePortInspector,
    environment: &BTreeMap<String, String>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    execute(
        options,
        engine,
        &environment_or_process(environment),
        &mut DockerCli,
        stdout,
        stderr,
    )
}

fn execute(
    options: &D2kOptions,
    engine: &mut dyn EnginePortInspector,
    environment: &BTreeMap<String, String>,
    docker: &mut dyn Docker,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    if !matches!(options.subcommand.as_deref(), Some("fetch" | "install")) {
        writeln!(stderr, "error: unknown d2k subcommand")?;
        return Ok(1);
    }
    let name = options.name.as_deref().unwrap_or("diorama");
    if name.is_empty()
        || name.len() > 128
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        writeln!(
            stderr,
            "error: instance name must be one safe alphanumeric component"
        )?;
        return Ok(1);
    }
    let user = resolve_invoking_user(environment);
    let directory = options
        .output
        .clone()
        .unwrap_or_else(|| user.home_dir.join(".docker/d2k").join(name));
    // Docker's endpoint option is CSV: quote each full key/value field, including paths.
    let mut fields = Vec::new();
    let host_install = options.path.join("pki/d2k-client.crt").try_exists()?;
    let port = if host_install {
        D2K_PORT
    } else {
        let raw = engine.inspect_port(name, D2K_PORT)?;
        resolve_published_endpoint(&raw)
            .map_err(io::Error::other)?
            .port
    };
    fields.push(format!("host=tcp://127.0.0.1:{port}"));
    for (key, file) in [("ca", "ca.pem"), ("cert", "cert.pem"), ("key", "key.pem")] {
        let path = directory.join(file);
        let text = path
            .to_str()
            .ok_or_else(|| io::Error::other("Docker credential path must be UTF-8"))?;
        fields.push(format!("{key}={text}"));
    }
    let endpoint = fields
        .iter()
        .map(|f| format!("\"{}\"", f.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(",");
    // Read all inputs before changing any existing credentials.
    let mut credentials = Vec::new();
    for (source, destination) in FILES {
        let data = if host_install {
            fs::read(options.path.join("pki").join(source))?
        } else {
            docker.copy(
                &crate::container::container_name(name),
                &format!("/var/lib/diorama/pki/{source}"),
            )?
        };
        if data.is_empty() {
            return Err(io::Error::other("D2K credential is empty"));
        }
        credentials.push((*destination, data));
    }
    publish_credentials(&directory, &credentials, &user)?;
    writeln!(
        stdout,
        "Certificate files written to {}",
        directory.display()
    )?;
    if !docker.available() {
        writeln!(
            stdout,
            "Docker CLI unavailable; context configuration requires Docker"
        )?;
        return Ok(0);
    }
    docker.configure(name, &endpoint, &user)?;
    writeln!(stdout, "D2K context '{name}' configured")?;
    Ok(0)
}

#[cfg(unix)]
fn publish_credentials(
    directory: &Path,
    credentials: &[(&str, Vec<u8>)],
    user: &InvokingUser,
) -> io::Result<()> {
    use rustix::fs::{
        AtFlags, CWD, Mode, OFlags, fchmod, fchown, fstat, mkdirat, openat, renameat, unlinkat,
    };
    use std::path::Component;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut parent = openat(
        CWD,
        if directory.is_absolute() { "/" } else { "." },
        flags,
        Mode::empty(),
    )?;
    for component in directory.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(io::Error::other(
                "certificate directory cannot contain parent components",
            ));
        };
        match openat(&parent, name, flags, Mode::empty()) {
            Ok(child) => parent = child,
            Err(rustix::io::Errno::NOENT) => {
                if !may_create_directory(
                    diorama_supervisor::rustix::process::geteuid().as_raw(),
                    user.uid,
                ) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "create the certificate directory as the invoking user before privileged export",
                    ));
                }
                mkdirat(&parent, name, Mode::RWXU)?;
                parent = openat(&parent, name, flags, Mode::empty())?;
            },
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = fstat(&parent)?;
    if user.uid.is_none_or(|uid| uid != metadata.st_uid) {
        return Err(io::Error::other(
            "certificate directory is not owned by the invoking user",
        ));
    }
    fchmod(&parent, Mode::RWXU)?;
    // The directory descriptor remains pinned even if an ancestor is renamed concurrently.
    for (destination, data) in credentials {
        let temporary = format!(".d2k-{}-{}", std::process::id(), destination);
        let file = openat(
            &parent,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        let result: io::Result<()> = (|| {
            let mut file = fs::File::from(file);
            file.write_all(data)?;
            if diorama_supervisor::rustix::process::geteuid().is_root() {
                fchown(
                    &file,
                    user.uid.map(rustix::fs::Uid::from_raw),
                    user.gid.map(rustix::fs::Gid::from_raw),
                )?;
            }
            file.sync_all()?;
            renameat(&parent, temporary.as_str(), &parent, *destination)?;
            Ok(())
        })();
        let _ = unlinkat(&parent, temporary.as_str(), AtFlags::empty());
        result?;
    }
    fs::File::from(parent).sync_all()
}

#[cfg(unix)]
fn may_create_directory(effective_uid: u32, invoking_uid: Option<u32>) -> bool {
    invoking_uid == Some(effective_uid)
}

#[cfg(not(unix))]
fn publish_credentials(_: &Path, _: &[(&str, Vec<u8>)], _: &InvokingUser) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure D2K export requires Unix",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn privileged_export_never_creates_or_chowns_another_users_directory() {
        assert!(!may_create_directory(0, Some(1000)));
        assert!(!may_create_directory(0, None));
        assert!(may_create_directory(1000, Some(1000)));
        assert!(may_create_directory(0, Some(0)));
    }

    #[test]
    fn cross_uid_directory_refusal_has_no_effects_and_preowned_export_succeeds() {
        let (_temporary, options, environment) = fixture();
        let directory = options.output.as_ref().unwrap();
        let owner = resolve_invoking_user(&environment);
        let mut other = owner.clone();
        other.uid = Some(owner.uid.unwrap().checked_add(1).unwrap());
        let credentials = vec![("key.pem", b"credential".to_vec())];
        let error = publish_credentials(directory, &credentials, &other).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!directory.exists());
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(publish_credentials(directory, &credentials, &other).is_err());
        assert!(!directory.join("key.pem").exists());
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o755
        );
        publish_credentials(directory, &credentials, &owner).unwrap();
        assert_eq!(fs::read(directory.join("key.pem")).unwrap(), b"credential");
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[derive(Default)]
    struct MockDocker {
        copies: Vec<(String, String)>,
        contexts: Vec<(String, String)>,
        fail_context: bool,
    }
    impl Docker for MockDocker {
        fn available(&self) -> bool {
            true
        }
        fn copy(&mut self, container: &str, source: &str) -> io::Result<Vec<u8>> {
            self.copies.push((container.into(), source.into()));
            Ok(b"credential".to_vec())
        }
        fn configure(&mut self, name: &str, endpoint: &str, _: &InvokingUser) -> io::Result<()> {
            self.contexts.push((name.into(), endpoint.into()));
            if self.fail_context {
                Err(io::Error::other("context failed"))
            } else {
                Ok(())
            }
        }
    }
    struct MockEngine {
        output: &'static str,
    }
    impl EnginePortInspector for MockEngine {
        fn inspect_port(&mut self, instance: &str, port: u16) -> io::Result<String> {
            assert!(instance == "dev" || instance == "diorama" || instance == "dev.cluster");
            assert_eq!(port, 2376);
            Ok(self.output.into())
        }
    }
    fn fixture() -> (tempfile::TempDir, D2kOptions, BTreeMap<String, String>) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let options = D2kOptions {
            subcommand: Some("fetch".into()),
            name: Some("dev".into()),
            path: root.join("node"),
            output: Some(root.join("export")),
        };
        let environment = BTreeMap::from([
            ("HOME".into(), root.display().to_string()),
            ("USER".into(), "test".into()),
        ]);
        (directory, options, environment)
    }
    fn host_credentials(options: &D2kOptions) {
        fs::create_dir_all(options.path.join("pki")).unwrap();
        for (source, _) in FILES {
            fs::write(options.path.join("pki").join(source), source).unwrap();
        }
    }
    #[test]
    fn container_names_flat_paths_port_and_output_are_preserved() {
        for (instance, container) in [
            ("dev", "diorama-dev"),
            ("diorama", "diorama"),
            ("dev.cluster", "diorama-dev.cluster"),
        ] {
            let (_temporary, mut options, environment) = fixture();
            options.name = Some(instance.into());
            let mut docker = MockDocker::default();
            let mut engine = MockEngine {
                output: "0.0.0.0:49237\n[::]:49237\n",
            };
            let code = execute(
                &options,
                &mut engine,
                &environment,
                &mut docker,
                &mut Vec::new(),
                &mut Vec::new(),
            )
            .unwrap();
            assert_eq!(code, 0);
            assert_eq!(docker.copies.len(), 3);
            assert!(docker.copies.iter().all(|(name, _)| name == container));
            assert_eq!(docker.copies[1].1, "/var/lib/diorama/pki/d2k-client.crt");
            assert!(docker.contexts[0].1.contains("127.0.0.1:49237"));
            let output = options.output.unwrap();
            assert_eq!(fs::read(output.join("key.pem")).unwrap(), b"credential");
            assert_eq!(
                fs::metadata(output.join("key.pem"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(output).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }
    #[test]
    fn host_credentials_use_current_pki_without_engine_access() {
        let (_temporary, options, environment) = fixture();
        host_credentials(&options);
        let mut docker = MockDocker::default();
        execute(
            &options,
            &mut crate::endpoints::UnavailableEngine,
            &environment,
            &mut docker,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(docker.copies, Vec::<(String, String)>::new());
        assert_eq!(
            fs::read(options.output.unwrap().join("cert.pem")).unwrap(),
            b"d2k-client.crt"
        );
    }
    #[test]
    fn port_failures_never_export_or_configure() {
        for output in ["", "unpublished", "0.0.0.0:0", "0.0.0.0:1\n[::]:2"] {
            let (_temporary, options, environment) = fixture();
            let mut docker = MockDocker::default();
            assert!(
                execute(
                    &options,
                    &mut MockEngine { output },
                    &environment,
                    &mut docker,
                    &mut Vec::new(),
                    &mut Vec::new()
                )
                .is_err()
            );
            assert_eq!(docker.copies, Vec::<(String, String)>::new());
            assert_eq!(docker.contexts, Vec::<(String, String)>::new());
            assert!(!options.output.unwrap().exists());
        }
    }
    #[test]
    fn unsafe_names_do_not_change_directories() {
        for name in ["", "/etc", "../escape", "a/b", "..", "-flag", "a,b"] {
            let (_temporary, mut options, environment) = fixture();
            options.name = Some(name.into());
            let mut docker = MockDocker::default();
            assert_eq!(
                execute(
                    &options,
                    &mut MockEngine { output: "" },
                    &environment,
                    &mut docker,
                    &mut Vec::new(),
                    &mut Vec::new()
                )
                .unwrap(),
                1
            );
            assert!(!options.output.unwrap().exists());
            assert_eq!(docker.copies, Vec::<(String, String)>::new());
        }
    }
    #[test]
    fn credential_symlink_target_is_never_modified() {
        let (_temporary, options, environment) = fixture();
        host_credentials(&options);
        let output = options.output.as_ref().unwrap();
        fs::create_dir_all(output).unwrap();
        let target = output.parent().unwrap().join("unrelated");
        fs::write(&target, "untouched").unwrap();
        symlink(&target, output.join("key.pem")).unwrap();
        execute(
            &options,
            &mut crate::endpoints::UnavailableEngine,
            &environment,
            &mut MockDocker::default(),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(target).unwrap(), "untouched");
        assert!(
            !fs::symlink_metadata(output.join("key.pem"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    #[test]
    fn directory_symlinks_are_rejected_without_chown_or_write() {
        let (_temporary, options, environment) = fixture();
        host_credentials(&options);
        let output = options.output.as_ref().unwrap();
        let unrelated = output.parent().unwrap().join("unrelated");
        fs::create_dir(&unrelated).unwrap();
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&unrelated, output).unwrap();
        assert!(
            execute(
                &options,
                &mut crate::endpoints::UnavailableEngine,
                &environment,
                &mut MockDocker::default(),
                &mut Vec::new(),
                &mut Vec::new()
            )
            .is_err()
        );
        assert_eq!(
            fs::metadata(unrelated).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    #[test]
    fn missing_host_key_never_partially_overwrites_credentials() {
        let (_temporary, options, environment) = fixture();
        host_credentials(&options);
        fs::remove_file(options.path.join("pki/d2k-client.key")).unwrap();
        assert!(
            execute(
                &options,
                &mut crate::endpoints::UnavailableEngine,
                &environment,
                &mut MockDocker::default(),
                &mut Vec::new(),
                &mut Vec::new()
            )
            .is_err()
        );
        assert!(!options.output.unwrap().exists());
    }
    #[test]
    fn context_failure_does_not_report_configured() {
        let (_temporary, options, environment) = fixture();
        host_credentials(&options);
        let mut output = Vec::new();
        let mut docker = MockDocker {
            fail_context: true,
            ..MockDocker::default()
        };
        assert!(
            execute(
                &options,
                &mut crate::endpoints::UnavailableEngine,
                &environment,
                &mut docker,
                &mut output,
                &mut Vec::new()
            )
            .is_err()
        );
        assert!(!String::from_utf8(output).unwrap().contains("configured"));
    }
    #[test]
    fn empty_environment_uses_process_and_explicit_environment_stays_isolated() {
        assert_eq!(
            environment_or_process(&BTreeMap::new()),
            std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
                .collect()
        );
        let explicit = BTreeMap::from([("HOME".into(), "/chosen".into())]);
        assert_eq!(environment_or_process(&explicit), explicit);
    }
}
