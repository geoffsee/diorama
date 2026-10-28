use diorama_platform::ExecutableAbi;
use diorama_platform::preflight::PortAvailability;
use diorama_platform::preflight_probe::SupplementalFacts;
use diorama_platform::{HostEvidence, Observation, PlatformError};
use dioramactl::CheckInputs;
use dioramactl::contract::{CommandHandler, DefaultCommandHandler, InstallOptions};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command as SysCommand;
use tempfile::TempDir;

struct MockInputs {
    evidence: HostEvidence,
    download_called: bool,
}

impl CheckInputs for MockInputs {
    fn discover(&mut self) -> Result<HostEvidence, PlatformError> {
        Ok(self.evidence.clone())
    }
    fn supplemental(&mut self) -> Result<SupplementalFacts, PlatformError> {
        Err(PlatformError::UnsupportedHost)
    }
    fn ports(&mut self, _pprof: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError> {
        Err(PlatformError::UnsupportedHost)
    }
    fn download_file(
        &mut self,
        _url: &str,
        _dest: &Path,
        _proxy: Option<&str>,
        _temp_dir: Option<&Path>,
    ) -> io::Result<()> {
        self.download_called = true;
        Err(io::Error::other("egress denied"))
    }
}

fn arm64_glibc_evidence() -> HostEvidence {
    HostEvidence {
        executable: ExecutableAbi {
            os: "linux".to_string(),
            architecture: "aarch64".to_string(),
            environment: "gnu".to_string(),
        },
        kernel: Observation::Unknown(diorama_platform::ProbeFailure::PermissionDenied),
        privileges: Observation::Unknown(diorama_platform::ProbeFailure::PermissionDenied),
        hostname: Observation::Unknown(diorama_platform::ProbeFailure::PermissionDenied),
        container_environment_set: false,
        landmarks: BTreeMap::new(),
        musl_linkers: Observation::Unknown(diorama_platform::ProbeFailure::PermissionDenied),
        files: BTreeMap::new(),
        requested_paths: vec![],
    }
}

#[test]
fn test_offline_install_mismatch() {
    let mut inputs = MockInputs {
        evidence: arm64_glibc_evidence(),
        download_called: false,
    };

    let temp = TempDir::new().unwrap();
    let dest_dir = temp.path().join("dest");

    // amd64 bundle on arm64 host should fail
    let offline_path = temp
        .path()
        .join("diorama-v1.1.8-linux-amd64-offline.tar.gz");
    fs::write(&offline_path, b"dummy").unwrap();

    let mut handler = DefaultCommandHandler;
    let mut stderr = Vec::new();
    let mut stdout = Vec::new();

    let opts = InstallOptions {
        offline_install: Some(offline_path),
        path: dest_dir,
        ..InstallOptions::default()
    };

    let res = handler.execute_install(opts, &mut inputs, &mut stdout, &mut stderr);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 1);

    let err_str = String::from_utf8(stderr).unwrap();
    assert!(err_str.contains("mismatched architecture"));
    assert!(!inputs.download_called, "egress denied validation");
}

const ARM64_ELF_HEADER: [u8; 20] = [
    0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 183, 0,
];

fn sha(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hex = String::new();
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}

/// Builds a bundle; `tamper` mutates the staged tree after the manifest is written.
fn build_bundle(root: &Path, elf: &[u8], tamper: impl FnOnce(&Path)) -> std::path::PathBuf {
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("diorama"), elf).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(src.join("diorama"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(src.join("data.txt"), b"hello world").unwrap();
    fs::write(
        src.join("bundle.manifest"),
        format!(
            "version=v1.1.8\nos=linux\narch=arm64\nlibc=glibc\nexec {} diorama\nfile {} data.txt\n",
            sha(elf),
            sha(b"hello world")
        ),
    )
    .unwrap();
    tamper(&src);
    let archive = root.join("diorama-v1.1.8-linux-arm64-offline.tar.gz");
    let status = SysCommand::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(&src)
        .arg(".")
        .status()
        .unwrap();
    assert!(status.success());
    archive
}

fn run(archive: std::path::PathBuf, dest: &Path) -> (u8, String, bool) {
    let mut inputs = MockInputs {
        evidence: arm64_glibc_evidence(),
        download_called: false,
    };
    let mut handler = DefaultCommandHandler;
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let opts = InstallOptions {
        offline_install: Some(archive),
        path: dest.to_path_buf(),
        ..InstallOptions::default()
    };
    let code = handler
        .execute_install(opts, &mut inputs, &mut stdout, &mut stderr)
        .unwrap();
    (
        code,
        String::from_utf8(stderr).unwrap(),
        inputs.download_called,
    )
}

#[test]
fn test_offline_install_success() {
    let temp = TempDir::new().unwrap();
    let dest = temp.path().join("dest");
    let archive = build_bundle(temp.path(), &ARM64_ELF_HEADER, |_| {});
    let (code, err, downloaded) = run(archive, &dest);
    assert_eq!(code, 0, "{err}");
    assert!(dest.join("data.txt").exists());
    assert!(dest.join("diorama").exists());
    assert!(!downloaded, "egress denied validation");
}

#[test]
fn musl_cli_uses_observed_glibc_host_for_bundle_selection() {
    let temp = TempDir::new().unwrap();
    let archive = build_bundle(temp.path(), &ARM64_ELF_HEADER, |_| {});
    let mut evidence = arm64_glibc_evidence();
    evidence.executable.environment = "musl".to_string();
    evidence.musl_linkers = Observation::Present(vec![]);
    let mut inputs = MockInputs {
        evidence,
        download_called: false,
    };
    let mut stderr = Vec::new();
    let dest = temp.path().join("dest");
    let code = DefaultCommandHandler
        .execute_install(
            InstallOptions {
                offline_install: Some(archive),
                path: dest.clone(),
                ..InstallOptions::default()
            },
            &mut inputs,
            &mut Vec::new(),
            &mut stderr,
        )
        .unwrap();
    assert_eq!(code, 0, "{}", String::from_utf8(stderr).unwrap());
    assert!(dest.join("diorama").exists());
    assert!(!inputs.download_called);
}

#[test]
fn glibc_bundle_installs_with_an_optional_musl_toolchain_present() {
    for environment in ["gnu", "musl"] {
        let temp = TempDir::new().unwrap();
        let archive = build_bundle(temp.path(), &ARM64_ELF_HEADER, |_| {});
        let mut evidence = arm64_glibc_evidence();
        evidence.executable.environment = environment.into();
        evidence.musl_linkers = Observation::Present(vec!["/lib/ld-musl-aarch64.so.1".into()]);
        evidence.landmarks.insert(
            "/lib/ld-linux-aarch64.so.1".into(),
            Observation::Present(true),
        );
        let mut inputs = MockInputs {
            evidence,
            download_called: false,
        };
        let dest = temp.path().join("dest");
        let mut stderr = Vec::new();
        let code = DefaultCommandHandler
            .execute_install(
                InstallOptions {
                    offline_install: Some(archive),
                    path: dest.clone(),
                    ..InstallOptions::default()
                },
                &mut inputs,
                &mut Vec::new(),
                &mut stderr,
            )
            .unwrap();
        assert_eq!(code, 0, "{}", String::from_utf8(stderr).unwrap());
        assert_eq!(fs::read(dest.join("diorama")).unwrap(), ARM64_ELF_HEADER);
        assert!(!inputs.download_called);
    }
}

#[test]
fn glibc_bundle_is_rejected_on_a_musl_only_host_without_mutation() {
    let temp = TempDir::new().unwrap();
    let archive = build_bundle(temp.path(), &ARM64_ELF_HEADER, |_| {});
    let mut evidence = arm64_glibc_evidence();
    evidence.executable.environment = "musl".into();
    evidence.musl_linkers = Observation::Present(vec!["/lib/ld-musl-aarch64.so.1".into()]);
    evidence
        .landmarks
        .insert("/lib/ld-linux-aarch64.so.1".into(), Observation::Absent);
    let mut inputs = MockInputs {
        evidence,
        download_called: false,
    };
    let dest = temp.path().join("dest");
    let mut stderr = Vec::new();
    let code = DefaultCommandHandler
        .execute_install(
            InstallOptions {
                offline_install: Some(archive),
                path: dest.clone(),
                ..InstallOptions::default()
            },
            &mut inputs,
            &mut Vec::new(),
            &mut stderr,
        )
        .unwrap();
    assert_eq!(code, 1);
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("mismatched architecture or libc")
    );
    assert!(!dest.exists());
    assert!(!inputs.download_called);
}

#[test]
fn test_offline_install_rejects_digest_mismatch_without_mutation() {
    let temp = TempDir::new().unwrap();
    let dest = temp.path().join("dest");
    let archive = build_bundle(temp.path(), &ARM64_ELF_HEADER, |src| {
        fs::write(src.join("data.txt"), b"corrupt").unwrap();
    });
    let (code, err, _) = run(archive, &dest);
    assert_eq!(code, 1);
    assert!(err.contains("digest mismatch"), "{err}");
    assert!(!dest.exists());
}

#[test]
fn test_offline_install_rejects_foreign_executable() {
    let temp = TempDir::new().unwrap();
    let dest = temp.path().join("dest");
    let mut amd64 = ARM64_ELF_HEADER;
    amd64[18] = 62;
    amd64[19] = 0;
    let archive = build_bundle(temp.path(), &amd64, |_| {});
    let (code, err, _) = run(archive, &dest);
    assert_eq!(code, 1);
    assert!(err.contains("expected 183"), "{err}");
    assert!(!dest.exists());
}

#[test]
fn test_offline_install_rejects_unlisted_file_and_corrupt_archive() {
    let temp = TempDir::new().unwrap();
    let dest = temp.path().join("dest");
    let archive = build_bundle(temp.path(), &ARM64_ELF_HEADER, |src| {
        fs::write(src.join("extra"), b"x").unwrap();
    });
    let (code, err, _) = run(archive.clone(), &dest);
    assert_eq!(code, 1);
    assert!(err.contains("unlisted file"), "{err}");
    fs::write(&archive, b"not gzip").unwrap();
    let (code, err, _) = run(archive, &dest);
    assert_eq!(code, 1);
    assert!(err.contains("corrupt"), "{err}");
    assert!(!dest.exists());
}

#[test]
fn incompatible_new_kind_leaves_even_target_parents_untouched() {
    let temp = TempDir::new().unwrap();
    let archive = build_bundle(temp.path(), &ARM64_ELF_HEADER, |_| {});
    let renamed = temp
        .path()
        .join("diorama-v1.1.8-linux-arm64-container-offline.tar.gz");
    fs::rename(archive, &renamed).unwrap();
    let dest = temp.path().join("untouched/node");
    let (code, _, downloaded) = run(renamed, &dest);
    assert_ne!(code, 0);
    assert!(!downloaded);
    assert!(!temp.path().join("untouched").exists());
}

#[test]
fn duplicate_archive_entries_are_rejected_without_mutation() {
    let temp = TempDir::new().unwrap();
    let archive = build_bundle(temp.path(), &ARM64_ELF_HEADER, |_| {});
    let expanded = temp.path().join("expanded");
    fs::create_dir(&expanded).unwrap();
    assert!(
        SysCommand::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&expanded)
            .status()
            .unwrap()
            .success()
    );
    // A separate inode keeps GNU tar from encoding the duplicate as a hard link.
    let duplicate = temp.path().join("duplicate");
    fs::create_dir(&duplicate).unwrap();
    fs::copy(
        expanded.join("bundle.manifest"),
        duplicate.join("bundle.manifest"),
    )
    .unwrap();
    assert!(
        SysCommand::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&expanded)
            .arg(".")
            .arg("-C")
            .arg(&duplicate)
            .arg("./bundle.manifest")
            .status()
            .unwrap()
            .success()
    );
    let dest = temp.path().join("dest");
    let (code, error, downloaded) = run(archive, &dest);
    assert_ne!(code, 0);
    assert!(
        error.contains("duplicate archive member bundle.manifest"),
        "{error}"
    );
    assert!(!downloaded);
    assert!(!dest.exists());
}

#[test]
fn host_install_into_existing_data_root_preserves_state_and_cleans_staging() {
    let temp = TempDir::new().unwrap();
    let archive = build_bundle(temp.path(), &ARM64_ELF_HEADER, |_| {});
    let dest = temp.path().join("mounted-data");
    fs::create_dir_all(dest.join("pki")).unwrap();
    fs::write(dest.join("pki/keep"), b"existing identity").unwrap();
    let (code, error, _) = run(archive, &dest);
    assert_eq!(code, 0, "{error}");
    assert_eq!(
        fs::read(dest.join("pki/keep")).unwrap(),
        b"existing identity"
    );
    assert!(dest.join("diorama").is_file());
    assert!(
        fs::read_dir(&dest).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".tmp"))
    );
}
