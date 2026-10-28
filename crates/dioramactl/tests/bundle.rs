use diorama_assets::{Architecture, Libc};
use diorama_platform::preflight::PortAvailability;
use diorama_platform::preflight_probe::SupplementalFacts;
use diorama_platform::{ExecutableAbi, HostEvidence, Observation, PlatformError, ProbeFailure};
use dioramactl::CheckInputs;
use dioramactl::bundle::{BundleInput, BundleSpec, build_offline_bundle};
use dioramactl::contract::{CommandHandler, DefaultCommandHandler, InstallOptions};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

type Case = (&'static str, fn(&Path), &'static str);

#[cfg(unix)]
#[test]
fn builder_normalizes_executable_modes_and_installer_rejects_missing_execute_bits() {
    use std::os::unix::fs::PermissionsExt;
    let t = TempDir::new().unwrap();
    let s = spec(t.path(), 183);
    fs::set_permissions(&s.inputs[0].source, fs::Permissions::from_mode(0o644)).unwrap();
    let archive = build_offline_bundle(&s).unwrap();
    let dest = t.path().join("dest");
    let (code, err) = install(archive, &dest);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        fs::metadata(dest.join("bin/diorama"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );

    let t = TempDir::new().unwrap();
    let archive = tampered(t.path(), |tree| {
        fs::set_permissions(tree.join("bin/diorama"), fs::Permissions::from_mode(0o644)).unwrap();
    });
    let dest = t.path().join("dest");
    let (code, err) = install(archive, &dest);
    assert_eq!(code, 1);
    assert!(err.contains("invalid executable permissions"), "{err}");
    assert!(!dest.exists());
}

#[cfg(unix)]
#[test]
fn publication_rejects_destination_symlinks_without_overwriting_files() {
    use std::os::unix::fs::symlink;
    for root_link in [false, true] {
        let t = TempDir::new().unwrap();
        let archive = build_offline_bundle(&spec(t.path(), 183)).unwrap();
        let dest = t.path().join("dest");
        let outside = t.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("diorama"), b"unrelated host data").unwrap();
        if root_link {
            symlink(&outside, &dest).unwrap();
        } else {
            fs::create_dir(&dest).unwrap();
            fs::write(dest.join("data.txt"), b"existing installation").unwrap();
            symlink(&outside, dest.join("bin")).unwrap();
        }
        let (code, err) = install(archive, &dest);
        assert_eq!(code, 1, "{err}");
        assert_eq!(
            fs::read(outside.join("diorama")).unwrap(),
            b"unrelated host data"
        );
        assert!(!dest.join("bundle.manifest").exists());
        if !root_link {
            assert_eq!(
                fs::read(dest.join("data.txt")).unwrap(),
                b"existing installation"
            );
        }
    }
}

struct Mock;

impl CheckInputs for Mock {
    fn discover(&mut self) -> Result<HostEvidence, PlatformError> {
        fn denied<T>() -> Observation<T> {
            Observation::Unknown(ProbeFailure::PermissionDenied)
        }
        Ok(HostEvidence {
            executable: ExecutableAbi {
                os: "linux".to_string(),
                architecture: "aarch64".to_string(),
                environment: "gnu".to_string(),
            },
            kernel: denied(),
            privileges: denied(),
            hostname: denied(),
            container_environment_set: false,
            landmarks: BTreeMap::new(),
            musl_linkers: denied(),
            files: BTreeMap::new(),
            requested_paths: vec![],
        })
    }
    fn supplemental(&mut self) -> Result<SupplementalFacts, PlatformError> {
        Err(PlatformError::UnsupportedHost)
    }
    fn ports(&mut self, _p: bool) -> Result<[Observation<PortAvailability>; 4], PlatformError> {
        Err(PlatformError::UnsupportedHost)
    }
    fn download_file(
        &mut self,
        _u: &str,
        _d: &Path,
        _p: Option<&str>,
        _t: Option<&Path>,
    ) -> io::Result<()> {
        panic!("network egress attempted");
    }
}

fn elf(machine: u16) -> Vec<u8> {
    let mut b = vec![0u8; 64];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[18..20].copy_from_slice(&machine.to_le_bytes());
    b
}

fn spec(root: &Path, machine: u16) -> BundleSpec {
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("diorama"), elf(machine)).unwrap();
    fs::write(src.join("data.txt"), b"hello").unwrap();
    BundleSpec {
        version: "v1.1.8".to_string(),
        architecture: Architecture::Arm64,
        libc: Libc::Glibc,
        inputs: vec![
            BundleInput {
                source: src.join("diorama"),
                relative: "bin/diorama".to_string(),
                executable: true,
            },
            BundleInput {
                source: src.join("data.txt"),
                relative: "data.txt".to_string(),
                executable: false,
            },
        ],
        output_dir: root.join("out"),
    }
}

fn install(archive: PathBuf, dest: &Path) -> (u8, String) {
    let mut stderr = Vec::new();
    let code = DefaultCommandHandler
        .execute_install(
            InstallOptions {
                offline_install: Some(archive),
                path: dest.to_path_buf(),
                ..InstallOptions::default()
            },
            &mut Mock,
            &mut Vec::new(),
            &mut stderr,
        )
        .unwrap();
    (code, String::from_utf8(stderr).unwrap())
}

#[test]
fn built_bundle_round_trips_through_offline_install() {
    let t = TempDir::new().unwrap();
    let archive = build_offline_bundle(&spec(t.path(), 183)).unwrap();
    assert_eq!(
        archive.file_name().unwrap(),
        "diorama-v1.1.8-linux-arm64-offline.tar.gz"
    );
    let dest = t.path().join("dest");
    let (code, err) = install(archive, &dest);
    assert_eq!(code, 0, "{err}");
    assert_eq!(fs::read(dest.join("data.txt")).unwrap(), b"hello");
    let manifest = fs::read_to_string(dest.join("bundle.manifest")).unwrap();
    assert!(manifest.contains("arch=arm64") && manifest.contains("libc=glibc"));
    assert!(manifest.contains("exec ") && manifest.contains(" bin/diorama"));
}

#[test]
fn builder_rejects_foreign_elf_bad_paths_and_duplicates() {
    let t = TempDir::new().unwrap();
    let err = build_offline_bundle(&spec(t.path(), 62)).unwrap_err();
    assert!(err.contains("expected 183"), "{err}");
    let mut s = spec(t.path(), 183);
    s.inputs[1].relative = "../escape".to_string();
    assert!(build_offline_bundle(&s).unwrap_err().contains("unsafe"));
    let mut s = spec(t.path(), 183);
    s.inputs[1].relative = "bin/diorama".to_string();
    assert!(build_offline_bundle(&s).unwrap_err().contains("duplicate"));
    let mut s = spec(t.path(), 183);
    s.inputs[1].relative = "bundle.manifest".to_string();
    assert!(build_offline_bundle(&s).unwrap_err().contains("reserved"));
    let mut s = spec(t.path(), 183);
    s.inputs[0].executable = true;
    s.inputs[1].executable = true;
    assert!(build_offline_bundle(&s).unwrap_err().contains("not an ELF"));
}

/// Unpacks a built archive, applies `tamper`, repacks under the same name.
fn tampered(root: &Path, tamper: impl FnOnce(&Path)) -> PathBuf {
    let archive = build_offline_bundle(&spec(root, 183)).unwrap();
    let tree = root.join("tamper");
    fs::create_dir(&tree).unwrap();
    assert!(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&tree)
            .status()
            .unwrap()
            .success()
    );
    tamper(&tree);
    assert!(
        Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&tree)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    archive
}

#[test]
fn tampered_built_bundles_are_rejected_without_mutation() {
    let cases: [Case; 4] = [
        (
            "digest",
            |t| fs::write(t.join("data.txt"), b"evil").unwrap(),
            "digest mismatch",
        ),
        (
            "unlisted",
            |t| fs::write(t.join("extra"), b"x").unwrap(),
            "unlisted file",
        ),
        (
            "foreign-elf",
            |t| fs::write(t.join("bin/diorama"), elf(62)).unwrap(),
            "digest mismatch",
        ),
        (
            "missing",
            |t| fs::remove_file(t.join("data.txt")).unwrap(),
            "missing bundle file",
        ),
    ];
    for (name, tamper, want) in cases {
        let t = TempDir::new().unwrap();
        let archive = tampered(t.path(), tamper);
        let dest = t.path().join("dest");
        let (code, err) = install(archive, &dest);
        assert_eq!(code, 1, "{name}: {err}");
        assert!(err.contains(want), "{name}: {err}");
        assert!(!dest.exists(), "{name}");
    }
}

#[test]
fn manifest_metadata_tamper_and_online_path() {
    let t = TempDir::new().unwrap();
    let archive = tampered(t.path(), |tree| {
        let p = tree.join("bundle.manifest");
        let m = fs::read_to_string(&p)
            .unwrap()
            .replace("libc=glibc", "libc=musl");
        fs::write(p, m).unwrap();
    });
    let dest = t.path().join("dest");
    let (code, err) = install(archive, &dest);
    assert_eq!(code, 1);
    assert!(err.contains("does not match target"), "{err}");
    assert!(!dest.exists());

    let mut stderr = Vec::new();
    let code = DefaultCommandHandler
        .execute_install(
            InstallOptions::default(),
            &mut Mock,
            &mut Vec::new(),
            &mut stderr,
        )
        .unwrap();
    assert_eq!(code, 1);
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("not yet implemented")
    );
}
