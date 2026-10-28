use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn copy(engine: &Path, source: &Path, destination: &Path, mode: &str) -> Output {
    Command::new("bash")
        .args([
            "-c",
            "source \"$1\"; engine=$2; name=test-node; copy_into_node \"$3\" \"$4\" \"$5\"",
            "copy-test",
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../container/offline-helpers.sh"))
        .args([engine, source, destination])
        .arg(mode)
        .output()
        .unwrap()
}

fn engine(root: &Path) -> std::path::PathBuf {
    let engine = root.join("test engine");
    // Execute the real container-side shell locally; keep stdin and arguments intact.
    fs::write(&engine, "#!/bin/sh\n[ \"$1\" = exec ] && [ \"$2\" = -i ] && [ \"$3\" = test-node ] || exit 99\nshift 3\nexec \"$@\"\n").unwrap();
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o755)).unwrap();
    engine
}

#[test]
fn offline_fixture_transfer_preserves_binary_bytes_paths_and_permissions() {
    let root = tempfile::tempdir().unwrap();
    let engine = engine(root.path());
    let source = root.path().join("binary input");
    let destination = root.path().join("destination $file's bytes");
    let bytes: Vec<u8> = (0..=255).cycle().take(8192).collect();
    fs::write(&source, &bytes).unwrap();
    for mode in [0o755, 0o644] {
        let output = copy(&engine, &source, &destination, &format!("{mode:o}"));
        assert!(output.status.success(), "{output:?}");
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            mode
        );
    }
}

#[test]
fn offline_fixture_transfer_propagates_read_write_and_engine_failures() {
    let root = tempfile::tempdir().unwrap();
    let engine = engine(root.path());
    let source = root.path().join("source");
    let destination = root.path().join("destination");
    fs::write(&source, b"fixture").unwrap();
    assert!(
        !copy(&engine, &root.path().join("missing"), &destination, "644")
            .status
            .success()
    );
    assert!(!destination.exists());
    assert!(!copy(&engine, &source, root.path(), "644").status.success());
    fs::write(&engine, "#!/bin/sh\nexit 7\n").unwrap();
    assert_eq!(
        copy(&engine, &source, &destination, "644").status.code(),
        Some(7)
    );
    assert!(!destination.exists());
}

#[test]
fn offline_job_extraction_accepts_the_bundle_builders_dot_prefixed_members() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input");
    let output = root.path().join("output");
    fs::create_dir(&input).unwrap();
    fs::create_dir(&output).unwrap();
    let job = br#"{"kind":"Job","metadata":{"name":"offline-installer"}}"#;
    fs::write(input.join("install-job.json"), job).unwrap();
    let archive = root.path().join("addon.tar.gz");
    assert!(
        Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&input)
            .arg(".")
            .status()
            .unwrap()
            .success()
    );
    let result = Command::new("bash")
        .args([
            "-c",
            "source \"$1\"; extract_install_job \"$2\" \"$3\"",
            "extract-test",
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../container/offline-helpers.sh"))
        .arg(&archive)
        .arg(&output)
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    assert_eq!(fs::read(output.join("install-job.json")).unwrap(), job);
}
