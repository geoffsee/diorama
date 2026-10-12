//! Run the pinned external scanners and require complete Rust source coverage.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use diorama_dev::{Result, read_bounded, repository_root, run_checked};
use serde_json::Value;

const SEMGREP_IMAGE: &str = "semgrep/semgrep:1.178.0@sha256:32e459968daabe7ab86968184a29109b9564aa00392401156f9788452b42786b";

fn sources(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let output = Command::new("git")
        .current_dir(root)
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "*.rs",
        ])
        .output()?;
    if !output.status.success() {
        return Err("cannot inventory Rust sources".into());
    }
    let mut paths = BTreeSet::new();
    for path in std::str::from_utf8(&output.stdout)?.split('\0') {
        if !path.is_empty()
            && !path.starts_with(".github/security/rules/")
            && root.join(path).is_file()
        {
            paths.insert(PathBuf::from(path));
        }
    }
    if paths.is_empty() {
        return Err("no Rust sources; refusing an empty security scan".into());
    }
    Ok(paths)
}

fn scanner(root: &Path, reports: &Path) -> Result<Command> {
    let user = format!(
        "{}:{}",
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw()
    );
    let source_mount = format!("{}:/workspace:ro", root.display());
    let report_mount = format!("{}:/reports:rw", reports.display());
    if root.to_string_lossy().contains(':') || reports.to_string_lossy().contains(':') {
        return Err("scanner mount paths must not contain a colon".into());
    }
    let mut command = Command::new("docker");
    command.args([
        "run",
        "--rm",
        "--user",
        &user,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=256m",
        "--env",
        "HOME=/tmp",
        "--env",
        "SEMGREP_SEND_METRICS=off",
        "--env",
        "SEMGREP_ENABLE_VERSION_CHECK=0",
        "--workdir",
        "/workspace",
        "--volume",
        &source_mount,
        "--volume",
        &report_mount,
        "--entrypoint",
        "semgrep",
        SEMGREP_IMAGE,
        "scan",
        "--metrics=off",
        "--disable-version-check",
    ]);
    Ok(command)
}

fn validate_report(report: &Value, expected: &BTreeSet<PathBuf>) -> Result<()> {
    let errors = report["errors"]
        .as_array()
        .ok_or("missing scanner error inventory")?;
    let findings = report["results"]
        .as_array()
        .ok_or("missing scanner finding inventory")?;
    if !errors.is_empty() || !findings.is_empty() {
        return Err("scanner reported errors or findings".into());
    }
    let scanned = report["paths"]["scanned"]
        .as_array()
        .ok_or("missing scanned paths")?;
    let mut actual = BTreeSet::new();
    for path in scanned {
        let path = Path::new(path.as_str().ok_or("invalid scanned path")?);
        let path = path.strip_prefix("/workspace").unwrap_or(path);
        if path.components().any(|part| {
            !matches!(
                part,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        }) {
            return Err("scanner returned an unexpected path".into());
        }
        actual.insert(
            path.components()
                .filter(|part| *part != std::path::Component::CurDir)
                .collect(),
        );
    }
    let missing: Vec<_> = expected.difference(&actual).collect();
    if !missing.is_empty() {
        return Err(format!("incomplete Rust scan; missing {missing:?}").into());
    }
    Ok(())
}

fn main() -> Result<()> {
    if std::env::args_os().len() != 1 {
        return Err("usage: diorama-security".into());
    }
    let root = repository_root(&std::env::current_dir()?)?;
    let sources = sources(&root)?;
    let directory = tempfile::Builder::new()
        .prefix("diorama-security-")
        .tempdir()?;
    run_checked(Command::new("docker").args(["pull", SEMGREP_IMAGE]))?;
    run_checked(scanner(&root, directory.path())?.args(["--test", ".github/security/rules"]))?;
    let mut scan = scanner(&root, directory.path())?;
    scan.args([
        "--config",
        ".github/security/rules",
        "--strict",
        "--error",
        "--disable-nosem",
        "--no-git-ignore",
        "--json-output",
        "/reports/semgrep.json",
        "--",
    ])
    .args(&sources);
    run_checked(&mut scan)?;
    let report = serde_json::from_slice(&read_bounded(
        &directory.path().join("semgrep.json"),
        32 * 1024 * 1024,
    )?)?;
    validate_report(&report, &sources)?;
    let mut zizmor = Command::new("zizmor");
    zizmor.current_dir(&root).args([
        "--offline",
        "--format",
        "plain",
        ".github/workflows",
        ".github/actions",
    ]);
    for name in [
        "SEMGREP_APP_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "ZIZMOR_GITHUB_TOKEN",
    ] {
        zizmor.env_remove(name);
    }
    run_checked(zizmor.env("ZIZMOR_OFFLINE", "1"))?;
    println!(
        "Security checks passed: {} Rust sources and local Actions definitions.",
        sources.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scanner_uses_effective_identity_without_changing_private_report_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let before = directory.path().metadata().unwrap().permissions().mode();
        let command = scanner(Path::new("/source"), directory.path()).unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        let identity = format!(
            "{}:{}",
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw()
        );
        assert!(args.windows(2).any(|pair| pair == ["--user", &identity]));
        assert!(args.windows(2).any(|pair| pair == ["--cap-drop", "ALL"]));
        assert!(args.contains(&"--read-only"));
        assert_eq!(before & 0o777, 0o700);
        assert_eq!(
            directory.path().metadata().unwrap().permissions().mode(),
            before
        );
    }

    #[test]
    fn scan_requires_complete_coverage_and_no_errors_or_findings() {
        let expected = BTreeSet::from([PathBuf::from("src/lib.rs")]);
        let valid = json!({"errors":[],"results":[],"paths":{"scanned":["/workspace/src/lib.rs"]}});
        assert!(validate_report(&valid, &expected).is_ok());
        for report in [
            json!({"errors":[],"results":[],"paths":{"scanned":[]}}),
            json!({"errors":[{}],"results":[],"paths":{"scanned":["src/lib.rs"]}}),
            json!({"errors":[],"results":[{}],"paths":{"scanned":["src/lib.rs"]}}),
            json!({"errors":[],"results":[],"paths":{"scanned":["../src/lib.rs"]}}),
            json!({"paths":{"scanned":["src/lib.rs"]}}),
        ] {
            assert!(validate_report(&report, &expected).is_err());
        }
    }
}
