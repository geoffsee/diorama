mod qualify;
#[cfg(target_os = "linux")]
mod runtime;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};
type Result<T> = diorama_dev::Result<T>;
fn require(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
pub(super) fn main(args: &[OsString]) -> Result<u8> {
    if args.first().is_some_and(|s| s == "__exec") {
        return crate::parity::process::child_exec(args);
    }
    #[cfg(target_os = "linux")]
    if args.first().is_some_and(|s| s == "__enter-chroot") {
        return runtime::enter(&args[1..]);
    }
    #[cfg(target_os = "linux")]
    if args == [OsString::from("--run-disposable-fixture")] {
        return runtime::run();
    }
    let command = args
        .first()
        .and_then(|s| s.to_str())
        .ok_or("qualify or verify required")?;
    require(
        ["qualify", "verify"].contains(&command),
        "qualify or verify required",
    )?;
    let mut root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
    let mut output = None;
    for pair in args[1..].chunks(2) {
        require(pair.len() == 2, "option value missing")?;
        match pair[0].to_str() {
            Some("--repo") => root = PathBuf::from(&pair[1]),
            Some("--output" | "--directory") => output = Some(PathBuf::from(&pair[1])),
            _ => return Err("unknown option".into()),
        }
    }
    let output = output.ok_or("output or directory required")?;
    if command == "verify" {
        crate::platform_fixture::preparation::verify(&root, &output)?;
        Ok(0)
    } else {
        qualify::run(&root, &output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn missing_prerequisite_sources_fail_before_output_creation() -> Result<()> {
        let root = tempfile::tempdir()?;
        let output = root.path().join("evidence");
        assert!(qualify::run(root.path(), &output).is_err());
        assert!(!output.exists());
        Ok(())
    }
    #[test]
    #[ignore = "receipt checks disabled"]
    fn historical_publication_remains_byte_identical() -> Result<()> {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        let here = root.join("tools/parity/fixtures/prerequisite-preparation");
        let provenance = diorama_dev::json::parse(&crate::parity::read(
            &here.join("linux-provenance.json"),
            65536,
        )?)?;
        assert_eq!(provenance["schema"], json!(1));
        let files = provenance["files"].as_object().ok_or("inventory")?;
        assert_eq!(
            files.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["build.log", "receipt.json", "run.log", "source-hashes.json"]
        );
        for (name, hash) in files {
            assert_eq!(
                &json!(crate::parity::digest(
                    &here.join("evidence-linux").join(name),
                    false
                )?),
                hash
            );
        }
        Ok(())
    }
    #[test]
    fn prerequisite_oracle_rejects_missing_cases_binary_aliases_and_false_exit_types() -> Result<()>
    {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        let raw = String::from_utf8(crate::parity::read(
            &root.join("tools/parity/fixtures/prerequisite-preparation/evidence-linux/run.log"),
            1024 * 1024,
        )?)?;
        crate::platform_fixture::preparation::verify_run(&raw)?;
        for bad in [
            raw.replace("6 passed;", "5 passed;"),
            raw.replace("/out/fixture-command", "/out/dioramactl"),
            raw.replace("/out/preparation-tests", "/out/unknown"),
        ] {
            assert!(crate::platform_fixture::preparation::verify_run(&bad).is_err());
        }
        let line = raw
            .lines()
            .find(|s| s.starts_with("DIORAMA_PREPARATION "))
            .ok_or("record")?;
        let record = diorama_dev::json::parse(
            line.strip_prefix("DIORAMA_PREPARATION ")
                .ok_or("prefix")?
                .as_bytes(),
        )?;
        for (index, key, value) in [
            (
                0,
                "actions",
                json!(["/sbin/apk add --no-cache nftables iptables"]),
            ),
            (1, "exit", json!(false)),
            (4, "stderr", json!("error")),
            (6, "owned_child_absent", json!(false)),
            (6, "signal_sent", json!(null)),
            (3, "exit", json!(0)),
        ] {
            let mut changed = record.clone();
            changed["cases"][index][key] = value;
            assert!(
                crate::platform_fixture::preparation::verify_run(&raw.replace(
                    line,
                    &format!("DIORAMA_PREPARATION {}", serde_json::to_string(&changed)?)
                ))
                .is_err(),
                "{index} {key}"
            );
        }
        let mut changed = record;
        changed["cases"].as_array_mut().ok_or("cases")?.pop();
        assert!(
            crate::platform_fixture::preparation::verify_run(&raw.replace(
                line,
                &format!("DIORAMA_PREPARATION {}", serde_json::to_string(&changed)?)
            ))
            .is_err()
        );
        Ok(())
    }
    #[test]
    #[ignore = "source hash qualification receipt checks disabled"]
    fn published_prerequisite_requires_current_rust_capture() -> Result<()> {
        let root = diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))?;
        crate::platform_fixture::preparation::verify(
            &root,
            &root.join("tools/parity/fixtures/prerequisite-preparation/evidence-rust"),
        )?;
        Ok(())
    }
}
