//! Source-bound startup and disposable Alpine qualification.
pub(crate) mod alpine;
mod capture;
pub(crate) mod command_evidence;
pub(crate) mod guest;
pub(crate) mod preparation;
mod prepare;
mod startup;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
type Result<T> = diorama_dev::Result<T>;
fn require(ok: bool, message: impl Into<String>) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    crate::parity::read(path, limit)
}
fn load(path: &Path) -> Result<Value> {
    diorama_dev::json::parse(&read(path, 8 * 1024 * 1024)?)
}
fn digest(path: &Path) -> Result<String> {
    crate::parity::digest(path, false)
}
fn equal(actual: &Value, expected: &Value, label: &str) -> Result<()> {
    require(
        diorama_dev::json::changes(actual, expected).is_empty(),
        format!("{label}: exact typed value mismatch"),
    )
}
fn text(path: &Path) -> Result<String> {
    Ok(String::from_utf8(read(path, 8 * 1024 * 1024)?)?)
}
fn fixture(root: &Path, name: &str) -> PathBuf {
    root.join("tools/parity/fixtures").join(name)
}
pub(crate) fn source_inventory(root: &Path, profile: &str) -> Result<Value> {
    fn add(root: &Path, path: &Path, map: &mut BTreeMap<String, String>) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        require(!metadata.is_symlink(), "source symlink rejected")?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path)? {
                add(root, &entry?.path(), map)?;
            }
        } else if metadata.is_file() {
            map.insert(
                path.strip_prefix(root)?.to_string_lossy().into_owned(),
                digest(path)?,
            );
        } else {
            return Err("special source file".into());
        }
        Ok(())
    }
    let mut map = BTreeMap::new();
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "tools/dev/Cargo.toml",
        "tools/dev/src",
    ] {
        add(root, &root.join(name), &mut map)?;
    }
    let names: &[&str] = match profile {
        "startup" => &[
            "cli-startup/suite.json",
            "cli-startup/observations.json",
            "cli-startup/provenance.json",
        ],
        "alpine" => &[
            "alpine-preparation/inputs.json",
            "alpine-preparation/guest.sh",
            "alpine-preparation/reboot.sh",
            "alpine-preparation/baseline_test.go",
            "alpine-preparation/go.mod",
            "alpine-preparation/Prepare.Dockerfile",
        ],
        "alpine-rust" => &[
            "alpine-rust-preparation/inputs.json",
            "alpine-rust-preparation/guest.sh",
            "alpine-rust-preparation/reboot.sh",
            "alpine-rust-preparation/service-double.sh",
        ],
        "prerequisite" => &[
            "prerequisite-preparation/Linux.Dockerfile",
            "prerequisite-preparation/fixture-command.rs",
            "management-check/cases.json",
            "management-check/expected.json",
        ],
        _ => return Err("unknown profile".into()),
    };
    for name in names {
        add(
            root,
            &root.join("tools/parity/fixtures").join(name),
            &mut map,
        )?;
    }
    Ok(serde_json::to_value(map)?)
}
#[derive(Debug)]
struct Options {
    values: BTreeMap<String, PathBuf>,
    privileged: bool,
}
impl Options {
    fn parse(args: &[OsString]) -> Result<Self> {
        let mut values = BTreeMap::new();
        let mut privileged = false;
        let mut args = args.iter();
        while let Some(key) = args.next() {
            let key = key.to_str().ok_or("UTF-8 option required")?;
            if key == "--allow-privileged-vm" {
                require(!privileged, "duplicate privilege flag")?;
                privileged = true;
                continue;
            }
            require(
                [
                    "--repo",
                    "--directory",
                    "--output",
                    "--artifact",
                    "--runner",
                    "--driver",
                    "--image-cache",
                    "--input-cache",
                    "--artifact-directory",
                    "--baseline-directory",
                    "--inject-failure",
                    "--cache",
                ]
                .contains(&key),
                "unknown option",
            )?;
            require(
                values
                    .insert(
                        key.into(),
                        PathBuf::from(args.next().ok_or("option value required")?),
                    )
                    .is_none(),
                "duplicate option",
            )?;
        }
        Ok(Self { values, privileged })
    }
    fn path(&self, name: &str) -> Result<&Path> {
        self.values
            .get(name)
            .map(PathBuf::as_path)
            .ok_or_else(|| format!("required {name}").into())
    }
    fn root(&self) -> Result<PathBuf> {
        diorama_dev::repository_root(
            self.values
                .get("--repo")
                .map_or(Path::new("."), PathBuf::as_path),
        )
    }
}
pub(crate) fn main(args: &[OsString]) -> Result<u8> {
    if args.first().is_some_and(|a| a == "__exec") {
        return crate::parity::main(args);
    }
    let profile = args
        .first()
        .and_then(|a| a.to_str())
        .ok_or("profile required")?;
    let command = args
        .get(1)
        .and_then(|a| a.to_str())
        .ok_or("command required")?;
    let options = Options::parse(&args[2..])?;
    let root = options.root()?;
    match (profile, command) {
        ("alpine", "prepare") => prepare::run(&root, &options),
        ("alpine", "verify-prepare") => {
            prepare::verify(&root, options.path("--directory")?)?;
            Ok(0)
        },
        ("startup", "capture") => startup::capture(&root, &options),
        ("startup", "verify") => {
            startup::verify(&root, options.path("--directory")?)?;
            Ok(0)
        },
        ("alpine" | "alpine-rust", "verify") => {
            alpine::verify_with_baseline(
                &root,
                profile,
                options.path("--directory")?,
                options
                    .values
                    .get("--baseline-directory")
                    .map(PathBuf::as_path),
            )?;
            Ok(0)
        },
        ("alpine" | "alpine-rust", "capture") => {
            require(
                options.privileged,
                "explicit --allow-privileged-vm required",
            )?;
            capture::alpine(&root, profile, &options)
        },
        _ => Err("unknown fixture profile/command".into()),
    }
}
