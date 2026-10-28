//! Validate an add-on pack before importing into the selected node's Kubernetes image store.
use diorama_assets::{Architecture, ArtifactNaming, BundleKind, BundleMetadata};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub const HELP: &str = "Load a verified offline add-on image.\n\nUsage:\n  dioramactl addon load <archive> [--path <node-data>] [--container <container-name>] [--engine docker|podman]\n\nAfter loading, configure and apply the archive's install-job.json on this node.\n";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddonOptions {
    pub archive: PathBuf,
    pub path: PathBuf,
    pub container: Option<String>,
    pub engine: String,
}

pub fn parse(args: &[String]) -> Result<AddonOptions, crate::ParseError> {
    if args.first().map(String::as_str) != Some("load") || args.len() < 2 {
        return Err(crate::ParseError::UnknownCommand);
    }
    let mut options = AddonOptions {
        archive: (&args[1]).into(),
        path: crate::DEFAULT_DATA_PATH.into(),
        container: None,
        engine: "docker".into(),
    };
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        let (key, value) = match arg.split_once('=') {
            Some(pair) => pair,
            None => (
                arg.as_str(),
                rest.next().ok_or(crate::ParseError::UnknownFlag)?.as_str(),
            ),
        };
        match key {
            "--path" => options.path = value.into(),
            "--container" if !value.starts_with('-') && !value.is_empty() => {
                options.container = Some(value.into());
            },
            "--engine" if matches!(value, "docker" | "podman") => options.engine = value.into(),
            _ => return Err(crate::ParseError::UnknownFlag),
        }
    }
    Ok(options)
}

fn architecture(options: &AddonOptions) -> io::Result<Architecture> {
    let arch = if let Some(container) = &options.container {
        let output = Command::new(&options.engine)
            .args(["exec", container, "uname", "-m"])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(
                "cannot inspect selected Diorama container",
            ));
        }
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    } else {
        if std::env::consts::OS != "linux" {
            return Err(io::Error::other(
                "host add-on loading requires Linux; select --container for a remote Linux node",
            ));
        }
        std::env::consts::ARCH.into()
    };
    match arch.as_str() {
        "aarch64" | "arm64" => Ok(Architecture::Arm64),
        "x86_64" | "amd64" => Ok(Architecture::Amd64),
        _ => Err(io::Error::other(
            "add-on packs support amd64 and arm64 nodes",
        )),
    }
}

fn stream(command: &mut Command, source: &Path) -> io::Result<()> {
    let mut source = fs::File::open(source)?;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let result = io::copy(
        &mut source,
        &mut child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing importer stdin"))?,
    );
    if let Err(error) = result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    if !child.wait()?.success() {
        return Err(io::Error::other(
            "add-on import or retention failed; check node runtime socket, data path and permissions",
        ));
    }
    Ok(())
}

fn retain(options: &AddonOptions, bundle: &BundleMetadata, source: &Path) -> io::Result<()> {
    let directory = options.path.join("images/addons");
    let name = format!("{}-{}.tar.gz", bundle.suffix(), bundle.version);
    if let Some(container) = &options.container {
        // Parameters remain positional shell arguments, never interpolated command text.
        let mut command = Command::new(&options.engine);
        command.args(["exec", "-i", container, "/bin/sh", "-c",
            "set -eu; mkdir -p \"$1\"; tmp=$(mktemp \"$1/.load.XXXXXX\"); trap 'rm -f \"$tmp\"' EXIT; cat > \"$tmp\"; chmod 0644 \"$tmp\"; mv -f \"$tmp\" \"$1/$2\"", "addon-retain"])
            .arg(directory).arg(name);
        stream(&mut command, source)
    } else {
        fs::create_dir_all(&directory)?;
        let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
        io::copy(&mut fs::File::open(source)?, &mut temporary)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(directory.join(name))
            .map_err(|e| e.error)?;
        Ok(())
    }
}

pub fn load(options: &AddonOptions, stdout: &mut dyn Write) -> io::Result<()> {
    let parsed = ArtifactNaming::parse_node_archive(
        &options
            .archive
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
    )
    .map_err(io::Error::other)?;
    if parsed.variant.architecture != architecture(options)? {
        return Err(io::Error::other(
            "add-on architecture does not match selected node",
        ));
    }
    let staged = tempfile::tempdir()?;
    crate::offline::stage(&options.archive, staged.path()).map_err(io::Error::other)?;
    let inventory = crate::offline::validate(staged.path(), &parsed, BundleKind::Addon)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("missing add-on inventory"))?;
    let bundle: &BundleMetadata = inventory
        .bundle()
        .ok_or_else(|| io::Error::other("legacy bundles are not add-on packs"))?;
    let (id, relative, _, _) = inventory
        .bundled_assets()
        .next()
        .ok_or_else(|| io::Error::other("missing installer image"))?;
    let mut command = if let Some(container) = &options.container {
        let mut command = Command::new(&options.engine);
        command.args(["exec", "-i", container, "/usr/local/bin/ctr"]);
        command
    } else {
        Command::new(options.path.join("bin/ctr"))
    };
    command
        .arg("--address")
        .arg(options.path.join("containerd/state/containerd.sock"))
        .args([
            "--namespace",
            "k8s.io",
            "images",
            "import",
            "--all-platforms",
            "-",
        ]);
    let source = staged.path().join(relative);
    stream(&mut command, &source)?;
    retain(options, bundle, &source)?;
    writeln!(
        stdout,
        "Loaded {} into k8s.io. Configure install-job.json with this node's name and apply it.",
        bundle.image_reference(id).unwrap_or_default()
    )?;
    Ok(())
}

pub fn execute(
    options: &AddonOptions,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> io::Result<u8> {
    match load(options, stdout) {
        Ok(()) => Ok(0),
        Err(error) => {
            writeln!(stderr, "error: add-on load: {error}")?;
            Ok(1)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diorama_assets::Capability;

    #[test]
    fn loading_options_keep_container_identity_explicit() {
        let args = [
            "load",
            "pack.tar.gz",
            "--container=node-one",
            "--engine",
            "podman",
            "--path=/node",
        ]
        .map(String::from);
        let options = parse(&args).unwrap();
        assert_eq!(options.container.as_deref(), Some("node-one"));
        assert_eq!(options.engine, "podman");
        assert_eq!(options.path, PathBuf::from("/node"));
        for value in ["", "--privileged"] {
            assert!(
                parse(&[
                    "load".into(),
                    "pack.tar.gz".into(),
                    format!("--container={value}")
                ])
                .is_err()
            );
        }
        assert!(parse(&["load".into(), "pack.tar.gz".into(), "--engine=sh".into()]).is_err());
    }

    #[test]
    fn verified_images_are_retained_across_versions_without_overwriting_other_addons() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("verified.gz");
        fs::write(&source, b"verified image bytes").unwrap();
        let options = AddonOptions {
            archive: source.clone(),
            path: root.path().join("node"),
            container: None,
            engine: "docker".into(),
        };
        for version in ["v1", "v2"] {
            retain(
                &options,
                &BundleMetadata {
                    kind: BundleKind::Addon,
                    version: version.into(),
                    capabilities: vec![Capability::D2k],
                },
                &source,
            )
            .unwrap();
        }
        for version in ["v1", "v2"] {
            assert_eq!(
                fs::read(
                    options
                        .path
                        .join(format!("images/addons/addon-d2k-{version}.tar.gz"))
                )
                .unwrap(),
                b"verified image bytes"
            );
        }
        assert_eq!(
            fs::read_dir(options.path.join("images/addons"))
                .unwrap()
                .count(),
            2
        );
    }
}
