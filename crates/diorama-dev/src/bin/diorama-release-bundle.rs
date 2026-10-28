//! Prepare pinned release inputs and package complete offline bundles.
use diorama_dev::{Result, release_bundle};
use std::{path::Path, process::ExitCode};

fn run(args: &[String]) -> Result<()> {
    match args {
        [command, arch, destination] if command == "prepare" => {
            release_bundle::prepare(arch, Path::new(destination))
        },
        [command, version, arch, installer, assets, engine, registry] if command == "build-images" => {
            release_bundle::build_images(version, arch, Path::new(installer), Path::new(assets), engine, registry)
        },
        [command, kind, version, arch, binaries, assets, output] if command == "package" => {
            use diorama_assets::{BundleKind, Capability};
            let (kind, addon) = match kind.as_str() {
                "host" => (BundleKind::Host, None), "container" => (BundleKind::Container, None),
                "portainer-agent" => (BundleKind::Addon, Some(Capability::PortainerAgent)),
                "d2k" => (BundleKind::Addon, Some(Capability::D2k)),
                _ => return Err("invalid bundle kind".into()),
            };
            let archive = release_bundle::package(
                kind, addon, version, arch, Path::new(binaries), Path::new(assets), Path::new(output),
            )?;
            println!("{}", archive.display());
            Ok(())
        },
        _ => Err("usage: diorama-release-bundle prepare <amd64|arm64> <assets-dir>\n       diorama-release-bundle build-images <version> <amd64|arm64> <installer> <assets-dir> <docker|podman> <local-registry>\n       diorama-release-bundle package <host|container|portainer-agent|d2k> <version> <amd64|arm64> <binary-dir> <assets-dir> <output-dir>".into()),
    }
}

fn main() -> ExitCode {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("offline bundle: {error}");
            ExitCode::FAILURE
        },
    }
}
