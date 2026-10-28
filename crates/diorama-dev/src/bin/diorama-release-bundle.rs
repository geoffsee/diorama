//! Prepare pinned release inputs and package complete offline bundles.
use diorama_dev::{Result, release_bundle};
use std::{path::Path, process::ExitCode};

fn run(args: &[String]) -> Result<()> {
    match args {
        [command, arch, destination] if command == "prepare" => {
            release_bundle::prepare(arch, Path::new(destination))
        },
        [command, version, arch, binaries, assets, output] if command == "package" => {
            let archive = release_bundle::package(
                version, arch, Path::new(binaries), Path::new(assets), Path::new(output),
            )?;
            println!("{}", archive.display());
            Ok(())
        },
        _ => Err("usage: diorama-release-bundle prepare <amd64|arm64> <assets-dir>\n       diorama-release-bundle package <version> <amd64|arm64> <binary-dir> <assets-dir> <output-dir>".into()),
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
