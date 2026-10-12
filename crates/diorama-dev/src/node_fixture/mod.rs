mod assessment;
mod build;
mod commands;
mod common;
#[cfg(test)]
mod constrained_diagnostics;
mod constrained_verify;
mod container;
mod docker;
#[cfg(test)]
mod docker_tests;
mod guest;
mod network;
mod runtime;
#[cfg(test)]
mod tests;
use common::Result;
pub(super) fn main() -> Result<u8> {
    let all = std::env::args_os().collect::<Vec<_>>();
    let args = &all[1..];
    if args.first().is_some_and(|s| s == "__exec") {
        return crate::parity::process::child_exec(args);
    }
    if args.first().is_some_and(|s| s == "probe") {
        return runtime::probe(&args[1..]);
    }
    if all.first().is_some_and(|s| {
        std::path::Path::new(s)
            .file_name()
            .is_some_and(|s| s == "iptables")
    }) {
        return runtime::probe(args);
    }
    let args = args
        .iter()
        .map(|s| s.to_str().ok_or("argument UTF8"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let cancellation = crate::parity::process::Cancellation::default();
    let _signals = if args.contains(&"capture-vm")
        || args.contains(&"capture")
        || args.contains(&"build")
        || args.contains(&"consumer")
    {
        Some(crate::parity::process::SignalGuard::install(
            cancellation.clone(),
        )?)
    } else {
        None
    };
    dispatch(&args, &cancellation)
}
fn dispatch(args: &[&str], cancellation: &crate::parity::process::Cancellation) -> Result<u8> {
    match args {
        [
            family @ ("network" | "container" | "constrained"),
            "verify-published",
        ] => {
            guest::published(&root()?, family)?;
            Ok(0)
        },
        [family, "capture-vm", options @ ..] => {
            guest::cli(&root()?, family, options, cancellation)?;
            Ok(0)
        },
        [
            family @ ("network" | "container" | "constrained"),
            "verify",
            directory,
        ] => {
            println!("{}", guest::verify(&root()?, family, directory.as_ref())?);
            Ok(0)
        },
        [family, "build" | "capture", directory] => {
            docker::capture(&root()?, family, directory.as_ref(), cancellation)?;
            Ok(0)
        },
        [family, "verify-build", directory] => {
            println!(
                "{}",
                docker::verify(&root()?, family, directory.as_ref(), true)?
            );
            Ok(0)
        },
        [family @ ("assessment" | "probes"), "verify", directory] => {
            docker::verify(&root()?, family, directory.as_ref(), false)?;
            Ok(0)
        },
        ["namespace"] => {
            runtime::namespace()?;
            Ok(0)
        },
        ["assessment", "records", path] => {
            let raw = String::from_utf8(common::read(path.as_ref(), 1024 * 1024)?)?;
            println!("{}", assessment::records(&raw)?.0);
            Ok(0)
        },
        ["held-writer"] => runtime::held_writer(),
        ["sentinel"] => {
            std::thread::sleep(std::time::Duration::from_mins(1));
            Ok(0)
        },
        ["consumer"] => {
            runtime::consumer(cancellation)?;
            Ok(0)
        },
        ["container", "semantic", path, metadata] => {
            let root = diorama_dev::repository_root(&std::env::current_dir()?)?;
            let raw = String::from_utf8(common::read(path.as_ref(), 8 * 1024 * 1024)?)?;
            println!(
                "{}",
                container::semantic(&root, &raw, &common::load(metadata.as_ref())?)?
            );
            Ok(0)
        },
        ["network", "semantic", path] => {
            let root = diorama_dev::repository_root(&std::env::current_dir()?)?;
            let raw = String::from_utf8(common::read(path.as_ref(), 8 * 1024 * 1024)?)?;
            println!("{}", network::semantic(&root, &raw)?);
            Ok(0)
        },
        [family, "build-log", path] => {
            let root = diorama_dev::repository_root(&std::env::current_dir()?)?;
            let raw = String::from_utf8(common::read(path.as_ref(), 32 * 1024 * 1024)?)?;
            println!("{}", build::verify_run(&root, family, &raw)?);
            Ok(0)
        },
        _ => crate::platform_fixture::main(
            &args
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>(),
        ),
    }
}
fn root() -> Result<std::path::PathBuf> {
    diorama_dev::repository_root(&std::env::current_dir()?)
}
