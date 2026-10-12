//! CLI tool for disposable Linux node scaffold execution and schema-2 receipt verification (E33.03 / Issue #343).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use diorama_dev::disposable_node::{self, DisposableNodeReceipt};

fn print_usage() {
    eprintln!(
        "Usage: diorama-disposable-node <COMMAND> [OPTIONS]\n\n\
         Commands:\n  \
           capture [--output <DIR>] [--kube-bin <PATH>] [--ctl-bin <PATH>]\n      \
             Execute scaffold steps, record logs, cleanup, and write schema-2 receipt.json\n  \
           verify <RECEIPT_OR_DIR>\n      \
             Verify a schema-2 integration receipt against all contract rules\n  \
           help\n      \
             Show this help message\n"
    );
}

fn handle_capture(args: &[String]) -> diorama_dev::Result<DisposableNodeReceipt> {
    let mut output_dir: Option<PathBuf> = None;
    let mut kube_bin: Option<PathBuf> = None;
    let mut ctl_bin: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                i += 1;
                if i >= args.len() {
                    return Err("--output requires a directory path".into());
                }
                output_dir = Some(PathBuf::from(&args[i]));
            },
            "--kube-bin" => {
                i += 1;
                if i >= args.len() {
                    return Err("--kube-bin requires a path".into());
                }
                kube_bin = Some(PathBuf::from(&args[i]));
            },
            "--ctl-bin" => {
                i += 1;
                if i >= args.len() {
                    return Err("--ctl-bin requires a path".into());
                }
                ctl_bin = Some(PathBuf::from(&args[i]));
            },
            other if !other.starts_with('-') && output_dir.is_none() => {
                output_dir = Some(PathBuf::from(other));
            },
            other => {
                return Err(format!("unexpected argument for capture: {other}").into());
            },
        }
        i += 1;
    }

    let out = output_dir
        .ok_or_else(|| "capture requires an output directory via --output <DIR>".to_string())?;

    disposable_node::capture(&out, kube_bin.as_deref(), ctl_bin.as_deref())
}

fn handle_verify(args: &[String]) -> diorama_dev::Result<DisposableNodeReceipt> {
    let target = match args {
        [path] => Path::new(path),
        [flag, path] if flag == "--input" || flag == "-i" => Path::new(path),
        _ => return Err("verify requires a receipt file or capture directory path".into()),
    };

    disposable_node::verify(target)
}

fn run(args: &[String]) -> diorama_dev::Result<()> {
    if args.is_empty() {
        print_usage();
        return Err("missing command; use 'capture' or 'verify'".into());
    }

    match args[0].as_str() {
        "capture" => {
            let receipt = handle_capture(&args[1..])?;
            println!(
                "Disposable node scaffold capture completed successfully:\n\
                 - Schema version: {}\n\
                 - Status: {}\n\
                 - Qualified: {} ({})\n\
                 - Candidate revision: {}\n\
                 - Commands executed: {}\n\
                 - Assertions passed: {}\n\
                 - Skips documented: {}\n\
                 - Residual resources: {}",
                receipt.schema_version,
                receipt.status,
                receipt.qualified,
                receipt.qualification_reason,
                receipt.candidate.source_revision,
                receipt.commands.len(),
                receipt.assertions.len(),
                receipt.skips.len(),
                receipt.cleanup.leftover_owned_resources.len()
            );
            Ok(())
        },
        "verify" => {
            let receipt = handle_verify(&args[1..])?;
            println!(
                "Receipt verification passed:\n\
                 - Schema version: {}\n\
                 - Status: {}\n\
                 - Qualified: {} ({})\n\
                 - Candidate revision: {}\n\
                 - Commands checked: {}\n\
                 - Assertions checked: {}\n\
                 - Cleaned state dir: {}",
                receipt.schema_version,
                receipt.status,
                receipt.qualified,
                receipt.qualification_reason,
                receipt.candidate.source_revision,
                receipt.commands.len(),
                receipt.assertions.len(),
                receipt.cleanup.state_directory_removed
            );
            Ok(())
        },
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        },
        unknown => {
            print_usage();
            Err(format!("unknown command: {unknown}").into())
        },
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("diorama-disposable-node error: {err}");
            ExitCode::FAILURE
        },
    }
}
