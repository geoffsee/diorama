//! CLI verification tool for operator handoff rehearsal and Criterion 11 qualification (Epic E37 / Issue #357).

use std::path::PathBuf;
use std::process::ExitCode;

fn handle_capture(args: &[String]) -> Result<(), String> {
    let mut output_dir: Option<PathBuf> = None;
    let mut root_dir: Option<PathBuf> = None;
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
            "--root" => {
                i += 1;
                if i >= args.len() {
                    return Err("--root requires a directory path".into());
                }
                root_dir = Some(PathBuf::from(&args[i]));
            },
            other if !other.starts_with('-') && output_dir.is_none() => {
                output_dir = Some(PathBuf::from(other));
            },
            other => return Err(format!("unexpected argument for capture: {other}")),
        }
        i += 1;
    }
    let output_dir =
        output_dir.unwrap_or_else(|| PathBuf::from("target/operator-handoff-rehearsal"));
    let root = match root_dir {
        Some(r) => r,
        None => diorama_dev::repository_root(&std::env::current_dir().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?,
    };

    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let (receipt_path, report_json_path, report_md_path) = rt
        .block_on(diorama_dev::operator_rehearsal::capture_operator_rehearsal(
            &output_dir,
            &root,
        ))
        .map_err(|e| e.to_string())?;

    println!("Operator handoff rehearsal capture completed successfully:");
    println!("  Receipt:     {}", receipt_path.display());
    println!("  Report JSON: {}", report_json_path.display());
    println!("  Report MD:   {}", report_md_path.display());
    Ok(())
}

fn handle_verify_receipt(args: &[String]) -> Result<(), String> {
    let mut input_path: Option<PathBuf> = None;
    let mut root_dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "-i" => {
                i += 1;
                if i >= args.len() {
                    return Err("--input requires a path".into());
                }
                input_path = Some(PathBuf::from(&args[i]));
            },
            "--root" => {
                i += 1;
                if i >= args.len() {
                    return Err("--root requires a directory path".into());
                }
                root_dir = Some(PathBuf::from(&args[i]));
            },
            other if !other.starts_with('-') && input_path.is_none() => {
                input_path = Some(PathBuf::from(other));
            },
            other => return Err(format!("unexpected argument for verify-receipt: {other}")),
        }
        i += 1;
    }

    let input_path = input_path
        .ok_or_else(|| "verify-receipt requires a receipt file or directory path".to_string())?;
    let root = match root_dir {
        Some(r) => r,
        None => diorama_dev::repository_root(&std::env::current_dir().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?,
    };

    let receipt =
        diorama_dev::operator_rehearsal::verify_operator_rehearsal_receipt(&input_path, &root)
            .map_err(|e| e.to_string())?;

    println!(
        "Operator handoff receipt verified successfully:\n\
         - Criterion: {}\n\
         - Status: qualified\n\
         - Candidate revision: {}\n\
         - Assertions passed: {}\n\
         - Skips documented: {}",
        receipt.criterion,
        receipt.candidate.source_revision,
        receipt.assertions.len(),
        receipt.skips.len()
    );
    Ok(())
}

fn execute(args: &[String]) -> Result<(), String> {
    match args {
        [] => execute(&["help".into()]),
        [s] if s == "help" || s == "--help" || s == "-h" => {
            println!(
                "diorama-operator-rehearsal: Candidate-bound operator handoff rehearsal and Criterion 11 qualification\n\
                 capture [--output DIR] [--root DIR] (Criterion 11 rehearsal capture)\n\
                 verify-receipt RECEIPT_OR_DIR [--root DIR] (Criterion 11 verification; fails closed on unqualifying runs)"
            );
            Ok(())
        },
        [command, rest @ ..] if command == "capture" => handle_capture(rest),
        [command, rest @ ..] if command == "verify-receipt" => handle_verify_receipt(rest),
        _ => Err("invalid arguments; use help".into()),
    }
}

fn main() -> ExitCode {
    match execute(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("operator-rehearsal: {error}");
            ExitCode::FAILURE
        },
    }
}
