//! Repository metadata audit and candidate-bound release qualification.
//! Actively loads and validates candidate-bound receipts against candidate inventory.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut metadata_only = false;
    let mut candidate_dir: Option<PathBuf> = None;

    for arg in &args {
        if arg == "--metadata-only" {
            metadata_only = true;
        } else if arg.starts_with('-') {
            eprintln!("usage: diorama-qualification [directory] [--metadata-only]");
            return ExitCode::from(2);
        } else if candidate_dir.is_none() {
            candidate_dir = Some(PathBuf::from(arg));
        } else {
            eprintln!("usage: diorama-qualification [directory] [--metadata-only]");
            return ExitCode::from(2);
        }
    }

    let root = match diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR"))) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("failed to resolve repository root: {err}");
            return ExitCode::from(2);
        },
    };

    let candidate_ref = candidate_dir.as_deref();

    if !metadata_only {
        return match diorama_dev::release_qualification::run_release_qualification_with_candidate(
            &root,
            candidate_ref,
        ) {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            },
        };
    }

    match diorama_dev::release_qualification::audit_repository_metadata_with_candidate(
        &root,
        candidate_ref,
    ) {
        Ok(report) => {
            report.print_summary();
            println!("METADATA AUDIT PASSED; RELEASE REMAINS UNQUALIFIED");
            ExitCode::SUCCESS
        },
        Err(error) => {
            eprintln!("REPOSITORY METADATA AUDIT FAILED:\n{error}");
            ExitCode::FAILURE
        },
    }
}
