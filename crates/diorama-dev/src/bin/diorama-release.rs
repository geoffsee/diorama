//! Explicit fixture diagnostics; production release qualification remains unavailable.
use diorama_dev::{
    release::{
        assemble_checksum_manifest, assemble_fixture_evidence, assemble_release_evidence,
        build_cell_inventory, regenerate_release_reports, verify_fixture_evidence,
        verify_release_evidence,
    },
    repository_root,
};
use std::{env, fs, path::PathBuf, process::ExitCode};
#[tokio::main]
async fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        println!(
            "diorama-release assemble|verify [directory]\n  Production commands require candidate qualification receipts for criteria 6, 7, 8, and 10 and fail closed if missing or invalid.\ndiorama-release assemble-fixtures|verify-fixtures [directory]\n  Unqualified fixture diagnostics only; default docs/release. Assembly requires empty output.\ndiorama-release build-cells [directory]\n  Build node cells and management targets; default docs/release.\ndiorama-release regenerate-reports [directory]\n  Regenerate qualification reports bound to candidate receipts; default docs/release."
        );
        return ExitCode::SUCCESS;
    }
    let result = async {
        if args.len() > 2 {
            return Err("unexpected arguments".into());
        }
        let root = repository_root(&env::current_dir()?)?;
        let dir = args
            .get(1)
            .map_or_else(|| root.join("docs/release"), PathBuf::from);
        match args[0].as_str() {
            "assemble" => assemble_release_evidence(&root, &dir).await,
            "verify" => verify_release_evidence(&dir),
            "assemble-fixtures" => assemble_fixture_evidence(&root, &dir).await,
            "verify-fixtures" => verify_fixture_evidence(&root, &dir),
            "regenerate-reports" => regenerate_release_reports(&root, &dir).await,
            "build-cells" => {
                let staging = tempfile::tempdir()?;
                let (inventory, cleanup) = build_cell_inventory(&root, staging.path())?;
                fs::create_dir_all(&dir)?;
                fs::write(
                    dir.join("cell-inventory.json"),
                    serde_json::to_vec_pretty(&inventory)?,
                )?;
                fs::write(
                    dir.join("cleanup-receipt.json"),
                    serde_json::to_vec_pretty(&cleanup)?,
                )?;
                if dir.join("SHA256SUMS").exists() {
                    fs::write(dir.join("SHA256SUMS"), assemble_checksum_manifest(&dir)?)?;
                }
                Ok(())
            },
            _ => Err("unknown command; use --help".into()),
        }
    }
    .await;
    match result {
        Ok(()) => {
            let message = match args[0].as_str() {
                "assemble-fixtures" => {
                    "UNQUALIFIED_FIXTURE_ONLY: fixture diagnostics assembled and consistency checked; no production release qualification."
                },
                "verify-fixtures" => {
                    "UNQUALIFIED_FIXTURE_ONLY: fixture consistency checked; no production release qualification."
                },
                "assemble" => "Production release evidence assembled.",
                "verify" => "Production release evidence verified.",
                "regenerate-reports" => {
                    "Production release qualification reports regenerated from candidate receipts."
                },
                "build-cells" => "Cell build receipts and smoke installation verified.",
                _ => unreachable!("unknown commands return an error"),
            };
            println!("{message}");
            ExitCode::SUCCESS
        },
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        },
    }
}
