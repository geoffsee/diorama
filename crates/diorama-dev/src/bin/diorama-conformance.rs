#![allow(clippy::pedantic)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use diorama_dev::conformance::{Kubeconfig, QualificationReport, QualificationRunner};

fn print_help() {
    eprintln!(
        r"diorama-conformance: Gate C13 workload and conformance qualification

Usage:
  diorama-conformance run [--output <dir>] [--root <dir>]
  diorama-conformance verify-receipt <path> [--root <dir>]
  diorama-conformance fixture [--output <dir>]
  diorama-conformance verify <report-json>
  diorama-conformance verify-fixture <report-json>
  diorama-conformance check-kubeconfig <path>
  diorama-conformance --help

Commands:
  run                Run candidate qualification (requires --output <dir>)
  verify-receipt     Verify candidate qualification receipt against inventory rules
  fixture            Execute synthetic in-process fixtures; does not qualify C13/E28
  verify             Validate an existing qualification report with zero hidden skips
  check-kubeconfig   Verify dual-format accommodation (YAML and JSON) of a kubeconfig file
"
    );
}

fn resolve_repo_root(custom_root: Option<&Path>) -> diorama_dev::Result<PathBuf> {
    if let Some(r) = custom_root {
        return Ok(r.to_path_buf());
    }
    if let Ok(cur) = std::env::current_dir()
        && let Ok(root) = diorama_dev::repository_root(&cur)
    {
        return Ok(root);
    }
    diorama_dev::repository_root(Path::new(env!("CARGO_MANIFEST_DIR")))
}

#[tokio::main]
#[allow(clippy::too_many_lines, clippy::excessive_nesting)]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return ExitCode::SUCCESS;
    }

    match args[0].as_str() {
        "run" => {
            let mut output_dir: Option<PathBuf> = None;
            let mut root_dir: Option<PathBuf> = None;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--output" || args[i] == "-o" {
                    if i + 1 >= args.len() {
                        eprintln!("error: --output requires a directory path");
                        return ExitCode::FAILURE;
                    }
                    output_dir = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else if args[i] == "--root" {
                    if i + 1 >= args.len() {
                        eprintln!("error: --root requires a directory path");
                        return ExitCode::FAILURE;
                    }
                    root_dir = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    eprintln!("error: unrecognized argument: {}", args[i]);
                    return ExitCode::FAILURE;
                }
            }

            let Some(output) = output_dir else {
                eprintln!(
                    "error: retained-executable C13/E28 node qualification is not implemented; use fixture for synthetic evidence"
                );
                return ExitCode::FAILURE;
            };

            let root = match resolve_repo_root(root_dir.as_deref()) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: cannot resolve repository root: {e}");
                    return ExitCode::FAILURE;
                },
            };

            println!("Running candidate qualification for Criterion 6...");
            let runner = QualificationRunner::new();
            match runner
                .run_candidate_qualification(&output, Some(&root))
                .await
            {
                Ok(receipt) => {
                    println!(
                        "Qualification passed! Receipt written to {}/receipt.json",
                        output.display()
                    );
                    println!("Receipt integrity hash: {}", receipt.integrity_hash);
                    ExitCode::SUCCESS
                },
                Err(err) => {
                    eprintln!("error: candidate qualification failed: {err}");
                    ExitCode::FAILURE
                },
            }
        },
        "verify-receipt" => {
            let mut receipt_path: Option<PathBuf> = None;
            let mut root_dir: Option<PathBuf> = None;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--root" {
                    if i + 1 >= args.len() {
                        eprintln!("error: --root requires a directory path");
                        return ExitCode::FAILURE;
                    }
                    root_dir = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else if !args[i].starts_with('-') && receipt_path.is_none() {
                    receipt_path = Some(PathBuf::from(&args[i]));
                    i += 1;
                } else {
                    eprintln!("error: unrecognized argument: {}", args[i]);
                    return ExitCode::FAILURE;
                }
            }

            let Some(path) = receipt_path else {
                eprintln!("error: verify-receipt requires a receipt JSON file path");
                return ExitCode::FAILURE;
            };

            let root = match resolve_repo_root(root_dir.as_deref()) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: cannot resolve repository root: {e}");
                    return ExitCode::FAILURE;
                },
            };

            match diorama_dev::release_qualification::receipt::load_and_validate_receipt(
                &path, &root, 6,
            ) {
                Ok(receipt) => {
                    println!(
                        "Receipt verification passed: schema_version={}, criterion={}, integrity_hash={}",
                        receipt.schema_version, receipt.criterion, receipt.integrity_hash
                    );
                    ExitCode::SUCCESS
                },
                Err(e) => {
                    eprintln!("error: receipt verification failed: {e}");
                    ExitCode::FAILURE
                },
            }
        },
        "fixture" => {
            let mut output_dir: Option<PathBuf> = None;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--output" || args[i] == "-o" {
                    if i + 1 >= args.len() {
                        eprintln!("error: --output requires a directory path");
                        return ExitCode::FAILURE;
                    }
                    output_dir = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    eprintln!("error: unrecognized argument: {}", args[i]);
                    return ExitCode::FAILURE;
                }
            }

            println!("Running synthetic in-process fixtures; C13/E28 remains unqualified...");
            let runner = QualificationRunner::new();
            let report = match runner.run_fixture().await {
                Ok(rep) => rep,
                Err(e) => {
                    eprintln!("error: qualification execution failed: {e}");
                    return ExitCode::FAILURE;
                },
            };

            // Print markdown summary
            println!("{}", report.to_markdown());

            // Write artifacts if output directory is provided
            if let Some(ref dir) = output_dir {
                if let Err(e) = fs::create_dir_all(dir) {
                    eprintln!(
                        "error: cannot create output directory {}: {e}",
                        dir.display()
                    );
                    return ExitCode::FAILURE;
                }

                let json_path = dir.join("fixture-report.json");
                let md_path = dir.join("fixture-report.md");

                let json_content = match report.to_json() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("error: failed to serialize report to JSON: {e}");
                        return ExitCode::FAILURE;
                    },
                };

                if let Err(e) = fs::write(&json_path, json_content) {
                    eprintln!("error: cannot write {}: {e}", json_path.display());
                    return ExitCode::FAILURE;
                }

                if let Err(e) = fs::write(&md_path, report.to_markdown()) {
                    eprintln!("error: cannot write {}: {e}", md_path.display());
                    return ExitCode::FAILURE;
                }

                println!("Report artifacts saved to: {}", dir.display());
            }

            ExitCode::SUCCESS
        },
        "verify" | "verify-fixture" => {
            if args.len() < 2 {
                eprintln!("error: verify requires a report JSON file path");
                return ExitCode::FAILURE;
            }
            let report_path = Path::new(&args[1]);
            let content = match fs::read_to_string(report_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: cannot read {}: {e}", report_path.display());
                    return ExitCode::FAILURE;
                },
            };

            let report: QualificationReport = match serde_json::from_str(&content) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: cannot parse qualification report JSON: {e}");
                    return ExitCode::FAILURE;
                },
            };

            let verification = if args[0] == "verify-fixture" {
                report.verify_fixture()
            } else {
                report.verify_qualification()
            };
            if let Err(e) = verification {
                eprintln!("error: qualification verification failed: {e}");
                return ExitCode::FAILURE;
            }

            println!(
                "Synthetic fixture coverage verified; pod egress and upstream conformance were not executed; C13/E28 remains unqualified."
            );
            ExitCode::SUCCESS
        },
        "check-kubeconfig" => {
            if args.len() < 2 {
                eprintln!("error: check-kubeconfig requires a kubeconfig file path");
                return ExitCode::FAILURE;
            }
            let path = Path::new(&args[1]);
            let kubeconfig = match Kubeconfig::from_file(path) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!(
                        "error: failed to parse kubeconfig from {}: {e}",
                        path.display()
                    );
                    return ExitCode::FAILURE;
                },
            };

            // Test dual serialization and parsing
            let as_json = match kubeconfig.to_json() {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("error: failed to serialize to JSON: {e}");
                    return ExitCode::FAILURE;
                },
            };
            let parsed_from_json = match Kubeconfig::parse(&as_json) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("error: failed to parse back from JSON: {e}");
                    return ExitCode::FAILURE;
                },
            };

            let as_yaml = kubeconfig.to_yaml();
            let parsed_from_yaml = match Kubeconfig::parse(&as_yaml) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("error: failed to parse back from YAML: {e}");
                    return ExitCode::FAILURE;
                },
            };

            if parsed_from_json != parsed_from_yaml {
                eprintln!("error: YAML and JSON roundtrips do not match");
                return ExitCode::FAILURE;
            }

            println!(
                "Kubeconfig valid (dual-format verified): context='{}', clusters={}, users={}",
                kubeconfig.current_context,
                kubeconfig.clusters.len(),
                kubeconfig.users.len()
            );
            ExitCode::SUCCESS
        },
        other => {
            eprintln!("error: unrecognized command '{other}'");
            print_help();
            ExitCode::FAILURE
        },
    }
}
