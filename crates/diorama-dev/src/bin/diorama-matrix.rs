//! Validate and inspect the supported variant matrix and clean-checkout artifact naming.
use diorama_assets::{
    Architecture, ArtifactNaming, Libc, Matrix, OptionalFeature, ReleasePackageManifest,
    ReleasePackager, Variant,
};
use std::process::ExitCode;

fn validate_all() -> Result<(), String> {
    let variants = Matrix::all_node_variants();
    if variants.len() != 16 {
        return Err(format!("expected 16 node variants, got {}", variants.len()));
    }

    for (index, variant) in variants.iter().enumerate() {
        let expected_cell =
            u8::try_from(index + 1).map_err(|e| format!("cell index conversion failed: {e}"))?;
        if variant.cell != expected_cell {
            return Err(format!(
                "cell mismatch: expected {expected_cell}, got {}",
                variant.cell
            ));
        }

        let canonical_name =
            ArtifactNaming::validate_clean_checkout_inputs("diorama-kube", "0.1.0", *variant, &[])
                .map_err(|e| {
                    format!("clean-checkout validation failed for cell {expected_cell}: {e}")
                })?;

        let parsed = ArtifactNaming::parse_node_archive(&canonical_name)
            .map_err(|e| format!("parse failed for {canonical_name}: {e}"))?;

        if parsed.variant.cell != expected_cell {
            return Err(format!(
                "parsed cell mismatch for {canonical_name}: expected {expected_cell}, got {}",
                parsed.variant.cell
            ));
        }
    }

    let management_targets = Matrix::all_management_targets();
    if management_targets.len() != 4 {
        return Err(format!(
            "expected 4 management targets, got {}",
            management_targets.len()
        ));
    }

    for target in management_targets {
        let binary_name = target.binary_filename("dioramactl");
        let parsed = ArtifactNaming::parse_management_binary(&binary_name)
            .map_err(|e| format!("management binary parse failed for {binary_name}: {e}"))?;

        if parsed.target != *target {
            return Err(format!(
                "management target mismatch for {binary_name}: expected {target:?}, got {:?}",
                parsed.target
            ));
        }
    }

    Ok(())
}

fn print_cells() {
    println!("Supported Node Variant Matrix (16 cells):");
    println!(
        "{:<5} {:<18} {:<8} {:<10} {:<16} {:<30}",
        "Cell", "Architecture", "Libc", "Variant", "OCI Platform", "Optional Image Limits"
    );
    println!("{:-<95}", "");

    for variant in Matrix::all_node_variants() {
        let limits = match variant.architecture {
            Architecture::Amd64 | Architecture::Arm64 => "Portainer & D2K supported",
            Architecture::ArmV7 => "Portainer supported; D2K disabled",
            Architecture::Riscv64 => "Portainer unavailable; D2K disabled",
        };

        let arch_str = match variant.architecture {
            Architecture::Amd64 => "amd64",
            Architecture::Arm64 => "arm64",
            Architecture::ArmV7 => "ARMv7 hard-float",
            Architecture::Riscv64 => "riscv64",
        };

        let libc_str = match variant.libc {
            Libc::Glibc => "glibc",
            Libc::Musl => "musl",
        };

        let variant_str = match variant.variant {
            Variant::Online => "online",
            Variant::Offline => "offline",
        };

        println!(
            "{:<5} {:<18} {:<8} {:<10} {:<16} {:<30}",
            variant.cell,
            arch_str,
            libc_str,
            variant_str,
            variant.oci_platform(),
            limits
        );
    }

    println!("\nManagement Targets (4 targets, Windows excluded by E01):");
    for target in Matrix::all_management_targets() {
        println!("  - {}-{}", target.os, target.architecture);
    }
}

fn handle_archive(filename: &str) -> ExitCode {
    match ArtifactNaming::canonical_node_archive(filename) {
        Ok(parsed) => {
            println!("Parsed node archive:");
            println!("  Prefix:       {}", parsed.prefix);
            println!("  Version:      {}", parsed.version);
            println!("  Cell:         {}", parsed.variant.cell);
            println!("  OCI Platform: {}", parsed.variant.oci_platform());
            println!(
                "  Portainer:    {:?}",
                parsed
                    .variant
                    .optional_feature_support(OptionalFeature::PortainerAgent)
            );
            println!(
                "  D2K:          {:?}",
                parsed
                    .variant
                    .optional_feature_support(OptionalFeature::D2k)
            );
            println!(
                "  LocalPath:    {:?}",
                parsed
                    .variant
                    .optional_feature_support(OptionalFeature::LocalPathStorage)
            );
            ExitCode::SUCCESS
        },
        Err(e) => {
            eprintln!("invalid archive filename: {e}");
            ExitCode::FAILURE
        },
    }
}

fn handle_binary(filename: &str) -> ExitCode {
    match ArtifactNaming::parse_management_binary(filename) {
        Ok(parsed) => {
            println!("Parsed management binary:");
            println!("  Prefix:       {}", parsed.prefix);
            println!("  OS:           {}", parsed.target.os);
            println!("  Architecture: {}", parsed.target.architecture);
            ExitCode::SUCCESS
        },
        Err(e) => {
            eprintln!("invalid binary filename: {e}");
            ExitCode::FAILURE
        },
    }
}

fn handle_verify_manifest(filename: &str, expected_version: &str) -> ExitCode {
    let data = match std::fs::read(filename) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("failed to read release manifest '{filename}': {e}");
            return ExitCode::FAILURE;
        },
    };
    let manifest: ReleasePackageManifest = match serde_json::from_slice(&data) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("failed to parse release manifest '{filename}': {e}");
            return ExitCode::FAILURE;
        },
    };
    match ReleasePackager::verify_release_manifest(
        &manifest,
        "diorama-kube",
        "dioramactl",
        expected_version,
    ) {
        Ok(()) => {
            println!(
                "release metadata '{}' (version {}) verified: 16 node archive descriptors, 4 management descriptors, {} OCI image descriptors; artifact bytes and installation are not qualified",
                manifest.product_name,
                manifest.version,
                manifest.oci_images.len()
            );
            ExitCode::SUCCESS
        },
        Err(e) => {
            eprintln!("release manifest verification failed: {e}");
            ExitCode::FAILURE
        },
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => match validate_all() {
            Ok(()) => {
                println!(
                    "all 16 node variant cells and 4 management targets validated successfully"
                );
                ExitCode::SUCCESS
            },
            Err(e) => {
                eprintln!("matrix validation error: {e}");
                ExitCode::FAILURE
            },
        },
        [cmd] if cmd == "validate" => match validate_all() {
            Ok(()) => {
                println!(
                    "all 16 node variant cells and 4 management targets validated successfully"
                );
                ExitCode::SUCCESS
            },
            Err(e) => {
                eprintln!("matrix validation error: {e}");
                ExitCode::FAILURE
            },
        },
        [cmd] if cmd == "list" => {
            print_cells();
            ExitCode::SUCCESS
        },
        [cmd, filename] if cmd == "archive" => handle_archive(filename),
        [cmd, filename] if cmd == "binary" => handle_binary(filename),
        [cmd, filename] if cmd == "verify-manifest" => {
            handle_verify_manifest(filename, env!("CARGO_PKG_VERSION"))
        },
        [cmd, filename, flag, expected_version]
            if cmd == "verify-manifest" && flag == "--expected-version" =>
        {
            handle_verify_manifest(filename, expected_version)
        },
        _ => {
            eprintln!(
                "Usage: diorama-matrix [validate | list | archive <filename> | binary <filename> | verify-manifest <json-file> [--expected-version <version>]]"
            );
            ExitCode::FAILURE
        },
    }
}
