//! Generate `crates/diorama-apiserver/src/http/generated/k8s_proto_schema.rs` from a directory of
//! upstream Kubernetes `generated.proto` files.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use diorama_dev::proto_schema::{
    DEFAULT_UPSTREAM_COMMIT, DEFAULT_UPSTREAM_VERSION, generate_from_dir,
};
use diorama_dev::repository_root;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(proto_dir) = args.next() else {
        eprintln!("usage: diorama-proto-schema <proto-dir> [output-rs] [version] [commit]");
        return ExitCode::from(2);
    };
    let root = match repository_root(Path::new(env!("CARGO_MANIFEST_DIR"))) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("cannot locate repository root: {error}");
            return ExitCode::from(2);
        },
    };
    let output_path = args.next().map_or_else(
        || root.join("crates/diorama-apiserver/src/http/generated/k8s_proto_schema.rs"),
        PathBuf::from,
    );
    let version = args
        .next()
        .unwrap_or_else(|| DEFAULT_UPSTREAM_VERSION.to_string());
    let commit = args
        .next()
        .unwrap_or_else(|| DEFAULT_UPSTREAM_COMMIT.to_string());

    let rendered = match generate_from_dir(Path::new(&proto_dir), &version, &commit) {
        Ok(rendered) => rendered,
        Err(error) => {
            eprintln!("failed to generate protobuf schema table: {error}");
            return ExitCode::FAILURE;
        },
    };
    if let Some(parent) = output_path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        eprintln!("failed to create {}: {error}", parent.display());
        return ExitCode::FAILURE;
    }
    if let Err(error) = std::fs::write(&output_path, rendered) {
        eprintln!("failed to write {}: {error}", output_path.display());
        return ExitCode::FAILURE;
    }
    println!("wrote {}", output_path.display());
    ExitCode::SUCCESS
}
