//! Tests for containerd shim resolution and PATH environment building.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use diorama_containerd::{
    DEFAULT_SHIM_BINARY_NAME, RUNTIME_RUNC_V2, ShimError, build_containerd_path, find_shim_in_path,
    validate_runtime_spec,
};

#[test]
fn shim_is_resolved_via_prepended_path() {
    let temp = TempDir::new().unwrap();
    let containerd_dir = temp.path().join("containerd");
    fs::create_dir_all(&containerd_dir).unwrap();

    let shim_path = containerd_dir.join(DEFAULT_SHIM_BINARY_NAME);
    fs::write(&shim_path, b"#!/bin/sh\necho shim\n").unwrap();
    let mut perms = fs::metadata(&shim_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&shim_path, perms).unwrap();

    // With an isolated path that does not contain the shim, lookup returns None
    let other_dir = temp.path().join("other_bin");
    fs::create_dir_all(&other_dir).unwrap();
    assert!(find_shim_in_path(DEFAULT_SHIM_BINARY_NAME, other_dir.as_os_str()).is_none());

    // Prepend containerd_dir to PATH
    let configured_path = build_containerd_path(&containerd_dir, Some(other_dir.as_os_str()));
    let resolved = find_shim_in_path(DEFAULT_SHIM_BINARY_NAME, &configured_path);
    assert_eq!(resolved, Some(shim_path.clone()));

    // Even if a host/fallback directory later in PATH contains a shim,
    // the prepended managed containerd directory takes precedence
    let fallback_dir = temp.path().join("fallback_bin");
    fs::create_dir_all(&fallback_dir).unwrap();
    let fallback_shim = fallback_dir.join(DEFAULT_SHIM_BINARY_NAME);
    fs::write(&fallback_shim, b"#!/bin/sh\necho host\n").unwrap();

    let multi_path = build_containerd_path(&containerd_dir, Some(fallback_dir.as_os_str()));
    let resolved_priority = find_shim_in_path(DEFAULT_SHIM_BINARY_NAME, &multi_path);
    assert_eq!(resolved_priority, Some(shim_path));
}

#[test]
fn runtime_spec_enforces_registered_type_and_forbids_runtime_path() {
    // 1. Registered type without runtime_path succeeds
    assert!(validate_runtime_spec(RUNTIME_RUNC_V2, None).is_ok());

    // 2. Rejecting absolute binary path as runtime_type
    // (Upstream note: CRI keys off io.containerd.runc.v2; an absolute path falls back
    // to runtimeoptions.v1.Options which fails to decode)
    let invalid_type = "/var/lib/diorama/containerd/containerd-shim-runc-v2";
    let err = validate_runtime_spec(invalid_type, None).unwrap_err();
    match err {
        ShimError::InvalidRuntimeType { actual, expected } => {
            assert_eq!(actual, invalid_type);
            assert_eq!(expected, RUNTIME_RUNC_V2);
        },
        other => panic!("unexpected error: {other:?}"),
    }

    // 3. Rejecting runtime_path override
    // (Upstream note: runtime_path triggers a spurious `<shim> -info` probe looking for runc)
    let err = validate_runtime_spec(
        RUNTIME_RUNC_V2,
        Some(Path::new(
            "/var/lib/diorama/containerd/containerd-shim-runc-v2",
        )),
    )
    .unwrap_err();
    match err {
        ShimError::DisallowedRuntimePath { path } => {
            assert_eq!(
                path,
                PathBuf::from("/var/lib/diorama/containerd/containerd-shim-runc-v2")
            );
        },
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn shim_lookup_operates_without_global_symlinks() {
    // Verify that shim resolution operates purely on local isolated path and
    // does not query or require /usr/local/bin or /usr/bin symlinks.
    let temp = TempDir::new().unwrap();
    let scoped_bin_dir = temp.path().join("isolated_bin");
    fs::create_dir_all(&scoped_bin_dir).unwrap();

    let shim_binary = scoped_bin_dir.join(DEFAULT_SHIM_BINARY_NAME);
    fs::write(&shim_binary, b"#!/bin/sh\n").unwrap();

    let custom_path = build_containerd_path(&scoped_bin_dir, None);
    let resolved = find_shim_in_path(DEFAULT_SHIM_BINARY_NAME, &custom_path);
    assert_eq!(resolved, Some(shim_binary));
}
