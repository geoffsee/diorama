use std::fs;
use tempfile::tempdir;

use diorama_network::{
    DEFAULT_BRIDGE_NAME, DEFAULT_CNI_CONFIG_NAME, DEFAULT_POD_CIDR, DEFAULT_STANDARD_CNI_BIN_DIR,
    DEFAULT_STANDARD_CNI_CONF_DIR, REQUIRED_CNI_PLUGINS, generate_cni_config,
    generate_cni_config_json, inspect_cni_dir_ordering, remove_if_symlink,
    warn_missing_cni_plugins, write_cni_config_file, write_external_cni_config,
    write_managed_cni_config,
};

#[test]
fn test_cni_constants_parity() {
    assert_eq!(DEFAULT_POD_CIDR, "10.42.0.0/16");
    assert_eq!(DEFAULT_BRIDGE_NAME, "cni0");
    assert_eq!(DEFAULT_CNI_CONFIG_NAME, "10-bridge.conflist");
    assert_eq!(DEFAULT_STANDARD_CNI_CONF_DIR, "/etc/cni/net.d");
    assert_eq!(DEFAULT_STANDARD_CNI_BIN_DIR, "/opt/cni/bin");
    assert_eq!(
        REQUIRED_CNI_PLUGINS,
        ["bridge", "host-local", "portmap", "loopback"]
    );
}

#[test]
fn test_golden_cni_configuration_structure_and_types() {
    let json_val = generate_cni_config(1500, None);

    assert_eq!(json_val["cniVersion"], "1.0.0");
    assert_eq!(json_val["name"], "kubesolo-net");

    let plugins = json_val["plugins"].as_array().expect("plugins is an array");
    assert_eq!(plugins.len(), 3);

    // Bridge Plugin
    let bridge = &plugins[0];
    assert_eq!(bridge["type"], "bridge");
    assert_eq!(bridge["bridge"], "cni0");
    assert_eq!(bridge["isGateway"], true);
    assert_eq!(bridge["ipMasq"], false);
    assert_eq!(bridge["hairpinMode"], true);
    assert_eq!(bridge["mtu"], 1500);

    let bridge_caps = &bridge["capabilities"];
    assert_eq!(bridge_caps["portMappings"], true);
    assert_eq!(bridge_caps["ips"], true);

    let ipam = &bridge["ipam"];
    assert_eq!(ipam["type"], "host-local");
    let ranges = ipam["ranges"].as_array().expect("ranges array");
    assert_eq!(ranges[0][0]["subnet"], "10.42.0.0/16");
    let routes = ipam["routes"].as_array().expect("routes array");
    assert_eq!(routes[0]["dst"], "0.0.0.0/0");

    // Portmap Plugin
    let portmap = &plugins[1];
    assert_eq!(portmap["type"], "portmap");
    assert_eq!(portmap["capabilities"]["portMappings"], true);

    // Loopback Plugin
    let loopback = &plugins[2];
    assert_eq!(loopback["type"], "loopback");
}

#[test]
fn test_cni_configuration_custom_mtu_and_pod_cidr() {
    let custom_mtus = [576, 1280, 1420, 1500, 9000];
    let custom_cidrs = ["10.244.0.0/16", "172.16.0.0/12", "192.168.0.0/16"];

    for &mtu in &custom_mtus {
        for &cidr in &custom_cidrs {
            let json_val = generate_cni_config(mtu, Some(cidr));
            assert_eq!(json_val["plugins"][0]["mtu"], mtu);
            assert_eq!(
                json_val["plugins"][0]["ipam"]["ranges"][0][0]["subnet"],
                cidr
            );

            let json_str =
                generate_cni_config_json(mtu, Some(cidr)).expect("serialization should succeed");
            assert!(json_str.contains(&format!("\"mtu\": {mtu}")));
            assert!(json_str.contains(&format!("\"subnet\": \"{cidr}\"")));
        }
    }
}

#[test]
fn test_write_cni_config_file_permissions() {
    let dir = tempdir().expect("tempdir");
    let target = dir.path().join("subdir/custom.conflist");

    write_cni_config_file(&target, 1500, None).expect("write file");
    assert!(target.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&target).expect("metadata").permissions();
        assert_eq!(perms.mode() & 0o777, 0o644);
    }
}

#[test]
fn test_managed_mode_writes_owned_config_and_links_standard_path() {
    let dir = tempdir().expect("tempdir");
    let base_path = dir.path().join("var/lib/diorama");
    let standard_dir = dir.path().join("etc/cni/net.d");

    let written =
        write_managed_cni_config(&base_path, 1400, Some("10.42.0.0/16"), Some(&standard_dir))
            .expect("write managed config");

    let expected_managed_file = base_path.join("containerd/cni/conf/10-bridge.conflist");
    assert_eq!(written, expected_managed_file);
    assert!(expected_managed_file.exists());

    #[cfg(unix)]
    {
        let standard_file = standard_dir.join("10-bridge.conflist");
        assert!(standard_file.exists());
        assert!(standard_file.is_symlink());
        let target = fs::read_link(&standard_file).expect("read symlink");
        assert_eq!(
            target,
            fs::canonicalize(&expected_managed_file).expect("canonicalize")
        );
    }
}

#[test]
fn test_external_mode_writes_only_owned_cni_files_and_cleans_symlink() {
    let dir = tempdir().expect("tempdir");
    let conf_dir = dir.path().join("etc/cni/net.d");
    fs::create_dir_all(&conf_dir).expect("create conf_dir");

    let owned_file = conf_dir.join("10-bridge.conflist");
    let unrelated_cni = conf_dir.join("99-other.conflist");
    let unrelated_extra = conf_dir.join("flannel.conf");
    let unrelated_text = conf_dir.join("notes.txt");

    fs::write(&unrelated_cni, b"{\"name\": \"other\"}").expect("write unrelated CNI");
    fs::write(&unrelated_extra, b"{\"type\": \"flannel\"}").expect("write flannel");
    fs::write(&unrelated_text, b"keep me").expect("write text");

    #[cfg(unix)]
    {
        // Simulate leftover symlink from earlier embedded run
        let dummy_target = dir.path().join("old-data-dir/10-bridge.conflist");
        std::os::unix::fs::symlink(&dummy_target, &owned_file).expect("symlink");
        assert!(owned_file.is_symlink());
    }

    let written = write_external_cni_config(&conf_dir, 1500, None).expect("write external");
    assert_eq!(written, owned_file);
    assert!(owned_file.exists());
    assert!(!owned_file.is_symlink());

    // Verify unrelated files are byte-for-byte preserved
    assert_eq!(
        fs::read(&unrelated_cni).expect("read unrelated CNI"),
        b"{\"name\": \"other\"}"
    );
    assert_eq!(
        fs::read(&unrelated_extra).expect("read flannel"),
        b"{\"type\": \"flannel\"}"
    );
    assert_eq!(fs::read(&unrelated_text).expect("read text"), b"keep me");
}

#[test]
fn test_ordering_inspection_identifies_earlier_competing_entries() {
    let dir = tempdir().expect("tempdir");
    let conf_dir = dir.path();

    // 00-calico.conflist and 05-cilium.conflist sort before 10-bridge.conflist
    fs::write(conf_dir.join("00-calico.conflist"), b"{}").expect("calico");
    fs::write(conf_dir.join("05-cilium.conflist"), b"{}").expect("cilium");
    // 10-bridge.conflist is our owned file
    fs::write(conf_dir.join("10-bridge.conflist"), b"{}").expect("owned");
    // 20-flannel.conf and 90-custom.json sort after
    fs::write(conf_dir.join("20-flannel.conf"), b"{}").expect("flannel");
    fs::write(conf_dir.join("90-custom.json"), b"{}").expect("custom");
    // Non-CNI extension files are ignored
    fs::write(conf_dir.join("01-not-cni.txt"), b"ignored").expect("txt");
    fs::write(conf_dir.join("02-config.yaml"), b"ignored").expect("yaml");

    let inspection =
        inspect_cni_dir_ordering(conf_dir, "10-bridge.conflist").expect("inspect ordering");

    assert_eq!(
        inspection.earlier_competing,
        vec!["00-calico.conflist", "05-cilium.conflist"]
    );
    assert_eq!(
        inspection.later_entries,
        vec!["20-flannel.conf", "90-custom.json"]
    );
}

#[test]
fn test_warn_missing_cni_plugins_detects_absent_binaries() {
    let dir = tempdir().expect("tempdir");
    let bin_dir = dir.path();

    // Initially all 4 are missing
    let missing = warn_missing_cni_plugins(bin_dir);
    assert_eq!(missing.len(), 4);
    assert_eq!(missing, vec!["bridge", "host-local", "portmap", "loopback"]);

    // Provide 2 of them
    fs::write(bin_dir.join("bridge"), b"mock-bridge").expect("write bridge");
    fs::write(bin_dir.join("host-local"), b"mock-host-local").expect("write host-local");

    let missing = warn_missing_cni_plugins(bin_dir);
    assert_eq!(missing, vec!["portmap", "loopback"]);

    // Provide all 4
    fs::write(bin_dir.join("portmap"), b"mock-portmap").expect("write portmap");
    fs::write(bin_dir.join("loopback"), b"mock-loopback").expect("write loopback");

    let missing = warn_missing_cni_plugins(bin_dir);
    assert!(missing.is_empty());
}

#[test]
fn test_remove_if_symlink_behavior() {
    let dir = tempdir().expect("tempdir");
    let regular_file = dir.path().join("regular.txt");
    fs::write(&regular_file, b"content").expect("write regular");

    // Regular file is not removed
    assert!(!remove_if_symlink(&regular_file).expect("remove_if_symlink"));
    assert!(regular_file.exists());

    // Non-existent file returns false
    assert!(!remove_if_symlink(&dir.path().join("nonexistent.txt")).expect("remove_if_symlink"));

    #[cfg(unix)]
    {
        let symlink = dir.path().join("symlink.txt");
        std::os::unix::fs::symlink(&regular_file, &symlink).expect("symlink");
        assert!(symlink.is_symlink());

        // Symlink is removed, original is untouched
        assert!(remove_if_symlink(&symlink).expect("remove_if_symlink"));
        assert!(!symlink.exists());
        assert!(regular_file.exists());
    }
}

#[test]
fn test_external_followed_by_managed_mode_replaces_regular_file() {
    let dir = tempdir().expect("tempdir");
    let standard_dir = dir.path().join("etc/cni/net.d");
    let base_path = dir.path().join("var/lib/diorama");

    // 1. First place external config (creates a regular file in standard_dir)
    let ext_written = write_external_cni_config(&standard_dir, 1400, Some("10.42.0.0/16"))
        .expect("write external");
    assert!(ext_written.is_file());
    assert!(!ext_written.is_symlink());

    // Verify it contains MTU 1400
    let ext_content = fs::read_to_string(&ext_written).expect("read external content");
    assert!(ext_content.contains("\"mtu\": 1400"));

    // 2. Next run managed mode with different settings (e.g. MTU 1500, pod CIDR 10.43.0.0/16)
    let managed_written =
        write_managed_cni_config(&base_path, 1500, Some("10.43.0.0/16"), Some(&standard_dir))
            .expect("write managed");

    // Managed file exists and contains new MTU 1500
    assert!(managed_written.exists());
    let managed_content = fs::read_to_string(&managed_written).expect("read managed content");
    assert!(managed_content.contains("\"mtu\": 1500"));
    assert!(managed_content.contains("\"subnet\": \"10.43.0.0/16\""));

    // Standard path is now a symlink pointing to the managed file
    let standard_file = standard_dir.join("10-bridge.conflist");
    #[cfg(unix)]
    {
        assert!(standard_file.is_symlink());
        let target = fs::read_link(&standard_file).expect("read symlink");
        assert_eq!(
            target,
            fs::canonicalize(&managed_written).expect("canonicalize")
        );
    }
    // Reading through standard_file yields the managed content
    let linked_content = fs::read_to_string(&standard_file).expect("read through symlink");
    assert!(linked_content.contains("\"mtu\": 1500"));
}

#[test]
fn test_managed_mode_relative_base_path_canonicalization() {
    let dir = tempdir().expect("tempdir");
    let relative_base = dir.path().join("relative_data");
    let standard_dir = dir.path().join("etc/cni/net.d");

    let written = write_managed_cni_config(
        &relative_base,
        1420,
        Some("10.42.0.0/16"),
        Some(&standard_dir),
    )
    .expect("write managed with relative base");

    #[cfg(unix)]
    {
        let standard_file = standard_dir.join("10-bridge.conflist");
        assert!(standard_file.is_symlink());
        let target = fs::read_link(&standard_file).expect("read symlink");
        assert!(target.is_absolute());
        assert_eq!(target, fs::canonicalize(&written).expect("canonicalize"));
    }
}
