use std::collections::BTreeMap;
use std::path::PathBuf;

use dioramalet::{KubeletCgroupVersion, KubeletConfigOptions};

#[test]
fn test_golden_host_mode_upstream_defaults() {
    let options = KubeletConfigOptions {
        node_name: "test-node".to_string(),
        node_ip: "192.0.2.10".to_string(),
        ca_file: PathBuf::from("/pki/ca.crt"),
        cert_file: PathBuf::from("/pki/kubelet.crt"),
        key_file: PathBuf::from("/pki/kubelet.key"),
        runtime_endpoint: "unix:///run/containerd/containerd.sock".to_string(),
        cgroup_driver: "systemd".to_string(),
        container_mode: false,
        ..Default::default()
    };

    let cfg = options.generate_kubelet_config();

    // Standard baseline configuration
    assert_eq!(cfg["apiVersion"], "kubelet.config.k8s.io/v1beta1");
    assert_eq!(cfg["kind"], "KubeletConfiguration");
    assert_eq!(
        cfg["containerRuntimeEndpoint"],
        "unix:///run/containerd/containerd.sock"
    );
    assert_eq!(cfg["cgroupDriver"], "systemd");
    assert_eq!(cfg["resolvConf"], "/etc/resolv.conf");
    assert_eq!(cfg["readOnlyPort"], 0);
    assert_eq!(cfg["failSwapOn"], false);
    assert_eq!(cfg["rotateCertificates"], true);
    assert_eq!(cfg["clusterDomain"], "cluster.local");
    assert_eq!(cfg["clusterDNS"], serde_json::json!(["10.43.0.10"]));

    // Upstream Kubernetes defaults: none of the removed KS-68 edge overrides or container-mode keys
    for key in [
        "maxPods",
        "enableProfilingHandler",
        "imageGCHighThresholdPercent",
        "evictionHard",
        "systemReserved",
        "kubeReserved",
        "cgroupsPerQOS",
        "enforceNodeAllocatable",
    ] {
        assert!(
            cfg.get(key).is_none(),
            "upstream host defaults must omit '{key}'"
        );
    }

    // Canonical YAML rendering must be deterministic and include only expected fields
    let yaml = options.render_yaml();
    assert!(yaml.starts_with("apiVersion: kubelet.config.k8s.io/v1beta1\n"));
    assert!(yaml.contains("cgroupDriver: systemd\n"));
    assert!(yaml.contains("resolvConf: /etc/resolv.conf\n"));
    assert!(!yaml.contains("cgroupsPerQOS"));
    assert!(!yaml.contains("evictionHard"));
    assert!(!yaml.contains("maxPods"));
}

#[test]
fn test_golden_host_mode_cgroup_drivers_and_versions() {
    // 1. Explicit cgroupfs driver
    let mut options = KubeletConfigOptions {
        cgroup_driver: "cgroupfs".to_string(),
        container_mode: false,
        ..Default::default()
    };
    let cfg = options.generate_kubelet_config();
    assert_eq!(cfg["cgroupDriver"], "cgroupfs");

    // 2. Runtime-reported driver overrides host setting
    options.cgroup_driver = "cgroupfs".to_string();
    options.runtime_cgroup_driver = Some("systemd".to_string());
    let cfg = options.generate_kubelet_config();
    assert_eq!(cfg["cgroupDriver"], "systemd");

    // 3. Cgroup version detection helper
    let temp_v2 = tempfile::tempdir().unwrap();
    std::fs::write(temp_v2.path().join("cgroup.controllers"), "cpu memory\n").unwrap();
    assert_eq!(
        KubeletCgroupVersion::detect(temp_v2.path()),
        KubeletCgroupVersion::V2
    );

    let temp_v1 = tempfile::tempdir().unwrap();
    assert_eq!(
        KubeletCgroupVersion::detect(temp_v1.path()),
        KubeletCgroupVersion::V1
    );
}

#[test]
fn test_golden_host_mode_custom_reservations_and_resolv() {
    let mut sys_res = BTreeMap::new();
    sys_res.insert("cpu".to_string(), "500m".to_string());
    sys_res.insert("memory".to_string(), "1Gi".to_string());

    let options = KubeletConfigOptions {
        container_mode: false,
        system_reserved: sys_res,
        resolv_conf: Some(PathBuf::from("/run/systemd/resolve/resolv.conf")),
        ..Default::default()
    };

    let cfg = options.generate_kubelet_config();
    assert_eq!(cfg["systemReserved"]["cpu"], "500m");
    assert_eq!(cfg["systemReserved"]["memory"], "1Gi");
    assert_eq!(cfg["resolvConf"], "/run/systemd/resolve/resolv.conf");
    assert!(cfg.get("kubeReserved").is_none());
}

#[test]
fn test_golden_container_mode_settings() {
    let options = KubeletConfigOptions {
        container_mode: true,
        cgroup_driver: "systemd".to_string(), // In container mode, defaults to cgroupfs unless runtime reports driver
        ..Default::default()
    };

    let cfg = options.generate_kubelet_config();

    // Container mode cgroup driver
    assert_eq!(cfg["cgroupDriver"], "cgroupfs");

    // Container mode DNS: /dev/null to prevent host DNS leaking into pods
    assert_eq!(cfg["resolvConf"], "/dev/null");

    // Container mode QoS cgroups and node allocatable disabled
    assert_eq!(cfg["cgroupsPerQOS"], false);
    assert_eq!(cfg["enforceNodeAllocatable"], serde_json::json!([]));

    // Relaxed eviction thresholds and GC high threshold
    assert_eq!(cfg["imageGCHighThresholdPercent"], 100);
    assert_eq!(
        cfg["evictionHard"],
        serde_json::json!({
            "imagefs.available": "0%",
            "memory.available": "50Mi",
            "nodefs.available": "0%",
            "nodefs.inodesFree": "0%"
        })
    );

    // Default container mode reservations are empty maps
    assert_eq!(cfg["systemReserved"], serde_json::json!({}));
    assert_eq!(cfg["kubeReserved"], serde_json::json!({}));

    // Secure defaults preserved
    assert_eq!(cfg["readOnlyPort"], 0);
    assert_eq!(cfg["failSwapOn"], false);
    assert_eq!(cfg["rotateCertificates"], true);

    // Ensure edge memory overrides are NOT set
    assert!(cfg.get("maxPods").is_none());
    assert!(cfg.get("enableProfilingHandler").is_none());

    let yaml = options.render_yaml();
    assert!(yaml.contains("cgroupsPerQOS: false\n"));
    assert!(yaml.contains("resolvConf: /dev/null\n"));
    assert!(yaml.contains("imageGCHighThresholdPercent: 100\n"));
    assert!(yaml.contains("memory.available: 50Mi\n"));
}

#[test]
fn test_golden_container_mode_preserves_operator_system_reserved() {
    let mut sys_res = BTreeMap::new();
    sys_res.insert("memory".to_string(), "500Mi".to_string());

    let options = KubeletConfigOptions {
        container_mode: true,
        system_reserved: sys_res,
        ..Default::default()
    };

    let cfg = options.generate_kubelet_config();
    assert_eq!(cfg["systemReserved"]["memory"], "500Mi");
    assert_eq!(cfg["kubeReserved"], serde_json::json!({}));
}

#[test]
fn test_golden_ipv6_disablement_and_node_ip_evaluation() {
    // 1. Valid non-loopback IPv4 with disable_ipv6 = true
    let mut options = KubeletConfigOptions {
        node_ip: "192.0.2.1".to_string(),
        disable_ipv6: true,
        ..Default::default()
    };
    let args = options.configure_kubelet_args();
    assert!(args.contains(&"--node-ip".to_string()));
    assert!(args.contains(&"192.0.2.1".to_string()));

    // 2. Valid non-loopback IPv6 with disable_ipv6 = true -> skipped (IPv4 only)
    options.node_ip = "2001:db8::1".to_string();
    options.disable_ipv6 = true;
    let args = options.configure_kubelet_args();
    assert!(!args.contains(&"--node-ip".to_string()));

    // 3. Valid non-loopback IPv6 with disable_ipv6 = false -> passed
    options.node_ip = "2001:db8::1".to_string();
    options.disable_ipv6 = false;
    let args = options.configure_kubelet_args();
    assert!(args.contains(&"--node-ip".to_string()));
    assert!(args.contains(&"2001:db8::1".to_string()));

    // 4. IPv4 loopback -> skipped
    options.node_ip = "127.0.0.1".to_string();
    options.disable_ipv6 = true;
    let args = options.configure_kubelet_args();
    assert!(!args.contains(&"--node-ip".to_string()));

    // 5. IPv6 loopback -> skipped
    options.node_ip = "::1".to_string();
    options.disable_ipv6 = false;
    let args = options.configure_kubelet_args();
    assert!(!args.contains(&"--node-ip".to_string()));

    // 6. Invalid IP string -> skipped
    options.node_ip = "not-an-ip".to_string();
    options.disable_ipv6 = false;
    let args = options.configure_kubelet_args();
    assert!(!args.contains(&"--node-ip".to_string()));
}

#[test]
fn test_static_cpu_manager_in_container_mode_is_rejected() {
    let options = KubeletConfigOptions {
        container_mode: true,
        cpu_manager_policy: "static".to_string(),
        ..Default::default()
    };

    let err = options
        .validate_upstream_resource_defaults()
        .expect_err("static policy must be rejected in container mode");
    assert!(
        err.to_string()
            .contains("static CPU manager policy is unsupported in container mode")
    );

    // In host mode, static policy is allowed
    let host_options = KubeletConfigOptions {
        container_mode: false,
        cpu_manager_policy: "static".to_string(),
        ..Default::default()
    };
    assert!(host_options.validate_upstream_resource_defaults().is_ok());
}
