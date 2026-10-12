use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

use dioramalet::{KubeletConfigOptions, render_canonical_yaml};

#[test]
fn test_kubelet_config_golden_host_default() {
    let options = KubeletConfigOptions {
        node_name: "fixture-node".to_string(),
        node_ip: "192.0.2.8".to_string(),
        ca_file: PathBuf::from("/fixture/ca.crt"),
        cert_file: PathBuf::from("/fixture/node.crt"),
        key_file: PathBuf::from("/fixture/node.key"),
        runtime_endpoint: "unix:///fixture/runtime.sock".to_string(),
        cgroup_driver: "cgroupfs".to_string(),
        container_mode: false,
        ..Default::default()
    };

    let config = options.generate_kubelet_config();
    assert_eq!(config["apiVersion"], "kubelet.config.k8s.io/v1beta1");
    assert_eq!(config["kind"], "KubeletConfiguration");
    assert_eq!(
        config["containerRuntimeEndpoint"],
        "unix:///fixture/runtime.sock"
    );
    assert_eq!(config["cgroupDriver"], "cgroupfs");
    assert_eq!(config["resolvConf"], "/etc/resolv.conf");
    assert_eq!(config["authentication"]["anonymous"]["enabled"], false);
    assert_eq!(config["authentication"]["webhook"]["enabled"], true);
    assert_eq!(
        config["authentication"]["x509"]["clientCAFile"],
        "/fixture/ca.crt"
    );
    assert_eq!(config["authorization"]["mode"], "Webhook");
    assert_eq!(config["clusterDNS"], serde_json::json!(["10.43.0.10"]));
    assert_eq!(config["clusterDomain"], "cluster.local");
    assert_eq!(config["readOnlyPort"], 0);
    assert_eq!(config["failSwapOn"], false);
    assert_eq!(config["rotateCertificates"], true);
    assert_eq!(config["tlsCertFile"], "/fixture/node.crt");
    assert_eq!(config["tlsPrivateKeyFile"], "/fixture/node.key");

    let yaml = options.render_yaml();
    assert!(yaml.starts_with("apiVersion: kubelet.config.k8s.io/v1beta1\n"));
    assert!(yaml.contains("kind: KubeletConfiguration\n"));
    assert!(yaml.contains("resolvConf: /etc/resolv.conf\n"));
    assert!(yaml.contains("cgroupDriver: cgroupfs\n"));
}

#[test]
fn test_kubelet_config_container_mode_and_static_cpu() {
    let mut policy_options = BTreeMap::new();
    policy_options.insert("full-pcpus-only".to_string(), "true".to_string());
    let mut sys_res = BTreeMap::new();
    sys_res.insert("cpu".to_string(), "200m".to_string());
    sys_res.insert("memory".to_string(), "128Mi".to_string());

    let options = KubeletConfigOptions {
        node_name: "fixture-node".to_string(),
        ca_file: PathBuf::from("/fixture/ca.crt"),
        cert_file: PathBuf::from("/fixture/node.crt"),
        key_file: PathBuf::from("/fixture/node.key"),
        runtime_endpoint: "unix:///fixture/runtime.sock".to_string(),
        cgroup_driver: "cgroupfs".to_string(),
        container_mode: true,
        cpu_manager_policy: "static".to_string(),
        reserved_cpus: "0-1".to_string(),
        cpu_manager_policy_options: policy_options,
        system_reserved: sys_res,
        ..Default::default()
    };

    let config = options.generate_kubelet_config();
    assert_eq!(config["resolvConf"], "/dev/null");
    assert_eq!(config["cgroupsPerQOS"], false);
    assert_eq!(config["enforceNodeAllocatable"], serde_json::json!([]));
    assert_eq!(config["imageGCHighThresholdPercent"], 100);
    assert_eq!(config["cpuManagerPolicy"], "static");
    assert_eq!(config["reservedSystemCPUs"], "0-1");
    assert_eq!(config["cpuManagerPolicyOptions"]["full-pcpus-only"], "true");
    assert_eq!(config["systemReserved"]["cpu"], "200m");
    assert_eq!(config["systemReserved"]["memory"], "128Mi");

    let yaml = options.render_yaml();
    assert!(yaml.contains("cpuManagerPolicy: static\n"));
    assert!(yaml.contains("reservedSystemCPUs: 0-1\n"));
    assert!(yaml.contains("resolvConf: /dev/null\n"));
    assert!(yaml.contains("full-pcpus-only: \"true\"\n"));
}

#[test]
fn test_kubelet_cli_args_evaluation() {
    let mut options = KubeletConfigOptions {
        config_file: PathBuf::from("/tmp/diorama-node/kubelet.yaml"),
        node_name: "fixture-node".to_string(),
        root_dir: PathBuf::from("/tmp/diorama-node"),
        kubeconfig: PathBuf::from("/fixture/node.kubeconfig"),
        node_ip: "192.0.2.8".to_string(),
        disable_ipv6: true,
        ..Default::default()
    };
    let args = options.configure_kubelet_args();
    assert_eq!(
        args,
        vec![
            "--config",
            "/tmp/diorama-node/kubelet.yaml",
            "--hostname-override",
            "fixture-node",
            "--root-dir",
            "/tmp/diorama-node",
            "--kubeconfig",
            "/fixture/node.kubeconfig",
            "--node-ip",
            "192.0.2.8"
        ]
    );

    // Case 2: valid IPv6 (when disable_ipv6 is false)
    options.node_ip = "2001:db8::8".to_string();
    options.disable_ipv6 = false;
    let args = options.configure_kubelet_args();
    assert!(args.contains(&"--node-ip".to_string()));
    assert!(args.contains(&"2001:db8::8".to_string()));

    // Case 3: valid IPv6 (when disable_ipv6 is true -> omitted)
    options.node_ip = "2001:db8::8".to_string();
    options.disable_ipv6 = true;
    let args = options.configure_kubelet_args();
    assert!(!args.contains(&"--node-ip".to_string()));

    // Case 4: loopback IPv4 (omitted)
    options.node_ip = "127.0.0.1".to_string();
    let args = options.configure_kubelet_args();
    assert!(!args.contains(&"--node-ip".to_string()));

    // Case 5: invalid IP (omitted)
    options.node_ip = "bad".to_string();
    let args = options.configure_kubelet_args();
    assert!(!args.contains(&"--node-ip".to_string()));
}

#[test]
fn test_write_kubelet_config_file_success_and_parent_file_failure() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("sub").join("kubelet.yaml");

    let mut options = KubeletConfigOptions {
        config_file: config_path.clone(),
        ..Default::default()
    };

    // Successful write creates parent directory
    options.write_kubelet_config_file().unwrap();
    assert!(config_path.exists());
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("apiVersion: kubelet.config.k8s.io/v1beta1"));

    // Repeat write produces identical content
    options.write_kubelet_config_file().unwrap();
    let repeat = fs::read_to_string(&config_path).unwrap();
    assert_eq!(content, repeat);

    // Parent is regular file failure
    let file_parent = dir.path().join("blocked");
    fs::write(&file_parent, "not a directory").unwrap();
    options.config_file = file_parent.join("config.yaml");
    assert!(options.write_kubelet_config_file().is_err());
}

#[test]
fn test_render_canonical_yaml_deterministic() {
    let val = serde_json::json!({
        "z": 1,
        "a": "hello",
        "nested": {
            "b": false,
            "a": true
        },
        "list": ["item1", "item2"]
    });
    let yaml = render_canonical_yaml(&val);
    assert_eq!(
        yaml,
        "a: hello\nlist:\n  - item1\n  - item2\nnested:\n  a: true\n  b: false\nz: 1\n"
    );
}
