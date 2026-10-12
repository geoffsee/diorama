use std::path::PathBuf;

use diorama_proxy::{
    ConntrackConfiguration, DEFAULT_CONNTRACK_MAX_PER_CORE, DEFAULT_CONNTRACK_MIN,
    DEFAULT_CONNTRACK_TCP_CLOSE_WAIT_TIMEOUT, DEFAULT_CONNTRACK_TCP_ESTABLISHED_TIMEOUT,
    DEFAULT_CONNTRACK_UDP_STREAM_TIMEOUT, DEFAULT_CONNTRACK_UDP_TIMEOUT, KubeProxyOptions,
    ProxyMode,
};

#[test]
fn test_host_mode_preserves_upstream_conntrack_defaults() {
    let conntrack = ConntrackConfiguration::default_host();

    assert_eq!(conntrack.max_per_core, Some(DEFAULT_CONNTRACK_MAX_PER_CORE));
    assert_eq!(conntrack.min, Some(DEFAULT_CONNTRACK_MIN));
    assert_eq!(
        conntrack.tcp_established_timeout.as_deref(),
        Some(DEFAULT_CONNTRACK_TCP_ESTABLISHED_TIMEOUT)
    );
    assert_eq!(
        conntrack.tcp_close_wait_timeout.as_deref(),
        Some(DEFAULT_CONNTRACK_TCP_CLOSE_WAIT_TIMEOUT)
    );
    assert_eq!(
        conntrack.udp_timeout.as_deref(),
        Some(DEFAULT_CONNTRACK_UDP_TIMEOUT)
    );
    assert_eq!(
        conntrack.udp_stream_timeout.as_deref(),
        Some(DEFAULT_CONNTRACK_UDP_STREAM_TIMEOUT)
    );

    assert!(conntrack.is_upstream_defaults());
    assert!(!conntrack.is_all_zero());

    // Host mode options
    let options = KubeProxyOptions::new(
        PathBuf::from("/etc/kubernetes/admin.kubeconfig"),
        false, // container_mode = false (host mode)
        ProxyMode::IpTables,
    );

    assert!(!options.container_mode);
    assert!(options.conntrack.is_upstream_defaults());
    assert!(!options.conntrack.is_all_zero());

    // CLI flags in host mode do NOT zero conntrack settings
    let flags = options.generate_flags();
    for zeroed_name in [
        "--conntrack-max-per-core=0",
        "--conntrack-min=0",
        "--conntrack-tcp-timeout-established=0s",
        "--conntrack-tcp-timeout-close-wait=0s",
        "--conntrack-udp-timeout=0s",
        "--conntrack-udp-timeout-stream=0s",
    ] {
        assert!(
            !flags.contains(&zeroed_name.to_string()),
            "host mode should not set {zeroed_name}"
        );
    }
}

#[test]
fn test_container_mode_sets_all_six_conntrack_settings_to_zero() {
    let conntrack = ConntrackConfiguration::container_mode();

    // 1. maxPerCore is 0
    assert_eq!(conntrack.max_per_core, Some(0));
    // 2. min is 0
    assert_eq!(conntrack.min, Some(0));
    // 3. tcpEstablishedTimeout is 0s
    assert_eq!(conntrack.tcp_established_timeout.as_deref(), Some("0s"));
    // 4. tcpCloseWaitTimeout is 0s
    assert_eq!(conntrack.tcp_close_wait_timeout.as_deref(), Some("0s"));
    // 5. udpTimeout is 0s
    assert_eq!(conntrack.udp_timeout.as_deref(), Some("0s"));
    // 6. udpStreamTimeout is 0s
    assert_eq!(conntrack.udp_stream_timeout.as_deref(), Some("0s"));

    assert!(conntrack.is_all_zero());
    assert!(!conntrack.is_upstream_defaults());

    // Container mode options
    let options = KubeProxyOptions::new(
        PathBuf::from("/etc/kubernetes/admin.kubeconfig"),
        true, // container_mode = true
        ProxyMode::IpTables,
    );

    assert!(options.container_mode);
    assert!(options.conntrack.is_all_zero());

    // CLI flags in container mode MUST set all six conntrack settings to zero
    let flags = options.generate_flags();
    let zeroed_flags = [
        "--conntrack-max-per-core=0",
        "--conntrack-min=0",
        "--conntrack-tcp-timeout-established=0s",
        "--conntrack-tcp-timeout-close-wait=0s",
        "--conntrack-udp-timeout=0s",
        "--conntrack-udp-timeout-stream=0s",
    ];

    for expected in zeroed_flags {
        assert!(
            flags.contains(&expected.to_string()),
            "container mode flags must contain {expected}"
        );
    }

    // Even if conntrack is manually set to non-zero values on the options struct,
    // container_mode = true must strictly override and zero all six settings in flags and v1alpha1 config.
    let mut overridden = options;
    overridden.conntrack = ConntrackConfiguration::default_host();
    let overridden_flags = overridden.generate_flags();
    for expected in zeroed_flags {
        assert!(
            overridden_flags.contains(&expected.to_string()),
            "container mode flags must enforce {expected} even if options had host defaults"
        );
    }
    let overridden_cfg = overridden.to_v1alpha1_config();
    assert!(overridden_cfg.conntrack.is_all_zero());
}

#[test]
fn test_v1alpha1_config_generation() {
    let host_opts = KubeProxyOptions::new(
        PathBuf::from("/etc/kubernetes/admin.kubeconfig"),
        false,
        ProxyMode::IpTables,
    );
    let host_cfg = host_opts.to_v1alpha1_config();
    assert_eq!(host_cfg.api_version, "kubeproxy.config.k8s.io/v1alpha1");
    assert_eq!(host_cfg.kind, "KubeProxyConfiguration");
    assert_eq!(host_cfg.mode, "iptables");
    assert!(host_cfg.iptables.masquerade_all);
    assert_eq!(
        host_cfg.conntrack.max_per_core,
        Some(DEFAULT_CONNTRACK_MAX_PER_CORE)
    );
    assert_eq!(host_cfg.conntrack.min, Some(DEFAULT_CONNTRACK_MIN));

    let json_str = serde_json::to_string_pretty(&host_cfg).unwrap();
    assert!(json_str.contains("\"apiVersion\": \"kubeproxy.config.k8s.io/v1alpha1\""));
    assert!(json_str.contains("\"maxPerCore\": 32768"));

    let container_opts = KubeProxyOptions::new(
        PathBuf::from("/etc/kubernetes/admin.kubeconfig"),
        true,
        ProxyMode::Nftables,
    );
    let container_cfg = container_opts.to_v1alpha1_config();
    assert_eq!(container_cfg.mode, "nftables");
    assert!(!container_cfg.iptables.masquerade_all);
    assert_eq!(container_cfg.conntrack.max_per_core, Some(0));
    assert_eq!(container_cfg.conntrack.min, Some(0));
    assert_eq!(
        container_cfg.conntrack.tcp_established_timeout.as_deref(),
        Some("0s")
    );
    assert_eq!(
        container_cfg.conntrack.tcp_close_wait_timeout.as_deref(),
        Some("0s")
    );
    assert_eq!(container_cfg.conntrack.udp_timeout.as_deref(), Some("0s"));
    assert_eq!(
        container_cfg.conntrack.udp_stream_timeout.as_deref(),
        Some("0s")
    );
}
