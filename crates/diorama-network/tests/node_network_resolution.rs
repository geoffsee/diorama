use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use diorama_network::{
    DEFAULT_MTU, FALLBACK_NAMESERVERS, INSTANCE_METADATA_SERVICE_IP, InterfaceCandidate,
    MAX_NAMESERVERS, MAX_VALID_MTU, MIN_VALID_MTU, NetworkError, classify_ipv4,
    disable_ipv6_sysctls_in_root, get_host_resolv_conf, get_local_ips, is_dns_name,
    is_global_unicast, is_ipv4_address, is_local_ip, is_valid_nameserver, is_valid_resolv_conf,
    resolve_load_balancer_ip, resolve_mtu, resolve_node_ip, sanitize_resolv_conf, select_mtu,
    select_node_ip,
};
use tempfile::TempDir;

fn make_candidate(name: &str, mtu: u32, addrs: &[&str]) -> InterfaceCandidate {
    let parsed = addrs
        .iter()
        .map(|s| s.parse::<IpAddr>().expect("valid ip"))
        .collect();
    InterfaceCandidate::new(name, mtu, parsed)
}

#[test]
fn test_multi_nic_selection_prefers_private_ipv4_over_public() {
    // Public IP candidate listed FIRST, private listed SECOND
    let candidates = vec![
        make_candidate("eth0", 1500, &["203.0.113.9"]),
        make_candidate("eth1", 1400, &["192.168.1.10"]),
    ];

    let selected_ip = select_node_ip(&candidates).expect("should find private IP");
    assert_eq!(selected_ip, Ipv4Addr::new(192, 168, 1, 10));

    let selected_mtu = select_mtu(&candidates).expect("should find private interface MTU");
    assert_eq!(selected_mtu, 1400);

    // Private listed FIRST, public listed SECOND
    let candidates_rev = vec![
        make_candidate("eth1", 1400, &["10.0.0.5"]),
        make_candidate("eth0", 1500, &["198.51.100.22"]),
    ];

    let selected_ip_rev = select_node_ip(&candidates_rev).unwrap();
    assert_eq!(selected_ip_rev, Ipv4Addr::new(10, 0, 0, 5));

    let selected_mtu_rev = select_mtu(&candidates_rev).unwrap();
    assert_eq!(selected_mtu_rev, 1400);
}

#[test]
fn test_multi_nic_fallback_to_public_ipv4_when_no_private_ip() {
    let candidates = vec![
        make_candidate("lo", 65536, &["127.0.0.1"]),
        make_candidate("eth0", 1450, &["203.0.113.9"]),
    ];

    let selected_ip = select_node_ip(&candidates).expect("should fall back to public IP");
    assert_eq!(selected_ip, Ipv4Addr::new(203, 0, 113, 9));

    let selected_mtu = select_mtu(&candidates).expect("should fall back to public MTU");
    assert_eq!(selected_mtu, 1450);
}

#[test]
fn test_skips_zero_mtu_candidate_and_handles_loopback_only() {
    // Candidate with 0 MTU is down/virtual and must be skipped for MTU
    let candidates = vec![
        make_candidate("dummy0", 0, &["192.168.1.10"]),
        make_candidate("eth0", 1500, &["192.168.1.11"]),
    ];
    let mtu = select_mtu(&candidates).unwrap();
    assert_eq!(mtu, 1500);

    // Loopback only fails with NoUsableInterface
    let loopback_only = vec![make_candidate("lo", 65536, &["127.0.0.1"])];
    let ip_err = select_node_ip(&loopback_only);
    assert!(ip_err.is_err());
    assert_eq!(
        ip_err.unwrap_err().diagnostic_code(),
        "network-no-usable-interface"
    );

    let mtu_err = select_mtu(&loopback_only);
    assert!(mtu_err.is_err());
    assert_eq!(
        mtu_err.unwrap_err().diagnostic_code(),
        "network-no-usable-interface"
    );
}

#[test]
fn test_vpn_and_low_mtu_interface_selection() {
    // VPN tunnel interface with MTU 1280 or 1400
    let candidates = vec![
        make_candidate("wg0", 1280, &["10.8.0.2"]),
        make_candidate("eth0", 1500, &["198.51.100.1"]),
    ];

    let (ip, pinned) = resolve_node_ip(None, &candidates).unwrap();
    assert_eq!(ip, Ipv4Addr::new(10, 8, 0, 2));
    assert!(!pinned);

    let (mtu, pinned_mtu) = resolve_mtu(None, &candidates).unwrap();
    assert_eq!(mtu, 1280);
    assert!(!pinned_mtu);
}

#[test]
fn test_explicit_node_ip_override_and_pinning() {
    let candidates = vec![make_candidate("eth0", 1500, &["192.168.1.10"])];

    // Valid override bound locally
    let (ip, pinned) = resolve_node_ip(Some("192.168.1.10"), &candidates).unwrap();
    assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 10));
    assert!(pinned, "valid override must be reported as pinned");

    // Valid override not bound locally (VIP) -> allowed and pinned
    let (vip, vip_pinned) = resolve_node_ip(Some("203.0.113.5"), &candidates).unwrap();
    assert_eq!(vip, Ipv4Addr::new(203, 0, 113, 5));
    assert!(vip_pinned, "VIP override must still be reported as pinned");

    // Invalid override (not an IPv4 address) -> falls back to auto-detection and NOT pinned
    let (fallback_ip, fallback_pinned) = resolve_node_ip(Some("not-an-ip"), &candidates).unwrap();
    assert_eq!(fallback_ip, Ipv4Addr::new(192, 168, 1, 10));
    assert!(
        !fallback_pinned,
        "invalid override must not be treated as pinned"
    );

    // IPv6 override rejected for IPv4 node IP -> falls back to auto-detection and NOT pinned
    let (fallback_v6, fallback_v6_pinned) =
        resolve_node_ip(Some("2001:db8::1"), &candidates).unwrap();
    assert_eq!(fallback_v6, Ipv4Addr::new(192, 168, 1, 10));
    assert!(!fallback_v6_pinned);

    // Empty override -> auto-detected, NOT pinned
    let (auto_ip, auto_pinned) = resolve_node_ip(Some(""), &candidates).unwrap();
    assert_eq!(auto_ip, Ipv4Addr::new(192, 168, 1, 10));
    assert!(!auto_pinned);
}

#[test]
fn test_explicit_mtu_override_and_pinning() {
    let candidates = vec![make_candidate("eth0", 1500, &["192.168.1.10"])];

    // Valid override
    let (mtu, pinned) = resolve_mtu(Some(1400), &candidates).unwrap();
    assert_eq!(mtu, 1400);
    assert!(pinned, "valid MTU override must be reported as pinned");

    // Valid boundary overrides [68, 65535]
    let (min_mtu, min_pinned) = resolve_mtu(Some(i64::from(MIN_VALID_MTU)), &candidates).unwrap();
    assert_eq!(min_mtu, MIN_VALID_MTU);
    assert!(min_pinned);

    let (max_mtu, max_pinned) = resolve_mtu(Some(i64::from(MAX_VALID_MTU)), &candidates).unwrap();
    assert_eq!(max_mtu, MAX_VALID_MTU);
    assert!(max_pinned);

    // Out-of-range override (> 65535) -> auto-detected and NOT pinned
    let (detected_high, pinned_high) = resolve_mtu(Some(70000), &candidates).unwrap();
    assert_eq!(detected_high, 1500);
    assert!(
        !pinned_high,
        "out of range MTU override must not be reported as pinned"
    );

    // Out-of-range override (< 68 but > 0) -> auto-detected and NOT pinned
    let (detected_low, pinned_low) = resolve_mtu(Some(50), &candidates).unwrap();
    assert_eq!(detected_low, 1500);
    assert!(!pinned_low);

    // Zero or negative -> auto-detected, NOT pinned
    let (detected_zero, pinned_zero) = resolve_mtu(Some(0), &candidates).unwrap();
    assert_eq!(detected_zero, 1500);
    assert!(!pinned_zero);

    let (detected_neg, pinned_neg) = resolve_mtu(Some(-1), &candidates).unwrap();
    assert_eq!(detected_neg, 1500);
    assert!(!pinned_neg);
}

#[test]
fn test_resolve_load_balancer_ip() {
    let candidates = vec![make_candidate("eth0", 1500, &["192.168.1.10"])];

    // Unset falls back to node IP
    assert_eq!(
        resolve_load_balancer_ip(None, "192.168.1.10", &candidates),
        "192.168.1.10"
    );
    assert_eq!(
        resolve_load_balancer_ip(Some(""), "192.168.1.10", &candidates),
        "192.168.1.10"
    );

    // Invalid IP falls back to node IP
    assert_eq!(
        resolve_load_balancer_ip(Some("not-an-ip"), "192.168.1.10", &candidates),
        "192.168.1.10"
    );
    assert_eq!(
        resolve_load_balancer_ip(Some("2001:db8::1"), "192.168.1.10", &candidates),
        "192.168.1.10"
    );

    // Valid override
    assert_eq!(
        resolve_load_balancer_ip(Some("192.168.1.10"), "192.168.1.10", &candidates),
        "192.168.1.10"
    );
    assert_eq!(
        resolve_load_balancer_ip(Some("203.0.113.9"), "192.168.1.10", &candidates),
        "203.0.113.9"
    );
}

#[test]
fn test_is_ipv4_address() {
    assert!(is_ipv4_address("10.43.0.1"));
    assert!(is_ipv4_address("127.0.0.1"));
    assert!(is_ipv4_address("0.0.0.0"));
    assert!(is_ipv4_address("255.255.255.255"));

    assert!(!is_ipv4_address("::1"));
    assert!(!is_ipv4_address("2001:db8::1"));
    assert!(!is_ipv4_address("10.43.0.256"));
    assert!(!is_ipv4_address("not-an-ip"));
    assert!(!is_ipv4_address(""));
    assert!(!is_ipv4_address("10.43.0"));
}

#[test]
fn test_is_dns_name() {
    assert!(is_dns_name("kubernetes.default"));
    assert!(is_dns_name("webhook.kubesolo.io"));
    assert!(is_dns_name("a"));
    assert!(is_dns_name("node-1"));

    assert!(!is_dns_name(""));
    assert!(!is_dns_name("-leadinghyphen"));
    assert!(!is_dns_name("trailinghyphen-"));
    assert!(!is_dns_name("under_score"));
    assert!(!is_dns_name("has space"));
    assert!(!is_dns_name("label..empty"));

    let long = "a".repeat(254);
    assert!(!is_dns_name(&long), "name >253 chars must be rejected");
}

#[test]
fn test_is_valid_nameserver() {
    assert!(is_global_unicast("8.8.8.8".parse().unwrap()));
    assert!(!is_global_unicast("127.0.0.1".parse().unwrap()));
    assert_eq!(
        INSTANCE_METADATA_SERVICE_IP,
        Ipv4Addr::new(169, 254, 169, 254)
    );
    assert_eq!(FALLBACK_NAMESERVERS, ["8.8.8.8", "1.1.1.1"]);
    assert_eq!(DEFAULT_MTU, 1500);

    assert!(is_valid_nameserver("8.8.8.8"));
    assert!(is_valid_nameserver("1.1.1.1"));
    assert!(
        is_valid_nameserver("169.254.169.254"),
        "cloud metadata IP must be allowed"
    );

    assert!(
        !is_valid_nameserver("127.0.0.1"),
        "loopback must not be accepted"
    );
    assert!(
        !is_valid_nameserver("127.0.0.53"),
        "systemd-resolved loopback must not be accepted"
    );
    assert!(
        !is_valid_nameserver("169.254.0.1"),
        "non-metadata link-local must not be accepted"
    );
    assert!(
        !is_valid_nameserver("0.0.0.0"),
        "unspecified must not be accepted"
    );
    assert!(!is_valid_nameserver("garbage"));
    assert!(!is_valid_nameserver(""));
}

#[test]
fn test_is_valid_resolv_conf() {
    let temp = TempDir::new().unwrap();

    let valid_path = temp.path().join("valid.conf");
    fs::write(
        &valid_path,
        "nameserver 8.8.8.8\nsearch example.com\noptions ndots:2\n",
    )
    .unwrap();
    assert!(is_valid_resolv_conf(&valid_path));

    // Loopback nameserver renders entire file unusable for pods
    let loopback_path = temp.path().join("loopback.conf");
    fs::write(&loopback_path, "nameserver 127.0.0.53\n").unwrap();
    assert!(!is_valid_resolv_conf(&loopback_path));

    // Mixed with a loopback nameserver also renders file invalid
    let mixed_path = temp.path().join("mixed.conf");
    fs::write(&mixed_path, "nameserver 8.8.8.8\nnameserver 127.0.0.53\n").unwrap();
    assert!(!is_valid_resolv_conf(&mixed_path));

    // No nameserver line
    let no_ns_path = temp.path().join("no_ns.conf");
    fs::write(&no_ns_path, "search example.com\noptions ndots:5\n").unwrap();
    assert!(!is_valid_resolv_conf(&no_ns_path));

    // Missing file
    assert!(!is_valid_resolv_conf(&temp.path().join("nonexistent.conf")));
}

#[test]
fn test_sanitize_resolv_conf() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();

    // 1. Under limit (<= 3 nameservers, no duplicates) returns source unchanged
    let under_path = temp.path().join("under.conf");
    fs::write(
        &under_path,
        "nameserver 8.8.8.8\nnameserver 1.1.1.1\nnameserver 9.9.9.9\nsearch corp\n",
    )
    .unwrap();
    let res = sanitize_resolv_conf(&under_path, &data_dir).unwrap();
    assert_eq!(res, under_path, "source path returned unchanged when valid");

    // 2. Over limit caps to 3, deduplicates, and preserves other configuration lines
    let over_path = temp.path().join("over.conf");
    fs::write(
        &over_path,
        "nameserver 8.8.8.8\n\
         nameserver 8.8.8.8\n\
         nameserver 1.1.1.1\n\
         nameserver 9.9.9.9\n\
         nameserver 4.4.4.4\n\
         search corp.example.com\n\
         options ndots:2\n",
    )
    .unwrap();
    let sanitized_path = sanitize_resolv_conf(&over_path, &data_dir).unwrap();
    assert_eq!(sanitized_path, data_dir.join("resolv.conf"));

    let content = fs::read_to_string(&sanitized_path).unwrap();
    assert!(content.contains("nameserver 8.8.8.8\n"));
    assert!(content.contains("nameserver 1.1.1.1\n"));
    assert!(content.contains("nameserver 9.9.9.9\n"));
    assert!(
        !content.contains("4.4.4.4"),
        "4th unique nameserver must be capped out"
    );
    assert!(content.contains("search corp.example.com\n"));
    assert!(content.contains("options ndots:2\n"));

    let nameserver_count = content
        .lines()
        .filter(|l| l.starts_with("nameserver"))
        .count();
    assert_eq!(nameserver_count, MAX_NAMESERVERS);
}

#[test]
fn test_get_host_resolv_conf_container_mode() {
    let temp = TempDir::new().unwrap();
    let path = get_host_resolv_conf(temp.path(), true);
    assert_eq!(
        path,
        Path::new("/dev/null"),
        "container mode must return /dev/null to prevent host DNS leakage"
    );
}

#[test]
fn test_get_host_resolv_conf_fallback_generation() {
    let temp = TempDir::new().unwrap();
    // When candidates are invalid or missing, it generates fallback with 8.8.8.8 and 1.1.1.1 in data_dir
    let missing = temp.path().join("missing.conf");
    let path =
        diorama_network::get_host_resolv_conf_with_candidates(temp.path(), false, &[&missing]);
    assert!(path.exists());
    let content = fs::read_to_string(&path).unwrap();
    assert!(content.contains("nameserver 8.8.8.8"));
    assert!(content.contains("nameserver 1.1.1.1"));
}

#[test]
fn test_disable_ipv6_sysctls_in_root() {
    let temp = TempDir::new().unwrap();
    let sysctl_root = temp.path().join("proc/sys");

    let all_path = sysctl_root.join("net/ipv6/conf/all/disable_ipv6");
    let default_path = sysctl_root.join("net/ipv6/conf/default/disable_ipv6");
    let lo_path = sysctl_root.join("net/ipv6/conf/lo/disable_ipv6");

    fs::create_dir_all(all_path.parent().unwrap()).unwrap();
    fs::create_dir_all(default_path.parent().unwrap()).unwrap();
    fs::create_dir_all(lo_path.parent().unwrap()).unwrap();

    fs::write(&all_path, b"0\n").unwrap();
    fs::write(&default_path, b"0\n").unwrap();
    fs::write(&lo_path, b"1\n").unwrap(); // already disabled

    // First run disables all
    disable_ipv6_sysctls_in_root(&sysctl_root).unwrap();
    assert_eq!(fs::read(&all_path).unwrap(), b"1");
    assert_eq!(fs::read(&default_path).unwrap(), b"1");
    assert_eq!(&fs::read(&lo_path).unwrap()[..1], b"1");

    // Second run is idempotent
    disable_ipv6_sysctls_in_root(&sysctl_root).unwrap();
    assert_eq!(fs::read(&all_path).unwrap(), b"1");

    // Non-existent root gracefully skips without error
    let missing_root = temp.path().join("missing/proc/sys");
    assert!(disable_ipv6_sysctls_in_root(&missing_root).is_ok());
}

#[test]
fn test_get_local_ips_and_is_local_ip() {
    let candidates = vec![
        make_candidate("eth0", 1500, &["192.168.1.10"]),
        make_candidate("eth1", 1400, &["10.0.0.1"]),
    ];

    let local_ips = get_local_ips(&candidates);
    assert!(local_ips.contains(&Ipv4Addr::new(192, 168, 1, 10)));
    assert!(local_ips.contains(&Ipv4Addr::new(10, 0, 0, 1)));
    assert!(local_ips.contains(&Ipv4Addr::LOCALHOST));

    assert!(is_local_ip("192.168.1.10", &candidates));
    assert!(is_local_ip("10.0.0.1", &candidates));
    assert!(is_local_ip("127.0.0.1", &candidates));
    assert!(!is_local_ip("198.51.100.1", &candidates));
    assert!(!is_local_ip("invalid-ip", &candidates));
}

#[test]
fn test_classify_ipv4() {
    let private = "192.168.1.1".parse::<IpAddr>().unwrap();
    let (ip, is_priv) = classify_ipv4(private).unwrap();
    assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
    assert!(is_priv);

    let public = "203.0.113.1".parse::<IpAddr>().unwrap();
    let (pub_ip, pub_is_priv) = classify_ipv4(public).unwrap();
    assert_eq!(pub_ip, Ipv4Addr::new(203, 0, 113, 1));
    assert!(!pub_is_priv);

    let loopback = "127.0.0.1".parse::<IpAddr>().unwrap();
    assert!(classify_ipv4(loopback).is_none());

    let v6 = "::1".parse::<IpAddr>().unwrap();
    assert!(classify_ipv4(v6).is_none());
}

#[test]
fn test_network_error_diagnostics() {
    let err = NetworkError::NoUsableInterface {
        reason: "none".to_string(),
    };
    assert_eq!(err.diagnostic_code(), "network-no-usable-interface");

    let err = NetworkError::InvalidNodeIP {
        ip: "x".to_string(),
        reason: "bad".to_string(),
    };
    assert_eq!(err.diagnostic_code(), "network-invalid-node-ip");

    let err = NetworkError::InvalidMTU {
        mtu: 10,
        reason: "too small".to_string(),
    };
    assert_eq!(err.diagnostic_code(), "network-invalid-mtu");

    let err = NetworkError::ResolvConfError {
        reason: "bad".to_string(),
    };
    assert_eq!(err.diagnostic_code(), "network-resolv-conf-error");

    let err = NetworkError::SysctlError {
        path: "/proc".to_string(),
        reason: "failed".to_string(),
    };
    assert_eq!(err.diagnostic_code(), "network-sysctl-error");
}
