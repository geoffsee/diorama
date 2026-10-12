#![allow(clippy::too_many_lines)]

use std::fs;
use std::sync::Arc;

use diorama_network::{CommandExecutor, DEFAULT_POD_CIDR, MASQUERADE_COMMENT, MockCommandExecutor};
use diorama_proxy::{
    DataplaneProber, DataplaneReconciler, EndpointItem, EndpointPort, EndpointSliceDefinition,
    FirewallSnapshot, KubeProxyOptions, Protocol, ProxyMode, ProxyService, ServiceDefinition,
    ServicePort, ServiceType,
};
use tempfile::TempDir;

#[tokio::test]
async fn test_clusterip_and_nodeport_traffic_recovers_after_restart_and_endpoint_replacement() {
    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let proc_net = temp.path().join("proc/net");
    fs::create_dir_all(&proc_net).unwrap();
    fs::write(proc_net.join("ip_tables_names"), "filter\nnat\n").unwrap();

    let mock = Arc::new(MockCommandExecutor::new_iptables_host());
    let options = KubeProxyOptions::new(kubeconfig, true, ProxyMode::IpTables);
    let executor: Arc<dyn CommandExecutor> = mock.clone();

    let mut service = ProxyService::new(options)
        .with_executor(executor)
        .with_sys_root(temp.path().to_path_buf());

    service.check_prerequisites().unwrap();
    service.start().unwrap();
    service.check_startup_readiness().unwrap();

    // 1. Initial Service and EndpointSlice setup
    let initial_svc = ServiceDefinition::new(
        "default",
        "api-service",
        ServiceType::NodePort,
        Some("10.43.0.50".to_string()),
        vec![
            ServicePort {
                name: Some("http".to_string()),
                protocol: Protocol::Tcp,
                port: 80,
                target_port: 8080,
                node_port: Some(30080),
            },
            ServicePort {
                name: Some("dns".to_string()),
                protocol: Protocol::Udp,
                port: 53,
                target_port: 53,
                node_port: Some(30053),
            },
        ],
    );
    service.apply_service(initial_svc).await;

    let initial_slice = EndpointSliceDefinition::new(
        "default",
        "api-slice-1",
        "api-service",
        vec![
            EndpointPort {
                name: Some("http".to_string()),
                port: Some(8080),
                protocol: Some(Protocol::Tcp),
            },
            EndpointPort {
                name: Some("dns".to_string()),
                port: Some(53),
                protocol: Some(Protocol::Udp),
            },
        ],
        vec![EndpointItem::new(
            vec!["10.42.0.10".to_string()],
            true,
            Some("node-1".to_string()),
        )],
    );
    service.apply_endpoint_slice(initial_slice).await;

    // Verify initial dataplane traffic routes to 10.42.0.10
    let prober = DataplaneProber::new();
    let initial_report = service.verify_dataplane(&prober).await.unwrap();
    assert!(initial_report.all_passed());
    assert!(service.is_dataplane_ready());

    let initial_tcp_probe = prober
        .probe_route(
            &*service.routing_table().read().await,
            "10.43.0.50",
            80,
            Protocol::Tcp,
        )
        .unwrap();
    assert_eq!(initial_tcp_probe.reached_endpoint.unwrap().ip, "10.42.0.10");

    // 2. Simulate proxy restart
    service.restart().unwrap();
    assert!(service.is_running());
    assert!(
        !service.is_dataplane_ready(),
        "dataplane readiness must be unconfirmed immediately after restart"
    );

    // 3. Simulate backend endpoint replacement / pod churn during/after restart:
    // Pod 10.42.0.10 terminated, replacement pod 10.42.0.25 scheduled and ready
    let replacement_slice = EndpointSliceDefinition::new(
        "default",
        "api-slice-1",
        "api-service",
        vec![
            EndpointPort {
                name: Some("http".to_string()),
                port: Some(8080),
                protocol: Some(Protocol::Tcp),
            },
            EndpointPort {
                name: Some("dns".to_string()),
                port: Some(53),
                protocol: Some(Protocol::Udp),
            },
        ],
        vec![EndpointItem::new(
            vec!["10.42.0.25".to_string()],
            true,
            Some("node-1".to_string()),
        )],
    );
    service.apply_endpoint_slice(replacement_slice).await;

    // Reconcile dataplane with awareness of previous endpoints
    let reconciler = DataplaneReconciler::new();
    let previous_eps = vec!["10.42.0.10:8080".to_string(), "10.42.0.10:53".to_string()];
    let summary = service
        .reconcile_dataplane(&reconciler, Some(&previous_eps))
        .await
        .unwrap();

    assert_eq!(summary.services_reconciled, 1);
    assert_eq!(summary.active_endpoints, 2); // 1 TCP (8080), 1 UDP (53)
    assert_eq!(summary.stale_endpoints_cleared, 2); // 2 old endpoints pruned
    assert!(summary.foreign_rules_preserved);

    // Verify actual dataplane rules in kernel/mock firewall:
    // DNAT targets the replacement backend 10.42.0.25 and no longer targets the stale 10.42.0.10
    {
        let active_rules = mock.iptables_rules.lock().unwrap();
        assert!(
            active_rules.iter().any(|r| r.contains("10.42.0.25")),
            "dataplane must contain DNAT rules targeting replacement endpoint 10.42.0.25"
        );
        assert!(
            !active_rules.iter().any(|r| r.contains("10.42.0.10")),
            "dataplane must NOT contain any DNAT rules targeting stale endpoint 10.42.0.10"
        );
    }

    // Verify command log demonstrates scoped chain repopulation
    {
        let log = mock.command_log.lock().unwrap();
        assert!(
            log.iter()
                .any(|cmd| cmd.contains("iptables -t nat -F KUBE-SERVICES")),
            "reconciliation must flush owned KUBE-SERVICES chain"
        );
        assert!(
            log.iter().any(|cmd| cmd.contains("10.42.0.25")),
            "reconciliation must program DNAT to replacement endpoint"
        );
    }

    // 4. Verify that ClusterIP and NodePort traffic recovers and routes to the replacement endpoint
    service.check_startup_readiness().unwrap();
    let recovered_report = service.verify_dataplane(&prober).await.unwrap();
    assert!(recovered_report.all_passed());
    assert!(service.is_dataplane_ready());

    let table = service.routing_table().read().await;

    // ClusterIP TCP probe reaches new backend 10.42.0.25
    let recovered_tcp = prober
        .probe_route(&table, "10.43.0.50", 80, Protocol::Tcp)
        .unwrap();
    assert!(recovered_tcp.success);
    assert_eq!(recovered_tcp.reached_endpoint.unwrap().ip, "10.42.0.25");

    // ClusterIP UDP probe reaches new backend 10.42.0.25
    let recovered_udp = prober
        .probe_route(&table, "10.43.0.50", 53, Protocol::Udp)
        .unwrap();
    assert!(recovered_udp.success);
    assert_eq!(recovered_udp.reached_endpoint.unwrap().ip, "10.42.0.25");

    // NodePort TCP probe reaches new backend 10.42.0.25
    let nodeport_tcp = prober
        .probe_service_node_port(&table, "default", "api-service", Protocol::Tcp)
        .unwrap();
    assert!(nodeport_tcp.success);
    assert_eq!(nodeport_tcp.reached_endpoint.unwrap().ip, "10.42.0.25");

    // NodePort UDP probe reaches new backend 10.42.0.25
    let nodeport_udp = prober
        .probe_service_node_port(&table, "default", "api-service", Protocol::Udp)
        .unwrap();
    assert!(nodeport_udp.success);
    assert_eq!(nodeport_udp.reached_endpoint.unwrap().ip, "10.42.0.25");

    service.stop();
}

#[tokio::test]
async fn test_unrelated_firewall_and_e15_egress_rules_remain_intact_iptables() {
    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let proc_net = temp.path().join("proc/net");
    fs::create_dir_all(&proc_net).unwrap();
    fs::write(proc_net.join("ip_tables_names"), "filter\nnat\n").unwrap();

    // Host with existing E15 pod egress masquerade rule + foreign host firewall rules
    let mock = Arc::new(MockCommandExecutor::new_iptables_host());

    // Program E15 pod masquerade rule in iptables POSTROUTING
    mock.run(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            DEFAULT_POD_CIDR,
            "!",
            "-d",
            DEFAULT_POD_CIDR,
            "-m",
            "comment",
            "--comment",
            MASQUERADE_COMMENT,
            "-j",
            "MASQUERADE",
        ],
    )
    .unwrap();

    // Program unrelated foreign firewall rule (e.g. host SSH or custom bridge)
    mock.run(
        "iptables",
        &[
            "-t", "filter", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT",
        ],
    )
    .unwrap();

    let before_snapshot = FirewallSnapshot::capture(mock.as_ref(), ProxyMode::IpTables);
    assert!(before_snapshot.e15_masquerade_present);
    assert!(
        before_snapshot
            .foreign_iptables_rules
            .iter()
            .any(|r| r.contains(MASQUERADE_COMMENT))
    );
    let initial_unrelated_count = mock.unrelated_nat_rules_count();

    // Initialize kube-proxy
    let options = KubeProxyOptions::new(kubeconfig, true, ProxyMode::IpTables);
    let executor: Arc<dyn CommandExecutor> = mock.clone();
    let mut service = ProxyService::new(options)
        .with_executor(executor)
        .with_sys_root(temp.path().to_path_buf());

    // Cycle through multiple startups, restarts, and reconciliations
    for _ in 0..3 {
        service.check_prerequisites().unwrap();
        service.start().unwrap();
        service.check_startup_readiness().unwrap();

        service
            .apply_service(ServiceDefinition::new(
                "default",
                "app",
                ServiceType::ClusterIP,
                Some("10.43.0.100".to_string()),
                vec![ServicePort {
                    name: Some("http".to_string()),
                    protocol: Protocol::Tcp,
                    port: 80,
                    target_port: 8080,
                    node_port: None,
                }],
            ))
            .await;

        service
            .apply_endpoint_slice(EndpointSliceDefinition::new(
                "default",
                "app-slice",
                "app",
                vec![EndpointPort {
                    name: Some("http".to_string()),
                    port: Some(8080),
                    protocol: Some(Protocol::Tcp),
                }],
                vec![EndpointItem::new(
                    vec!["10.42.0.50".to_string()],
                    true,
                    None,
                )],
            ))
            .await;

        let reconciler = DataplaneReconciler::new();
        let summary = service
            .reconcile_dataplane(&reconciler, None)
            .await
            .unwrap();
        assert!(summary.foreign_rules_preserved);

        let after_snapshot = service.capture_firewall_snapshot();
        before_snapshot.verify_preserved(&after_snapshot).unwrap();

        // Restart proxy
        service.restart().unwrap();
    }

    // Verify after all restarts: E15 egress rules and unrelated firewall rules remain 100% intact!
    let final_snapshot = service.capture_firewall_snapshot();
    assert!(final_snapshot.e15_masquerade_present);
    assert_eq!(mock.unrelated_nat_rules_count(), initial_unrelated_count);
    before_snapshot.verify_preserved(&final_snapshot).unwrap();

    service.stop();
}

#[tokio::test]
async fn test_unrelated_firewall_and_e15_egress_rules_remain_intact_nftables() {
    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    // Nftables host with existing E15 table "kubesolo-masq" and foreign table "ip nat"
    let mock = Arc::new(MockCommandExecutor::new_nftables_host());

    // Create E15 pod masquerade table
    mock.run("nft", &["add", "table", "ip", "kubesolo-masq"])
        .unwrap();

    let before_snapshot = FirewallSnapshot::capture(mock.as_ref(), ProxyMode::Nftables);
    assert!(before_snapshot.e15_masquerade_present);
    assert!(before_snapshot.foreign_nft_tables.contains("kubesolo-masq"));
    let initial_unrelated_count = mock.unrelated_nat_rules_count();

    // Initialize kube-proxy in nftables mode
    let options = KubeProxyOptions::new(kubeconfig, true, ProxyMode::Nftables);
    let executor: Arc<dyn CommandExecutor> = mock.clone();
    let mut service = ProxyService::new(options)
        .with_executor(executor)
        .with_sys_root(temp.path().to_path_buf());

    // Cycle through multiple startups, restarts, and reconciliations
    for _ in 0..3 {
        // Prerequisites must NOT perform blanket flush of table ip nat!
        service.check_prerequisites().unwrap();
        service.start().unwrap();
        service.check_startup_readiness().unwrap();

        let after_startup_snapshot = service.capture_firewall_snapshot();
        assert!(
            after_startup_snapshot.e15_masquerade_present,
            "startup must not flush E15 masquerade table kubesolo-masq"
        );
        before_snapshot
            .verify_preserved(&after_startup_snapshot)
            .unwrap();

        // Perform restart
        service.restart().unwrap();
    }

    // Verify after all restarts: E15 table and unrelated NAT rules remain completely untouched
    let final_snapshot = service.capture_firewall_snapshot();
    assert!(final_snapshot.e15_masquerade_present);
    assert_eq!(mock.unrelated_nat_rules_count(), initial_unrelated_count);
    before_snapshot.verify_preserved(&final_snapshot).unwrap();

    service.stop();
}

#[tokio::test]
async fn test_repeated_backend_churn_and_scaling_reconciliation() {
    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let proc_net = temp.path().join("proc/net");
    fs::create_dir_all(&proc_net).unwrap();
    fs::write(proc_net.join("ip_tables_names"), "filter\nnat\n").unwrap();

    let mock = Arc::new(MockCommandExecutor::new_iptables_host());
    let options = KubeProxyOptions::new(kubeconfig, true, ProxyMode::IpTables);
    let executor: Arc<dyn CommandExecutor> = mock.clone();

    let service = ProxyService::new(options)
        .with_executor(executor)
        .with_sys_root(temp.path().to_path_buf());
    service.start().unwrap();
    service.check_startup_readiness().unwrap();

    let prober = DataplaneProber::new();
    let reconciler = DataplaneReconciler::new();

    service
        .apply_service(ServiceDefinition::new(
            "default",
            "scale-svc",
            ServiceType::ClusterIP,
            Some("10.43.0.200".to_string()),
            vec![ServicePort {
                name: Some("http".to_string()),
                protocol: Protocol::Tcp,
                port: 80,
                target_port: 8080,
                node_port: None,
            }],
        ))
        .await;

    // Churn 1: Initial single replica (10.42.0.1)
    service
        .apply_endpoint_slice(EndpointSliceDefinition::new(
            "default",
            "slice-1",
            "scale-svc",
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(8080),
                protocol: Some(Protocol::Tcp),
            }],
            vec![EndpointItem::new(vec!["10.42.0.1".to_string()], true, None)],
        ))
        .await;

    service.verify_dataplane(&prober).await.unwrap();
    let summary1 = service
        .reconcile_dataplane(&reconciler, None)
        .await
        .unwrap();
    assert_eq!(summary1.active_endpoints, 1);

    // Churn 2: Scale up to 3 replicas (10.42.0.1, 10.42.0.2, 10.42.0.3)
    let previous_eps = vec!["10.42.0.1:8080".to_string()];
    service
        .apply_endpoint_slice(EndpointSliceDefinition::new(
            "default",
            "slice-1",
            "scale-svc",
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(8080),
                protocol: Some(Protocol::Tcp),
            }],
            vec![
                EndpointItem::new(vec!["10.42.0.1".to_string()], true, None),
                EndpointItem::new(vec!["10.42.0.2".to_string()], true, None),
                EndpointItem::new(vec!["10.42.0.3".to_string()], true, None),
            ],
        ))
        .await;

    service.verify_dataplane(&prober).await.unwrap();
    let summary2 = service
        .reconcile_dataplane(&reconciler, Some(&previous_eps))
        .await
        .unwrap();
    assert_eq!(summary2.active_endpoints, 3);
    assert_eq!(summary2.stale_endpoints_cleared, 0);

    // Churn 3: Rolling update / replacement:
    // 10.42.0.1 and 10.42.0.2 terminated, replaced by 10.42.0.4 and 10.42.0.5
    let previous_eps2 = vec![
        "10.42.0.1:8080".to_string(),
        "10.42.0.2:8080".to_string(),
        "10.42.0.3:8080".to_string(),
    ];
    service
        .apply_endpoint_slice(EndpointSliceDefinition::new(
            "default",
            "slice-1",
            "scale-svc",
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(8080),
                protocol: Some(Protocol::Tcp),
            }],
            vec![
                EndpointItem::new(vec!["10.42.0.3".to_string()], true, None),
                EndpointItem::new(vec!["10.42.0.4".to_string()], true, None),
                EndpointItem::new(vec!["10.42.0.5".to_string()], true, None),
            ],
        ))
        .await;

    service.verify_dataplane(&prober).await.unwrap();
    let summary3 = service
        .reconcile_dataplane(&reconciler, Some(&previous_eps2))
        .await
        .unwrap();
    assert_eq!(summary3.active_endpoints, 3);
    assert_eq!(summary3.stale_endpoints_cleared, 2); // 10.42.0.1 and 10.42.0.2 cleared!

    // Verify routing only resolves to the 3 active endpoints
    let eps = service
        .routing_table()
        .read()
        .await
        .get_ready_endpoints("default", "scale-svc", 80, Protocol::Tcp)
        .unwrap();
    let ips: Vec<&str> = eps.iter().map(|e| e.ip.as_str()).collect();
    assert_eq!(ips, vec!["10.42.0.3", "10.42.0.4", "10.42.0.5"]);
    assert!(!ips.contains(&"10.42.0.1"));
    assert!(!ips.contains(&"10.42.0.2"));

    // Verify dataplane in mock firewall reflects active endpoints and clears stale ones
    {
        let active_rules = mock.iptables_rules.lock().unwrap();
        assert!(active_rules.iter().any(|r| r.contains("10.42.0.3")));
        assert!(active_rules.iter().any(|r| r.contains("10.42.0.4")));
        assert!(active_rules.iter().any(|r| r.contains("10.42.0.5")));
        assert!(!active_rules.iter().any(|r| r.contains("10.42.0.1")));
        assert!(!active_rules.iter().any(|r| r.contains("10.42.0.2")));
    }

    service.stop();
}
