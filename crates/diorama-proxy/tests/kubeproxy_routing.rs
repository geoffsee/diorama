#![allow(clippy::too_many_lines)]

use std::fs;
use std::sync::Arc;

use diorama_network::{CommandExecutor, MockCommandExecutor};
use diorama_proxy::{
    DataplaneProber, DataplaneReconciler, EndpointConditions, EndpointItem, EndpointPort,
    EndpointSliceDefinition, IptablesDataplane, KubeProxyOptions, NftablesDataplane, Protocol,
    ProxyError, ProxyMode, ProxyService, ServiceDefinition, ServicePort, ServiceRoutingTable,
    ServiceType,
};
use tempfile::TempDir;

#[test]
fn test_tcp_and_udp_workload_probes_reach_correct_backends() {
    let mut table = ServiceRoutingTable::new();

    // 1. Setup a TCP Service (web: ClusterIP + NodePort)
    let web_svc = ServiceDefinition::new(
        "tier1-workload",
        "web",
        ServiceType::NodePort,
        Some("10.43.0.100".to_string()),
        vec![ServicePort {
            name: Some("http".to_string()),
            protocol: Protocol::Tcp,
            port: 80,
            target_port: 8080,
            node_port: Some(30080),
        }],
    );
    table.apply_service(web_svc);

    let web_slice = EndpointSliceDefinition::new(
        "tier1-workload",
        "web-slice-1",
        "web",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(8080),
            protocol: Some(Protocol::Tcp),
        }],
        vec![
            EndpointItem::new(
                vec!["10.42.0.10".to_string()],
                true,
                Some("node-1".to_string()),
            ),
            EndpointItem::new(
                vec!["10.42.0.11".to_string()],
                true,
                Some("node-1".to_string()),
            ),
        ],
    );
    table.apply_endpoint_slice(web_slice);

    // 2. Setup a UDP Service (dns: ClusterIP + NodePort)
    let dns_svc = ServiceDefinition::new(
        "kube-system",
        "kube-dns",
        ServiceType::NodePort,
        Some("10.43.0.10".to_string()),
        vec![ServicePort {
            name: Some("dns".to_string()),
            protocol: Protocol::Udp,
            port: 53,
            target_port: 53,
            node_port: Some(30053),
        }],
    );
    table.apply_service(dns_svc);

    let dns_slice = EndpointSliceDefinition::new(
        "kube-system",
        "kube-dns-slice-1",
        "kube-dns",
        vec![EndpointPort {
            name: Some("dns".to_string()),
            port: Some(53),
            protocol: Some(Protocol::Udp),
        }],
        vec![
            EndpointItem::new(
                vec!["10.42.0.20".to_string()],
                true,
                Some("node-1".to_string()),
            ),
            EndpointItem::new(
                vec!["10.42.0.21".to_string()],
                true,
                Some("node-1".to_string()),
            ),
        ],
    );
    table.apply_endpoint_slice(dns_slice);

    let prober = DataplaneProber::new();

    // Verify TCP ClusterIP probe
    let tcp_res = prober
        .probe_service_cluster_ip(&table, "tier1-workload", "web", Protocol::Tcp)
        .unwrap();
    assert!(tcp_res.success);
    let target = tcp_res.reached_endpoint.unwrap();
    assert_eq!(target.port, 8080);
    assert_eq!(target.protocol, Protocol::Tcp);
    assert!(target.ip == "10.42.0.10" || target.ip == "10.42.0.11");

    // Verify TCP NodePort probe
    let tcp_np_res = prober
        .probe_service_node_port(&table, "tier1-workload", "web", Protocol::Tcp)
        .unwrap();
    assert!(tcp_np_res.success);
    let target_np = tcp_np_res.reached_endpoint.unwrap();
    assert_eq!(target_np.port, 8080);
    assert_eq!(target_np.protocol, Protocol::Tcp);

    // Verify UDP ClusterIP probe
    let udp_res = prober
        .probe_service_cluster_ip(&table, "kube-system", "kube-dns", Protocol::Udp)
        .unwrap();
    assert!(udp_res.success);
    let target_udp = udp_res.reached_endpoint.unwrap();
    assert_eq!(target_udp.port, 53);
    assert_eq!(target_udp.protocol, Protocol::Udp);
    assert!(target_udp.ip == "10.42.0.20" || target_udp.ip == "10.42.0.21");

    // Verify UDP NodePort probe
    let udp_np_res = prober
        .probe_service_node_port(&table, "kube-system", "kube-dns", Protocol::Udp)
        .unwrap();
    assert!(udp_np_res.success);
    let target_udp_np = udp_np_res.reached_endpoint.unwrap();
    assert_eq!(target_udp_np.port, 53);
    assert_eq!(target_udp_np.protocol, Protocol::Udp);

    // Verify protocol isolation: TCP probe against UDP service fails
    let mismatch_res =
        prober.probe_service_cluster_ip(&table, "kube-system", "kube-dns", Protocol::Tcp);
    assert!(mismatch_res.is_err());

    // Verify protocol isolation: UDP probe against TCP service fails
    let mismatch_res2 =
        prober.probe_service_cluster_ip(&table, "tier1-workload", "web", Protocol::Udp);
    assert!(mismatch_res2.is_err());
}

#[test]
fn test_endpoint_additions_and_removals_dynamically_update_traffic_routing() {
    let mut table = ServiceRoutingTable::new();

    let svc = ServiceDefinition::new(
        "default",
        "api-svc",
        ServiceType::ClusterIP,
        Some("10.43.10.50".to_string()),
        vec![ServicePort {
            name: Some("http".to_string()),
            protocol: Protocol::Tcp,
            port: 80,
            target_port: 80,
            node_port: None,
        }],
    );
    table.apply_service(svc);

    // 1. Initial EndpointSlice with single endpoint
    let initial_slice = EndpointSliceDefinition::new(
        "default",
        "api-svc-slice",
        "api-svc",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Tcp),
        }],
        vec![EndpointItem::new(
            vec!["10.42.1.10".to_string()],
            true,
            None,
        )],
    );
    table.apply_endpoint_slice(initial_slice);

    let prober = DataplaneProber::new();

    // Must route strictly to 10.42.1.10
    for _ in 0..5 {
        let res = prober
            .probe_route(&table, "10.43.10.50", 80, Protocol::Tcp)
            .unwrap();
        assert_eq!(res.reached_endpoint.unwrap().ip, "10.42.1.10");
    }

    // 2. Endpoint Addition: scale out to 3 endpoints
    let updated_slice = EndpointSliceDefinition::new(
        "default",
        "api-svc-slice",
        "api-svc",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Tcp),
        }],
        vec![
            EndpointItem::new(vec!["10.42.1.10".to_string()], true, None),
            EndpointItem::new(vec!["10.42.1.11".to_string()], true, None),
            EndpointItem::new(vec!["10.42.1.12".to_string()], true, None),
        ],
    );
    table.apply_endpoint_slice(updated_slice);

    // Verify that traffic now distributes across all 3 endpoints
    let mut seen_ips = std::collections::BTreeSet::new();
    for _ in 0..12 {
        let res = prober
            .probe_route(&table, "10.43.10.50", 80, Protocol::Tcp)
            .unwrap();
        seen_ips.insert(res.reached_endpoint.unwrap().ip);
    }
    assert_eq!(seen_ips.len(), 3);
    assert!(seen_ips.contains("10.42.1.10"));
    assert!(seen_ips.contains("10.42.1.11"));
    assert!(seen_ips.contains("10.42.1.12"));

    // 3. Endpoint Removal: scale down, remove 10.42.1.10
    let scaled_down_slice = EndpointSliceDefinition::new(
        "default",
        "api-svc-slice",
        "api-svc",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Tcp),
        }],
        vec![
            EndpointItem::new(vec!["10.42.1.11".to_string()], true, None),
            EndpointItem::new(vec!["10.42.1.12".to_string()], true, None),
        ],
    );
    table.apply_endpoint_slice(scaled_down_slice);

    seen_ips.clear();
    for _ in 0..10 {
        let res = prober
            .probe_route(&table, "10.43.10.50", 80, Protocol::Tcp)
            .unwrap();
        let ip = res.reached_endpoint.unwrap().ip;
        assert_ne!(
            ip, "10.42.1.10",
            "removed endpoint must not receive traffic"
        );
        seen_ips.insert(ip);
    }
    assert_eq!(seen_ips.len(), 2);
    assert!(seen_ips.contains("10.42.1.11"));
    assert!(seen_ips.contains("10.42.1.12"));

    // 4. Endpoint Unreadiness: mark 10.42.1.12 as not ready
    let unready_slice = EndpointSliceDefinition::new(
        "default",
        "api-svc-slice",
        "api-svc",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Tcp),
        }],
        vec![
            EndpointItem::new(vec!["10.42.1.11".to_string()], true, None),
            EndpointItem::new(vec!["10.42.1.12".to_string()], false, None), // ready = false
        ],
    );
    table.apply_endpoint_slice(unready_slice);

    for _ in 0..5 {
        let res = prober
            .probe_route(&table, "10.43.10.50", 80, Protocol::Tcp)
            .unwrap();
        assert_eq!(
            res.reached_endpoint.unwrap().ip,
            "10.42.1.11",
            "unready endpoint must be excluded from traffic routing"
        );
    }

    // 5. Total endpoint outage: all endpoints unready
    let all_unready_slice = EndpointSliceDefinition::new(
        "default",
        "api-svc-slice",
        "api-svc",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Tcp),
        }],
        vec![
            EndpointItem::new(vec!["10.42.1.11".to_string()], false, None),
            EndpointItem::new(vec!["10.42.1.12".to_string()], false, None),
        ],
    );
    table.apply_endpoint_slice(all_unready_slice);

    let err = prober
        .probe_route(&table, "10.43.10.50", 80, Protocol::Tcp)
        .unwrap_err();
    match err {
        ProxyError::DataplaneProbeFailed { service, reason } => {
            assert!(service.contains("10.43.10.50:80/TCP"));
            assert!(reason.contains("no ready endpoints"));
        },
        other => panic!("expected DataplaneProbeFailed error, got: {other:?}"),
    }
}

#[test]
fn test_iptables_and_nftables_dataplane_rule_synthesis() {
    let mut table = ServiceRoutingTable::new();

    let svc = ServiceDefinition::new(
        "tier1-workload",
        "web-clusterip",
        ServiceType::NodePort,
        Some("10.43.0.100".to_string()),
        vec![ServicePort {
            name: Some("http".to_string()),
            protocol: Protocol::Tcp,
            port: 80,
            target_port: 80,
            node_port: Some(30080),
        }],
    );
    table.apply_service(svc);

    let slice = EndpointSliceDefinition::new(
        "tier1-workload",
        "web-slice",
        "web-clusterip",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(80),
            protocol: Some(Protocol::Tcp),
        }],
        vec![
            EndpointItem::new(vec!["10.42.0.10".to_string()], true, None),
            EndpointItem::new(vec!["10.42.0.11".to_string()], true, None),
        ],
    );
    table.apply_endpoint_slice(slice);

    // 1. Test Iptables rule generation
    let iptables_rules = IptablesDataplane::generate_rules(&table);
    assert_ne!(
        iptables_rules,
        <[diorama_proxy::IptablesRule; 0]>::default()
    );

    let has_clusterip_rule = iptables_rules.iter().any(|r| {
        r.chain == "KUBE-SERVICES"
            && r.rule
                .contains("-d 10.43.0.100/32 -p tcp -m tcp --dport 80")
    });
    assert!(has_clusterip_rule, "iptables rules must route ClusterIP");

    let has_nodeport_rule = iptables_rules
        .iter()
        .any(|r| r.chain == "KUBE-NODEPORTS" && r.rule.contains("-p tcp -m tcp --dport 30080"));
    assert!(has_nodeport_rule, "iptables rules must route NodePort");

    let has_dnat_rule = iptables_rules.iter().any(|r| {
        r.rule.contains("DNAT --to-destination 10.42.0.10:80")
            || r.rule.contains("DNAT --to-destination 10.42.0.11:80")
    });
    assert!(has_dnat_rule, "iptables rules must DNAT to endpoints");

    // 2. Test Nftables rule generation
    let nftables_rules = NftablesDataplane::generate_rules(&table);
    assert_ne!(
        nftables_rules,
        <[diorama_proxy::NftablesRule; 0]>::default()
    );

    let has_nft_clusterip = nftables_rules.iter().any(|r| {
        r.chain == "services"
            && r.statement
                .contains("ip daddr 10.43.0.100 tcp dport 80 dnat")
    });
    assert!(has_nft_clusterip, "nftables rules must route ClusterIP");

    let has_nft_nodeport = nftables_rules
        .iter()
        .any(|r| r.chain == "nodeports" && r.statement.contains("tcp dport 30080 dnat"));
    assert!(has_nft_nodeport, "nftables rules must route NodePort");
}

#[tokio::test]
async fn test_logs_and_readiness_distinguish_component_startup_from_dataplane_probes() {
    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let proc_net = temp.path().join("proc/net");
    fs::create_dir_all(&proc_net).unwrap();
    fs::write(proc_net.join("ip_tables_names"), "filter\nnat\n").unwrap();

    let mock = MockCommandExecutor::new_iptables_host();
    let options = KubeProxyOptions::new(kubeconfig, true, ProxyMode::IpTables);

    let mut service = ProxyService::new(options)
        .with_executor(Arc::new(mock))
        .with_sys_root(temp.path().to_path_buf());

    assert!(service.check_prerequisites().is_ok());
    assert!(service.start().is_ok());
    assert!(service.is_running());

    // 1. Component startup readiness
    // At this stage, component process is running and SNAT is established,
    // but dataplane probes have not run yet.
    let startup_health = service.check_startup_readiness().unwrap();
    assert!(startup_health.is_healthy);
    assert!(startup_health.startup_ready);
    assert!(!startup_health.dataplane_ready);
    assert!(service.is_ready());
    assert!(!service.is_dataplane_ready());

    let readiness_report = service.check_readiness().unwrap();
    assert!(readiness_report.startup_ready);
    assert!(!readiness_report.dataplane_ready);
    assert_eq!(
        readiness_report.details.get("dataplane_status").unwrap(),
        "dataplane probes not yet verified"
    );

    // 2. Configure Service and EndpointSlice in routing table
    {
        let mut table = service.routing_table().write().await;
        table.apply_service(ServiceDefinition::new(
            "tier1-workload",
            "web-clusterip",
            ServiceType::ClusterIP,
            Some("10.43.0.100".to_string()),
            vec![ServicePort {
                name: Some("http".to_string()),
                protocol: Protocol::Tcp,
                port: 80,
                target_port: 80,
                node_port: None,
            }],
        ));
        table.apply_endpoint_slice(EndpointSliceDefinition::new(
            "tier1-workload",
            "web-slice",
            "web-clusterip",
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(80),
                protocol: Some(Protocol::Tcp),
            }],
            vec![EndpointItem::new(
                vec!["10.42.0.10".to_string()],
                true,
                None,
            )],
        ));
    }

    // 3. Execute dataplane verification
    let prober = DataplaneProber::new();
    let dp_report = service.verify_dataplane(&prober).await.unwrap();
    assert!(dp_report.all_passed());
    assert!(dp_report.tcp_clusterip_probes_passed);
    assert!(service.is_dataplane_ready());

    // Now readiness clearly indicates BOTH component startup and dataplane probe success
    let full_readiness = service.check_readiness().unwrap();
    assert!(full_readiness.startup_ready);
    assert!(full_readiness.dataplane_ready);
    assert_eq!(
        full_readiness.details.get("dataplane_status").unwrap(),
        "dataplane probes verified"
    );

    // 4. Test failure case: If all endpoints become unready, dataplane probes fail
    // while component startup remains intact!
    {
        let mut table = service.routing_table().write().await;
        table.apply_endpoint_slice(EndpointSliceDefinition::new(
            "tier1-workload",
            "web-slice",
            "web-clusterip",
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(80),
                protocol: Some(Protocol::Tcp),
            }],
            vec![EndpointItem::new(
                vec!["10.42.0.10".to_string()],
                false,
                None,
            )], // unready
        ));
    }

    let err = service.verify_dataplane(&prober).await.unwrap_err();
    match err {
        ProxyError::DataplaneProbeFailed { .. } => {},
        other => panic!("expected DataplaneProbeFailed error, got: {other:?}"),
    }

    // Component startup is still ready, but dataplane is not ready!
    assert!(service.is_ready());
    assert!(!service.is_dataplane_ready());

    let degraded_report = service.check_readiness().unwrap();
    assert!(degraded_report.startup_ready);
    assert!(!degraded_report.dataplane_ready);
    assert_eq!(
        degraded_report.details.get("dataplane_status").unwrap(),
        "dataplane probes not yet verified"
    );

    service.stop();
    assert!(!service.is_running());
    assert!(!service.is_ready());
    assert!(!service.is_dataplane_ready());
}

#[test]
fn test_multi_port_service_routing_selects_correct_named_ports() {
    let mut table = ServiceRoutingTable::new();

    // Service with two TCP ports: http (80 -> 8080) and metrics (9090 -> 9091)
    let multi_svc = ServiceDefinition::new(
        "default",
        "app",
        ServiceType::ClusterIP,
        Some("10.43.0.50".to_string()),
        vec![
            ServicePort {
                name: Some("http".to_string()),
                protocol: Protocol::Tcp,
                port: 80,
                target_port: 8080,
                node_port: None,
            },
            ServicePort {
                name: Some("metrics".to_string()),
                protocol: Protocol::Tcp,
                port: 9090,
                target_port: 9091,
                node_port: None,
            },
        ],
    );
    table.apply_service(multi_svc);

    // EndpointSlice defining ports in reverse order: metrics first, then http
    let slice = EndpointSliceDefinition::new(
        "default",
        "app-slice",
        "app",
        vec![
            EndpointPort {
                name: Some("metrics".to_string()),
                port: Some(9091),
                protocol: Some(Protocol::Tcp),
            },
            EndpointPort {
                name: Some("http".to_string()),
                port: Some(8080),
                protocol: Some(Protocol::Tcp),
            },
        ],
        vec![EndpointItem::new(
            vec!["10.42.0.100".to_string()],
            true,
            Some("node-1".to_string()),
        )],
    );
    table.apply_endpoint_slice(slice);

    // Resolving port 80 (http) should map to 8080, NOT 9091
    let http_targets = table
        .get_ready_endpoints("default", "app", 80, Protocol::Tcp)
        .unwrap();
    assert_eq!(http_targets.len(), 1);
    assert_eq!(http_targets[0].port, 8080);
    assert_eq!(http_targets[0].ip, "10.42.0.100");

    // Resolving port 9090 (metrics) should map to 9091, NOT 8080
    let metrics_targets = table
        .get_ready_endpoints("default", "app", 9090, Protocol::Tcp)
        .unwrap();
    assert_eq!(metrics_targets.len(), 1);
    assert_eq!(metrics_targets[0].port, 9091);
    assert_eq!(metrics_targets[0].ip, "10.42.0.100");
}

#[tokio::test]
async fn test_routing_table_mutation_invalidates_dataplane_ready() {
    let temp = TempDir::new().unwrap();
    let kubeconfig = temp.path().join("admin.kubeconfig");
    fs::write(&kubeconfig, "apiVersion: v1\nkind: Config\n").unwrap();

    let proc_net = temp.path().join("proc/net");
    fs::create_dir_all(&proc_net).unwrap();
    fs::write(proc_net.join("ip_tables_names"), "filter\nnat\n").unwrap();

    let mock = MockCommandExecutor::new_iptables_host();
    let opts = KubeProxyOptions::new(kubeconfig, true, ProxyMode::IpTables);

    let service = ProxyService::new(opts)
        .with_executor(Arc::new(mock))
        .with_sys_root(temp.path().to_path_buf());
    service.start().unwrap();
    service.check_startup_readiness().unwrap();

    // Initially dataplane is not ready
    assert!(!service.is_dataplane_ready());

    // Add service and endpoint slice
    service
        .apply_service(ServiceDefinition::new(
            "default",
            "web",
            ServiceType::ClusterIP,
            Some("10.43.0.10".to_string()),
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
            "web-slice",
            "web",
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(8080),
                protocol: Some(Protocol::Tcp),
            }],
            vec![EndpointItem::new(
                vec!["10.42.0.10".to_string()],
                true,
                None,
            )],
        ))
        .await;

    let prober = DataplaneProber::new();
    let report = service.verify_dataplane(&prober).await.unwrap();
    assert!(report.all_passed());
    assert!(service.is_dataplane_ready());

    // Applying another slice mutates the table and must immediately invalidate dataplane_ready
    service
        .apply_endpoint_slice(EndpointSliceDefinition::new(
            "default",
            "web-slice-2",
            "web",
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(8080),
                protocol: Some(Protocol::Tcp),
            }],
            vec![EndpointItem::new(
                vec!["10.42.0.11".to_string()],
                true,
                None,
            )],
        ))
        .await;

    assert!(
        !service.is_dataplane_ready(),
        "mutation should invalidate dataplane readiness until reverified"
    );

    // Re-verify dataplane
    let report2 = service.verify_dataplane(&prober).await.unwrap();
    assert!(report2.all_passed());
    assert!(service.is_dataplane_ready());

    // Removing an endpoint slice also invalidates dataplane readiness
    let removed = service
        .remove_endpoint_slice("default", "web-slice-2")
        .await;
    assert!(removed.is_some());
    assert!(
        !service.is_dataplane_ready(),
        "removing endpoint slice should invalidate dataplane readiness"
    );

    service.stop();
}

#[test]
fn test_incompatible_slice_ports_are_skipped() {
    let mut table = ServiceRoutingTable::new();

    let svc = ServiceDefinition::new(
        "default",
        "api",
        ServiceType::ClusterIP,
        Some("10.43.0.60".to_string()),
        vec![ServicePort {
            name: Some("http".to_string()),
            protocol: Protocol::Tcp,
            port: 80,
            target_port: 8080,
            node_port: None,
        }],
    );
    table.apply_service(svc);

    // Incompatible slice (only UDP port "dns", no "http" port)
    let incompatible_slice = EndpointSliceDefinition::new(
        "default",
        "api-udp-slice",
        "api",
        vec![EndpointPort {
            name: Some("dns".to_string()),
            port: Some(53),
            protocol: Some(Protocol::Udp),
        }],
        vec![EndpointItem::new(
            vec!["10.42.0.88".to_string()],
            true,
            None,
        )],
    );
    table.apply_endpoint_slice(incompatible_slice);

    // Compatible slice (has TCP port "http")
    let compatible_slice = EndpointSliceDefinition::new(
        "default",
        "api-tcp-slice",
        "api",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(8080),
            protocol: Some(Protocol::Tcp),
        }],
        vec![EndpointItem::new(
            vec!["10.42.0.99".to_string()],
            true,
            None,
        )],
    );
    table.apply_endpoint_slice(compatible_slice);

    let endpoints = table
        .get_ready_endpoints("default", "api", 80, Protocol::Tcp)
        .unwrap();
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].ip, "10.42.0.99");
    assert_eq!(endpoints[0].port, 8080);
}

#[test]
fn test_terminating_endpoints_are_excluded_when_ready_is_none() {
    let terminating_conditions = EndpointConditions {
        ready: None,
        serving: Some(true),
        terminating: Some(true),
    };
    assert!(
        !terminating_conditions.is_ready(),
        "terminating endpoints must be excluded even if serving is true when ready is None"
    );

    let non_terminating_conditions = EndpointConditions {
        ready: None,
        serving: Some(true),
        terminating: Some(false),
    };
    assert!(
        non_terminating_conditions.is_ready(),
        "non-terminating serving endpoints must be ready when ready is None"
    );
}

#[test]
fn test_live_socket_probe_verification() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut table = ServiceRoutingTable::new();
    table.apply_service(ServiceDefinition::new(
        "default",
        "live-test",
        ServiceType::ClusterIP,
        Some("127.0.0.1".to_string()),
        vec![ServicePort {
            name: Some("http".to_string()),
            protocol: Protocol::Tcp,
            port,
            target_port: port,
            node_port: None,
        }],
    ));

    table.apply_endpoint_slice(EndpointSliceDefinition::new(
        "default",
        "live-test-slice",
        "live-test",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(port),
            protocol: Some(Protocol::Tcp),
        }],
        vec![EndpointItem::new(vec!["127.0.0.1".to_string()], true, None)],
    ));

    let prober = DataplaneProber::new_live(std::time::Duration::from_millis(500));
    let result = prober
        .probe_route(&table, "127.0.0.1", port, Protocol::Tcp)
        .unwrap();
    assert!(result.success);
    assert_eq!(result.reached_endpoint.unwrap().port, port);

    // Drop listener so subsequent live probe fails
    drop(listener);

    let err = prober
        .probe_route(&table, "127.0.0.1", port, Protocol::Tcp)
        .unwrap_err();
    match err {
        ProxyError::DataplaneProbeFailed { reason, .. } => {
            assert!(
                reason.contains("TCP connect to backend failed"),
                "expected TCP connect failure reason, got: {reason}"
            );
        },
        other => panic!("expected DataplaneProbeFailed, got: {other:?}"),
    }
}

#[test]
fn test_endpoint_slice_protocol_defaults_to_tcp() {
    let mut table = ServiceRoutingTable::new();

    // TCP Service
    table.apply_service(ServiceDefinition::new(
        "default",
        "web-tcp",
        ServiceType::ClusterIP,
        Some("10.43.0.70".to_string()),
        vec![ServicePort {
            name: Some("http".to_string()),
            protocol: Protocol::Tcp,
            port: 80,
            target_port: 8080,
            node_port: None,
        }],
    ));

    // UDP Service
    table.apply_service(ServiceDefinition::new(
        "default",
        "dns-udp",
        ServiceType::ClusterIP,
        Some("10.43.0.71".to_string()),
        vec![ServicePort {
            name: Some("http".to_string()),
            protocol: Protocol::Udp,
            port: 80,
            target_port: 8080,
            node_port: None,
        }],
    ));

    // EndpointSlice with protocol: None (must default to TCP)
    table.apply_endpoint_slice(EndpointSliceDefinition::new(
        "default",
        "slice-no-proto",
        "web-tcp",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(8080),
            protocol: None, // defaults to TCP
        }],
        vec![EndpointItem::new(
            vec!["10.42.0.70".to_string()],
            true,
            None,
        )],
    ));

    table.apply_endpoint_slice(EndpointSliceDefinition::new(
        "default",
        "slice-no-proto-udp",
        "dns-udp",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(8080),
            protocol: None, // defaults to TCP, should NOT match UDP service!
        }],
        vec![EndpointItem::new(
            vec!["10.42.0.71".to_string()],
            true,
            None,
        )],
    ));

    // TCP service should successfully match the slice with protocol: None
    let tcp_eps = table
        .get_ready_endpoints("default", "web-tcp", 80, Protocol::Tcp)
        .unwrap();
    assert_eq!(tcp_eps.len(), 1);
    assert_eq!(tcp_eps[0].ip, "10.42.0.70");

    // UDP service should skip the slice because protocol defaults to TCP!
    let udp_res = table.get_ready_endpoints("default", "dns-udp", 80, Protocol::Udp);
    assert!(
        udp_res.is_err(),
        "UDP service must not match slice defaulting to TCP"
    );
}

#[test]
fn test_live_udp_socket_probe_verification() {
    let echo_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = echo_socket.local_addr().unwrap().port();

    let echo_server = std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        if let Ok((len, src)) = echo_socket.recv_from(&mut buf) {
            let _ = echo_socket.send_to(&buf[..len], src);
        }
    });

    let mut table = ServiceRoutingTable::new();
    table.apply_service(ServiceDefinition::new(
        "default",
        "udp-echo",
        ServiceType::ClusterIP,
        Some("127.0.0.1".to_string()),
        vec![ServicePort {
            name: Some("echo".to_string()),
            protocol: Protocol::Udp,
            port,
            target_port: port,
            node_port: None,
        }],
    ));

    table.apply_endpoint_slice(EndpointSliceDefinition::new(
        "default",
        "udp-echo-slice",
        "udp-echo",
        vec![EndpointPort {
            name: Some("echo".to_string()),
            port: Some(port),
            protocol: Some(Protocol::Udp),
        }],
        vec![EndpointItem::new(vec!["127.0.0.1".to_string()], true, None)],
    ));

    let prober = DataplaneProber::new_live(std::time::Duration::from_millis(500));
    let result = prober
        .probe_route(&table, "127.0.0.1", port, Protocol::Udp)
        .unwrap();
    assert!(result.success);
    assert_eq!(result.reached_endpoint.unwrap().port, port);

    echo_server.join().unwrap();
}

#[test]
fn reconcile_installs_clusterip_and_nodeport_rules_and_second_reconcile_verifies() {
    let mut table = ServiceRoutingTable::new();
    table.apply_service(ServiceDefinition::new(
        "default",
        "webnp",
        ServiceType::NodePort,
        Some("10.43.0.3".to_string()),
        vec![ServicePort {
            name: Some("http".to_string()),
            protocol: Protocol::Tcp,
            port: 8080,
            target_port: 8080,
            node_port: Some(30000),
        }],
    ));
    table.apply_endpoint_slice(EndpointSliceDefinition::new(
        "default",
        "webnp-slice",
        "webnp",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(8080),
            protocol: Some(Protocol::Tcp),
        }],
        vec![EndpointItem::new(vec!["10.42.0.5".to_string()], true, None)],
    ));

    let mock = MockCommandExecutor::new_iptables_host();
    // Seed the E15 masquerade rule so foreign-firewall preservation stays green.
    let _ = mock.run(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            "10.42.0.0/16",
            "!",
            "-d",
            "10.42.0.0/16",
            "-m",
            "comment",
            "--comment",
            "kubesolo: pod masquerade",
            "-j",
            "MASQUERADE",
        ],
    );

    let reconciler = DataplaneReconciler::new();
    reconciler
        .reconcile(&table, ProxyMode::IpTables, &mock, None)
        .expect("first reconcile must succeed");

    let save = mock.run("iptables", &["-t", "nat", "-S"]).unwrap();
    assert!(
        save.stdout
            .contains("-d 10.43.0.3/32 -p tcp -m tcp --dport 8080"),
        "KUBE-SERVICES must program ClusterIP DNAT dispatch: {}",
        save.stdout
    );
    assert!(
        save.stdout
            .contains("-A KUBE-NODEPORTS -p tcp -m tcp --dport 30000")
            || save
                .stdout
                .contains("iptables -t nat -A KUBE-NODEPORTS -p tcp -m tcp --dport 30000"),
        "KUBE-NODEPORTS must program NodePort dispatch: {}",
        save.stdout
    );
    assert!(
        save.stdout.contains("KUBE-NODEPORTS")
            && (save.stdout.contains("-j KUBE-NODEPORTS")
                || save.stdout.contains("jump KUBE-NODEPORTS")),
        "KUBE-SERVICES (or an equivalent hook) must jump to KUBE-NODEPORTS so localhost NodePort works: {}",
        save.stdout
    );
    assert!(
        save.stdout.contains("DNAT --to-destination 10.42.0.5:8080")
            || save.stdout.contains("--to-destination 10.42.0.5:8080"),
        "ready endpoint must receive DNAT: {}",
        save.stdout
    );

    reconciler
        .reconcile(&table, ProxyMode::IpTables, &mock, None)
        .expect("second reconcile must still verify");

    let save2 = mock.run("iptables", &["-t", "nat", "-S"]).unwrap();
    assert!(
        save2
            .stdout
            .contains("-d 10.43.0.3/32 -p tcp -m tcp --dport 8080"),
        "ClusterIP rule must survive second reconcile: {}",
        save2.stdout
    );
    assert!(
        save2.stdout.contains("--dport 30000"),
        "NodePort rule must survive second reconcile: {}",
        save2.stdout
    );
    assert!(
        save2.stdout.contains("-j KUBE-NODEPORTS") || save2.stdout.contains("jump KUBE-NODEPORTS"),
        "NodePort jump must survive second reconcile: {}",
        save2.stdout
    );
}

#[test]
fn reconcile_with_leftover_rules_and_full_service_set_still_verifies() {
    let mut table = ServiceRoutingTable::new();
    // Mimic the Alpine guest service set after the probe creates workloads.
    table.apply_service(ServiceDefinition::new(
        "default",
        "kubernetes",
        ServiceType::ClusterIP,
        Some("10.43.0.1".to_string()),
        vec![ServicePort {
            name: Some("https".to_string()),
            protocol: Protocol::Tcp,
            port: 443,
            target_port: 6443,
            node_port: None,
        }],
    ));
    table.apply_endpoint_slice(EndpointSliceDefinition::new(
        "default",
        "kubernetes",
        "kubernetes",
        vec![EndpointPort {
            name: Some("https".to_string()),
            port: Some(6443),
            protocol: Some(Protocol::Tcp),
        }],
        vec![EndpointItem::new(vec!["127.0.0.1".to_string()], true, None)],
    ));
    table.apply_service(ServiceDefinition::new(
        "kube-system",
        "kube-dns",
        ServiceType::ClusterIP,
        Some("10.43.0.10".to_string()),
        vec![
            ServicePort {
                name: Some("dns".to_string()),
                protocol: Protocol::Udp,
                port: 53,
                target_port: 53,
                node_port: None,
            },
            ServicePort {
                name: Some("dns-tcp".to_string()),
                protocol: Protocol::Tcp,
                port: 53,
                target_port: 53,
                node_port: None,
            },
        ],
    ));
    table.apply_endpoint_slice(EndpointSliceDefinition::new(
        "kube-system",
        "kube-dns",
        "kube-dns",
        vec![
            EndpointPort {
                name: Some("dns".to_string()),
                port: Some(53),
                protocol: Some(Protocol::Udp),
            },
            EndpointPort {
                name: Some("dns-tcp".to_string()),
                port: Some(53),
                protocol: Some(Protocol::Tcp),
            },
        ],
        vec![EndpointItem::new(vec!["10.42.0.3".to_string()], true, None)],
    ));
    table.apply_service(ServiceDefinition::new(
        "default",
        "web",
        ServiceType::ClusterIP,
        Some("10.43.0.2".to_string()),
        vec![ServicePort {
            name: Some("http".to_string()),
            protocol: Protocol::Tcp,
            port: 8080,
            target_port: 8080,
            node_port: None,
        }],
    ));
    table.apply_service(ServiceDefinition::new(
        "default",
        "webnp",
        ServiceType::NodePort,
        Some("10.43.0.3".to_string()),
        vec![ServicePort {
            name: Some("http".to_string()),
            protocol: Protocol::Tcp,
            port: 8080,
            target_port: 8080,
            node_port: Some(30000),
        }],
    ));
    table.apply_service(ServiceDefinition::new(
        "default",
        "webhead",
        ServiceType::ClusterIP,
        None,
        vec![ServicePort {
            name: Some("http".to_string()),
            protocol: Protocol::Tcp,
            port: 8080,
            target_port: 8080,
            node_port: None,
        }],
    ));
    table.apply_endpoint_slice(EndpointSliceDefinition::new(
        "default",
        "web-slice",
        "web",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(8080),
            protocol: Some(Protocol::Tcp),
        }],
        vec![EndpointItem::new(vec!["10.42.0.5".to_string()], true, None)],
    ));
    table.apply_endpoint_slice(EndpointSliceDefinition::new(
        "default",
        "webnp-slice",
        "webnp",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(8080),
            protocol: Some(Protocol::Tcp),
        }],
        vec![EndpointItem::new(vec!["10.42.0.5".to_string()], true, None)],
    ));
    table.apply_endpoint_slice(EndpointSliceDefinition::new(
        "default",
        "webhead",
        "webhead",
        vec![EndpointPort {
            name: Some("http".to_string()),
            port: Some(8080),
            protocol: Some(Protocol::Tcp),
        }],
        vec![EndpointItem::new(vec!["10.42.0.5".to_string()], true, None)],
    ));

    let mock = MockCommandExecutor::new_iptables_host();
    let _ = mock.run(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            "10.42.0.0/16",
            "!",
            "-d",
            "10.42.0.0/16",
            "-m",
            "comment",
            "--comment",
            "kubesolo: pod masquerade",
            "-j",
            "MASQUERADE",
        ],
    );

    let reconciler = DataplaneReconciler::new();
    reconciler
        .reconcile(&table, ProxyMode::IpTables, &mock, None)
        .expect("first full-set reconcile");
    // Second reconcile simulates a process restart that inherits leftover nat rules.
    reconciler
        .reconcile(&table, ProxyMode::IpTables, &mock, None)
        .expect("second full-set reconcile with leftover rules must verify");
}

#[test]
fn reconcile_creates_service_chain_for_clusterip_without_ready_endpoints() {
    let mut table = ServiceRoutingTable::new();
    table.apply_service(ServiceDefinition::new(
        "kube-system",
        "kube-dns",
        ServiceType::ClusterIP,
        Some("10.43.0.10".to_string()),
        vec![ServicePort {
            name: Some("dns".to_string()),
            protocol: Protocol::Udp,
            port: 53,
            target_port: 53,
            node_port: None,
        }],
    ));
    // No EndpointSlice on purpose: second-start can list the Service before
    // EndpointSlices are ready or while backends are empty.

    let mock = MockCommandExecutor::new_iptables_host();
    let _ = mock.run(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            "10.42.0.0/16",
            "!",
            "-d",
            "10.42.0.0/16",
            "-m",
            "comment",
            "--comment",
            "kubesolo: pod masquerade",
            "-j",
            "MASQUERADE",
        ],
    );

    let reconciler = DataplaneReconciler::new();
    reconciler
        .reconcile(&table, ProxyMode::IpTables, &mock, None)
        .expect("ClusterIP with no endpoints must still program a jump target chain");

    let save = mock.run("iptables", &["-t", "nat", "-S"]).unwrap();
    assert!(
        save.stdout
            .contains("-d 10.43.0.10/32 -p udp -m udp --dport 53"),
        "ClusterIP jump must be installed: {}",
        save.stdout
    );
    assert!(
        save.stdout.contains("-N KUBE-SVC-") || save.stdout.contains("KUBE-SVC-"),
        "KUBE-SVC chain for the ClusterIP jump must exist: {}",
        save.stdout
    );

    // A second reconcile with leftover rules must keep verifying.
    reconciler
        .reconcile(&table, ProxyMode::IpTables, &mock, None)
        .expect("second reconcile without endpoints must still verify");
}
