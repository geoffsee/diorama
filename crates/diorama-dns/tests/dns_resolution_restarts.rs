use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverConfig, ApiserverService, KubernetesApiClient, KubernetesStorage,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_dns::{
    COREDNS_NAMESPACE, CoreDnsConfig, CoreDnsService, DnsError, DnsProber, DnsProtocol,
    DnsRecordType, DnsResolutionProbe, LocalDnsServer, ProbeTransport,
};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use serde_json::json;

fn setup_test_cluster(dir: &TempDir) -> (ApiserverService, KubernetesApiClient) {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");

    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_service = ApiserverService::new(apiserver_config, storage);
    let client = apiserver_service.admin_client();

    (apiserver_service, client)
}

#[tokio::test]
async fn test_udp_and_tcp_same_namespace_resolution() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    // Setup namespace tier5-a
    client.create_namespace("tier5-a").await.unwrap();

    // Create ClusterIP Service `web` in tier5-a
    let svc_ip: Ipv4Addr = "10.43.10.20".parse().unwrap();
    let service_val = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "web",
            "namespace": "tier5-a"
        },
        "spec": {
            "type": "ClusterIP",
            "clusterIP": svc_ip.to_string(),
            "ports": [{
                "name": "http",
                "port": 80,
                "protocol": "TCP"
            }]
        }
    });
    client.create_service("tier5-a", service_val).await.unwrap();

    let config = CoreDnsConfig::new();

    // 1. Synthetic resolution probe (verifies API semantics)
    let synthetic_prober = DnsProber::new(ProbeTransport::Synthetic {
        client: Arc::new(client.clone()),
        config,
    });

    let probe_udp = DnsResolutionProbe::same_namespace("web", "tier5-a", svc_ip, DnsProtocol::Udp);
    let result_udp = synthetic_prober.execute_probe(&probe_udp).await.unwrap();
    assert!(result_udp.success, "Synthetic UDP probe must succeed");
    assert_eq!(result_udp.resolved_ips, vec![svc_ip]);

    let probe_tcp = DnsResolutionProbe::same_namespace("web", "tier5-a", svc_ip, DnsProtocol::Tcp);
    let result_tcp = synthetic_prober.execute_probe(&probe_tcp).await.unwrap();
    assert!(result_tcp.success, "Synthetic TCP probe must succeed");
    assert_eq!(result_tcp.resolved_ips, vec![svc_ip]);

    // 2. Live network socket I/O probe against LocalDnsServer
    let server = LocalDnsServer::start_loopback().await.unwrap();
    server
        .add_a_record("web.tier5-a.svc.cluster.local", svc_ip)
        .await;

    let live_prober = DnsProber::new(ProbeTransport::Live {
        server_addr: server.local_addr(),
        timeout: Duration::from_secs(2),
    });

    let live_udp = live_prober.execute_probe(&probe_udp).await.unwrap();
    assert!(
        live_udp.success,
        "Live UDP same-namespace probe failed: {}",
        live_udp.details
    );
    assert_eq!(live_udp.resolved_ips, vec![svc_ip]);

    let live_tcp = live_prober.execute_probe(&probe_tcp).await.unwrap();
    assert!(
        live_tcp.success,
        "Live TCP same-namespace probe failed: {}",
        live_tcp.details
    );
    assert_eq!(live_tcp.resolved_ips, vec![svc_ip]);
}

#[tokio::test]
async fn test_udp_and_tcp_cross_namespace_resolution() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    // Setup namespaces tier5-a and tier5-b (matching upstream 05-dns-lb tier test)
    client.create_namespace("tier5-a").await.unwrap();
    client.create_namespace("tier5-b").await.unwrap();

    let svc_ip: Ipv4Addr = "10.43.20.30".parse().unwrap();
    let service_val = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "web",
            "namespace": "tier5-a"
        },
        "spec": {
            "type": "ClusterIP",
            "clusterIP": svc_ip.to_string(),
            "ports": [{
                "name": "http",
                "port": 80,
                "protocol": "TCP"
            }]
        }
    });
    client.create_service("tier5-a", service_val).await.unwrap();

    let config = CoreDnsConfig::new();

    // 1. Synthetic probe from tier5-b querying web.tier5-a
    let synthetic_prober = DnsProber::new(ProbeTransport::Synthetic {
        client: Arc::new(client.clone()),
        config,
    });

    let probe_udp =
        DnsResolutionProbe::cross_namespace("web", "tier5-a", "tier5-b", svc_ip, DnsProtocol::Udp);
    let res_udp = synthetic_prober.execute_probe(&probe_udp).await.unwrap();
    assert!(
        res_udp.success,
        "Synthetic cross-namespace UDP probe failed"
    );
    assert_eq!(res_udp.resolved_ips, vec![svc_ip]);

    let probe_tcp =
        DnsResolutionProbe::cross_namespace("web", "tier5-a", "tier5-b", svc_ip, DnsProtocol::Tcp);
    let res_tcp = synthetic_prober.execute_probe(&probe_tcp).await.unwrap();
    assert!(
        res_tcp.success,
        "Synthetic cross-namespace TCP probe failed"
    );
    assert_eq!(res_tcp.resolved_ips, vec![svc_ip]);

    // 2. Live network socket probe
    let server = LocalDnsServer::start_loopback().await.unwrap();
    server
        .add_a_record("web.tier5-a.svc.cluster.local", svc_ip)
        .await;

    let live_prober = DnsProber::new(ProbeTransport::Live {
        server_addr: server.local_addr(),
        timeout: Duration::from_secs(2),
    });

    let live_udp = live_prober.execute_probe(&probe_udp).await.unwrap();
    assert!(live_udp.success, "Live cross-namespace UDP probe failed");
    assert_eq!(live_udp.resolved_ips, vec![svc_ip]);

    let live_tcp = live_prober.execute_probe(&probe_tcp).await.unwrap();
    assert!(live_tcp.success, "Live cross-namespace TCP probe failed");
    assert_eq!(live_tcp.resolved_ips, vec![svc_ip]);
}

#[tokio::test]
async fn test_udp_and_tcp_external_name_resolution() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    client.create_namespace("tier5-a").await.unwrap();

    // Create Service type: ExternalName
    let external_cname = "database.provider.internal";
    let service_val = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "db-external",
            "namespace": "tier5-a"
        },
        "spec": {
            "type": "ExternalName",
            "externalName": external_cname
        }
    });
    client.create_service("tier5-a", service_val).await.unwrap();

    let config = CoreDnsConfig::new();

    // Synthetic probe
    let synthetic_prober = DnsProber::new(ProbeTransport::Synthetic {
        client: Arc::new(client.clone()),
        config,
    });

    let probe_udp = DnsResolutionProbe::external_name(
        "db-external",
        "tier5-a",
        external_cname,
        DnsProtocol::Udp,
    );
    let res_udp = synthetic_prober.execute_probe(&probe_udp).await.unwrap();
    assert!(res_udp.success, "Synthetic ExternalName UDP probe failed");
    assert_eq!(res_udp.resolved_cnames, vec![external_cname]);

    let probe_tcp = DnsResolutionProbe::external_name(
        "db-external",
        "tier5-a",
        external_cname,
        DnsProtocol::Tcp,
    );
    let res_tcp = synthetic_prober.execute_probe(&probe_tcp).await.unwrap();
    assert!(res_tcp.success, "Synthetic ExternalName TCP probe failed");
    assert_eq!(res_tcp.resolved_cnames, vec![external_cname]);

    // Live socket probe
    let server = LocalDnsServer::start_loopback().await.unwrap();
    server
        .add_cname_record("db-external.tier5-a.svc.cluster.local", external_cname)
        .await;

    let live_prober = DnsProber::new(ProbeTransport::Live {
        server_addr: server.local_addr(),
        timeout: Duration::from_secs(2),
    });

    let live_udp = live_prober.execute_probe(&probe_udp).await.unwrap();
    assert!(
        live_udp.success,
        "Live ExternalName UDP probe failed: {}",
        live_udp.details
    );
    assert_eq!(live_udp.resolved_cnames, vec![external_cname]);

    let live_tcp = live_prober.execute_probe(&probe_tcp).await.unwrap();
    assert!(
        live_tcp.success,
        "Live ExternalName TCP probe failed: {}",
        live_tcp.details
    );
    assert_eq!(live_tcp.resolved_cnames, vec![external_cname]);
}

#[tokio::test]
async fn test_offline_egress_denied_with_local_external_dependency() {
    // In offline environments where external egress is blocked,
    // external dependencies must be provided locally.
    let local_upstream = LocalDnsServer::start_loopback().await.unwrap();
    let upstream_addr = local_upstream.local_addr();

    // Register local external record on the upstream dependency
    let external_ip: Ipv4Addr = "192.0.2.53".parse().unwrap();
    local_upstream
        .add_a_record("api.internal.local", external_ip)
        .await;

    // Configure DNS to forward upstream queries to local external dependency
    let config = CoreDnsConfig::new()
        .with_upstream_resolvers(vec![upstream_addr.to_string()])
        .with_container_mode(false);

    // Verify synthetic resolution recognizes the locally provided upstream resolver
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let prober = DnsProber::new(ProbeTransport::Synthetic {
        client: Arc::new(client),
        config,
    });

    let probe_udp =
        DnsResolutionProbe::upstream("api.internal.local", external_ip, DnsProtocol::Udp);
    let res_udp = prober.execute_probe(&probe_udp).await.unwrap();
    assert!(
        res_udp.success,
        "Offline local external dependency UDP probe failed"
    );

    let probe_tcp =
        DnsResolutionProbe::upstream("api.internal.local", external_ip, DnsProtocol::Tcp);
    let res_tcp = prober.execute_probe(&probe_tcp).await.unwrap();
    assert!(
        res_tcp.success,
        "Offline local external dependency TCP probe failed"
    );

    // Verify live I/O against the local upstream fixture over UDP and TCP
    let live_prober = DnsProber::new(ProbeTransport::Live {
        server_addr: upstream_addr,
        timeout: Duration::from_secs(2),
    });

    let live_res_udp = live_prober.execute_probe(&probe_udp).await.unwrap();
    assert!(
        live_res_udp.success,
        "Live offline UDP probe failed: {}",
        live_res_udp.details
    );
    assert_eq!(live_res_udp.resolved_ips, vec![external_ip]);

    let live_res_tcp = live_prober.execute_probe(&probe_tcp).await.unwrap();
    assert!(
        live_res_tcp.success,
        "Live offline TCP probe failed: {}",
        live_res_tcp.details
    );
    assert_eq!(live_res_tcp.resolved_ips, vec![external_ip]);
}

#[tokio::test]
async fn test_node_and_dns_restart_recovers_resolution() {
    let service_ip: Ipv4Addr = "10.43.0.55".parse().unwrap();
    let domain = "api-service.default.svc.cluster.local";

    // 1. Start initial local DNS server
    let server1 = LocalDnsServer::start_loopback().await.unwrap();
    let addr = server1.local_addr();
    server1.add_a_record(domain, service_ip).await;

    let probe_udp =
        DnsResolutionProbe::same_namespace("api-service", "default", service_ip, DnsProtocol::Udp);
    let probe_tcp =
        DnsResolutionProbe::same_namespace("api-service", "default", service_ip, DnsProtocol::Tcp);

    let prober = DnsProber::new(ProbeTransport::Live {
        server_addr: addr,
        timeout: Duration::from_millis(300),
    });

    // Initial resolution passes
    let res1_udp = prober.execute_probe(&probe_udp).await.unwrap();
    assert!(res1_udp.success, "Initial UDP resolution should succeed");
    let res1_tcp = prober.execute_probe(&probe_tcp).await.unwrap();
    assert!(res1_tcp.success, "Initial TCP resolution should succeed");

    // 2. Simulate Node/DNS restart outage: stop server
    server1.stop();
    // Allow sockets to close
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Probes should now fail while server is down
    let down_udp = prober.execute_probe(&probe_udp).await;
    let down_tcp = prober.execute_probe(&probe_tcp).await;
    assert!(
        down_udp.is_err() || !down_udp.unwrap().success,
        "UDP probe must not succeed while DNS server is stopped"
    );
    assert!(
        down_tcp.is_err() || !down_tcp.unwrap().success,
        "TCP probe must not succeed while DNS server is stopped"
    );

    // 3. Restart DNS server on the original address (recovering resolution for existing clients)
    let server2 = LocalDnsServer::start_on(addr).await.unwrap();
    server2.add_a_record(domain, service_ip).await;

    let rec_udp = prober.execute_probe(&probe_udp).await.unwrap();
    assert!(
        rec_udp.success,
        "UDP resolution must recover on original endpoint after DNS restart"
    );
    assert_eq!(rec_udp.resolved_ips, vec![service_ip]);

    let rec_tcp = prober.execute_probe(&probe_tcp).await.unwrap();
    assert!(
        rec_tcp.success,
        "TCP resolution must recover on original endpoint after DNS restart"
    );
    assert_eq!(rec_tcp.resolved_ips, vec![service_ip]);
}

#[tokio::test]
async fn test_historical_readiness_regression_detection() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();
    let _ = client.create_namespace(COREDNS_NAMESPACE).await;

    let config = CoreDnsConfig::new().with_readiness_timeout(Duration::from_millis(150));
    let service = CoreDnsService::new(config, Arc::new(client.clone()));

    // Start service (creates manifests: Deployment readyReplicas is 0)
    service.start().await.unwrap();
    assert!(service.is_running());
    assert!(
        !service.is_ready(),
        "CoreDNS must not report ready prematurely before pods are healthy"
    );

    // Readiness check detects unready state without declaring false ready (historical KS-16 regression)
    let health = service.check_readiness().await.unwrap();
    assert!(
        !health.is_healthy,
        "Must detect zero ready replicas as not healthy"
    );
    assert_eq!(health.ready_replicas, 0);

    // wait_for_readiness must time out when replicas are 0
    let err = service
        .wait_for_readiness(Duration::from_millis(150))
        .await
        .unwrap_err();
    assert!(matches!(err, DnsError::ReadinessTimeout { .. }));

    // Now simulate pod readiness: update deployment status readyReplicas = 1
    let mut dep = client
        .get_deployment(COREDNS_NAMESPACE, diorama_dns::COREDNS_DEPLOYMENT_NAME)
        .await
        .unwrap();
    dep["status"] = json!({
        "replicas": 1,
        "readyReplicas": 1,
        "updatedReplicas": 1,
        "availableReplicas": 1
    });
    client
        .update_deployment(COREDNS_NAMESPACE, diorama_dns::COREDNS_DEPLOYMENT_NAME, dep)
        .await
        .unwrap();

    // Now readiness succeeds immediately
    let health_after = service.check_readiness().await.unwrap();
    assert!(
        health_after.is_healthy,
        "Readiness must succeed once readyReplicas > 0"
    );
    assert_eq!(health_after.ready_replicas, 1);
    service
        .wait_for_readiness(Duration::from_secs(1))
        .await
        .unwrap();
    assert!(service.is_ready());
}

#[tokio::test]
async fn test_ipv6_reverse_forwarding_omitted_when_ipv6_disabled() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();
    let _ = client.create_namespace(COREDNS_NAMESPACE).await;

    // Case A: IPv6 is disabled
    let config_no_ipv6 = CoreDnsConfig::new().with_disable_ipv6(true);
    diorama_dns::DnsReconciler::new(&config_no_ipv6)
        .reconcile(&client)
        .await
        .unwrap();

    // Configure dual-stack clusterIPs on kube-dns
    let mut svc = client
        .get_service(COREDNS_NAMESPACE, "kube-dns")
        .await
        .unwrap();
    svc["spec"]["clusterIPs"] = json!(["10.43.0.10", "2001:db8::567:89ab"]);
    client
        .update_service(COREDNS_NAMESPACE, "kube-dns", svc)
        .await
        .unwrap();

    let client_arc = Arc::new(client);
    let prober_no_ipv6 = DnsProber::new(ProbeTransport::Synthetic {
        client: Arc::clone(&client_arc),
        config: config_no_ipv6,
    });

    let probe_ipv4 = DnsResolutionProbe::reverse_ipv4(
        "10.43.0.10".parse().unwrap(),
        "kube-dns.kube-system.svc.cluster.local",
        DnsProtocol::Udp,
    );
    let res_ipv4 = prober_no_ipv6.execute_probe(&probe_ipv4).await.unwrap();
    assert!(res_ipv4.success, "IPv4 reverse lookup must succeed");

    let probe_ipv6 = DnsResolutionProbe {
        category: diorama_dns::ProbeCategory::ReverseLookup,
        query_name: "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
            .to_string(),
        record_type: DnsRecordType::PTR.as_u16(),
        protocol: DnsProtocol::Udp,
        client_namespace: "default".to_string(),
        expected_ip: None,
        expected_cname: None,
        expected_ptr: Some("kube-dns.kube-system.svc.cluster.local".to_string()),
        expected_srv: None,
        expected_rcode: diorama_dns::DnsRcode::NoError.as_u8(),
    };
    let res_ipv6_disabled = prober_no_ipv6.execute_probe(&probe_ipv6).await.unwrap();
    // When IPv6 is disabled, reverse IPv6 zone is absent (returns NXDomain), so probe expecting NoError fails
    assert!(
        !res_ipv6_disabled.success,
        "IPv6 reverse forwarding must be absent when IPv6 is disabled"
    );

    // Case B: IPv6 is enabled
    let config_with_ipv6 = CoreDnsConfig::new().with_disable_ipv6(false);
    let prober_with_ipv6 = DnsProber::new(ProbeTransport::Synthetic {
        client: client_arc,
        config: config_with_ipv6,
    });
    let res_ipv6_enabled = prober_with_ipv6.execute_probe(&probe_ipv6).await.unwrap();
    assert!(
        res_ipv6_enabled.success,
        "IPv6 reverse forwarding should be enabled when IPv6 is enabled"
    );

    // Unassigned IPv6 address must return NXDomain
    let unassigned_probe = DnsResolutionProbe {
        category: diorama_dns::ProbeCategory::ReverseLookup,
        query_name: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
            .to_string(),
        record_type: DnsRecordType::PTR.as_u16(),
        protocol: DnsProtocol::Udp,
        client_namespace: "default".to_string(),
        expected_ip: None,
        expected_cname: None,
        expected_ptr: None,
        expected_srv: None,
        expected_rcode: diorama_dns::DnsRcode::NXDomain.as_u8(),
    };
    let unassigned_res = prober_with_ipv6
        .execute_probe(&unassigned_probe)
        .await
        .unwrap();
    assert!(
        unassigned_res.success,
        "Unassigned IPv6 address query must return NXDomain"
    );
}

#[tokio::test]
async fn test_dns_suite_aggregation_report() {
    let server = LocalDnsServer::start_loopback().await.unwrap();
    let addr = server.local_addr();

    let web_ip: Ipv4Addr = "10.43.1.100".parse().unwrap();
    let db_ip: Ipv4Addr = "10.43.1.200".parse().unwrap();
    let ext_cname = "ext.domain.com";

    server
        .add_a_record("web.prod.svc.cluster.local", web_ip)
        .await;
    server
        .add_a_record("db.prod.svc.cluster.local", db_ip)
        .await;
    server
        .add_cname_record("service.prod.svc.cluster.local", ext_cname)
        .await;

    let prober = DnsProber::new(ProbeTransport::Live {
        server_addr: addr,
        timeout: Duration::from_secs(2),
    });

    let probe_suite = vec![
        DnsResolutionProbe::same_namespace("web", "prod", web_ip, DnsProtocol::Udp),
        DnsResolutionProbe::same_namespace("web", "prod", web_ip, DnsProtocol::Tcp),
        DnsResolutionProbe::cross_namespace("db", "prod", "staging", db_ip, DnsProtocol::Udp),
        DnsResolutionProbe::cross_namespace("db", "prod", "staging", db_ip, DnsProtocol::Tcp),
        DnsResolutionProbe::external_name("service", "prod", ext_cname, DnsProtocol::Udp),
        DnsResolutionProbe::external_name("service", "prod", ext_cname, DnsProtocol::Tcp),
    ];

    let report = prober.execute_suite(&probe_suite).await.unwrap();
    assert_eq!(report.total_probes, 6);
    assert_eq!(report.successful_probes, 6);
    assert_eq!(report.failed_probes, 0);
    assert!(report.all_passed());
    assert!(report.udp_same_namespace_passed);
    assert!(report.tcp_same_namespace_passed);
    assert!(report.udp_cross_namespace_passed);
    assert!(report.tcp_cross_namespace_passed);
    assert!(report.udp_external_name_passed);
    assert!(report.tcp_external_name_passed);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_headless_service_dns_resolution() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let ns = "tier5-headless";
    client.create_namespace(ns).await.unwrap();

    let pod_ip: Ipv4Addr = "10.244.2.100".parse().unwrap();

    // 1. Create headless Service (clusterIP: "None") with Endpoints
    let svc_val = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "db-headless",
            "namespace": ns
        },
        "spec": {
            "type": "ClusterIP",
            "clusterIP": "None",
            "ports": [{
                "name": "postgres",
                "port": 5432,
                "protocol": "TCP"
            }]
        }
    });
    client.create_service(ns, svc_val).await.unwrap();

    let ep_val = json!({
        "apiVersion": "v1",
        "kind": "Endpoints",
        "metadata": {
            "name": "db-headless",
            "namespace": ns
        },
        "subsets": [{
            "addresses": [{
                "ip": pod_ip.to_string(),
                "targetRef": {
                    "kind": "Pod",
                    "name": "db-headless-0",
                    "namespace": ns
                }
            }],
            "ports": [{
                "name": "postgres",
                "port": 5432,
                "protocol": "TCP"
            }]
        }]
    });
    client.create_endpoints(ns, ep_val).await.unwrap();

    let config = CoreDnsConfig::new();
    let prober = DnsProber::new(ProbeTransport::Synthetic {
        client: Arc::new(client.clone()),
        config,
    });

    // Verify headless service resolution (UDP and TCP)
    let probe_udp = DnsResolutionProbe::headless("db-headless", ns, pod_ip, DnsProtocol::Udp);
    let res_udp = prober.execute_probe(&probe_udp).await.unwrap();
    assert!(
        res_udp.success,
        "Headless UDP probe must succeed: {}",
        res_udp.details
    );
    assert_eq!(res_udp.resolved_ips, vec![pod_ip]);

    let probe_tcp = DnsResolutionProbe::headless("db-headless", ns, pod_ip, DnsProtocol::Tcp);
    let res_tcp = prober.execute_probe(&probe_tcp).await.unwrap();
    assert!(
        res_tcp.success,
        "Headless TCP probe must succeed: {}",
        res_tcp.details
    );
    assert_eq!(res_tcp.resolved_ips, vec![pod_ip]);

    // 2. Create headless Service resolved via EndpointSlice
    let slice_pod_ip: Ipv4Addr = "10.244.2.101".parse().unwrap();
    let slice_svc_val = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "cache-headless",
            "namespace": ns
        },
        "spec": {
            "type": "ClusterIP",
            "clusterIP": "None",
            "ports": [{
                "name": "redis",
                "port": 6379,
                "protocol": "TCP"
            }]
        }
    });
    client.create_service(ns, slice_svc_val).await.unwrap();

    let slice_val = json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": "cache-headless-slice",
            "namespace": ns,
            "labels": {
                "kubernetes.io/service-name": "cache-headless"
            }
        },
        "addressType": "IPv4",
        "endpoints": [{
            "addresses": [slice_pod_ip.to_string()],
            "conditions": {
                "ready": true
            },
            "targetRef": {
                "kind": "Pod",
                "name": "cache-headless-0",
                "namespace": ns
            }
        }],
        "ports": [{
            "name": "redis",
            "port": 6379,
            "protocol": "TCP"
        }]
    });
    client.create_endpointslice(ns, slice_val).await.unwrap();

    let slice_probe =
        DnsResolutionProbe::headless("cache-headless", ns, slice_pod_ip, DnsProtocol::Udp);
    let slice_res = prober.execute_probe(&slice_probe).await.unwrap();
    assert!(
        slice_res.success,
        "EndpointSlice-backed headless probe must succeed: {}",
        slice_res.details
    );
    assert_eq!(slice_res.resolved_ips, vec![slice_pod_ip]);

    // 3. Verify pod-in-service query: db-headless-0.db-headless.tier5-headless.svc.cluster.local
    let mut pod_probe = DnsResolutionProbe::headless("db-headless", ns, pod_ip, DnsProtocol::Udp);
    pod_probe.query_name = format!("db-headless-0.db-headless.{ns}.svc.cluster.local");
    let pod_res = prober.execute_probe(&pod_probe).await.unwrap();
    assert!(
        pod_res.success,
        "Pod-in-service query must resolve to pod IP: {}",
        pod_res.details
    );
    assert_eq!(pod_res.resolved_ips, vec![pod_ip]);

    // 4. Verify valid dashed-IP query in service: 10-244-2-100.db-headless.tier5-headless.svc.cluster.local
    let mut dashed_probe =
        DnsResolutionProbe::headless("db-headless", ns, pod_ip, DnsProtocol::Udp);
    dashed_probe.query_name = format!("10-244-2-100.db-headless.{ns}.svc.cluster.local");
    let dashed_res = prober.execute_probe(&dashed_probe).await.unwrap();
    assert!(
        dashed_res.success,
        "Valid dashed-IP query must resolve to pod IP: {}",
        dashed_res.details
    );
    assert_eq!(dashed_res.resolved_ips, vec![pod_ip]);

    // 5. Verify unassociated dashed-IP query fails: 10-244-9-99.db-headless.tier5-headless.svc.cluster.local
    let unassociated_ip: Ipv4Addr = "10.244.9.99".parse().unwrap();
    let mut invalid_dashed_probe =
        DnsResolutionProbe::headless("db-headless", ns, unassociated_ip, DnsProtocol::Udp);
    invalid_dashed_probe.query_name = format!("10-244-9-99.db-headless.{ns}.svc.cluster.local");
    let invalid_res = prober.execute_probe(&invalid_dashed_probe).await.unwrap();
    assert!(
        !invalid_res.success,
        "Dashed-IP not belonging to service must fail to resolve"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_pqdn_and_srv_record_dns_resolution() {
    let dir = TempDir::new().unwrap();
    let (_apiserver, client) = setup_test_cluster(&dir);
    let client_arc = Arc::new(client);

    // 1. Create namespaces and service with named port
    client_arc.create_namespace("tier5-a").await.unwrap();
    client_arc.create_namespace("tier5-b").await.unwrap();

    let svc_ip: Ipv4Addr = "10.43.0.100".parse().unwrap();
    client_arc
        .create_service(
            "tier5-a",
            json!({
                "metadata": {
                    "name": "web",
                    "namespace": "tier5-a"
                },
                "spec": {
                    "type": "ClusterIP",
                    "clusterIP": "10.43.0.100",
                    "ports": [
                        {
                            "name": "http",
                            "protocol": "TCP",
                            "port": 8080,
                            "targetPort": 8080
                        }
                    ]
                }
            }),
        )
        .await
        .unwrap();

    let config = CoreDnsConfig::new();
    let prober = DnsProber::new(ProbeTransport::Synthetic {
        client: client_arc.clone(),
        config: config.clone(),
    });

    // 2. Same-namespace PQDN: query "web" with client_namespace "tier5-a"
    let probe_pqdn_same = DnsResolutionProbe::pqdn("web", "tier5-a", svc_ip, DnsProtocol::Udp);
    let res_same = prober.execute_probe(&probe_pqdn_same).await.unwrap();
    assert!(
        res_same.success,
        "Same-namespace PQDN resolution must succeed: {}",
        res_same.details
    );
    assert_eq!(res_same.resolved_ips, vec![svc_ip]);

    // 3. Cross-namespace PQDN: query "web.tier5-a" with client_namespace "tier5-b"
    let probe_pqdn_cross =
        DnsResolutionProbe::pqdn("web.tier5-a", "tier5-b", svc_ip, DnsProtocol::Udp);
    let res_cross = prober.execute_probe(&probe_pqdn_cross).await.unwrap();
    assert!(
        res_cross.success,
        "Cross-namespace PQDN resolution must succeed: {}",
        res_cross.details
    );
    assert_eq!(res_cross.resolved_ips, vec![svc_ip]);

    // 4. PQDN with .svc suffix: query "web.tier5-a.svc" with client_namespace "tier5-b"
    let probe_pqdn_svc =
        DnsResolutionProbe::pqdn("web.tier5-a.svc", "tier5-b", svc_ip, DnsProtocol::Tcp);
    let res_svc = prober.execute_probe(&probe_pqdn_svc).await.unwrap();
    assert!(
        res_svc.success,
        "PQDN with .svc suffix resolution must succeed: {}",
        res_svc.details
    );
    assert_eq!(res_svc.resolved_ips, vec![svc_ip]);

    // 5. SRV resolution (Synthetic): _http._tcp.web.tier5-a.svc.cluster.local
    let probe_srv_fqdn = DnsResolutionProbe::srv(
        "_http._tcp.web.tier5-a.svc.cluster.local",
        "tier5-a",
        8080,
        "web.tier5-a.svc.cluster.local",
        DnsProtocol::Udp,
    );
    let res_srv = prober.execute_probe(&probe_srv_fqdn).await.unwrap();
    assert!(
        res_srv.success,
        "Synthetic SRV resolution must succeed: {}",
        res_srv.details
    );
    assert_eq!(res_srv.resolved_srvs.len(), 1);
    assert_eq!(res_srv.resolved_srvs[0].2, 8080);

    // 6. SRV resolution (Live Mock Server) over both UDP and TCP
    let local_server = LocalDnsServer::start_loopback().await.unwrap();
    local_server
        .add_srv_record(
            "_http._tcp.web.tier5-a.svc.cluster.local",
            0,
            100,
            8080,
            "web.tier5-a.svc.cluster.local",
        )
        .await;

    let live_prober = DnsProber::new(ProbeTransport::Live {
        server_addr: local_server.local_addr(),
        timeout: Duration::from_secs(2),
    });

    let live_udp_srv = DnsResolutionProbe::srv(
        "_http._tcp.web.tier5-a.svc.cluster.local",
        "tier5-a",
        8080,
        "web.tier5-a.svc.cluster.local",
        DnsProtocol::Udp,
    );
    let live_udp_res = live_prober.execute_probe(&live_udp_srv).await.unwrap();
    assert!(
        live_udp_res.success,
        "Live UDP SRV query must succeed: {}",
        live_udp_res.details
    );

    let live_tcp_srv = DnsResolutionProbe::srv(
        "_http._tcp.web.tier5-a.svc.cluster.local",
        "tier5-a",
        8080,
        "web.tier5-a.svc.cluster.local",
        DnsProtocol::Tcp,
    );
    let live_tcp_res = live_prober.execute_probe(&live_tcp_srv).await.unwrap();
    assert!(
        live_tcp_res.success,
        "Live TCP SRV query must succeed: {}",
        live_tcp_res.details
    );
}
