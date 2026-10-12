use serde_json::json;
use std::net::IpAddr;
use tempfile::TempDir;

use diorama_apiserver::{ApiserverConfig, ApiserverError, ApiserverService, KubernetesStorage};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};

fn setup_service(dir: &TempDir) -> ApiserverService {
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let node_ip: IpAddr = "192.0.2.50".parse().unwrap();
    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("pki reconcile");

    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);

    let data_dir = dir.path().join("datastore");
    let ds_config = DatastoreConfig::new(data_dir);
    let (engine, _) = DatastoreEngine::open(ds_config).expect("datastore open");
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let service = ApiserverService::new(apiserver_config, storage);
    service.start().expect("service start");
    service
}

#[tokio::test]
async fn nodeport_service_allocates_cluster_ip_and_node_port() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    let svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "webnp"
        },
        "spec": {
            "type": "NodePort",
            "ports": [
                {
                    "port": 80,
                    "targetPort": 8080
                }
            ]
        }
    });

    let created = client
        .create_service("default", svc)
        .await
        .expect("create service succeeds");

    assert_eq!(created["spec"]["type"], "NodePort");
    assert_eq!(created["spec"]["clusterIP"], "10.43.0.2");
    assert_eq!(created["spec"]["clusterIPs"], json!(["10.43.0.2"]));
    assert_eq!(created["spec"]["sessionAffinity"], "None");

    let ports = created["spec"]["ports"].as_array().expect("ports array");
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0]["port"], 80);
    assert_eq!(ports[0]["protocol"], "TCP");
    assert_eq!(ports[0]["nodePort"], 30000);

    // Verify fetched service matches
    let fetched = client
        .get_service("default", "webnp")
        .await
        .expect("get service");
    assert_eq!(fetched["spec"]["clusterIP"], "10.43.0.2");
    assert_eq!(fetched["spec"]["ports"][0]["nodePort"], 30000);
}

#[tokio::test]
async fn multiple_services_allocate_distinct_cluster_ips_and_node_ports() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    let svc1 = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "svc1" },
        "spec": {
            "type": "NodePort",
            "ports": [{ "port": 80 }]
        }
    });
    let created1 = client.create_service("default", svc1).await.unwrap();
    assert_eq!(created1["spec"]["clusterIP"], "10.43.0.2");
    assert_eq!(created1["spec"]["ports"][0]["nodePort"], 30000);

    let svc2 = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "svc2" },
        "spec": {
            "type": "NodePort",
            "ports": [{ "port": 443 }]
        }
    });
    let created2 = client.create_service("default", svc2).await.unwrap();
    assert_eq!(created2["spec"]["clusterIP"], "10.43.0.3");
    assert_eq!(created2["spec"]["ports"][0]["nodePort"], 30001);

    // Multi-port NodePort service
    let svc3 = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "svc3" },
        "spec": {
            "type": "NodePort",
            "ports": [
                { "name": "http", "port": 80 },
                { "name": "https", "port": 443 }
            ]
        }
    });
    let created3 = client.create_service("default", svc3).await.unwrap();
    assert_eq!(created3["spec"]["clusterIP"], "10.43.0.4");
    assert_eq!(created3["spec"]["ports"][0]["nodePort"], 30002);
    assert_eq!(created3["spec"]["ports"][1]["nodePort"], 30003);
}

#[tokio::test]
async fn explicit_cluster_ip_and_node_port_honored_and_validated() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    let svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "explicit-svc" },
        "spec": {
            "type": "NodePort",
            "clusterIP": "10.43.10.50",
            "ports": [{ "port": 80, "nodePort": 31234 }]
        }
    });
    let created = client.create_service("default", svc).await.unwrap();
    assert_eq!(created["spec"]["clusterIP"], "10.43.10.50");
    assert_eq!(created["spec"]["ports"][0]["nodePort"], 31234);

    // Colliding explicit nodePort should be rejected
    let collide_port = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "collide-port" },
        "spec": {
            "type": "NodePort",
            "ports": [{ "port": 80, "nodePort": 31234 }]
        }
    });
    let err = client
        .create_service("default", collide_port)
        .await
        .unwrap_err();
    assert!(matches!(err, ApiserverError::InvalidInput { .. }));

    // Colliding explicit clusterIP should be rejected
    let collide_ip = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "collide-ip" },
        "spec": {
            "type": "NodePort",
            "clusterIP": "10.43.10.50",
            "ports": [{ "port": 80 }]
        }
    });
    let err = client
        .create_service("default", collide_ip)
        .await
        .unwrap_err();
    assert!(matches!(err, ApiserverError::InvalidInput { .. }));

    // Out-of-range nodePort should be rejected
    let out_of_range_port = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "bad-port" },
        "spec": {
            "type": "NodePort",
            "ports": [{ "port": 80, "nodePort": 8080 }]
        }
    });
    let err = client
        .create_service("default", out_of_range_port)
        .await
        .unwrap_err();
    assert!(matches!(err, ApiserverError::InvalidInput { .. }));

    // Out-of-range clusterIP should be rejected
    let out_of_range_ip = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "bad-ip" },
        "spec": {
            "type": "NodePort",
            "clusterIP": "192.168.1.1",
            "ports": [{ "port": 80 }]
        }
    });
    let err = client
        .create_service("default", out_of_range_ip)
        .await
        .unwrap_err();
    assert!(matches!(err, ApiserverError::InvalidInput { .. }));
}

#[tokio::test]
async fn headless_service_does_not_allocate_ip() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    let svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "headless" },
        "spec": {
            "clusterIP": "None",
            "ports": [{ "port": 80 }]
        }
    });
    let created = client.create_service("default", svc).await.unwrap();
    assert_eq!(created["spec"]["clusterIP"], "None");
    assert!(created["spec"].get("clusterIPs").is_none());
}

#[tokio::test]
async fn clusterip_service_does_not_allocate_node_port() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    let svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "clusterip-only" },
        "spec": {
            "ports": [{ "port": 80 }]
        }
    });
    let created = client.create_service("default", svc).await.unwrap();
    assert_eq!(created["spec"]["type"], "ClusterIP");
    assert_eq!(created["spec"]["clusterIP"], "10.43.0.2");
    assert!(created["spec"]["ports"][0].get("nodePort").is_none());
}

#[tokio::test]
async fn kubernetes_service_allocates_reserved_dot_one_ip() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    let k8s_svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "kubernetes" },
        "spec": {
            "ports": [{ "port": 443 }]
        }
    });
    let created = client.create_service("default", k8s_svc).await.unwrap();
    assert_eq!(created["spec"]["clusterIP"], "10.43.0.1");

    // Next service allocates .2 onwards
    let regular_svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "app" },
        "spec": {
            "ports": [{ "port": 80 }]
        }
    });
    let created_reg = client.create_service("default", regular_svc).await.unwrap();
    assert_eq!(created_reg["spec"]["clusterIP"], "10.43.0.2");
}

#[tokio::test]
async fn service_update_preserves_allocations_and_enforces_cluster_ip_immutability() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    let svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "updatable" },
        "spec": {
            "type": "NodePort",
            "ports": [{ "name": "http", "port": 80 }]
        }
    });
    let created = client.create_service("default", svc).await.unwrap();
    assert_eq!(created["spec"]["clusterIP"], "10.43.0.2");
    assert_eq!(created["spec"]["ports"][0]["nodePort"], 30000);

    // Update with preserved clusterIP and nodePort
    let mut updated = created.clone();
    updated["metadata"]["labels"] = json!({ "app": "test" });
    // Omit nodePort in ports to test auto-preservation
    updated["spec"]["ports"] = json!([{ "name": "http", "port": 80 }]);
    let saved = client
        .update_service("default", "updatable", updated)
        .await
        .unwrap();
    assert_eq!(saved["spec"]["clusterIP"], "10.43.0.2");
    assert_eq!(saved["spec"]["ports"][0]["nodePort"], 30000);
    assert_eq!(saved["metadata"]["labels"]["app"], "test");

    // Attempting to change clusterIP must fail
    let mut bad_update = saved.clone();
    bad_update["spec"]["clusterIP"] = json!("10.43.0.99");
    let err = client
        .update_service("default", "updatable", bad_update)
        .await
        .unwrap_err();
    assert!(matches!(err, ApiserverError::InvalidInput { .. }));

    // Changing type to ClusterIP deallocates nodePort
    let mut clusterip_update = saved.clone();
    clusterip_update["spec"]["type"] = json!("ClusterIP");
    let converted = client
        .update_service("default", "updatable", clusterip_update)
        .await
        .unwrap();
    assert_eq!(converted["spec"]["type"], "ClusterIP");
    assert_eq!(converted["spec"]["clusterIP"], "10.43.0.2");
    assert!(converted["spec"]["ports"][0].get("nodePort").is_none());
}

#[tokio::test]
async fn test_reject_network_and_broadcast_cluster_ips() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    // Default service_cluster_ip_range is 10.43.0.0/16
    // 10.43.0.0 is network address
    let net_svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "net-svc" },
        "spec": {
            "clusterIP": "10.43.0.0",
            "ports": [{ "port": 80 }]
        }
    });
    let err_net = client.create_service("default", net_svc).await.unwrap_err();
    assert!(matches!(err_net, ApiserverError::InvalidInput { .. }));

    // 10.43.255.255 is broadcast address
    let bcast_svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "bcast-svc" },
        "spec": {
            "clusterIP": "10.43.255.255",
            "ports": [{ "port": 80 }]
        }
    });
    let err_bcast = client
        .create_service("default", bcast_svc)
        .await
        .unwrap_err();
    assert!(matches!(err_bcast, ApiserverError::InvalidInput { .. }));

    // A valid IP within bounds should succeed
    let valid_svc = json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "valid-svc" },
        "spec": {
            "clusterIP": "10.43.0.10",
            "ports": [{ "port": 80 }]
        }
    });
    let created = client.create_service("default", valid_svc).await.unwrap();
    assert_eq!(created["spec"]["clusterIP"], "10.43.0.10");
}
