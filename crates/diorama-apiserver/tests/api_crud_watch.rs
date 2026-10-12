use serde_json::json;
use std::collections::BTreeMap;
use std::net::IpAddr;
use tempfile::TempDir;

use diorama_apiserver::{ApiserverConfig, ApiserverError, ApiserverService, KubernetesStorage};
use diorama_datastore::{DatastoreConfig, DatastoreEngine, WatchEventType};
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
async fn api_discovery_returns_core_and_group_resources() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    let core = client.discover_core().expect("discover_core succeeds");
    assert_eq!(core["kind"], "APIResourceList");
    let res_array = core["resources"].as_array().expect("resources array");
    let names: Vec<&str> = res_array
        .iter()
        .filter_map(|r| r["name"].as_str())
        .collect();
    assert!(names.contains(&"namespaces"));
    assert!(names.contains(&"configmaps"));
    assert!(names.contains(&"secrets"));
    assert!(names.contains(&"pods"));
    assert!(names.contains(&"endpoints"));
    assert!(names.contains(&"persistentvolumeclaims"));
    assert!(names.contains(&"persistentvolumes"));
    let claim_resource = res_array
        .iter()
        .find(|r| r["name"] == "persistentvolumeclaims")
        .unwrap();
    assert_eq!(claim_resource["shortNames"], json!(["pvc"]));
    let volume_resource = res_array
        .iter()
        .find(|r| r["name"] == "persistentvolumes")
        .unwrap();
    assert_eq!(volume_resource["shortNames"], json!(["pv"]));

    let apis = client.discover_apis().expect("discover_apis succeeds");
    assert_eq!(apis["kind"], "APIGroupList");
    let groups = apis["groups"].as_array().expect("groups array");
    let group_names: Vec<&str> = groups.iter().filter_map(|g| g["name"].as_str()).collect();
    assert!(group_names.contains(&"apps"));
    assert!(group_names.contains(&"apiextensions.k8s.io"));
    assert!(group_names.contains(&"discovery.k8s.io"));
    assert!(group_names.contains(&"storage.k8s.io"));

    let discovery_group = client
        .discover_group_resources("discovery.k8s.io", "v1")
        .expect("discover discovery.k8s.io/v1 succeeds");
    let slice_resource = discovery_group["resources"]
        .as_array()
        .expect("discovery resources array")
        .iter()
        .find(|r| r["name"] == "endpointslices")
        .expect("endpointslices in discovery");
    assert_eq!(slice_resource["shortNames"], json!(["es"]));

    let core_resources = client
        .discover_core()
        .expect("discover core resources succeeds");
    let endpoints_resource = core_resources["resources"]
        .as_array()
        .expect("core resources array")
        .iter()
        .find(|r| r["name"] == "endpoints")
        .expect("endpoints in core discovery");
    assert_eq!(endpoints_resource["shortNames"], json!(["ep"]));

    let storage_group = client
        .discover_group_resources("storage.k8s.io", "v1")
        .expect("storage group discovery");
    let sc_res = &storage_group["resources"][0];
    assert_eq!(sc_res["name"], "storageclasses");
    assert_eq!(sc_res["shortNames"], json!(["sc"]));
}

#[tokio::test]
async fn authenticated_crud_list_watch_on_configmaps_and_namespaces() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    // 1. Create Namespace
    let ns = client
        .create_namespace("team-a")
        .await
        .expect("create namespace");
    assert_eq!(ns["metadata"]["name"], "team-a");

    // 2. Start Watch on ConfigMaps in namespace team-a
    let mut watch_rx = client
        .watch("configmaps/team-a/")
        .await
        .expect("watch succeeds");

    // 3. Create ConfigMap
    let mut data1 = BTreeMap::new();
    data1.insert("host".to_string(), "10.0.0.1".to_string());
    data1.insert("port".to_string(), "8080".to_string());
    let cm1 = client
        .create_configmap("team-a", "service-cfg", data1)
        .await
        .expect("create configmap");
    assert_eq!(cm1["metadata"]["name"], "service-cfg");
    let rv1_str = cm1["metadata"]["resourceVersion"].as_str().unwrap();
    let rv1: u64 = rv1_str.parse().unwrap();

    // Verify watch received ADDED (Put)
    let event1 = watch_rx.recv().await.expect("recv watch event 1");
    assert_eq!(event1.event_type, WatchEventType::Put);
    assert_eq!(event1.kv.mod_revision, rv1);

    // 4. Update ConfigMap
    let mut data2 = BTreeMap::new();
    data2.insert("host".to_string(), "10.0.0.1".to_string());
    data2.insert("port".to_string(), "8443".to_string());
    let cm2 = client
        .update_configmap("team-a", "service-cfg", data2, Some(rv1))
        .await
        .expect("update configmap");
    assert_eq!(cm2["data"]["port"], "8443");
    let rv2: u64 = cm2["metadata"]["resourceVersion"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(rv2 > rv1, "Resource version must increase monotonically");

    // Verify watch received MODIFIED (Put)
    let event2 = watch_rx.recv().await.expect("recv watch event 2");
    assert_eq!(event2.event_type, WatchEventType::Put);
    assert_eq!(event2.kv.mod_revision, rv2);

    // 5. Optimistic Concurrency Conflict on stale update
    let mut stale_data = BTreeMap::new();
    stale_data.insert("port".to_string(), "9000".to_string());
    let conflict_err = client
        .update_configmap("team-a", "service-cfg", stale_data, Some(rv1))
        .await;
    assert!(
        matches!(conflict_err, Err(ApiserverError::Conflict { .. })),
        "Stale resourceVersion update must return Conflict"
    );

    // 6. List ConfigMaps
    let list = client
        .list_configmaps("team-a")
        .await
        .expect("list configmaps");
    assert_eq!(list["items"].as_array().unwrap().len(), 1);

    // 7. Delete ConfigMap
    client
        .delete_configmap("team-a", "service-cfg", Some(rv2))
        .await
        .expect("delete configmap");

    // Verify watch received DELETED (Delete)
    let event3 = watch_rx.recv().await.expect("recv watch event 3");
    assert_eq!(event3.event_type, WatchEventType::Delete);

    // 8. Delete Namespace
    client
        .delete_namespace("team-a")
        .await
        .expect("delete namespace");
    let get_ns_err = client.get_namespace("team-a").await;
    assert!(matches!(get_ns_err, Err(ApiserverError::NotFound { .. })));
}

#[tokio::test]
async fn crd_and_custom_resource_lifecycle() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    let crd = json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {
            "name": "crontabs.stable.example.com"
        },
        "spec": {
            "group": "stable.example.com",
            "scope": "Namespaced",
            "names": {
                "plural": "crontabs",
                "singular": "crontab",
                "kind": "CronTab"
            }
        }
    });

    // 1. Create CRD
    let created_crd = client.create_crd(crd).await.expect("create CRD");
    assert_eq!(
        created_crd["metadata"]["name"],
        "crontabs.stable.example.com"
    );

    // 2. Read CRD
    let fetched_crd = client
        .get_crd("crontabs.stable.example.com")
        .await
        .expect("get CRD");
    assert_eq!(fetched_crd["spec"]["names"]["kind"], "CronTab");

    // 3. Create Custom Resource instance preserving arbitrary JSON
    let cr_instance = json!({
        "apiVersion": "stable.example.com/v1",
        "kind": "CronTab",
        "metadata": {
            "name": "my-cron",
            "namespace": "default"
        },
        "spec": {
            "cronSpec": "* * * * *",
            "image": "my-cron-image",
            "replicas": 3,
            "extraOptions": {
                "tags": ["prod", "hourly"],
                "active": true
            }
        }
    });

    let created_cr = client
        .create_custom_resource(
            "stable.example.com",
            "crontabs",
            "default",
            "my-cron",
            cr_instance,
        )
        .await
        .expect("create custom resource");
    assert_eq!(created_cr["spec"]["replicas"], 3);
    assert_eq!(created_cr["spec"]["extraOptions"]["active"], true);

    // 4. Fetch Custom Resource
    let fetched_cr = client
        .get_custom_resource("stable.example.com", "crontabs", "default", "my-cron")
        .await
        .expect("fetch custom resource");
    assert_eq!(fetched_cr["metadata"]["name"], "my-cron");
    assert_eq!(fetched_cr["spec"]["cronSpec"], "* * * * *");

    // 5. Delete CRD
    client
        .delete_crd("crontabs.stable.example.com")
        .await
        .expect("delete CRD");
    assert!(client.get_crd("crontabs.stable.example.com").await.is_err());
}

#[tokio::test]
async fn unauthenticated_and_unauthorized_requests_are_rejected() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);

    // 1. Anonymous request rejection (--anonymous-auth=false)
    let anon_client = service.anonymous_client();
    let anon_err = anon_client.discover_core();
    assert!(
        matches!(anon_err, Err(ApiserverError::Unauthenticated { .. })),
        "Anonymous client must be rejected when --anonymous-auth=false"
    );

    // 2. Invalid bearer token rejection (including prefix spoofing attempts)
    let invalid_token_client = service.token_client("bad-token-xyz");
    let token_err = invalid_token_client.create_namespace("hacked").await;
    assert!(
        matches!(token_err, Err(ApiserverError::Unauthorized { .. })),
        "Invalid token must be rejected with Unauthorized"
    );

    let spoofed_token_client = service.token_client("system:adminX");
    let spoof_err = spoofed_token_client.create_namespace("hacked2").await;
    assert!(
        matches!(spoof_err, Err(ApiserverError::Unauthorized { .. })),
        "Token with system:admin prefix must not grant admin access"
    );

    // 3. Restricted user forbidden from cluster mutation
    let restricted_client = service.restricted_client("developer-bob", vec!["devs".to_string()]);
    let forbidden_err = restricted_client.create_namespace("restricted-ns").await;
    assert!(
        matches!(forbidden_err, Err(ApiserverError::Unauthorized { .. })),
        "Restricted user without admin RBAC role must be rejected with Unauthorized"
    );
}

#[tokio::test]
async fn authenticated_crud_on_endpoints_and_endpointslices() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    let client = service.admin_client();

    client.create_namespace("ep-test").await.unwrap();

    // 1. Endpoints CRUD
    let ep_doc = json!({
        "apiVersion": "v1",
        "kind": "Endpoints",
        "metadata": {
            "name": "headless-svc",
            "namespace": "ep-test"
        },
        "subsets": [{
            "addresses": [{"ip": "10.244.1.5"}],
            "ports": [{"port": 80, "protocol": "TCP"}]
        }]
    });
    let created_ep = client.create_endpoints("ep-test", ep_doc).await.unwrap();
    assert_eq!(created_ep["metadata"]["name"], "headless-svc");

    let fetched_ep = client
        .get_endpoints("ep-test", "headless-svc")
        .await
        .unwrap();
    assert_eq!(fetched_ep["subsets"][0]["addresses"][0]["ip"], "10.244.1.5");

    let ep_list = client.list_endpoints("ep-test").await.unwrap();
    assert_eq!(ep_list["items"].as_array().unwrap().len(), 1);

    // 2. EndpointSlice CRUD
    let slice_doc = json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": "headless-svc-slice",
            "namespace": "ep-test",
            "labels": {
                "kubernetes.io/service-name": "headless-svc"
            }
        },
        "addressType": "IPv4",
        "endpoints": [{
            "addresses": ["10.244.1.5"],
            "conditions": {
                "ready": true
            }
        }],
        "ports": [{
            "port": 80,
            "protocol": "TCP"
        }]
    });
    let created_slice = client
        .create_endpointslice("ep-test", slice_doc)
        .await
        .unwrap();
    assert_eq!(created_slice["metadata"]["name"], "headless-svc-slice");

    let fetched_slice = client
        .get_endpointslice("ep-test", "headless-svc-slice")
        .await
        .unwrap();
    assert_eq!(fetched_slice["endpoints"][0]["addresses"][0], "10.244.1.5");

    let slice_list = client.list_endpointslices("ep-test").await.unwrap();
    assert_eq!(slice_list["items"].as_array().unwrap().len(), 1);

    // 3. Delete
    client
        .delete_endpoints("ep-test", "headless-svc")
        .await
        .unwrap();
    assert!(
        client
            .get_endpoints("ep-test", "headless-svc")
            .await
            .is_err()
    );

    client
        .delete_endpointslice("ep-test", "headless-svc-slice")
        .await
        .unwrap();
    assert!(
        client
            .get_endpointslice("ep-test", "headless-svc-slice")
            .await
            .is_err()
    );
}
