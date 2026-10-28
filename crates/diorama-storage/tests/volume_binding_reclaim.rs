use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverConfig, ApiserverService, KubernetesApiClient, KubernetesStorage,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_storage::{
    LocalPathConfig, LocalPathReconciler, LocalPathService, LocalPathVolumeManager,
    PV_PROTECTION_FINALIZER, PVC_PROTECTION_FINALIZER, StorageError,
    VOLUME_SELECTED_NODE_ANNOTATION, VolumeReclaimAction, safe_resolve_volume_path,
    safe_teardown_volume_dir,
};
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
async fn test_first_consumer_binding_with_placement_integration() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let storage_root = temp.path().join("local-path-storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    let config = LocalPathConfig::new()
        .with_storage_path(storage_root.display().to_string())
        .with_volume_binding_mode("WaitForFirstConsumer")
        .with_reclaim_policy("Retain");

    // 1. Reconcile storage provisioner manifests into cluster
    let reconciler = LocalPathReconciler::new(&config);
    let report = reconciler.reconcile(&client).await.unwrap();
    assert!(report.storage_class_created);

    // 2. Create consumer namespace
    let ns = "storage-test-consumer";
    client.create_namespace(ns).await.unwrap();

    // 3. Create PVC requesting local-path storage class
    let pvc_req = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": "data-claim",
            "namespace": ns,
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": "local-path",
            "resources": {
                "requests": {
                    "storage": "5Gi"
                }
            }
        },
        "status": {
            "phase": "Pending"
        }
    });
    let pvc = client.create_pvc(ns, pvc_req).await.unwrap();
    assert_eq!(pvc["status"]["phase"], "Pending");

    let volume_mgr = LocalPathVolumeManager::new(config, client.clone());

    // 4. Create Pod referencing PVC but without node placement (simulating unscheduled pod)
    let pod_unplaced = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "writer-pod",
            "namespace": ns,
        },
        "spec": {
            "containers": [{
                "name": "app",
                "image": "busybox",
            }],
            "volumes": [{
                "name": "app-volume",
                "persistentVolumeClaim": {
                    "claimName": "data-claim"
                }
            }]
        }
    });
    client.create_pod(ns, pod_unplaced).await.unwrap();

    // 5. Volume binding attempt must fail/wait because pod is unplaced (WaitForFirstConsumer)
    let bind_err = volume_mgr.bind_volumes_for_pod(ns, "writer-pod").await;
    assert!(bind_err.is_err(), "binding must require node placement");
    match bind_err.err().unwrap() {
        StorageError::VolumeBindingFailed(msg) => {
            assert!(msg.contains("no node placement assigned"));
        },
        other => panic!("expected VolumeBindingFailed, got: {other:?}"),
    }

    // 6. Now simulate scheduler placing the pod onto a node
    let placed_node = "kubesolo-worker-01";
    let mut pod = client.get_pod(ns, "writer-pod").await.unwrap();
    pod["spec"]["nodeName"] = json!(placed_node);
    client.update_pod(ns, "writer-pod", pod).await.unwrap();

    // 7. Trigger binding with placement integration
    let bound_pvs = volume_mgr
        .bind_volumes_for_pod(ns, "writer-pod")
        .await
        .unwrap();
    assert_eq!(bound_pvs.len(), 1);

    let pv = &bound_pvs[0];
    assert_eq!(pv["status"]["phase"], "Bound");
    assert_eq!(pv["spec"]["storageClassName"], "local-path");
    assert_eq!(pv["spec"]["capacity"]["storage"], "5Gi");
    assert_eq!(pv["spec"]["persistentVolumeReclaimPolicy"], "Retain");
    assert_eq!(pv["spec"]["claimRef"]["name"], "data-claim");
    assert_eq!(pv["spec"]["claimRef"]["namespace"], ns);

    // Verify node affinity is pinned to the placed node
    let terms = pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"]
        .as_array()
        .unwrap();
    let values = terms[0]["matchExpressions"][0]["values"]
        .as_array()
        .unwrap();
    assert_eq!(values[0].as_str().unwrap(), placed_node);

    // Verify host directory was created on disk
    let host_path_str = pv["spec"]["local"]["path"].as_str().unwrap();
    let host_path = Path::new(host_path_str);
    assert!(host_path.exists());
    assert!(host_path.is_dir());
    assert!(host_path.starts_with(&storage_root));

    // 8. Verify PVC is now Bound and references this PV
    let updated_pvc = client.get_pvc(ns, "data-claim").await.unwrap();
    assert_eq!(updated_pvc["status"]["phase"], "Bound");
    assert_eq!(
        updated_pvc["spec"]["volumeName"],
        pv["metadata"]["name"].as_str().unwrap()
    );
}

#[tokio::test]
async fn test_data_survives_writing_pod_deletion_and_replacement() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let storage_root = temp.path().join("local-path-storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    let config = LocalPathConfig::new().with_storage_path(storage_root.display().to_string());
    let reconciler = LocalPathReconciler::new(&config);
    reconciler.reconcile(&client).await.unwrap();

    let ns = "persist-data-test";
    client.create_namespace(ns).await.unwrap();

    // Create PVC
    let pvc = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": "persist-claim", "namespace": ns },
        "spec": { "accessModes": ["ReadWriteOnce"], "storageClassName": "local-path" },
        "status": { "phase": "Pending" }
    });
    client.create_pvc(ns, pvc).await.unwrap();

    // Create First Pod (writer) placed on node
    let node_name = "test-node-alpha";
    let pod1 = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "pod-writer-1", "namespace": ns },
        "spec": {
            "nodeName": node_name,
            "containers": [{ "name": "writer", "image": "busybox" }],
            "volumes": [{
                "name": "data-vol",
                "persistentVolumeClaim": { "claimName": "persist-claim" }
            }]
        }
    });
    client.create_pod(ns, pod1).await.unwrap();

    let volume_mgr = LocalPathVolumeManager::new(config.clone(), client.clone());
    let pvs = volume_mgr
        .bind_volumes_for_pod(ns, "pod-writer-1")
        .await
        .unwrap();
    let vol_path_str = pvs[0]["spec"]["local"]["path"].as_str().unwrap();
    let vol_path = Path::new(vol_path_str);

    // Pod 1 writes persistent data into volume
    let test_file = vol_path.join("cluster_state.json");
    let test_data = b"{\"transaction_id\": 4294967295, \"cluster_status\": \"OPERATIONAL\"}";
    std::fs::write(&test_file, test_data).unwrap();
    assert!(test_file.exists());

    // Delete Pod 1 (simulating pod termination/eviction)
    client
        .delete_pod_options(ns, "pod-writer-1", Some(0))
        .await
        .unwrap();
    assert!(client.get_pod(ns, "pod-writer-1").await.is_err());

    // Verify data survives pod deletion
    assert!(test_file.exists());
    assert_eq!(std::fs::read(&test_file).unwrap(), test_data);

    // Create Replacement Pod 2 referencing the EXACT SAME PVC
    let pod2 = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "pod-replacement-2", "namespace": ns },
        "spec": {
            "nodeName": node_name,
            "containers": [{ "name": "reader", "image": "busybox" }],
            "volumes": [{
                "name": "data-vol",
                "persistentVolumeClaim": { "claimName": "persist-claim" }
            }]
        }
    });
    client.create_pod(ns, pod2).await.unwrap();

    // Replacement pod binds to existing volume idempotently
    let pvs2 = volume_mgr
        .bind_volumes_for_pod(ns, "pod-replacement-2")
        .await
        .unwrap();
    assert_eq!(pvs2.len(), 1);
    assert_eq!(pvs2[0]["metadata"]["name"], pvs[0]["metadata"]["name"]);

    // Read and verify data in replacement pod
    let read_back = std::fs::read(&test_file).unwrap();
    assert_eq!(read_back, test_data);
}

#[tokio::test]
async fn test_separate_deletion_reclaim_retain_behavior() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let storage_root = temp.path().join("local-path-storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    let config = LocalPathConfig::new()
        .with_storage_path(storage_root.display().to_string())
        .with_reclaim_policy("Retain");

    let reconciler = LocalPathReconciler::new(&config);
    reconciler.reconcile(&client).await.unwrap();

    let ns = "retain-reclaim-test";
    client.create_namespace(ns).await.unwrap();

    let pvc = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": "retained-claim", "namespace": ns },
        "spec": { "accessModes": ["ReadWriteOnce"], "storageClassName": "local-path" },
        "status": { "phase": "Pending" }
    });
    client.create_pvc(ns, pvc).await.unwrap();

    let volume_mgr = LocalPathVolumeManager::new(config, client.clone());
    let pv = volume_mgr
        .provision_volume_for_pvc(ns, "retained-claim", "node-retain")
        .await
        .unwrap();

    let pv_name = pv["metadata"]["name"].as_str().unwrap();
    let vol_path_str = pv["spec"]["local"]["path"].as_str().unwrap();
    let vol_path = Path::new(vol_path_str);

    // Write important data to volume
    let data_file = vol_path.join("retained_payload.txt");
    std::fs::write(&data_file, b"this data must be retained forever").unwrap();

    // Reclaim PVC
    let action = volume_mgr.reclaim_pvc(ns, "retained-claim").await.unwrap();

    match action {
        VolumeReclaimAction::Retained { pv_name: pvn, path } => {
            assert_eq!(pvn, pv_name);
            assert_eq!(path, vol_path_str);
        },
        VolumeReclaimAction::Deleted { .. } => panic!("expected Retained, got Deleted"),
    }

    // 1. PVC must be deleted from API server
    assert!(client.get_pvc(ns, "retained-claim").await.is_err());

    // 2. PV must STILL EXIST in API server with phase "Released"
    let updated_pv = client.get_pv(pv_name).await.unwrap();
    assert_eq!(updated_pv["status"]["phase"], "Released");

    // 3. Host volume directory and data MUST BE INTACT!
    assert!(vol_path.exists());
    assert!(data_file.exists());
    assert_eq!(
        std::fs::read_to_string(&data_file).unwrap(),
        "this data must be retained forever"
    );
}

#[tokio::test]
async fn test_delete_reclaim_protects_unrelated_host_data() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let storage_root = temp.path().join("local-path-storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    // Create unrelated host data in the storage root and adjacent directories
    let sibling_dir = storage_root.join("unrelated_sibling_app");
    std::fs::create_dir_all(&sibling_dir).unwrap();
    let sibling_file = sibling_dir.join("critical_backup.tar");
    std::fs::write(&sibling_file, b"CRITICAL_BACKUP_DO_NOT_TOUCH").unwrap();

    let root_file = storage_root.join("global_storage_config.yaml");
    std::fs::write(&root_file, b"version: 1.0\nenabled: true").unwrap();

    let config = LocalPathConfig::new()
        .with_storage_path(storage_root.display().to_string())
        .with_reclaim_policy("Delete");

    let reconciler = LocalPathReconciler::new(&config);
    reconciler.reconcile(&client).await.unwrap();

    let ns = "delete-reclaim-test";
    client.create_namespace(ns).await.unwrap();

    let pvc = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": "ephemeral-claim", "namespace": ns },
        "spec": { "accessModes": ["ReadWriteOnce"], "storageClassName": "local-path" },
        "status": { "phase": "Pending" }
    });
    client.create_pvc(ns, pvc).await.unwrap();

    let volume_mgr = LocalPathVolumeManager::new(config, client.clone());
    let pv = volume_mgr
        .provision_volume_for_pvc(ns, "ephemeral-claim", "node-delete")
        .await
        .unwrap();

    let pv_name = pv["metadata"]["name"].as_str().unwrap();
    let vol_path_str = pv["spec"]["local"]["path"].as_str().unwrap();
    let vol_path = Path::new(vol_path_str);

    // Write ephemeral volume data
    let test_file = vol_path.join("temp_workload.tmp");
    std::fs::write(&test_file, b"ephemeral data").unwrap();
    assert!(vol_path.exists());

    // Reclaim PVC
    let action = volume_mgr.reclaim_pvc(ns, "ephemeral-claim").await.unwrap();

    match action {
        VolumeReclaimAction::Deleted { pv_name: pvn, path } => {
            assert_eq!(pvn, pv_name);
            assert_eq!(path, vol_path_str);
        },
        VolumeReclaimAction::Retained { .. } => panic!("expected Deleted, got Retained"),
    }

    // 1. Target volume directory MUST BE GONE
    assert!(!vol_path.exists());

    // 2. PV and PVC MUST BE GONE from API
    assert!(client.get_pvc(ns, "ephemeral-claim").await.is_err());
    assert!(client.get_pv(pv_name).await.is_err());

    // 3. UNRELATED HOST DATA MUST BE COMPLETELY UNTOUCHED!
    assert!(
        sibling_dir.exists(),
        "sibling directory must remain untouched"
    );
    assert!(sibling_file.exists(), "sibling file must remain untouched");
    assert_eq!(
        std::fs::read(&sibling_file).unwrap(),
        b"CRITICAL_BACKUP_DO_NOT_TOUCH"
    );

    assert!(
        root_file.exists(),
        "root storage file must remain untouched"
    );
    assert_eq!(
        std::fs::read(&root_file).unwrap(),
        b"version: 1.0\nenabled: true"
    );
}

#[tokio::test]
async fn test_normal_vs_shared_filesystem_path_behavior() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let normal_root = temp.path().join("normal-path");
    let shared_root = temp.path().join("shared-nfs-path");
    std::fs::create_dir_all(&normal_root).unwrap();
    std::fs::create_dir_all(&shared_root).unwrap();

    // 1. Normal storage path test
    let normal_config = LocalPathConfig::new()
        .with_storage_path(normal_root.display().to_string())
        .with_shared_path(None);
    let normal_mgr = LocalPathVolumeManager::new(normal_config, client.clone());
    assert_eq!(normal_mgr.effective_base_path(), normal_root);

    let ns1 = "ns-normal";
    client.create_namespace(ns1).await.unwrap();
    let pvc1 = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": "normal-claim", "namespace": ns1 },
        "spec": { "accessModes": ["ReadWriteOnce"], "storageClassName": "local-path" },
        "status": { "phase": "Pending" }
    });
    client.create_pvc(ns1, pvc1).await.unwrap();

    let pv_normal = normal_mgr
        .provision_volume_for_pvc(ns1, "normal-claim", "node-1")
        .await
        .unwrap();
    let path_normal = pv_normal["spec"]["local"]["path"].as_str().unwrap();
    assert!(path_normal.starts_with(normal_root.to_str().unwrap()));
    assert!(!path_normal.starts_with(shared_root.to_str().unwrap()));

    // 2. Shared filesystem path test (as introduced in upstream #79 / KS-79)
    let shared_config = LocalPathConfig::new()
        .with_storage_path(normal_root.display().to_string())
        .with_shared_path(Some(shared_root.display().to_string()));
    let shared_mgr = LocalPathVolumeManager::new(shared_config, client.clone());
    assert_eq!(shared_mgr.effective_base_path(), shared_root);

    let ns2 = "ns-shared";
    client.create_namespace(ns2).await.unwrap();
    let pvc2 = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": "shared-claim", "namespace": ns2 },
        "spec": { "accessModes": ["ReadWriteOnce"], "storageClassName": "local-path" },
        "status": { "phase": "Pending" }
    });
    client.create_pvc(ns2, pvc2).await.unwrap();

    let pv_shared = shared_mgr
        .provision_volume_for_pvc(ns2, "shared-claim", "node-2")
        .await
        .unwrap();
    let path_shared = pv_shared["spec"]["local"]["path"].as_str().unwrap();
    assert!(path_shared.starts_with(shared_root.to_str().unwrap()));
    assert!(!path_shared.starts_with(normal_root.to_str().unwrap()));
}

#[test]
fn test_path_security_and_traversal_protection() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("secure-storage");
    std::fs::create_dir_all(&root).unwrap();

    // 1. Path traversal attempts
    let attacks = [
        "../../etc/shadow",
        "../sibling",
        "valid/../../escape",
        "/etc/passwd",
        "/root",
        "",
        ".",
        "vol\0hidden",
    ];

    for attack in &attacks {
        let res = safe_resolve_volume_path(&root, attack);
        assert!(
            res.is_err(),
            "attack vector '{attack}' must be rejected by safe_resolve_volume_path"
        );
        match res.err().unwrap() {
            StorageError::PathSecurityViolation(_) => {},
            other => panic!("expected PathSecurityViolation for '{attack}', got: {other:?}"),
        }
    }

    // 2. Safe teardown protections
    let escape_target = temp.path().join("other_data");
    std::fs::create_dir_all(&escape_target).unwrap();

    // Cannot teardown base root itself
    let res_root = safe_teardown_volume_dir(&root, &root);
    assert!(res_root.is_err());

    // Cannot teardown directories outside storage root
    let res_escape = safe_teardown_volume_dir(&root, &escape_target);
    assert!(res_escape.is_err());

    // Valid volume dir teardown succeeds
    let valid_vol = root.join("valid_volume_dir");
    std::fs::create_dir_all(&valid_vol).unwrap();
    assert!(valid_vol.exists());
    assert!(safe_teardown_volume_dir(&root, &valid_vol).is_ok());
    assert!(!valid_vol.exists());
}

#[tokio::test]
async fn test_deterministic_pv_recovery_on_retry() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let storage_root = temp.path().join("local-path-storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    let config = LocalPathConfig::new().with_storage_path(storage_root.display().to_string());
    let reconciler = LocalPathReconciler::new(&config);
    reconciler.reconcile(&client).await.unwrap();

    let ns = "retry-recovery-ns";
    client.create_namespace(ns).await.unwrap();

    let pvc = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": "retry-claim", "namespace": ns },
        "spec": { "accessModes": ["ReadWriteOnce"], "storageClassName": "local-path" },
        "status": { "phase": "Pending" }
    });
    let created_pvc = client.create_pvc(ns, pvc).await.unwrap();
    let pvc_uid = created_pvc["metadata"]["uid"].as_str().unwrap();
    let pv_name = format!("pvc-{pvc_uid}");

    // Simulate scenario: PV was created in API server, but PVC update had failed
    let partial_pv = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": { "name": &pv_name },
        "spec": {
            "capacity": { "storage": "1Gi" },
            "accessModes": ["ReadWriteOnce"],
            "persistentVolumeReclaimPolicy": "Retain",
            "storageClassName": "local-path",
            "local": { "path": storage_root.join(format!("{ns}_retry-claim_{pv_name}")).display().to_string() },
            "claimRef": { "namespace": ns, "name": "retry-claim" }
        },
        "status": { "phase": "Bound" }
    });
    client.create_pv(partial_pv).await.unwrap();

    // Verify PVC is still Pending
    let pending_pvc = client.get_pvc(ns, "retry-claim").await.unwrap();
    assert_eq!(pending_pvc["status"]["phase"], "Pending");

    let volume_mgr = LocalPathVolumeManager::new(config, client.clone());

    // Call provision_volume_for_pvc to recover the PV
    let recovered_pv = volume_mgr
        .provision_volume_for_pvc(ns, "retry-claim", "node-recovery")
        .await
        .unwrap();

    assert_eq!(recovered_pv["metadata"]["name"], pv_name);

    // PVC should now be Bound
    let bound_pvc = client.get_pvc(ns, "retry-claim").await.unwrap();
    assert_eq!(bound_pvc["status"]["phase"], "Bound");
    assert_eq!(bound_pvc["spec"]["volumeName"], pv_name);
}

#[tokio::test]
async fn test_empty_storage_class_name_disables_dynamic_provisioning() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let storage_root = temp.path().join("local-path-storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    let config = LocalPathConfig::new()
        .with_storage_path(storage_root.display().to_string())
        .with_volume_binding_mode("Immediate")
        .with_reclaim_policy("Delete");

    let ns = "test-empty-sc";
    client.create_namespace(ns).await.unwrap();

    // 1. PVC with storageClassName: ""
    let empty_sc_pvc = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": "manual-bind-claim", "namespace": ns },
        "spec": { "accessModes": ["ReadWriteOnce"], "storageClassName": "" },
        "status": { "phase": "Pending" }
    });
    client.create_pvc(ns, empty_sc_pvc).await.unwrap();

    let volume_mgr = LocalPathVolumeManager::new(config, client.clone());
    let err = volume_mgr
        .provision_volume_for_pvc(ns, "manual-bind-claim", "node-1")
        .await
        .unwrap_err();

    match err {
        StorageError::VolumeBindingFailed(msg) => {
            assert!(msg.contains("dynamic provisioning disabled"));
        },
        other => panic!("expected VolumeBindingFailed error, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_default_storage_class_dynamic_provisioning_and_verify_binding() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let storage_root = temp.path().join("local-path-storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    let config = LocalPathConfig::new()
        .with_storage_path(storage_root.display().to_string())
        .with_volume_binding_mode("Immediate")
        .with_reclaim_policy("Delete");

    // Reconciler creates default StorageClass "local-path" with is-default-class annotation
    let reconciler = LocalPathReconciler::new(&config);
    let report = reconciler.reconcile(&client).await.unwrap();
    assert!(report.storage_class_created);

    let ns = "test-default-sc";
    client.create_namespace(ns).await.unwrap();

    // Create PVC with NO spec.storageClassName (omitted entirely)
    let pvc_req = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": "omitted-sc-claim", "namespace": ns },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": { "requests": { "storage": "2Gi" } }
        },
        "status": { "phase": "Pending" }
    });
    let created_pvc = client.create_pvc(ns, pvc_req).await.unwrap();
    assert!(created_pvc["spec"].get("storageClassName").is_none());

    let volume_mgr = LocalPathVolumeManager::new(config, client.clone());
    let pv = volume_mgr
        .provision_volume_for_pvc(ns, "omitted-sc-claim", "node-1")
        .await
        .unwrap();

    let pv_name = pv["metadata"]["name"].as_str().unwrap();
    assert_eq!(pv["spec"]["storageClassName"], "local-path");
    assert_eq!(pv["status"]["phase"], "Bound");

    let bound_pvc = client.get_pvc(ns, "omitted-sc-claim").await.unwrap();
    assert_eq!(bound_pvc["status"]["phase"], "Bound");
    assert_eq!(bound_pvc["spec"]["volumeName"], pv_name);

    // Verify bi-directional binding check
    let is_bound = volume_mgr
        .verify_binding(ns, "omitted-sc-claim")
        .await
        .unwrap();
    assert!(
        is_bound,
        "verify_binding must confirm bi-directional binding"
    );
}

#[tokio::test]
async fn test_wait_for_first_consumer_delayed_binding_pass() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let storage_root = temp.path().join("local-path-storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    let config = LocalPathConfig::new()
        .with_storage_path(storage_root.display().to_string())
        .with_volume_binding_mode("WaitForFirstConsumer")
        .with_reclaim_policy("Delete");

    let reconciler = LocalPathReconciler::new(&config);
    reconciler.reconcile(&client).await.unwrap();

    let ns = "test-delayed-binding";
    client.create_namespace(ns).await.unwrap();

    // PVC without selected-node annotation
    let pvc_req = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": "delayed-claim", "namespace": ns },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": "local-path",
            "resources": { "requests": { "storage": "1Gi" } }
        },
        "status": { "phase": "Pending" }
    });
    client.create_pvc(ns, pvc_req).await.unwrap();

    let service = LocalPathService::new(config.clone(), std::sync::Arc::new(client.clone()));

    // 1. Binder pass without selected-node annotation: should NOT bind
    service.bind_pending_volumes().await;

    let pvc = client.get_pvc(ns, "delayed-claim").await.unwrap();
    assert_eq!(pvc["status"]["phase"], "Pending");
    assert!(pvc["spec"].get("volumeName").is_none());

    // 2. Pod scheduling annotates PVC with volume.kubernetes.io/selected-node: "worker-node-42"
    let mut updated_pvc = pvc.clone();
    let meta = updated_pvc["metadata"].as_object_mut().unwrap();
    meta.insert(
        "annotations".to_string(),
        json!({
            VOLUME_SELECTED_NODE_ANNOTATION: "worker-node-42"
        }),
    );
    client
        .update_pvc(ns, "delayed-claim", updated_pvc)
        .await
        .unwrap();

    // 3. Binder pass now picks up the annotated PVC
    service.bind_pending_volumes().await;

    let bound_pvc = client.get_pvc(ns, "delayed-claim").await.unwrap();
    assert_eq!(bound_pvc["status"]["phase"], "Bound");
    let pv_name = bound_pvc["spec"]["volumeName"].as_str().unwrap();

    let pv = client.get_pv(pv_name).await.unwrap();
    assert_eq!(pv["status"]["phase"], "Bound");
    assert_eq!(
        pv["metadata"]["annotations"][VOLUME_SELECTED_NODE_ANNOTATION],
        "worker-node-42"
    );
    let node_affinity = &pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"];
    assert_eq!(
        node_affinity[0]["matchExpressions"][0]["values"][0],
        "worker-node-42"
    );
}

#[tokio::test]
#[allow(clippy::similar_names)]
async fn test_pvc_pv_protection_and_in_use() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let storage_root = temp.path().join("local-path-storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    let config = LocalPathConfig::new()
        .with_storage_path(storage_root.display().to_string())
        .with_volume_binding_mode("Immediate")
        .with_reclaim_policy("Delete");

    let reconciler = LocalPathReconciler::new(&config);
    reconciler.reconcile(&client).await.unwrap();

    let ns = "test-protection";
    client.create_namespace(ns).await.unwrap();

    let pvc_req = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": "prot-claim", "namespace": ns },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": "local-path",
            "resources": { "requests": { "storage": "1Gi" } }
        },
        "status": { "phase": "Pending" }
    });
    client.create_pvc(ns, pvc_req).await.unwrap();

    let volume_mgr = LocalPathVolumeManager::new(config, client.clone());
    let pv = volume_mgr
        .provision_volume_for_pvc(ns, "prot-claim", "node-1")
        .await
        .unwrap();
    let pv_name = pv["metadata"]["name"].as_str().unwrap();

    // Verify protection finalizers were added during provision
    let pvc_with_fin = client.get_pvc(ns, "prot-claim").await.unwrap();
    let pvc_fins = pvc_with_fin["metadata"]["finalizers"].as_array().unwrap();
    assert!(
        pvc_fins
            .iter()
            .any(|f| f.as_str() == Some(PVC_PROTECTION_FINALIZER))
    );

    let pv_with_fin = client.get_pv(pv_name).await.unwrap();
    let pv_fins = pv_with_fin["metadata"]["finalizers"].as_array().unwrap();
    assert!(
        pv_fins
            .iter()
            .any(|f| f.as_str() == Some(PV_PROTECTION_FINALIZER))
    );

    // Initially no pod uses the PVC
    let in_use = volume_mgr.is_pvc_in_use(ns, "prot-claim").await.unwrap();
    assert!(!in_use);

    // Create a Pod referencing this PVC
    let pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "user-pod", "namespace": ns },
        "spec": {
            "nodeName": "node-1",
            "containers": [{ "name": "c", "image": "busybox" }],
            "volumes": [{
                "name": "vol",
                "persistentVolumeClaim": { "claimName": "prot-claim" }
            }]
        }
    });
    client.create_pod(ns, pod).await.unwrap();

    // Now PVC IS in use
    let in_use_after = volume_mgr.is_pvc_in_use(ns, "prot-claim").await.unwrap();
    assert!(
        in_use_after,
        "PVC should be detected as in-use while pod exists"
    );

    // Delete pod
    client
        .delete_pod_options(ns, "user-pod", Some(0))
        .await
        .unwrap();

    // Now PVC is no longer in use
    let in_use_done = volume_mgr.is_pvc_in_use(ns, "prot-claim").await.unwrap();
    assert!(
        !in_use_done,
        "PVC should no longer be in use once pod is deleted"
    );

    // Remove finalizers
    let pvc_no_fin = volume_mgr
        .remove_pvc_protection(ns, "prot-claim")
        .await
        .unwrap();
    let pvc_no_fins = pvc_no_fin["metadata"]["finalizers"].as_array().unwrap();
    assert!(
        !pvc_no_fins
            .iter()
            .any(|f| f.as_str() == Some(PVC_PROTECTION_FINALIZER))
    );

    let pv_no_fin = volume_mgr.remove_pv_protection(pv_name).await.unwrap();
    let pv_no_fins = pv_no_fin["metadata"]["finalizers"].as_array().unwrap();
    assert!(
        !pv_no_fins
            .iter()
            .any(|f| f.as_str() == Some(PV_PROTECTION_FINALIZER))
    );
}

#[tokio::test]
async fn test_csi_resources_lifecycle() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let storage_root = temp.path().join("local-path-storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    let config = LocalPathConfig::new()
        .with_storage_path(storage_root.display().to_string())
        .with_volume_binding_mode("Immediate")
        .with_reclaim_policy("Delete");

    let volume_mgr = LocalPathVolumeManager::new(config, client.clone());

    // 1. CSINode registration and query
    volume_mgr
        .ensure_csi_node(
            "test-node-1",
            "rancher.io/local-path",
            "uuid-node-1",
            &["kubernetes.io/hostname"],
        )
        .await
        .unwrap();
    let csi_node = volume_mgr.get_csi_node("test-node-1").await.unwrap();
    assert_eq!(csi_node["metadata"]["name"], "test-node-1");

    // 2. CSIStorageCapacity publication and query
    let mut topo = BTreeMap::new();
    topo.insert(
        "kubernetes.io/hostname".to_string(),
        "test-node-1".to_string(),
    );
    volume_mgr
        .record_storage_capacity(
            "default",
            "cap-node-1",
            "local-path",
            50_000_000_000,
            Some(&topo),
        )
        .await
        .unwrap();
    let cap = volume_mgr
        .get_storage_capacity("default", "cap-node-1")
        .await
        .unwrap();
    assert_eq!(cap, Some(50_000_000_000));

    // 3. VolumeAttachment create, status update, query
    volume_mgr
        .create_volume_attachment(
            "va-node-1",
            "rancher.io/local-path",
            "test-node-1",
            "pv-test-1",
        )
        .await
        .unwrap();
    volume_mgr
        .set_volume_attachment_status("va-node-1", true)
        .await
        .unwrap();
    let va = volume_mgr.get_volume_attachment("va-node-1").await.unwrap();
    assert_eq!(va["status"]["attached"], true);

    // 4. VolumeAttributesClass create and query
    let mut params = BTreeMap::new();
    params.insert("provisioner".to_string(), "local-path".to_string());
    params.insert("tier".to_string(), "gold".to_string());
    volume_mgr
        .create_volume_attributes_class("gold-tier", "rancher.io/local-path", &params)
        .await
        .unwrap();
    let vac = volume_mgr
        .get_volume_attributes_class("gold-tier")
        .await
        .unwrap();
    assert_eq!(vac["driverName"], "rancher.io/local-path");
    assert_eq!(vac["parameters"]["tier"], "gold");

    // 5. Cleanup CSI resources
    volume_mgr
        .delete_volume_attributes_class("gold-tier")
        .await
        .unwrap();
    volume_mgr
        .delete_volume_attachment("va-node-1")
        .await
        .unwrap();
    volume_mgr
        .delete_storage_capacity("default", "cap-node-1")
        .await
        .unwrap();
    volume_mgr.delete_csi_node("test-node-1").await.unwrap();
}

#[tokio::test]
async fn test_pvc_condition_and_pv_status_updates() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();

    let storage_root = temp.path().join("local-path-storage");
    std::fs::create_dir_all(&storage_root).unwrap();

    let config = LocalPathConfig::new()
        .with_storage_path(storage_root.display().to_string())
        .with_volume_binding_mode("Immediate")
        .with_reclaim_policy("Delete");

    let volume_mgr = LocalPathVolumeManager::new(config, client.clone());

    let ns = "test-status-updates";
    client.create_namespace(ns).await.unwrap();
    let claim_manifest = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": { "name": "cond-claim", "namespace": ns },
        "spec": { "accessModes": ["ReadWriteOnce"] },
        "status": { "phase": "Bound" }
    });
    client.create_pvc(ns, claim_manifest).await.unwrap();

    let updated_pvc = volume_mgr
        .update_pvc_condition(
            ns,
            "cond-claim",
            "Resizing",
            "True",
            "Expanding",
            "In progress",
        )
        .await
        .unwrap();
    let cond = &updated_pvc["status"]["conditions"][0];
    assert_eq!(cond["type"], "Resizing");
    assert_eq!(cond["status"], "True");
    assert_eq!(cond["reason"], "Expanding");
    assert_eq!(cond["message"], "In progress");

    let volume_manifest = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": { "name": "status-pv" },
        "spec": { "accessModes": ["ReadWriteOnce"] },
        "status": { "phase": "Available" }
    });
    client.create_pv(volume_manifest).await.unwrap();

    let updated_pv = volume_mgr
        .update_pv_status_details(
            "status-pv",
            "Released",
            Some("ClaimLost"),
            Some("Claim deleted"),
        )
        .await
        .unwrap();
    assert_eq!(updated_pv["status"]["phase"], "Released");
    assert_eq!(updated_pv["status"]["reason"], "ClaimLost");
    assert_eq!(updated_pv["status"]["message"], "Claim deleted");
}

#[tokio::test]
async fn deleted_claims_release_only_owned_volumes_without_active_consumers() {
    let temp = TempDir::new().unwrap();
    let (apiserver, client) = setup_test_cluster(&temp);
    apiserver.check_prerequisites().await.unwrap();
    client.create_namespace("reclaim-test").await.unwrap();
    for (name, provisioner) in [
        ("owned", "rancher.io/local-path"),
        ("unrelated", "example.com/other"),
    ] {
        client
            .create_pv(json!({"apiVersion":"v1","kind":"PersistentVolume",
            "metadata":{"name":name,"annotations":{"pv.kubernetes.io/provisioned-by":provisioner}},
            "spec":{"capacity":{"storage":"1Mi"},"accessModes":["ReadWriteOnce"],
            "local":{"path":"/unused/test"},"claimRef":{"namespace":"reclaim-test","name":"gone"},
            "persistentVolumeReclaimPolicy":"Retain"},"status":{"phase":"Bound"}}))
            .await
            .unwrap();
    }
    client
        .create_pod(
            "reclaim-test",
            json!({"apiVersion":"v1","kind":"Pod",
        "metadata":{"name":"consumer"},"spec":{"containers":[{"name":"test","image":"busybox"}],
        "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"gone"}}]}}),
        )
        .await
        .unwrap();
    let manager = LocalPathVolumeManager::new(LocalPathConfig::new(), client.clone());
    manager.release_deleted_claims().await.unwrap();
    assert_eq!(
        client.get_pv("owned").await.unwrap()["status"]["phase"],
        "Bound"
    );
    client.delete_pod("reclaim-test", "consumer").await.unwrap();
    manager.release_deleted_claims().await.unwrap();
    assert_eq!(
        client.get_pv("owned").await.unwrap()["status"]["phase"],
        "Released"
    );
    assert_eq!(
        client.get_pv("owned").await.unwrap()["spec"]["volumeMode"],
        "Filesystem"
    );
    assert_eq!(
        client.get_pv("unrelated").await.unwrap()["status"]["phase"],
        "Bound"
    );
}
