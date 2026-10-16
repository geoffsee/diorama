#[path = "controller_config.rs"]
mod controller_config;
#[path = "controller_supervisor.rs"]
mod controller_supervisor;
#[path = "endpointslice_reconciliation.rs"]
mod endpointslice_reconciliation;
#[path = "loadbalancer_status_assignment.rs"]
mod loadbalancer_status_assignment;
#[path = "webhook_admission_transport.rs"]
mod webhook_admission_transport;
#[path = "workload_placement_admission.rs"]
mod workload_placement_admission;
#[path = "workload_reconciliation.rs"]
mod workload_reconciliation;

mod deployment_and_rc_lifecycle {
    use std::net::IpAddr;
    use std::sync::Arc;

    use diorama_apiserver::client::KubernetesApiClient;
    use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
    use diorama_controller::{ControllerManagerConfig, ControllerManagerService};
    use diorama_datastore::{DatastoreConfig, DatastoreEngine};
    use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
    use serde_json::{Value, json};
    use tempfile::TempDir;

    fn setup_controller(dir: &TempDir) -> ControllerManagerService {
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

        let controller_config = ControllerManagerConfig::default_for_pki(&pki_dir, node_ip);
        let apiserver_arc = Arc::new(apiserver_service);

        ControllerManagerService::new(controller_config, apiserver_arc)
    }

    async fn mark_pod_ready(client: &KubernetesApiClient, ns: &str, pod_name: &str) {
        let mut pod = client.get_pod(ns, pod_name).await.unwrap();
        pod["status"] = json!({
            "phase": "Running",
            "conditions": [
                { "type": "Ready", "status": "True" }
            ]
        });
        client.update_pod(ns, pod_name, pod).await.unwrap();
    }

    async fn mark_all_pods_ready(client: &KubernetesApiClient, ns: &str) {
        let list = client.list_pods(ns).await.unwrap();
        if let Some(items) = list.get("items").and_then(Value::as_array) {
            for pod in items {
                if let Some(name) = pod.pointer("/metadata/name").and_then(Value::as_str) {
                    mark_pod_ready(client, ns, name).await;
                }
            }
        }
    }

    #[tokio::test]
    async fn test_deployment_creation_status_and_readiness() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "dep-create-ns";
        client.create_namespace(ns).await.unwrap();

        let dep = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "web-deploy", "namespace": ns },
            "spec": {
                "replicas": 2,
                "selector": { "matchLabels": { "app": "web" } },
                "template": {
                    "metadata": { "labels": { "app": "web" } },
                    "spec": { "containers": [{ "name": "nginx", "image": "nginx:1.27" }] }
                }
            }
        });
        client.create_deployment(ns, dep).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let rs_list = client.list_replicasets(ns).await.unwrap();
        let rs_items = rs_list["items"].as_array().unwrap();
        assert_eq!(rs_items.len(), 1);
        let rs = &rs_items[0];
        let hash = rs
            .pointer("/metadata/labels/pod-template-hash")
            .and_then(Value::as_str);
        assert!(
            hash.is_some(),
            "ReplicaSet must have pod-template-hash label"
        );

        let pod_list = client.list_pods(ns).await.unwrap();
        let pods = pod_list["items"].as_array().unwrap();
        assert_eq!(pods.len(), 2);
        for p in pods {
            assert_eq!(
                p.pointer("/metadata/labels/pod-template-hash")
                    .and_then(Value::as_str),
                hash
            );
            let owners = p
                .pointer("/metadata/ownerReferences")
                .and_then(Value::as_array)
                .unwrap();
            assert_eq!(owners[0]["kind"], "ReplicaSet");
        }

        let dep_obj = client.get_deployment(ns, "web-deploy").await.unwrap();
        assert_eq!(dep_obj["status"]["observedGeneration"], 1);
        assert_eq!(dep_obj["status"]["replicas"], 2);
        assert_eq!(dep_obj["status"]["updatedReplicas"], 2);
        assert_eq!(dep_obj["status"]["readyReplicas"], 0);
        assert_eq!(dep_obj["status"]["availableReplicas"], 0);
        assert_eq!(dep_obj["status"]["unavailableReplicas"], 2);

        mark_all_pods_ready(&client, ns).await;
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let dep_ready = client.get_deployment(ns, "web-deploy").await.unwrap();
        assert_eq!(dep_ready["status"]["readyReplicas"], 2);
        assert_eq!(dep_ready["status"]["availableReplicas"], 2);
        assert_eq!(dep_ready["status"]["unavailableReplicas"], 0);

        let conditions = dep_ready["status"]["conditions"].as_array().unwrap();
        let avail = conditions
            .iter()
            .find(|c| c["type"] == "Available")
            .unwrap();
        assert_eq!(avail["status"], "True");
        assert_eq!(avail["reason"], "MinimumReplicasAvailable");

        let prog = conditions
            .iter()
            .find(|c| c["type"] == "Progressing")
            .unwrap();
        assert_eq!(prog["status"], "True");
        assert_eq!(prog["reason"], "NewReplicaSetAvailable");
    }

    #[tokio::test]
    async fn test_deployment_rolling_update_and_conditions() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "dep-roll-ns";
        client.create_namespace(ns).await.unwrap();

        let dep = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "roll-deploy", "namespace": ns },
            "spec": {
                "replicas": 2,
                "strategy": {
                    "type": "RollingUpdate",
                    "rollingUpdate": { "maxSurge": 1, "maxUnavailable": 0 }
                },
                "selector": { "matchLabels": { "app": "roll" } },
                "template": {
                    "metadata": { "labels": { "app": "roll" } },
                    "spec": { "containers": [{ "name": "c", "image": "nginx:1.27" }] }
                }
            }
        });
        client.create_deployment(ns, dep).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        mark_all_pods_ready(&client, ns).await;
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let mut dep_v2 = client.get_deployment(ns, "roll-deploy").await.unwrap();
        dep_v2["spec"]["template"]["spec"]["containers"][0]["image"] = json!("nginx:1.28");
        client
            .update_deployment(ns, "roll-deploy", dep_v2)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let rs_list = client.list_replicasets(ns).await.unwrap();
        let rs_items = rs_list["items"].as_array().unwrap();
        assert_eq!(
            rs_items.len(),
            2,
            "RollingUpdate must create a second ReplicaSet"
        );

        let dep_after_patch = client.get_deployment(ns, "roll-deploy").await.unwrap();
        assert_eq!(
            dep_after_patch
                .pointer("/metadata/annotations/deployment.kubernetes.io~1revision")
                .and_then(Value::as_str),
            Some("2")
        );

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        mark_all_pods_ready(&client, ns).await;
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        mark_all_pods_ready(&client, ns).await;
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let final_dep = client.get_deployment(ns, "roll-deploy").await.unwrap();
        assert_eq!(final_dep["status"]["updatedReplicas"], 2);
        assert_eq!(final_dep["status"]["readyReplicas"], 2);

        let conditions = final_dep["status"]["conditions"].as_array().unwrap();
        let prog = conditions
            .iter()
            .find(|c| c["type"] == "Progressing")
            .unwrap();
        assert_eq!(prog["reason"], "NewReplicaSetAvailable");
    }

    #[tokio::test]
    async fn test_deployment_scale_and_clean_deletion() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "dep-scale-ns";
        client.create_namespace(ns).await.unwrap();

        let dep = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "scale-deploy", "namespace": ns },
            "spec": {
                "replicas": 2,
                "selector": { "matchLabels": { "app": "scale" } },
                "template": {
                    "metadata": { "labels": { "app": "scale" } },
                    "spec": { "containers": [{ "name": "app", "image": "nginx:1.27" }] }
                }
            }
        });
        client.create_deployment(ns, dep).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let mut dep_scale_up = client.get_deployment(ns, "scale-deploy").await.unwrap();
        dep_scale_up["spec"]["replicas"] = json!(4);
        client
            .update_deployment(ns, "scale-deploy", dep_scale_up)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let pods_up = client.list_pods(ns).await.unwrap();
        assert_eq!(pods_up["items"].as_array().unwrap().len(), 4);

        let mut dep_scale_down = client.get_deployment(ns, "scale-deploy").await.unwrap();
        dep_scale_down["spec"]["replicas"] = json!(1);
        client
            .update_deployment(ns, "scale-deploy", dep_scale_down)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let pods_down = client.list_pods(ns).await.unwrap();
        assert_eq!(pods_down["items"].as_array().unwrap().len(), 1);

        client.delete_deployment(ns, "scale-deploy").await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let rs_after_del = client.list_replicasets(ns).await.unwrap();
        assert_eq!(rs_after_del["items"].as_array().unwrap().len(), 0);
        let pods_after_del = client.list_pods(ns).await.unwrap();
        assert_eq!(pods_after_del["items"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_deployment_recreate_strategy() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "dep-rec-ns";
        client.create_namespace(ns).await.unwrap();

        let dep = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "recreate-deploy", "namespace": ns },
            "spec": {
                "replicas": 2,
                "strategy": { "type": "Recreate" },
                "selector": { "matchLabels": { "app": "recreate" } },
                "template": {
                    "metadata": { "labels": { "app": "recreate" } },
                    "spec": { "containers": [{ "name": "app", "image": "nginx:1.27" }] }
                }
            }
        });
        client.create_deployment(ns, dep).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let pods_v1 = client.list_pods(ns).await.unwrap();
        assert_eq!(pods_v1["items"].as_array().unwrap().len(), 2);

        let mut dep_v2 = client.get_deployment(ns, "recreate-deploy").await.unwrap();
        dep_v2["spec"]["template"]["spec"]["containers"][0]["image"] = json!("nginx:1.28");
        client
            .update_deployment(ns, "recreate-deploy", dep_v2)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let rs_list = client.list_replicasets(ns).await.unwrap();
        for rs in rs_list["items"].as_array().unwrap() {
            let img = rs
                .pointer("/spec/template/spec/containers/0/image")
                .and_then(Value::as_str);
            if img == Some("nginx:1.27") {
                assert_eq!(
                    rs["spec"]["replicas"], 0,
                    "Old RS must scale to 0 under Recreate"
                );
            }
        }

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let final_pods = client.list_pods(ns).await.unwrap();
        let final_items = final_pods["items"].as_array().unwrap();
        assert_eq!(final_items.len(), 2);
        for p in final_items {
            assert_eq!(
                p.pointer("/spec/containers/0/image")
                    .and_then(Value::as_str),
                Some("nginx:1.28")
            );
        }
    }

    #[tokio::test]
    async fn test_deployment_proportional_scaling() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "dep-prop-ns";
        client.create_namespace(ns).await.unwrap();

        let dep = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "prop-deploy", "namespace": ns },
            "spec": {
                "replicas": 10,
                "selector": { "matchLabels": { "app": "prop" } },
                "template": {
                    "metadata": { "labels": { "app": "prop" } },
                    "spec": { "containers": [{ "name": "app", "image": "nginx:1.27" }] }
                }
            }
        });
        client.create_deployment(ns, dep).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let dep_obj = client.get_deployment(ns, "prop-deploy").await.unwrap();
        let dep_uid = dep_obj
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let old_rs = client.get_replicaset(ns, "prop-deploy-rs").await.unwrap();
        let mut old_scaled = old_rs.clone();
        old_scaled["spec"]["replicas"] = json!(2);
        client
            .update_replicaset(ns, "prop-deploy-rs", old_scaled)
            .await
            .unwrap();

        let new_rs = json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": {
                "name": "prop-deploy-newhash",
                "namespace": ns,
                "labels": { "app": "prop", "pod-template-hash": "newhash" },
                "annotations": { "deployment.kubernetes.io/revision": "2" },
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "prop-deploy",
                    "uid": dep_uid,
                    "controller": true,
                    "blockOwnerDeletion": true
                }]
            },
            "spec": {
                "replicas": 8,
                "selector": { "matchLabels": { "app": "prop", "pod-template-hash": "newhash" } },
                "template": {
                    "metadata": { "labels": { "app": "prop", "pod-template-hash": "newhash" } },
                    "spec": { "containers": [{ "name": "app", "image": "nginx:1.28" }] }
                }
            }
        });
        client.create_replicaset(ns, new_rs).await.unwrap();

        let mut dep_scaled = client.get_deployment(ns, "prop-deploy").await.unwrap();
        dep_scaled["spec"]["replicas"] = json!(20);
        dep_scaled["spec"]["template"]["spec"]["containers"][0]["image"] = json!("nginx:1.28");
        client
            .update_deployment(ns, "prop-deploy", dep_scaled)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let old_after = client.get_replicaset(ns, "prop-deploy-rs").await.unwrap();
        assert_eq!(
            old_after["spec"]["replicas"], 4,
            "Old RS must scale to 4 (20% of 20)"
        );
        let new_after = client
            .get_replicaset(ns, "prop-deploy-newhash")
            .await
            .unwrap();
        assert_eq!(
            new_after["spec"]["replicas"], 16,
            "New RS must scale to 16 (80% of 20)"
        );
    }

    #[tokio::test]
    async fn test_replicationcontroller_creation_defaulted_selector_and_status() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "rc-create-ns";
        client.create_namespace(ns).await.unwrap();

        let rc = json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "rc-demo", "namespace": ns },
            "spec": {
                "replicas": 2,
                "template": {
                    "metadata": { "labels": { "app": "rc-demo" } },
                    "spec": { "containers": [{ "name": "c", "image": "busybox:latest" }] }
                }
            }
        });
        client.create_replicationcontroller(ns, rc).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let fetched_rc = client
            .get_replicationcontroller(ns, "rc-demo")
            .await
            .unwrap();
        assert_eq!(
            fetched_rc
                .pointer("/spec/selector/app")
                .and_then(Value::as_str),
            Some("rc-demo"),
            "spec.selector must default from spec.template.metadata.labels"
        );
        assert_eq!(fetched_rc["status"]["observedGeneration"], 1);
        assert_eq!(fetched_rc["status"]["replicas"], 2);
        assert_eq!(fetched_rc["status"]["fullyLabeledReplicas"], 2);
        assert_eq!(fetched_rc["status"]["readyReplicas"], 0);

        let pod_list = client.list_pods(ns).await.unwrap();
        let pods = pod_list["items"].as_array().unwrap();
        assert_eq!(pods.len(), 2);
        for p in pods {
            assert_eq!(
                p.pointer("/metadata/labels/app").and_then(Value::as_str),
                Some("rc-demo")
            );
            let owners = p
                .pointer("/metadata/ownerReferences")
                .and_then(Value::as_array)
                .unwrap();
            assert_eq!(owners[0]["kind"], "ReplicationController");
        }

        mark_all_pods_ready(&client, ns).await;
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let ready_rc = client
            .get_replicationcontroller(ns, "rc-demo")
            .await
            .unwrap();
        assert_eq!(ready_rc["status"]["readyReplicas"], 2);
        assert_eq!(ready_rc["status"]["availableReplicas"], 2);
    }

    #[tokio::test]
    async fn test_replicationcontroller_scaling_and_clean_deletion() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "rc-scale-ns";
        client.create_namespace(ns).await.unwrap();

        let rc = json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "rc-scale", "namespace": ns },
            "spec": {
                "replicas": 2,
                "selector": { "app": "rc-scale" },
                "template": {
                    "metadata": { "labels": { "app": "rc-scale" } },
                    "spec": { "containers": [{ "name": "c", "image": "busybox:latest" }] }
                }
            }
        });
        client.create_replicationcontroller(ns, rc).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let mut rc_up = client
            .get_replicationcontroller(ns, "rc-scale")
            .await
            .unwrap();
        rc_up["spec"]["replicas"] = json!(4);
        client
            .update_replicationcontroller(ns, "rc-scale", rc_up)
            .await
            .unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let pods_up = client.list_pods(ns).await.unwrap();
        assert_eq!(pods_up["items"].as_array().unwrap().len(), 4);

        let mut rc_down = client
            .get_replicationcontroller(ns, "rc-scale")
            .await
            .unwrap();
        rc_down["spec"]["replicas"] = json!(1);
        client
            .update_replicationcontroller(ns, "rc-scale", rc_down)
            .await
            .unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let pods_down = client.list_pods(ns).await.unwrap();
        assert_eq!(pods_down["items"].as_array().unwrap().len(), 1);

        client
            .delete_replicationcontroller(ns, "rc-scale")
            .await
            .unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let pods_after_del = client.list_pods(ns).await.unwrap();
        assert_eq!(pods_after_del["items"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_replicationcontroller_label_adoption_and_release() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "rc-adopt-ns";
        client.create_namespace(ns).await.unwrap();

        let rc = json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "rc-adopt", "namespace": ns },
            "spec": {
                "replicas": 2,
                "selector": { "app": "rc-adopt" },
                "template": {
                    "metadata": { "labels": { "app": "rc-adopt" } },
                    "spec": { "containers": [{ "name": "c", "image": "busybox:latest" }] }
                }
            }
        });
        client.create_replicationcontroller(ns, rc).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let pods = client.list_pods(ns).await.unwrap();
        let pod_items = pods["items"].as_array().unwrap();
        assert_eq!(pod_items.len(), 2);

        // Relabel 1 pod so RC releases it
        let mut relabeled_pod = pod_items[0].clone();
        relabeled_pod["metadata"]["labels"] = json!({ "app": "unmatched" });
        let p_name = relabeled_pod["metadata"]["name"]
            .as_str()
            .unwrap()
            .to_string();
        client.update_pod(ns, &p_name, relabeled_pod).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        // The relabeled pod must have ownerReferences removed
        let released = client.get_pod(ns, &p_name).await.unwrap();
        let owners = released
            .pointer("/metadata/ownerReferences")
            .and_then(Value::as_array);
        let has_rc_owner =
            owners.is_some_and(|arr| arr.iter().any(|o| o["kind"] == "ReplicationController"));
        assert!(!has_rc_owner, "Relabeled pod must be released by RC");

        // RC must have created a replacement pod
        let all_pods = client.list_pods(ns).await.unwrap();
        let owned_by_rc = all_pods["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| {
                p.pointer("/metadata/ownerReferences")
                    .and_then(Value::as_array)
                    .is_some_and(|arr| arr.iter().any(|o| o["kind"] == "ReplicationController"))
            })
            .count();
        assert_eq!(
            owned_by_rc, 2,
            "RC must maintain 2 owned pods after release"
        );

        // Now create an unowned orphan pod matching the RC selector
        let orphan = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "orphan-pod",
                "namespace": ns,
                "labels": { "app": "rc-adopt" }
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox:latest" }] }
        });
        client.create_pod(ns, orphan).await.unwrap();

        // Scale RC desired replicas to 3 to adopt without immediately deleting
        let mut rc_scale = client
            .get_replicationcontroller(ns, "rc-adopt")
            .await
            .unwrap();
        rc_scale["spec"]["replicas"] = json!(3);
        client
            .update_replicationcontroller(ns, "rc-adopt", rc_scale)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let adopted = client.get_pod(ns, "orphan-pod").await.unwrap();
        let adopted_owners = adopted
            .pointer("/metadata/ownerReferences")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(adopted_owners[0]["kind"], "ReplicationController");
    }
}
