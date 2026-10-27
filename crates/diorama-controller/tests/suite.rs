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

mod workload_conformance_lane_t07 {
    use std::net::IpAddr;
    use std::sync::Arc;

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

    #[tokio::test]
    async fn test_daemonset_node_selection_dynamic_label_addition_and_removal() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "ds-selection-ns";
        client.create_namespace(ns).await.unwrap();

        // Create 2 nodes
        let node1 = json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "node-1",
                "labels": { "zone": "east", "tier": "frontend" }
            }
        });
        client.create_node(node1).await.unwrap();

        let node2 = json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "node-2",
                "labels": { "zone": "west", "tier": "frontend" }
            }
        });
        client.create_node(node2).await.unwrap();

        // Create DaemonSet targeting zone: east
        let ds = json!({
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": { "name": "complex-ds", "namespace": ns },
            "spec": {
                "selector": { "matchLabels": { "app": "complex-ds" } },
                "template": {
                    "metadata": { "labels": { "app": "complex-ds" } },
                    "spec": {
                        "nodeSelector": { "zone": "east" },
                        "containers": [{ "name": "c", "image": "busybox:latest" }]
                    }
                }
            }
        });
        client.create_daemonset(ns, ds).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        // Only node-1 matches
        assert!(client.get_pod(ns, "complex-ds-node-1").await.is_ok());
        assert!(client.get_pod(ns, "complex-ds-node-2").await.is_err());

        let ds_obj = client.get_daemonset(ns, "complex-ds").await.unwrap();
        assert_eq!(ds_obj["status"]["desiredNumberScheduled"], 1);
        assert_eq!(ds_obj["status"]["currentNumberScheduled"], 1);
        assert_eq!(ds_obj["status"]["updatedNumberScheduled"], 1);

        // Dynamically add label zone: east to node-2
        let mut node2_obj = client.get_node("node-2").await.unwrap();
        node2_obj["metadata"]["labels"]["zone"] = json!("east");
        client.update_node("node-2", node2_obj).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        // Now both node-1 and node-2 should have a pod
        assert!(client.get_pod(ns, "complex-ds-node-1").await.is_ok());
        assert!(client.get_pod(ns, "complex-ds-node-2").await.is_ok());

        let ds_obj2 = client.get_daemonset(ns, "complex-ds").await.unwrap();
        assert_eq!(ds_obj2["status"]["desiredNumberScheduled"], 2);
        assert_eq!(ds_obj2["status"]["currentNumberScheduled"], 2);
        assert_eq!(ds_obj2["status"]["updatedNumberScheduled"], 2);

        // Dynamically mutate/remove label from node-1
        let mut node1_obj = client.get_node("node-1").await.unwrap();
        node1_obj["metadata"]["labels"]["zone"] = json!("north");
        client.update_node("node-1", node1_obj).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        // Pod on node-1 must be deleted
        assert!(client.get_pod(ns, "complex-ds-node-1").await.is_err());
        assert!(client.get_pod(ns, "complex-ds-node-2").await.is_ok());

        let ds_obj3 = client.get_daemonset(ns, "complex-ds").await.unwrap();
        assert_eq!(ds_obj3["status"]["desiredNumberScheduled"], 1);
        assert_eq!(ds_obj3["status"]["currentNumberScheduled"], 1);
        assert_eq!(ds_obj3["status"]["updatedNumberScheduled"], 1);
    }

    #[tokio::test]
    async fn test_daemonset_node_affinity_and_unschedulable_node() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "ds-affinity-ns";
        client.create_namespace(ns).await.unwrap();

        let node_gpu = json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "node-gpu",
                "labels": { "accelerator": "nvidia-h100" }
            }
        });
        client.create_node(node_gpu).await.unwrap();

        let ds = json!({
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": { "name": "gpu-monitor", "namespace": ns },
            "spec": {
                "selector": { "matchLabels": { "app": "gpu-monitor" } },
                "template": {
                    "metadata": { "labels": { "app": "gpu-monitor" } },
                    "spec": {
                        "affinity": {
                            "nodeAffinity": {
                                "requiredDuringSchedulingIgnoredDuringExecution": {
                                    "nodeSelectorTerms": [{
                                        "matchExpressions": [{
                                            "key": "accelerator",
                                            "operator": "In",
                                            "values": ["nvidia-h100", "nvidia-a100"]
                                        }]
                                    }]
                                }
                            }
                        },
                        "containers": [{ "name": "c", "image": "nvidia/cuda:latest" }]
                    }
                }
            }
        });
        client.create_daemonset(ns, ds).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        assert!(client.get_pod(ns, "gpu-monitor-node-gpu").await.is_ok());

        // Mark node as unschedulable
        let mut node_obj = client.get_node("node-gpu").await.unwrap();
        node_obj["spec"] = json!({ "unschedulable": true });
        client.update_node("node-gpu", node_obj).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        assert!(client.get_pod(ns, "gpu-monitor-node-gpu").await.is_err());

        let ds_obj = client.get_daemonset(ns, "gpu-monitor").await.unwrap();
        assert_eq!(ds_obj["status"]["desiredNumberScheduled"], 0);
        assert_eq!(ds_obj["status"]["currentNumberScheduled"], 0);
    }

    #[tokio::test]
    async fn test_daemonset_companion_worker_pod_naming() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "ds-companion-ns";
        client.create_namespace(ns).await.unwrap();

        let primary_node = json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "diorama",
                "labels": { "kubernetes.io/hostname": "diorama" }
            }
        });
        client.create_node(primary_node).await.unwrap();

        let worker_node = json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "diorama-worker",
                "labels": { "kubernetes.io/hostname": "diorama-worker" }
            }
        });
        client.create_node(worker_node).await.unwrap();

        let ds = json!({
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {
                "name": "marker",
                "namespace": ns
            },
            "spec": {
                "selector": {
                    "matchLabels": { "app": "marker" }
                },
                "template": {
                    "metadata": {
                        "labels": { "app": "marker" }
                    },
                    "spec": {
                        "containers": [{
                            "name": "marker",
                            "image": "registry.k8s.io/pause:3.9"
                        }]
                    }
                }
            }
        });
        client.create_daemonset(ns, ds).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let primary_pod = client
            .get_pod(ns, "marker-node")
            .await
            .expect("marker-node must exist");
        assert_eq!(
            primary_pod
                .pointer("/spec/nodeName")
                .and_then(Value::as_str),
            Some("diorama")
        );

        let worker_pod = client
            .get_pod(ns, "marker-diorama-worker")
            .await
            .expect("marker-diorama-worker must exist");
        assert_eq!(
            worker_pod.pointer("/spec/nodeName").and_then(Value::as_str),
            Some("diorama-worker")
        );

        let ds_obj = client.get_daemonset(ns, "marker").await.unwrap();
        assert_eq!(ds_obj["status"]["desiredNumberScheduled"], 2);
    }

    #[tokio::test]
    async fn test_cronjob_concurrency_policies_and_suspend() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "cj-conformance-ns";
        client.create_namespace(ns).await.unwrap();

        // 1. Suspended CronJob must not schedule jobs
        let cj_suspended = json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": { "name": "cj-susp", "namespace": ns },
            "spec": {
                "suspend": true,
                "schedule": "*/1 * * * *",
                "jobTemplate": {
                    "spec": { "template": { "spec": { "containers": [{ "name": "c", "image": "busybox" }] } } }
                }
            }
        });
        client.create_cronjob(ns, cj_suspended).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let jobs_list = client.list_jobs(ns).await.unwrap();
        assert_eq!(
            jobs_list["items"].as_array().unwrap().len(),
            0,
            "Suspended CronJob must not create jobs"
        );

        // 2. Unsuspend with ForbidConcurrent
        let mut cj_forbid = client.get_cronjob(ns, "cj-susp").await.unwrap();
        cj_forbid["spec"]["suspend"] = json!(false);
        cj_forbid["spec"]["concurrencyPolicy"] = json!("Forbid");
        client
            .update_cronjob(ns, "cj-susp", cj_forbid)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let child1 = client.get_job(ns, "cj-susp-scheduled").await.unwrap();
        assert_eq!(child1["metadata"]["name"], "cj-susp-scheduled");

        let cj_after_sched = client.get_cronjob(ns, "cj-susp").await.unwrap();
        let active = cj_after_sched["status"]["active"].as_array().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0]["name"], "cj-susp-scheduled");

        // Reconcile again: Forbid policy must not schedule another job while child is active
        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let jobs_after_forbid = client.list_jobs(ns).await.unwrap();
        assert_eq!(jobs_after_forbid["items"].as_array().unwrap().len(), 1);

        // 3. Update to Replace policy
        let mut cj_replace = client.get_cronjob(ns, "cj-susp").await.unwrap();
        cj_replace["spec"]["concurrencyPolicy"] = json!("Replace");
        client
            .update_cronjob(ns, "cj-susp", cj_replace)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        // Old child should be replaced
        let cj_after_replace = client.get_cronjob(ns, "cj-susp").await.unwrap();
        let active_replace = cj_after_replace["status"]["active"].as_array().unwrap();
        assert_eq!(active_replace.len(), 1);
    }

    #[tokio::test]
    async fn test_job_suspend_resume_and_indexed_hostname() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "job-conformance-ns";
        client.create_namespace(ns).await.unwrap();

        // 1. Create suspended Job
        let job = json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "suspend-job", "namespace": ns },
            "spec": {
                "suspend": true,
                "parallelism": 2,
                "template": {
                    "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
                }
            }
        });
        client.create_job(ns, job).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let pods_during_suspend = client.list_pods(ns).await.unwrap();
        assert_eq!(pods_during_suspend["items"].as_array().unwrap().len(), 0);

        let suspended_job = client.get_job(ns, "suspend-job").await.unwrap();
        assert_eq!(suspended_job["status"]["active"], 0);
        let conds = suspended_job["status"]["conditions"].as_array().unwrap();
        let susp_cond = conds.iter().find(|c| c["type"] == "Suspended").unwrap();
        assert_eq!(susp_cond["status"], "True");
        assert_eq!(susp_cond["reason"], "JobSuspended");

        // Resume Job
        let mut job_resumed = suspended_job.clone();
        job_resumed["spec"]["suspend"] = json!(false);
        client
            .update_job(ns, "suspend-job", job_resumed)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let pods_resumed = client.list_pods(ns).await.unwrap();
        assert_eq!(pods_resumed["items"].as_array().unwrap().len(), 2);

        let active_job = client.get_job(ns, "suspend-job").await.unwrap();
        assert_eq!(active_job["status"]["active"], 2);

        // 2. Indexed Job creates pods with completion index and hostname
        let indexed_job = json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "indexed-job", "namespace": ns },
            "spec": {
                "completionMode": "Indexed",
                "completions": 2,
                "parallelism": 2,
                "template": {
                    "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
                }
            }
        });
        client.create_job(ns, indexed_job).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let p0 = client.get_pod(ns, "indexed-job-0").await.unwrap();
        assert_eq!(
            p0["metadata"]["labels"]["batch.kubernetes.io/job-completion-index"],
            "0"
        );
        assert_eq!(p0["spec"]["hostname"], "indexed-job-0");

        let p1 = client.get_pod(ns, "indexed-job-1").await.unwrap();
        assert_eq!(
            p1["metadata"]["labels"]["batch.kubernetes.io/job-completion-index"],
            "1"
        );
        assert_eq!(p1["spec"]["hostname"], "indexed-job-1");
    }

    #[tokio::test]
    async fn test_statefulset_pvc_retention_policy_and_scaling() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "ss-retention-ns";
        client.create_namespace(ns).await.unwrap();

        let ss = json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "pvc-ss", "namespace": ns },
            "spec": {
                "replicas": 2,
                "podManagementPolicy": "Parallel",
                "persistentVolumeClaimRetentionPolicy": {
                    "whenDeleted": "Delete",
                    "whenScaled": "Delete"
                },
                "volumeClaimTemplates": [{
                    "metadata": { "name": "data" },
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": { "requests": { "storage": "1Gi" } }
                    }
                }],
                "template": {
                    "metadata": { "labels": { "app": "pvc-ss" } },
                    "spec": {
                        "containers": [{ "name": "c", "image": "redis:7" }]
                    }
                }
            }
        });
        client.create_statefulset(ns, ss).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        // Verify ordinal pods and PVCs created
        let pvc0 = client.get_pvc(ns, "data-pvc-ss-0").await.unwrap();
        let pvc1 = client.get_pvc(ns, "data-pvc-ss-1").await.unwrap();
        assert_eq!(pvc0["metadata"]["name"], "data-pvc-ss-0");
        assert_eq!(pvc1["metadata"]["name"], "data-pvc-ss-1");

        let owner_refs = pvc0["metadata"]["ownerReferences"].as_array().unwrap();
        assert_eq!(owner_refs[0]["kind"], "StatefulSet");

        let pod0 = client.get_pod(ns, "pvc-ss-0").await.unwrap();
        let vols = pod0["spec"]["volumes"].as_array().unwrap();
        let data_vol = vols.iter().find(|v| v["name"] == "data").unwrap();
        assert_eq!(
            data_vol["persistentVolumeClaim"]["claimName"],
            "data-pvc-ss-0"
        );

        // Scale down to 1: whenScaled=Delete must delete PVC 1
        let mut ss_scale = client.get_statefulset(ns, "pvc-ss").await.unwrap();
        ss_scale["spec"]["replicas"] = json!(1);
        client
            .update_statefulset(ns, "pvc-ss", ss_scale)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        assert!(client.get_pod(ns, "pvc-ss-0").await.is_ok());
        assert!(client.get_pod(ns, "pvc-ss-1").await.is_err());

        assert!(client.get_pvc(ns, "data-pvc-ss-0").await.is_ok());
        assert!(
            client.get_pvc(ns, "data-pvc-ss-1").await.is_err(),
            "PVC for pruned ordinal must be deleted under whenScaled: Delete"
        );
    }

    #[tokio::test]
    async fn test_endpointslice_unnamed_port_has_name_empty_string() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-eps-unnamed-port";
        client.create_namespace(ns).await.unwrap();

        let service = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "unnamed-port-svc", "namespace": ns },
            "spec": {
                "selector": { "app": "web" },
                "ports": [{ "port": 80, "protocol": "TCP" }]
            }
        });
        client.create_service(ns, service).await.unwrap();

        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "web-pod-1", "namespace": ns, "labels": { "app": "web" } },
            "spec": { "containers": [{ "name": "c", "image": "test:latest" }] },
            "status": {
                "phase": "Running",
                "podIP": "10.244.0.11",
                "conditions": [{ "type": "Ready", "status": "True" }]
            }
        });
        client.create_pod(ns, pod).await.unwrap();
        wm.reconcile_namespace(ns).await.unwrap();

        let slice = client
            .get_endpointslice(ns, "unnamed-port-svc-1")
            .await
            .unwrap();
        let ports = slice.get("ports").and_then(Value::as_array).unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0]["name"], "");
        assert_eq!(ports[0]["port"], 80);
    }

    #[tokio::test]
    async fn test_cronjob_concurrency_policy_allow_schedules_concurrent_jobs() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-cj-allow";
        client.create_namespace(ns).await.unwrap();

        let cj = json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": { "name": "my-cj", "namespace": ns },
            "spec": {
                "schedule": "* * * * *",
                "concurrencyPolicy": "Allow",
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "restartPolicy": "Never",
                                "containers": [{ "name": "c", "image": "busybox" }]
                            }
                        }
                    }
                }
            }
        });
        client.create_cronjob(ns, cj).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let cj1 = client.get_cronjob(ns, "my-cj").await.unwrap();
        let active1 = cj1
            .pointer("/status/active")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(active1.len(), 1);
        assert_eq!(active1[0]["name"], "my-cj-scheduled");
        assert!(client.get_job(ns, "my-cj-scheduled").await.is_ok());

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let cj2 = client.get_cronjob(ns, "my-cj").await.unwrap();
        let active2 = cj2
            .pointer("/status/active")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(active2.len(), 2);
        assert!(active2.iter().any(|j| j["name"] == "my-cj-scheduled"));
        assert!(active2.iter().any(|j| j["name"] == "my-cj-scheduled-1"));
        assert!(client.get_job(ns, "my-cj-scheduled-1").await.is_ok());
    }

    #[tokio::test]
    async fn test_cronjob_concurrency_policy_replace_replaces_old_job_with_distinct_name() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-cj-replace";
        client.create_namespace(ns).await.unwrap();

        let cj = json!({
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": { "name": "replace-cj", "namespace": ns },
            "spec": {
                "schedule": "* * * * *",
                "concurrencyPolicy": "Replace",
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "restartPolicy": "Never",
                                "containers": [{ "name": "c", "image": "busybox" }]
                            }
                        }
                    }
                }
            }
        });
        client.create_cronjob(ns, cj).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let cj1 = client.get_cronjob(ns, "replace-cj").await.unwrap();
        let active1 = cj1
            .pointer("/status/active")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(active1.len(), 1);
        let first_job_name = active1[0]["name"].as_str().unwrap().to_string();
        assert_eq!(first_job_name, "replace-cj-scheduled");

        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "replace-cj-pod-1",
                "namespace": ns,
                "labels": { "job-name": first_job_name },
                "ownerReferences": [{
                    "apiVersion": "batch/v1",
                    "kind": "Job",
                    "name": first_job_name,
                    "uid": "fake-uid"
                }]
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] }
        });
        client.create_pod(ns, pod).await.unwrap();

        let past_time = diorama_apiserver::time::rfc3339_seconds(
            diorama_apiserver::time::now_unix().saturating_sub(5),
        );
        let mut cj_modified = cj1.clone();
        cj_modified["status"]["lastScheduleTime"] = json!(past_time);
        client
            .update_cronjob(ns, "replace-cj", cj_modified)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let cj2 = client.get_cronjob(ns, "replace-cj").await.unwrap();
        let active2 = cj2
            .pointer("/status/active")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(active2.len(), 1);
        let second_job_name = active2[0]["name"].as_str().unwrap().to_string();
        assert_ne!(first_job_name, second_job_name);
        assert_eq!(second_job_name, "replace-cj-scheduled-1");

        assert!(client.get_job(ns, &first_job_name).await.is_err());
        assert!(client.get_pod(ns, "replace-cj-pod-1").await.is_err());
        assert!(client.get_job(ns, &second_job_name).await.is_ok());
    }

    #[tokio::test]
    async fn test_statefulset_scale_down_unready_pod() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-ss-scale-unready";
        client.create_namespace(ns).await.unwrap();

        let ss = json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "ss-unready", "namespace": ns },
            "spec": {
                "replicas": 2,
                "template": {
                    "metadata": { "labels": { "app": "test" } },
                    "spec": { "containers": [{ "name": "c", "image": "test:latest" }] }
                }
            }
        });
        client.create_statefulset(ns, ss).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        assert!(client.get_pod(ns, "ss-unready-0").await.is_ok());
        assert!(client.get_pod(ns, "ss-unready-1").await.is_ok());

        let mut pod1 = client.get_pod(ns, "ss-unready-1").await.unwrap();
        pod1["status"]["conditions"] = json!([{ "type": "Ready", "status": "False" }]);
        client.update_pod(ns, "ss-unready-1", pod1).await.unwrap();

        let mut ss_scale = client.get_statefulset(ns, "ss-unready").await.unwrap();
        ss_scale["spec"]["replicas"] = json!(0);
        client
            .update_statefulset(ns, "ss-unready", ss_scale)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        assert!(
            client.get_pod(ns, "ss-unready-1").await.is_err(),
            "Unready pod-1 should be pruned during scale-down to 0"
        );
    }

    #[tokio::test]
    async fn test_statefulset_rolling_update_current_revision_tracking() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-ss-revisions";
        client.create_namespace(ns).await.unwrap();

        let ss = json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "ss-rev", "namespace": ns },
            "spec": {
                "replicas": 3,
                "template": {
                    "metadata": { "labels": { "app": "test" } },
                    "spec": { "containers": [{ "name": "c", "image": "v1" }] }
                }
            }
        });
        client.create_statefulset(ns, ss).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let ss1 = client.get_statefulset(ns, "ss-rev").await.unwrap();
        let rev1 = ss1
            .pointer("/status/currentRevision")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let update1 = ss1
            .pointer("/status/updateRevision")
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(rev1, update1);

        let mut ss_patch = ss1.clone();
        ss_patch["spec"]["template"]["spec"]["containers"][0]["image"] = json!("v2");
        ss_patch["spec"]["updateStrategy"] = json!({
            "type": "RollingUpdate",
            "rollingUpdate": { "partition": 2 }
        });
        client
            .update_statefulset(ns, "ss-rev", ss_patch)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let ss2 = client.get_statefulset(ns, "ss-rev").await.unwrap();
        let current_rev2 = ss2
            .pointer("/status/currentRevision")
            .and_then(Value::as_str)
            .unwrap();
        let update_rev2 = ss2
            .pointer("/status/updateRevision")
            .and_then(Value::as_str)
            .unwrap();

        assert_eq!(current_rev2, rev1);
        assert_ne!(current_rev2, update_rev2);
    }

    #[tokio::test]
    async fn test_job_status_terminating_field_and_orphan_adoption_fallback_selector() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-job-orphan-terminating";
        client.create_namespace(ns).await.unwrap();

        let orphan_pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "worker-orphan-pod",
                "namespace": ns,
                "labels": { "app": "worker-orphan" }
            },
            "spec": { "containers": [{ "name": "c", "image": "busybox" }] },
            "status": { "phase": "Running" }
        });
        client.create_pod(ns, orphan_pod).await.unwrap();

        let job = json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "orphan-adopting-job", "namespace": ns },
            "spec": {
                "template": {
                    "metadata": { "labels": { "app": "worker-orphan" } },
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{ "name": "c", "image": "busybox" }]
                    }
                }
            }
        });
        client.create_job(ns, job).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let adopted_pod = client.get_pod(ns, "worker-orphan-pod").await.unwrap();
        let owners = adopted_pod
            .pointer("/metadata/ownerReferences")
            .and_then(Value::as_array)
            .unwrap();
        assert!(
            owners
                .iter()
                .any(|o| o["kind"] == "Job" && o["name"] == "orphan-adopting-job"),
            "Orphan pod should have been adopted by the Job"
        );

        let job_status = client.get_job(ns, "orphan-adopting-job").await.unwrap();
        assert_eq!(job_status.pointer("/status/terminating"), Some(&json!(0)));

        let mut term_pod = adopted_pod.clone();
        term_pod["metadata"]["deletionTimestamp"] = json!(diorama_apiserver::time::now_rfc3339());
        client
            .update_pod(ns, "worker-orphan-pod", term_pod)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let job_status_after = client.get_job(ns, "orphan-adopting-job").await.unwrap();
        assert_eq!(
            job_status_after.pointer("/status/terminating"),
            Some(&json!(1)),
            "status.terminating should count terminating pods"
        );
    }

    #[tokio::test]
    async fn test_endpointslice_per_pod_port_resolution_distinct_slices() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-eps-per-pod-ports";
        client.create_namespace(ns).await.unwrap();

        let service = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "multi-target-svc", "namespace": ns },
            "spec": {
                "selector": { "app": "multi-target" },
                "ports": [{ "name": "port100", "port": 80, "targetPort": "port100", "protocol": "TCP" }]
            }
        });
        client.create_service(ns, service).await.unwrap();

        let pod1 = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "target-pod-1", "namespace": ns, "labels": { "app": "multi-target" } },
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "test:latest",
                    "ports": [{ "name": "port100", "containerPort": 100, "protocol": "TCP" }]
                }]
            },
            "status": {
                "phase": "Running",
                "podIP": "10.244.0.10",
                "conditions": [{ "type": "Ready", "status": "True" }]
            }
        });
        let pod2 = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "target-pod-2", "namespace": ns, "labels": { "app": "multi-target" } },
            "spec": {
                "containers": [{
                    "name": "c",
                    "image": "test:latest",
                    "ports": [{ "name": "port100", "containerPort": 101, "protocol": "TCP" }]
                }]
            },
            "status": {
                "phase": "Running",
                "podIP": "10.244.0.11",
                "conditions": [{ "type": "Ready", "status": "True" }]
            }
        });
        client.create_pod(ns, pod1).await.unwrap();
        client.create_pod(ns, pod2).await.unwrap();
        wm.reconcile_namespace(ns).await.unwrap();

        let list = client.list_endpointslices(ns).await.unwrap();
        let items = list["items"].as_array().unwrap();
        let svc_slices: Vec<&Value> = items
            .iter()
            .filter(|s| {
                s.pointer("/metadata/labels/kubernetes.io~1service-name")
                    == Some(&json!("multi-target-svc"))
            })
            .collect();

        assert_eq!(
            svc_slices.len(),
            2,
            "Expected 2 slices for 2 distinct resolved port numbers"
        );
        let ports: Vec<i64> = svc_slices
            .iter()
            .map(|s| s.pointer("/ports/0/port").and_then(Value::as_i64).unwrap())
            .collect();
        assert!(ports.contains(&100));
        assert!(ports.contains(&101));
    }

    #[tokio::test]
    async fn test_endpoints_and_endpointslice_hostname_populated() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-ep-hostname";
        client.create_namespace(ns).await.unwrap();

        let service = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "host-svc", "namespace": ns },
            "spec": {
                "selector": { "app": "host" },
                "ports": [{ "port": 80, "protocol": "TCP" }]
            }
        });
        client.create_service(ns, service).await.unwrap();

        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "host-pod", "namespace": ns, "labels": { "app": "host" } },
            "spec": {
                "hostname": "my-host-name",
                "subdomain": "not-service-name",
                "containers": [{ "name": "c", "image": "test:latest" }]
            },
            "status": {
                "phase": "Running",
                "podIP": "10.244.0.22",
                "conditions": [{ "type": "Ready", "status": "True" }]
            }
        });
        client.create_pod(ns, pod).await.unwrap();
        wm.reconcile_namespace(ns).await.unwrap();

        let ep = client.get_endpoints(ns, "host-svc").await.unwrap();
        let ep_hostname = ep
            .pointer("/subsets/0/addresses/0/hostname")
            .and_then(Value::as_str);
        assert_eq!(ep_hostname, Some("my-host-name"));

        let slice = client.get_endpointslice(ns, "host-svc-1").await.unwrap();
        let slice_hostname = slice
            .pointer("/endpoints/0/hostname")
            .and_then(Value::as_str);
        assert_eq!(slice_hostname, Some("my-host-name"));
    }

    #[tokio::test]
    async fn test_selectorless_service_manual_endpoints_and_slices_preserved() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-manual-headless";
        client.create_namespace(ns).await.unwrap();

        let service = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "manual-svc", "namespace": ns },
            "spec": {
                "clusterIP": "None",
                "ports": [{ "port": 443, "protocol": "TCP" }]
            }
        });
        client.create_service(ns, service).await.unwrap();

        let manual_ep = json!({
            "apiVersion": "v1",
            "kind": "Endpoints",
            "metadata": { "name": "manual-svc", "namespace": ns },
            "subsets": [{
                "addresses": [{ "ip": "192.168.1.100" }],
                "ports": [{ "port": 443, "protocol": "TCP" }]
            }]
        });
        client.create_endpoints(ns, manual_ep).await.unwrap();

        let manual_slice = json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "manual-svc-custom",
                "namespace": ns,
                "labels": {
                    "kubernetes.io/service-name": "manual-svc",
                    "endpointslice.kubernetes.io/managed-by": "custom-admin"
                }
            },
            "addressType": "IPv4",
            "ports": [{ "port": 443, "protocol": "TCP" }],
            "endpoints": [{ "addresses": ["192.168.1.100"], "conditions": { "ready": true } }]
        });
        client.create_endpointslice(ns, manual_slice).await.unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let ep_after = client.get_endpoints(ns, "manual-svc").await.unwrap();
        assert_eq!(
            ep_after.pointer("/subsets/0/addresses/0/ip"),
            Some(&json!("192.168.1.100"))
        );

        let slice_after = client
            .get_endpointslice(ns, "manual-svc-custom")
            .await
            .unwrap();
        assert_eq!(
            slice_after.pointer("/endpoints/0/addresses/0"),
            Some(&json!("192.168.1.100"))
        );
    }

    #[tokio::test]
    async fn test_service_port_update_reconciles_promptly() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-service-port-update";
        client.create_namespace(ns).await.unwrap();

        let service = json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "port-svc", "namespace": ns },
            "spec": {
                "selector": { "app": "port-app" },
                "ports": [{ "name": "http", "port": 80, "targetPort": 8080, "protocol": "TCP" }]
            }
        });
        client.create_service(ns, service).await.unwrap();

        let pod = json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "port-pod", "namespace": ns, "labels": { "app": "port-app" } },
            "spec": { "containers": [{ "name": "c", "image": "test:latest" }] },
            "status": {
                "phase": "Running",
                "podIP": "10.244.0.33",
                "conditions": [{ "type": "Ready", "status": "True" }]
            }
        });
        client.create_pod(ns, pod).await.unwrap();
        wm.reconcile_namespace(ns).await.unwrap();

        let slice1 = client.get_endpointslice(ns, "port-svc-1").await.unwrap();
        assert_eq!(slice1.pointer("/ports/0/port"), Some(&json!(8080)));

        let mut updated_svc = client.get_service(ns, "port-svc").await.unwrap();
        updated_svc["spec"]["ports"] =
            json!([{ "name": "http", "port": 80, "targetPort": 9090, "protocol": "TCP" }]);
        client
            .update_service(ns, "port-svc", updated_svc)
            .await
            .unwrap();

        wm.reconcile_namespace(ns).await.unwrap();

        let slice2 = client.get_endpointslice(ns, "port-svc-1").await.unwrap();
        assert_eq!(slice2.pointer("/ports/0/port"), Some(&json!(9090)));
    }

    #[tokio::test]
    async fn test_replicationcontroller_replica_failure_condition_on_create_error() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-rc-replica-failure";
        client.create_namespace(ns).await.unwrap();

        let rc = json!({
            "apiVersion": "v1",
            "kind": "ReplicationController",
            "metadata": { "name": "failing-rc", "namespace": ns },
            "spec": {
                "replicas": 1,
                "template": {
                    "metadata": { "labels": { "app": "failing-rc" } },
                    "spec": {
                        "runtimeClassName": "non-existent-runtime-class",
                        "containers": [{ "name": "c", "image": "test:latest" }]
                    }
                }
            }
        });
        client.create_replicationcontroller(ns, rc).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let rc_status = client
            .get_replicationcontroller(ns, "failing-rc")
            .await
            .unwrap();
        let conditions = rc_status
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .unwrap();
        let fail_cond = conditions
            .iter()
            .find(|c| c["type"] == "ReplicaFailure")
            .expect("ReplicaFailure condition");
        assert_eq!(fail_cond["status"], "True");
        assert_eq!(fail_cond["reason"], "FailedCreate");

        let mut fixed_rc = client
            .get_replicationcontroller(ns, "failing-rc")
            .await
            .unwrap();
        fixed_rc["spec"]["template"]["spec"] = json!({
            "containers": [{ "name": "c", "image": "test:latest" }]
        });
        client
            .update_replicationcontroller(ns, "failing-rc", fixed_rc)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let rc_fixed = client
            .get_replicationcontroller(ns, "failing-rc")
            .await
            .unwrap();
        let fixed_conditions = rc_fixed
            .pointer("/status/conditions")
            .and_then(Value::as_array);
        if let Some(conds) = fixed_conditions {
            assert!(conds.iter().all(|c| c["type"] != "ReplicaFailure"));
        }
    }

    #[tokio::test]
    async fn test_replicaset_replica_failure_condition_on_create_error() {
        let temp = TempDir::new().unwrap();
        let svc = setup_controller(&temp);
        svc.start().await.unwrap();
        let client = svc.client();
        let wm = svc.workload_manager();
        let ns = "test-rs-replica-failure";
        client.create_namespace(ns).await.unwrap();

        let rs = json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "failing-rs", "namespace": ns },
            "spec": {
                "replicas": 1,
                "selector": { "matchLabels": { "app": "failing-rs" } },
                "template": {
                    "metadata": { "labels": { "app": "failing-rs" } },
                    "spec": {
                        "runtimeClassName": "non-existent-runtime-class",
                        "containers": [{ "name": "c", "image": "test:latest" }]
                    }
                }
            }
        });
        client.create_replicaset(ns, rs).await.unwrap();
        let _ = wm.reconcile_namespace(ns).await.unwrap();

        let rs_status = client.get_replicaset(ns, "failing-rs").await.unwrap();
        let conditions = rs_status
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .unwrap();
        let fail_cond = conditions
            .iter()
            .find(|c| c["type"] == "ReplicaFailure")
            .expect("ReplicaFailure condition");
        assert_eq!(fail_cond["status"], "True");
        assert_eq!(fail_cond["reason"], "FailedCreate");

        let mut fixed_rs = client.get_replicaset(ns, "failing-rs").await.unwrap();
        fixed_rs["spec"]["template"]["spec"] = json!({
            "containers": [{ "name": "c", "image": "test:latest" }]
        });
        client
            .update_replicaset(ns, "failing-rs", fixed_rs)
            .await
            .unwrap();

        let _ = wm.reconcile_namespace(ns).await.unwrap();
        let rs_fixed = client.get_replicaset(ns, "failing-rs").await.unwrap();
        let fixed_conditions = rs_fixed
            .pointer("/status/conditions")
            .and_then(Value::as_array);
        if let Some(conds) = fixed_conditions {
            assert!(conds.iter().all(|c| c["type"] != "ReplicaFailure"));
        }
    }
}
