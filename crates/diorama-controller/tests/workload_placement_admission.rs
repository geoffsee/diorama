#![allow(clippy::too_many_lines)]

use std::net::IpAddr;
use std::sync::Arc;
use tempfile::TempDir;

use diorama_apiserver::{ApiserverConfig, ApiserverError, ApiserverService, KubernetesStorage};
use diorama_controller::webhook::{NodeSetterHandler, WebhookConfig, WebhookService};
use diorama_controller::{ControllerManagerConfig, ControllerManagerService};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use serde_json::json;

fn setup_test_cluster(
    dir: &TempDir,
) -> (
    Arc<ApiserverService>,
    WebhookService,
    ControllerManagerService,
) {
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
    let apiserver_service = Arc::new(ApiserverService::new(apiserver_config, storage));

    let mut webhook_config =
        WebhookConfig::default_for_pki(&pki_dir, "test-node", "192.0.2.9", true);
    webhook_config.port = 0; // ephemeral port for test isolation
    let webhook_service = WebhookService::new(webhook_config, apiserver_service.clone());

    let controller_config = ControllerManagerConfig::default_for_pki(&pki_dir, node_ip);
    let controller_service =
        ControllerManagerService::new(controller_config, apiserver_service.clone());

    (apiserver_service, webhook_service, controller_service)
}

#[tokio::test]
async fn test_unassigned_vs_explicit_pod_placement_and_immutability() {
    let temp = TempDir::new().unwrap();
    let (apiserver, webhook_service, _) = setup_test_cluster(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    webhook_service.check_prerequisites().await.unwrap();
    webhook_service.start().await.unwrap();

    let client = apiserver.admin_client();
    let ns = "test-pod-placement";
    client.create_namespace(ns).await.unwrap();

    // 1. Unassigned Pod: should receive spec.nodeName = "test-node" via NodeSetter mutating admission
    let unassigned_pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "unassigned-pod",
            "namespace": ns
        },
        "spec": {
            "containers": [{
                "name": "web",
                "image": "nginx:1.27"
            }]
        }
    });

    let created_unassigned = client.create_pod(ns, unassigned_pod).await.unwrap();
    assert_eq!(
        created_unassigned["spec"]["nodeName"], "test-node",
        "Unassigned pod must be assigned to test-node"
    );

    // 2. Explicitly assigned Pod: should remain unchanged
    let explicit_pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "explicit-pod",
            "namespace": ns
        },
        "spec": {
            "nodeName": "custom-worker-1",
            "containers": [{
                "name": "worker",
                "image": "busybox:1.36"
            }]
        }
    });

    let created_explicit = client.create_pod(ns, explicit_pod).await.unwrap();
    assert_eq!(
        created_explicit["spec"]["nodeName"], "custom-worker-1",
        "Explicitly assigned pod nodeName must not be modified"
    );

    // 3. Update Pod metadata with same nodeName: succeeds
    let mut pod_for_update = created_unassigned.clone();
    if let Some(labels) = pod_for_update
        .pointer_mut("/metadata/labels")
        .and_then(|v| v.as_object_mut())
    {
        labels.insert("updated".to_string(), json!("true"));
    } else if let Some(meta) = pod_for_update["metadata"].as_object_mut() {
        meta.insert("labels".to_string(), json!({"updated": "true"}));
    }

    let updated = client
        .update_pod(ns, "unassigned-pod", pod_for_update)
        .await
        .unwrap();
    assert_eq!(updated["spec"]["nodeName"], "test-node");
    assert_eq!(updated["metadata"]["labels"]["updated"], "true");

    // 4. Update Pod attempting to mutate spec.nodeName: fails with InvalidInput
    let mut illegal_update = updated.clone();
    illegal_update["spec"]["nodeName"] = json!("different-node");
    let err = client
        .update_pod(ns, "unassigned-pod", illegal_update)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApiserverError::InvalidInput { ref field, .. } if field == "spec.nodeName"),
        "Mutating spec.nodeName on UPDATE must fail, got: {err:?}"
    );

    // 5. Update Pod attempting to unset spec.nodeName: fails with InvalidInput
    let mut unset_update = updated.clone();
    unset_update["spec"]
        .as_object_mut()
        .unwrap()
        .remove("nodeName");
    let err2 = client
        .update_pod(ns, "unassigned-pod", unset_update)
        .await
        .unwrap_err();
    assert!(
        matches!(err2, ApiserverError::InvalidInput { ref field, .. } if field == "spec.nodeName"),
        "Unsetting spec.nodeName on UPDATE must fail, got: {err2:?}"
    );

    webhook_service.stop().await;
}

#[tokio::test]
async fn test_pvc_selected_node_annotation_and_preservation() {
    let temp = TempDir::new().unwrap();
    let (apiserver, webhook_service, _) = setup_test_cluster(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    webhook_service.check_prerequisites().await.unwrap();
    webhook_service.start().await.unwrap();

    let client = apiserver.admin_client();
    let ns = "test-pvc-placement";
    client.create_namespace(ns).await.unwrap();

    // 1. Unannotated PVC: should receive volume.kubernetes.io/selected-node: test-node
    let unannotated_pvc = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": "auto-pvc",
            "namespace": ns
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {
                "requests": {
                    "storage": "2Gi"
                }
            }
        }
    });

    let created_pvc = client.create_pvc(ns, unannotated_pvc).await.unwrap();
    assert_eq!(
        created_pvc["metadata"]["annotations"]["volume.kubernetes.io/selected-node"], "test-node",
        "Unassigned PVC must receive volume.kubernetes.io/selected-node annotation"
    );

    // 2. Explicitly annotated PVC: should remain unchanged and preserve other annotations
    let explicit_pvc = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": "explicit-pvc",
            "namespace": ns,
            "annotations": {
                "volume.kubernetes.io/selected-node": "storage-host-9",
                "custom.io/provisioner": "local-path"
            }
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {
                "requests": {
                    "storage": "5Gi"
                }
            }
        }
    });

    let created_explicit_pvc = client.create_pvc(ns, explicit_pvc).await.unwrap();
    assert_eq!(
        created_explicit_pvc["metadata"]["annotations"]["volume.kubernetes.io/selected-node"],
        "storage-host-9",
        "Explicitly selected-node annotation must be preserved"
    );
    assert_eq!(
        created_explicit_pvc["metadata"]["annotations"]["custom.io/provisioner"], "local-path",
        "Pre-existing annotations must be preserved"
    );

    // 3. Update PVC: NodeSetter CREATE-only rule does not overwrite or mutate on UPDATE
    let mut updated_pvc = created_pvc.clone();
    updated_pvc["metadata"]["annotations"]
        .as_object_mut()
        .unwrap()
        .insert("app.kubernetes.io/name".to_string(), json!("db"));
    let res = client
        .update_pvc(ns, "auto-pvc", updated_pvc)
        .await
        .unwrap();
    assert_eq!(
        res["metadata"]["annotations"]["volume.kubernetes.io/selected-node"],
        "test-node"
    );
    assert_eq!(
        res["metadata"]["annotations"]["app.kubernetes.io/name"],
        "db"
    );

    webhook_service.stop().await;
}

#[tokio::test]
async fn test_job_node_selector_and_immutability() {
    let temp = TempDir::new().unwrap();
    let (apiserver, webhook_service, _) = setup_test_cluster(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    webhook_service.check_prerequisites().await.unwrap();
    webhook_service.start().await.unwrap();

    let client = apiserver.admin_client();
    let ns = "test-job-placement";
    client.create_namespace(ns).await.unwrap();

    // 1. Unassigned Job: should receive kubernetes.io/hostname = test-node in template spec
    let unassigned_job = json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "auto-job",
            "namespace": ns
        },
        "spec": {
            "template": {
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [{
                        "name": "task",
                        "image": "busybox:1.36",
                        "command": ["echo", "hello"]
                    }]
                }
            }
        }
    });

    let created_job = client.create_job(ns, unassigned_job).await.unwrap();
    assert_eq!(
        created_job["spec"]["template"]["spec"]["nodeSelector"]["kubernetes.io/hostname"],
        "test-node",
        "Unassigned Job template must have nodeSelector kubernetes.io/hostname = test-node"
    );

    // 2. Explicitly assigned Job: preserves existing hostname and extra selectors
    let explicit_job = json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "explicit-job",
            "namespace": ns
        },
        "spec": {
            "template": {
                "spec": {
                    "nodeSelector": {
                        "kubernetes.io/hostname": "custom-node-42",
                        "topology.kubernetes.io/zone": "zone-a"
                    },
                    "restartPolicy": "Never",
                    "containers": [{
                        "name": "task",
                        "image": "busybox:1.36"
                    }]
                }
            }
        }
    });

    let created_explicit_job = client.create_job(ns, explicit_job).await.unwrap();
    let selectors = &created_explicit_job["spec"]["template"]["spec"]["nodeSelector"];
    assert_eq!(selectors["kubernetes.io/hostname"], "custom-node-42");
    assert_eq!(selectors["topology.kubernetes.io/zone"], "zone-a");

    // 3. Update Job metadata: succeeds
    let mut updated_job = created_job.clone();
    updated_job["metadata"]["labels"] = json!({"status": "processing"});
    let update_res = client
        .update_job(ns, "auto-job", updated_job)
        .await
        .unwrap();
    assert_eq!(update_res["metadata"]["labels"]["status"], "processing");

    // 4. Update Job template: rejected by apiserver as immutable
    let mut illegal_job_update = update_res.clone();
    illegal_job_update["spec"]["template"]["spec"]["containers"][0]["image"] =
        json!("busybox:latest");
    let err = client
        .update_job(ns, "auto-job", illegal_job_update)
        .await
        .unwrap_err();
    assert!(
        matches!(err, ApiserverError::InvalidInput { ref field, .. } if field == "spec.template"),
        "Updating spec.template on Job must be rejected as immutable, got: {err:?}"
    );

    // 5. Update Job removing spec.template entirely: rejected as immutable
    let mut remove_tmpl_job = update_res.clone();
    remove_tmpl_job["spec"]
        .as_object_mut()
        .unwrap()
        .remove("template");
    let err_remove = client
        .update_job(ns, "auto-job", remove_tmpl_job)
        .await
        .unwrap_err();
    assert!(
        matches!(err_remove, ApiserverError::InvalidInput { ref field, .. } if field == "spec.template"),
        "Removing spec.template on Job must be rejected as immutable, got: {err_remove:?}"
    );

    webhook_service.stop().await;
}

#[tokio::test]
async fn test_controller_workloads_execute_through_integrated_node() {
    let temp = TempDir::new().unwrap();
    let (apiserver, webhook_service, controller_service) = setup_test_cluster(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    webhook_service.check_prerequisites().await.unwrap();
    webhook_service.start().await.unwrap();

    controller_service.check_prerequisites().await.unwrap();
    controller_service.start().await.unwrap();

    let client = controller_service.client();
    let wm = controller_service.workload_manager();
    let ns = "test-controller-workloads";
    client.create_namespace(ns).await.unwrap();

    // 1. Deployment -> ReplicaSet -> Pods
    let deployment = json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "controller-deploy",
            "namespace": ns
        },
        "spec": {
            "replicas": 2,
            "selector": {
                "matchLabels": { "app": "controller-app" }
            },
            "template": {
                "metadata": {
                    "labels": { "app": "controller-app" }
                },
                "spec": {
                    "containers": [{
                        "name": "nginx",
                        "image": "nginx:1.27"
                    }]
                }
            }
        }
    });

    client.create_deployment(ns, deployment).await.unwrap();

    // Pass 1: Deployment -> ReplicaSet
    let _ = wm.reconcile_namespace(ns).await.unwrap();
    // Pass 2: ReplicaSet -> Pods
    let _ = wm.reconcile_namespace(ns).await.unwrap();

    let pods = client.list_pods(ns).await.unwrap();
    let items = pods["items"].as_array().unwrap();
    let deploy_pods: Vec<_> = items
        .iter()
        .filter(|p| {
            p["metadata"]["ownerReferences"]
                .as_array()
                .is_some_and(|owners| owners.iter().any(|o| o["kind"] == "ReplicaSet"))
        })
        .collect();
    assert_eq!(deploy_pods.len(), 2, "Expected 2 deployment-managed pods");
    for p in deploy_pods {
        assert_eq!(
            p["spec"]["nodeName"], "test-node",
            "All pods created by ReplicaSet controller must have nodeName = test-node"
        );
    }

    // 2. StatefulSet -> Pods
    let statefulset = json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": "controller-ss",
            "namespace": ns
        },
        "spec": {
            "replicas": 2,
            "template": {
                "metadata": {
                    "labels": { "app": "stateful-app" }
                },
                "spec": {
                    "containers": [{
                        "name": "redis",
                        "image": "redis:7"
                    }]
                }
            }
        }
    });

    client.create_statefulset(ns, statefulset).await.unwrap();
    let _ = wm.reconcile_namespace(ns).await.unwrap();

    let ss_pod_0 = client.get_pod(ns, "controller-ss-0").await.unwrap();
    let ss_pod_1 = client.get_pod(ns, "controller-ss-1").await.unwrap();
    assert_eq!(
        ss_pod_0["spec"]["nodeName"], "test-node",
        "StatefulSet ordinal pod 0 must be placed on test-node"
    );
    assert_eq!(
        ss_pod_1["spec"]["nodeName"], "test-node",
        "StatefulSet ordinal pod 1 must be placed on test-node"
    );

    // 3. DaemonSet -> Pods
    let daemonset = json!({
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": {
            "name": "controller-ds",
            "namespace": ns
        },
        "spec": {
            "template": {
                "metadata": {
                    "labels": { "app": "daemon-app" }
                },
                "spec": {
                    "containers": [{
                        "name": "fluentd",
                        "image": "fluentd:v1"
                    }]
                }
            }
        }
    });

    client.create_daemonset(ns, daemonset).await.unwrap();
    let _ = wm.reconcile_namespace(ns).await.unwrap();

    let ds_pods = client.list_pods(ns).await.unwrap();
    let ds_pod = ds_pods["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| {
            p["metadata"]["ownerReferences"]
                .as_array()
                .is_some_and(|owners| owners.iter().any(|o| o["kind"] == "DaemonSet"))
        })
        .expect("DaemonSet pod generated");
    assert_eq!(
        ds_pod["spec"]["nodeName"], "test-node",
        "DaemonSet pod must be placed on test-node"
    );

    // 4. CronJob -> Job -> Pods
    let cronjob = json!({
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {
            "name": "controller-cron",
            "namespace": ns
        },
        "spec": {
            "schedule": "*/1 * * * *",
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "restartPolicy": "Never",
                            "containers": [{
                                "name": "cron-worker",
                                "image": "busybox:1.36",
                                "command": ["echo", "cron-run"]
                            }]
                        }
                    }
                }
            }
        }
    });

    client.create_cronjob(ns, cronjob).await.unwrap();
    // Pass 1: CronJob -> Job
    let _ = wm.reconcile_namespace(ns).await.unwrap();

    let child_job = client
        .get_job(ns, "controller-cron-scheduled")
        .await
        .unwrap();
    assert_eq!(
        child_job["spec"]["template"]["spec"]["nodeSelector"]["kubernetes.io/hostname"],
        "test-node",
        "Child job created by CronJob controller must receive kubernetes.io/hostname selector"
    );

    // Pass 2: Job -> Pod
    let _ = wm.reconcile_namespace(ns).await.unwrap();

    let job_pod = client
        .get_pod(ns, "controller-cron-scheduled-0")
        .await
        .unwrap();
    assert_eq!(
        job_pod["spec"]["nodeName"], "test-node",
        "Pod generated by Job reconciler must be placed on test-node"
    );

    webhook_service.stop().await;
}

#[tokio::test]
async fn test_dry_run_placement_and_side_effect_isolation() {
    let temp = TempDir::new().unwrap();
    let (apiserver, webhook_service, _) = setup_test_cluster(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();

    webhook_service.check_prerequisites().await.unwrap();
    webhook_service.start().await.unwrap();

    let client = apiserver.admin_client();
    let ns = "test-dry-run-ns";
    client.create_namespace(ns).await.unwrap();

    // 1. Dry-run create Pod: returns mutated pod with nodeName, but does not persist
    let dry_pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "dry-run-pod",
            "namespace": ns
        },
        "spec": {
            "containers": [{
                "name": "dry-c",
                "image": "alpine:latest"
            }]
        }
    });

    let mutated_pod = client.create_pod_options(ns, dry_pod, true).await.unwrap();
    assert_eq!(
        mutated_pod["spec"]["nodeName"], "test-node",
        "Dry-run Pod creation must still evaluate mutating admission"
    );

    // Verify storage has no trace of this pod
    let get_res = client.get_pod(ns, "dry-run-pod").await;
    assert!(
        matches!(get_res, Err(ApiserverError::NotFound { .. })),
        "Dry-run Pod must NOT be saved in storage"
    );

    // 2. Dry-run create PVC: returns mutated PVC with selected-node annotation, but does not persist
    let dry_pvc = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": "dry-run-pvc",
            "namespace": ns
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "resources": {
                "requests": { "storage": "10Gi" }
            }
        }
    });

    let mutated_pvc = client.create_pvc_options(ns, dry_pvc, true).await.unwrap();
    assert_eq!(
        mutated_pvc["metadata"]["annotations"]["volume.kubernetes.io/selected-node"], "test-node",
        "Dry-run PVC creation must evaluate selected-node annotation"
    );

    let get_pvc_res = client.get_pvc(ns, "dry-run-pvc").await;
    assert!(
        matches!(get_pvc_res, Err(ApiserverError::NotFound { .. })),
        "Dry-run PVC must NOT be saved in storage"
    );

    // 3. Dry-run create Job: returns mutated Job with hostname selector, but does not persist
    let dry_job = json!({
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "dry-run-job",
            "namespace": ns
        },
        "spec": {
            "template": {
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [{
                        "name": "dry-job-c",
                        "image": "busybox:1.36"
                    }]
                }
            }
        }
    });

    let mutated_job = client.create_job_options(ns, dry_job, true).await.unwrap();
    assert_eq!(
        mutated_job["spec"]["template"]["spec"]["nodeSelector"]["kubernetes.io/hostname"],
        "test-node",
        "Dry-run Job creation must evaluate node selector mutation"
    );

    let get_job_res = client.get_job(ns, "dry-run-job").await;
    assert!(
        matches!(get_job_res, Err(ApiserverError::NotFound { .. })),
        "Dry-run Job must NOT be saved in storage"
    );

    // 4. Dry-run update on an existing persisted pod
    let persisted_pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "persisted-pod",
            "namespace": ns,
            "labels": { "ver": "v1" }
        },
        "spec": {
            "containers": [{
                "name": "nginx",
                "image": "nginx:1.27"
            }]
        }
    });
    let original = client.create_pod(ns, persisted_pod).await.unwrap();
    assert_eq!(original["metadata"]["labels"]["ver"], "v1");

    let mut dry_update = original.clone();
    dry_update["metadata"]["labels"]["ver"] = json!("v2");

    let dry_updated = client
        .update_pod_options(ns, "persisted-pod", dry_update, true)
        .await
        .unwrap();
    assert_eq!(dry_updated["metadata"]["labels"]["ver"], "v2");

    // Verify storage still retains v1
    let stored = client.get_pod(ns, "persisted-pod").await.unwrap();
    assert_eq!(
        stored["metadata"]["labels"]["ver"], "v1",
        "Persisted pod in storage must remain untouched after dry-run update"
    );

    // 5. NodeSetterHandler: dryRun: true produces no side-effects (locks remain empty)
    let handler = NodeSetterHandler::new("test-node", "192.0.2.9", true);
    let dry_svc_req = json!({
        "uid": "dry-svc-uid",
        "kind": { "group": "", "version": "v1", "kind": "Service" },
        "operation": "CREATE",
        "dryRun": true,
        "object": {
            "metadata": { "name": "lb-svc", "namespace": "default" },
            "spec": { "type": "LoadBalancer" }
        }
    });

    let (patch, scheduled) = handler.evaluate_mutation(&dry_svc_req).await.unwrap();
    assert!(patch.is_none());
    assert!(!scheduled, "Dry-run must not schedule status updates");
    assert!(
        handler.locks().lock().await.is_empty(),
        "Dry-run must not acquire locks"
    );

    webhook_service.stop().await;
}
