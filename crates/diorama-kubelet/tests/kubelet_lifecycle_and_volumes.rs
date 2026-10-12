#![allow(clippy::too_many_lines)]

use std::net::IpAddr;
use std::sync::Arc;
use tempfile::TempDir;

use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use dioramalet::{ExecResult, KubeletConfigOptions, KubeletService, MockRuntimeProvider};

fn setup_test_environment(
    dir: &TempDir,
) -> (
    ApiserverService,
    KubeletConfigOptions,
    DatastoreEngine,
    std::path::PathBuf,
) {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");
    let kubelet_dir = dir.path().join("kubelet");
    std::fs::create_dir_all(&kubelet_dir).unwrap();

    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_service = ApiserverService::new(apiserver_config, storage);

    let kubelet_options =
        KubeletConfigOptions::default_for_pki(&pki_dir, "test-node", "192.0.2.1", &kubelet_dir);

    (apiserver_service, kubelet_options, engine, pki_dir)
}

#[tokio::test]
async fn test_pod_lifecycle_probes_and_logs_exec_managed_runtime() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options, _engine, _pki_dir) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime.clone());
    kubelet.start().await.unwrap();

    let client = kubelet.client();

    // 1. Configure initial probe responses so both readiness and liveness pass
    runtime.set_exec_response(
        "cat /tmp/ready",
        ExecResult {
            exit_code: 0,
            stdout: "ready\n".to_string(),
            stderr: String::new(),
        },
    );
    runtime.set_exec_response(
        "cat /tmp/healthy",
        ExecResult {
            exit_code: 0,
            stdout: "healthy\n".to_string(),
            stderr: String::new(),
        },
    );

    // 2. Create pod with readinessProbe and livenessProbe
    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "lifecycle-managed-pod",
            "namespace": "default",
            "uid": "uid-lifecycle-managed"
        },
        "spec": {
            "nodeName": "test-node",
            "restartPolicy": "Always",
            "containers": [
                {
                    "name": "web",
                    "image": "docker.io/library/nginx:1.27",
                    "readinessProbe": {
                        "exec": {
                            "command": ["cat", "/tmp/ready"]
                        }
                    },
                    "livenessProbe": {
                        "exec": {
                            "command": ["cat", "/tmp/healthy"]
                        }
                    }
                }
            ]
        }
    });

    client.create_pod("default", pod_spec).await.unwrap();

    // Initial reconciliation
    let count = kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    assert_eq!(count, 1);

    // Verify initial Running state with Ready=True
    let pod = client
        .get_pod("default", "lifecycle-managed-pod")
        .await
        .unwrap();
    assert_eq!(pod["status"]["phase"], "Running");
    assert_eq!(pod["status"]["containerStatuses"][0]["ready"], true);
    assert_eq!(pod["status"]["containerStatuses"][0]["restartCount"], 0);

    let conditions = pod["status"]["conditions"].as_array().unwrap();
    let ready_cond = conditions
        .iter()
        .find(|c| c["type"] == "Ready")
        .expect("Ready condition");
    assert_eq!(ready_cond["status"], "True");

    // 3. Test logs fetching and tailing
    runtime.set_container_logs(
        "web",
        "line 1: start\nline 2: init\nline 3: listening\nline 4: request\nline 5: done\n",
    );
    let all_logs = kubelet
        .get_container_logs("uid-lifecycle-managed", "web", None)
        .await
        .unwrap();
    assert!(all_logs.contains("line 1: start"));
    assert!(all_logs.contains("line 5: done"));

    let tailed_logs = kubelet
        .get_container_logs("uid-lifecycle-managed", "web", Some(2))
        .await
        .unwrap();
    assert!(!tailed_logs.contains("line 1: start"));
    assert!(tailed_logs.contains("line 4: request"));
    assert!(tailed_logs.contains("line 5: done"));

    // 4. Test exec execution
    let echo_res = kubelet
        .exec_in_container(
            "uid-lifecycle-managed",
            "web",
            &[
                "echo".to_string(),
                "hello".to_string(),
                "kubelet".to_string(),
            ],
        )
        .await
        .unwrap();
    assert_eq!(echo_res.exit_code, 0);
    assert_eq!(echo_res.stdout.trim(), "hello kubelet");

    runtime.set_exec_response(
        "uname -a",
        ExecResult {
            exit_code: 0,
            stdout: "Linux diorama-node 6.6.0\n".to_string(),
            stderr: String::new(),
        },
    );
    let custom_exec = kubelet
        .exec_in_container(
            "uid-lifecycle-managed",
            "web",
            &["uname".to_string(), "-a".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(custom_exec.exit_code, 0);
    assert!(custom_exec.stdout.contains("Linux diorama-node"));

    // 5. Test readiness probe failure and recovery
    runtime.set_exec_response(
        "cat /tmp/ready",
        ExecResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "not ready\n".to_string(),
        },
    );

    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    let pod_unready = client
        .get_pod("default", "lifecycle-managed-pod")
        .await
        .unwrap();
    assert_eq!(
        pod_unready["status"]["containerStatuses"][0]["ready"],
        false
    );
    let conditions = pod_unready["status"]["conditions"].as_array().unwrap();
    let ready_cond = conditions
        .iter()
        .find(|c| c["type"] == "Ready")
        .expect("Ready condition");
    assert_eq!(ready_cond["status"], "False");

    // Recover readiness probe
    runtime.set_exec_response(
        "cat /tmp/ready",
        ExecResult {
            exit_code: 0,
            stdout: "ready again\n".to_string(),
            stderr: String::new(),
        },
    );
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    let pod_recovered = client
        .get_pod("default", "lifecycle-managed-pod")
        .await
        .unwrap();
    assert_eq!(
        pod_recovered["status"]["containerStatuses"][0]["ready"],
        true
    );
    let conditions = pod_recovered["status"]["conditions"].as_array().unwrap();
    let ready_cond = conditions
        .iter()
        .find(|c| c["type"] == "Ready")
        .expect("Ready condition");
    assert_eq!(ready_cond["status"], "True");

    // 6. Test liveness probe failure with container restart
    runtime.set_exec_response(
        "cat /tmp/healthy",
        ExecResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "deadlock\n".to_string(),
        },
    );

    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    let pod_restarted = client
        .get_pod("default", "lifecycle-managed-pod")
        .await
        .unwrap();
    assert_eq!(
        pod_restarted["status"]["containerStatuses"][0]["restartCount"],
        1
    );
    assert_eq!(
        pod_restarted["status"]["containerStatuses"][0]["ready"],
        false
    );

    // Fix liveness probe
    runtime.set_exec_response(
        "cat /tmp/healthy",
        ExecResult {
            exit_code: 0,
            stdout: "healthy\n".to_string(),
            stderr: String::new(),
        },
    );
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    let pod_stable = client
        .get_pod("default", "lifecycle-managed-pod")
        .await
        .unwrap();
    assert_eq!(
        pod_stable["status"]["containerStatuses"][0]["restartCount"],
        1
    );
    assert_eq!(pod_stable["status"]["containerStatuses"][0]["ready"], true);
}

#[tokio::test]
async fn test_pod_lifecycle_probes_and_logs_exec_external_runtime() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options, _engine, _pki_dir) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new_external("external-podman"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime.clone());
    kubelet.start().await.unwrap();

    let client = kubelet.client();

    runtime.set_exec_response(
        "cat /tmp/ready",
        ExecResult {
            exit_code: 0,
            stdout: "ok\n".to_string(),
            stderr: String::new(),
        },
    );
    runtime.set_exec_response(
        "cat /tmp/healthy",
        ExecResult {
            exit_code: 0,
            stdout: "ok\n".to_string(),
            stderr: String::new(),
        },
    );

    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "lifecycle-external-pod",
            "namespace": "default",
            "uid": "uid-lifecycle-external"
        },
        "spec": {
            "nodeName": "test-node",
            "restartPolicy": "Always",
            "containers": [
                {
                    "name": "worker",
                    "image": "docker.io/library/redis:7.2",
                    "readinessProbe": {
                        "exec": {
                            "command": ["cat", "/tmp/ready"]
                        }
                    },
                    "livenessProbe": {
                        "exec": {
                            "command": ["cat", "/tmp/healthy"]
                        }
                    }
                }
            ]
        }
    });

    client.create_pod("default", pod_spec).await.unwrap();

    let count = kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    assert_eq!(count, 1);

    let pod = client
        .get_pod("default", "lifecycle-external-pod")
        .await
        .unwrap();
    assert_eq!(pod["status"]["phase"], "Running");
    assert_eq!(pod["status"]["containerStatuses"][0]["ready"], true);
    assert_eq!(pod["status"]["containerStatuses"][0]["restartCount"], 0);

    // Verify logs
    runtime.set_container_logs("worker", "redis 1\nredis 2\nredis 3\n");
    let logs = kubelet
        .get_container_logs("uid-lifecycle-external", "worker", Some(1))
        .await
        .unwrap();
    assert_eq!(logs.trim(), "redis 3");

    // Verify exec
    let res = kubelet
        .exec_in_container(
            "uid-lifecycle-external",
            "worker",
            &["echo".to_string(), "ping".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(res.exit_code, 0);
    assert_eq!(res.stdout.trim(), "ping");

    // Liveness failure and restart on external runtime
    runtime.set_exec_response(
        "cat /tmp/healthy",
        ExecResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "redis frozen\n".to_string(),
        },
    );

    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    let pod_restarted = client
        .get_pod("default", "lifecycle-external-pod")
        .await
        .unwrap();
    assert_eq!(
        pod_restarted["status"]["containerStatuses"][0]["restartCount"],
        1
    );
    assert_eq!(
        pod_restarted["status"]["containerStatuses"][0]["ready"],
        false
    );
}

#[tokio::test]
async fn test_secret_and_configmap_volume_mounts() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options, _engine, _pki_dir) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime);
    kubelet.start().await.unwrap();

    let admin_client = apiserver_arc.admin_client();
    let client = kubelet.client();

    // 1. Create Secret in default namespace
    let mut secret_data = std::collections::BTreeMap::new();
    secret_data.insert(
        "username".to_string(),
        diorama_pki::base64_encode(b"admin-user"),
    );
    secret_data.insert(
        "password".to_string(),
        diorama_pki::base64_encode(b"super-secret-pwd"),
    );
    admin_client
        .create_secret("default", "db-secret", secret_data, None)
        .await
        .unwrap();

    // 2. Create ConfigMap in default namespace
    let mut cm_data = std::collections::BTreeMap::new();
    cm_data.insert(
        "app.conf".to_string(),
        "database_url = postgres://admin-user:super-secret-pwd@db:5432/main".to_string(),
    );
    cm_data.insert("features.env".to_string(), "ENABLE_METRICS=1".to_string());
    admin_client
        .create_configmap("default", "app-config", cm_data)
        .await
        .unwrap();

    // 3. Create Pod referencing both Secret and ConfigMap volumes
    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "vol-test-pod",
            "namespace": "default",
            "uid": "uid-vol-test-123"
        },
        "spec": {
            "nodeName": "test-node",
            "containers": [
                {
                    "name": "app",
                    "image": "docker.io/library/alpine:3.20"
                }
            ],
            "volumes": [
                {
                    "name": "secret-vol-mapped",
                    "secret": {
                        "secretName": "db-secret",
                        "items": [
                            {
                                "key": "username",
                                "path": "custom-user.txt"
                            }
                        ]
                    }
                },
                {
                    "name": "secret-vol-all",
                    "secret": {
                        "secretName": "db-secret"
                    }
                },
                {
                    "name": "cm-vol-mapped",
                    "configMap": {
                        "name": "app-config",
                        "items": [
                            {
                                "key": "app.conf",
                                "path": "config/app.conf"
                            }
                        ]
                    }
                },
                {
                    "name": "cm-vol-all",
                    "configMap": {
                        "name": "app-config"
                    }
                }
            ]
        }
    });

    client.create_pod("default", pod_spec).await.unwrap();

    // Reconcile pod
    let count = kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    assert_eq!(count, 1);

    // 4. Verify volume staging paths on host filesystem
    let sec_mapped_dir = kubelet.get_pod_volume_dir(
        "uid-vol-test-123",
        "kubernetes.io~secret",
        "secret-vol-mapped",
    );
    assert!(sec_mapped_dir.exists());
    let user_content =
        std::fs::read_to_string(sec_mapped_dir.join("custom-user.txt")).expect("custom-user.txt");
    assert_eq!(user_content, "admin-user");

    let sec_all_dir =
        kubelet.get_pod_volume_dir("uid-vol-test-123", "kubernetes.io~secret", "secret-vol-all");
    assert!(sec_all_dir.exists());
    let all_username =
        std::fs::read_to_string(sec_all_dir.join("username")).expect("username file");
    assert_eq!(all_username, "admin-user");
    let all_password =
        std::fs::read_to_string(sec_all_dir.join("password")).expect("password file");
    assert_eq!(all_password, "super-secret-pwd");

    let cm_mapped_dir = kubelet.get_pod_volume_dir(
        "uid-vol-test-123",
        "kubernetes.io~configmap",
        "cm-vol-mapped",
    );
    assert!(cm_mapped_dir.exists());
    let app_conf = std::fs::read_to_string(cm_mapped_dir.join("config/app.conf"))
        .expect("config/app.conf file");
    assert!(app_conf.contains("postgres://admin-user:super-secret-pwd@db:5432/main"));

    let cm_all_dir =
        kubelet.get_pod_volume_dir("uid-vol-test-123", "kubernetes.io~configmap", "cm-vol-all");
    assert!(cm_all_dir.exists());
    let features_env =
        std::fs::read_to_string(cm_all_dir.join("features.env")).expect("features.env file");
    assert_eq!(features_env, "ENABLE_METRICS=1");
}

#[tokio::test]
async fn test_projected_volume_and_persistence_across_kubelet_restart() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options, _engine, _pki_dir) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime1 = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let kubelet1 = KubeletService::new(
        kubelet_options.clone(),
        apiserver_arc.clone(),
        runtime1.clone(),
    );
    kubelet1.start().await.unwrap();

    let admin_client = apiserver_arc.admin_client();
    let client = kubelet1.client();

    // Create supporting ConfigMap and Secret
    let mut cm_data = std::collections::BTreeMap::new();
    cm_data.insert(
        "ca.crt".to_string(),
        "-----BEGIN CERTIFICATE-----\nMOCK_CA\n-----END CERTIFICATE-----".to_string(),
    );
    admin_client
        .create_configmap("default", "kube-root-ca", cm_data)
        .await
        .unwrap();

    let mut sec_data = std::collections::BTreeMap::new();
    sec_data.insert(
        "api-key".to_string(),
        diorama_pki::base64_encode(b"vault-secret-api-key-xyz"),
    );
    admin_client
        .create_secret("default", "vault-creds", sec_data, None)
        .await
        .unwrap();

    // Create Pod with Projected volume
    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "projected-vol-pod",
            "namespace": "default",
            "uid": "uid-proj-999"
        },
        "spec": {
            "nodeName": "test-node",
            "serviceAccountName": "default",
            "containers": [
                {
                    "name": "vault-agent",
                    "image": "docker.io/hashicorp/vault:1.15"
                }
            ],
            "volumes": [
                {
                    "name": "kube-api-access",
                    "projected": {
                        "sources": [
                            {
                                "serviceAccountToken": {
                                    "path": "token",
                                    "audience": "vault",
                                    "expirationSeconds": 3600
                                }
                            },
                            {
                                "configMap": {
                                    "name": "kube-root-ca",
                                    "items": [
                                        {
                                            "key": "ca.crt",
                                            "path": "ca.crt"
                                        }
                                    ]
                                }
                            },
                            {
                                "downwardAPI": {
                                    "items": [
                                        {
                                            "path": "namespace",
                                            "fieldRef": {
                                                "apiVersion": "v1",
                                                "fieldPath": "metadata.namespace"
                                            }
                                        },
                                        {
                                            "path": "pod-name",
                                            "fieldRef": {
                                                "apiVersion": "v1",
                                                "fieldPath": "metadata.name"
                                            }
                                        },
                                        {
                                            "path": "pod-uid",
                                            "fieldRef": {
                                                "apiVersion": "v1",
                                                "fieldPath": "metadata.uid"
                                            }
                                        }
                                    ]
                                }
                            },
                            {
                                "secret": {
                                    "name": "vault-creds"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    });

    client.create_pod("default", pod_spec).await.unwrap();

    // Reconcile on first Kubelet instance
    let count = kubelet1
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    assert_eq!(count, 1);

    let proj_dir =
        kubelet1.get_pod_volume_dir("uid-proj-999", "kubernetes.io~projected", "kube-api-access");
    assert!(proj_dir.exists());

    // Verify token projection
    let token_content = std::fs::read_to_string(proj_dir.join("token")).expect("token file");
    assert!(!token_content.trim().is_empty());

    // Verify CA bundle
    let ca_content = std::fs::read_to_string(proj_dir.join("ca.crt")).expect("ca.crt file");
    assert!(ca_content.contains("BEGIN CERTIFICATE"));

    // Verify downwardAPI metadata files
    let ns_content = std::fs::read_to_string(proj_dir.join("namespace")).expect("namespace file");
    assert_eq!(ns_content, "default");
    let name_content = std::fs::read_to_string(proj_dir.join("pod-name")).expect("pod-name file");
    assert_eq!(name_content, "projected-vol-pod");
    let uid_content = std::fs::read_to_string(proj_dir.join("pod-uid")).expect("pod-uid file");
    assert_eq!(uid_content, "uid-proj-999");

    // Verify projected secret
    let secret_key = std::fs::read_to_string(proj_dir.join("api-key")).expect("api-key file");
    assert_eq!(secret_key, "vault-secret-api-key-xyz");

    // 5. Test persistence across Kubelet restart with external runtime
    kubelet1.stop();

    let runtime2 = Arc::new(MockRuntimeProvider::new_external("external-podman"));
    let kubelet2 = KubeletService::new(
        kubelet_options.clone(),
        apiserver_arc.clone(),
        runtime2.clone(),
    );
    kubelet2.start().await.unwrap();

    // Re-reconcile with restarted Kubelet
    let count2 = kubelet2
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    assert_eq!(count2, 1);

    let proj_dir_after_restart =
        kubelet2.get_pod_volume_dir("uid-proj-999", "kubernetes.io~projected", "kube-api-access");
    assert!(proj_dir_after_restart.exists());
    assert_eq!(
        std::fs::read_to_string(proj_dir_after_restart.join("pod-name")).unwrap(),
        "projected-vol-pod"
    );
    assert_eq!(
        std::fs::read_to_string(proj_dir_after_restart.join("api-key")).unwrap(),
        "vault-secret-api-key-xyz"
    );

    let pod_after = kubelet2
        .client()
        .get_pod("default", "projected-vol-pod")
        .await
        .unwrap();
    assert_eq!(pod_after["status"]["phase"], "Running");
    assert_eq!(pod_after["status"]["containerStatuses"][0]["ready"], true);
}

#[tokio::test]
async fn test_cri_volume_mounts_and_exec_sync_reading() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options, _engine, _pki_dir) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime.clone());
    kubelet.start().await.unwrap();

    let admin_client = apiserver_arc.admin_client();
    let client = kubelet.client();

    // 1. Create Secret
    let mut secret_data = std::collections::BTreeMap::new();
    secret_data.insert(
        "password".to_string(),
        diorama_pki::base64_encode(b"secret-password-xyz"),
    );
    admin_client
        .create_secret("default", "my-secret", secret_data, None)
        .await
        .unwrap();

    // 2. Create ConfigMap
    let mut cm_data = std::collections::BTreeMap::new();
    cm_data.insert("app.conf".to_string(), "port=8080\nenv=prod\n".to_string());
    admin_client
        .create_configmap("default", "my-config", cm_data)
        .await
        .unwrap();

    // 3. Create hostPath directory and file
    let host_dir = temp.path().join("host-test-dir");
    std::fs::create_dir_all(&host_dir).unwrap();
    std::fs::write(host_dir.join("host-file.txt"), "hello from hostPath").unwrap();

    // 4. Create Pod with 5 volume types and volumeMounts
    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "all-mounts-pod",
            "namespace": "default",
            "uid": "uid-all-mounts"
        },
        "spec": {
            "nodeName": "test-node",
            "serviceAccountName": "default",
            "containers": [
                {
                    "name": "worker",
                    "image": "docker.io/library/busybox:1.36",
                    "volumeMounts": [
                        {
                            "name": "sec-vol",
                            "mountPath": "/etc/secret",
                            "readOnly": true
                        },
                        {
                            "name": "cm-vol",
                            "mountPath": "/etc/config",
                            "readOnly": false
                        },
                        {
                            "name": "empty-vol",
                            "mountPath": "/var/scratch"
                        },
                        {
                            "name": "host-vol",
                            "mountPath": "/mnt/host"
                        },
                        {
                            "name": "proj-vol",
                            "mountPath": "/var/run/secrets/tokens"
                        }
                    ]
                }
            ],
            "volumes": [
                {
                    "name": "sec-vol",
                    "secret": {
                        "secretName": "my-secret"
                    }
                },
                {
                    "name": "cm-vol",
                    "configMap": {
                        "name": "my-config"
                    }
                },
                {
                    "name": "empty-vol",
                    "emptyDir": {}
                },
                {
                    "name": "host-vol",
                    "hostPath": {
                        "path": host_dir.to_str().unwrap()
                    }
                },
                {
                    "name": "proj-vol",
                    "projected": {
                        "sources": [
                            {
                                "configMap": {
                                    "name": "my-config",
                                    "items": [
                                        {
                                            "key": "app.conf",
                                            "path": "proj-app.conf"
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }
            ]
        }
    });

    client.create_pod("default", pod_spec).await.unwrap();

    let count = kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    assert_eq!(count, 1);

    // Verify container configs received CRI Mount specs
    let c_configs = runtime.container_configs("uid-all-mounts");
    assert_eq!(c_configs.len(), 1);
    let mounts = &c_configs[0].mounts;
    assert!(
        mounts
            .iter()
            .any(|m| m.container_path == "/etc/secret" && m.readonly)
    );
    assert!(
        mounts
            .iter()
            .any(|m| m.container_path == "/etc/config" && !m.readonly)
    );
    assert!(mounts.iter().any(|m| m.container_path == "/var/scratch"));
    assert!(mounts.iter().any(|m| m.container_path == "/mnt/host"));
    assert!(
        mounts
            .iter()
            .any(|m| m.container_path == "/var/run/secrets/tokens")
    );

    // Write file into emptyDir volume directory on host
    let empty_dir =
        kubelet.get_pod_volume_dir("uid-all-mounts", "kubernetes.io~empty-dir", "empty-vol");
    assert!(empty_dir.exists());
    std::fs::write(empty_dir.join("test-scratch.txt"), "scratch contents").unwrap();

    // Verify reading mounted files via exec_sync (both cat and /bin/cat)
    let secret_res = kubelet
        .exec_in_container(
            "uid-all-mounts",
            "worker",
            &["cat".to_string(), "/etc/secret/password".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(secret_res.exit_code, 0);
    assert_eq!(secret_res.stdout, "secret-password-xyz");

    let cm_res = kubelet
        .exec_in_container(
            "uid-all-mounts",
            "worker",
            &["/bin/cat".to_string(), "/etc/config/app.conf".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(cm_res.exit_code, 0);
    assert_eq!(cm_res.stdout, "port=8080\nenv=prod\n");

    let host_res = kubelet
        .exec_in_container(
            "uid-all-mounts",
            "worker",
            &["cat".to_string(), "/mnt/host/host-file.txt".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(host_res.exit_code, 0);
    assert_eq!(host_res.stdout, "hello from hostPath");

    let scratch_res = kubelet
        .exec_in_container(
            "uid-all-mounts",
            "worker",
            &[
                "cat".to_string(),
                "/var/scratch/test-scratch.txt".to_string(),
            ],
        )
        .await
        .unwrap();
    assert_eq!(scratch_res.exit_code, 0);
    assert_eq!(scratch_res.stdout, "scratch contents");

    let proj_res = kubelet
        .exec_in_container(
            "uid-all-mounts",
            "worker",
            &[
                "cat".to_string(),
                "/var/run/secrets/tokens/proj-app.conf".to_string(),
            ],
        )
        .await
        .unwrap();
    assert_eq!(proj_res.exit_code, 0);
    assert_eq!(proj_res.stdout, "port=8080\nenv=prod\n");
}

#[tokio::test]
async fn test_init_containers_sequential_execution_and_status() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options, _engine, _pki_dir) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime.clone());
    kubelet.start().await.unwrap();

    let client = kubelet.client();

    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "init-seq-pod",
            "namespace": "default",
            "uid": "uid-init-seq"
        },
        "spec": {
            "nodeName": "test-node",
            "restartPolicy": "Always",
            "initContainers": [
                {
                    "name": "init-step-1",
                    "image": "docker.io/library/busybox:1.36"
                },
                {
                    "name": "init-step-2",
                    "image": "docker.io/library/busybox:1.36"
                }
            ],
            "containers": [
                {
                    "name": "app-main",
                    "image": "docker.io/library/nginx:1.27"
                }
            ]
        }
    });

    client.create_pod("default", pod_spec).await.unwrap();

    // 1st reconcile: init-step-1 starts; init-step-2 and app-main do not start
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    let pod1 = client.get_pod("default", "init-seq-pod").await.unwrap();
    assert_eq!(pod1["status"]["phase"], "Pending");
    let init_statuses1 = pod1["status"]["initContainerStatuses"].as_array().unwrap();
    assert_eq!(init_statuses1.len(), 2);
    assert_eq!(init_statuses1[0]["name"], "init-step-1");
    assert!(init_statuses1[0]["state"]["running"].is_object());
    assert_eq!(init_statuses1[1]["name"], "init-step-2");
    assert!(init_statuses1[1]["state"]["waiting"].is_object());

    let app_statuses1 = pod1["status"]["containerStatuses"].as_array().unwrap();
    assert_eq!(app_statuses1.len(), 1);
    assert_eq!(app_statuses1[0]["name"], "app-main");
    assert_eq!(
        app_statuses1[0]["state"]["waiting"]["reason"],
        "PodInitializing"
    );

    let conds1 = pod1["status"]["conditions"].as_array().unwrap();
    let init_cond1 = conds1.iter().find(|c| c["type"] == "Initialized").unwrap();
    assert_eq!(init_cond1["status"], "False");
    assert_eq!(init_cond1["reason"], "ContainersNotInitialized");

    // Complete init-step-1 with exit code 0
    runtime.set_container_exit("uid-init-seq", "init-step-1", 0);

    // 2nd reconcile: init-step-1 is completed; init-step-2 starts; app-main still waiting
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    let pod2 = client.get_pod("default", "init-seq-pod").await.unwrap();
    assert_eq!(pod2["status"]["phase"], "Pending");
    let init_statuses2 = pod2["status"]["initContainerStatuses"].as_array().unwrap();
    assert_eq!(init_statuses2.len(), 2);
    assert_eq!(init_statuses2[0]["name"], "init-step-1");
    assert_eq!(init_statuses2[0]["state"]["terminated"]["exitCode"], 0);
    assert_eq!(init_statuses2[1]["name"], "init-step-2");
    assert!(init_statuses2[1]["state"]["running"].is_object());

    let app_statuses2 = pod2["status"]["containerStatuses"].as_array().unwrap();
    assert_eq!(
        app_statuses2[0]["state"]["waiting"]["reason"],
        "PodInitializing"
    );

    // Complete init-step-2 with exit code 0
    runtime.set_container_exit("uid-init-seq", "init-step-2", 0);

    // 3rd reconcile: all init containers complete; app-main starts and becomes Running
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    let pod3 = client.get_pod("default", "init-seq-pod").await.unwrap();
    assert_eq!(pod3["status"]["phase"], "Running");
    let init_statuses3 = pod3["status"]["initContainerStatuses"].as_array().unwrap();
    assert_eq!(init_statuses3.len(), 2);
    assert_eq!(init_statuses3[0]["state"]["terminated"]["exitCode"], 0);
    assert_eq!(init_statuses3[1]["state"]["terminated"]["exitCode"], 0);

    let app_statuses3 = pod3["status"]["containerStatuses"].as_array().unwrap();
    assert!(app_statuses3[0]["state"]["running"].is_object());
    assert_eq!(app_statuses3[0]["ready"], true);

    let conds3 = pod3["status"]["conditions"].as_array().unwrap();
    let init_cond3 = conds3.iter().find(|c| c["type"] == "Initialized").unwrap();
    assert_eq!(init_cond3["status"], "True");
}

#[tokio::test]
async fn test_init_container_failure_with_restart_policy_never() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options, _engine, _pki_dir) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime.clone());
    kubelet.start().await.unwrap();

    let client = kubelet.client();

    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "init-fail-pod",
            "namespace": "default",
            "uid": "uid-init-fail"
        },
        "spec": {
            "nodeName": "test-node",
            "restartPolicy": "Never",
            "initContainers": [
                {
                    "name": "bad-init",
                    "image": "docker.io/library/busybox:1.36"
                }
            ],
            "containers": [
                {
                    "name": "app",
                    "image": "docker.io/library/nginx:1.27"
                }
            ]
        }
    });

    client.create_pod("default", pod_spec).await.unwrap();

    // 1st reconcile: bad-init starts
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    let pod1 = client.get_pod("default", "init-fail-pod").await.unwrap();
    assert_eq!(pod1["status"]["phase"], "Pending");

    // bad-init exits with non-zero exit code
    runtime.set_container_exit("uid-init-fail", "bad-init", 1);

    // 2nd reconcile: with restartPolicy: Never, pod phase becomes Failed
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    let pod2 = client.get_pod("default", "init-fail-pod").await.unwrap();
    assert_eq!(pod2["status"]["phase"], "Failed");
    let init_statuses = pod2["status"]["initContainerStatuses"].as_array().unwrap();
    assert_eq!(init_statuses[0]["state"]["terminated"]["exitCode"], 1);
}

#[tokio::test]
async fn test_http_and_tcp_probes_readiness_and_liveness() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options, _engine, _pki_dir) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime.clone());
    kubelet.start().await.unwrap();

    let client = kubelet.client();

    // Mock probe successes
    runtime.set_exec_response(
        "curl -fsk -o /dev/null http://127.0.0.1:8080/ready",
        ExecResult {
            exit_code: 0,
            stdout: "ready\n".to_string(),
            stderr: String::new(),
        },
    );
    runtime.set_exec_response(
        "nc -z 127.0.0.1 9000",
        ExecResult {
            exit_code: 0,
            stdout: "live\n".to_string(),
            stderr: String::new(),
        },
    );

    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "http-tcp-pod",
            "namespace": "default",
            "uid": "uid-http-tcp"
        },
        "spec": {
            "nodeName": "test-node",
            "restartPolicy": "Always",
            "containers": [
                {
                    "name": "server",
                    "image": "docker.io/library/nginx:1.27",
                    "ports": [
                        { "containerPort": 8080 },
                        { "containerPort": 9000 }
                    ],
                    "readinessProbe": {
                        "httpGet": {
                            "path": "/ready",
                            "port": 8080
                        }
                    },
                    "livenessProbe": {
                        "tcpSocket": {
                            "port": 9000
                        },
                        "failureThreshold": 3
                    }
                }
            ]
        }
    });

    client.create_pod("default", pod_spec).await.unwrap();

    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    let pod = client.get_pod("default", "http-tcp-pod").await.unwrap();
    assert_eq!(pod["status"]["phase"], "Running");
    assert_eq!(pod["status"]["containerStatuses"][0]["ready"], true);
    assert_eq!(pod["status"]["containerStatuses"][0]["restartCount"], 0);

    // 1. HTTP readiness probe failure
    runtime.set_exec_response(
        "curl -fsk -o /dev/null http://127.0.0.1:8080/ready",
        ExecResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "404 Not Found\n".to_string(),
        },
    );

    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    let pod_unready = client.get_pod("default", "http-tcp-pod").await.unwrap();
    assert_eq!(
        pod_unready["status"]["containerStatuses"][0]["ready"],
        false
    );

    // Recover readiness
    runtime.set_exec_response(
        "curl -fsk -o /dev/null http://127.0.0.1:8080/ready",
        ExecResult {
            exit_code: 0,
            stdout: "ready again\n".to_string(),
            stderr: String::new(),
        },
    );

    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    let pod_recovered = client.get_pod("default", "http-tcp-pod").await.unwrap();
    assert_eq!(
        pod_recovered["status"]["containerStatuses"][0]["ready"],
        true
    );

    // 2. TCP liveness probe failure trips failure threshold (3 times)
    runtime.set_exec_response(
        "nc -z 127.0.0.1 9000",
        ExecResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "connection refused\n".to_string(),
        },
    );

    // 1st failure
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    // 2nd failure
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    // 3rd failure (trips threshold 3 -> restart)
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    let pod_restarted = client.get_pod("default", "http-tcp-pod").await.unwrap();
    assert_eq!(
        pod_restarted["status"]["containerStatuses"][0]["restartCount"],
        1
    );
}

#[tokio::test]
async fn test_pre_stop_hook_and_linux_resources_and_port_mappings() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options, _engine, _pki_dir) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime.clone());
    kubelet.start().await.unwrap();

    let client = kubelet.client();

    let pod_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "resources-hook-pod",
            "namespace": "default",
            "uid": "uid-res-hook"
        },
        "spec": {
            "nodeName": "test-node",
            "restartPolicy": "Always",
            "containers": [
                {
                    "name": "app",
                    "image": "docker.io/library/nginx:1.27",
                    "ports": [
                        {
                            "containerPort": 80,
                            "hostPort": 8080,
                            "protocol": "TCP"
                        }
                    ],
                    "resources": {
                        "requests": {
                            "cpu": "500m",
                            "memory": "64Mi"
                        },
                        "limits": {
                            "cpu": "1",
                            "memory": "128Mi"
                        }
                    },
                    "lifecycle": {
                        "preStop": {
                            "exec": {
                                "command": ["/bin/sh", "-c", "echo graceful shutdown"]
                            }
                        }
                    }
                }
            ]
        }
    });

    client.create_pod("default", pod_spec).await.unwrap();

    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    // Verify Port Mappings in CRI PodSandboxConfig
    let sandboxes = runtime.sandbox_configs("uid-res-hook");
    assert_eq!(sandboxes.len(), 1);
    assert_eq!(sandboxes[0].port_mappings.len(), 1);
    assert_eq!(sandboxes[0].port_mappings[0].container_port, 80);
    assert_eq!(sandboxes[0].port_mappings[0].host_port, 8080);

    // Verify Linux Container Resources in CRI ContainerConfig
    let containers = runtime.container_configs("uid-res-hook");
    assert_eq!(containers.len(), 1);
    let linux = containers[0].linux.as_ref().expect("linux config");
    let res = linux.resources.as_ref().expect("resources");
    assert_eq!(res.cpu_quota, 100_000);
    assert_eq!(res.cpu_period, 100_000);
    assert_eq!(res.cpu_shares, 512);
    assert_eq!(res.memory_limit_in_bytes, 134_217_728);

    // Verify PreStop hook execution on pod termination
    let admin_client = apiserver_arc.admin_client();
    admin_client
        .delete_pod("default", "resources-hook-pod")
        .await
        .unwrap();

    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    let exec_calls = runtime.exec_calls();
    let pre_stop_called = exec_calls
        .iter()
        .any(|(_, cmd)| cmd.iter().any(|arg| arg.contains("echo graceful shutdown")));
    assert!(
        pre_stop_called,
        "preStop hook must have been executed via exec_sync prior to stop"
    );
}

#[tokio::test]
async fn test_persistent_volume_claim_mount_and_recreate_persistence() {
    let temp = TempDir::new().unwrap();
    let (apiserver, kubelet_options, _engine, _pki_dir) = setup_test_environment(&temp);

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("managed-containerd"));
    let kubelet = KubeletService::new(kubelet_options, apiserver_arc.clone(), runtime.clone());
    kubelet.start().await.unwrap();

    let client = apiserver_arc.admin_client();

    let storage_dir = temp.path().join("local-storage");
    std::fs::create_dir_all(&storage_dir).unwrap();

    // 1. Create a PV with local path
    let volume_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": {
            "name": "pv-smoke-1",
        },
        "spec": {
            "capacity": {
                "storage": "1Gi"
            },
            "accessModes": ["ReadWriteOnce"],
            "persistentVolumeReclaimPolicy": "Retain",
            "storageClassName": "local-path",
            "local": {
                "path": storage_dir.display().to_string(),
            },
            "nodeAffinity": {
                "required": {
                    "nodeSelectorTerms": [
                        {
                            "matchExpressions": [
                                {
                                    "key": "kubernetes.io/hostname",
                                    "operator": "In",
                                    "values": ["test-node"]
                                }
                            ]
                        }
                    ]
                }
            }
        }
    });
    client.create_pv(volume_spec).await.unwrap();

    // 2. Create PVC bound to that PV
    let claim_spec = serde_json::json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": "smoke-pvc",
            "namespace": "default",
        },
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": "local-path",
            "volumeName": "pv-smoke-1",
            "resources": {
                "requests": {
                    "storage": "1Gi"
                }
            }
        },
        "status": {
            "phase": "Bound"
        }
    });
    client.create_pvc("default", claim_spec).await.unwrap();

    // 3. Create Pod mounting the PVC
    let pod_spec_1 = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "writer-pod",
            "namespace": "default",
            "uid": "uid-writer-pod",
        },
        "spec": {
            "nodeName": "test-node",
            "volumes": [
                {
                    "name": "data-vol",
                    "persistentVolumeClaim": {
                        "claimName": "smoke-pvc"
                    }
                }
            ],
            "containers": [
                {
                    "name": "writer",
                    "image": "alpine:latest",
                    "volumeMounts": [
                        {
                            "name": "data-vol",
                            "mountPath": "/var/data"
                        }
                    ]
                }
            ]
        }
    });
    client.create_pod("default", pod_spec_1).await.unwrap();

    // Reconcile pod 1
    let count = kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    assert_eq!(count, 1);

    // Verify mount host path points to the storage_dir canonical path
    let configs = runtime.container_configs("uid-writer-pod");
    assert_eq!(configs.len(), 1);
    let mount = configs[0]
        .mounts
        .iter()
        .find(|m| m.container_path == "/var/data")
        .expect("mount found");
    let canonical_storage_dir = std::fs::canonicalize(&storage_dir).unwrap();
    assert_eq!(
        mount.host_path,
        canonical_storage_dir.to_string_lossy().to_string()
    );

    // Write a test file into the storage directory (simulating container write)
    std::fs::write(
        storage_dir.join("smoke-test.txt"),
        "hello alpine local-path",
    )
    .unwrap();

    // Verify container can read it via exec
    let res = kubelet
        .exec_in_container(
            "uid-writer-pod",
            "writer",
            &["cat".to_string(), "/var/data/smoke-test.txt".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(res.exit_code, 0);
    assert_eq!(res.stdout, "hello alpine local-path");

    // 4. Delete the first pod
    client.delete_pod("default", "writer-pod").await.unwrap();
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    // 5. Create a second pod mounting the same PVC
    let pod_spec_2 = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "reader-pod",
            "namespace": "default",
            "uid": "uid-reader-pod",
        },
        "spec": {
            "nodeName": "test-node",
            "volumes": [
                {
                    "name": "data-vol",
                    "persistentVolumeClaim": {
                        "claimName": "smoke-pvc"
                    }
                }
            ],
            "containers": [
                {
                    "name": "reader",
                    "image": "alpine:latest",
                    "volumeMounts": [
                        {
                            "name": "data-vol",
                            "mountPath": "/mnt/shared"
                        }
                    ]
                }
            ]
        }
    });
    client.create_pod("default", pod_spec_2).await.unwrap();

    // Reconcile pod 2
    let count2 = kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();
    assert!(count2 >= 1);

    // Verify reader pod can read the persisted file from the PVC!
    let res2 = kubelet
        .exec_in_container(
            "uid-reader-pod",
            "reader",
            &["cat".to_string(), "/mnt/shared/smoke-test.txt".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(res2.exit_code, 0);
    assert_eq!(res2.stdout, "hello alpine local-path");
}
