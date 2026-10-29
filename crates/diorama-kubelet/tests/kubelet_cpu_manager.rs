use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::sync::Arc;

use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use dioramalet::{
    CPU_MANAGER_CHECKPOINT_FILE, CpuManager, KubeletConfigOptions, KubeletService,
    MockRuntimeProvider, PodQoSClass, PodReconciler, determine_pod_qos, format_cpuset,
    is_container_cpu_pinning_eligible, parse_cpuset,
};
use tempfile::TempDir;

fn setup_test_environment(dir: &TempDir) -> (ApiserverService, KubeletConfigOptions) {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    fs::create_dir_all(&pki_dir).unwrap();
    let datastore_dir = dir.path().join("datastore");
    let kubelet_dir = dir.path().join("kubelet");
    fs::create_dir_all(&kubelet_dir).unwrap();

    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "test-node".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(datastore_dir)).unwrap();
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let apiserver_service = ApiserverService::new(apiserver_config, storage);

    let kubelet_options =
        KubeletConfigOptions::default_for_pki(&pki_dir, "test-node", "192.0.2.1", &kubelet_dir);

    (apiserver_service, kubelet_options)
}

#[test]
fn test_checkpoint_transitions_parity_matrix() {
    let temp = TempDir::new().unwrap();
    let root = temp.path();

    let checkpoint = root.join(CPU_MANAGER_CHECKPOINT_FILE);

    let checkpoint_state = || -> &'static str {
        match fs::read(&checkpoint) {
            Ok(bytes) => {
                if bytes == b"synthetic checkpoint" {
                    "unchanged"
                } else {
                    "changed"
                }
            },
            Err(_) => "absent",
        }
    };

    let cases = [
        "same",
        "policy",
        "options",
        "reserved",
        "unrelated",
        "malformed_previous",
    ];
    let mut results = BTreeMap::new();

    for case in cases {
        let mut policy_options = BTreeMap::new();
        policy_options.insert("full-pcpus-only".to_string(), "true".to_string());

        let mut options = KubeletConfigOptions {
            root_dir: root.to_path_buf(),
            config_dir: root.to_path_buf(),
            config_file: root.join("kubelet.yaml"),
            container_mode: true,
            cpu_manager_policy: "static".to_string(),
            reserved_cpus: "0".to_string(),
            cpu_manager_policy_options: policy_options.clone(),
            ..Default::default()
        };

        // 1. Initial write
        options.write_kubelet_config_file().unwrap();
        fs::write(&checkpoint, b"synthetic checkpoint").unwrap();

        // 2. Transition mutation
        match case {
            "policy" => {
                options.cpu_manager_policy = "none".to_string();
                options.reserved_cpus.clear();
                options.cpu_manager_policy_options.clear();
            },
            "options" => {
                options
                    .cpu_manager_policy_options
                    .insert("full-pcpus-only".to_string(), "false".to_string());
            },
            "reserved" => {
                options.reserved_cpus = "1".to_string();
            },
            "unrelated" => {
                options
                    .system_reserved
                    .insert("memory".to_string(), "128Mi".to_string());
            },
            "malformed_previous" => {
                fs::write(&options.config_file, b"[invalid").unwrap();
            },
            _ => {}, // "same" keeps settings
        }

        // 3. Second write
        options.write_kubelet_config_file().unwrap();
        results.insert(case, checkpoint_state());
    }

    assert_eq!(results["same"], "unchanged");
    assert_eq!(results["unrelated"], "unchanged");
    assert_eq!(results["policy"], "absent");
    assert_eq!(results["options"], "absent");
    assert_eq!(results["reserved"], "absent");
    assert_eq!(results["malformed_previous"], "absent");

    // Negative control: corrupted but present checkpoint
    fs::write(&checkpoint, b"corrupt but present").unwrap();
    assert_eq!(checkpoint_state(), "changed");
}

#[test]
fn test_cpu_manager_validation_rules() {
    let mut options = KubeletConfigOptions {
        cpu_manager_policy: "dynamic".to_string(),
        ..KubeletConfigOptions::default()
    };

    // 1. Unknown policy rejected
    assert!(options.validate_cpu_manager(4).is_err());

    // 2. None policy rejects options or reservations
    options.cpu_manager_policy = "none".to_string();
    options.reserved_cpus = "0".to_string();
    assert!(options.validate_cpu_manager(4).is_err());

    options.reserved_cpus.clear();
    options
        .cpu_manager_policy_options
        .insert("full-pcpus-only".to_string(), "true".to_string());
    assert!(options.validate_cpu_manager(4).is_err());
    options.cpu_manager_policy_options.clear();

    // 3. Static policy in container mode rejected
    options.cpu_manager_policy = "static".to_string();
    options.container_mode = true;
    assert!(options.validate_cpu_manager(4).is_err());
    options.container_mode = false;

    // 4. Single-CPU host rejected for static policy
    assert!(options.validate_cpu_manager(1).is_err());

    // 5. Unknown policy option rejected
    options
        .cpu_manager_policy_options
        .insert("align-by-socket".to_string(), "true".to_string());
    assert!(options.validate_cpu_manager(4).is_err());
    options.cpu_manager_policy_options.clear();

    options
        .cpu_manager_policy_options
        .insert("make-it-fast".to_string(), "true".to_string());
    assert!(options.validate_cpu_manager(4).is_err());
    options.cpu_manager_policy_options.clear();

    // 6. Non-boolean option value rejected
    options
        .cpu_manager_policy_options
        .insert("full-pcpus-only".to_string(), "yes-please".to_string());
    assert!(options.validate_cpu_manager(4).is_err());
    options.cpu_manager_policy_options.clear();

    // 7. Incompatible NUMA and uncore cache options rejected
    options.cpu_manager_policy_options.insert(
        "prefer-align-cpus-by-uncorecache".to_string(),
        "true".to_string(),
    );
    options.cpu_manager_policy_options.insert(
        "distribute-cpus-across-numa".to_string(),
        "true".to_string(),
    );
    assert!(options.validate_cpu_manager(4).is_err());
    options.cpu_manager_policy_options.clear();

    // 8. Invalid cpuset syntax rejected
    options.reserved_cpus = "zero".to_string();
    assert!(options.validate_cpu_manager(4).is_err());

    options.reserved_cpus = "3-1".to_string();
    assert!(options.validate_cpu_manager(4).is_err());

    // 9. CPU index exceeding host CPUs rejected
    options.reserved_cpus = "4".to_string();
    assert!(options.validate_cpu_manager(4).is_err());

    // 10. Reserving all CPUs rejected
    options.reserved_cpus = "0-3".to_string();
    assert!(options.validate_cpu_manager(4).is_err());

    // 11. Unknown system reserved resource rejected
    options.reserved_cpus.clear();
    options
        .system_reserved
        .insert("gpu".to_string(), "1".to_string());
    assert!(options.validate_cpu_manager(4).is_err());
    options.system_reserved.clear();

    // 12. System reserved cpu reserving all CPUs rejected
    options
        .system_reserved
        .insert("cpu".to_string(), "4".to_string());
    assert!(options.validate_cpu_manager(4).is_err());
    options.system_reserved.clear();

    // 13. Valid static configuration accepted
    options.reserved_cpus = "0-1".to_string();
    options
        .cpu_manager_policy_options
        .insert("full-pcpus-only".to_string(), "true".to_string());
    assert!(options.validate_cpu_manager(4).is_ok());
}

#[test]
fn test_pod_qos_guaranteed_pinning_eligibility() {
    // 1. Guaranteed QoS with integer CPU (Eligible: 2 cores)
    let guaranteed_integer_pod = serde_json::json!({
        "spec": {
            "containers": [
                {
                    "name": "c1",
                    "resources": {
                        "requests": { "cpu": "2", "memory": "512Mi" },
                        "limits": { "cpu": "2", "memory": "512Mi" }
                    }
                }
            ]
        }
    });
    let qos = determine_pod_qos(&guaranteed_integer_pod);
    assert_eq!(qos, PodQoSClass::Guaranteed);
    let c1 = &guaranteed_integer_pod["spec"]["containers"][0];
    assert_eq!(is_container_cpu_pinning_eligible(qos, c1), Some(2));

    // 2. Guaranteed QoS with limits only (Requests default to limits -> Eligible: 1 core)
    let guaranteed_limits_only = serde_json::json!({
        "spec": {
            "containers": [
                {
                    "name": "c1",
                    "resources": {
                        "limits": { "cpu": "1000m", "memory": "256Mi" }
                    }
                }
            ]
        }
    });
    let qos = determine_pod_qos(&guaranteed_limits_only);
    assert_eq!(qos, PodQoSClass::Guaranteed);
    let c1 = &guaranteed_limits_only["spec"]["containers"][0];
    assert_eq!(is_container_cpu_pinning_eligible(qos, c1), Some(1));

    // 3. Guaranteed QoS with fractional CPU (Ineligible -> runs in shared pool)
    let guaranteed_fractional = serde_json::json!({
        "spec": {
            "containers": [
                {
                    "name": "c1",
                    "resources": {
                        "requests": { "cpu": "1500m", "memory": "512Mi" },
                        "limits": { "cpu": "1500m", "memory": "512Mi" }
                    }
                }
            ]
        }
    });
    let qos = determine_pod_qos(&guaranteed_fractional);
    assert_eq!(qos, PodQoSClass::Guaranteed);
    let c1 = &guaranteed_fractional["spec"]["containers"][0];
    assert_eq!(is_container_cpu_pinning_eligible(qos, c1), None);
}

#[test]
fn test_pod_qos_burstable_and_best_effort() {
    // 4. Burstable QoS: cpu only, no memory (Ineligible)
    let burstable_pod = serde_json::json!({
        "spec": {
            "containers": [
                {
                    "name": "c1",
                    "resources": {
                        "requests": { "cpu": "1" },
                        "limits": { "cpu": "1" }
                    }
                }
            ]
        }
    });
    let qos = determine_pod_qos(&burstable_pod);
    assert_eq!(qos, PodQoSClass::Burstable);
    let c1 = &burstable_pod["spec"]["containers"][0];
    assert_eq!(is_container_cpu_pinning_eligible(qos, c1), None);

    // 5. Multi-container pod where one sidecar breaks Guaranteed QoS
    let sidecar_breaks_guaranteed = serde_json::json!({
        "spec": {
            "containers": [
                {
                    "name": "app",
                    "resources": {
                        "requests": { "cpu": "2", "memory": "512Mi" },
                        "limits": { "cpu": "2", "memory": "512Mi" }
                    }
                },
                {
                    "name": "sidecar",
                    "resources": {
                        "requests": { "cpu": "100m" }
                    }
                }
            ]
        }
    });
    let qos = determine_pod_qos(&sidecar_breaks_guaranteed);
    assert_eq!(qos, PodQoSClass::Burstable);
    let app = &sidecar_breaks_guaranteed["spec"]["containers"][0];
    assert_eq!(is_container_cpu_pinning_eligible(qos, app), None);

    // 6. BestEffort QoS (no resources)
    let best_effort_pod = serde_json::json!({
        "spec": {
            "containers": [
                {
                    "name": "c1"
                }
            ]
        }
    });
    let qos = determine_pod_qos(&best_effort_pod);
    assert_eq!(qos, PodQoSClass::BestEffort);
    let c1 = &best_effort_pod["spec"]["containers"][0];
    assert_eq!(is_container_cpu_pinning_eligible(qos, c1), None);
}

#[tokio::test]
async fn test_exclusive_cpu_allocation_and_checkpoint_state() {
    let temp = TempDir::new().unwrap();
    let (apiserver, mut kubelet_options) = setup_test_environment(&temp);

    kubelet_options.cpu_manager_policy = "static".to_string();
    kubelet_options.reserved_cpus = "0".to_string(); // CPU 0 reserved, leaves CPUs 1.. on host

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    let runtime = Arc::new(MockRuntimeProvider::new("test-runtime"));

    // Configure CPU manager with 4 host CPUs and CPU 0 reserved
    let checkpoint_file = kubelet_options.cpu_manager_checkpoint_path();
    let mut reserved = std::collections::BTreeSet::new();
    reserved.insert(0);
    let cpu_manager = Arc::new(CpuManager::new(
        "static",
        BTreeMap::new(),
        reserved,
        4, // 4 CPUs: 0 reserved, 1, 2, 3 allocatable
        checkpoint_file.clone(),
    ));

    let client = Arc::new(apiserver_arc.node_client(&kubelet_options.node_name));
    let reconciler = PodReconciler::new(
        client.clone(),
        runtime.clone(),
        &kubelet_options.node_name,
        &kubelet_options.node_ip,
    )
    .with_root_dir(&kubelet_options.root_dir)
    .with_cpu_manager(cpu_manager.clone());

    // 1. Create an eligible Guaranteed Pod requesting 2 cores
    let guaranteed_pod = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "guaranteed-pinned-pod",
            "namespace": "default"
        },
        "spec": {
            "nodeName": "test-node",
            "containers": [
                {
                    "name": "audio-dsp",
                    "image": "docker.io/library/dsp:latest",
                    "resources": {
                        "requests": { "cpu": "2", "memory": "1Gi" },
                        "limits": { "cpu": "2", "memory": "1Gi" }
                    }
                }
            ]
        }
    });
    client.create_pod("default", guaranteed_pod).await.unwrap();

    // 2. Reconcile the pod
    let count = reconciler.reconcile_namespace("default").await.unwrap();
    assert_eq!(count, 1);

    // 3. Verify container received exclusive CPUs
    let pod = client
        .get_pod("default", "guaranteed-pinned-pod")
        .await
        .unwrap();
    assert_eq!(pod["status"]["phase"], "Running");
    assert_eq!(pod["status"]["qosClass"], "Guaranteed");

    let container_statuses = pod["status"]["containerStatuses"].as_array().unwrap();
    assert_eq!(container_statuses.len(), 1);
    assert_eq!(container_statuses[0]["name"], "audio-dsp");
    assert_eq!(container_statuses[0]["exclusiveCPU"], true);
    let cpuset = container_statuses[0]["cpuset"].as_str().unwrap();
    assert_eq!(cpuset, "1-2"); // Cores 1 and 2 allocated exclusively!
    assert_eq!(container_statuses[0]["allocatedResources"]["cpu"], "1-2");

    // 4. Verify checkpoint file on disk
    assert!(checkpoint_file.exists());
    let checkpoint_content = fs::read_to_string(&checkpoint_file).unwrap();
    assert!(checkpoint_content.contains("\"policyName\": \"static\""));
    assert!(checkpoint_content.contains("\"default/guaranteed-pinned-pod/audio-dsp\": \"1-2\""));
    assert!(checkpoint_content.contains("\"defaultCpuSet\": \"3\"")); // Remaining shared pool core

    // 5. Shared pool pod runs on remaining core 3
    let burstable_pod = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "shared-pool-pod",
            "namespace": "default"
        },
        "spec": {
            "nodeName": "test-node",
            "containers": [
                {
                    "name": "web-worker",
                    "image": "docker.io/library/worker:latest",
                    "resources": {
                        "requests": { "cpu": "500m" }
                    }
                }
            ]
        }
    });
    client.create_pod("default", burstable_pod).await.unwrap();
    let count = reconciler.reconcile_namespace("default").await.unwrap();
    assert_eq!(count, 2);

    let pod2 = client.get_pod("default", "shared-pool-pod").await.unwrap();
    assert_eq!(pod2["status"]["qosClass"], "Burstable");
    let c2_statuses = pod2["status"]["containerStatuses"].as_array().unwrap();
    assert_eq!(c2_statuses[0]["exclusiveCPU"], false);
    assert_eq!(c2_statuses[0]["cpuset"], "3"); // Runs on shared core 3
}

#[tokio::test]
async fn checkpoint_removal_failure_preserves_allocations_and_prevents_start() {
    let temp = TempDir::new().unwrap();
    let (apiserver, mut options) = setup_test_environment(&temp);
    options.write_kubelet_config_file().unwrap();
    let previous_yaml = fs::read(&options.config_file).unwrap();
    options.cpu_manager_policy = "static".to_string();
    options.reserved_cpus = "0".to_string();
    let checkpoint = options.cpu_manager_checkpoint_path();
    fs::write(
        &checkpoint,
        r#"{"policyName":"static","defaultCpuSet":"","entries":{"default/pinned/app":"1"}}"#,
    )
    .unwrap();
    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let kubelet = KubeletService::new(
        options.clone(),
        Arc::new(apiserver),
        Arc::new(MockRuntimeProvider::new("test-runtime")),
    );
    let allocations = kubelet.reconciler().cpu_manager().current_allocations();
    assert!(!allocations.is_empty());

    // A directory at the owned checkpoint path makes remove_file fail even as root.
    fs::remove_file(&checkpoint).unwrap();
    fs::create_dir(&checkpoint).unwrap();
    fs::write(
        checkpoint.join("retained-state"),
        b"keep checkpoint evidence",
    )
    .unwrap();
    let error = kubelet.start().await.unwrap_err();
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("failed to remove stale CPU manager checkpoint"));
    assert!(diagnostic.contains(checkpoint.to_str().unwrap()));
    assert_eq!(fs::read(&options.config_file).unwrap(), previous_yaml);
    assert_eq!(
        fs::read(checkpoint.join("retained-state")).unwrap(),
        b"keep checkpoint evidence"
    );
    assert_eq!(
        kubelet.reconciler().cpu_manager().current_allocations(),
        allocations
    );
    assert!(!kubelet.reconciler().is_checkpoint_invalidated());
    assert!(!kubelet.is_running());
    assert!(kubelet.client().get_node(&options.node_name).await.is_err());
}

#[test]
fn previous_configuration_read_failure_preserves_checkpoint() {
    let temp = TempDir::new().unwrap();
    let options = KubeletConfigOptions {
        config_file: temp.path().join("kubelet.yaml"),
        root_dir: temp.path().to_path_buf(),
        ..Default::default()
    };
    fs::create_dir(&options.config_file).unwrap();
    let checkpoint = options.cpu_manager_checkpoint_path();
    fs::write(&checkpoint, b"retained checkpoint").unwrap();
    let error = options.write_kubelet_config_file().unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to read previous configuration")
    );
    assert!(
        error
            .to_string()
            .contains(options.config_file.to_str().unwrap())
    );
    assert!(options.config_file.is_dir());
    assert_eq!(fs::read(checkpoint).unwrap(), b"retained checkpoint");
}

#[tokio::test]
async fn test_external_runtime_workload_restart_diagnostics() {
    let temp = TempDir::new().unwrap();
    let (apiserver, mut kubelet_options) = setup_test_environment(&temp);

    kubelet_options.cpu_manager_policy = "static".to_string();
    kubelet_options.reserved_cpus = "0".to_string();

    apiserver.check_prerequisites().await.unwrap();
    apiserver.start().unwrap();
    let apiserver_arc = Arc::new(apiserver);

    // External runtime provider
    let runtime = Arc::new(MockRuntimeProvider::new_external("external-containerd"));

    let kubelet = KubeletService::new(
        kubelet_options.clone(),
        apiserver_arc.clone(),
        runtime.clone(),
    );
    kubelet.start().await.unwrap();

    let client = apiserver_arc.admin_client();

    // 1. Create and reconcile a Guaranteed pinned pod
    let guaranteed_pod = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "surviving-pod",
            "namespace": "default"
        },
        "spec": {
            "nodeName": "test-node",
            "containers": [
                {
                    "name": "realtime-app",
                    "image": "docker.io/library/app:latest",
                    "resources": {
                        "requests": { "cpu": "1", "memory": "256Mi" },
                        "limits": { "cpu": "1", "memory": "256Mi" }
                    }
                }
            ]
        }
    });
    client.create_pod("default", guaranteed_pod).await.unwrap();
    kubelet
        .reconciler()
        .reconcile_namespace("default")
        .await
        .unwrap();

    // Verify initially no restart needed
    let reports = kubelet
        .report_workload_restart_needs("default")
        .await
        .unwrap();
    assert_eq!(reports, <[dioramalet::WorkloadRestartReport; 0]>::default());

    // 2. Simulate Kubelet restart with changed CPU manager settings (e.g. reserved CPUs changed from 0 to 1)
    let mut updated_options = kubelet_options.clone();
    updated_options.reserved_cpus = "1".to_string();

    let kubelet_after_restart =
        KubeletService::new(updated_options, apiserver_arc.clone(), runtime.clone());
    // Starting the kubelet detects changed settings, removes checkpoint, and marks invalidation
    kubelet_after_restart.start().await.unwrap();

    assert!(
        kubelet_after_restart
            .reconciler()
            .is_checkpoint_invalidated()
    );

    // 3. Report workload-restart needs
    let restart_reports = kubelet_after_restart
        .report_workload_restart_needs("default")
        .await
        .unwrap();

    assert_eq!(restart_reports.len(), 1);
    assert_eq!(restart_reports[0].pod_name, "surviving-pod");
    assert_eq!(restart_reports[0].container_name, "realtime-app");
    assert!(
        restart_reports[0]
            .container_id
            .starts_with("external-containerd://")
    );
    assert!(
        restart_reports[0]
            .reason
            .contains("CPU manager checkpoint invalidated")
    );
    assert!(
        restart_reports[0]
            .reason
            .contains("surviving external container")
    );
}

#[test]
fn test_cpuset_parsing_and_formatting() {
    let set1 = parse_cpuset("0").unwrap();
    assert_eq!(set1, [0].into_iter().collect());
    assert_eq!(format_cpuset(&set1), "0");

    let set2 = parse_cpuset("0-2,4").unwrap();
    assert_eq!(set2, [0, 1, 2, 4].into_iter().collect());
    assert_eq!(format_cpuset(&set2), "0-2,4");

    let set3 = parse_cpuset("1,3,5").unwrap();
    assert_eq!(set3, [1, 3, 5].into_iter().collect());
    assert_eq!(format_cpuset(&set3), "1,3,5");

    let empty = parse_cpuset("").unwrap();
    assert!(empty.is_empty());
    assert_eq!(format_cpuset(&empty), "");
}
