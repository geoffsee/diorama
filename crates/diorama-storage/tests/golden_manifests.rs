use serde_json::Value;

use diorama_storage::{
    DEFAULT_ALLOW_VOLUME_EXPANSION, DEFAULT_APP_LABEL_KEY, DEFAULT_APP_LABEL_VALUE,
    DEFAULT_BASE_STORAGE_PATH, DEFAULT_CPU_REQUEST, DEFAULT_HELPER_IMAGE, DEFAULT_MEMORY_LIMIT,
    DEFAULT_MEMORY_REQUEST, DEFAULT_PROVISIONER_IMAGE, DEFAULT_RECLAIM_POLICY,
    DEFAULT_STORAGE_DIR_NAME, DEFAULT_VOLUME_BINDING_MODE, IS_DEFAULT_CLASS_ANNOTATION,
    LOCAL_PATH_CLUSTER_ROLE_BINDING_NAME, LOCAL_PATH_CLUSTER_ROLE_NAME, LOCAL_PATH_CONFIGMAP_NAME,
    LOCAL_PATH_DEPLOYMENT_NAME, LOCAL_PATH_NAMESPACE, LOCAL_PATH_PROVISIONER_NAME,
    LOCAL_PATH_ROLE_BINDING_NAME, LOCAL_PATH_ROLE_NAME, LOCAL_PATH_SERVICE_ACCOUNT_NAME,
    LOCAL_PATH_STORAGE_CLASS_NAME, LocalPathConfig, LocalPathManifests, PV_PROTECTION_FINALIZER,
    PVC_PROTECTION_FINALIZER, STORAGE_PROVISIONED_BY_ANNOTATION, VOLUME_SELECTED_NODE_ANNOTATION,
    generate_config_json, generate_csi_driver, generate_csi_node, generate_csi_storage_capacity,
    generate_helper_pod_yaml, generate_storage_class, generate_volume_attachment,
    generate_volume_attributes_class, provisioner_labels,
};

fn load_golden_fixtures() -> Value {
    let content = include_str!("fixtures/localpath.json");
    serde_json::from_str(content).expect("valid JSON fixture")
}

#[test]
#[allow(clippy::too_many_lines, clippy::similar_names)]
fn test_golden_fixtures_parity_all_variants() {
    let fixtures = load_golden_fixtures();
    let entries = fixtures.as_array().expect("fixture array");
    assert_eq!(
        entries.len(),
        2,
        "expected 2 golden variants: local and shared"
    );

    for entry in entries {
        let variant = entry["variant"].as_str().expect("variant string");
        let golden_objects = &entry["objects"];

        let config = match variant {
            "local" => LocalPathConfig::new()
                .with_storage_path("/fixture/storage")
                .with_shared_path(None),
            "shared" => LocalPathConfig::new()
                .with_storage_path("/fixture/storage")
                .with_shared_path(Some("/fixture/shared".to_string())),
            other => panic!("unexpected variant: {other}"),
        };

        let manifests = LocalPathManifests::new(&config).expect("manifest generation succeeds");

        // 1. Namespace comparison
        let ns_golden = &golden_objects["namespaces"][0];
        assert_eq!(
            manifests.namespace.metadata.name.as_deref(),
            Some(ns_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: Namespace name"
        );

        // 2. ServiceAccount comparison
        let sa_golden = &golden_objects["serviceaccounts"][0];
        assert_eq!(
            manifests.service_account.metadata.name.as_deref(),
            Some(sa_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: ServiceAccount name"
        );
        assert_eq!(
            manifests.service_account.metadata.namespace.as_deref(),
            Some(sa_golden["metadata"]["namespace"].as_str().unwrap()),
            "variant {variant}: ServiceAccount namespace"
        );

        // 3. Role comparison
        let role_golden = &golden_objects["roles"][0];
        assert_eq!(
            manifests.role.metadata.name.as_deref(),
            Some(role_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: Role name"
        );
        assert_eq!(
            manifests.role.metadata.namespace.as_deref(),
            Some(role_golden["metadata"]["namespace"].as_str().unwrap()),
            "variant {variant}: Role namespace"
        );
        let role_rules_val = serde_json::to_value(manifests.role.rules.as_ref().unwrap()).unwrap();
        assert_eq!(
            role_rules_val, role_golden["rules"],
            "variant {variant}: Role rules"
        );

        // 4. ClusterRole comparison
        let cr_golden = &golden_objects["clusterroles"][0];
        assert_eq!(
            manifests.cluster_role.metadata.name.as_deref(),
            Some(cr_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: ClusterRole name"
        );
        let cr_rules_val =
            serde_json::to_value(manifests.cluster_role.rules.as_ref().unwrap()).unwrap();
        assert_eq!(
            cr_rules_val, cr_golden["rules"],
            "variant {variant}: ClusterRole rules"
        );

        // 5. RoleBinding comparison
        let rb_golden = &golden_objects["rolebindings"][0];
        assert_eq!(
            manifests.role_binding.metadata.name.as_deref(),
            Some(rb_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: RoleBinding name"
        );
        assert_eq!(
            manifests.role_binding.metadata.namespace.as_deref(),
            Some(rb_golden["metadata"]["namespace"].as_str().unwrap()),
            "variant {variant}: RoleBinding namespace"
        );
        let role_ref_val = serde_json::to_value(&manifests.role_binding.role_ref).unwrap();
        assert_eq!(
            role_ref_val, rb_golden["roleRef"],
            "variant {variant}: RoleRef"
        );
        let subjects_val =
            serde_json::to_value(manifests.role_binding.subjects.as_ref().unwrap()).unwrap();
        assert_eq!(
            subjects_val, rb_golden["subjects"],
            "variant {variant}: Subjects"
        );

        // 6. ClusterRoleBinding comparison
        let crb_golden = &golden_objects["clusterrolebindings"][0];
        assert_eq!(
            manifests.cluster_role_binding.metadata.name.as_deref(),
            Some(crb_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: ClusterRoleBinding name"
        );
        let crb_role_ref_val =
            serde_json::to_value(&manifests.cluster_role_binding.role_ref).unwrap();
        assert_eq!(
            crb_role_ref_val, crb_golden["roleRef"],
            "variant {variant}: ClusterRoleBinding roleRef"
        );
        let crb_subjects_val =
            serde_json::to_value(manifests.cluster_role_binding.subjects.as_ref().unwrap())
                .unwrap();
        assert_eq!(
            crb_subjects_val, crb_golden["subjects"],
            "variant {variant}: ClusterRoleBinding subjects"
        );

        // 7. ConfigMap comparison
        let cm_golden = &golden_objects["configmaps"][0];
        assert_eq!(
            manifests.config_map.metadata.name.as_deref(),
            Some(cm_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: ConfigMap name"
        );
        assert_eq!(
            manifests.config_map.metadata.namespace.as_deref(),
            Some(cm_golden["metadata"]["namespace"].as_str().unwrap()),
            "variant {variant}: ConfigMap namespace"
        );

        let cm_data = manifests.config_map.data.as_ref().unwrap();
        let expected_config_json = cm_golden["data"]["config.json"].as_str().unwrap();
        assert_eq!(
            cm_data.get("config.json").unwrap(),
            expected_config_json,
            "variant {variant}: config.json exact match"
        );
        assert_eq!(
            cm_data.get("setup").unwrap(),
            cm_golden["data"]["setup"].as_str().unwrap(),
            "variant {variant}: setup script exact match"
        );
        assert_eq!(
            cm_data.get("teardown").unwrap(),
            cm_golden["data"]["teardown"].as_str().unwrap(),
            "variant {variant}: teardown script exact match"
        );
        assert_eq!(
            cm_data.get("helperPod.yaml").unwrap(),
            cm_golden["data"]["helperPod.yaml"].as_str().unwrap(),
            "variant {variant}: helperPod.yaml exact match"
        );

        // 8. StorageClass comparison
        let sc_golden = &golden_objects["storageclasses"][0];
        assert_eq!(
            manifests.storage_class.metadata.name.as_deref(),
            Some(sc_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: StorageClass name"
        );
        assert_eq!(
            manifests.storage_class.provisioner,
            sc_golden["provisioner"].as_str().unwrap(),
            "variant {variant}: StorageClass provisioner"
        );
        assert_eq!(
            manifests.storage_class.volume_binding_mode.as_deref(),
            Some(sc_golden["volumeBindingMode"].as_str().unwrap()),
            "variant {variant}: StorageClass volumeBindingMode"
        );
        assert_eq!(
            manifests.storage_class.reclaim_policy.as_deref(),
            Some(sc_golden["reclaimPolicy"].as_str().unwrap()),
            "variant {variant}: StorageClass reclaimPolicy"
        );
        let sc_annotations = serde_json::to_value(
            manifests
                .storage_class
                .metadata
                .annotations
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            sc_annotations, sc_golden["metadata"]["annotations"],
            "variant {variant}: StorageClass annotations"
        );

        // 9. Deployment comparison
        let dep_golden = &golden_objects["deployments"][0];
        assert_eq!(
            manifests.deployment.metadata.name.as_deref(),
            Some(dep_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: Deployment name"
        );
        assert_eq!(
            manifests.deployment.metadata.namespace.as_deref(),
            Some(dep_golden["metadata"]["namespace"].as_str().unwrap()),
            "variant {variant}: Deployment namespace"
        );

        let dep_spec = manifests.deployment.spec.as_ref().unwrap();
        let expected_replicas =
            i32::try_from(dep_golden["spec"]["replicas"].as_i64().unwrap()).unwrap();
        assert_eq!(
            dep_spec.replicas,
            Some(expected_replicas),
            "variant {variant}: Deployment replicas"
        );

        let selector_val = serde_json::to_value(&dep_spec.selector).unwrap();
        assert_eq!(
            selector_val, dep_golden["spec"]["selector"],
            "variant {variant}: Deployment selector"
        );

        let template_spec = dep_spec.template.spec.as_ref().unwrap();
        assert_eq!(
            template_spec.service_account_name.as_deref(),
            Some(
                dep_golden["spec"]["template"]["spec"]["serviceAccountName"]
                    .as_str()
                    .unwrap()
            ),
            "variant {variant}: Pod serviceAccountName"
        );

        let container = &template_spec.containers[0];
        let container_golden = &dep_golden["spec"]["template"]["spec"]["containers"][0];
        assert_eq!(
            container.image.as_deref(),
            Some(container_golden["image"].as_str().unwrap()),
            "variant {variant}: Container image"
        );
        assert_eq!(
            container.image_pull_policy.as_deref(),
            Some(container_golden["imagePullPolicy"].as_str().unwrap()),
            "variant {variant}: Container imagePullPolicy"
        );
        let cmd_val = serde_json::to_value(container.command.as_ref().unwrap()).unwrap();
        assert_eq!(
            cmd_val, container_golden["command"],
            "variant {variant}: Container command"
        );

        let env_val = serde_json::to_value(container.env.as_ref().unwrap()).unwrap();
        assert_eq!(
            env_val, container_golden["env"],
            "variant {variant}: Container env"
        );

        let resources_val = serde_json::to_value(container.resources.as_ref().unwrap()).unwrap();
        assert_eq!(
            resources_val, container_golden["resources"],
            "variant {variant}: Container resources (verifies memory limits avoid OOM)"
        );

        let vm_val = serde_json::to_value(container.volume_mounts.as_ref().unwrap()).unwrap();
        assert_eq!(
            vm_val, container_golden["volumeMounts"],
            "variant {variant}: Container volumeMounts"
        );

        let vol_val = serde_json::to_value(template_spec.volumes.as_ref().unwrap()).unwrap();
        assert_eq!(
            vol_val, dep_golden["spec"]["template"]["spec"]["volumes"],
            "variant {variant}: Pod volumes"
        );
    }
}

#[test]
fn test_default_constants_and_contract() {
    assert_eq!(LOCAL_PATH_NAMESPACE, "local-path-storage");
    assert_eq!(
        LOCAL_PATH_SERVICE_ACCOUNT_NAME,
        "local-path-provisioner-service-account"
    );
    assert_eq!(LOCAL_PATH_ROLE_NAME, "local-path-provisioner-role");
    assert_eq!(LOCAL_PATH_CLUSTER_ROLE_NAME, "local-path-provisioner-role");
    assert_eq!(LOCAL_PATH_ROLE_BINDING_NAME, "local-path-provisioner-bind");
    assert_eq!(
        LOCAL_PATH_CLUSTER_ROLE_BINDING_NAME,
        "local-path-provisioner-bind"
    );
    assert_eq!(LOCAL_PATH_CONFIGMAP_NAME, "local-path-config");
    assert_eq!(LOCAL_PATH_DEPLOYMENT_NAME, "local-path-provisioner");
    assert_eq!(LOCAL_PATH_STORAGE_CLASS_NAME, "local-path");
    assert_eq!(LOCAL_PATH_PROVISIONER_NAME, "rancher.io/local-path");
    assert_eq!(
        DEFAULT_PROVISIONER_IMAGE,
        "docker.io/rancher/local-path-provisioner:v0.0.36"
    );
    assert_eq!(DEFAULT_HELPER_IMAGE, "busybox");
    assert_eq!(DEFAULT_STORAGE_DIR_NAME, "local-path-storage");
    assert_eq!(
        DEFAULT_BASE_STORAGE_PATH,
        "/var/lib/diorama/local-path-storage"
    );
    assert_eq!(DEFAULT_RECLAIM_POLICY, "Retain");
    assert_eq!(DEFAULT_VOLUME_BINDING_MODE, "WaitForFirstConsumer");
    assert_eq!(DEFAULT_MEMORY_LIMIT, "128Mi");
    assert_eq!(DEFAULT_MEMORY_REQUEST, "32Mi");
    assert_eq!(DEFAULT_CPU_REQUEST, "50m");
    assert_eq!(DEFAULT_APP_LABEL_KEY, "app");
    assert_eq!(DEFAULT_APP_LABEL_VALUE, "local-path-provisioner");
}

#[test]
fn test_labels_and_selectors_consistency() {
    let labels = provisioner_labels();
    assert_eq!(labels.len(), 1);
    assert_eq!(
        labels.get("app"),
        Some(&"local-path-provisioner".to_string())
    );

    let config = LocalPathConfig::new();
    let manifests = LocalPathManifests::new(&config).unwrap();

    let dep_spec = manifests.deployment.spec.unwrap();
    assert_eq!(
        dep_spec.selector.match_labels.as_ref().unwrap(),
        &labels,
        "Deployment selector must match provisioner labels"
    );
    assert_eq!(
        dep_spec
            .template
            .metadata
            .as_ref()
            .unwrap()
            .labels
            .as_ref()
            .unwrap(),
        &labels,
        "Pod template labels must match provisioner labels"
    );
}

#[test]
fn test_storage_class_default_and_non_default() {
    // Default StorageClass has annotation
    let default_config = LocalPathConfig::new().with_default_class(true);
    let sc_default = generate_storage_class(&default_config);
    let annotations = sc_default.metadata.annotations.unwrap();
    assert_eq!(
        annotations.get("storageclass.kubernetes.io/is-default-class"),
        Some(&"true".to_string())
    );
    assert_eq!(sc_default.provisioner, "rancher.io/local-path");
    assert_eq!(
        sc_default.volume_binding_mode.as_deref(),
        Some("WaitForFirstConsumer")
    );
    assert_eq!(sc_default.reclaim_policy.as_deref(), Some("Retain"));

    // Non-default StorageClass has no annotations
    let non_default_config = LocalPathConfig::new().with_default_class(false);
    let sc_non_default = generate_storage_class(&non_default_config);
    assert!(sc_non_default.metadata.annotations.is_none());
}

#[test]
fn test_storage_class_custom_reclaim_and_binding() {
    let custom_config = LocalPathConfig::new()
        .with_reclaim_policy("Delete")
        .with_volume_binding_mode("Immediate");
    let sc = generate_storage_class(&custom_config);
    assert_eq!(sc.reclaim_policy.as_deref(), Some("Delete"));
    assert_eq!(sc.volume_binding_mode.as_deref(), Some("Immediate"));
}

#[test]
fn test_config_json_node_path_map_formatting() {
    let config = LocalPathConfig::new().with_storage_path("/custom/storage/path");
    let json_str = generate_config_json(&config).unwrap();

    assert!(
        json_str.contains("\"node\": \"DEFAULT_PATH_FOR_NON_LISTED_NODES\""),
        "must contain sentinel node name"
    );
    assert!(
        json_str.contains("\"/custom/storage/path\""),
        "must contain custom storage path"
    );
    assert!(
        !json_str.contains("sharedFileSystemPath"),
        "local config must not contain sharedFileSystemPath"
    );

    let val: Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(
        val["nodePathMap"][0]["node"],
        "DEFAULT_PATH_FOR_NON_LISTED_NODES"
    );
    assert_eq!(val["nodePathMap"][0]["paths"][0], "/custom/storage/path");
}

#[test]
fn test_config_json_shared_file_system_formatting() {
    let config = LocalPathConfig::new().with_shared_path(Some("/mnt/nfs/shared".to_string()));
    let json_str = generate_config_json(&config).unwrap();

    assert!(
        json_str.contains("\"sharedFileSystemPath\": \"/mnt/nfs/shared\""),
        "must contain sharedFileSystemPath with 4-space indent"
    );
    assert!(
        !json_str.contains("nodePathMap"),
        "shared config must not contain nodePathMap"
    );
}

#[test]
fn test_helper_pod_template() {
    let yaml = generate_helper_pod_yaml("custom-busybox:1.36");
    assert!(yaml.contains("image: custom-busybox:1.36"));
    assert!(yaml.contains("priorityClassName: system-node-critical"));
    assert!(yaml.contains("key: node.kubernetes.io/disk-pressure"));
}

#[test]
fn test_from_diorama_config_default_and_custom() {
    let mut root_config = diorama_config::Config {
        path: "/var/lib/my-cluster".to_string(),
        ..Default::default()
    };
    root_config.storage.local_path.enabled = true;
    root_config.storage.local_path.shared_path = String::new();

    let storage_cfg = LocalPathConfig::from_diorama_config(&root_config);
    assert!(storage_cfg.enabled);
    assert_eq!(
        storage_cfg.storage_path,
        "/var/lib/my-cluster/local-path-storage"
    );
    assert_eq!(storage_cfg.shared_path, None);
    assert_eq!(storage_cfg.provisioner_image, DEFAULT_PROVISIONER_IMAGE);

    // Custom shared path
    root_config.storage.local_path.shared_path = "/shared/nfs".to_string();
    let shared_cfg = LocalPathConfig::from_diorama_config(&root_config);
    assert_eq!(shared_cfg.shared_path, Some("/shared/nfs".to_string()));

    // Disabled mode
    root_config.storage.local_path.enabled = false;
    let disabled_cfg = LocalPathConfig::from_diorama_config(&root_config);
    assert!(!disabled_cfg.enabled);
}

#[test]
fn test_disabled_config_rejects_manifest_generation() {
    let config = LocalPathConfig::new().with_enabled(false);
    let err = LocalPathManifests::new(&config).unwrap_err();
    assert!(
        matches!(err, diorama_storage::StorageError::InvalidConfiguration(ref msg) if msg.contains("disabled"))
    );
}

#[test]
fn test_invalid_reclaim_policy_rejected() {
    let config = LocalPathConfig::new().with_reclaim_policy("Recycle");
    let err = LocalPathManifests::new(&config).unwrap_err();
    assert!(
        matches!(err, diorama_storage::StorageError::InvalidConfiguration(ref msg) if msg.contains("unsupported reclaim policy"))
    );
}

#[test]
fn test_invalid_volume_binding_mode_rejected() {
    let config = LocalPathConfig::new().with_volume_binding_mode("CustomMode");
    let err = LocalPathManifests::new(&config).unwrap_err();
    assert!(
        matches!(err, diorama_storage::StorageError::InvalidConfiguration(ref msg) if msg.contains("unsupported volume binding mode"))
    );
}

#[test]
fn test_constants_and_annotations() {
    const { assert!(DEFAULT_ALLOW_VOLUME_EXPANSION) };
    assert_eq!(PVC_PROTECTION_FINALIZER, "kubernetes.io/pvc-protection");
    assert_eq!(PV_PROTECTION_FINALIZER, "kubernetes.io/pv-protection");
    assert_eq!(
        STORAGE_PROVISIONED_BY_ANNOTATION,
        "pv.kubernetes.io/provisioned-by"
    );
    assert_eq!(
        VOLUME_SELECTED_NODE_ANNOTATION,
        "volume.kubernetes.io/selected-node"
    );
    assert_eq!(
        IS_DEFAULT_CLASS_ANNOTATION,
        "storageclass.kubernetes.io/is-default-class"
    );
}

#[test]
fn test_csi_manifest_generators() {
    let driver = generate_csi_driver("rancher.io/local-path", true, false, true);
    assert_eq!(driver["apiVersion"], "storage.k8s.io/v1");
    assert_eq!(driver["kind"], "CSIDriver");
    assert_eq!(driver["metadata"]["name"], "rancher.io/local-path");
    assert_eq!(driver["spec"]["attachRequired"], true);
    assert_eq!(driver["spec"]["podInfoOnMount"], false);
    assert_eq!(driver["spec"]["storageCapacity"], true);

    let topo_keys = vec!["kubernetes.io/hostname"];
    let node = generate_csi_node(
        "worker-1",
        "rancher.io/local-path",
        "node-uuid-1",
        &topo_keys,
    );
    assert_eq!(node["apiVersion"], "storage.k8s.io/v1");
    assert_eq!(node["kind"], "CSINode");
    assert_eq!(node["metadata"]["name"], "worker-1");
    let drivers = node["spec"]["drivers"].as_array().unwrap();
    assert_eq!(drivers[0]["name"], "rancher.io/local-path");
    assert_eq!(drivers[0]["nodeID"], "node-uuid-1");
    assert_eq!(drivers[0]["topologyKeys"][0], "kubernetes.io/hostname");

    let mut topo = std::collections::BTreeMap::new();
    topo.insert("kubernetes.io/hostname".to_string(), "worker-1".to_string());
    let cap = generate_csi_storage_capacity(
        "cap-1",
        "default",
        "local-path",
        10_737_418_240,
        Some(&topo),
    );
    assert_eq!(cap["apiVersion"], "storage.k8s.io/v1");
    assert_eq!(cap["kind"], "CSIStorageCapacity");
    assert_eq!(cap["storageClassName"], "local-path");
    assert_eq!(cap["capacity"], "10737418240");
    assert_eq!(
        cap["nodeTopology"]["matchLabels"]["kubernetes.io/hostname"],
        "worker-1"
    );

    let va = generate_volume_attachment("va-test", "rancher.io/local-path", "worker-1", "pvc-123");
    assert_eq!(va["apiVersion"], "storage.k8s.io/v1");
    assert_eq!(va["kind"], "VolumeAttachment");
    assert_eq!(va["spec"]["attacher"], "rancher.io/local-path");
    assert_eq!(va["spec"]["nodeName"], "worker-1");
    assert_eq!(va["spec"]["source"]["persistentVolumeName"], "pvc-123");

    let mut params = std::collections::BTreeMap::new();
    params.insert("iops".to_string(), "3000".to_string());
    let vac = generate_volume_attributes_class("silver-vac", "rancher.io/local-path", &params);
    assert_eq!(vac["apiVersion"], "storage.k8s.io/v1");
    assert_eq!(vac["kind"], "VolumeAttributesClass");
    assert_eq!(vac["metadata"]["name"], "silver-vac");
    assert_eq!(vac["driverName"], "rancher.io/local-path");
    assert_eq!(vac["parameters"]["iops"], "3000");
}

#[test]
fn test_allow_volume_expansion_and_csi_enabled_config() {
    let config = LocalPathConfig::new()
        .with_allow_volume_expansion(true)
        .with_csi_enabled(true);
    assert!(config.allow_volume_expansion);
    assert!(config.csi_enabled);

    let sc = generate_storage_class(&config);
    assert_eq!(sc.allow_volume_expansion, Some(true));
}
