use serde_json::Value;

use diorama_dns::{
    COREDNS_CLUSTER_ROLE_NAME, COREDNS_CONFIGMAP_NAME, COREDNS_DEPLOYMENT_NAME, COREDNS_NAMESPACE,
    COREDNS_SERVICE_ACCOUNT_NAME, COREDNS_SERVICE_NAME, CoreDnsConfig, CoreDnsManifests,
    DEFAULT_COREDNS_IP, coredns_labels, coredns_selector, generate_config_map_patch,
    should_recreate_service,
};

fn load_golden_fixtures() -> Value {
    let content = include_str!("fixtures/coredns.json");
    serde_json::from_str(content).expect("valid JSON fixture")
}

#[test]
#[allow(clippy::too_many_lines, clippy::similar_names)]
fn test_golden_fixtures_parity_all_variants() {
    let fixtures = load_golden_fixtures();
    let entries = fixtures.as_array().expect("fixture array");
    assert_eq!(entries.len(), 4, "expected 4 golden variants");

    for entry in entries {
        let variant = entry["variant"].as_str().expect("variant string");
        let (container_mode, disable_ipv6) = match variant {
            "host-dual" => (false, false),
            "container-dual" => (true, false),
            "host-ipv4" => (false, true),
            "container-ipv4" => (true, true),
            other => panic!("unexpected variant: {other}"),
        };

        let config = CoreDnsConfig::new()
            .with_container_mode(container_mode)
            .with_disable_ipv6(disable_ipv6);
        let manifests = CoreDnsManifests::new(&config);

        let golden_objects = &entry["objects"];

        // 1. ServiceAccount golden comparison
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

        // 2. ClusterRole golden comparison
        let cr_golden = &golden_objects["clusterroles"][0];
        assert_eq!(
            manifests.cluster_role.metadata.name.as_deref(),
            Some(cr_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: ClusterRole name"
        );
        let rules_val =
            serde_json::to_value(manifests.cluster_role.rules.as_ref().unwrap()).unwrap();
        assert_eq!(
            rules_val, cr_golden["rules"],
            "variant {variant}: ClusterRole rules"
        );

        // 3. ClusterRoleBinding golden comparison
        let crb_golden = &golden_objects["clusterrolebindings"][0];
        assert_eq!(
            manifests.cluster_role_binding.metadata.name.as_deref(),
            Some(crb_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: ClusterRoleBinding name"
        );
        let role_ref_val = serde_json::to_value(&manifests.cluster_role_binding.role_ref).unwrap();
        assert_eq!(
            role_ref_val, crb_golden["roleRef"],
            "variant {variant}: RoleRef"
        );
        let subjects_val =
            serde_json::to_value(manifests.cluster_role_binding.subjects.as_ref().unwrap())
                .unwrap();
        assert_eq!(
            subjects_val, crb_golden["subjects"],
            "variant {variant}: Subjects"
        );

        // 4. ConfigMap golden comparison
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
        let generated_corefile = manifests
            .config_map
            .data
            .as_ref()
            .unwrap()
            .get("Corefile")
            .unwrap();
        let expected_corefile = cm_golden["data"]["Corefile"].as_str().unwrap();
        assert_eq!(
            generated_corefile, expected_corefile,
            "variant {variant}: Corefile exact match"
        );

        // 5. Service golden comparison
        let svc_golden = &golden_objects["services"][0];
        assert_eq!(
            manifests.service.metadata.name.as_deref(),
            Some(svc_golden["metadata"]["name"].as_str().unwrap()),
            "variant {variant}: Service name"
        );
        assert_eq!(
            manifests.service.metadata.namespace.as_deref(),
            Some(svc_golden["metadata"]["namespace"].as_str().unwrap()),
            "variant {variant}: Service namespace"
        );
        let svc_spec = manifests.service.spec.as_ref().unwrap();
        assert_eq!(
            svc_spec.cluster_ip.as_deref(),
            Some(svc_golden["spec"]["clusterIP"].as_str().unwrap()),
            "variant {variant}: Service ClusterIP"
        );
        let svc_labels =
            serde_json::to_value(manifests.service.metadata.labels.as_ref().unwrap()).unwrap();
        assert_eq!(
            svc_labels, svc_golden["metadata"]["labels"],
            "variant {variant}: Service labels"
        );
        let svc_selector = serde_json::to_value(svc_spec.selector.as_ref().unwrap()).unwrap();
        assert_eq!(
            svc_selector, svc_golden["spec"]["selector"],
            "variant {variant}: Service selector"
        );
        let svc_ports = serde_json::to_value(svc_spec.ports.as_ref().unwrap()).unwrap();
        assert_eq!(
            svc_ports, svc_golden["spec"]["ports"],
            "variant {variant}: Service ports"
        );

        // 6. Deployment golden comparison
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
        let dep_labels =
            serde_json::to_value(manifests.deployment.metadata.labels.as_ref().unwrap()).unwrap();
        assert_eq!(
            dep_labels, dep_golden["metadata"]["labels"],
            "variant {variant}: Deployment labels"
        );

        let dep_spec = manifests.deployment.spec.as_ref().unwrap();
        let expected_replicas =
            i32::try_from(dep_golden["spec"]["replicas"].as_i64().unwrap()).unwrap();
        assert_eq!(
            dep_spec.replicas,
            Some(expected_replicas),
            "variant {variant}: Deployment replicas"
        );
        let strategy_val = serde_json::to_value(dep_spec.strategy.as_ref().unwrap()).unwrap();
        assert_eq!(
            strategy_val, dep_golden["spec"]["strategy"],
            "variant {variant}: Deployment strategy"
        );

        let selector_val = serde_json::to_value(&dep_spec.selector).unwrap();
        assert_eq!(
            selector_val, dep_golden["spec"]["selector"],
            "variant {variant}: Deployment selector"
        );

        let template_spec = dep_spec.template.spec.as_ref().unwrap();
        assert_eq!(
            template_spec.dns_policy.as_deref(),
            Some(
                dep_golden["spec"]["template"]["spec"]["dnsPolicy"]
                    .as_str()
                    .unwrap()
            ),
            "variant {variant}: Pod dnsPolicy"
        );
        assert_eq!(
            template_spec.priority_class_name.as_deref(),
            Some(
                dep_golden["spec"]["template"]["spec"]["priorityClassName"]
                    .as_str()
                    .unwrap()
            ),
            "variant {variant}: Pod priorityClassName"
        );
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
        let args_val = serde_json::to_value(container.args.as_ref().unwrap()).unwrap();
        assert_eq!(
            args_val, container_golden["args"],
            "variant {variant}: Container args"
        );

        let ports_val = serde_json::to_value(container.ports.as_ref().unwrap()).unwrap();
        assert_eq!(
            ports_val, container_golden["ports"],
            "variant {variant}: Container ports"
        );

        let liveness_val =
            serde_json::to_value(container.liveness_probe.as_ref().unwrap()).unwrap();
        assert_eq!(
            liveness_val, container_golden["livenessProbe"],
            "variant {variant}: Liveness probe"
        );

        let readiness_val =
            serde_json::to_value(container.readiness_probe.as_ref().unwrap()).unwrap();
        assert_eq!(
            readiness_val, container_golden["readinessProbe"],
            "variant {variant}: Readiness probe"
        );

        let volume_mounts_val =
            serde_json::to_value(container.volume_mounts.as_ref().unwrap()).unwrap();
        assert_eq!(
            volume_mounts_val, container_golden["volumeMounts"],
            "variant {variant}: Volume mounts"
        );

        let resources_val = serde_json::to_value(container.resources.as_ref().unwrap()).unwrap();
        assert_eq!(
            resources_val, container_golden["resources"],
            "variant {variant}: Container resources"
        );

        let volumes_val = serde_json::to_value(template_spec.volumes.as_ref().unwrap()).unwrap();
        assert_eq!(
            volumes_val, dep_golden["spec"]["template"]["spec"]["volumes"],
            "variant {variant}: Volumes"
        );
    }
}

#[test]
fn test_ipv4_only_corefile_omits_ip6_reverse_forwarding() {
    let config_ipv4 = CoreDnsConfig::new().with_disable_ipv6(true);
    let corefile_ipv4 = config_ipv4.generate_corefile();

    assert!(
        corefile_ipv4.contains("in-addr.arpa"),
        "IPv4-only Corefile must retain in-addr.arpa"
    );
    assert!(
        !corefile_ipv4.contains("ip6.arpa"),
        "IPv4-only Corefile must NOT contain ip6.arpa"
    );
    assert!(
        corefile_ipv4.contains("kubernetes cluster.local in-addr.arpa {\n\t\tpods insecure\n\t\tfallthrough in-addr.arpa\n\t\tttl 30\n\t}"),
        "IPv4-only Corefile must format kubernetes plugin block with only in-addr.arpa"
    );
}

#[test]
fn test_dual_stack_corefile_includes_ip6_reverse_forwarding() {
    let config_dual = CoreDnsConfig::new().with_disable_ipv6(false);
    let corefile_dual = config_dual.generate_corefile();

    assert!(
        corefile_dual.contains("in-addr.arpa ip6.arpa"),
        "Dual-stack Corefile must contain in-addr.arpa ip6.arpa"
    );
    assert!(
        corefile_dual.contains("kubernetes cluster.local in-addr.arpa ip6.arpa {\n\t\tpods insecure\n\t\tfallthrough in-addr.arpa ip6.arpa\n\t\tttl 30\n\t}"),
        "Dual-stack Corefile must format kubernetes plugin block with both in-addr.arpa and ip6.arpa"
    );
}

#[test]
fn test_external_resolver_preservation() {
    // 1. Host mode defaults to /etc/resolv.conf
    let host_config = CoreDnsConfig::new().with_container_mode(false);
    assert!(
        host_config
            .generate_corefile()
            .contains("forward . /etc/resolv.conf")
    );

    // 2. Container mode defaults to 1.1.1.1 8.8.8.8
    let container_config = CoreDnsConfig::new().with_container_mode(true);
    assert!(
        container_config
            .generate_corefile()
            .contains("forward . 1.1.1.1 8.8.8.8")
    );

    // 3. Explicit custom resolvers override both modes
    let custom_resolvers = vec!["10.0.0.2".to_string(), "10.0.0.3".to_string()];
    let custom_host = CoreDnsConfig::new()
        .with_container_mode(false)
        .with_upstream_resolvers(custom_resolvers.clone());
    assert!(
        custom_host
            .generate_corefile()
            .contains("forward . 10.0.0.2 10.0.0.3")
    );
    assert!(!custom_host.generate_corefile().contains("/etc/resolv.conf"));

    let custom_container = CoreDnsConfig::new()
        .with_container_mode(true)
        .with_upstream_resolvers(custom_resolvers);
    assert!(
        custom_container
            .generate_corefile()
            .contains("forward . 10.0.0.2 10.0.0.3")
    );
    assert!(!custom_container.generate_corefile().contains("1.1.1.1"));
}

#[test]
fn test_labels_selectors_and_service_identity() {
    let config = CoreDnsConfig::new();
    let manifests = CoreDnsManifests::new(&config);

    // Verify constant names
    assert_eq!(
        manifests.service.metadata.name.as_deref(),
        Some(COREDNS_SERVICE_NAME)
    );
    assert_eq!(
        manifests.service.metadata.namespace.as_deref(),
        Some(COREDNS_NAMESPACE)
    );
    assert_eq!(
        manifests.config_map.metadata.name.as_deref(),
        Some(COREDNS_CONFIGMAP_NAME)
    );
    assert_eq!(
        manifests.deployment.metadata.name.as_deref(),
        Some(COREDNS_DEPLOYMENT_NAME)
    );
    assert_eq!(
        manifests.service_account.metadata.name.as_deref(),
        Some(COREDNS_SERVICE_ACCOUNT_NAME)
    );
    assert_eq!(
        manifests.cluster_role.metadata.name.as_deref(),
        Some(COREDNS_CLUSTER_ROLE_NAME)
    );
    assert_eq!(
        manifests.cluster_role_binding.metadata.name.as_deref(),
        Some(COREDNS_CLUSTER_ROLE_NAME)
    );

    // Verify label consistency between Service and Deployment
    let labels = coredns_labels();
    assert_eq!(manifests.service.metadata.labels.as_ref().unwrap(), &labels);
    assert_eq!(
        manifests.deployment.metadata.labels.as_ref().unwrap(),
        &labels
    );

    // Verify selector consistency between Service and Pod template
    let selector = coredns_selector();
    let svc_spec = manifests.service.spec.as_ref().unwrap();
    let dep_spec = manifests.deployment.spec.as_ref().unwrap();
    assert_eq!(svc_spec.selector.as_ref().unwrap(), &selector);
    assert_eq!(dep_spec.selector.match_labels.as_ref().unwrap(), &selector);
    assert_eq!(
        dep_spec
            .template
            .metadata
            .as_ref()
            .unwrap()
            .labels
            .as_ref()
            .unwrap(),
        &selector
    );

    // Verify ClusterIP default
    assert_eq!(svc_spec.cluster_ip.as_deref(), Some(DEFAULT_COREDNS_IP));

    // Verify ConfigMap reference in volume mount
    let volume = &dep_spec
        .template
        .spec
        .as_ref()
        .unwrap()
        .volumes
        .as_ref()
        .unwrap()[0];
    assert_eq!(volume.name, "config-volume");
    let cm_source = volume.config_map.as_ref().expect("configMap source");
    assert_eq!(cm_source.name, COREDNS_CONFIGMAP_NAME);
    let item = &cm_source.items.as_ref().expect("items")[0];
    assert_eq!(item.key, "Corefile");
    assert_eq!(item.path, "Corefile");
}

#[test]
fn test_configmap_merge_patch_preserves_unrelated_keys() {
    let patch = generate_config_map_patch("mock-corefile-content");
    assert_eq!(
        patch,
        serde_json::json!({
            "data": {
                "Corefile": "mock-corefile-content"
            }
        })
    );
}

#[test]
fn test_should_recreate_service_comparison() {
    let config = CoreDnsConfig::new();
    let desired = diorama_dns::generate_service(&config, COREDNS_NAMESPACE);

    // Identical service should not require recreation
    assert!(!should_recreate_service(&desired, &desired));

    // Defaulted or modified mutable fields with same clusterIP should NOT trigger recreation
    let mut modified_mutable = desired.clone();
    modified_mutable.spec.as_mut().unwrap().session_affinity = Some("ClientIP".to_string());
    assert!(!should_recreate_service(&modified_mutable, &desired));

    // Changed clusterIP requires recreation
    let mut modified_ip = desired.clone();
    modified_ip.spec.as_mut().unwrap().cluster_ip = Some("10.43.0.99".to_string());
    assert!(should_recreate_service(&modified_ip, &desired));

    // Missing existing spec triggers recreation
    let mut missing_spec = desired.clone();
    missing_spec.spec = None;
    assert!(should_recreate_service(&missing_spec, &desired));

    // Missing desired spec does not trigger recreation
    let mut missing_desired = desired;
    missing_desired.spec = None;
    assert!(!should_recreate_service(&modified_ip, &missing_desired));
}
