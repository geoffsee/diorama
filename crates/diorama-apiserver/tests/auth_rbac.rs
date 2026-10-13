use std::collections::BTreeMap;
use std::net::IpAddr;
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverConfig, ApiserverError, ApiserverService, ClusterRole, ClusterRoleBinding,
    KubernetesStorage, PolicyRule, Role, RoleBinding, Subject,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};

fn setup_service(dir: &TempDir) -> ApiserverService {
    let node_ip: IpAddr = "192.0.2.1".parse().unwrap();
    let pki_dir = dir.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "node-1".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);

    let data_dir = dir.path().join("datastore");
    let ds_config = DatastoreConfig::new(data_dir);
    let (engine, _) = DatastoreEngine::open(ds_config).expect("datastore open");
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    ApiserverService::new(apiserver_config, storage)
}

#[tokio::test]
async fn rbac_bootstrap_roles_and_admin_bypass() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();

    let admin = service.admin_client();
    let ctl_mgr = service.controller_manager_client();
    let scheduler = service.scheduler_client();

    // 1. Admin client has full cluster-admin access
    let ns = admin
        .get_namespace("kube-system")
        .await
        .expect("admin gets bootstrapped kube-system ns");
    assert_eq!(ns["metadata"]["name"], "kube-system");

    let custom_ns = admin
        .create_namespace("custom-admin-ns")
        .await
        .expect("admin creates ns");
    assert_eq!(custom_ns["metadata"]["name"], "custom-admin-ns");

    let mut cm_data = BTreeMap::new();
    cm_data.insert("leader".to_string(), "node-1".to_string());
    let cm = admin
        .create_configmap("kube-system", "leader-lock", cm_data.clone())
        .await
        .expect("admin creates cm");
    assert_eq!(cm["data"]["leader"], "node-1");

    // 2. Controller manager has bootstrap system:kube-controller-manager permissions
    let fetched = ctl_mgr
        .get_configmap("kube-system", "leader-lock")
        .await
        .expect("controller manager can get cm");
    assert_eq!(fetched["data"]["leader"], "node-1");

    // 3. Scheduler has bootstrap system:kube-scheduler permissions
    let sched_list = scheduler.list_configmaps("kube-system").await;
    // Scheduler has get/list/watch on pods/nodes/bindings, but not configmaps by default
    assert!(
        matches!(sched_list, Err(ApiserverError::Unauthorized { .. })),
        "Scheduler should be rejected for configmaps when not granted in its bootstrap role"
    );
}

#[tokio::test]
async fn rbac_namespace_roles_and_role_bindings() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();

    admin.create_namespace("finance").await.unwrap();
    admin.create_namespace("engineering").await.unwrap();

    // 1. Create a Role in namespace 'finance' allowing get, list, create on configmaps
    let finance_role = Role {
        namespace: "finance".to_string(),
        name: "configmap-editor".to_string(),
        rules: vec![PolicyRule {
            verbs: vec!["get".to_string(), "list".to_string(), "create".to_string()],
            api_groups: vec![String::new()],
            resources: vec!["configmaps".to_string()],
            resource_names: Vec::new(),
            non_resource_urls: Vec::new(),
        }],
    };
    admin.create_role(finance_role).await.expect("create role");

    // 2. Bind the Role to ServiceAccount 'finance:accountant'
    let finance_binding = RoleBinding {
        namespace: "finance".to_string(),
        name: "accountant-binding".to_string(),
        role_ref: "configmap-editor".to_string(),
        subjects: vec![Subject::ServiceAccount {
            namespace: "finance".to_string(),
            name: "accountant".to_string(),
        }],
    };
    admin
        .create_role_binding(finance_binding)
        .await
        .expect("create role binding");

    // 3. Test ServiceAccount client
    let sa_client = service.service_account_client("finance", "accountant");

    // Authorized: create configmap in 'finance'
    let mut data = BTreeMap::new();
    data.insert("quarter".to_string(), "Q4".to_string());
    let created = sa_client
        .create_configmap("finance", "report-cfg", data)
        .await
        .expect("accountant can create configmap in finance");
    assert_eq!(created["data"]["quarter"], "Q4");

    // Authorized: get configmap in 'finance'
    let fetched = sa_client
        .get_configmap("finance", "report-cfg")
        .await
        .expect("accountant can get configmap in finance");
    assert_eq!(fetched["data"]["quarter"], "Q4");

    // Unauthorized: delete configmap in 'finance' (delete verb is not granted)
    let delete_err = sa_client
        .delete_configmap("finance", "report-cfg", None)
        .await;
    assert!(
        matches!(delete_err, Err(ApiserverError::Unauthorized { .. })),
        "Accountant cannot delete configmap without delete permission"
    );

    // Unauthorized: create configmap in 'engineering' (different namespace)
    let eng_err = sa_client
        .create_configmap("engineering", "eng-cfg", BTreeMap::new())
        .await;
    assert!(
        matches!(eng_err, Err(ApiserverError::Unauthorized { .. })),
        "Accountant cannot create configmap in engineering namespace"
    );
}

#[tokio::test]
async fn rbac_cluster_roles_and_cluster_role_bindings() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();

    admin.create_namespace("alpha").await.unwrap();
    admin.create_namespace("beta").await.unwrap();

    // 1. Create a ClusterRole allowing configmaps reading across the cluster
    let auditor_role = ClusterRole {
        name: "configmap-reader".to_string(),
        rules: vec![PolicyRule {
            verbs: vec!["get".to_string(), "list".to_string()],
            api_groups: vec![String::new()],
            resources: vec!["configmaps".to_string()],
            resource_names: Vec::new(),
            non_resource_urls: Vec::new(),
        }],
    };
    admin
        .create_cluster_role(auditor_role)
        .await
        .expect("create cluster role");

    // 2. User with 'auditors' group before binding exists -> denied
    let auditor_client = service.user_client("auditor-alice", vec!["auditors".to_string()]);
    let pre_binding_err = auditor_client.list_configmaps("alpha").await;
    assert!(
        matches!(pre_binding_err, Err(ApiserverError::Unauthorized { .. })),
        "Auditor cannot list configmaps before ClusterRoleBinding exists"
    );

    // 3. Bind ClusterRole to group 'auditors'
    let auditor_binding = ClusterRoleBinding {
        name: "auditors-crb".to_string(),
        role_ref: "configmap-reader".to_string(),
        subjects: vec![Subject::Group {
            name: "auditors".to_string(),
        }],
    };
    admin
        .create_cluster_role_binding(auditor_binding)
        .await
        .expect("create cluster role binding");

    // 4. Authorized: list configmaps across multiple namespaces
    let list_alpha = auditor_client
        .list_configmaps("alpha")
        .await
        .expect("list configmaps in alpha");
    assert!(list_alpha["items"].as_array().is_some());

    let list_beta = auditor_client
        .list_configmaps("beta")
        .await
        .expect("list configmaps in beta");
    assert!(list_beta["items"].as_array().is_some());

    // 5. Unauthorized: create configmap (write verb not granted)
    let create_err = auditor_client
        .create_configmap("alpha", "unauthorized-cfg", BTreeMap::new())
        .await;
    assert!(
        matches!(create_err, Err(ApiserverError::Unauthorized { .. })),
        "Auditor cannot create configmaps"
    );
}

#[tokio::test]
async fn http_rbac_objects_reach_the_authorizer_and_survive_restart() {
    let temp = TempDir::new().unwrap();
    let service = setup_service(&temp);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();
    admin.create_namespace("gaps").await.unwrap();

    let reader = service.service_account_client("gaps", "reader");
    let before = reader.list_configmaps("gaps").await;
    assert!(
        matches!(before, Err(ApiserverError::Unauthorized { .. })),
        "service account starts with no grant"
    );

    admin
        .create_cluster_object(
            "rbac.authorization.k8s.io",
            "ClusterRole",
            "clusterroles",
            serde_json::json!({
                "metadata": {"name": "reader"},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list"]}]
            }),
        )
        .await
        .expect("create clusterrole");
    admin
        .create_cluster_object(
            "rbac.authorization.k8s.io",
            "ClusterRoleBinding",
            "clusterrolebindings",
            serde_json::json!({
                "metadata": {"name": "reader-binding"},
                "roleRef": {"kind": "ClusterRole", "name": "reader"},
                "subjects": [{"kind": "ServiceAccount", "name": "reader", "namespace": "gaps"}]
            }),
        )
        .await
        .expect("create binding");

    reader
        .list_configmaps("gaps")
        .await
        .expect("binding grants list");

    let restarted = ApiserverService::new(service.config().clone(), service.storage().clone());
    restarted.check_prerequisites().await.unwrap();
    restarted
        .service_account_client("gaps", "reader")
        .list_configmaps("gaps")
        .await
        .expect("restart reloads the stored binding");

    admin
        .delete_cluster_object(
            "rbac.authorization.k8s.io",
            "clusterrolebindings",
            "reader-binding",
        )
        .await
        .unwrap();
    let after = reader.list_configmaps("gaps").await;
    assert!(
        matches!(after, Err(ApiserverError::Unauthorized { .. })),
        "deleting the binding revokes the grant"
    );
}
