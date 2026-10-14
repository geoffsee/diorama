use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;
use tempfile::TempDir;

use diorama_apiserver::{
    ApiserverConfig, ApiserverError, ApiserverService, KubernetesStorage, PolicyRule, Role,
    RoleBinding, Subject,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};

fn setup_pki_and_storage(
    dir: &TempDir,
    node_ip: IpAddr,
) -> (ApiserverConfig, DatastoreEngine, KubernetesStorage) {
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

    (apiserver_config, engine, storage)
}

#[tokio::test]
async fn projected_service_account_token_volume_and_authentication() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.10".parse().unwrap();
    let (config, _engine, storage) = setup_pki_and_storage(&temp, node_ip);

    let service = ApiserverService::new(config, storage);
    service.check_prerequisites().await.unwrap();
    let admin = service.admin_client();

    admin.create_namespace("production").await.unwrap();
    let default_sa = admin
        .get_service_account("production", "default")
        .await
        .expect("namespace creation creates the default service account");
    assert_eq!(default_sa["metadata"]["name"], "default");
    assert_eq!(default_sa["metadata"]["namespace"], "production");
    admin
        .get_service_account("kube-system", "default")
        .await
        .expect("bootstrapped namespaces also have a default service account");
    let root_ca = admin
        .get_configmap("production", "kube-root-ca.crt")
        .await
        .expect("namespace creation publishes kube-root-ca.crt");
    let ca_crt = root_ca["data"]["ca.crt"].as_str().unwrap_or("");
    assert!(
        ca_crt.contains("BEGIN CERTIFICATE"),
        "kube-root-ca.crt must carry the cluster CA"
    );
    assert_ne!(
        root_ca["metadata"]["annotations"]["kubernetes.io/description"]
            .as_str()
            .unwrap_or(""),
        ""
    );

    // 1. Grant RBAC permissions to ServiceAccount 'production:app-service'
    let app_role = Role {
        namespace: "production".to_string(),
        name: "app-role".to_string(),
        rules: vec![PolicyRule {
            verbs: vec!["get".to_string(), "list".to_string(), "create".to_string()],
            api_groups: vec![String::new()],
            resources: vec!["configmaps".to_string()],
            resource_names: Vec::new(),
            non_resource_urls: Vec::new(),
        }],
    };
    admin.create_role(app_role).await.unwrap();

    let app_binding = RoleBinding {
        namespace: "production".to_string(),
        name: "app-binding".to_string(),
        role_ref: "app-role".to_string(),
        subjects: vec![Subject::ServiceAccount {
            namespace: "production".to_string(),
            name: "app-service".to_string(),
        }],
    };
    admin.create_role_binding(app_binding).await.unwrap();

    // 2. Project service account token volume
    let volume_dir = temp.path().join("projected-volume");
    let token_path = service
        .project_service_account_token(
            &volume_dir,
            "production",
            "app-service",
            &["https://kubernetes.default.svc".to_string()],
            Duration::from_hours(1),
        )
        .expect("project token succeeds");

    assert!(token_path.exists());
    assert!(volume_dir.join("ca.crt").exists());
    let ns_content = std::fs::read_to_string(volume_dir.join("namespace")).unwrap();
    assert_eq!(ns_content, "production");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&token_path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "Token file must have 0600 mode"
        );
    }

    // 3. Authenticate using projected token
    let token_string = std::fs::read_to_string(&token_path).unwrap();
    let token_client = service.token_client(token_string);

    // Authorized operation: create configmap in 'production'
    let mut data = BTreeMap::new();
    data.insert("db_host".to_string(), "postgres.internal".to_string());
    let created = token_client
        .create_configmap("production", "app-env", data)
        .await
        .expect("projected token client creates configmap");
    assert_eq!(created["data"]["db_host"], "postgres.internal");

    // Unauthorized operation: create configmap in unauthorized namespace
    let unauth_err = token_client
        .create_configmap("default", "bad-cfg", BTreeMap::new())
        .await;
    assert!(
        matches!(unauth_err, Err(ApiserverError::Unauthorized { .. })),
        "Projected token client cannot modify unauthorized namespace"
    );
}

#[tokio::test]
async fn projected_token_lifetime_and_audience_enforcement() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.11".parse().unwrap();
    let (config, _engine, storage) = setup_pki_and_storage(&temp, node_ip);

    let service = ApiserverService::new(config, storage);
    service.check_prerequisites().await.unwrap();
    let ts = service.token_service().unwrap();

    // 1. Audience validation
    let token_aud_vault = ts
        .issue_token(
            "default",
            "vault-sa",
            "uid-1",
            &["https://vault.corp".to_string()],
            Duration::from_hours(1),
        )
        .unwrap();

    // Verify against intended audience succeeds
    assert!(
        ts.verify_token(&token_aud_vault, Some("https://vault.corp"))
            .is_ok()
    );

    // Verify against different audience fails
    let bad_aud_err = ts.verify_token(&token_aud_vault, Some("https://kubernetes.default.svc"));
    assert!(
        matches!(bad_aud_err, Err(ApiserverError::Unauthorized { .. })),
        "Token verification must fail when audience mismatches"
    );

    // 2. Lifetime expiration
    let expired_token = ts
        .issue_token(
            "default",
            "short-sa",
            "uid-2",
            &["https://kubernetes.default.svc".to_string()],
            Duration::from_secs(0), // Expired immediately
        )
        .unwrap();

    // Sleep 1 second to ensure now > exp
    tokio::time::sleep(Duration::from_secs(1)).await;

    let expired_err = ts.verify_token(&expired_token, Some("https://kubernetes.default.svc"));
    assert!(
        matches!(expired_err, Err(ApiserverError::Unauthorized { .. })),
        "Expired token must be rejected with Unauthorized"
    );

    // 3. Cryptographic signature tampering rejection
    let valid_token = ts
        .issue_token(
            "default",
            "safe-sa",
            "uid-3",
            &["https://kubernetes.default.svc".to_string()],
            Duration::from_hours(1),
        )
        .unwrap();

    let mut tampered_token = valid_token.clone();
    // Tamper the signature segment
    tampered_token.push('X');
    let tampered_err = ts.verify_token(&tampered_token, Some("https://kubernetes.default.svc"));
    assert!(
        matches!(tampered_err, Err(ApiserverError::Unauthorized { .. })),
        "Tampered token signature must be rejected"
    );
}

#[tokio::test]
async fn projected_credentials_survive_ordinary_restart() {
    let temp = TempDir::new().unwrap();
    let node_ip: IpAddr = "192.0.2.12".parse().unwrap();
    let pki_dir = temp.path().join("pki");
    std::fs::create_dir_all(&pki_dir).unwrap();
    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), "node-1".to_string(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile().expect("PKI reconcile");

    let apiserver_config = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    let data_dir = temp.path().join("datastore");

    let projected_token_string: String;

    // === Session 1: Issue projected token and configure RBAC ===
    {
        let ds_config = DatastoreConfig::new(data_dir.clone());
        let (engine1, _) = DatastoreEngine::open(ds_config).expect("datastore open 1");
        let storage1 = KubernetesStorage::new(engine1.client(), "/registry");

        let service1 = ApiserverService::new(apiserver_config.clone(), storage1);
        service1.check_prerequisites().await.unwrap();
        service1.start().unwrap();

        let admin1 = service1.admin_client();
        admin1.create_namespace("monitoring").await.unwrap();

        let mon_role = Role {
            namespace: "monitoring".to_string(),
            name: "metric-collector".to_string(),
            rules: vec![PolicyRule {
                verbs: vec!["get".to_string(), "list".to_string(), "create".to_string()],
                api_groups: vec![String::new()],
                resources: vec!["configmaps".to_string()],
                resource_names: Vec::new(),
                non_resource_urls: Vec::new(),
            }],
        };
        admin1.create_role(mon_role).await.unwrap();

        let mon_binding = RoleBinding {
            namespace: "monitoring".to_string(),
            name: "collector-binding".to_string(),
            role_ref: "metric-collector".to_string(),
            subjects: vec![Subject::ServiceAccount {
                namespace: "monitoring".to_string(),
                name: "prometheus".to_string(),
            }],
        };
        admin1.create_role_binding(mon_binding).await.unwrap();

        // Project token
        let volume_dir = temp.path().join("prom-volume");
        let token_path = service1
            .project_service_account_token(
                &volume_dir,
                "monitoring",
                "prometheus",
                &["https://kubernetes.default.svc".to_string()],
                Duration::from_hours(2),
            )
            .unwrap();

        projected_token_string = std::fs::read_to_string(token_path).unwrap();

        // Verify token client works in Session 1
        let client1 = service1.token_client(&projected_token_string);
        let mut data = BTreeMap::new();
        data.insert("metrics_port".to_string(), "9090".to_string());
        client1
            .create_configmap("monitoring", "prom-config", data)
            .await
            .expect("session 1 token create cm");

        service1.stop();
        drop(service1);
        drop(engine1);
    }

    // === Session 2: Ordinary restart with same PKI and datastore ===
    {
        let ds_config2 = DatastoreConfig::new(data_dir.clone());
        let (engine2, _) = DatastoreEngine::open(ds_config2).expect("datastore open 2");
        let storage2 = KubernetesStorage::new(engine2.client(), "/registry");

        let service2 = ApiserverService::new(apiserver_config.clone(), storage2);
        service2.check_prerequisites().await.unwrap();
        service2.start().unwrap();

        // Reconnect with the projected token issued in Session 1
        let client2 = service2.token_client(&projected_token_string);

        // Fetch pre-existing state created before restart
        let fetched = client2
            .get_configmap("monitoring", "prom-config")
            .await
            .expect("session 2 client fetches pre-existing configmap");
        assert_eq!(fetched["data"]["metrics_port"], "9090");

        // Mutate new state using the persisted credentials
        let mut new_data = BTreeMap::new();
        new_data.insert("rules".to_string(), "alert_rules.yaml".to_string());
        let created2 = client2
            .create_configmap("monitoring", "prom-rules", new_data)
            .await
            .expect("session 2 client creates new configmap");
        assert_eq!(created2["data"]["rules"], "alert_rules.yaml");

        service2.stop();
    }
}
