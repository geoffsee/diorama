//! Real TLS tests for the worker boundary and scheduler binding contract.
use diorama_apiserver::{
    ApiserverAdapter, ApiserverConfig, ApiserverError, ApiserverService, KubernetesStorage,
    transport::HttpsClient,
};
use diorama_datastore::{DatastoreConfig, DatastoreEngine};
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc, time::Duration};

fn credentials(dir: &Path, leaf: &str, endpoint: &str) -> HttpsClient {
    let path = dir.join(format!("{leaf}.kubeconfig"));
    let mut doc: Value = serde_saphyr::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    doc["clusters"][0]["cluster"]["server"] = json!(endpoint);
    std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
    HttpsClient::new(path)
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn tls_nodes_bootstrap_tokens_and_atomic_binding() {
    let temp = tempfile::tempdir().unwrap();
    let pki = temp.path().join("pki");
    let ip = "127.0.0.1".parse().unwrap();
    ClusterPki::new(ClusterPkiConfig::new(pki.clone(), "node-a".into(), ip))
        .reconcile()
        .unwrap();
    let (engine, _) =
        DatastoreEngine::open(DatastoreConfig::new(temp.path().join("data"))).unwrap();
    let service = Arc::new(ApiserverService::new(
        ApiserverConfig::default_for_pki(&pki, ip),
        KubernetesStorage::new(engine.client(), "/registry"),
    ));
    let registration =
        ApiserverAdapter::registration("api", (*service).clone(), vec![], Duration::from_secs(10));
    let supervisor = diorama_supervisor::Supervisor::new(vec![registration]).unwrap();
    let (stop, rx) = diorama_supervisor::stop_channel();
    let task = tokio::spawn(supervisor.run(rx));
    let addr = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(addr) = service.bound_addr() {
                break addr;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let endpoint = format!("https://{addr}");
    let admin = credentials(&pki, "admin", &endpoint);
    let node = credentials(&pki, "kubelet", &endpoint);
    let scheduler = credentials(&pki, "kube-scheduler", &endpoint);
    pvc_defaults_over_https(&admin).await;
    node.request(
        "POST",
        "/api/v1/nodes",
        Some(json!({"apiVersion":"v1","kind":"Node","metadata":{"name":"node-a"}})),
    )
    .await
    .unwrap();
    assert!(matches!(
        node.request(
            "POST",
            "/api/v1/nodes",
            Some(json!({"metadata":{"name":"node-b"}}))
        )
        .await,
        Err(ApiserverError::Unauthorized { .. })
    ));
    admin
        .request(
            "POST",
            "/api/v1/nodes",
            Some(json!({"metadata":{"name":"node-b"},"spec":{"podCIDR":"10.42.2.0/24"}})),
        )
        .await
        .unwrap();
    for path in [
        "/api/v1/nodes/node-b/status",
        "/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/node-b",
    ] {
        assert!(matches!(
            node.request("PATCH", path, Some(json!({"status":{}})))
                .await,
            Err(ApiserverError::Unauthorized { .. })
        ));
    }
    node.request(
        "PATCH",
        "/api/v1/nodes/node-a",
        Some(json!({"metadata":{"annotations":{"csi.volume.kubernetes.io/nodeid":"{}"}}})),
    )
    .await
    .unwrap();
    assert!(matches!(
        node.request(
            "PATCH",
            "/api/v1/nodes/node-a",
            Some(json!({"spec":{"podCIDR":"10.42.9.0/24"}}))
        )
        .await,
        Err(ApiserverError::Unauthorized { .. })
    ));
    let csi = "/apis/storage.k8s.io/v1/csinodes";
    node.request(
        "POST",
        csi,
        Some(json!({"metadata":{"name":"node-a"},"spec":{"drivers":[]}})),
    )
    .await
    .unwrap();
    assert!(matches!(
        node.request(
            "POST",
            csi,
            Some(json!({"metadata":{"name":"node-b"},"spec":{"drivers":[]}}))
        )
        .await,
        Err(ApiserverError::Unauthorized { .. })
    ));
    assert!(matches!(
        node.request("GET", "/api/v1/pods", None).await,
        Err(ApiserverError::Unauthorized { .. })
    ));
    node.request(
        "GET",
        "/api/v1/pods?fieldSelector=spec.nodeName%3Dnode-a",
        None,
    )
    .await
    .unwrap();
    assert!(matches!(
        node.request(
            "GET",
            "/api/v1/pods?fieldSelector=spec.nodeName%3Dnode-a-worker",
            None
        )
        .await,
        Err(ApiserverError::Unauthorized { .. })
    ));

    let pod_path = "/api/v1/namespaces/default/pods";
    let pod = admin.request("POST", pod_path, Some(json!({"metadata":{"name":"race"},"spec":{"containers":[{"name":"test","image":"pause"}]}}))).await.unwrap();
    assert_eq!(pod["spec"]["schedulerName"], "default-scheduler");
    let binding_path = format!("{pod_path}/race/binding");
    let binding = |name| json!({"apiVersion":"v1","kind":"Binding","metadata":{"name":"race","uid":pod["metadata"]["uid"]},"target":{"apiVersion":"v1","kind":"Node","name":name}});
    assert!(matches!(
        node.request("POST", &binding_path, Some(binding("node-a")))
            .await,
        Err(ApiserverError::Unauthorized { .. })
    ));
    let (a, b) = tokio::join!(
        scheduler.request("POST", &binding_path, Some(binding("node-a"))),
        scheduler.request("POST", &binding_path, Some(binding("node-b")))
    );
    assert_eq!(
        usize::from(a.is_ok()) + usize::from(b.is_ok()),
        1,
        "{a:?} {b:?}"
    );
    assert!(
        matches!(a, Err(ApiserverError::Conflict { .. }))
            || matches!(b, Err(ApiserverError::Conflict { .. }))
    );

    for (name, assigned) in [("mine", "node-a"), ("theirs", "node-b")] {
        admin.request("POST", pod_path, Some(json!({"metadata":{"name":name},"spec":{"nodeName":assigned,"containers":[{"name":"test","image":"pause"}],"volumes":[{"name":"secret","secret":{"secretName":name}}]}}))).await.unwrap();
        admin
            .request(
                "POST",
                "/api/v1/namespaces/default/secrets",
                Some(json!({"metadata":{"name":name},"stringData":{"value":"workload-only"}})),
            )
            .await
            .unwrap();
    }
    node.request("GET", "/api/v1/namespaces/default/secrets/mine", None)
        .await
        .unwrap();
    for path in [
        "/api/v1/namespaces/default/secrets/theirs",
        "/api/v1/namespaces/default/pods/theirs",
    ] {
        assert!(matches!(
            node.request("GET", path, None).await,
            Err(ApiserverError::Unauthorized { .. })
        ));
    }
    let mine = node
        .request("GET", "/api/v1/namespaces/default/pods/mine", None)
        .await
        .unwrap();
    let token_path = "/api/v1/namespaces/default/serviceaccounts/default/token";
    let token_request = json!({"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","spec":{"audiences":[],"expirationSeconds":600,"boundObjectRef":{"apiVersion":"v1","kind":"Pod","name":"mine","uid":mine["metadata"]["uid"]}}});
    let issued = node
        .request("POST", token_path, Some(token_request.clone()))
        .await
        .unwrap();
    assert!(issued["status"]["token"].is_string());
    let mut forged = token_request;
    forged["spec"]["boundObjectRef"]["name"] = json!("theirs");
    assert!(matches!(
        node.request("POST", token_path, Some(forged)).await,
        Err(ApiserverError::Unauthorized { .. })
    ));
    scheduler
        .request(
            "PATCH",
            "/api/v1/namespaces/default/pods/mine/status",
            Some(json!({"status":{"conditions":[{"type":"PodScheduled","status":"True"}]}})),
        )
        .await
        .unwrap();
    let token = "abcdef.0123456789abcdef";
    let expiry =
        diorama_apiserver::time::rfc3339_seconds(diorama_apiserver::time::now_unix() + 3600);
    let secret_path = "/api/v1/namespaces/kube-system/secrets";
    admin.request("POST", secret_path, Some(json!({"metadata":{"name":"bootstrap-token-abcdef"},"type":"bootstrap.kubernetes.io/token","stringData":{"token-id":"abcdef","token-secret":"0123456789abcdef","usage-bootstrap-authentication":"true","expiration":expiry}}))).await.unwrap();
    let bootstrap_path = temp.path().join("bootstrap.json");
    let mut bootstrap = admin.document().unwrap();
    bootstrap["users"][0]["user"] = json!({"token":token});
    std::fs::write(&bootstrap_path, serde_json::to_vec(&bootstrap).unwrap()).unwrap();
    let bootstrap = HttpsClient::new(bootstrap_path);
    assert!(matches!(
        bootstrap
            .request(
                "POST",
                "/api/v1/nodes",
                Some(json!({"metadata":{"name":"bootstrap-node"}}))
            )
            .await,
        Err(ApiserverError::Unauthorized { .. })
    ));
    assert!(matches!(
        bootstrap
            .request("POST", &binding_path, Some(binding("node-a")))
            .await,
        Err(ApiserverError::Unauthorized { .. })
    ));
    let request =
        diorama_pki::bootstrap::kubelet_request("joining-worker", &temp.path().join("worker.key"))
            .unwrap();
    let csr_path = "/apis/certificates.k8s.io/v1/certificatesigningrequests";
    let csr = bootstrap.request("POST", csr_path, Some(json!({"metadata":{"generateName":"worker-"},"spec":{"request":diorama_pki::base64_encode(request.as_bytes()),"signerName":diorama_pki::bootstrap::KUBELET_SIGNER,"usages":["digital signature","client auth"],"username":"system:admin","groups":["system:masters"]},"status":{"conditions":[{"type":"Approved"}]}}))).await.unwrap();
    assert_eq!(csr["spec"]["username"], "system:bootstrap:abcdef");
    assert!(csr.get("status").is_none());
    let name = csr["metadata"]["name"].as_str().unwrap();
    assert!(matches!(
        bootstrap
            .request("PUT", &format!("{csr_path}/{name}/approval"), Some(csr))
            .await,
        Err(ApiserverError::Unauthorized { .. })
    ));
    admin
        .request(
            "DELETE",
            &format!("{secret_path}/bootstrap-token-abcdef"),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        bootstrap.request("GET", csr_path, None).await,
        Err(ApiserverError::Unauthenticated { .. })
    ));
    stop.stop();
    task.await.unwrap();
}

async fn pvc_defaults_over_https(admin: &HttpsClient) {
    let collection = "/api/v1/namespaces/default/persistentvolumeclaims";
    for (name, mode) in [
        ("filesystem-default", Value::Null),
        ("explicit-block", json!("Block")),
    ] {
        let mut spec =
            json!({"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"16Mi"}}});
        if !mode.is_null() {
            spec["volumeMode"] = mode.clone();
        }
        let created = admin
            .request(
                "POST",
                collection,
                Some(json!({"metadata":{"name":name},"spec":spec})),
            )
            .await
            .unwrap();
        let expected = if mode.is_null() {
            json!("Filesystem")
        } else {
            mode
        };
        assert_eq!(created["spec"]["volumeMode"], expected);
        let updated = admin
            .request(
                "PATCH",
                &format!("{collection}/{name}"),
                Some(json!({"metadata":{"annotations":{"fixture":"updated"}}})),
            )
            .await
            .unwrap();
        assert_eq!(updated["spec"]["volumeMode"], expected);
        let listed = admin.request("GET", collection, None).await.unwrap();
        assert!(
            listed["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|claim| claim["metadata"]["name"] == name
                    && claim["spec"]["volumeMode"] == expected)
        );
    }
}
