//! Control-plane ownership of kubelet client signing and expired bootstrap tokens.
use diorama_apiserver::{
    ApiserverError, KubernetesApiClient,
    bootstrap::{secret_field, token_expired},
    time::now_rfc3339,
};
use serde_json::{Value, json};
use std::path::Path;

pub(crate) async fn reconcile(
    client: &KubernetesApiClient,
    ca: &Path,
) -> Result<(), ApiserverError> {
    let secrets = client.list_secrets("kube-system").await?;
    for secret in secrets["items"].as_array().into_iter().flatten() {
        if secret["type"] == "bootstrap.kubernetes.io/token"
            && token_expired(secret)
            && let Some(name) = secret.pointer("/metadata/name").and_then(Value::as_str)
        {
            client
                .delete_secret(
                    "kube-system",
                    name,
                    secret
                        .pointer("/metadata/resourceVersion")
                        .and_then(Value::as_str)
                        .and_then(|v| v.parse().ok()),
                )
                .await?;
        }
    }
    let requests = client
        .list_cluster_objects(
            "certificates.k8s.io",
            "CertificateSigningRequest",
            "certificatesigningrequests",
        )
        .await?;
    for request in requests["items"].as_array().into_iter().flatten() {
        if request.pointer("/spec/signerName").and_then(Value::as_str)
            != Some(diorama_pki::bootstrap::KUBELET_SIGNER)
            || request
                .pointer("/status/certificate")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            || request
                .pointer("/status/conditions")
                .and_then(Value::as_array)
                .is_some_and(|cs| {
                    cs.iter()
                        .any(|c| c["type"] == "Denied" || c["type"] == "Failed")
                })
        {
            continue;
        }
        if let Err(error) = sign(client, ca, request.clone()).await {
            tracing::warn!(error = %error, "kubelet certificate request was not signed");
        }
    }
    Ok(())
}
async fn sign(
    client: &KubernetesApiClient,
    ca: &Path,
    mut request: Value,
) -> Result<(), ApiserverError> {
    let invalid = || ApiserverError::BadRequest {
        message: "kubelet CSR failed signer validation".into(),
    };
    let name = request
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?
        .to_string();
    let pem = request
        .pointer("/spec/request")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let pem = String::from_utf8(diorama_pki::base64_decode(pem).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let node = diorama_apiserver::bootstrap::validate_kubelet_csr(&request)?;
    let user = request
        .pointer("/spec/username")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let groups = request
        .pointer("/spec/groups")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if let Some(id) = user.strip_prefix("system:bootstrap:") {
        let token = client
            .get_secret("kube-system", &format!("bootstrap-token-{id}"))
            .await?;
        if token_expired(&token)
            || secret_field(&token, "usage-bootstrap-authentication").as_deref() != Some("true")
            || !groups.iter().any(|g| g == "system:bootstrappers")
        {
            return Err(invalid());
        }
        // A bootstrap token cannot take over an already registered node identity.
        match client.get_node(&node).await {
            Err(ApiserverError::NotFound { .. }) => {},
            _ => return Err(invalid()),
        }
    } else if user != format!("system:node:{node}") || !groups.iter().any(|g| g == "system:nodes") {
        return Err(invalid());
    }
    let lifetime = request
        .pointer("/spec/expirationSeconds")
        .and_then(Value::as_u64)
        .unwrap_or(86_400);
    let certificate = diorama_pki::bootstrap::sign_kubelet_request(
        &pem,
        ca,
        &ca.with_file_name("ca.key"),
        u32::try_from(lifetime.min(86_400)).map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    request["status"] = json!({"conditions":[{"type":"Approved", "status":"True", "reason":"DioramaKubeletClient", "message":"validated kubelet client identity", "lastUpdateTime":now_rfc3339()}], "certificate":diorama_pki::base64_encode(certificate.as_bytes())});
    client
        .replace_cluster_object(
            "certificates.k8s.io",
            "CertificateSigningRequest",
            "certificatesigningrequests",
            &name,
            request,
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
    use diorama_datastore::{DatastoreConfig, DatastoreEngine};
    use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};

    async fn setup(dir: &Path) -> ApiserverService {
        let pki = dir.join("pki");
        let ip = "127.0.0.1".parse().unwrap();
        ClusterPki::new(ClusterPkiConfig::new(pki.clone(), "controller".into(), ip))
            .reconcile()
            .unwrap();
        let (engine, _) = DatastoreEngine::open(DatastoreConfig::new(dir.join("data"))).unwrap();
        let service = ApiserverService::new(
            ApiserverConfig::default_for_pki(pki, ip),
            KubernetesStorage::new(engine.client(), "/registry"),
        );
        service.check_prerequisites().await.unwrap();
        service
    }
    fn request(node: &str, key: &Path) -> Value {
        json!({"metadata":{"generateName":"worker-"},"spec":{"request":diorama_pki::base64_encode(diorama_pki::bootstrap::kubelet_request(node,key).unwrap().as_bytes()),"signerName":diorama_pki::bootstrap::KUBELET_SIGNER,"usages":["digital signature","client auth"],"expirationSeconds":600}})
    }
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn bootstrap_renewal_expiry_and_leader_exclusion() {
        let temp = tempfile::tempdir().unwrap();
        let service = setup(temp.path()).await;
        let admin = service.admin_client();
        let secret = json!({"metadata":{"name":"bootstrap-token-abcdef"},"type":"bootstrap.kubernetes.io/token","stringData":{"token-id":"abcdef","token-secret":"0123456789abcdef","usage-bootstrap-authentication":"true","expiration":diorama_apiserver::time::rfc3339_seconds(diorama_apiserver::time::now_unix()+3600)}});
        admin
            .create_secret_object("kube-system", secret)
            .await
            .unwrap();
        let bootstrap = service
            .bootstrap_client("abcdef.0123456789abcdef")
            .await
            .unwrap();
        let group = "certificates.k8s.io";
        let plural = "certificatesigningrequests";
        let csr = bootstrap
            .create_cluster_object(
                group,
                "CertificateSigningRequest",
                plural,
                request("joined", &temp.path().join("worker.key")),
            )
            .await
            .unwrap();
        let ca = temp.path().join("pki/ca.crt");
        reconcile(&admin, &ca).await.unwrap();
        let signed = admin
            .get_cluster_object(group, plural, csr["metadata"]["name"].as_str().unwrap())
            .await
            .unwrap();
        let certificate = String::from_utf8(
            diorama_pki::base64_decode(signed["status"]["certificate"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let identity = diorama_pki::verify_certificate_chain(
            &certificate,
            &std::fs::read_to_string(&ca).unwrap(),
        )
        .unwrap();
        assert_eq!(identity.common_name, "system:node:joined");
        admin
            .create_node(json!({"metadata":{"name":"joined"}}))
            .await
            .unwrap();
        let node = service.node_client("joined");
        assert!(
            node.create_cluster_object(
                group,
                "CertificateSigningRequest",
                plural,
                request("another", &temp.path().join("other.key"))
            )
            .await
            .is_err()
        );
        let renewal = node
            .create_cluster_object(
                group,
                "CertificateSigningRequest",
                plural,
                request("joined", &temp.path().join("worker.key")),
            )
            .await
            .unwrap();
        reconcile(&admin, &ca).await.unwrap();
        let renewed = admin
            .get_cluster_object(group, plural, renewal["metadata"]["name"].as_str().unwrap())
            .await
            .unwrap();
        assert!(
            renewed
                .pointer("/status/certificate")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        );
        assert!(crate::leader::acquire(&admin, "first").await.unwrap());
        assert!(!crate::leader::acquire(&admin, "second").await.unwrap());
        let mut lease = admin
            .get_lease("kube-system", "kube-controller-manager")
            .await
            .unwrap();
        lease["spec"]["renewTime"] = json!("2000-01-01T00:00:00Z");
        admin
            .update_lease("kube-system", "kube-controller-manager", lease)
            .await
            .unwrap();
        assert!(crate::leader::acquire(&admin, "second").await.unwrap());
        let mut secret = admin
            .get_secret("kube-system", "bootstrap-token-abcdef")
            .await
            .unwrap();
        secret["data"]["expiration"] = json!(diorama_pki::base64_encode(b"2000-01-01T00:00:00Z"));
        admin
            .replace_namespaced_object(
                "",
                "Secret",
                "secrets",
                "kube-system",
                "bootstrap-token-abcdef",
                secret,
            )
            .await
            .unwrap();
        assert!(
            service
                .bootstrap_client("abcdef.0123456789abcdef")
                .await
                .is_none()
        );
        reconcile(&admin, &ca).await.unwrap();
        assert!(
            admin
                .get_secret("kube-system", "bootstrap-token-abcdef")
                .await
                .is_err()
        );
    }
}
