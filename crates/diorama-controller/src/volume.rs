//! Bind provisioner-created volumes to their scheduler-selected claims. Filesystem
//! setup and deletion remain exclusively in the node-local provisioner helpers.
use diorama_apiserver::{ApiserverError, KubernetesApiClient, quota::parse_quantity_value};
use serde_json::{Value, json};

pub(crate) async fn reconcile(client: &KubernetesApiClient) -> Result<(), ApiserverError> {
    let claims = client.list_pvcs("").await?;
    for claim in claims["items"].as_array().into_iter().flatten() {
        if let Err(error) = request_provisioning(client, claim.clone()).await
            && !matches!(error, ApiserverError::Conflict { .. })
        {
            return Err(error);
        }
    }
    let volumes = client.list_pvs().await?;
    for pv in volumes["items"].as_array().into_iter().flatten() {
        if pv["spec"]["storageClassName"] != "local-path"
            || pv["metadata"].get("deletionTimestamp").is_some()
        {
            continue;
        }
        if let Err(error) = bind(client, pv.clone()).await
            && !matches!(error, ApiserverError::Conflict { .. })
        {
            return Err(error);
        }
    }
    Ok(())
}
async fn request_provisioning(
    client: &KubernetesApiClient,
    mut claim: Value,
) -> Result<(), ApiserverError> {
    if claim["spec"]["storageClassName"] != "local-path"
        || claim["spec"]["volumeName"]
            .as_str()
            .is_some_and(|name| !name.is_empty())
        || claim["metadata"].get("deletionTimestamp").is_some()
    {
        return Ok(());
    }
    let Some(node) =
        claim["metadata"]["annotations"]["volume.kubernetes.io/selected-node"].as_str()
    else {
        return Ok(());
    };
    match client.get_node(node).await {
        Ok(node) if node["metadata"]["labels"]["diorama.io/runtime"] == "ordinary" => {},
        Ok(_) | Err(ApiserverError::NotFound { .. }) => return Ok(()),
        Err(error) => return Err(error),
    }
    let class = match client.get_storage_class("local-path").await {
        Ok(class) => class,
        Err(ApiserverError::NotFound { .. }) => return Ok(()),
        Err(error) => return Err(error),
    };
    if class["provisioner"] != "rancher.io/local-path"
        || class["volumeBindingMode"] != "WaitForFirstConsumer"
    {
        return Ok(());
    }
    let keys = [
        "volume.kubernetes.io/storage-provisioner",
        "volume.beta.kubernetes.io/storage-provisioner",
    ];
    if keys
        .iter()
        .all(|key| claim["metadata"]["annotations"][key] == class["provisioner"])
    {
        return Ok(());
    }
    let namespace = claim["metadata"]["namespace"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let name = claim["metadata"]["name"].as_str().unwrap_or("").to_string();
    // The scheduler owns selected-node. The provisioner starts its node-local
    // helper only after the PV controller supplies the provisioner annotation.
    for key in keys {
        claim["metadata"]["annotations"][key] = class["provisioner"].clone();
    }
    client.update_pvc(&namespace, &name, claim).await?;
    Ok(())
}
async fn bind(client: &KubernetesApiClient, mut pv: Value) -> Result<(), ApiserverError> {
    let Some(namespace) = pv["spec"]["claimRef"]["namespace"]
        .as_str()
        .map(str::to_owned)
    else {
        return Ok(());
    };
    let Some(name) = pv["spec"]["claimRef"]["name"].as_str().map(str::to_owned) else {
        return Ok(());
    };
    let Some(pv_name) = pv["metadata"]["name"].as_str().map(str::to_owned) else {
        return Ok(());
    };
    let mut claim = match client.get_pvc(&namespace, &name).await {
        Ok(claim) if claim["metadata"]["uid"] == pv["spec"]["claimRef"]["uid"] => claim,
        Ok(_) | Err(ApiserverError::NotFound { .. }) => {
            if pv["status"]["phase"] != "Released" {
                pv["status"]["phase"] = json!("Released");
                client.update_pv(&pv_name, pv).await?;
            }
            return Ok(());
        },
        Err(error) => return Err(error),
    };
    if claim["spec"]["storageClassName"] != pv["spec"]["storageClassName"]
        || claim["spec"]["volumeName"]
            .as_str()
            .is_some_and(|name| !name.is_empty() && name != pv_name)
        || claim["spec"]["volumeMode"].as_str().unwrap_or("Filesystem")
            != pv["spec"]["volumeMode"].as_str().unwrap_or("Filesystem")
        || claim["metadata"].get("deletionTimestamp").is_some()
    {
        return Ok(());
    }
    let Some(node) =
        claim["metadata"]["annotations"]["volume.kubernetes.io/selected-node"].as_str()
    else {
        return Ok(());
    };
    let registered = match client.get_node(node).await {
        Ok(node) => node,
        Err(ApiserverError::NotFound { .. }) => return Ok(()),
        Err(error) => return Err(error),
    };
    if registered["metadata"]["labels"]["diorama.io/runtime"] != "ordinary"
        || !targets_node(&pv, node)
    {
        return Ok(());
    }
    let Some(requested) = parse_quantity_value(&claim["spec"]["resources"]["requests"]["storage"])
    else {
        return Ok(());
    };
    if parse_quantity_value(&pv["spec"]["capacity"]["storage"])
        .is_none_or(|capacity| capacity < requested)
    {
        return Ok(());
    }
    let modes = claim["spec"]["accessModes"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !modes.iter().all(|mode| {
        pv["spec"]["accessModes"]
            .as_array()
            .is_some_and(|available| available.contains(mode))
    }) {
        return Ok(());
    }
    if claim["spec"]["volumeName"] != pv_name || claim["status"]["phase"] != "Bound" {
        claim["spec"]["volumeName"] = json!(pv_name);
        claim["metadata"]["annotations"]["pv.kubernetes.io/bind-completed"] = json!("yes");
        claim["metadata"]["annotations"]["pv.kubernetes.io/bound-by-controller"] = json!("yes");
        claim["status"] =
            json!({"phase":"Bound","accessModes":modes,"capacity":pv["spec"]["capacity"]});
        client.update_pvc(&namespace, &name, claim).await?;
    }
    if pv["status"]["phase"] != "Bound" {
        pv["status"]["phase"] = json!("Bound");
        client.update_pv(&pv_name, pv).await?;
    }
    Ok(())
}
fn targets_node(pv: &Value, node: &str) -> bool {
    let Some(terms) = pv
        .pointer("/spec/nodeAffinity/required/nodeSelectorTerms")
        .and_then(Value::as_array)
    else {
        return false;
    };
    terms.iter().any(|term| {
        let Some(expressions) = term["matchExpressions"]
            .as_array()
            .filter(|expressions| expressions.len() == 1)
        else {
            return false;
        };
        let expression = &expressions[0];
        expression["key"] == "kubernetes.io/hostname"
            && expression["operator"] == "In"
            && expression["values"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == node))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use diorama_apiserver::{ApiserverConfig, ApiserverService, KubernetesStorage};
    use diorama_datastore::{DatastoreConfig, DatastoreEngine};
    #[tokio::test]
    async fn binds_only_selected_matching_claim_and_releases_stale_uid() {
        let temp = tempfile::tempdir().unwrap();
        let (engine, _) =
            DatastoreEngine::open(DatastoreConfig::new(temp.path().join("store"))).unwrap();
        diorama_pki::cluster::ClusterPki::new(diorama_pki::cluster::ClusterPkiConfig::new(
            temp.path().to_path_buf(),
            "control".into(),
            "127.0.0.1".parse().unwrap(),
        ))
        .reconcile()
        .unwrap();
        let service = ApiserverService::new(
            ApiserverConfig::default_for_pki(temp.path(), "127.0.0.1".parse().unwrap()),
            KubernetesStorage::new(engine.client(), "/registry"),
        );
        service.check_prerequisites().await.unwrap();
        let client = service.admin_client();

        client.create_storage_class(json!({"metadata":{"name":"local-path"},"provisioner":"rancher.io/local-path","volumeBindingMode":"WaitForFirstConsumer"})).await.unwrap();

        client
            .create_node(
                json!({"metadata":{"name":"worker-2","labels":{"diorama.io/runtime":"ordinary"}}}),
            )
            .await
            .unwrap();
        let claim = client.create_pvc("default", json!({"metadata":{"name":"disk","annotations":{"volume.kubernetes.io/selected-node":"worker-2"}},"spec":{"storageClassName":"local-path","accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}}})).await.unwrap();
        client
            .create_node(
                json!({"metadata":{"name":"foreign","labels":{"diorama.io/runtime":"foreign"}}}),
            )
            .await
            .unwrap();
        for (name, annotations) in [
            ("unselected", json!({})),
            (
                "foreign",
                json!({"volume.kubernetes.io/selected-node":"foreign"}),
            ),
        ] {
            client.create_pvc("default", json!({"metadata":{"name":name,"annotations":annotations},"spec":{"storageClassName":"local-path","accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}}})).await.unwrap();
        }
        let pv = json!({"metadata":{"name":"disk-volume"},"spec":{"storageClassName":"local-path","claimRef":{"namespace":"default","name":"disk","uid":claim["metadata"]["uid"]},"capacity":{"storage":"1Gi"},"accessModes":["ReadWriteOnce"],"nodeAffinity":{"required":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/hostname","operator":"In","values":["worker-1"]}]}]}}}});
        client.create_pv(pv).await.unwrap();
        reconcile(&client).await.unwrap();
        assert_eq!(
            client.get_pvc("default", "disk").await.unwrap()["metadata"]["annotations"]["volume.kubernetes.io/storage-provisioner"],
            "rancher.io/local-path"
        );
        for name in ["unselected", "foreign"] {
            assert!(client.get_pvc("default", name).await.unwrap()["metadata"]["annotations"]["volume.kubernetes.io/storage-provisioner"].is_null());
        }
        assert!(client.get_pvc("default", "disk").await.unwrap()["spec"]["volumeName"].is_null());
        let mut pv = client.get_pv("disk-volume").await.unwrap();
        pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"][0]["values"] =
            json!(["worker-2"]);
        client.update_pv("disk-volume", pv).await.unwrap();
        reconcile(&client).await.unwrap();
        assert_eq!(
            client.get_pvc("default", "disk").await.unwrap()["status"]["phase"],
            "Bound"
        );
        client.delete_pvc("default", "disk").await.unwrap();
        reconcile(&client).await.unwrap();
        assert_eq!(
            client.get_pv("disk-volume").await.unwrap()["status"]["phase"],
            "Released"
        );
        assert!(!temp.path().join("local-path-storage").exists());
    }
}
