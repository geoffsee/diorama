use diorama_addon::{Error, JOB_MANAGER, MANAGER, OWNER, Result, Settings};
use kube::{
    Api, Client, ResourceExt,
    api::{DynamicObject, ListParams, PostParams},
    core::{ApiResource, GroupVersionKind},
};
use serde_json::Value;
use std::{collections::BTreeMap, process::ExitCode, time::Duration};

fn api(client: Client, object: &Value) -> Result<Api<DynamicObject>> {
    let version = object["apiVersion"].as_str().ok_or("missing apiVersion")?;
    let (group, version) = version.split_once('/').unwrap_or(("", version));
    let kind = object["kind"].as_str().ok_or("missing kind")?;
    let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(group, version, kind));
    Ok(if let Some(ns) = object["metadata"]["namespace"].as_str() {
        Api::namespaced_with(client, ns, &resource)
    } else {
        Api::all_with(client, &resource)
    })
}

fn ensure_owner(existing: &DynamicObject, addon: &str) -> Result<()> {
    if existing.labels().get(OWNER).map(String::as_str) != Some(addon)
        || existing.labels().get(MANAGER).map(String::as_str) != Some(JOB_MANAGER)
    {
        return Err(format!("{} exists and is not owned by this add-on Job. Preserve or explicitly remove the legacy installation before installing this pack.", existing.name_any()).into());
    }
    Ok(())
}

fn replacement(desired: &DynamicObject, existing: &DynamicObject) -> DynamicObject {
    let mut replacement = desired.clone();
    // Preserve server identity and unrelated metadata, including finalizers.
    replacement.metadata = existing.metadata.clone();
    replacement
        .metadata
        .labels
        .get_or_insert_with(BTreeMap::new)
        .extend(desired.labels().clone());
    if desired.types.as_ref().is_some_and(|t| t.kind == "Service") {
        for key in [
            "clusterIP",
            "clusterIPs",
            "ipFamilies",
            "ipFamilyPolicy",
            "healthCheckNodePort",
        ] {
            if let Some(value) = existing.data["spec"].get(key) {
                replacement.data["spec"][key] = value.clone();
            }
        }
    }
    if desired
        .types
        .as_ref()
        .is_some_and(|t| t.kind == "ConfigMap")
    {
        replacement.data["data"] = existing.data["data"].clone();
    }
    replacement
}

async fn install(client: Client, settings: &Settings) -> Result<()> {
    let (secret_name, keys) = settings.secret();
    let secrets: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), &settings.namespace);
    let secret = secrets.get_opt(secret_name).await?.ok_or_else(|| {
        format!(
            "create Secret {}/{secret_name} with keys {} before running the Job",
            settings.namespace,
            keys.join(", ")
        )
    })?;
    for key in keys {
        if secret
            .data
            .as_ref()
            .and_then(|data| data.get(*key))
            .is_none_or(|v| v.0.is_empty())
        {
            return Err(format!("Secret {secret_name} is missing nonempty key {key}").into());
        }
    }
    let resources = diorama_addon::resources(settings)?;
    // Check every collision before the first write; never adopt a legacy or unrelated resource.
    for object in &resources {
        let api = api(client.clone(), object)?;
        let name = object["metadata"]["name"].as_str().ok_or("missing name")?;
        if let Some(existing) = api.get_opt(name).await? {
            ensure_owner(&existing, &settings.addon)?;
        }
    }
    for object in resources {
        let api = api(client.clone(), &object)?;
        let desired: DynamicObject = serde_json::from_value(object)?;
        let name = desired.name_any();
        let mut applied = false;
        for _ in 0..5 {
            let current = api.get_opt(&name).await?;
            let result = if let Some(existing) = current {
                ensure_owner(&existing, &settings.addon)?;
                let replacement = replacement(&desired, &existing);
                api.replace(&name, &PostParams::default(), &replacement)
                    .await
            } else {
                api.create(&PostParams::default(), &desired).await
            };
            match result {
                Ok(_) => {
                    applied = true;
                    break;
                },
                Err(kube::Error::Api(error)) if error.code == 409 => {},
                Err(error) => return Err(error.into()),
            }
        }
        if !applied {
            return Err(format!(
                "{name}: concurrent updates prevented installation; rerun the Job"
            )
            .into());
        }
        println!("Applied {name}");
    }
    wait_ready(client, settings).await
}

async fn wait_ready(client: Client, settings: &Settings) -> Result<()> {
    let deployments: Api<k8s_openapi::api::apps::v1::Deployment> =
        Api::namespaced(client.clone(), &settings.namespace);
    let ready = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            let deployment = deployments.get(&settings.addon).await?;
            if let Some(status) = deployment.status
                && status.observed_generation.unwrap_or(0)
                    >= deployment.metadata.generation.unwrap_or(1)
                && status.updated_replicas.unwrap_or(0) >= 1
                && status.available_replicas.unwrap_or(0) >= 1
            {
                return Ok::<(), kube::Error>(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await;
    if let Ok(result) = ready {
        return result.map_err(Into::into);
    }
    let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(client, &settings.namespace);
    if let Ok(pods) = pods
        .list(&ListParams::default().labels(&format!("app={}", settings.addon)))
        .await
    {
        for pod in pods {
            eprintln!(
                "Pod {} phase {:?}",
                pod.name_any(),
                pod.status.as_ref().and_then(|s| s.phase.as_ref())
            );
            for status in pod
                .status
                .and_then(|s| s.container_statuses)
                .unwrap_or_default()
            {
                eprintln!(
                    "Container {} ready={} state={:?}",
                    status.name, status.ready, status.state
                );
            }
        }
    }
    Err("workload did not become ready in 300s; check the loaded image, nodeName, Secret and pod events".into())
}

async fn run() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let get = |name| std::env::var(name).map_err(|_| -> Error { format!("missing {name}").into() });
    let settings = Settings {
        addon: get("DIORAMA_ADDON")?,
        image: get("DIORAMA_ADDON_IMAGE")?,
        namespace: get("DIORAMA_ADDON_NAMESPACE")?,
        node: get("DIORAMA_ADDON_NODE")?,
    };
    settings.validate()?;
    let mut config = kube::Config::incluster()?;
    config.connect_timeout = Some(Duration::from_secs(10));
    config.read_timeout = Some(Duration::from_secs(30));
    install(Client::try_from(config)?, &settings).await?;
    println!("{} is ready", settings.addon);
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("add-on installation failed: {error}");
            ExitCode::FAILURE
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ownership_refuses_legacy_and_unrelated_resources() {
        let mut object: DynamicObject = serde_json::from_value(json!({
            "apiVersion":"v1", "kind":"Service", "metadata":{"name":"d2k"}
        }))
        .unwrap();
        assert!(ensure_owner(&object, "d2k").is_err());
        object.metadata.labels = Some(BTreeMap::from([
            (OWNER.into(), "d2k".into()),
            (MANAGER.into(), JOB_MANAGER.into()),
        ]));
        assert!(ensure_owner(&object, "d2k").is_ok());
        assert!(ensure_owner(&object, "portainer-agent").is_err());
    }

    #[test]
    fn replacement_preserves_service_identity_and_user_config() {
        let existing: DynamicObject = serde_json::from_value(json!({
            "apiVersion":"v1", "kind":"Service",
            "metadata":{"name":"d2k","resourceVersion":"12","annotations":{"user":"keep"}},
            "spec":{"clusterIP":"10.43.0.5","clusterIPs":["10.43.0.5"],"ports":[{"port":2376}]}
        }))
        .unwrap();
        let mut desired = existing.clone();
        desired.data["spec"] = json!({"ports":[{"port":2377}]});
        let updated = replacement(&desired, &existing);
        assert_eq!(updated.metadata.resource_version.as_deref(), Some("12"));
        assert_eq!(updated.annotations()["user"], "keep");
        assert_eq!(updated.data["spec"]["clusterIP"], "10.43.0.5");
        assert_eq!(updated.data["spec"]["ports"][0]["port"], 2377);
        let existing: DynamicObject = serde_json::from_value(json!({
            "apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"edge"},
            "data":{"EDGE_ASYNC":"true","user":"keep"}
        }))
        .unwrap();
        let mut desired = existing.clone();
        desired.data["data"] = json!({"EDGE_ASYNC":"false"});
        assert_eq!(
            replacement(&desired, &existing).data["data"],
            existing.data["data"]
        );
    }
}
