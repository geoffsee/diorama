//! The kubelet's API boundary. Production constructs HTTPS; the in-process adapter
//! exists for deterministic component tests only.
use diorama_apiserver::{ApiserverError, KubernetesApiClient, transport::HttpsClient};
use serde_json::{Value, json};
use std::sync::Arc;
#[derive(Clone, Debug)]
pub enum NodeApi {
    Https { client: HttpsClient, node: String },
    InProcess(Arc<KubernetesApiClient>),
}
impl From<Arc<KubernetesApiClient>> for NodeApi {
    fn from(client: Arc<KubernetesApiClient>) -> Self {
        Self::InProcess(client)
    }
}
impl NodeApi {
    pub async fn watch_pods(&self) -> Result<(), ApiserverError> {
        match self {
            Self::Https { client, node } => {
                let list = self.list_all_pods().await?;
                let revision = list
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("0");
                client.watch_once(&format!("/api/v1/pods?watch=true&timeoutSeconds=30&resourceVersion={revision}&fieldSelector=spec.nodeName%3D{node}")).await
            },
            Self::InProcess(_) => std::future::pending().await,
        }
    }

    pub fn https(path: impl Into<std::path::PathBuf>, node: String) -> Self {
        Self::Https {
            client: HttpsClient::new(path),
            node,
        }
    }
    pub async fn get_node(&self, name: &str) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.get_node(name).await,
            Self::Https { client, .. } => {
                let value = client
                    .request("GET", &format!("/api/v1/nodes/{name}"), None)
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn create_node(&self, node: Value) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.create_node(node).await,
            Self::Https { client, .. } => {
                let value = client.request("POST", "/api/v1/nodes", Some(node)).await?;
                Ok(value)
            },
        }
    }
    pub async fn update_node(&self, name: &str, node: Value) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.update_node(name, node).await,
            Self::Https { client, .. } => {
                let value = client
                    .request("PUT", &format!("/api/v1/nodes/{name}"), Some(node))
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn patch_node_status(
        &self,
        name: &str,
        status: Value,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.patch_node_status(name, status).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "PATCH",
                        &format!("/api/v1/nodes/{name}/status"),
                        Some(json!({"status":status})),
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn get_lease(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.get_lease(namespace, name).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "GET",
                        &format!(
                            "/apis/coordination.k8s.io/v1/namespaces/{namespace}/leases/{name}"
                        ),
                        None,
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn create_lease(
        &self,
        namespace: &str,
        lease: Value,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.create_lease(namespace, lease).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "POST",
                        &format!("/apis/coordination.k8s.io/v1/namespaces/{namespace}/leases"),
                        Some(lease),
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn update_lease(
        &self,
        namespace: &str,
        name: &str,
        lease: Value,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.update_lease(namespace, name, lease).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "PUT",
                        &format!(
                            "/apis/coordination.k8s.io/v1/namespaces/{namespace}/leases/{name}"
                        ),
                        Some(lease),
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn get_pod(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.get_pod(namespace, name).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "GET",
                        &format!("/api/v1/namespaces/{namespace}/pods/{name}"),
                        None,
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn update_pod(
        &self,
        namespace: &str,
        name: &str,
        pod: Value,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.update_pod(namespace, name, pod).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "PUT",
                        &format!("/api/v1/namespaces/{namespace}/pods/{name}"),
                        Some(pod),
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn patch_pod_status(
        &self,
        namespace: &str,
        name: &str,
        status: Value,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.patch_pod_status(namespace, name, status).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "PATCH",
                        &format!("/api/v1/namespaces/{namespace}/pods/{name}/status"),
                        Some(json!({"status":status})),
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn list_services(&self, namespace: &str) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.list_services(namespace).await,
            Self::Https { client, .. } => {
                let path = resource_path("", "services", namespace);
                client.request("GET", &path, None).await
            },
        }
    }
    pub async fn list_nodes(&self) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.list_nodes().await,
            Self::Https { client, .. } => {
                let value = client.request("GET", "/api/v1/nodes", None).await?;
                Ok(value)
            },
        }
    }
    pub async fn get_configmap(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.get_configmap(namespace, name).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "GET",
                        &format!("/api/v1/namespaces/{namespace}/configmaps/{name}"),
                        None,
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn get_secret(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.get_secret(namespace, name).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "GET",
                        &format!("/api/v1/namespaces/{namespace}/secrets/{name}"),
                        None,
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn get_service_account(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.get_service_account(namespace, name).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "GET",
                        &format!("/api/v1/namespaces/{namespace}/serviceaccounts/{name}"),
                        None,
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn get_pvc(&self, namespace: &str, name: &str) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.get_pvc(namespace, name).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "GET",
                        &format!("/api/v1/namespaces/{namespace}/persistentvolumeclaims/{name}"),
                        None,
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn get_pv(&self, name: &str) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.get_pv(name).await,
            Self::Https { client, .. } => {
                let value = client
                    .request("GET", &format!("/api/v1/persistentvolumes/{name}"), None)
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn create_token_request(
        &self,
        namespace: &str,
        sa_name: &str,
        doc: Value,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.create_token_request(namespace, sa_name, doc).await,
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "POST",
                        &format!("/api/v1/namespaces/{namespace}/serviceaccounts/{sa_name}/token"),
                        Some(doc),
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn get_cluster_object(
        &self,
        group: &str,
        plural: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.get_cluster_object(group, plural, name).await,
            Self::Https { client, .. } => {
                let value = client
                    .request("GET", &format!("/apis/{group}/v1/{plural}/{name}"), None)
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn list_cluster_objects(
        &self,
        group: &str,
        kind_list: &str,
        plural: &str,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => client.list_cluster_objects(group, kind_list, plural).await,
            Self::Https { client, .. } => {
                let _ = kind_list;
                let value = client
                    .request("GET", &format!("/apis/{group}/v1/{plural}"), None)
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn get_namespaced_object(
        &self,
        group: &str,
        plural: &str,
        namespace: &str,
        name: &str,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => {
                client
                    .get_namespaced_object(group, plural, namespace, name)
                    .await
            },
            Self::Https { client, .. } => {
                let value = client
                    .request(
                        "GET",
                        &format!("{}/{name}", resource_path(group, plural, namespace)),
                        None,
                    )
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn create_namespaced_object(
        &self,
        group: &str,
        kind: &str,
        plural: &str,
        namespace: &str,
        doc: Value,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => {
                client
                    .create_namespaced_object(group, kind, plural, namespace, doc)
                    .await
            },
            Self::Https { client, .. } => {
                let _ = kind;
                let value = client
                    .request("POST", &resource_path(group, plural, namespace), Some(doc))
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn list_namespaced_objects(
        &self,
        group: &str,
        kind_list: &str,
        plural: &str,
        namespace: &str,
    ) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(client) => {
                client
                    .list_namespaced_objects(group, kind_list, plural, namespace)
                    .await
            },
            Self::Https { client, .. } => {
                let _ = kind_list;
                let value = client
                    .request("GET", &resource_path(group, plural, namespace), None)
                    .await?;
                Ok(value)
            },
        }
    }
    pub async fn delete_pod_options(
        &self,
        namespace: &str,
        name: &str,
        grace_period_seconds: Option<i64>,
    ) -> Result<Option<Value>, ApiserverError> {
        match self {
            Self::InProcess(client) => {
                client
                    .delete_pod_options(namespace, name, grace_period_seconds)
                    .await
            },
            Self::Https { client, .. } => {
                let value = client.request("DELETE", &format!("/api/v1/namespaces/{namespace}/pods/{name}"), Some(json!({"apiVersion":"v1","kind":"DeleteOptions","gracePeriodSeconds":grace_period_seconds}))).await?;
                Ok(Some(value))
            },
        }
    }
    pub async fn delete_pod(&self, namespace: &str, name: &str) -> Result<(), ApiserverError> {
        match self {
            Self::InProcess(client) => client.delete_pod(namespace, name).await,
            Self::Https { client, .. } => {
                let _ = client
                    .request(
                        "DELETE",
                        &format!("/api/v1/namespaces/{namespace}/pods/{name}"),
                        None,
                    )
                    .await?;
                Ok(())
            },
        }
    }
    pub async fn list_pods(&self, namespace: &str) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(c) => c.list_pods(namespace).await,
            Self::Https { client, node } => client
                .request(
                    "GET",
                    &format!(
                        "/api/v1/namespaces/{namespace}/pods?fieldSelector=spec.nodeName%3D{node}"
                    ),
                    None,
                )
                .await,
        }
    }
    pub async fn list_all_pods(&self) -> Result<Value, ApiserverError> {
        match self {
            Self::InProcess(c) => c.list_all_pods().await,
            Self::Https { client, node } => {
                client
                    .request(
                        "GET",
                        &format!("/api/v1/pods?fieldSelector=spec.nodeName%3D{node}"),
                        None,
                    )
                    .await
            },
        }
    }
}

fn resource_path(group: &str, plural: &str, namespace: &str) -> String {
    let prefix = if group.is_empty() {
        "/api/v1".to_owned()
    } else {
        format!("/apis/{group}/v1")
    };
    if namespace.is_empty() {
        format!("{prefix}/{plural}")
    } else {
        format!("{prefix}/namespaces/{namespace}/{plural}")
    }
}
