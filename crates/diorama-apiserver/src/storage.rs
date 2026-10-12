use diorama_datastore::{DatastoreClient, DatastoreError, KeyValue, WatchReceiver};

use crate::error::ApiserverError;

/// Storage coordinator translating Kubernetes API object persistence
/// to the revision-based `diorama-datastore` etcd engine.
#[derive(Clone, Debug)]
pub struct KubernetesStorage {
    client: DatastoreClient,
    prefix: String,
}

impl KubernetesStorage {
    pub fn new(client: DatastoreClient, prefix: impl Into<String>) -> Self {
        Self {
            client,
            prefix: prefix.into(),
        }
    }

    #[must_use]
    pub fn client(&self) -> &DatastoreClient {
        &self.client
    }

    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Verifies storage health and responsiveness.
    pub async fn check_health(&self) -> Result<(), ApiserverError> {
        let test_key = format!("{}/healthz_probe", self.prefix);
        match self.client.get(&test_key).await {
            Ok(_) => Ok(()),
            Err(e) => Err(ApiserverError::StorageUnusable {
                reason: format!("datastore get failed: {e}"),
            }),
        }
    }

    pub async fn current_revision(&self) -> u64 {
        self.client.current_revision().await
    }

    pub async fn get(&self, key: &str) -> Result<Option<KeyValue>, ApiserverError> {
        self.client
            .get(key)
            .await
            .map_err(|e| ApiserverError::StorageUnusable {
                reason: format!("get failed for {key}: {e}"),
            })
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<KeyValue>, ApiserverError> {
        self.client
            .list(prefix)
            .await
            .map_err(|e| ApiserverError::StorageUnusable {
                reason: format!("list failed for {prefix}: {e}"),
            })
    }

    pub async fn create(&self, key: &str, value: Vec<u8>) -> Result<KeyValue, ApiserverError> {
        self.client.create(key, value).await.map_err(|e| match e {
            DatastoreError::KeyAlreadyExists { .. } => ApiserverError::Conflict {
                resource: "storage".to_string(),
                name: key.to_string(),
            },
            other => ApiserverError::StorageUnusable {
                reason: format!("create failed for {key}: {other}"),
            },
        })
    }

    pub async fn update(
        &self,
        key: &str,
        value: Vec<u8>,
        expected_mod_revision: Option<u64>,
    ) -> Result<KeyValue, ApiserverError> {
        self.client
            .update(key, value, expected_mod_revision)
            .await
            .map_err(|e| match e {
                DatastoreError::RevisionMismatch { .. } => ApiserverError::Conflict {
                    resource: "storage".to_string(),
                    name: key.to_string(),
                },
                DatastoreError::KeyNotFound { .. } => ApiserverError::NotFound {
                    resource: "storage".to_string(),
                    name: key.to_string(),
                },
                other => ApiserverError::StorageUnusable {
                    reason: format!("update failed for {key}: {other}"),
                },
            })
    }

    pub async fn delete(
        &self,
        key: &str,
        expected_mod_revision: Option<u64>,
    ) -> Result<Option<KeyValue>, ApiserverError> {
        self.client
            .delete(key, expected_mod_revision)
            .await
            .map_err(|e| match e {
                DatastoreError::RevisionMismatch { .. } => ApiserverError::Conflict {
                    resource: "storage".to_string(),
                    name: key.to_string(),
                },
                other => ApiserverError::StorageUnusable {
                    reason: format!("delete failed for {key}: {other}"),
                },
            })
    }

    pub async fn watch(&self, prefix: &str) -> WatchReceiver {
        self.client.watch(prefix).await
    }
}
