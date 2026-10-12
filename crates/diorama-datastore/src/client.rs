use crate::engine::DatastoreEngine;
use crate::error::DatastoreError;
use crate::model::{KeyValue, WatchReceiver};

#[derive(Clone, Debug)]
pub struct DatastoreClient {
    engine: DatastoreEngine,
}

impl DatastoreClient {
    pub fn new(engine: DatastoreEngine) -> Self {
        Self { engine }
    }

    pub async fn current_revision(&self) -> u64 {
        self.engine.current_revision().await
    }

    pub async fn get(&self, key: &str) -> Result<Option<KeyValue>, DatastoreError> {
        self.engine.get(key).await
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<KeyValue>, DatastoreError> {
        self.engine.list(prefix).await
    }

    pub async fn create(&self, key: &str, value: Vec<u8>) -> Result<KeyValue, DatastoreError> {
        self.engine.create(key, value).await
    }

    pub async fn update(
        &self,
        key: &str,
        value: Vec<u8>,
        expected_mod_revision: Option<u64>,
    ) -> Result<KeyValue, DatastoreError> {
        self.engine.update(key, value, expected_mod_revision).await
    }

    pub async fn delete(
        &self,
        key: &str,
        expected_mod_revision: Option<u64>,
    ) -> Result<Option<KeyValue>, DatastoreError> {
        self.engine.delete(key, expected_mod_revision).await
    }

    pub async fn watch(&self, prefix: &str) -> WatchReceiver {
        self.engine.watch(prefix).await
    }

    pub async fn create_backup(
        &self,
        backup_dir: &std::path::Path,
    ) -> Result<crate::backup::BackupMetadata, DatastoreError> {
        self.engine.create_backup(backup_dir).await
    }
}
