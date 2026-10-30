use std::net::SocketAddr;
use std::path::PathBuf;

use crate::engine::DatastoreEngine;
use crate::error::DatastoreError;
use crate::model::{KeyValue, RemoteKvRequest, RemoteKvResponse, WatchReceiver};
use crate::quic::{execute_remote_kv_rpc, start_remote_kv_watch};

#[derive(Clone, Debug)]
enum ClientBackend {
    Local(Box<DatastoreEngine>),
    Remote {
        peer_addr: SocketAddr,
        cert_file: Option<PathBuf>,
        key_file: Option<PathBuf>,
    },
}

#[derive(Clone, Debug)]
pub struct DatastoreClient {
    backend: ClientBackend,
}

impl DatastoreClient {
    #[must_use]
    pub fn new(engine: DatastoreEngine) -> Self {
        Self {
            backend: ClientBackend::Local(Box::new(engine)),
        }
    }

    #[must_use]
    pub fn new_remote(
        peer_addr: SocketAddr,
        cert_file: Option<PathBuf>,
        key_file: Option<PathBuf>,
    ) -> Self {
        Self {
            backend: ClientBackend::Remote {
                peer_addr,
                cert_file,
                key_file,
            },
        }
    }

    pub async fn current_revision(&self) -> u64 {
        match &self.backend {
            ClientBackend::Local(engine) => engine.current_revision().await,
            ClientBackend::Remote {
                peer_addr,
                cert_file,
                key_file,
            } => match Box::pin(execute_remote_kv_rpc(
                *peer_addr,
                cert_file.as_deref(),
                key_file.as_deref(),
                &RemoteKvRequest::CurrentRevision,
            ))
            .await
            {
                Ok(RemoteKvResponse::Revision(rev)) => rev,
                _ => 0,
            },
        }
    }

    pub async fn get(&self, key: &str) -> Result<Option<KeyValue>, DatastoreError> {
        match &self.backend {
            ClientBackend::Local(engine) => engine.get(key).await,
            ClientBackend::Remote {
                peer_addr,
                cert_file,
                key_file,
            } => match Box::pin(execute_remote_kv_rpc(
                *peer_addr,
                cert_file.as_deref(),
                key_file.as_deref(),
                &RemoteKvRequest::Get {
                    key: key.to_string(),
                },
            ))
            .await?
            {
                RemoteKvResponse::Value(val) => Ok(val),
                _ => Err(DatastoreError::Fatal(
                    "unexpected remote get response".into(),
                )),
            },
        }
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<KeyValue>, DatastoreError> {
        match &self.backend {
            ClientBackend::Local(engine) => engine.list(prefix).await,
            ClientBackend::Remote {
                peer_addr,
                cert_file,
                key_file,
            } => match Box::pin(execute_remote_kv_rpc(
                *peer_addr,
                cert_file.as_deref(),
                key_file.as_deref(),
                &RemoteKvRequest::List {
                    prefix: prefix.to_string(),
                },
            ))
            .await?
            {
                RemoteKvResponse::List(items) => Ok(items),
                _ => Err(DatastoreError::Fatal(
                    "unexpected remote list response".into(),
                )),
            },
        }
    }

    pub async fn create(&self, key: &str, value: Vec<u8>) -> Result<KeyValue, DatastoreError> {
        match &self.backend {
            ClientBackend::Local(engine) => engine.create(key, value).await,
            ClientBackend::Remote {
                peer_addr,
                cert_file,
                key_file,
            } => match Box::pin(execute_remote_kv_rpc(
                *peer_addr,
                cert_file.as_deref(),
                key_file.as_deref(),
                &RemoteKvRequest::Create {
                    key: key.to_string(),
                    value,
                },
            ))
            .await?
            {
                RemoteKvResponse::Mutated(outcome) => outcome.into_kv_result(),
                _ => Err(DatastoreError::Fatal(
                    "unexpected remote create response".into(),
                )),
            },
        }
    }

    pub async fn update(
        &self,
        key: &str,
        value: Vec<u8>,
        expected_mod_revision: Option<u64>,
    ) -> Result<KeyValue, DatastoreError> {
        match &self.backend {
            ClientBackend::Local(engine) => engine.update(key, value, expected_mod_revision).await,
            ClientBackend::Remote {
                peer_addr,
                cert_file,
                key_file,
            } => match Box::pin(execute_remote_kv_rpc(
                *peer_addr,
                cert_file.as_deref(),
                key_file.as_deref(),
                &RemoteKvRequest::Update {
                    key: key.to_string(),
                    value,
                    expected_mod_revision,
                },
            ))
            .await?
            {
                RemoteKvResponse::Mutated(outcome) => outcome.into_kv_result(),
                _ => Err(DatastoreError::Fatal(
                    "unexpected remote update response".into(),
                )),
            },
        }
    }

    pub async fn delete(
        &self,
        key: &str,
        expected_mod_revision: Option<u64>,
    ) -> Result<Option<KeyValue>, DatastoreError> {
        match &self.backend {
            ClientBackend::Local(engine) => engine.delete(key, expected_mod_revision).await,
            ClientBackend::Remote {
                peer_addr,
                cert_file,
                key_file,
            } => match Box::pin(execute_remote_kv_rpc(
                *peer_addr,
                cert_file.as_deref(),
                key_file.as_deref(),
                &RemoteKvRequest::Delete {
                    key: key.to_string(),
                    expected_mod_revision,
                },
            ))
            .await?
            {
                RemoteKvResponse::Mutated(outcome) => outcome.into_delete_result(),
                _ => Err(DatastoreError::Fatal(
                    "unexpected remote delete response".into(),
                )),
            },
        }
    }

    pub async fn watch(&self, prefix: &str) -> WatchReceiver {
        match &self.backend {
            ClientBackend::Local(engine) => engine.watch(prefix).await,
            ClientBackend::Remote {
                peer_addr,
                cert_file,
                key_file,
            } => {
                start_remote_kv_watch(
                    *peer_addr,
                    cert_file.clone(),
                    key_file.clone(),
                    prefix.to_string(),
                )
                .await
            },
        }
    }

    pub async fn create_backup(
        &self,
        backup_dir: &std::path::Path,
    ) -> Result<crate::backup::BackupMetadata, DatastoreError> {
        match &self.backend {
            ClientBackend::Local(engine) => engine.create_backup(backup_dir).await,
            ClientBackend::Remote { .. } => Err(DatastoreError::Fatal(
                "backup is not supported on a remote worker client".into(),
            )),
        }
    }

    pub async fn register_bootstrap_token(
        &self,
        token: &diorama_pki::token::JoinToken,
    ) -> Result<KeyValue, DatastoreError> {
        let issued_key = format!(
            "{}{}",
            DatastoreEngine::BOOTSTRAP_ISSUED_PREFIX,
            token.token_id
        );
        match self.create(&issued_key, b"issued".to_vec()).await {
            Ok(_) | Err(DatastoreError::KeyAlreadyExists(_)) => {},
            Err(err) => return Err(err),
        }
        let key = format!(
            "{}{}",
            DatastoreEngine::BOOTSTRAP_SECRET_PREFIX,
            token.token_id
        );
        let value = serde_json::to_vec(&token.to_bootstrap_secret_json())?;
        match self.create(&key, value.clone()).await {
            Ok(kv) => Ok(kv),
            Err(DatastoreError::KeyAlreadyExists(_)) => self.update(&key, value, None).await,
            Err(err) => Err(err),
        }
    }

    pub async fn list_bootstrap_tokens(
        &self,
    ) -> Result<Vec<diorama_pki::token::BootstrapTokenRecord>, DatastoreError> {
        let items = self.list(DatastoreEngine::BOOTSTRAP_SECRET_PREFIX).await?;
        let mut records = Vec::new();
        for kv in items {
            let Ok(secret) = serde_json::from_slice::<serde_json::Value>(&kv.value) else {
                continue;
            };
            let Some(rec) = diorama_pki::token::JoinToken::from_bootstrap_secret_json(&secret)
            else {
                continue;
            };
            let revoked_key = format!(
                "{}{}",
                DatastoreEngine::BOOTSTRAP_REVOKED_PREFIX,
                rec.token_id
            );
            if self.get(&revoked_key).await?.is_none() {
                records.push(rec);
            }
        }
        Ok(records)
    }

    pub async fn invalidate_bootstrap_token(&self, token_id: &str) -> Result<bool, DatastoreError> {
        let secret_key = format!("{}{token_id}", DatastoreEngine::BOOTSTRAP_SECRET_PREFIX);
        let deleted = self.delete(&secret_key, None).await?.is_some();
        let revoked_key = format!("{}{token_id}", DatastoreEngine::BOOTSTRAP_REVOKED_PREFIX);
        match self.create(&revoked_key, b"revoked".to_vec()).await {
            Ok(_) | Err(DatastoreError::KeyAlreadyExists(_)) => {},
            Err(err) => return Err(err),
        }
        Ok(deleted)
    }
}
