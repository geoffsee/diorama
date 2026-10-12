use std::path::{Path, PathBuf};

use crate::error::DatastoreError;

pub const DEFAULT_ETCD_CLIENT_PORT: u16 = 2379;
pub const DEFAULT_ETCD_PEER_PORT: u16 = 2380;
pub const DEFAULT_QUOTA_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatastoreConfig {
    pub data_dir: PathBuf,
    pub listen_client_urls: Vec<String>,
    pub listen_peer_urls: Vec<String>,
    pub client_cert_auth: bool,
    pub ca_file: Option<PathBuf>,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub quota_backend_bytes: u64,
    pub auto_repair_wal: bool,
}

impl DatastoreConfig {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            listen_client_urls: vec![format!("https://127.0.0.1:{DEFAULT_ETCD_CLIENT_PORT}")],
            listen_peer_urls: vec![format!("https://127.0.0.1:{DEFAULT_ETCD_PEER_PORT}")],
            client_cert_auth: false,
            ca_file: None,
            cert_file: None,
            key_file: None,
            quota_backend_bytes: DEFAULT_QUOTA_BYTES,
            auto_repair_wal: false,
        }
    }

    #[must_use]
    pub fn with_client_tls(
        mut self,
        ca_file: impl Into<PathBuf>,
        cert_file: impl Into<PathBuf>,
        key_file: impl Into<PathBuf>,
    ) -> Self {
        self.client_cert_auth = true;
        self.ca_file = Some(ca_file.into());
        self.cert_file = Some(cert_file.into());
        self.key_file = Some(key_file.into());
        self
    }

    #[must_use]
    pub fn with_wal_repair(mut self, enabled: bool) -> Self {
        self.auto_repair_wal = enabled;
        self
    }

    #[must_use]
    pub fn wal_path(&self) -> PathBuf {
        self.data_dir.join("member/wal/00000001.wal")
    }

    #[must_use]
    pub fn snapshot_path(&self) -> PathBuf {
        self.data_dir.join("snapshot.db")
    }

    pub fn validate(&self) -> Result<(), DatastoreError> {
        let s = self.data_dir.to_string_lossy();
        if s.is_empty() || s == "." || s == "/" {
            return Err(DatastoreError::UnsafePath(format!(
                "unsafe datastore directory: {s}"
            )));
        }
        if self.data_dir.is_symlink() {
            return Err(DatastoreError::UnsafePath(
                "symlink datastore directory is rejected".into(),
            ));
        }
        if let Ok(canonical) = self.data_dir.canonicalize()
            && canonical == Path::new("/")
        {
            return Err(DatastoreError::UnsafePath(
                "canonical root / is rejected".into(),
            ));
        }

        if self.client_cert_auth {
            let Some(ca) = &self.ca_file else {
                return Err(DatastoreError::AuthenticationConfig(
                    "client certificate authentication requested but ca_file is missing".into(),
                ));
            };
            if !ca.exists() {
                return Err(DatastoreError::AuthenticationConfig(format!(
                    "CA file does not exist: {}",
                    ca.display()
                )));
            }

            let Some(cert) = &self.cert_file else {
                return Err(DatastoreError::AuthenticationConfig(
                    "client certificate authentication requested but cert_file is missing".into(),
                ));
            };
            if !cert.exists() {
                return Err(DatastoreError::AuthenticationConfig(format!(
                    "Certificate file does not exist: {}",
                    cert.display()
                )));
            }

            let Some(key) = &self.key_file else {
                return Err(DatastoreError::AuthenticationConfig(
                    "client certificate authentication requested but key_file is missing".into(),
                ));
            };
            if !key.exists() {
                return Err(DatastoreError::AuthenticationConfig(format!(
                    "Key file does not exist: {}",
                    key.display()
                )));
            }
        }

        Ok(())
    }
}
