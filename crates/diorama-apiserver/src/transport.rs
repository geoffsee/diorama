//! Authenticated HTTPS access shared by node and management clients. Credentials are
//! reloaded for each connection so atomic kubeconfig rotation takes effect immediately.
use crate::ApiserverError;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct HttpsClient {
    kubeconfig: PathBuf,
}

fn credentials() -> ApiserverError {
    ApiserverError::InvalidCredentials {
        reason: "invalid HTTPS kubeconfig or credentials".into(),
    }
}
fn unavailable() -> ApiserverError {
    ApiserverError::StorageUnusable {
        reason: "HTTPS API request failed".into(),
    }
}
fn material(value: &Value, key: &str, base: &Path) -> Result<Vec<u8>, ApiserverError> {
    if let Some(data) = value.get(format!("{key}-data")).and_then(Value::as_str) {
        return diorama_pki::base64_decode(data).map_err(|_| credentials());
    }
    let path = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(credentials)?;
    std::fs::read(base.join(path)).map_err(|_| credentials())
}

impl HttpsClient {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            kubeconfig: path.into(),
        }
    }
    pub fn document(&self) -> Result<Value, ApiserverError> {
        let bytes = std::fs::read_to_string(&self.kubeconfig).map_err(|_| credentials())?;
        serde_saphyr::from_str(&bytes).map_err(|_| credentials())
    }
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, ApiserverError> {
        tokio::time::timeout(Duration::from_secs(45), self.send(method, path, body))
            .await
            .map_err(|_| unavailable())?
    }
    /// Wait for one event on a bounded Kubernetes watch. Callers relist after
    /// disconnects (including HTTP 410) instead of retaining a stale assignment.
    pub async fn watch_once(&self, path: &str) -> Result<(), ApiserverError> {
        tokio::time::timeout(Duration::from_secs(40), async {
            let response = self.response("GET", path, None).await?;
            if !response.status().is_success() {
                return Err(unavailable());
            }
            let mut body = response.into_body();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|_| unavailable())?;
                if frame.data_ref().is_some_and(|bytes| !bytes.is_empty()) {
                    return Ok(());
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| unavailable())?
    }
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, ApiserverError> {
        let response = self.response(method, path, body).await?;
        let status = response.status();
        let bytes = Limited::new(response.into_body(), 32 * 1024 * 1024)
            .collect()
            .await
            .map_err(|_| unavailable())?
            .to_bytes();
        if status.is_success() {
            return serde_json::from_slice(&bytes).map_err(Into::into);
        }
        match status.as_u16() {
            404 => Err(ApiserverError::NotFound {
                resource: path.into(),
                name: String::new(),
            }),
            409 => Err(ApiserverError::Conflict {
                resource: path.into(),
                name: String::new(),
            }),
            401 => Err(ApiserverError::Unauthenticated {
                reason: "API rejected credentials".into(),
            }),
            403 => Err(ApiserverError::Unauthorized {
                reason: serde_json::from_slice::<Value>(&bytes)
                    .ok()
                    .and_then(|v| v["message"].as_str().map(str::to_owned))
                    .unwrap_or_else(|| "API denied request".into()),
            }),
            _ => Err(ApiserverError::BadRequest {
                message: format!("API returned HTTP {}", status.as_u16()),
            }),
        }
    }
    #[allow(clippy::too_many_lines)]
    async fn response(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, ApiserverError> {
        let doc = self.document()?;
        let context_name = doc["current-context"].as_str().ok_or_else(credentials)?;
        let context = doc["contexts"]
            .as_array()
            .ok_or_else(credentials)?
            .iter()
            .find(|c| c["name"].as_str() == Some(context_name))
            .ok_or_else(credentials)?;
        let cluster = doc["clusters"]
            .as_array()
            .ok_or_else(credentials)?
            .iter()
            .find(|c| c["name"] == context["context"]["cluster"])
            .ok_or_else(credentials)?;
        let user = doc["users"]
            .as_array()
            .ok_or_else(credentials)?
            .iter()
            .find(|c| c["name"] == context["context"]["user"])
            .ok_or_else(credentials)?;
        let cluster = &cluster["cluster"];
        let user = &user["user"];
        let endpoint: http::Uri = cluster["server"]
            .as_str()
            .ok_or_else(credentials)?
            .parse()
            .map_err(|_| credentials())?;
        if endpoint.scheme_str() != Some("https") || cluster["insecure-skip-tls-verify"] == true {
            return Err(credentials());
        }
        let authority = endpoint.authority().ok_or_else(credentials)?;
        let host = endpoint
            .host()
            .ok_or_else(credentials)?
            .trim_matches(['[', ']']);
        let base = self.kubeconfig.parent().unwrap_or(Path::new("."));
        let ca = material(cluster, "certificate-authority", base)?;
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&ca) {
            roots
                .add(cert.map_err(|_| credentials())?)
                .map_err(|_| credentials())?;
        }
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let builder = ClientConfig::builder().with_root_certificates(roots);
        let tls = if user.get("token").is_some() {
            builder.with_no_client_auth()
        } else {
            let certs = material(user, "client-certificate", base)?;
            let key = material(user, "client-key", base)?;
            builder
                .with_client_auth_cert(
                    CertificateDer::pem_slice_iter(&certs)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| credentials())?,
                    PrivateKeyDer::from_pem_slice(&key).map_err(|_| credentials())?,
                )
                .map_err(|_| credentials())?
        };
        let tcp = tokio::net::TcpStream::connect((host, endpoint.port_u16().unwrap_or(443)))
            .await
            .map_err(|_| unavailable())?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(tls))
            .connect(
                ServerName::try_from(host.to_string()).map_err(|_| credentials())?,
                tcp,
            )
            .await
            .map_err(|error| ApiserverError::InvalidCredentials {
                reason: format!("HTTPS TLS handshake failed: {error}"),
            })?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| unavailable())?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut request = http::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", authority.as_str())
            .header("Accept", "application/json")
            .header(
                "Content-Type",
                if method == "PATCH" {
                    "application/merge-patch+json"
                } else {
                    "application/json"
                },
            );
        if let Some(token) = user["token"].as_str() {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let bytes = body
            .map(|v| serde_json::to_vec(&v))
            .transpose()?
            .unwrap_or_default();
        let response = sender
            .send_request(
                request
                    .body(Full::new(Bytes::from(bytes)))
                    .map_err(|_| credentials())?,
            )
            .await
            .map_err(|_| unavailable())?;
        Ok(response)
    }
}
