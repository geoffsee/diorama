//! TLS material for the API server listener.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, WebPkiClientVerifier};

use crate::config::ApiserverConfig;
use crate::error::ApiserverError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerIdentity {
    pub(crate) username: String,
    pub(crate) groups: Vec<String>,
}

pub(crate) fn server_config(config: &ApiserverConfig) -> Result<Arc<ServerConfig>, ApiserverError> {
    let client_ca = load_certs(&config.client_ca_file, "client CA")?;
    let mut roots = RootCertStore::empty();
    for cert in client_ca {
        roots
            .add(cert)
            .map_err(|err| ApiserverError::InvalidCredentials {
                reason: format!("client CA was rejected: {err}"),
            })?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .map_err(|err| ApiserverError::InvalidCredentials {
            reason: format!("client certificate verifier: {err}"),
        })?;
    let server_certs = load_certs(&config.tls_cert_file, "API server certificate")?;
    let key = load_key(&config.tls_private_key_file, "API server private key")?;
    let server = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, key)
        .map_err(|err| ApiserverError::InvalidCredentials {
            reason: format!("API server certificate: {err}"),
        })?;
    Ok(Arc::new(server))
}

pub(crate) fn identity_from_der(der: &[u8]) -> Option<PeerIdentity> {
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der).ok()?;
    let mut username = None;
    let mut groups = Vec::new();
    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
                if let Ok(name) = attr.as_str() {
                    username = Some(name.to_string());
                }
            } else if attr.attr_type() == &x509_parser::oid_registry::OID_X509_ORGANIZATION_NAME
                && let Ok(org) = attr.as_str()
            {
                groups.push(org.to_string());
            }
        }
    }
    let username = username?;
    if !groups.iter().any(|group| group == "system:authenticated") {
        groups.push("system:authenticated".to_string());
    }
    Some(PeerIdentity { username, groups })
}

fn load_certs(path: &Path, name: &str) -> Result<Vec<CertificateDer<'static>>, ApiserverError> {
    let bytes = fs::read(path).map_err(|err| ApiserverError::InvalidCredentials {
        reason: format!("failed to read {name} at {}: {err}", path.display()),
    })?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| ApiserverError::InvalidCredentials {
            reason: format!(
                "{name} at {} is not a PEM certificate: {err}",
                path.display()
            ),
        })?;
    if certs.is_empty() {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!("{name} at {} contained no certificates", path.display()),
        });
    }
    Ok(certs)
}

fn load_key(path: &Path, name: &str) -> Result<PrivateKeyDer<'static>, ApiserverError> {
    let bytes = fs::read(path).map_err(|err| ApiserverError::InvalidCredentials {
        reason: format!("failed to read {name} at {}: {err}", path.display()),
    })?;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|err| ApiserverError::InvalidCredentials {
        reason: format!(
            "{name} at {} is not a PEM private key: {err}",
            path.display()
        ),
    })
}
