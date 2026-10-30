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
    // `--all-features` enables both rustls crypto providers. Pick aws-lc once.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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

#[derive(Debug)]
pub(crate) struct AnyCertVerifier;

impl rustls::client::danger::ServerCertVerifier for AnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

pub(crate) fn tls_connector_for_ca(ca_bundle_pem: Option<&str>) -> tokio_rustls::TlsConnector {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client_config = if let Some(pem_str) = ca_bundle_pem {
        let mut root_store = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(pem_str.as_bytes()).flatten() {
            let _ = root_store.add(cert);
        }
        if root_store.is_empty() {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCertVerifier))
                .with_no_client_auth()
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertVerifier))
            .with_no_client_auth()
    };
    tokio_rustls::TlsConnector::from(Arc::new(client_config))
}
