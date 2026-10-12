//! TLS server configuration and listener utilities for the datastore endpoint.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use tokio_rustls::TlsAcceptor;

use crate::config::DatastoreConfig;
use crate::error::DatastoreError;

pub fn build_tls_acceptor(config: &DatastoreConfig) -> Result<TlsAcceptor, DatastoreError> {
    let ca_file = config.ca_file.as_ref().ok_or_else(|| {
        DatastoreError::AuthenticationConfig("missing ca_file for client authentication".into())
    })?;
    let cert_file = config.cert_file.as_ref().ok_or_else(|| {
        DatastoreError::AuthenticationConfig("missing cert_file for datastore server".into())
    })?;
    let key_file = config.key_file.as_ref().ok_or_else(|| {
        DatastoreError::AuthenticationConfig("missing key_file for datastore server".into())
    })?;

    let ca_certs = load_certs(ca_file, "datastore CA")?;
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots.add(cert).map_err(|err| {
            DatastoreError::AuthenticationConfig(format!("datastore CA rejected: {err}"))
        })?;
    }

    // Require client certificate authentication signed by datastore CA
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|err| {
            DatastoreError::AuthenticationConfig(format!("client verifier error: {err}"))
        })?;

    let server_certs = load_certs(cert_file, "datastore server cert")?;
    let key = load_key(key_file, "datastore server key")?;

    let server_cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, key)
        .map_err(|err| DatastoreError::AuthenticationConfig(format!("server cert error: {err}")))?;

    Ok(TlsAcceptor::from(Arc::new(server_cfg)))
}

fn load_certs(path: &Path, name: &str) -> Result<Vec<CertificateDer<'static>>, DatastoreError> {
    let bytes = fs::read(path).map_err(|err| {
        DatastoreError::AuthenticationConfig(format!(
            "failed to read {name} at {}: {err}",
            path.display()
        ))
    })?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            DatastoreError::AuthenticationConfig(format!(
                "{name} at {} is not a valid PEM certificate: {err}",
                path.display()
            ))
        })?;
    if certs.is_empty() {
        return Err(DatastoreError::AuthenticationConfig(format!(
            "{name} at {} contained no certificates",
            path.display()
        )));
    }
    Ok(certs)
}

fn load_key(path: &Path, name: &str) -> Result<PrivateKeyDer<'static>, DatastoreError> {
    let bytes = fs::read(path).map_err(|err| {
        DatastoreError::AuthenticationConfig(format!(
            "failed to read {name} at {}: {err}",
            path.display()
        ))
    })?;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|err| {
        DatastoreError::AuthenticationConfig(format!(
            "{name} at {} is not a valid PEM private key: {err}",
            path.display()
        ))
    })
}

pub fn parse_listen_addr(url_str: &str) -> Result<SocketAddr, DatastoreError> {
    let trimmed = url_str
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    trimmed.parse::<SocketAddr>().map_err(|err| {
        DatastoreError::AuthenticationConfig(format!("invalid listen client url {url_str}: {err}"))
    })
}
