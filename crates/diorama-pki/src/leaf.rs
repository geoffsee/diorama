use rcgen::{CertificateParams, Issuer, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
use std::fs;
use std::path::Path;

use crate::{PkiError, atomic_write, to_pkcs1_pem};

pub fn issue_leaf_certificate(
    cert_path: &Path,
    key_path: &Path,
    signer_cert_path: &Path,
    signer_key_path: &Path,
    params: &CertificateParams,
) -> Result<(), PkiError> {
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Load CA cert and key
    let ca_cert_pem = fs::read_to_string(signer_cert_path)?;
    let ca_key_pem = fs::read_to_string(signer_key_path)?;
    let ca_key_pair = KeyPair::from_pem(&ca_key_pem).map_err(PkiError::Rcgen)?;

    // Create Issuer from CA
    let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key_pair).map_err(PkiError::Rcgen)?;

    // Generate leaf key
    let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)?;

    // Sign leaf with CA issuer
    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(PkiError::Rcgen)?;

    let pkcs8_pem = key_pair.serialize_pem();
    let key_pem = to_pkcs1_pem(&pkcs8_pem)?;

    atomic_write(cert_path, cert.pem().as_bytes(), 0o644)?;
    atomic_write(key_path, key_pem.as_bytes(), 0o600)?;

    Ok(())
}

pub fn ensure_leaf_certificate(
    cert_path: &Path,
    key_path: &Path,
    signer_cert_path: &Path,
    signer_key_path: &Path,
    params: &CertificateParams,
) -> Result<(), PkiError> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    issue_leaf_certificate(
        cert_path,
        key_path,
        signer_cert_path,
        signer_key_path,
        params,
    )
}
