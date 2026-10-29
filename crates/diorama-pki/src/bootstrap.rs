//! Kubelet CSR key generation and strictly scoped client-certificate signing.
use crate::{PkiError, atomic_write};
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose,
};
use std::{fs, path::Path};

pub const KUBELET_SIGNER: &str = "kubernetes.io/kube-apiserver-client-kubelet";

pub fn valid_node_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The private key is generated on the worker and never included in the CSR.
pub fn kubelet_request(node: &str, key_path: &Path) -> Result<String, PkiError> {
    if !valid_node_name(node) {
        return Err(PkiError::InvalidCert);
    }
    let key = if key_path.exists() {
        KeyPair::from_pem(&fs::read_to_string(key_path)?)?
    } else {
        let key = KeyPair::generate()?;
        atomic_write(key_path, key.serialize_pem().as_bytes(), 0o600)?;
        key
    };
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("system:node:{node}"));
    params
        .distinguished_name
        .push(DnType::OrganizationName, "system:nodes");
    Ok(params.serialize_request(&key)?.pem()?)
}

/// rcgen verifies the CSR signature before any identity is accepted.
pub fn validate_kubelet_request(pem: &str) -> Result<String, PkiError> {
    use x509_parser::prelude::FromDer;
    let (_, raw) =
        x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|_| PkiError::InvalidCert)?;
    let (_, raw) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&raw.contents)
            .map_err(|_| PkiError::InvalidCert)?;
    if raw
        .certification_request_info
        .subject
        .iter_attributes()
        .count()
        != 2
    {
        return Err(PkiError::InvalidCert);
    }
    let csr = CertificateSigningRequestParams::from_pem(pem)?;
    let subject = &raw.certification_request_info.subject;
    let cn = subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .ok_or(PkiError::InvalidCert)?;
    let organization = subject
        .iter_organization()
        .next()
        .and_then(|o| o.as_str().ok());
    let node = cn
        .strip_prefix("system:node:")
        .filter(|name| valid_node_name(name))
        .ok_or(PkiError::InvalidCert)?;
    if organization != Some("system:nodes")
        || !csr.params.subject_alt_names.is_empty()
        || matches!(csr.params.is_ca, rcgen::IsCa::Ca(_))
        || csr
            .params
            .extended_key_usages
            .iter()
            .any(|u| *u != ExtendedKeyUsagePurpose::ClientAuth)
        || csr.params.key_usages.iter().any(|u| {
            !matches!(
                u,
                KeyUsagePurpose::DigitalSignature | KeyUsagePurpose::KeyEncipherment
            )
        })
    {
        return Err(PkiError::InvalidCert);
    }
    Ok(node.into())
}

pub fn sign_kubelet_request(
    pem: &str,
    ca_cert: &Path,
    ca_key: &Path,
    lifetime_seconds: u32,
) -> Result<String, PkiError> {
    validate_kubelet_request(pem)?;
    let mut csr = CertificateSigningRequestParams::from_pem(pem)?;
    csr.params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    csr.params.not_after = time::OffsetDateTime::now_utc()
        + time::Duration::seconds(i64::from(lifetime_seconds.clamp(600, 31_536_000)));
    csr.params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let issuer = Issuer::from_ca_cert_pem(
        &fs::read_to_string(ca_cert)?,
        KeyPair::from_pem(&fs::read_to_string(ca_key)?)?,
    )?;
    Ok(csr.signed_by(&issuer)?.pem())
}
