use rcgen::{
    BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_RSA_SHA256,
    RsaKeySize,
};
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
pub mod cluster;
pub mod kubeconfig;
pub mod leaf;
pub mod profile;
pub mod rotate;
pub mod token;

#[derive(Debug)]
pub enum PkiError {
    Io(std::io::Error),
    Rcgen(rcgen::Error),
    InvalidKey,
    InvalidCert,
    UnsafePath(String),
    InvalidToken,
    InvalidSignature,
}

impl std::error::Error for PkiError {}
impl std::fmt::Display for PkiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl From<std::io::Error> for PkiError {
    fn from(e: std::io::Error) -> Self {
        PkiError::Io(e)
    }
}
impl From<rcgen::Error> for PkiError {
    fn from(e: rcgen::Error) -> Self {
        PkiError::Rcgen(e)
    }
}

pub fn ensure_ca(cert_path: &Path, key_path: &Path, common_name: &str) -> Result<(), PkiError> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }

    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut params =
        CertificateParams::new(vec![common_name.to_string()]).map_err(PkiError::Rcgen)?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, common_name.to_string());
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)?;

    let cert = params.self_signed(&key_pair)?;

    let pkcs8_pem = key_pair.serialize_pem();
    let key_pem = to_pkcs1_pem(&pkcs8_pem)?;

    atomic_write(cert_path, cert.pem().as_bytes(), 0o644)?;
    atomic_write(key_path, key_pem.as_bytes(), 0o600)?;

    Ok(())
}

pub fn ensure_service_account_key(key_path: &Path) -> Result<(), PkiError> {
    if key_path.exists() {
        return Ok(());
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)?;
    let pkcs8_pem = key_pair.serialize_pem();
    let key_pem = to_pkcs1_pem(&pkcs8_pem)?;

    atomic_write(key_path, key_pem.as_bytes(), 0o600)?;

    Ok(())
}

fn to_pkcs1_pem(pkcs8_pem: &str) -> Result<String, PkiError> {
    use pkcs8::der::Decode;

    let parsed_pem = pem::parse(pkcs8_pem).map_err(|_| PkiError::InvalidKey)?;
    let pkcs8_doc =
        pkcs8::PrivateKeyInfo::from_der(parsed_pem.contents()).map_err(|_| PkiError::InvalidKey)?;

    let pkcs1_pem = pem::encode(&pem::Pem::new("RSA PRIVATE KEY", pkcs8_doc.private_key));
    Ok(pkcs1_pem)
}

pub fn validate_certificate_pem(bytes: &[u8]) -> Result<(), PkiError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PkiError::InvalidCert)?;
    let begin_count = text
        .lines()
        .filter(|line| line.starts_with("-----BEGIN "))
        .count();
    let end_count = text
        .lines()
        .filter(|line| line.starts_with("-----END "))
        .count();
    if begin_count == 0 || begin_count != end_count {
        return Err(PkiError::InvalidCert);
    }

    let pem_entries = pem::parse_many(bytes).map_err(|_| PkiError::InvalidCert)?;
    if pem_entries.len() != begin_count {
        return Err(PkiError::InvalidCert);
    }

    let mut found = false;
    for entry in pem_entries {
        if entry.tag() == "CERTIFICATE" {
            found = true;
            let (_, _cert) = x509_parser::parse_x509_certificate(entry.contents())
                .map_err(|_| PkiError::InvalidCert)?;
        }
    }
    if !found {
        return Err(PkiError::InvalidCert);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateValidity {
    pub not_before_seconds: i64,
    pub not_after_seconds: i64,
}

impl CertificateValidity {
    #[must_use]
    pub fn is_valid_at(&self, timestamp_seconds: i64) -> bool {
        timestamp_seconds >= self.not_before_seconds && timestamp_seconds <= self.not_after_seconds
    }
}

pub fn inspect_certificate_pem(bytes: &[u8]) -> Result<CertificateValidity, PkiError> {
    let pem_entries = pem::parse_many(bytes).map_err(|_| PkiError::InvalidCert)?;
    for entry in pem_entries {
        if entry.tag() == "CERTIFICATE" {
            let (_, cert) = x509_parser::parse_x509_certificate(entry.contents())
                .map_err(|_| PkiError::InvalidCert)?;
            return Ok(CertificateValidity {
                not_before_seconds: cert.validity().not_before.timestamp(),
                not_after_seconds: cert.validity().not_after.timestamp(),
            });
        }
    }
    Err(PkiError::InvalidCert)
}

pub fn inspect_certificate_file(path: &Path) -> Result<CertificateValidity, PkiError> {
    let bytes = fs::read(path)?;
    inspect_certificate_pem(&bytes)
}

pub fn validate_private_key_pem(bytes: &[u8]) -> Result<(), PkiError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PkiError::InvalidKey)?;
    let begin_count = text
        .lines()
        .filter(|line| line.starts_with("-----BEGIN "))
        .count();
    let end_count = text
        .lines()
        .filter(|line| line.starts_with("-----END "))
        .count();
    if begin_count == 0 || begin_count != end_count {
        return Err(PkiError::InvalidKey);
    }

    let pem_entries = pem::parse_many(bytes).map_err(|_| PkiError::InvalidKey)?;
    if pem_entries.len() != begin_count {
        return Err(PkiError::InvalidKey);
    }

    let mut found = false;
    for entry in pem_entries {
        let tag = entry.tag();
        if tag == "RSA PRIVATE KEY" || tag == "PRIVATE KEY" || tag == "EC PRIVATE KEY" {
            found = true;
            if entry.contents().is_empty() {
                return Err(PkiError::InvalidKey);
            }
            let entry_pem = pem::encode(&entry);
            if KeyPair::from_pem(&entry_pem).is_err()
                && pkcs8::PrivateKeyInfo::try_from(entry.contents()).is_err()
            {
                return Err(PkiError::InvalidKey);
            }
        }
    }
    if !found {
        return Err(PkiError::InvalidKey);
    }
    Ok(())
}

pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<(), std::io::Error> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::Builder::new().tempfile_in(dir)?;

    // Set permissions before writing
    #[cfg(unix)]
    {
        let mut perms = temp.as_file().metadata()?.permissions();
        perms.set_mode(mode);
        temp.as_file_mut().set_permissions(perms)?;
    }

    temp.write_all(data)?;
    temp.flush()?;

    // Atomically persist
    temp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn base64_decode(data: &str) -> Result<Vec<u8>, PkiError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data.trim())
        .map_err(|_| PkiError::InvalidCert)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertificateIdentity {
    pub common_name: String,
    pub dns_names: Vec<String>,
}

impl CertificateIdentity {
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        self.common_name == name || self.dns_names.iter().any(|d| d == name)
    }
}

pub fn verify_certificate_chain(
    cert_pem: &str,
    ca_cert_pem: &str,
) -> Result<CertificateIdentity, PkiError> {
    use x509_parser::prelude::{FromDer, GeneralName, ParsedExtension};
    let cert_pem_parsed = ::pem::parse(cert_pem).map_err(|_| PkiError::InvalidCert)?;
    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(cert_pem_parsed.contents())
        .map_err(|_| PkiError::InvalidCert)?;

    let ca_pem_parsed = ::pem::parse(ca_cert_pem).map_err(|_| PkiError::InvalidCert)?;
    let (_, ca_cert) = x509_parser::prelude::X509Certificate::from_der(ca_pem_parsed.contents())
        .map_err(|_| PkiError::InvalidCert)?;

    cert.verify_signature(Some(ca_cert.public_key()))
        .map_err(|_| PkiError::InvalidSignature)?;

    if !cert.validity().is_valid() || !ca_cert.validity().is_valid() {
        return Err(PkiError::InvalidCert);
    }

    let mut common_name = String::new();
    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME
                && let Ok(name) = attr.as_str()
            {
                common_name = name.to_string();
                break;
            }
        }
    }

    let mut dns_names = Vec::new();
    for ext in cert.iter_extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for gn in &san.general_names {
                if let GeneralName::DNSName(dns) = gn {
                    dns_names.push((*dns).to_string());
                }
            }
        }
    }

    Ok(CertificateIdentity {
        common_name,
        dns_names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_ca_generation_and_reuse() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("ca.crt");
        let key_path = dir.path().join("ca.key");

        // Generate initially
        ensure_ca(&cert_path, &key_path, "test-ca").unwrap();
        assert!(cert_path.exists());
        assert!(key_path.exists());
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&cert_path).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }

        let initial_cert = fs::read(&cert_path).unwrap();

        // Ensure reuse
        ensure_ca(&cert_path, &key_path, "test-ca").unwrap();
        let reused_cert = fs::read(&cert_path).unwrap();
        assert_eq!(initial_cert, reused_cert);
    }

    #[test]
    fn test_sa_key_generation_and_reuse() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("sa.key");

        // Generate initially
        ensure_service_account_key(&key_path).unwrap();
        assert!(key_path.exists());
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let initial_key = fs::read(&key_path).unwrap();

        // Ensure reuse
        ensure_service_account_key(&key_path).unwrap();
        let reused_key = fs::read(&key_path).unwrap();
        assert_eq!(initial_key, reused_key);
    }

    #[test]
    fn test_validate_keys_multi_block_and_truncated() {
        let rsa_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let pkcs8_pem = rsa_pair.serialize_pem();
        let pkcs1_pem = to_pkcs1_pem(&pkcs8_pem).unwrap();

        // Multi-block: RSA PKCS#1 followed by a certificate block
        let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&rsa_pair).unwrap();
        let bundle = format!("{pkcs1_pem}\n{}", cert.pem());

        assert!(validate_private_key_pem(bundle.as_bytes()).is_ok());

        // EC key multi-block
        let ec_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ec_bundle = format!("{}\n{}", ec_pair.serialize_pem(), cert.pem());
        assert!(validate_private_key_pem(ec_bundle.as_bytes()).is_ok());

        // Valid key followed by truncated PEM block
        let corrupt_bundle = format!("{pkcs1_pem}\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n");
        assert!(validate_private_key_pem(corrupt_bundle.as_bytes()).is_err());
    }

    #[test]
    fn test_base64_helpers_and_cert_chain_verification() {
        let raw = b"kubernetes-admission-webhook-token";
        let enc = base64_encode(raw);
        let dec = base64_decode(&enc).unwrap();
        assert_eq!(dec, raw);

        // Test valid certificate chain verification
        let ca_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let mut ca_params = CertificateParams::new(vec!["test-ca".to_string()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_pair).unwrap();

        let leaf_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let leaf_params = CertificateParams::new(vec!["system:auth-proxy".to_string()]).unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert.pem(), ca_pair).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_pair, &issuer).unwrap();

        let id = verify_certificate_chain(&leaf_cert.pem(), &ca_cert.pem()).unwrap();
        assert!(id.matches("system:auth-proxy"));

        // Tampered / untrusted CA verification fails
        let untrusted_pair =
            KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let untrusted_ca = CertificateParams::new(vec!["other-ca".to_string()])
            .unwrap()
            .self_signed(&untrusted_pair)
            .unwrap();
        assert!(verify_certificate_chain(&leaf_cert.pem(), &untrusted_ca.pem()).is_err());
    }
}
