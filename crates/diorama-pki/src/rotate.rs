use rcgen::CertificateParams;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

use crate::PkiError;
use crate::leaf::issue_leaf_certificate;

pub fn validate_pki_dir(dir: &Path) -> Result<(), PkiError> {
    let s = dir.to_string_lossy();
    if s.is_empty() || s == "." || s == "/" {
        return Err(PkiError::UnsafePath(format!("unsafe pki directory: {s}")));
    }
    if dir.is_symlink() {
        return Err(PkiError::UnsafePath(
            "symlink pki directory is rejected".into(),
        ));
    }
    if let Ok(canonical) = dir.canonicalize()
        && canonical == Path::new("/")
    {
        return Err(PkiError::UnsafePath("canonical root / is rejected".into()));
    }
    Ok(())
}

fn parse_ip_address(ip_bytes: &[u8]) -> Option<IpAddr> {
    if ip_bytes.len() == 4 {
        Some(IpAddr::V4(std::net::Ipv4Addr::new(
            ip_bytes[0],
            ip_bytes[1],
            ip_bytes[2],
            ip_bytes[3],
        )))
    } else if ip_bytes.len() == 16 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(ip_bytes);
        Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
    } else {
        None
    }
}

fn process_general_name(
    gn: &GeneralName<'_>,
    dns: &mut HashSet<String>,
    ips: &mut HashSet<IpAddr>,
) {
    match gn {
        GeneralName::DNSName(name) => {
            dns.insert((*name).to_string());
        },
        GeneralName::IPAddress(ip_bytes) => {
            if let Some(ip) = parse_ip_address(ip_bytes) {
                ips.insert(ip);
            }
        },
        _ => {},
    }
}

fn extract_sans(cert: &X509Certificate<'_>) -> (HashSet<String>, HashSet<IpAddr>) {
    let mut found_dns: HashSet<String> = HashSet::new();
    let mut found_ips: HashSet<IpAddr> = HashSet::new();

    for ext in cert.iter_extensions() {
        let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() else {
            continue;
        };
        for gn in &san.general_names {
            process_general_name(gn, &mut found_dns, &mut found_ips);
        }
    }
    (found_dns, found_ips)
}

#[allow(clippy::too_many_arguments)]
pub fn inspect_leaf_with_signer(
    cert_path: &Path,
    key_path: &Path,
    signer_cert_path: Option<&Path>,
    expected_cn: &str,
    expected_dns: &[String],
    expected_ips: &[IpAddr],
) -> Result<bool, PkiError> {
    if !cert_path.exists() || !key_path.exists() {
        return Ok(false);
    }

    // Check key validity
    let Ok(key_bytes) = std::fs::read(key_path) else {
        return Ok(false);
    };
    let Ok(key_str) = std::str::from_utf8(&key_bytes) else {
        return Ok(false);
    };
    let Ok(key_pair) = rcgen::KeyPair::from_pem(key_str) else {
        return Ok(false);
    };

    // Check cert validity
    let Ok(cert_bytes) = std::fs::read(cert_path) else {
        return Ok(false);
    };
    let Ok(cert_str) = std::str::from_utf8(&cert_bytes) else {
        return Ok(false);
    };
    let Ok(parsed_pem) = ::pem::parse(cert_str) else {
        return Ok(false);
    };
    let Ok((_, cert)) = X509Certificate::from_der(parsed_pem.contents()) else {
        return Ok(false);
    };

    // Verify key pair matches cert public key
    if cert.public_key().subject_public_key.data.as_ref() != key_pair.public_key_raw() {
        return Ok(false);
    }

    // Check signature if signer cert provided
    if let Some(signer_path) = signer_cert_path {
        let Ok(signer_bytes) = std::fs::read(signer_path) else {
            return Ok(false);
        };
        let Ok(signer_str) = std::str::from_utf8(&signer_bytes) else {
            return Ok(false);
        };
        let Ok(signer_pem) = ::pem::parse(signer_str) else {
            return Ok(false);
        };
        let Ok((_, signer_cert)) = X509Certificate::from_der(signer_pem.contents()) else {
            return Ok(false);
        };
        if cert
            .verify_signature(Some(signer_cert.public_key()))
            .is_err()
        {
            return Ok(false);
        }
    }

    // Check expiration: not_before <= now <= not_after
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        .try_into()
        .unwrap_or(0i64);
    let not_after = cert.validity().not_after.timestamp();
    let not_before = cert.validity().not_before.timestamp();
    if now < not_before || now >= not_after {
        return Ok(false);
    }

    // Check CN if present in expected
    if !expected_cn.is_empty() {
        let mut cn_matched = false;
        for rdn in cert.subject().iter_rdn() {
            for attr in rdn.iter() {
                if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME
                    && attr.as_str().is_ok_and(|cn| cn == expected_cn)
                {
                    cn_matched = true;
                }
            }
        }
        if !cn_matched {
            return Ok(false);
        }
    }

    // Check SANs
    let (found_dns, found_ips) = extract_sans(&cert);

    for dns in expected_dns {
        if !found_dns.contains(dns) {
            return Ok(false);
        }
    }

    for ip in expected_ips {
        if !found_ips.contains(ip) {
            return Ok(false);
        }
    }

    Ok(true)
}

pub fn inspect_leaf(
    cert_path: &Path,
    key_path: &Path,
    expected_cn: &str,
    expected_dns: &[String],
    expected_ips: &[IpAddr],
) -> Result<bool, PkiError> {
    inspect_leaf_with_signer(
        cert_path,
        key_path,
        None,
        expected_cn,
        expected_dns,
        expected_ips,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn rotate_leaf_if_needed(
    cert_path: &Path,
    key_path: &Path,
    signer_cert_path: &Path,
    signer_key_path: &Path,
    params: &CertificateParams,
    expected_cn: &str,
    expected_dns: &[String],
    expected_ips: &[IpAddr],
) -> Result<bool, PkiError> {
    if inspect_leaf_with_signer(
        cert_path,
        key_path,
        Some(signer_cert_path),
        expected_cn,
        expected_dns,
        expected_ips,
    )? {
        return Ok(false);
    }

    issue_leaf_certificate(
        cert_path,
        key_path,
        signer_cert_path,
        signer_key_path,
        params,
    )?;
    Ok(true)
}
