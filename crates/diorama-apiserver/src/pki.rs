use std::fs;
use std::path::Path;

use diorama_pki::{validate_certificate_pem, validate_private_key_pem};

use crate::config::ApiserverConfig;
use crate::error::ApiserverError;

/// Validates that all required PKI credentials and keys exist, are non-empty,
/// and contain valid PEM formatted certificates or keys.
pub fn validate_pki_prerequisites(config: &ApiserverConfig) -> Result<(), ApiserverError> {
    // 1. Client CA
    validate_cert_file(&config.client_ca_file, "client CA")?;

    // 2. Apiserver TLS Cert and Key
    validate_cert_file(&config.tls_cert_file, "API server certificate")?;
    validate_key_file(&config.tls_private_key_file, "API server private key")?;

    // 3. Service Account signing key
    validate_key_file(
        &config.service_account_signing_key_file,
        "service account signing key",
    )?;

    // 4. Request header CA
    validate_cert_file(&config.request_header_ca_file, "request-header CA")?;

    Ok(())
}

fn validate_cert_file(path: &Path, name: &str) -> Result<(), ApiserverError> {
    if !path.exists() {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!("{name} file not found at {}", path.display()),
        });
    }

    let bytes = fs::read(path).map_err(|e| ApiserverError::InvalidCredentials {
        reason: format!("failed to read {name} at {}: {e}", path.display()),
    })?;

    if bytes.is_empty() {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!("{name} file at {} is empty", path.display()),
        });
    }

    validate_certificate_pem(&bytes).map_err(|e| ApiserverError::InvalidCredentials {
        reason: format!(
            "{name} at {} is not a valid PEM certificate: {e}",
            path.display()
        ),
    })?;

    Ok(())
}

fn validate_key_file(path: &Path, name: &str) -> Result<(), ApiserverError> {
    if !path.exists() {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!("{name} file not found at {}", path.display()),
        });
    }

    let bytes = fs::read(path).map_err(|e| ApiserverError::InvalidCredentials {
        reason: format!("failed to read {name} at {}: {e}", path.display()),
    })?;

    if bytes.is_empty() {
        return Err(ApiserverError::InvalidCredentials {
            reason: format!("{name} file at {} is empty", path.display()),
        });
    }

    validate_private_key_pem(&bytes).map_err(|e| ApiserverError::InvalidCredentials {
        reason: format!(
            "{name} at {} is not a valid PEM private key: {e}",
            path.display()
        ),
    })?;

    Ok(())
}
