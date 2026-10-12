use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::ApiserverError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccountClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: u64,
    pub nbf: u64,
    pub iat: u64,
    pub jti: String,
    #[serde(rename = "kubernetes.io/serviceaccount/namespace")]
    pub namespace: String,
    #[serde(rename = "kubernetes.io/serviceaccount/service-account.name")]
    pub service_account_name: String,
    #[serde(rename = "kubernetes.io/serviceaccount/service-account.uid")]
    pub service_account_uid: String,
}

#[derive(Debug, Clone)]
pub struct TokenProjection<'a> {
    pub target_dir: &'a Path,
    pub namespace: &'a str,
    pub sa_name: &'a str,
    pub sa_uid: &'a str,
    pub audiences: &'a [String],
    pub lifetime: Duration,
    pub ca_cert: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct TokenService {
    issuer: String,
    api_audiences: Vec<String>,
    signing_key_pem: String,
    verification_key_pem: String,
}

impl TokenService {
    pub fn new(
        issuer: String,
        api_audiences: Vec<String>,
        signing_key_path: &Path,
        verification_key_path: &Path,
    ) -> Result<Self, ApiserverError> {
        let signing_key_bytes =
            fs::read(signing_key_path).map_err(|e| ApiserverError::InvalidCredentials {
                reason: format!("failed to read signing key: {e}"),
            })?;
        let signing_key_pem = String::from_utf8(signing_key_bytes).map_err(|e| {
            ApiserverError::InvalidCredentials {
                reason: format!("signing key is not valid UTF-8: {e}"),
            }
        })?;

        // Determine verification key: either from verification_key_path or derived from signing key
        let verification_key_pem = if verification_key_path.exists() {
            let verif_bytes = fs::read(verification_key_path).map_err(|e| {
                ApiserverError::InvalidCredentials {
                    reason: format!("failed to read verification key: {e}"),
                }
            })?;
            let verif_pem =
                String::from_utf8(verif_bytes).map_err(|e| ApiserverError::InvalidCredentials {
                    reason: format!("verification key is not valid UTF-8: {e}"),
                })?;
            // If the verification key file contains a private key, derive public key from it
            if verif_pem.contains("PRIVATE KEY") {
                diorama_pki::token::public_key_pem_from_private_key_pem(&verif_pem).map_err(
                    |e| ApiserverError::InvalidCredentials {
                        reason: format!("failed to extract public key: {e:?}"),
                    },
                )?
            } else {
                verif_pem
            }
        } else {
            diorama_pki::token::public_key_pem_from_private_key_pem(&signing_key_pem).map_err(
                |e| ApiserverError::InvalidCredentials {
                    reason: format!("failed to derive public key: {e:?}"),
                },
            )?
        };

        Ok(Self {
            issuer,
            api_audiences,
            signing_key_pem,
            verification_key_pem,
        })
    }

    pub fn issue_token(
        &self,
        namespace: &str,
        sa_name: &str,
        sa_uid: &str,
        audiences: &[String],
        lifetime: Duration,
    ) -> Result<String, ApiserverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ApiserverError::Internal {
                reason: format!("clock error: {e}"),
            })?
            .as_secs();

        if audiences.iter().any(|a| a == "*") {
            return Err(ApiserverError::InvalidInput {
                field: "audiences".to_string(),
                reason: "wildcard audience '*' is not permitted".to_string(),
            });
        }

        let exp = now.saturating_add(lifetime.as_secs());
        let aud = if audiences.is_empty() {
            self.api_audiences.clone()
        } else {
            audiences.to_vec()
        };

        let jti = format!(
            "{:016x}{:016x}",
            now,
            now.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1)
        );

        let claims = ServiceAccountClaims {
            iss: self.issuer.clone(),
            sub: format!("system:serviceaccount:{namespace}:{sa_name}"),
            aud,
            exp,
            nbf: now,
            iat: now,
            jti,
            namespace: namespace.to_string(),
            service_account_name: sa_name.to_string(),
            service_account_uid: sa_uid.to_string(),
        };

        let header_json = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT"
        });
        let header_str = header_json.to_string();
        let header_b64 = diorama_pki::token::base64url_encode(header_str.as_bytes());

        let claims_str = serde_json::to_string(&claims).map_err(|e| ApiserverError::Internal {
            reason: format!("failed to serialize claims: {e}"),
        })?;
        let claims_b64 = diorama_pki::token::base64url_encode(claims_str.as_bytes());

        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig =
            diorama_pki::token::sign_with_rsa_key(&self.signing_key_pem, signing_input.as_bytes())
                .map_err(|e| ApiserverError::Internal {
                    reason: format!("failed to sign token: {e:?}"),
                })?;
        let sig_b64 = diorama_pki::token::base64url_encode(&sig);

        Ok(format!("{signing_input}.{sig_b64}"))
    }

    pub fn verify_token(
        &self,
        token_str: &str,
        expected_audience: Option<&str>,
    ) -> Result<ServiceAccountClaims, ApiserverError> {
        let parts: Vec<&str> = token_str.split('.').collect();
        if parts.len() != 3 {
            return Err(ApiserverError::Unauthorized {
                reason: "invalid bearer token structure: must be 3 dot-separated segments"
                    .to_string(),
            });
        }

        let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

        // 1. Verify header
        let header_bytes = diorama_pki::token::base64url_decode(header_b64).map_err(|_| {
            ApiserverError::Unauthorized {
                reason: "invalid token header encoding".to_string(),
            }
        })?;
        let header_val: serde_json::Value =
            serde_json::from_slice(&header_bytes).map_err(|_| ApiserverError::Unauthorized {
                reason: "invalid token header JSON".to_string(),
            })?;

        if header_val.get("alg").and_then(|v| v.as_str()) != Some("RS256") {
            return Err(ApiserverError::Unauthorized {
                reason: "unsupported token signing algorithm (expected RS256)".to_string(),
            });
        }

        // 2. Decode claims
        let payload_bytes = diorama_pki::token::base64url_decode(payload_b64).map_err(|_| {
            ApiserverError::Unauthorized {
                reason: "invalid token payload encoding".to_string(),
            }
        })?;
        let claims: ServiceAccountClaims =
            serde_json::from_slice(&payload_bytes).map_err(|e| ApiserverError::Unauthorized {
                reason: format!("invalid token claims format: {e}"),
            })?;

        // 3. Verify timestamps
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > claims.exp {
            return Err(ApiserverError::Unauthorized {
                reason: format!("token has expired (exp: {}, now: {})", claims.exp, now),
            });
        }

        if now < claims.nbf {
            return Err(ApiserverError::Unauthorized {
                reason: format!("token not yet valid (nbf: {}, now: {})", claims.nbf, now),
            });
        }

        // 4. Verify audience
        if let Some(expected_aud) = expected_audience {
            let matched = claims.aud.iter().any(|a| a == expected_aud);
            if !matched {
                return Err(ApiserverError::Unauthorized {
                    reason: format!(
                        "token audience mismatch (token aud: {:?}, expected: {})",
                        claims.aud, expected_aud
                    ),
                });
            }
        }

        // 5. Verify cryptographic signature
        let sig_bytes = diorama_pki::token::base64url_decode(sig_b64).map_err(|_| {
            ApiserverError::Unauthorized {
                reason: "invalid token signature encoding".to_string(),
            }
        })?;

        let signed_data = format!("{header_b64}.{payload_b64}");
        diorama_pki::token::verify_rsa_signature(
            &self.verification_key_pem,
            &sig_bytes,
            signed_data.as_bytes(),
        )
        .map_err(|_| ApiserverError::Unauthorized {
            reason: "cryptographic token signature verification failed".to_string(),
        })?;

        Ok(claims)
    }

    pub fn project_token_volume(
        &self,
        projection: &TokenProjection<'_>,
    ) -> Result<PathBuf, ApiserverError> {
        let token_str = self.issue_token(
            projection.namespace,
            projection.sa_name,
            projection.sa_uid,
            projection.audiences,
            projection.lifetime,
        )?;

        fs::create_dir_all(projection.target_dir).map_err(|e| ApiserverError::Internal {
            reason: format!(
                "failed to create projected volume dir {}: {e}",
                projection.target_dir.display()
            ),
        })?;

        let token_path = projection.target_dir.join("token");
        diorama_pki::atomic_write(&token_path, token_str.as_bytes(), 0o600).map_err(|e| {
            ApiserverError::Internal {
                reason: format!("failed to write projected token: {e}"),
            }
        })?;

        let ca_path = projection.target_dir.join("ca.crt");
        diorama_pki::atomic_write(&ca_path, projection.ca_cert, 0o644).map_err(|e| {
            ApiserverError::Internal {
                reason: format!("failed to write ca.crt: {e}"),
            }
        })?;

        let ns_path = projection.target_dir.join("namespace");
        diorama_pki::atomic_write(&ns_path, projection.namespace.as_bytes(), 0o644).map_err(
            |e| ApiserverError::Internal {
                reason: format!("failed to write namespace: {e}"),
            },
        )?;

        Ok(token_path)
    }
}
