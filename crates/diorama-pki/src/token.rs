use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use rcgen::{KeyPair, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::PkiError;

/// Node role encoded in a k0s-style cluster join token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JoinRole {
    Controller,
    Worker,
}

impl JoinRole {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::Worker => "worker",
        }
    }
}

impl fmt::Display for JoinRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JoinRole {
    type Err = PkiError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "controller" => Ok(Self::Controller),
            "worker" => Ok(Self::Worker),
            _ => Err(PkiError::InvalidToken),
        }
    }
}

/// Cryptographically signed k0s-style join token containing the cluster CA,
/// discovery endpoints, role, expiration, and RSA-SHA256 signature.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinToken {
    pub role: JoinRole,
    pub api_endpoint: String,
    pub peer_addr: SocketAddr,
    pub ca_cert_pem: String,
    pub datastore_ca_cert_pem: String,
    pub token_id: String,
    pub expires_at: Option<u64>,
    pub signature_b64: String,
}

impl fmt::Debug for JoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinToken")
            .field("role", &self.role)
            .field("api_endpoint", &self.api_endpoint)
            .field("peer_addr", &self.peer_addr)
            .field("token_id", &self.token_id)
            .field("expires_at", &self.expires_at)
            .field("signature_b64", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl JoinToken {
    /// Creates and signs a join token using the cluster CA in `pki_dir`.
    pub fn create_from_pki_dir(
        pki_dir: &Path,
        role: JoinRole,
        api_endpoint: String,
        peer_addr: SocketAddr,
        ttl_secs: Option<u64>,
    ) -> Result<Self, PkiError> {
        let ca_cert_pem = std::fs::read_to_string(pki_dir.join("ca.crt"))?;
        let ca_key_pem = std::fs::read_to_string(pki_dir.join("ca.key"))?;
        let datastore_ca_cert_pem = std::fs::read_to_string(pki_dir.join("datastore-ca.crt"))?;

        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut hasher = Sha256::new();
        hasher.update(now_nanos.to_le_bytes());
        hasher.update(role.as_str().as_bytes());
        hasher.update(api_endpoint.as_bytes());
        let digest = hasher.finalize();
        let token_id = format!("{:02x}{:02x}{:02x}", digest[0], digest[1], digest[2]);

        let expires_at = ttl_secs.map(|ttl| {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now_secs.saturating_add(ttl)
        });

        let mut token = Self {
            role,
            api_endpoint,
            peer_addr,
            ca_cert_pem,
            datastore_ca_cert_pem,
            token_id,
            expires_at,
            signature_b64: String::new(),
        };
        let payload = token.signing_payload();
        let sig = sign_with_rsa_key(&ca_key_pem, payload.as_bytes())?;
        token.signature_b64 = base64url_encode(&sig);
        Ok(token)
    }

    fn signing_payload(&self) -> String {
        format!(
            "diorama-join-v1|{}|{}|{}|{}|{}",
            self.role.as_str(),
            self.api_endpoint,
            self.peer_addr,
            self.token_id,
            self.expires_at.unwrap_or(0),
        )
    }

    /// Encodes the token as a single-line base64url string (matching `k0s token create` UX).
    pub fn encode(&self) -> Result<String, PkiError> {
        let json_bytes = serde_json::to_vec(self).map_err(|_| PkiError::InvalidToken)?;
        Ok(base64url_encode(&json_bytes))
    }

    /// Decodes a base64url join token and verifies its cryptographic signature and expiration.
    pub fn decode(encoded: &str) -> Result<Self, PkiError> {
        let raw = base64url_decode(encoded.trim())?;
        let token: Self = serde_json::from_slice(&raw).map_err(|_| PkiError::InvalidToken)?;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        token.verify(None, now_secs)?;
        Ok(token)
    }

    /// Verifies the token's signature against its embedded CA (and optional expected CA) and expiry.
    pub fn verify(
        &self,
        expected_ca_cert_pem: Option<&str>,
        now_secs: u64,
    ) -> Result<(), PkiError> {
        if let Some(expected) = expected_ca_cert_pem
            && self.ca_cert_pem.trim() != expected.trim()
        {
            return Err(PkiError::InvalidCert);
        }
        if let Some(exp) = self.expires_at
            && now_secs > exp
        {
            return Err(PkiError::InvalidToken);
        }
        let sig = base64url_decode(&self.signature_b64)?;
        let payload = self.signing_payload();
        verify_rsa_signature_with_cert(&self.ca_cert_pem, &sig, payload.as_bytes())
    }
}

/// Shared cluster PKI and Raft topology material returned when a `controller` node joins.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerJoinMaterial {
    pub assigned_node_id: u64,
    pub peers: BTreeMap<u64, SocketAddr>,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub request_header_ca_cert_pem: String,
    pub request_header_ca_key_pem: String,
    pub datastore_ca_cert_pem: String,
    pub datastore_ca_key_pem: String,
    pub service_account_key_pem: String,
}

impl fmt::Debug for ControllerJoinMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControllerJoinMaterial")
            .field("assigned_node_id", &self.assigned_node_id)
            .field("peers", &self.peers)
            .field("ca_key_pem", &"<redacted>")
            .field("datastore_ca_key_pem", &"<redacted>")
            .field("service_account_key_pem", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Signed node credentials returned when a `worker` node joins.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerJoinMaterial {
    pub api_endpoint: String,
    pub ca_cert_pem: String,
    pub kubelet_cert_pem: String,
    pub kubelet_key_pem: String,
    pub kube_proxy_cert_pem: String,
    pub kube_proxy_key_pem: String,
    pub datastore_ca_cert_pem: String,
    pub datastore_server_cert_pem: String,
    pub datastore_server_key_pem: String,
}

impl fmt::Debug for WorkerJoinMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerJoinMaterial")
            .field("api_endpoint", &self.api_endpoint)
            .field("kubelet_key_pem", &"<redacted>")
            .field("kube_proxy_key_pem", &"<redacted>")
            .field("datastore_server_key_pem", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Request sent by a joining node to the seed controller's `/cluster/join` H3 endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequest {
    pub token: JoinToken,
    pub node_name: String,
    pub node_ip: std::net::IpAddr,
    pub listen_peer_addr: Option<SocketAddr>,
}

/// Response returned by the seed controller's `/cluster/join` H3 endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinResponse {
    Controller(Box<ControllerJoinMaterial>),
    Worker(Box<WorkerJoinMaterial>),
    Rejected(String),
}

pub fn verify_rsa_signature_with_cert(
    cert_pem: &str,
    sig: &[u8],
    data: &[u8],
) -> Result<(), PkiError> {
    let parsed_pem = ::pem::parse(cert_pem).map_err(|_| PkiError::InvalidCert)?;
    let (_, cert) =
        X509Certificate::from_der(parsed_pem.contents()).map_err(|_| PkiError::InvalidCert)?;
    let alg_id = AlgorithmIdentifier {
        algorithm: x509_parser::oid_registry::OID_PKCS1_SHA256WITHRSA,
        parameters: None,
    };
    let bit_string = x509_parser::asn1_rs::BitString::new(0, sig);
    x509_parser::verify::verify_signature(cert.public_key(), &alg_id, &bit_string, data)
        .map_err(|_| PkiError::InvalidSignature)
}

#[must_use]
pub fn base64url_encode(data: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(data)
}

pub fn base64url_decode(data: &str) -> Result<Vec<u8>, PkiError> {
    BASE64_URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|_| PkiError::InvalidToken)
}

pub fn sign_with_rsa_key(key_pem: &str, data: &[u8]) -> Result<Vec<u8>, PkiError> {
    let key_pair = KeyPair::from_pem(key_pem).map_err(PkiError::Rcgen)?;
    key_pair.sign(data).map_err(PkiError::Rcgen)
}

pub fn public_key_pem_from_private_key_pem(key_pem: &str) -> Result<String, PkiError> {
    let key_pair = KeyPair::from_pem(key_pem).map_err(PkiError::Rcgen)?;
    Ok(key_pair.public_key_pem())
}

pub fn verify_rsa_signature(pub_key_pem: &str, sig: &[u8], data: &[u8]) -> Result<(), PkiError> {
    let parsed_pem = ::pem::parse(pub_key_pem).map_err(|_| PkiError::InvalidKey)?;
    let (_, spki) =
        SubjectPublicKeyInfo::from_der(parsed_pem.contents()).map_err(|_| PkiError::InvalidKey)?;
    let alg_id = AlgorithmIdentifier {
        algorithm: x509_parser::oid_registry::OID_PKCS1_SHA256WITHRSA,
        parameters: None,
    };
    let bit_string = x509_parser::asn1_rs::BitString::new(0, sig);
    x509_parser::verify::verify_signature(&spki, &alg_id, &bit_string, data)
        .map_err(|_| PkiError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{PKCS_RSA_SHA256, RsaKeySize};

    #[test]
    fn test_rsa_token_helpers() {
        let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let key_pem = key_pair.serialize_pem();
        let pub_pem = public_key_pem_from_private_key_pem(&key_pem).unwrap();

        let message = b"sample-kubernetes-jwt-claims";
        let sig = sign_with_rsa_key(&key_pem, message).unwrap();
        assert!(verify_rsa_signature(&pub_pem, &sig, message).is_ok());

        let encoded_sig = base64url_encode(&sig);
        let decoded_sig = base64url_decode(&encoded_sig).unwrap();
        assert_eq!(sig, decoded_sig);

        // Verification fails with tampered message
        assert!(verify_rsa_signature(&pub_pem, &sig, b"tampered").is_err());
    }
}
