use base64::prelude::*;
use rcgen::{KeyPair, SigningKey};
use x509_parser::prelude::*;

use crate::PkiError;

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
