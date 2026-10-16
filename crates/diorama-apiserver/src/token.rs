use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::ApiserverError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundObjectRef {
    #[serde(
        rename = "apiVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub api_version: Option<String>,
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BoundItemRef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

pub type PodClaimRef = BoundItemRef;
pub type SecretClaimRef = BoundItemRef;
pub type NodeClaimRef = BoundItemRef;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServiceAccountRef {
    pub name: String,
    pub uid: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KubernetesIoClaims {
    pub namespace: String,
    pub serviceaccount: ServiceAccountRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<BoundItemRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<BoundItemRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<BoundItemRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceAccountClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: u64,
    pub nbf: u64,
    pub iat: u64,
    pub jti: String,
    #[serde(rename = "kubernetes.io")]
    pub kubernetes_io: KubernetesIoClaims,
    #[serde(
        rename = "kubernetes.io/serviceaccount/namespace",
        skip_serializing_if = "String::is_empty"
    )]
    pub namespace: String,
    #[serde(
        rename = "kubernetes.io/serviceaccount/service-account.name",
        skip_serializing_if = "String::is_empty"
    )]
    pub service_account_name: String,
    #[serde(
        rename = "kubernetes.io/serviceaccount/service-account.uid",
        skip_serializing_if = "String::is_empty"
    )]
    pub service_account_uid: String,
}

impl ServiceAccountClaims {
    #[must_use]
    pub fn username(&self) -> &str {
        &self.sub
    }

    #[must_use]
    pub fn groups(&self) -> Vec<String> {
        vec![
            "system:serviceaccounts".to_string(),
            format!("system:serviceaccounts:{}", self.namespace),
            "system:authenticated".to_string(),
        ]
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawAudience {
    List(Vec<String>),
    Single(String),
}

#[derive(Deserialize)]
struct RawClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    aud: Option<RawAudience>,
    exp: u64,
    nbf: u64,
    iat: u64,
    jti: String,
    #[serde(rename = "kubernetes.io", default)]
    kubernetes_io: Option<KubernetesIoClaims>,
    #[serde(rename = "kubernetes.io/serviceaccount/namespace", default)]
    legacy_namespace: Option<String>,
    #[serde(rename = "kubernetes.io/serviceaccount/service-account.name", default)]
    legacy_sa_name: Option<String>,
    #[serde(rename = "kubernetes.io/serviceaccount/service-account.uid", default)]
    legacy_sa_uid: Option<String>,
}

impl<'de> Deserialize<'de> for ServiceAccountClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawClaims::deserialize(deserializer)?;
        let aud = match raw.aud {
            Some(RawAudience::List(list)) => list,
            Some(RawAudience::Single(single)) => vec![single],
            None => Vec::new(),
        };

        let (kubernetes_io, namespace, sa_name, sa_uid) = if let Some(mut k8s) = raw.kubernetes_io {
            if k8s.namespace.is_empty()
                && let Some(leg_ns) = raw.legacy_namespace
            {
                k8s.namespace = leg_ns;
            }
            if k8s.serviceaccount.name.is_empty()
                && let Some(leg_sa) = raw.legacy_sa_name
            {
                k8s.serviceaccount.name = leg_sa;
            }
            if k8s.serviceaccount.uid.is_empty()
                && let Some(leg_uid) = raw.legacy_sa_uid
            {
                k8s.serviceaccount.uid = leg_uid;
            }
            let ns = k8s.namespace.clone();
            let name = k8s.serviceaccount.name.clone();
            let uid = k8s.serviceaccount.uid.clone();
            (k8s, ns, name, uid)
        } else {
            let ns = raw.legacy_namespace.unwrap_or_default();
            let name = raw.legacy_sa_name.unwrap_or_default();
            let uid = raw.legacy_sa_uid.unwrap_or_default();
            (
                KubernetesIoClaims {
                    namespace: ns.clone(),
                    serviceaccount: ServiceAccountRef {
                        name: name.clone(),
                        uid: uid.clone(),
                    },
                    pod: None,
                    secret: None,
                    node: None,
                },
                ns,
                name,
                uid,
            )
        };

        let mut namespace = namespace;
        let mut sa_name = sa_name;

        if (namespace.is_empty() || sa_name.is_empty())
            && let Some(rest) = raw.sub.strip_prefix("system:serviceaccount:")
        {
            let parts: Vec<&str> = rest.split(':').collect();
            if parts.len() == 2 {
                if namespace.is_empty() {
                    namespace = parts[0].to_string();
                }
                if sa_name.is_empty() {
                    sa_name = parts[1].to_string();
                }
            }
        }

        Ok(ServiceAccountClaims {
            iss: raw.iss,
            sub: raw.sub,
            aud,
            exp: raw.exp,
            nbf: raw.nbf,
            iat: raw.iat,
            jti: raw.jti,
            kubernetes_io,
            namespace,
            service_account_name: sa_name,
            service_account_uid: sa_uid,
        })
    }
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRequest {
    #[serde(rename = "apiVersion", default = "default_auth_api_version")]
    pub api_version: String,
    #[serde(rename = "kind", default = "default_token_request_kind")]
    pub kind: String,
    #[serde(default)]
    pub metadata: TokenRequestMetadata,
    pub spec: TokenRequestSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TokenRequestStatus>,
}

fn default_auth_api_version() -> String {
    "authentication.k8s.io/v1".to_string()
}

fn default_token_request_kind() -> String {
    "TokenRequest".to_string()
}

fn default_token_review_kind() -> String {
    "TokenReview".to_string()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenRequestMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(
        rename = "creationTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub creation_timestamp: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenRequestSpec {
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(
        rename = "expirationSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expiration_seconds: Option<i64>,
    #[serde(
        rename = "boundObjectRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub bound_object_ref: Option<BoundObjectRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenRequestStatus {
    pub token: String,
    #[serde(rename = "expirationTimestamp")]
    pub expiration_timestamp: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenReview {
    #[serde(rename = "apiVersion", default = "default_auth_api_version")]
    pub api_version: String,
    #[serde(rename = "kind", default = "default_token_review_kind")]
    pub kind: String,
    #[serde(default)]
    pub metadata: TokenReviewMetadata,
    pub spec: TokenReviewSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TokenReviewStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenReviewMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(
        rename = "creationTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub creation_timestamp: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenReviewSpec {
    pub token: String,
    #[serde(default)]
    pub audiences: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenReviewStatus {
    pub authenticated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<UserInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UserInfo {
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Vec<String>>,
}

struct TokenIssueParams<'a> {
    now: u64,
    exp: u64,
    namespace: &'a str,
    sa_name: &'a str,
    sa_uid: &'a str,
    audiences: &'a [String],
    bound_object_ref: Option<&'a BoundObjectRef>,
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
        self.issue_token_bound(namespace, sa_name, sa_uid, audiences, lifetime, None)
    }

    pub fn issue_token_bound(
        &self,
        namespace: &str,
        sa_name: &str,
        sa_uid: &str,
        audiences: &[String],
        lifetime: Duration,
        bound_object_ref: Option<&BoundObjectRef>,
    ) -> Result<String, ApiserverError> {
        let now = crate::time::now_unix();
        let exp = now.saturating_add(lifetime.as_secs());
        let params = TokenIssueParams {
            now,
            exp,
            namespace,
            sa_name,
            sa_uid,
            audiences,
            bound_object_ref,
        };
        self.issue_token_internal(&params)
    }

    fn issue_token_internal(
        &self,
        params: &TokenIssueParams<'_>,
    ) -> Result<String, ApiserverError> {
        if params.audiences.iter().any(|a| a == "*") {
            return Err(ApiserverError::InvalidInput {
                field: "audiences".to_string(),
                reason: "wildcard audience '*' is not permitted".to_string(),
            });
        }

        let aud = if params.audiences.is_empty() {
            if self.api_audiences.is_empty() {
                vec![self.issuer.clone()]
            } else {
                self.api_audiences.clone()
            }
        } else {
            params.audiences.to_vec()
        };

        let mut kubernetes_io = KubernetesIoClaims {
            namespace: params.namespace.to_string(),
            serviceaccount: ServiceAccountRef {
                name: params.sa_name.to_string(),
                uid: params.sa_uid.to_string(),
            },
            pod: None,
            secret: None,
            node: None,
        };

        if let Some(bound) = params.bound_object_ref {
            let item = BoundItemRef {
                name: bound.name.clone(),
                uid: bound.uid.clone(),
            };
            match bound.kind.as_str() {
                "Pod" => kubernetes_io.pod = Some(item),
                "Secret" => kubernetes_io.secret = Some(item),
                "Node" => kubernetes_io.node = Some(item),
                other => {
                    return Err(ApiserverError::InvalidInput {
                        field: "boundObjectRef.kind".to_string(),
                        reason: format!(
                            "unsupported bound object kind '{other}': must be Pod, Secret, or Node"
                        ),
                    });
                },
            }
        }

        let jti = format!(
            "{:016x}{:016x}",
            params.now,
            params
                .now
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1)
        );

        let claims = ServiceAccountClaims {
            iss: self.issuer.clone(),
            sub: format!(
                "system:serviceaccount:{}:{}",
                params.namespace, params.sa_name
            ),
            aud,
            exp: params.exp,
            nbf: params.now,
            iat: params.now,
            jti,
            kubernetes_io,
            namespace: params.namespace.to_string(),
            service_account_name: params.sa_name.to_string(),
            service_account_uid: params.sa_uid.to_string(),
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

    pub fn create_token_request(
        &self,
        namespace: &str,
        sa_name: &str,
        sa_uid: &str,
        mut request: TokenRequest,
    ) -> Result<TokenRequest, ApiserverError> {
        let now = crate::time::now_unix();
        // Kubernetes minimum floor: 600s (10 minutes). Default if omitted: 3600s (1 hour).
        let exp_secs = match request.spec.expiration_seconds {
            Some(secs) if secs < 600 => 600u64,
            Some(secs) => secs.max(600).cast_unsigned(),
            None => 3600u64,
        };
        let exp = now.saturating_add(exp_secs);
        let expiration_timestamp = crate::time::rfc3339_seconds(exp);

        let audiences = if request.spec.audiences.is_empty() {
            if self.api_audiences.is_empty() {
                vec![self.issuer.clone()]
            } else {
                self.api_audiences.clone()
            }
        } else {
            request.spec.audiences.clone()
        };

        let params = TokenIssueParams {
            now,
            exp,
            namespace,
            sa_name,
            sa_uid,
            audiences: &audiences,
            bound_object_ref: request.spec.bound_object_ref.as_ref(),
        };
        let token_str = self.issue_token_internal(&params)?;

        request.spec.audiences = audiences;
        request.spec.expiration_seconds = Some(exp_secs.cast_signed());
        request.status = Some(TokenRequestStatus {
            token: token_str,
            expiration_timestamp,
        });

        Ok(request)
    }

    pub fn create_token_request_value(
        &self,
        namespace: &str,
        sa_name: &str,
        sa_uid: &str,
        val: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiserverError> {
        let req: TokenRequest =
            serde_json::from_value(val.clone()).map_err(|e| ApiserverError::InvalidInput {
                field: "body".to_string(),
                reason: format!("failed to parse TokenRequest: {e}"),
            })?;
        let res = self.create_token_request(namespace, sa_name, sa_uid, req)?;
        serde_json::to_value(res).map_err(|e| ApiserverError::Internal {
            reason: format!("failed to serialize TokenRequest response: {e}"),
        })
    }

    pub fn review_token(&self, mut review: TokenReview) -> TokenReview {
        let token = &review.spec.token;
        if token.is_empty() {
            review.status = Some(TokenReviewStatus {
                authenticated: false,
                user: None,
                audiences: Vec::new(),
                error: Some("token is required".to_string()),
            });
            return review;
        }

        match self.verify_token_audiences(token, &review.spec.audiences) {
            Ok(claims) => {
                let username = claims.username().to_string();
                let sa_uid = claims.service_account_uid.clone();
                let groups = claims.groups();
                let mut extra = HashMap::new();
                if let Some(pod) = &claims.kubernetes_io.pod {
                    extra.insert(
                        "authentication.kubernetes.io/pod-name".to_string(),
                        vec![pod.name.clone()],
                    );
                    if let Some(uid) = &pod.uid {
                        extra.insert(
                            "authentication.kubernetes.io/pod-uid".to_string(),
                            vec![uid.clone()],
                        );
                    }
                }
                if let Some(node) = &claims.kubernetes_io.node {
                    extra.insert(
                        "authentication.kubernetes.io/node-name".to_string(),
                        vec![node.name.clone()],
                    );
                    if let Some(uid) = &node.uid {
                        extra.insert(
                            "authentication.kubernetes.io/node-uid".to_string(),
                            vec![uid.clone()],
                        );
                    }
                }
                review.status = Some(TokenReviewStatus {
                    authenticated: true,
                    user: Some(UserInfo {
                        username,
                        uid: if sa_uid.is_empty() {
                            None
                        } else {
                            Some(sa_uid)
                        },
                        groups,
                        extra,
                    }),
                    audiences: claims.aud.clone(),
                    error: None,
                });
            },
            Err(e) => {
                review.status = Some(TokenReviewStatus {
                    authenticated: false,
                    user: None,
                    audiences: Vec::new(),
                    error: Some(e.to_string()),
                });
            },
        }
        review
    }

    pub fn review_token_value(
        &self,
        val: &serde_json::Value,
    ) -> Result<serde_json::Value, ApiserverError> {
        let req: TokenReview =
            serde_json::from_value(val.clone()).map_err(|e| ApiserverError::InvalidInput {
                field: "body".to_string(),
                reason: format!("failed to parse TokenReview: {e}"),
            })?;
        let res = self.review_token(req);
        serde_json::to_value(res).map_err(|e| ApiserverError::Internal {
            reason: format!("failed to serialize TokenReview response: {e}"),
        })
    }

    fn verify_token_internal(
        &self,
        token_str: &str,
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
        let now = crate::time::now_unix();

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

        // 4. Verify cryptographic signature
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

    pub fn verify_token(
        &self,
        token_str: &str,
        expected_audience: Option<&str>,
    ) -> Result<ServiceAccountClaims, ApiserverError> {
        let claims = self.verify_token_internal(token_str)?;
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
        Ok(claims)
    }

    pub fn verify_token_audiences(
        &self,
        token_str: &str,
        expected_audiences: &[String],
    ) -> Result<ServiceAccountClaims, ApiserverError> {
        let claims = self.verify_token_internal(token_str)?;

        if expected_audiences.is_empty() {
            let default_auds = if self.api_audiences.is_empty() {
                std::slice::from_ref(&self.issuer)
            } else {
                &self.api_audiences
            };
            let matched = claims.aud.iter().any(|a| default_auds.contains(a));
            if !matched {
                return Err(ApiserverError::Unauthorized {
                    reason: format!(
                        "token audience mismatch (token aud: {:?}, expected one of apiserver audiences: {:?})",
                        claims.aud, default_auds
                    ),
                });
            }
        } else {
            let matched = claims
                .aud
                .iter()
                .any(|a| expected_audiences.iter().any(|exp_aud| exp_aud == a));
            if !matched {
                return Err(ApiserverError::Unauthorized {
                    reason: format!(
                        "token audience mismatch (token aud: {:?}, expected one of: {:?})",
                        claims.aud, expected_audiences
                    ),
                });
            }
        }

        Ok(claims)
    }

    pub fn project_token_volume_bound(
        &self,
        projection: &TokenProjection<'_>,
        bound_object_ref: Option<&BoundObjectRef>,
    ) -> Result<PathBuf, ApiserverError> {
        let token_str = self.issue_token_bound(
            projection.namespace,
            projection.sa_name,
            projection.sa_uid,
            projection.audiences,
            projection.lifetime,
            bound_object_ref,
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

    pub fn project_token_volume(
        &self,
        projection: &TokenProjection<'_>,
    ) -> Result<PathBuf, ApiserverError> {
        self.project_token_volume_bound(projection, None)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tempfile::TempDir;

    use super::{
        BoundObjectRef, TokenProjection, TokenRequest, TokenRequestMetadata, TokenRequestSpec,
        TokenReview, TokenReviewMetadata, TokenReviewSpec, TokenService,
    };

    fn test_token_service(temp: &TempDir) -> TokenService {
        let key_pair =
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
                .expect("RSA key generation");
        let key_pem = key_pair.serialize_pem();
        let signing_key_path = temp.path().join("sa-signing.key");
        let verification_key_path = temp.path().join("sa-verification.pub");
        std::fs::write(&signing_key_path, key_pem.as_bytes()).expect("write signing key");

        TokenService::new(
            "https://kubernetes.default.svc".to_string(),
            vec!["https://kubernetes.default.svc".to_string()],
            &signing_key_path,
            &verification_key_path,
        )
        .expect("TokenService::new")
    }

    #[test]
    fn test_token_request_with_custom_audiences_expiration_and_bound_object_ref() {
        let temp = TempDir::new().expect("tempdir");
        let ts = test_token_service(&temp);

        let req = TokenRequest {
            api_version: "authentication.k8s.io/v1".to_string(),
            kind: "TokenRequest".to_string(),
            metadata: TokenRequestMetadata::default(),
            spec: TokenRequestSpec {
                audiences: vec!["https://vault.corp".to_string(), "custom-aud".to_string()],
                expiration_seconds: Some(1200),
                bound_object_ref: Some(BoundObjectRef {
                    api_version: Some("v1".to_string()),
                    kind: "Pod".to_string(),
                    name: "app-pod-1".to_string(),
                    uid: Some("pod-uid-99".to_string()),
                }),
            },
            status: None,
        };

        let result = ts
            .create_token_request("prod", "web-sa", "sa-uid-42", req)
            .expect("create_token_request");

        // 1. Verify spec and status in result
        assert_eq!(result.spec.expiration_seconds, Some(1200));
        assert_eq!(
            result.spec.audiences,
            vec!["https://vault.corp".to_string(), "custom-aud".to_string()]
        );
        let status = result.status.expect("status must be present");
        assert_ne!(status.token, "");
        assert!(status.expiration_timestamp.ends_with('Z'));

        // 2. Parse and verify JWT claims payload
        let parts: Vec<&str> = status.token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload_bytes =
            diorama_pki::token::base64url_decode(parts[1]).expect("base64url decode");
        let claims_val: serde_json::Value =
            serde_json::from_slice(&payload_bytes).expect("json parse");

        assert_eq!(claims_val["iss"], "https://kubernetes.default.svc");
        assert_eq!(claims_val["sub"], "system:serviceaccount:prod:web-sa");
        assert_eq!(
            claims_val["aud"],
            serde_json::json!(["https://vault.corp", "custom-aud"])
        );
        assert_eq!(claims_val["kubernetes.io"]["namespace"], "prod");
        assert_eq!(
            claims_val["kubernetes.io"]["serviceaccount"]["name"],
            "web-sa"
        );
        assert_eq!(
            claims_val["kubernetes.io"]["serviceaccount"]["uid"],
            "sa-uid-42"
        );
        assert_eq!(claims_val["kubernetes.io"]["pod"]["name"], "app-pod-1");
        assert_eq!(claims_val["kubernetes.io"]["pod"]["uid"], "pod-uid-99");
        assert!(claims_val["exp"].is_u64());
        assert!(claims_val["nbf"].is_u64());
        assert!(claims_val["iat"].is_u64());

        // 3. Verify token with verify_token
        let verified = ts
            .verify_token(&status.token, Some("https://vault.corp"))
            .expect("token verification");
        assert_eq!(verified.namespace, "prod");
        assert_eq!(verified.service_account_name, "web-sa");
        assert_eq!(verified.service_account_uid, "sa-uid-42");
        assert_eq!(verified.username(), "system:serviceaccount:prod:web-sa");
        assert_eq!(
            verified.groups(),
            vec![
                "system:serviceaccounts".to_string(),
                "system:serviceaccounts:prod".to_string(),
                "system:authenticated".to_string()
            ]
        );
    }

    #[test]
    fn test_token_request_expiration_floor_and_default_audience() {
        let temp = TempDir::new().expect("tempdir");
        let ts = test_token_service(&temp);

        // Sub-600s expiration is floored to 600s
        let short_request = TokenRequest {
            api_version: "authentication.k8s.io/v1".to_string(),
            kind: "TokenRequest".to_string(),
            metadata: TokenRequestMetadata::default(),
            spec: TokenRequestSpec {
                audiences: Vec::new(),
                expiration_seconds: Some(60),
                bound_object_ref: None,
            },
            status: None,
        };

        let short_result = ts
            .create_token_request("default", "default", "uid-1", short_request)
            .expect("create_token_request");
        assert_eq!(short_result.spec.expiration_seconds, Some(600));
        assert_eq!(
            short_result.spec.audiences,
            vec!["https://kubernetes.default.svc".to_string()]
        );

        // Missing expirationSeconds defaults to 3600s
        let unspecified_request = TokenRequest {
            api_version: "authentication.k8s.io/v1".to_string(),
            kind: "TokenRequest".to_string(),
            metadata: TokenRequestMetadata::default(),
            spec: TokenRequestSpec {
                audiences: Vec::new(),
                expiration_seconds: None,
                bound_object_ref: None,
            },
            status: None,
        };

        let unspecified_result = ts
            .create_token_request("default", "default", "uid-1", unspecified_request)
            .expect("create_token_request");
        assert_eq!(unspecified_result.spec.expiration_seconds, Some(3600));
    }

    #[test]
    fn test_token_request_bound_nodes_secrets_and_invalid_kind() {
        let temp = TempDir::new().expect("tempdir");
        let ts = test_token_service(&temp);

        // Node bound
        let node_request = TokenRequest {
            api_version: "authentication.k8s.io/v1".to_string(),
            kind: "TokenRequest".to_string(),
            metadata: TokenRequestMetadata::default(),
            spec: TokenRequestSpec {
                audiences: vec!["https://kubernetes.default.svc".to_string()],
                expiration_seconds: Some(600),
                bound_object_ref: Some(BoundObjectRef {
                    api_version: None,
                    kind: "Node".to_string(),
                    name: "node-1".to_string(),
                    uid: Some("node-uid-10".to_string()),
                }),
            },
            status: None,
        };
        let node_result = ts
            .create_token_request("kube-system", "node-agent", "sa-uid-node", node_request)
            .expect("create node token");
        let token_node = node_result.status.unwrap().token;
        let verified_node = ts
            .verify_token(&token_node, Some("https://kubernetes.default.svc"))
            .expect("verify node token");
        assert_eq!(
            verified_node.kubernetes_io.node.as_ref().unwrap().name,
            "node-1"
        );
        assert_eq!(
            verified_node
                .kubernetes_io
                .node
                .as_ref()
                .unwrap()
                .uid
                .as_deref(),
            Some("node-uid-10")
        );

        // Secret bound
        let secret_request = TokenRequest {
            api_version: "authentication.k8s.io/v1".to_string(),
            kind: "TokenRequest".to_string(),
            metadata: TokenRequestMetadata::default(),
            spec: TokenRequestSpec {
                audiences: vec!["https://kubernetes.default.svc".to_string()],
                expiration_seconds: Some(600),
                bound_object_ref: Some(BoundObjectRef {
                    api_version: None,
                    kind: "Secret".to_string(),
                    name: "my-secret".to_string(),
                    uid: None,
                }),
            },
            status: None,
        };
        let secret_result = ts
            .create_token_request("default", "secret-agent", "sa-uid-sec", secret_request)
            .expect("create secret token");
        let token_sec = secret_result.status.unwrap().token;
        let verified_sec = ts
            .verify_token(&token_sec, Some("https://kubernetes.default.svc"))
            .expect("verify secret token");
        assert_eq!(
            verified_sec.kubernetes_io.secret.as_ref().unwrap().name,
            "my-secret"
        );

        // Invalid bound kind rejected
        let req_invalid = TokenRequest {
            api_version: "authentication.k8s.io/v1".to_string(),
            kind: "TokenRequest".to_string(),
            metadata: TokenRequestMetadata::default(),
            spec: TokenRequestSpec {
                audiences: vec!["https://kubernetes.default.svc".to_string()],
                expiration_seconds: Some(600),
                bound_object_ref: Some(BoundObjectRef {
                    api_version: None,
                    kind: "Deployment".to_string(),
                    name: "my-deploy".to_string(),
                    uid: None,
                }),
            },
            status: None,
        };
        assert!(
            ts.create_token_request("default", "sa", "uid", req_invalid)
                .is_err()
        );
    }

    #[test]
    fn test_project_token_volume_nested_jwt_claims() {
        let temp = TempDir::new().expect("tempdir");
        let ts = test_token_service(&temp);

        let target_dir = temp.path().join("projected-volume");
        let audiences = ["https://kubernetes.default.svc".to_string()];
        let bound = BoundObjectRef {
            api_version: Some("v1".to_string()),
            kind: "Pod".to_string(),
            name: "runner-pod".to_string(),
            uid: Some("runner-uid".to_string()),
        };
        let projection = TokenProjection {
            target_dir: &target_dir,
            namespace: "work",
            sa_name: "job-runner",
            sa_uid: "uid-job-1",
            audiences: &audiences,
            lifetime: Duration::from_mins(30),
            ca_cert: b"FAKE-CA-CERT",
        };

        let token_path = ts
            .project_token_volume_bound(&projection, Some(&bound))
            .expect("project_token_volume_bound");
        assert_eq!(token_path, target_dir.join("token"));
        assert!(target_dir.join("ca.crt").exists());
        assert_eq!(
            std::fs::read_to_string(target_dir.join("namespace")).unwrap(),
            "work"
        );

        let token_str = std::fs::read_to_string(token_path).unwrap();
        let verified = ts
            .verify_token(&token_str, Some("https://kubernetes.default.svc"))
            .expect("verify projected token");
        assert_eq!(verified.namespace, "work");
        assert_eq!(verified.service_account_name, "job-runner");
        assert_eq!(
            verified.kubernetes_io.pod.as_ref().unwrap().name,
            "runner-pod"
        );
        assert_eq!(
            verified.kubernetes_io.pod.as_ref().unwrap().uid.as_deref(),
            Some("runner-uid")
        );
    }

    #[test]
    fn test_token_review_validation() {
        let temp = TempDir::new().expect("tempdir");
        let ts = test_token_service(&temp);

        let req = TokenRequest {
            api_version: "authentication.k8s.io/v1".to_string(),
            kind: "TokenRequest".to_string(),
            metadata: TokenRequestMetadata::default(),
            spec: TokenRequestSpec {
                audiences: vec!["https://kubernetes.default.svc".to_string()],
                expiration_seconds: Some(800),
                bound_object_ref: Some(BoundObjectRef {
                    api_version: Some("v1".to_string()),
                    kind: "Pod".to_string(),
                    name: "backend-pod".to_string(),
                    uid: Some("pod-uid-backend".to_string()),
                }),
            },
            status: None,
        };
        let res = ts
            .create_token_request("staging", "backend-sa", "sa-uid-stage", req)
            .unwrap();
        let token = res.status.unwrap().token;

        // 1. Successful TokenReview with matching audience
        let review_req = TokenReview {
            api_version: "authentication.k8s.io/v1".to_string(),
            kind: "TokenReview".to_string(),
            metadata: TokenReviewMetadata::default(),
            spec: TokenReviewSpec {
                token: token.clone(),
                audiences: vec!["https://kubernetes.default.svc".to_string()],
            },
            status: None,
        };
        let reviewed_output = ts.review_token(review_req);
        let status = reviewed_output.status.expect("status");
        assert!(status.authenticated);
        assert!(status.error.is_none());
        let user = status.user.expect("user");
        assert_eq!(user.username, "system:serviceaccount:staging:backend-sa");
        assert_eq!(user.uid.as_deref(), Some("sa-uid-stage"));
        assert_eq!(
            user.groups,
            vec![
                "system:serviceaccounts".to_string(),
                "system:serviceaccounts:staging".to_string(),
                "system:authenticated".to_string()
            ]
        );
        assert_eq!(
            user.extra.get("authentication.kubernetes.io/pod-name"),
            Some(&vec!["backend-pod".to_string()])
        );
        assert_eq!(
            user.extra.get("authentication.kubernetes.io/pod-uid"),
            Some(&vec!["pod-uid-backend".to_string()])
        );

        // 2. Successful TokenReview with empty audiences (defaults to cluster audiences)
        let review_empty_aud = TokenReview {
            api_version: "authentication.k8s.io/v1".to_string(),
            kind: "TokenReview".to_string(),
            metadata: TokenReviewMetadata::default(),
            spec: TokenReviewSpec {
                token: token.clone(),
                audiences: Vec::new(),
            },
            status: None,
        };
        let res_empty = ts.review_token(review_empty_aud);
        assert!(res_empty.status.unwrap().authenticated);

        // 3. Failed TokenReview with wrong audience
        let review_bad_aud = TokenReview {
            api_version: "authentication.k8s.io/v1".to_string(),
            kind: "TokenReview".to_string(),
            metadata: TokenReviewMetadata::default(),
            spec: TokenReviewSpec {
                token: token.clone(),
                audiences: vec!["https://other-service.internal".to_string()],
            },
            status: None,
        };
        let res_bad_aud = ts.review_token(review_bad_aud);
        let bad_status = res_bad_aud.status.unwrap();
        assert!(!bad_status.authenticated);
        assert!(bad_status.user.is_none());
        assert!(bad_status.error.is_some());

        // 4. Failed TokenReview with tampered token
        let review_tampered = TokenReview {
            api_version: "authentication.k8s.io/v1".to_string(),
            kind: "TokenReview".to_string(),
            metadata: TokenReviewMetadata::default(),
            spec: TokenReviewSpec {
                token: format!("{token}extra"),
                audiences: vec!["https://kubernetes.default.svc".to_string()],
            },
            status: None,
        };
        let res_tampered = ts.review_token(review_tampered);
        assert!(!res_tampered.status.unwrap().authenticated);
    }
}
