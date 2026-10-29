//! Kubernetes bootstrap-token Secrets and kubelet CSR admission.
use crate::{ApiserverError, ApiserverService, KubernetesApiClient};
use serde_json::{Value, json};

pub fn secret_field(secret: &Value, name: &str) -> Option<String> {
    let data = secret.get("data")?.get(name)?.as_str()?;
    String::from_utf8(diorama_pki::base64_decode(data).ok()?).ok()
}
pub fn token_expired(secret: &Value) -> bool {
    secret_field(secret, "expiration").is_none_or(|v| {
        crate::time::parse_rfc3339_seconds(&v).is_none_or(|exp| exp <= crate::time::now_unix())
    })
}
fn token_parts(token: &str) -> Option<(&str, &str)> {
    let (id, secret) = token.split_once('.')?;
    (id.len() == 6
        && secret.len() == 16
        && id
            .bytes()
            .chain(secret.bytes())
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    .then_some((id, secret))
}
fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

impl ApiserverService {
    /// Consult storage on every request: revocation and expiry never depend on a cache.
    pub async fn bootstrap_client(&self, token: &str) -> Option<KubernetesApiClient> {
        let (id, supplied) = token_parts(token)?;
        let secret = self
            .admin_client()
            .get_secret("kube-system", &format!("bootstrap-token-{id}"))
            .await
            .ok()?;
        if secret["type"] != "bootstrap.kubernetes.io/token"
            || token_expired(&secret)
            || secret_field(&secret, "token-id").as_deref() != Some(id)
            || secret_field(&secret, "usage-bootstrap-authentication").as_deref() != Some("true")
            || !constant_time_equal(
                supplied.as_bytes(),
                secret_field(&secret, "token-secret")?.as_bytes(),
            )
        {
            return None;
        }
        Some(self.user_client(
            format!("system:bootstrap:{id}"),
            vec!["system:bootstrappers".into(), "system:authenticated".into()],
        ))
    }
}

pub async fn prepare_csr(
    client: &KubernetesApiClient,
    doc: &mut Value,
) -> Result<(), ApiserverError> {
    let user = client.current_user_info().await;
    if doc.pointer("/spec/signerName").and_then(Value::as_str)
        == Some(diorama_pki::bootstrap::KUBELET_SIGNER)
        || user.username.starts_with("system:node:")
        || user.username.starts_with("system:bootstrap:")
    {
        let node = validate_kubelet_csr(doc)?;
        if user.username.starts_with("system:node:")
            && user.username != format!("system:node:{node}")
        {
            return Err(invalid());
        }
    }
    // Authenticated requester information is server-owned, including on admin submissions.
    doc["spec"]["username"] = json!(user.username);
    doc["spec"]["groups"] = json!(user.groups);
    doc["spec"]
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove("extra");
    doc["spec"]
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove("uid");
    doc.as_object_mut().ok_or_else(invalid)?.remove("status");
    Ok(())
}
pub fn validate_kubelet_csr(doc: &Value) -> Result<String, ApiserverError> {
    let request = doc
        .pointer("/spec/request")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let pem = String::from_utf8(diorama_pki::base64_decode(request).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let node = diorama_pki::bootstrap::validate_kubelet_request(&pem).map_err(|_| invalid())?;
    if doc.pointer("/spec/signerName").and_then(Value::as_str)
        != Some(diorama_pki::bootstrap::KUBELET_SIGNER)
    {
        return Err(invalid());
    }
    let usages = doc
        .pointer("/spec/usages")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if !usages.iter().any(|u| u == "client auth")
        || !usages.iter().any(|u| u == "digital signature")
        || usages.iter().any(|u| {
            !matches!(
                u.as_str(),
                Some("client auth" | "digital signature" | "key encipherment")
            )
        })
    {
        return Err(invalid());
    }
    Ok(node)
}
fn invalid() -> ApiserverError {
    ApiserverError::BadRequest {
        message: "invalid kubelet client certificate request".into(),
    }
}
