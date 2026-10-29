//! Lease ownership is checked before each reconciliation pass. CAS updates prevent
//! a process from taking over a live leader's lease.
use diorama_apiserver::{
    ApiserverError, KubernetesApiClient,
    time::{now_rfc3339, now_unix, parse_rfc3339_seconds},
};
use serde_json::{Value, json};
pub(crate) async fn acquire(
    client: &KubernetesApiClient,
    identity: &str,
) -> Result<bool, ApiserverError> {
    let (namespace, name) = ("kube-system", "kube-controller-manager");
    let old = match client.get_lease(namespace, name).await {
        Ok(old) => Some(old),
        Err(ApiserverError::NotFound { .. }) => None,
        Err(e) => return Err(e),
    };
    if let Some(old) = &old {
        let holder = old
            .pointer("/spec/holderIdentity")
            .and_then(Value::as_str)
            .unwrap_or("");
        let renewed = old
            .pointer("/spec/renewTime")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_seconds)
            .unwrap_or(0);
        let lifetime = old
            .pointer("/spec/leaseDurationSeconds")
            .and_then(Value::as_u64)
            .unwrap_or(60);
        if holder != identity && now_unix() < renewed.saturating_add(lifetime) {
            return Ok(false);
        }
    }
    let mut lease = json!({"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{"name":name,"namespace":namespace},"spec":{"holderIdentity":identity,"leaseDurationSeconds":60,"renewTime":now_rfc3339()}});
    let result = if let Some(old) = old {
        lease["metadata"]["resourceVersion"] = old["metadata"]["resourceVersion"].clone();
        client.update_lease(namespace, name, lease).await
    } else {
        client.create_lease(namespace, lease).await
    };
    match result {
        Ok(_) => Ok(true),
        Err(ApiserverError::Conflict { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}
