//! Minimal `OpenAPI` v3 documents for kubectl's validation handshake.
//!
//! kubectl refuses to create objects without `--validate=false` unless it can
//! download `OpenAPI`. It only needs to learn that the `fieldValidation` query
//! parameter is supported for a kind; the schema itself may be empty. These
//! documents cover the core kinds the gateway serves and nothing else.

use serde_json::{Value, json};

/// Stable identifier kubectl uses to cache the core document.
pub const CORE_HASH: &str = "diorama-core-v1";
/// Stable identifier kubectl uses to cache the storage document.
pub const STORAGE_HASH: &str = "diorama-storage-v1";

/// Groups served with per-group `OpenAPI` documents.
const GROUP_DOCS: &[(&str, &str)] = &[
    ("apps", "v1"),
    ("batch", "v1"),
    ("coordination.k8s.io", "v1"),
    ("events.k8s.io", "v1"),
    ("rbac.authorization.k8s.io", "v1"),
    ("discovery.k8s.io", "v1"),
    ("apiextensions.k8s.io", "v1"),
    ("admissionregistration.k8s.io", "v1"),
    ("apiregistration.k8s.io", "v1"),
];

/// `GET /openapi/v3`: discovery of per-group documents.
#[must_use]
pub fn v3_index() -> Value {
    let mut paths = serde_json::Map::new();
    paths.insert(
        "api/v1".to_string(),
        json!({
            "serverRelativeURL": format!("/openapi/v3/api/v1?hash={CORE_HASH}")
        }),
    );
    paths.insert(
        "apis/storage.k8s.io/v1".to_string(),
        json!({
            "serverRelativeURL": format!("/openapi/v3/apis/storage.k8s.io/v1?hash={STORAGE_HASH}")
        }),
    );
    for (group, version) in GROUP_DOCS {
        let key = format!("apis/{group}/{version}");
        let hash = format!("diorama-{}-{version}", group.replace('.', "-"));
        paths.insert(
            key.clone(),
            json!({
                "serverRelativeURL": format!("/openapi/v3/{key}?hash={hash}")
            }),
        );
    }
    json!({ "paths": paths })
}

/// `GET /openapi/v3/api/v1`: core group paths carrying the kubectl extensions.
#[must_use]
pub fn v3_core() -> Value {
    let mut paths = serde_json::Map::new();
    for (kind, path) in [
        ("Namespace", "/api/v1/namespaces/{name}"),
        (
            "ConfigMap",
            "/api/v1/namespaces/{namespace}/configmaps/{name}",
        ),
        ("Pod", "/api/v1/namespaces/{namespace}/pods/{name}"),
        ("Service", "/api/v1/namespaces/{namespace}/services/{name}"),
        (
            "Endpoints",
            "/api/v1/namespaces/{namespace}/endpoints/{name}",
        ),
        ("Secret", "/api/v1/namespaces/{namespace}/secrets/{name}"),
        (
            "PersistentVolumeClaim",
            "/api/v1/namespaces/{namespace}/persistentvolumeclaims/{name}",
        ),
        ("PersistentVolume", "/api/v1/persistentvolumes/{name}"),
    ] {
        let collection = path.trim_end_matches("/{name}");
        paths.insert(collection.to_string(), json!({ "post": operation(kind) }));
    }
    json!({
        "openapi": "3.0.0",
        "info": { "title": "Kubernetes", "version": crate::KUBERNETES_VERSION },
        "paths": paths,
        "components": { "schemas": {} }
    })
}

/// `GET /openapi/v3/apis/storage.k8s.io/v1`: storage.k8s.io group paths.
#[must_use]
pub fn v3_storage_v1() -> Value {
    let mut paths = serde_json::Map::new();
    paths.insert(
        "/apis/storage.k8s.io/v1/storageclasses".to_string(),
        json!({ "post": group_operation("storage.k8s.io", "v1", "StorageClass") }),
    );
    json!({
        "openapi": "3.0.0",
        "info": { "title": "Kubernetes", "version": crate::KUBERNETES_VERSION },
        "paths": paths,
        "components": { "schemas": {} }
    })
}

/// `GET /openapi/v3/apis/<group>/<version>`: per-group paths for kubectl validation.
#[must_use]
pub fn v3_group(group: &str, version: &str) -> Value {
    let mut paths = serde_json::Map::new();
    for (kind, plural, namespaced) in group_kinds(group, version) {
        let path = if namespaced {
            format!("/apis/{group}/{version}/namespaces/{{namespace}}/{plural}")
        } else {
            format!("/apis/{group}/{version}/{plural}")
        };
        paths.insert(
            path,
            json!({ "post": group_operation(group, version, kind) }),
        );
    }
    json!({
        "openapi": "3.0.0",
        "info": { "title": "Kubernetes", "version": crate::KUBERNETES_VERSION },
        "paths": paths,
        "components": { "schemas": {} }
    })
}

fn group_kinds(group: &str, version: &str) -> Vec<(&'static str, &'static str, bool)> {
    match (group, version) {
        ("apps", "v1") => vec![
            ("Deployment", "deployments", true),
            ("ReplicaSet", "replicasets", true),
            ("StatefulSet", "statefulsets", true),
            ("DaemonSet", "daemonsets", true),
        ],
        ("batch", "v1") => vec![("Job", "jobs", true), ("CronJob", "cronjobs", true)],
        ("coordination.k8s.io", "v1") => vec![("Lease", "leases", true)],
        ("events.k8s.io", "v1") => vec![("Event", "events", true)],
        ("discovery.k8s.io", "v1") => vec![("EndpointSlice", "endpointslices", true)],
        ("rbac.authorization.k8s.io", "v1") => vec![
            ("ClusterRole", "clusterroles", false),
            ("ClusterRoleBinding", "clusterrolebindings", false),
            ("Role", "roles", true),
            ("RoleBinding", "rolebindings", true),
        ],
        ("apiextensions.k8s.io", "v1") => vec![(
            "CustomResourceDefinition",
            "customresourcedefinitions",
            false,
        )],
        ("admissionregistration.k8s.io", "v1") => vec![
            (
                "ValidatingWebhookConfiguration",
                "validatingwebhookconfigurations",
                false,
            ),
            (
                "MutatingWebhookConfiguration",
                "mutatingwebhookconfigurations",
                false,
            ),
        ],
        ("apiregistration.k8s.io", "v1") => vec![("APIService", "apiservices", false)],
        ("storage.k8s.io", "v1") => vec![("StorageClass", "storageclasses", false)],
        _ => Vec::new(),
    }
}

fn operation(kind: &str) -> Value {
    json!({
        "parameters": [
            {
                "name": "fieldValidation",
                "in": "query",
                "schema": { "type": "string", "uniqueItems": true }
            },
            {
                "name": "dryRun",
                "in": "query",
                "schema": { "type": "string", "uniqueItems": true }
            }
        ],
        "responses": { "200": { "description": "OK" } },
        "x-kubernetes-group-version-kind": { "group": "", "version": "v1", "kind": kind }
    })
}

fn group_operation(group: &str, version: &str, kind: &str) -> Value {
    json!({
        "parameters": [
            {
                "name": "fieldValidation",
                "in": "query",
                "schema": { "type": "string", "uniqueItems": true }
            },
            {
                "name": "dryRun",
                "in": "query",
                "schema": { "type": "string", "uniqueItems": true }
            }
        ],
        "responses": { "200": { "description": "OK" } },
        "x-kubernetes-group-version-kind": { "group": group, "version": version, "kind": kind }
    })
}

#[cfg(test)]
mod tests {
    use super::{CORE_HASH, STORAGE_HASH, v3_core, v3_index, v3_storage_v1};
    use serde_json::Value;

    #[test]
    fn index_points_at_core_and_storage_documents() {
        let url = v3_index()["paths"]["api/v1"]["serverRelativeURL"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(url, format!("/openapi/v3/api/v1?hash={CORE_HASH}"));

        let storage_url = v3_index()["paths"]["apis/storage.k8s.io/v1"]["serverRelativeURL"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            storage_url,
            format!("/openapi/v3/apis/storage.k8s.io/v1?hash={STORAGE_HASH}")
        );
    }

    #[test]
    fn storage_create_advertises_field_validation() {
        let doc = v3_storage_v1();
        let post = &doc["paths"]["/apis/storage.k8s.io/v1/storageclasses"]["post"];
        assert_eq!(
            post["x-kubernetes-group-version-kind"]["kind"],
            "StorageClass"
        );
        assert_eq!(
            post["x-kubernetes-group-version-kind"]["group"],
            "storage.k8s.io"
        );
    }

    #[test]
    fn pod_and_pvc_create_advertises_field_validation() {
        let doc = v3_core();
        let post = &doc["paths"]["/api/v1/namespaces/{namespace}/pods"]["post"];
        assert_eq!(post["x-kubernetes-group-version-kind"]["kind"], "Pod");
        let names: Vec<&str> = post["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["name"].as_str())
            .collect();
        assert!(names.contains(&"fieldValidation"));
        assert!(matches!(
            doc["paths"]["/api/v1/namespaces"]["post"],
            Value::Object(_)
        ));
        assert!(matches!(
            doc["paths"]["/api/v1/namespaces/{namespace}/persistentvolumeclaims"]["post"],
            Value::Object(_)
        ));
        assert!(matches!(
            doc["paths"]["/api/v1/persistentvolumes"]["post"],
            Value::Object(_)
        ));
    }
}
