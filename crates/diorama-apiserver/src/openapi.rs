//! Minimal `OpenAPI` v3 documents for kubectl's validation handshake.
//!
//! kubectl refuses to create objects without `--validate=false` unless it can
//! download `OpenAPI`. It only needs to learn that the `fieldValidation` query
//! parameter is supported for a kind; the schema itself may be empty. These
//! documents cover the core kinds the gateway serves and nothing else.

use serde_json::{Value, json};

/// Stable identifier kubectl uses to cache the core document.
pub const CORE_HASH: &str = "diorama-core-v1";

/// `GET /openapi/v3`: discovery of per-group documents.
#[must_use]
pub fn v3_index() -> Value {
    json!({
        "paths": {
            "api/v1": {
                "serverRelativeURL": format!("/openapi/v3/api/v1?hash={CORE_HASH}")
            }
        }
    })
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
    ] {
        let collection = path.trim_end_matches("/{name}");
        paths.insert(collection.to_string(), json!({ "post": operation(kind) }));
    }
    json!({
        "openapi": "3.0.0",
        "info": { "title": "Kubernetes", "version": "v1.35.7" },
        "paths": paths,
        "components": { "schemas": {} }
    })
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

#[cfg(test)]
mod tests {
    use super::{CORE_HASH, v3_core, v3_index};
    use serde_json::Value;

    #[test]
    fn index_points_at_core_document() {
        let url = v3_index()["paths"]["api/v1"]["serverRelativeURL"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(url, format!("/openapi/v3/api/v1?hash={CORE_HASH}"));
    }

    #[test]
    fn pod_create_advertises_field_validation() {
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
    }
}
