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
    ("autoscaling", "v1"),
    ("autoscaling", "v2"),
    ("policy", "v1"),
    ("networking.k8s.io", "v1"),
    ("certificates.k8s.io", "v1"),
    ("scheduling.k8s.io", "v1"),
    ("node.k8s.io", "v1"),
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
    v3_index_with_crds(&[])
}

/// `GET /openapi/v3`: discovery of per-group documents including dynamic CRDs.
#[must_use]
pub fn v3_index_with_crds(crds: &[Value]) -> Value {
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
    for crd in crds {
        let Some(spec) = crd.get("spec") else {
            continue;
        };
        let Some(group) = spec.get("group").and_then(Value::as_str) else {
            continue;
        };
        let rv = crd
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .unwrap_or("1");
        if let Some(versions) = spec.get("versions").and_then(Value::as_array) {
            for v in versions {
                if v.get("served").and_then(Value::as_bool) == Some(false) {
                    continue;
                }
                let Some(v_name) = v.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let key = format!("apis/{group}/{v_name}");
                let hash = format!("diorama-{}-{v_name}-{rv}", group.replace('.', "-"));
                paths.insert(
                    key.clone(),
                    json!({
                        "serverRelativeURL": format!("/openapi/v3/{key}?hash={hash}")
                    }),
                );
            }
        }
    }
    json!({ "paths": paths })
}

/// `GET /openapi/v3/api/v1`: core group paths carrying the kubectl extensions.
#[must_use]
pub fn v3_core() -> Value {
    let mut paths = serde_json::Map::new();
    for (kind, path) in [
        ("Namespace", "/api/v1/namespaces/{name}"),
        ("Node", "/api/v1/nodes/{name}"),
        (
            "ConfigMap",
            "/api/v1/namespaces/{namespace}/configmaps/{name}",
        ),
        ("Pod", "/api/v1/namespaces/{namespace}/pods/{name}"),
        (
            "PodTemplate",
            "/api/v1/namespaces/{namespace}/podtemplates/{name}",
        ),
        (
            "ReplicationController",
            "/api/v1/namespaces/{namespace}/replicationcontrollers/{name}",
        ),
        (
            "ResourceQuota",
            "/api/v1/namespaces/{namespace}/resourcequotas/{name}",
        ),
        (
            "LimitRange",
            "/api/v1/namespaces/{namespace}/limitranges/{name}",
        ),
        ("Service", "/api/v1/namespaces/{namespace}/services/{name}"),
        (
            "ServiceAccount",
            "/api/v1/namespaces/{namespace}/serviceaccounts/{name}",
        ),
        (
            "Endpoints",
            "/api/v1/namespaces/{namespace}/endpoints/{name}",
        ),
        ("Secret", "/api/v1/namespaces/{namespace}/secrets/{name}"),
        ("Event", "/api/v1/namespaces/{namespace}/events/{name}"),
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
    for (kind, path) in [
        ("StorageClass", "/apis/storage.k8s.io/v1/storageclasses"),
        ("CSINode", "/apis/storage.k8s.io/v1/csinodes"),
        ("CSIDriver", "/apis/storage.k8s.io/v1/csidrivers"),
        (
            "CSIStorageCapacity",
            "/apis/storage.k8s.io/v1/namespaces/{namespace}/csistoragecapacities",
        ),
        (
            "VolumeAttachment",
            "/apis/storage.k8s.io/v1/volumeattachments",
        ),
        (
            "VolumeAttributesClass",
            "/apis/storage.k8s.io/v1/volumeattributesclasses",
        ),
    ] {
        paths.insert(
            path.to_string(),
            json!({ "post": group_operation("storage.k8s.io", "v1", kind) }),
        );
    }
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
    v3_group_with_crds(group, version, &[])
}

/// `GET /openapi/v3/apis/<group>/<version>`: per-group paths and schemas including dynamic CRDs.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn v3_group_with_crds(group: &str, version: &str, crds: &[Value]) -> Value {
    let mut paths = serde_json::Map::new();
    let mut schemas = serde_json::Map::new();
    for (kind, plural, namespaced) in group_kinds(group, version) {
        let path = if namespaced {
            format!("/apis/{group}/{version}/namespaces/{{namespace}}/{plural}")
        } else {
            format!("/apis/{group}/{version}/{plural}")
        };
        let item_path = format!("{path}/{{name}}");
        paths.insert(
            path,
            json!({ "post": group_operation(group, version, kind) }),
        );
        paths.insert(
            item_path,
            json!({
                "put": group_operation(group, version, kind),
                "patch": group_operation(group, version, kind)
            }),
        );
    }

    let reversed_group = reverse_group(group);
    for crd in crds {
        let Some(spec) = crd.get("spec") else {
            continue;
        };
        if spec.get("group").and_then(Value::as_str) != Some(group) {
            continue;
        }
        let kind = spec
            .pointer("/names/kind")
            .and_then(Value::as_str)
            .unwrap_or("CustomResource");
        let plural = spec
            .pointer("/names/plural")
            .and_then(Value::as_str)
            .unwrap_or("customresources");
        let namespaced = spec
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or("Namespaced")
            == "Namespaced";
        let Some(versions) = spec.get("versions").and_then(Value::as_array) else {
            continue;
        };
        for v in versions {
            if v.get("served").and_then(Value::as_bool) == Some(false) {
                continue;
            }
            if v.get("name").and_then(Value::as_str) != Some(version) {
                continue;
            }
            let path = if namespaced {
                format!("/apis/{group}/{version}/namespaces/{{namespace}}/{plural}")
            } else {
                format!("/apis/{group}/{version}/{plural}")
            };
            let item_path = format!("{path}/{{name}}");
            paths.insert(
                path,
                json!({
                    "get": group_operation(group, version, kind),
                    "post": group_operation(group, version, kind)
                }),
            );
            paths.insert(
                item_path,
                json!({
                    "get": group_operation(group, version, kind),
                    "put": group_operation(group, version, kind),
                    "patch": group_operation(group, version, kind),
                    "delete": group_operation(group, version, kind)
                }),
            );
            let def_key = format!("{reversed_group}.{version}.{kind}");
            let raw_schema = v.pointer("/schema/openAPIV3Schema");
            schemas.insert(
                def_key,
                build_crd_schema(
                    group,
                    version,
                    kind,
                    raw_schema,
                    "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta",
                    false,
                ),
            );
        }
    }
    if !schemas.is_empty() {
        schemas.insert(
            "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta".to_string(),
            object_meta_schema(),
        );
    }

    json!({
        "openapi": "3.0.0",
        "info": { "title": "Kubernetes", "version": crate::KUBERNETES_VERSION },
        "paths": paths,
        "components": { "schemas": schemas }
    })
}

/// Minimal valid Protobuf encoding of `openapi_v2.Document` (swagger="2.0", title="Kubernetes", version="v1.37.1").
pub const OPENAPI_V2_PROTO_BYTES: &[u8] = &[
    0x0a, 0x03, b'2', b'.', b'0', // 1: swagger = "2.0"
    0x12, 0x15, // 2: info (21 bytes)
    0x0a, 0x0a, b'K', b'u', b'b', b'e', b'r', b'n', b'e', b't', b'e',
    b's', // 1: title = "Kubernetes"
    0x12, 0x07, b'v', b'1', b'.', b'3', b'7', b'.', b'1', // 2: version = "v1.37.1"
];

/// `GET /openapi/v2`: Swagger 2.0 document publishing `ObjectMeta` and dynamic CRD schemas.
#[must_use]
pub fn v2_with_crds(crds: &[Value]) -> Value {
    let mut paths = serde_json::Map::new();
    let mut definitions = serde_json::Map::new();
    definitions.insert(
        "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta".to_string(),
        object_meta_schema(),
    );

    for crd in crds {
        let Some(spec) = crd.get("spec") else {
            continue;
        };
        let Some(group) = spec.get("group").and_then(Value::as_str) else {
            continue;
        };
        let kind = spec
            .pointer("/names/kind")
            .and_then(Value::as_str)
            .unwrap_or("CustomResource");
        let plural = spec
            .pointer("/names/plural")
            .and_then(Value::as_str)
            .unwrap_or("customresources");
        let namespaced = spec
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or("Namespaced")
            == "Namespaced";
        let reversed_group = reverse_group(group);
        let Some(versions) = spec.get("versions").and_then(Value::as_array) else {
            continue;
        };
        for v in versions {
            if v.get("served").and_then(Value::as_bool) == Some(false) {
                continue;
            }
            let Some(v_name) = v.get("name").and_then(Value::as_str) else {
                continue;
            };
            let def_key = format!("{reversed_group}.{v_name}.{kind}");
            let raw_schema = v.pointer("/schema/openAPIV3Schema");
            definitions.insert(
                def_key.clone(),
                build_crd_schema(
                    group,
                    v_name,
                    kind,
                    raw_schema,
                    "#/definitions/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta",
                    true,
                ),
            );
            let path = if namespaced {
                format!("/apis/{group}/{v_name}/namespaces/{{namespace}}/{plural}")
            } else {
                format!("/apis/{group}/{v_name}/{plural}")
            };
            let item_path = format!("{path}/{{name}}");
            let op = v2_group_operation(group, v_name, kind, &def_key);
            paths.insert(path, json!({ "get": op.clone(), "post": op.clone() }));
            paths.insert(
                item_path,
                json!({
                    "get": op.clone(),
                    "put": op.clone(),
                    "patch": op.clone(),
                    "delete": op
                }),
            );
        }
    }

    json!({
        "swagger": "2.0",
        "info": { "title": "Kubernetes", "version": crate::KUBERNETES_VERSION },
        "paths": paths,
        "definitions": definitions
    })
}

fn reverse_group(group: &str) -> String {
    group.split('.').rev().collect::<Vec<_>>().join(".")
}

fn object_meta_schema() -> Value {
    json!({
        "description": "Standard object's metadata. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata",
        "type": "object",
        "properties": {
            "annotations": {
                "type": "object",
                "additionalProperties": { "type": "string" },
                "description": "Annotations is an unstructured key value map stored with a resource."
            },
            "creationTimestamp": {
                "type": "string",
                "format": "date-time",
                "description": "CreationTimestamp is a timestamp representing the server time when this object was created."
            },
            "deletionGracePeriodSeconds": {
                "type": "integer",
                "format": "int64",
                "description": "Number of seconds allowed for this object to gracefully terminate."
            },
            "deletionTimestamp": {
                "type": "string",
                "format": "date-time",
                "description": "DeletionTimestamp is RFC 3339 date and time at which this resource will be deleted."
            },
            "finalizers": {
                "type": "array",
                "items": { "type": "string" }
            },
            "generateName": {
                "type": "string"
            },
            "generation": {
                "type": "integer",
                "format": "int64"
            },
            "labels": {
                "type": "object",
                "additionalProperties": { "type": "string" }
            },
            "name": {
                "type": "string",
                "description": "Name must be unique within a namespace."
            },
            "namespace": {
                "type": "string",
                "description": "Namespace defines the space within which each name must be unique."
            },
            "resourceVersion": {
                "type": "string"
            },
            "uid": {
                "type": "string"
            }
        }
    })
}

fn clean_crd_schema(schema: &mut Value) {
    let Some(obj) = schema.as_object_mut() else {
        return;
    };
    for key in [
        "nullable",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "uniqueItems",
        "x-kubernetes-embedded-resource",
        "x-kubernetes-int-or-string",
        "x-kubernetes-preserve-unknown-fields",
    ] {
        if obj.get(key).and_then(Value::as_bool) == Some(false) {
            obj.remove(key);
        }
    }
    if let Some(props) = obj.get_mut("properties").and_then(Value::as_object_mut) {
        for val in props.values_mut() {
            clean_crd_schema(val);
        }
    }
    if let Some(items) = obj.get_mut("items") {
        clean_crd_schema(items);
    }
    if let Some(add_props) = obj.get_mut("additionalProperties")
        && add_props.is_object()
    {
        clean_crd_schema(add_props);
    }
}

fn v2_transform_schema(schema: &mut Value) {
    let Some(obj) = schema.as_object_mut() else {
        return;
    };
    let preserve_unknown = obj
        .get("x-kubernetes-preserve-unknown-fields")
        .and_then(Value::as_bool)
        == Some(true);
    let has_props = obj
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|p| !p.is_empty());
    if preserve_unknown && !has_props {
        obj.remove("type");
    }
    obj.retain(|k, _| !k.starts_with("x-kubernetes-"));
    if let Some(props) = obj.get_mut("properties").and_then(Value::as_object_mut) {
        for val in props.values_mut() {
            v2_transform_schema(val);
        }
    }
    if let Some(items) = obj.get_mut("items") {
        v2_transform_schema(items);
    }
    if let Some(add_props) = obj.get_mut("additionalProperties")
        && add_props.is_object()
    {
        v2_transform_schema(add_props);
    }
}

fn build_crd_schema(
    group: &str,
    version: &str,
    kind: &str,
    raw_schema: Option<&Value>,
    meta_ref: &str,
    is_v2: bool,
) -> Value {
    let mut schema = raw_schema
        .cloned()
        .unwrap_or_else(|| json!({ "type": "object" }));
    clean_crd_schema(&mut schema);
    if is_v2 {
        v2_transform_schema(&mut schema);
    }
    if let Some(obj) = schema.as_object_mut() {
        let preserve_root = obj
            .get("x-kubernetes-preserve-unknown-fields")
            .and_then(Value::as_bool)
            == Some(true)
            && obj
                .get("properties")
                .and_then(Value::as_object)
                .is_none_or(serde_json::Map::is_empty);
        if !preserve_root {
            obj.insert("type".to_string(), json!("object"));
            let props = obj
                .entry("properties".to_string())
                .or_insert_with(|| json!({}));
            if let Some(props_obj) = props.as_object_mut() {
                props_obj
                    .entry("apiVersion".to_string())
                    .or_insert_with(|| {
                        json!({
                            "type": "string",
                            "description": "APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values."
                        })
                    });
                props_obj.entry("kind".to_string()).or_insert_with(|| {
                    json!({
                        "type": "string",
                        "description": "Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to."
                    })
                });
                props_obj.entry("metadata".to_string()).or_insert_with(|| {
                    json!({
                        "$ref": meta_ref,
                        "description": "Standard object's metadata. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata"
                    })
                });
            }
        }
        obj.insert(
            "x-kubernetes-group-version-kind".to_string(),
            json!([{ "group": group, "version": version, "kind": kind }]),
        );
    }
    schema
}

fn v2_group_operation(group: &str, version: &str, kind: &str, def_key: &str) -> Value {
    json!({
        "parameters": [
            {
                "name": "body",
                "in": "body",
                "required": true,
                "schema": { "$ref": format!("#/definitions/{def_key}") }
            },
            {
                "name": "fieldValidation",
                "in": "query",
                "type": "string",
                "uniqueItems": true
            },
            {
                "name": "dryRun",
                "in": "query",
                "type": "string",
                "uniqueItems": true
            }
        ],
        "responses": {
            "200": {
                "description": "OK",
                "schema": { "$ref": format!("#/definitions/{def_key}") }
            }
        },
        "x-kubernetes-group-version-kind": { "group": group, "version": version, "kind": kind }
    })
}

fn group_kinds(group: &str, version: &str) -> Vec<(&'static str, &'static str, bool)> {
    match (group, version) {
        ("apps", "v1") => vec![
            ("Deployment", "deployments", true),
            ("ReplicaSet", "replicasets", true),
            ("StatefulSet", "statefulsets", true),
            ("DaemonSet", "daemonsets", true),
            ("ControllerRevision", "controllerrevisions", true),
        ],
        ("batch", "v1") => vec![("Job", "jobs", true), ("CronJob", "cronjobs", true)],
        ("autoscaling", "v1" | "v2") => {
            vec![("HorizontalPodAutoscaler", "horizontalpodautoscalers", true)]
        },
        ("policy", "v1") => vec![("PodDisruptionBudget", "poddisruptionbudgets", true)],
        ("networking.k8s.io", "v1") => vec![
            ("NetworkPolicy", "networkpolicies", true),
            ("Ingress", "ingresses", true),
            ("IngressClass", "ingressclasses", false),
            ("IPAddress", "ipaddresses", false),
            ("ServiceCIDR", "servicecidrs", false),
        ],
        ("certificates.k8s.io", "v1") => vec![
            (
                "CertificateSigningRequest",
                "certificatesigningrequests",
                false,
            ),
            ("ClusterTrustBundle", "clustertrustbundles", false),
        ],
        ("scheduling.k8s.io", "v1") => vec![("PriorityClass", "priorityclasses", false)],
        ("node.k8s.io", "v1") => vec![("RuntimeClass", "runtimeclasses", false)],
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
            (
                "ValidatingAdmissionPolicy",
                "validatingadmissionpolicies",
                false,
            ),
            (
                "ValidatingAdmissionPolicyBinding",
                "validatingadmissionpolicybindings",
                false,
            ),
            (
                "MutatingAdmissionPolicy",
                "mutatingadmissionpolicies",
                false,
            ),
            (
                "MutatingAdmissionPolicyBinding",
                "mutatingadmissionpolicybindings",
                false,
            ),
        ],
        ("apiregistration.k8s.io", "v1") => vec![("APIService", "apiservices", false)],
        ("storage.k8s.io", "v1") => vec![
            ("StorageClass", "storageclasses", false),
            ("CSINode", "csinodes", false),
            ("CSIDriver", "csidrivers", false),
            ("CSIStorageCapacity", "csistoragecapacities", true),
            ("VolumeAttachment", "volumeattachments", false),
            ("VolumeAttributesClass", "volumeattributesclasses", false),
        ],
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
    use super::{
        CORE_HASH, OPENAPI_V2_PROTO_BYTES, STORAGE_HASH, v3_core, v3_index, v3_storage_v1,
    };
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

    #[test]
    fn openapi_v2_proto_bytes_structure() {
        assert_eq!(
            &OPENAPI_V2_PROTO_BYTES[..5],
            &[0x0a, 0x03, b'2', b'.', b'0']
        );
        assert_eq!(OPENAPI_V2_PROTO_BYTES[5], 0x12);
        let info_len = OPENAPI_V2_PROTO_BYTES[6] as usize;
        assert_eq!(info_len, 21);
        let info = &OPENAPI_V2_PROTO_BYTES[7..7 + info_len];
        assert_eq!(
            &info[..12],
            &[
                0x0a, 0x0a, b'K', b'u', b'b', b'e', b'r', b'n', b'e', b't', b'e', b's'
            ]
        );
        assert_eq!(&info[12..14], &[0x12, 0x07]);
        assert_eq!(&info[14..], crate::KUBERNETES_VERSION.as_bytes());
    }
}
