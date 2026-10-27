//! Decode Kubernetes protobuf request bodies into the JSON objects the rest of
//! the apiserver already stores.
//!
//! `client-go` sends built-in types as `application/vnd.kubernetes.protobuf`.
//! The payload is `k8s\0` plus a `runtime.Unknown` whose `raw` field is the
//! generated protobuf for that kind. Field definitions come from the static
//! Kubernetes v1.37.1 schema table in `generated/k8s_proto_schema.rs`,
//! regenerated offline with `diorama-proto-schema`.

// Field numbers and zig-zag values are fixed-width protobuf integers.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::excessive_nesting,
    clippy::type_complexity,
    clippy::unnecessary_wraps,
    clippy::verbose_bit_mask
)]

use serde_json::{Map, Value, json};

use crate::error::ApiserverError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum WireKind {
    String,
    Bytes,
    Bool,
    Int32,
    Int64,
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Float,
    Double,
    Message,
    Enum,
}

#[derive(Clone, Copy, Debug)]
struct FieldDef {
    number: u32,
    name: &'static str,
    kind: WireKind,
    type_name: &'static str,
    repeated: bool,
    map_value: Option<WireKind>,
    map_value_type: &'static str,
}

impl FieldDef {
    const fn scalar(number: u32, name: &'static str, kind: WireKind) -> Self {
        Self {
            number,
            name,
            kind,
            type_name: "",
            repeated: false,
            map_value: None,
            map_value_type: "",
        }
    }

    const fn repeated_scalar(number: u32, name: &'static str, kind: WireKind) -> Self {
        Self {
            number,
            name,
            kind,
            type_name: "",
            repeated: true,
            map_value: None,
            map_value_type: "",
        }
    }

    const fn typed(
        number: u32,
        name: &'static str,
        kind: WireKind,
        type_name: &'static str,
    ) -> Self {
        Self {
            number,
            name,
            kind,
            type_name,
            repeated: false,
            map_value: None,
            map_value_type: "",
        }
    }

    const fn repeated_typed(
        number: u32,
        name: &'static str,
        kind: WireKind,
        type_name: &'static str,
    ) -> Self {
        Self {
            number,
            name,
            kind,
            type_name,
            repeated: true,
            map_value: None,
            map_value_type: "",
        }
    }

    const fn map(
        number: u32,
        name: &'static str,
        value_kind: WireKind,
        value_type: &'static str,
    ) -> Self {
        Self {
            number,
            name,
            kind: WireKind::Message,
            type_name: "",
            repeated: true,
            map_value: Some(value_kind),
            map_value_type: value_type,
        }
    }
}

include!("generated/k8s_proto_schema.rs");

static EXTRA_MESSAGES: &[(&str, &[FieldDef])] = &[
    (
        "k8s.io.api.apidiscovery.v2.APIGroupDiscovery",
        &[FieldDef::typed(
            1,
            "metadata",
            WireKind::Message,
            "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
        )],
    ),
    (
        "k8s.io.api.apidiscovery.v2.APIGroupDiscoveryList",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ListMeta",
            ),
            FieldDef::repeated_typed(
                2,
                "items",
                WireKind::Message,
                "k8s.io.api.apidiscovery.v2.APIGroupDiscovery",
            ),
        ],
    ),
    (
        "k8s.io.api.authentication.v1.BoundObjectReference",
        &[
            FieldDef::scalar(1, "kind", WireKind::String),
            FieldDef::scalar(2, "apiVersion", WireKind::String),
            FieldDef::scalar(3, "name", WireKind::String),
            FieldDef::scalar(4, "uid", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.authentication.v1.SelfSubjectReview",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "status",
                WireKind::Message,
                "k8s.io.api.authentication.v1.SelfSubjectReviewStatus",
            ),
        ],
    ),
    (
        "k8s.io.api.authentication.v1.SelfSubjectReviewStatus",
        &[FieldDef::typed(
            1,
            "userInfo",
            WireKind::Message,
            "k8s.io.api.authentication.v1.UserInfo",
        )],
    ),
    (
        "k8s.io.api.authentication.v1.TokenRequest",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.authentication.v1.TokenRequestSpec",
            ),
            FieldDef::typed(
                3,
                "status",
                WireKind::Message,
                "k8s.io.api.authentication.v1.TokenRequestStatus",
            ),
        ],
    ),
    (
        "k8s.io.api.authentication.v1.TokenRequestSpec",
        &[
            FieldDef::repeated_scalar(1, "audiences", WireKind::String),
            FieldDef::scalar(2, "expirationSeconds", WireKind::Int64),
            FieldDef::typed(
                3,
                "boundObjectRef",
                WireKind::Message,
                "k8s.io.api.authentication.v1.BoundObjectReference",
            ),
        ],
    ),
    (
        "k8s.io.api.authentication.v1.TokenRequestStatus",
        &[
            FieldDef::scalar(1, "token", WireKind::String),
            FieldDef::typed(
                2,
                "expirationTimestamp",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.Time",
            ),
        ],
    ),
    (
        "k8s.io.api.authentication.v1.TokenReview",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.authentication.v1.TokenReviewSpec",
            ),
            FieldDef::typed(
                3,
                "status",
                WireKind::Message,
                "k8s.io.api.authentication.v1.TokenReviewStatus",
            ),
        ],
    ),
    (
        "k8s.io.api.authentication.v1.TokenReviewSpec",
        &[
            FieldDef::scalar(1, "token", WireKind::String),
            FieldDef::repeated_scalar(2, "audiences", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.authentication.v1.TokenReviewStatus",
        &[
            FieldDef::scalar(1, "authenticated", WireKind::Bool),
            FieldDef::typed(
                2,
                "user",
                WireKind::Message,
                "k8s.io.api.authentication.v1.UserInfo",
            ),
            FieldDef::repeated_scalar(3, "audiences", WireKind::String),
            FieldDef::scalar(4, "error", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.authentication.v1.UserInfo",
        &[
            FieldDef::scalar(1, "username", WireKind::String),
            FieldDef::scalar(2, "uid", WireKind::String),
            FieldDef::repeated_scalar(3, "groups", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.LocalSubjectAccessReview",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.authorization.v1.SubjectAccessReviewSpec",
            ),
            FieldDef::typed(
                3,
                "status",
                WireKind::Message,
                "k8s.io.api.authorization.v1.SubjectAccessReviewStatus",
            ),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.NonResourceAttributes",
        &[
            FieldDef::scalar(1, "path", WireKind::String),
            FieldDef::scalar(2, "verb", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.NonResourceRule",
        &[
            FieldDef::repeated_scalar(1, "verbs", WireKind::String),
            FieldDef::repeated_scalar(2, "nonResourceURLs", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.ResourceAttributes",
        &[
            FieldDef::scalar(1, "namespace", WireKind::String),
            FieldDef::scalar(2, "verb", WireKind::String),
            FieldDef::scalar(3, "group", WireKind::String),
            FieldDef::scalar(4, "version", WireKind::String),
            FieldDef::scalar(5, "resource", WireKind::String),
            FieldDef::scalar(6, "subresource", WireKind::String),
            FieldDef::scalar(7, "name", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.ResourceRule",
        &[
            FieldDef::repeated_scalar(1, "verbs", WireKind::String),
            FieldDef::repeated_scalar(2, "apiGroups", WireKind::String),
            FieldDef::repeated_scalar(3, "resources", WireKind::String),
            FieldDef::repeated_scalar(4, "resourceNames", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.SelfSubjectAccessReview",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.authorization.v1.SelfSubjectAccessReviewSpec",
            ),
            FieldDef::typed(
                3,
                "status",
                WireKind::Message,
                "k8s.io.api.authorization.v1.SubjectAccessReviewStatus",
            ),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.SelfSubjectAccessReviewSpec",
        &[
            FieldDef::typed(
                1,
                "resourceAttributes",
                WireKind::Message,
                "k8s.io.api.authorization.v1.ResourceAttributes",
            ),
            FieldDef::typed(
                2,
                "nonResourceAttributes",
                WireKind::Message,
                "k8s.io.api.authorization.v1.NonResourceAttributes",
            ),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.SelfSubjectRulesReview",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.authorization.v1.SelfSubjectRulesReviewSpec",
            ),
            FieldDef::typed(
                3,
                "status",
                WireKind::Message,
                "k8s.io.api.authorization.v1.SubjectRulesReviewStatus",
            ),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.SelfSubjectRulesReviewSpec",
        &[FieldDef::scalar(1, "namespace", WireKind::String)],
    ),
    (
        "k8s.io.api.authorization.v1.SubjectAccessReview",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.authorization.v1.SubjectAccessReviewSpec",
            ),
            FieldDef::typed(
                3,
                "status",
                WireKind::Message,
                "k8s.io.api.authorization.v1.SubjectAccessReviewStatus",
            ),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.SubjectAccessReviewSpec",
        &[
            FieldDef::typed(
                1,
                "resourceAttributes",
                WireKind::Message,
                "k8s.io.api.authorization.v1.ResourceAttributes",
            ),
            FieldDef::typed(
                2,
                "nonResourceAttributes",
                WireKind::Message,
                "k8s.io.api.authorization.v1.NonResourceAttributes",
            ),
            FieldDef::scalar(3, "user", WireKind::String),
            FieldDef::repeated_scalar(4, "groups", WireKind::String),
            FieldDef::scalar(5, "uid", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.SubjectAccessReviewStatus",
        &[
            FieldDef::scalar(1, "allowed", WireKind::Bool),
            FieldDef::scalar(2, "denied", WireKind::Bool),
            FieldDef::scalar(3, "reason", WireKind::String),
            FieldDef::scalar(4, "evaluationError", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.authorization.v1.SubjectRulesReviewStatus",
        &[
            FieldDef::repeated_typed(
                1,
                "resourceRules",
                WireKind::Message,
                "k8s.io.api.authorization.v1.ResourceRule",
            ),
            FieldDef::repeated_typed(
                2,
                "nonResourceRules",
                WireKind::Message,
                "k8s.io.api.authorization.v1.NonResourceRule",
            ),
            FieldDef::scalar(3, "incomplete", WireKind::Bool),
            FieldDef::scalar(4, "evaluationError", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.certificates.v1alpha1.ClusterTrustBundle",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.certificates.v1alpha1.ClusterTrustBundleSpec",
            ),
        ],
    ),
    (
        "k8s.io.api.certificates.v1alpha1.ClusterTrustBundleList",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ListMeta",
            ),
            FieldDef::repeated_typed(
                2,
                "items",
                WireKind::Message,
                "k8s.io.api.certificates.v1alpha1.ClusterTrustBundle",
            ),
        ],
    ),
    (
        "k8s.io.api.certificates.v1alpha1.ClusterTrustBundleSpec",
        &[
            FieldDef::scalar(1, "signerName", WireKind::String),
            FieldDef::scalar(2, "trustBundle", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.certificates.v1alpha1.PodCertificateRequest",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.certificates.v1alpha1.PodCertificateRequestSpec",
            ),
            FieldDef::typed(
                3,
                "status",
                WireKind::Message,
                "k8s.io.api.certificates.v1alpha1.PodCertificateRequestStatus",
            ),
        ],
    ),
    (
        "k8s.io.api.certificates.v1alpha1.PodCertificateRequestList",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ListMeta",
            ),
            FieldDef::repeated_typed(
                2,
                "items",
                WireKind::Message,
                "k8s.io.api.certificates.v1alpha1.PodCertificateRequest",
            ),
        ],
    ),
    (
        "k8s.io.api.certificates.v1alpha1.PodCertificateRequestSpec",
        &[
            FieldDef::scalar(1, "serviceAccountName", WireKind::String),
            FieldDef::scalar(2, "serviceAccountUID", WireKind::String),
            FieldDef::scalar(3, "podName", WireKind::String),
            FieldDef::scalar(4, "podUID", WireKind::String),
            FieldDef::scalar(5, "nodeName", WireKind::String),
            FieldDef::scalar(6, "nodeUID", WireKind::String),
            FieldDef::scalar(7, "signerName", WireKind::String),
            FieldDef::scalar(8, "keyType", WireKind::String),
            FieldDef::scalar(9, "pkixPublicKey", WireKind::Bytes),
            FieldDef::scalar(10, "proofOfPossession", WireKind::Bytes),
            FieldDef::scalar(11, "maxExpirationSeconds", WireKind::Int64),
        ],
    ),
    (
        "k8s.io.api.certificates.v1alpha1.PodCertificateRequestStatus",
        &[FieldDef::scalar(1, "certificate", WireKind::Bytes)],
    ),
    (
        "k8s.io.api.certificates.v1beta1.ClusterTrustBundle",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.certificates.v1alpha1.ClusterTrustBundleSpec",
            ),
        ],
    ),
    (
        "k8s.io.api.certificates.v1beta1.ClusterTrustBundleList",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ListMeta",
            ),
            FieldDef::repeated_typed(
                2,
                "items",
                WireKind::Message,
                "k8s.io.api.certificates.v1beta1.ClusterTrustBundle",
            ),
        ],
    ),
    (
        "k8s.io.api.certificates.v1beta1.PodCertificateRequest",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.certificates.v1alpha1.PodCertificateRequestSpec",
            ),
            FieldDef::typed(
                3,
                "status",
                WireKind::Message,
                "k8s.io.api.certificates.v1alpha1.PodCertificateRequestStatus",
            ),
        ],
    ),
    (
        "k8s.io.api.certificates.v1beta1.PodCertificateRequestList",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ListMeta",
            ),
            FieldDef::repeated_typed(
                2,
                "items",
                WireKind::Message,
                "k8s.io.api.certificates.v1beta1.PodCertificateRequest",
            ),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.ExemptPriorityLevelConfiguration",
        &[
            FieldDef::scalar(1, "nominalConcurrencyShares", WireKind::Int32),
            FieldDef::scalar(2, "lendablePercent", WireKind::Int32),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.FlowDistinguisherMethod",
        &[FieldDef::scalar(1, "type", WireKind::String)],
    ),
    (
        "k8s.io.api.flowcontrol.v1.FlowSchema",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.FlowSchemaSpec",
            ),
            FieldDef::typed(
                3,
                "status",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.FlowSchemaStatus",
            ),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.FlowSchemaCondition",
        &[
            FieldDef::scalar(1, "type", WireKind::String),
            FieldDef::scalar(2, "status", WireKind::String),
            FieldDef::typed(
                3,
                "lastTransitionTime",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.Time",
            ),
            FieldDef::scalar(4, "reason", WireKind::String),
            FieldDef::scalar(5, "message", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.FlowSchemaList",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ListMeta",
            ),
            FieldDef::repeated_typed(
                2,
                "items",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.FlowSchema",
            ),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.FlowSchemaSpec",
        &[
            FieldDef::typed(
                1,
                "priorityLevelConfiguration",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.PriorityLevelConfigurationReference",
            ),
            FieldDef::scalar(2, "matchingPrecedence", WireKind::Int32),
            FieldDef::typed(
                3,
                "distinguisherMethod",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.FlowDistinguisherMethod",
            ),
            FieldDef::repeated_typed(
                4,
                "rules",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.PolicyRulesWithSubjects",
            ),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.FlowSchemaStatus",
        &[FieldDef::repeated_typed(
            1,
            "conditions",
            WireKind::Message,
            "k8s.io.api.flowcontrol.v1.FlowSchemaCondition",
        )],
    ),
    (
        "k8s.io.api.flowcontrol.v1.GroupSubject",
        &[FieldDef::scalar(1, "name", WireKind::String)],
    ),
    (
        "k8s.io.api.flowcontrol.v1.LimitResponse",
        &[
            FieldDef::scalar(1, "type", WireKind::String),
            FieldDef::typed(
                2,
                "queuing",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.QueuingConfiguration",
            ),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.LimitedPriorityLevelConfiguration",
        &[
            FieldDef::scalar(1, "nominalConcurrencyShares", WireKind::Int32),
            FieldDef::typed(
                2,
                "limitResponse",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.LimitResponse",
            ),
            FieldDef::scalar(3, "lendablePercent", WireKind::Int32),
            FieldDef::scalar(4, "borrowingLimitPercent", WireKind::Int32),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.NonResourcePolicyRule",
        &[
            FieldDef::repeated_scalar(1, "verbs", WireKind::String),
            FieldDef::repeated_scalar(2, "nonResourceURLs", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.PolicyRulesWithSubjects",
        &[
            FieldDef::repeated_typed(
                1,
                "subjects",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.Subject",
            ),
            FieldDef::repeated_typed(
                2,
                "resourceRules",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.ResourcePolicyRule",
            ),
            FieldDef::repeated_typed(
                3,
                "nonResourceRules",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.NonResourcePolicyRule",
            ),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.PriorityLevelConfiguration",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta",
            ),
            FieldDef::typed(
                2,
                "spec",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.PriorityLevelConfigurationSpec",
            ),
            FieldDef::typed(
                3,
                "status",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.PriorityLevelConfigurationStatus",
            ),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.PriorityLevelConfigurationCondition",
        &[
            FieldDef::scalar(1, "type", WireKind::String),
            FieldDef::scalar(2, "status", WireKind::String),
            FieldDef::typed(
                3,
                "lastTransitionTime",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.Time",
            ),
            FieldDef::scalar(4, "reason", WireKind::String),
            FieldDef::scalar(5, "message", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.PriorityLevelConfigurationList",
        &[
            FieldDef::typed(
                1,
                "metadata",
                WireKind::Message,
                "k8s.io.apimachinery.pkg.apis.meta.v1.ListMeta",
            ),
            FieldDef::repeated_typed(
                2,
                "items",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.PriorityLevelConfiguration",
            ),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.PriorityLevelConfigurationReference",
        &[FieldDef::scalar(1, "name", WireKind::String)],
    ),
    (
        "k8s.io.api.flowcontrol.v1.PriorityLevelConfigurationSpec",
        &[
            FieldDef::scalar(1, "type", WireKind::String),
            FieldDef::typed(
                2,
                "limited",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.LimitedPriorityLevelConfiguration",
            ),
            FieldDef::typed(
                3,
                "exempt",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.ExemptPriorityLevelConfiguration",
            ),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.PriorityLevelConfigurationStatus",
        &[FieldDef::repeated_typed(
            1,
            "conditions",
            WireKind::Message,
            "k8s.io.api.flowcontrol.v1.PriorityLevelConfigurationCondition",
        )],
    ),
    (
        "k8s.io.api.flowcontrol.v1.QueuingConfiguration",
        &[
            FieldDef::scalar(1, "queues", WireKind::Int32),
            FieldDef::scalar(2, "handSize", WireKind::Int32),
            FieldDef::scalar(3, "queueLengthLimit", WireKind::Int32),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.ResourcePolicyRule",
        &[
            FieldDef::repeated_scalar(1, "verbs", WireKind::String),
            FieldDef::repeated_scalar(2, "apiGroups", WireKind::String),
            FieldDef::repeated_scalar(3, "resources", WireKind::String),
            FieldDef::scalar(4, "clusterScope", WireKind::Bool),
            FieldDef::repeated_scalar(5, "namespaces", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.ServiceAccountSubject",
        &[
            FieldDef::scalar(1, "namespace", WireKind::String),
            FieldDef::scalar(2, "name", WireKind::String),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.Subject",
        &[
            FieldDef::scalar(1, "kind", WireKind::String),
            FieldDef::typed(
                2,
                "user",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.UserSubject",
            ),
            FieldDef::typed(
                3,
                "group",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.GroupSubject",
            ),
            FieldDef::typed(
                4,
                "serviceAccount",
                WireKind::Message,
                "k8s.io.api.flowcontrol.v1.ServiceAccountSubject",
            ),
        ],
    ),
    (
        "k8s.io.api.flowcontrol.v1.UserSubject",
        &[FieldDef::scalar(1, "name", WireKind::String)],
    ),
];

fn lookup_extra_message(name: &str) -> Option<&'static [FieldDef]> {
    EXTRA_MESSAGES
        .binary_search_by_key(&name, |(message, _)| *message)
        .ok()
        .map(|index| EXTRA_MESSAGES[index].1)
}

fn lookup_message(name: &str) -> Option<&'static [FieldDef]> {
    MESSAGES
        .binary_search_by_key(&name, |(message, _)| *message)
        .ok()
        .map(|index| MESSAGES[index].1)
        .or_else(|| lookup_extra_message(name))
}

fn lookup_field(fields: &'static [FieldDef], number: u32) -> Option<&'static FieldDef> {
    fields
        .binary_search_by_key(&number, |field| field.number)
        .ok()
        .map(|index| &fields[index])
}

fn lookup_enum(type_name: &str, value: i64) -> Option<&'static str> {
    let variants = ENUMS
        .binary_search_by_key(&type_name, |(name, _)| *name)
        .ok()
        .map(|index| ENUMS[index].1)?;
    variants
        .binary_search_by_key(&value, |(number, _)| *number)
        .ok()
        .map(|index| variants[index].1)
}

const MAX_RECURSION_DEPTH: usize = 64;

pub(crate) fn decode_k8s_protobuf(
    body: &[u8],
    group: &str,
    resource: &str,
) -> Result<Option<Value>, ApiserverError> {
    let payload = body
        .strip_prefix(b"k8s\x00")
        .ok_or_else(|| ApiserverError::BadRequest {
            message: "kubernetes protobuf body is missing the k8s prefix".to_string(),
        })?;
    let (type_meta, raw) = unknown_parts(payload)?;
    if raw.is_empty() {
        return Err(ApiserverError::BadRequest {
            message: "kubernetes protobuf body did not contain an object".to_string(),
        });
    }
    if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
        return Ok(Some(value));
    }
    let Some(message) = message_for(type_meta.as_ref(), group, resource) else {
        return Ok(None);
    };
    if lookup_message(&message).is_none() {
        return Ok(None);
    }
    decode_message(&message, &raw, 0).map(Some)
}

fn message_for(
    type_meta: Option<&(String, String)>,
    group: &str,
    resource: &str,
) -> Option<String> {
    if let Some((api_version, kind)) = type_meta
        && let Some(name) = message_for_gvk(api_version, kind)
    {
        return Some(name);
    }
    let kind = super::dispatch::kind_name(resource)?;
    let api_version = if group.is_empty() {
        "v1".to_string()
    } else {
        format!("{group}/v1")
    };
    message_for_gvk(&api_version, kind)
        .or_else(|| message_for_gvk("v1", kind))
        .or_else(|| message_for_gvk("apps/v1", kind))
}

fn message_for_gvk(api_version: &str, kind: &str) -> Option<String> {
    if kind == "DeleteOptions" {
        return Some("k8s.io.apimachinery.pkg.apis.meta.v1.DeleteOptions".to_string());
    }
    let (group, version) = api_version
        .split_once('/')
        .map_or(("", api_version), |(group, version)| (group, version));
    let package = match (group, version) {
        ("", "v1") => "k8s.io.api.core.v1",
        ("apps", "v1") => "k8s.io.api.apps.v1",
        ("batch", "v1") => "k8s.io.api.batch.v1",
        ("policy", "v1") => "k8s.io.api.policy.v1",
        ("autoscaling", "v1") => "k8s.io.api.autoscaling.v1",
        ("autoscaling", "v2") => "k8s.io.api.autoscaling.v2",
        ("networking.k8s.io", "v1") => "k8s.io.api.networking.v1",
        ("storage.k8s.io", "v1") => "k8s.io.api.storage.v1",
        ("certificates.k8s.io", "v1") => "k8s.io.api.certificates.v1",
        ("coordination.k8s.io", "v1") => "k8s.io.api.coordination.v1",
        ("discovery.k8s.io", "v1") => "k8s.io.api.discovery.v1",
        ("rbac.authorization.k8s.io", "v1") => "k8s.io.api.rbac.v1",
        ("admissionregistration.k8s.io", "v1") => "k8s.io.api.admissionregistration.v1",
        ("events.k8s.io", "v1") => "k8s.io.api.events.v1",
        ("node.k8s.io", "v1") => "k8s.io.api.node.v1",
        ("scheduling.k8s.io", "v1") => "k8s.io.api.scheduling.v1",
        ("apiextensions.k8s.io", "v1") => {
            "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1"
        },
        ("apiregistration.k8s.io", "v1") => "k8s.io.kube_aggregator.pkg.apis.apiregistration.v1",
        ("certificates.k8s.io", "v1alpha1") => "k8s.io.api.certificates.v1alpha1",
        ("certificates.k8s.io", "v1beta1") => "k8s.io.api.certificates.v1beta1",
        ("authentication.k8s.io", "v1") => "k8s.io.api.authentication.v1",
        ("authorization.k8s.io", "v1") => "k8s.io.api.authorization.v1",
        ("flowcontrol.apiserver.k8s.io", "v1") => "k8s.io.api.flowcontrol.v1",
        ("apidiscovery.k8s.io", "v2" | "v2beta1") => "k8s.io.api.apidiscovery.v2",
        ("resource.k8s.io", "v1") => "k8s.io.api.resource.v1",
        ("storagemigration.k8s.io", "v1" | "v1alpha1") => "k8s.io.api.storagemigration.v1",
        _ => return None,
    };
    Some(format!("{package}.{kind}"))
}

fn unknown_parts(payload: &[u8]) -> Result<(Option<(String, String)>, Vec<u8>), ApiserverError> {
    let mut input = payload;
    let mut raw = None;
    let mut type_meta = None;
    while !input.is_empty() {
        let (key, rest) = read_varint(input)?;
        input = rest;
        let field = key >> 3;
        let wire = key & 0x07;
        match wire {
            2 => {
                let (chunk, rest) = read_len(input)?;
                input = rest;
                if field == 1 {
                    type_meta = decode_type_meta(chunk);
                } else if field == 2 {
                    raw = Some(chunk.to_vec());
                }
            },
            0 => {
                let (_, rest) = read_varint(input)?;
                input = rest;
            },
            1 => {
                if input.len() < 8 {
                    return Err(truncated());
                }
                input = &input[8..];
            },
            5 => {
                if input.len() < 4 {
                    return Err(truncated());
                }
                input = &input[4..];
            },
            _ => {
                return Err(ApiserverError::BadRequest {
                    message: format!("unsupported kubernetes protobuf wire type {wire}"),
                });
            },
        }
    }
    Ok((
        type_meta,
        raw.ok_or_else(|| ApiserverError::BadRequest {
            message: "kubernetes protobuf body has no raw object".to_string(),
        })?,
    ))
}

fn decode_type_meta(bytes: &[u8]) -> Option<(String, String)> {
    let mut input = bytes;
    let mut api_version = None;
    let mut kind = None;
    while !input.is_empty() {
        let (key, rest) = read_varint(input).ok()?;
        input = rest;
        if key & 0x07 != 2 {
            return None;
        }
        let (chunk, rest) = read_len(input).ok()?;
        input = rest;
        let text = std::str::from_utf8(chunk).ok()?.to_string();
        match key >> 3 {
            1 => api_version = Some(text),
            2 => kind = Some(text),
            _ => {},
        }
    }
    Some((api_version?, kind?))
}

fn decode_message(name: &str, bytes: &[u8], depth: usize) -> Result<Value, ApiserverError> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(ApiserverError::BadRequest {
            message: "kubernetes protobuf exceeds maximum nesting depth".to_string(),
        });
    }
    if let Some(value) = decode_special(name, bytes)? {
        return Ok(value);
    }
    let fields = lookup_message(name).unwrap_or(&[]);
    let mut object = Map::new();
    let mut input = bytes;
    while !input.is_empty() {
        let (key, rest) = read_varint(input)?;
        input = rest;
        let number = u32::try_from(key >> 3).unwrap_or(0);
        let wire = key & 0x07;
        let Some(field) = lookup_field(fields, number) else {
            input = skip_wire(input, wire)?;
            continue;
        };
        if wire == 2 && field.repeated && field.map_value.is_none() && is_packed_scalar(field.kind)
        {
            let (chunk, rest) = read_len(input)?;
            input = rest;
            for item in decode_packed(field, chunk)? {
                store_field(name, &mut object, field, item);
            }
            continue;
        }
        let value = match wire {
            0 => {
                let (raw, rest) = read_varint(input)?;
                input = rest;
                decode_varint(field, raw)
            },
            1 => {
                if input.len() < 8 {
                    return Err(truncated());
                }
                let raw = u64::from_le_bytes(input[..8].try_into().unwrap_or([0; 8]));
                input = &input[8..];
                if field.kind == WireKind::Double {
                    json!(f64::from_bits(raw))
                } else {
                    json!(raw)
                }
            },
            5 => {
                if input.len() < 4 {
                    return Err(truncated());
                }
                let raw = u32::from_le_bytes(input[..4].try_into().unwrap_or([0; 4]));
                input = &input[4..];
                if field.kind == WireKind::Float {
                    json!(f32::from_bits(raw))
                } else {
                    json!(raw)
                }
            },
            2 => {
                let (chunk, rest) = read_len(input)?;
                input = rest;
                decode_length(field, chunk, depth + 1)?
            },
            _ => {
                input = skip_wire(input, wire)?;
                continue;
            },
        };
        store_field(name, &mut object, field, value);
    }
    if let Some(val) = unwrap_props_union(name, &mut object) {
        return Ok(val);
    }
    Ok(Value::Object(object))
}

fn unwrap_props_union(name: &str, object: &mut Map<String, Value>) -> Option<Value> {
    match name {
        "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaPropsOrArray" => {
            if let Some(arr) = object.remove("jSONSchemas") {
                return Some(arr);
            }
            if let Some(schema) = object.remove("schema")
                && schema.as_object().is_some_and(|m| !m.is_empty())
            {
                return Some(schema);
            }
            Some(Value::Null)
        },
        "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaPropsOrBool" => {
            if let Some(schema) = object.remove("schema")
                && schema.as_object().is_some_and(|m| !m.is_empty())
            {
                return Some(schema);
            }
            Some(object.remove("allows").unwrap_or(Value::Bool(false)))
        },
        "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaPropsOrStringArray" => {
            if let Some(arr) = object.remove("property") {
                return Some(arr);
            }
            if let Some(schema) = object.remove("schema")
                && schema.as_object().is_some_and(|m| !m.is_empty())
            {
                return Some(schema);
            }
            Some(Value::Null)
        },
        _ => None,
    }
}

const fn is_packed_scalar(kind: WireKind) -> bool {
    matches!(
        kind,
        WireKind::Bool
            | WireKind::Int32
            | WireKind::Int64
            | WireKind::Uint32
            | WireKind::Uint64
            | WireKind::Sint32
            | WireKind::Sint64
            | WireKind::Float
            | WireKind::Double
            | WireKind::Enum
    )
}

fn decode_packed(field: &FieldDef, mut input: &[u8]) -> Result<Vec<Value>, ApiserverError> {
    let mut values = Vec::new();
    while !input.is_empty() {
        let value = match field.kind {
            WireKind::Double => {
                if input.len() < 8 {
                    return Err(truncated());
                }
                let raw = u64::from_le_bytes(input[..8].try_into().unwrap_or([0; 8]));
                input = &input[8..];
                json!(f64::from_bits(raw))
            },
            WireKind::Float => {
                if input.len() < 4 {
                    return Err(truncated());
                }
                let raw = u32::from_le_bytes(input[..4].try_into().unwrap_or([0; 4]));
                input = &input[4..];
                json!(f32::from_bits(raw))
            },
            _ => {
                let (raw, rest) = read_varint(input)?;
                input = rest;
                decode_varint(field, raw)
            },
        };
        values.push(value);
    }
    Ok(values)
}

fn decode_special(name: &str, bytes: &[u8]) -> Result<Option<Value>, ApiserverError> {
    match name {
        "k8s.io.apimachinery.pkg.api.resource.Quantity"
        | "k8s.io.apimachinery.pkg.api.resource.QuantityValue" => {
            Ok(Some(string_field(bytes, 1).unwrap_or_else(|| json!(""))))
        },
        "k8s.io.apimachinery.pkg.apis.meta.v1.Time"
        | "k8s.io.apimachinery.pkg.apis.meta.v1.Timestamp" => {
            let seconds_opt = varint_field(bytes, 1);
            let nanos_opt = varint_field(bytes, 2);
            if seconds_opt.is_none() && nanos_opt.is_none() {
                return Ok(Some(Value::Null));
            }
            let seconds = seconds_opt.unwrap_or(0) as i64;
            let nanos = nanos_opt.unwrap_or(0) as i32;
            Ok(Some(json!(rfc3339(seconds, nanos))))
        },
        "k8s.io.apimachinery.pkg.apis.meta.v1.MicroTime" => {
            let seconds_opt = varint_field(bytes, 1);
            let nanos_opt = varint_field(bytes, 2);
            if seconds_opt.is_none() && nanos_opt.is_none() {
                return Ok(Some(Value::Null));
            }
            let seconds = seconds_opt.unwrap_or(0) as i64;
            let nanos = nanos_opt.unwrap_or(0) as i32;
            Ok(Some(json!(rfc3339_micro(seconds, nanos))))
        },
        "k8s.io.apimachinery.pkg.util.intstr.IntOrString" => {
            let kind = varint_field(bytes, 1);
            let text = string_field(bytes, 3);
            if kind == Some(1) {
                return Ok(Some(text.unwrap_or_else(|| json!(""))));
            }
            if let Some(Value::String(value)) = text
                && !value.is_empty()
            {
                return Ok(Some(Value::String(value)));
            }
            let int_val = varint_field(bytes, 2).unwrap_or(0) as i32;
            Ok(Some(json!(int_val)))
        },
        "k8s.io.apimachinery.pkg.runtime.RawExtension" => {
            let raw = bytes_field(bytes, 1).unwrap_or_default();
            if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
                return Ok(Some(value));
            }
            Ok(Some(json!({})))
        },
        "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSON"
        | "k8s.io.apimachinery.pkg.apis.meta.v1.FieldsV1" => {
            let raw = bytes_field(bytes, 1).unwrap_or_default();
            if raw.is_empty() {
                return Ok(Some(Value::Null));
            }
            if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
                return Ok(Some(value));
            }
            Ok(Some(Value::Null))
        },
        _ => Ok(None),
    }
}

fn decode_varint(field: &FieldDef, raw: u64) -> Value {
    match field.kind {
        WireKind::Bool => json!(raw != 0),
        WireKind::Int32 | WireKind::Int64 | WireKind::Uint32 | WireKind::Uint64 => {
            json!(raw as i64)
        },
        WireKind::Sint32 | WireKind::Sint64 => json!(zigzag(raw)),
        WireKind::Enum => lookup_enum(field.type_name, raw as i64).map_or_else(
            || json!(raw as i64),
            |label| Value::String(label.to_string()),
        ),
        _ => json!(raw as i64),
    }
}

fn decode_length(field: &FieldDef, chunk: &[u8], depth: usize) -> Result<Value, ApiserverError> {
    if field.map_value.is_some() {
        return decode_map_entry(field, chunk, depth);
    }
    match field.kind {
        WireKind::String => Ok(Value::String(String::from_utf8_lossy(chunk).into_owned())),
        WireKind::Bytes => Ok(Value::String(base64(chunk))),
        WireKind::Message => decode_message(field.type_name, chunk, depth),
        _ => Ok(json!(String::from_utf8_lossy(chunk))),
    }
}

fn decode_map_entry(field: &FieldDef, chunk: &[u8], depth: usize) -> Result<Value, ApiserverError> {
    let mut input = chunk;
    let mut key = String::new();
    let mut value = Value::Null;
    while !input.is_empty() {
        let (tag, rest) = read_varint(input)?;
        input = rest;
        let number = tag >> 3;
        let wire = tag & 0x07;
        if number == 1 && wire == 2 {
            let (bytes, rest) = read_len(input)?;
            input = rest;
            key = String::from_utf8_lossy(bytes).into_owned();
        } else if number == 2 {
            value = match wire {
                2 => {
                    let (bytes, rest) = read_len(input)?;
                    input = rest;
                    match field.map_value {
                        Some(WireKind::String) => {
                            Value::String(String::from_utf8_lossy(bytes).into_owned())
                        },
                        Some(WireKind::Bytes) => Value::String(base64(bytes)),
                        Some(WireKind::Message) | None => {
                            decode_message(field.map_value_type, bytes, depth)?
                        },
                        Some(_) => json!(String::from_utf8_lossy(bytes)),
                    }
                },
                0 => {
                    let (raw, rest) = read_varint(input)?;
                    input = rest;
                    json!(raw as i64)
                },
                _ => {
                    input = skip_wire(input, wire)?;
                    Value::Null
                },
            };
        } else {
            input = skip_wire(input, wire)?;
        }
    }
    Ok(json!({ "key": key, "value": value }))
}

fn is_inline_field(name: &str, type_name: &str) -> bool {
    matches!(
        (name, type_name),
        ("volumeSource", "k8s.io.api.core.v1.VolumeSource")
            | (
                "persistentVolumeSource",
                "k8s.io.api.core.v1.PersistentVolumeSource"
            )
            | ("handler", "k8s.io.api.core.v1.ProbeHandler")
            | (
                "localObjectReference",
                "k8s.io.api.core.v1.LocalObjectReference"
            )
            | (
                "ephemeralContainerCommon",
                "k8s.io.api.core.v1.EphemeralContainerCommon"
            )
            | (
                "ingressRuleValue",
                "k8s.io.api.networking.v1.IngressRuleValue"
            )
            | (
                "ruleWithOperations",
                "k8s.io.api.admissionregistration.v1.RuleWithOperations"
            )
            | ("rule", "k8s.io.api.admissionregistration.v1.Rule")
            | ("typeMeta", "k8s.io.apimachinery.pkg.runtime.TypeMeta")
    )
}

fn json_field_name<'a>(parent_message: &str, field_name: &'a str) -> &'a str {
    match field_name {
        "Webhooks" => "webhooks",
        "Expression" => "expression",
        "Name" => "name",
        "Raw" => "raw",
        _ if parent_message
            == "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps" =>
        {
            match field_name {
                "schema" => "$schema",
                "ref" => "$ref",
                "xKubernetesPreserveUnknownFields" => "x-kubernetes-preserve-unknown-fields",
                "xKubernetesEmbeddedResource" => "x-kubernetes-embedded-resource",
                "xKubernetesIntOrString" => "x-kubernetes-int-or-string",
                "xKubernetesListMapKeys" => "x-kubernetes-list-map-keys",
                "xKubernetesListType" => "x-kubernetes-list-type",
                "xKubernetesMapType" => "x-kubernetes-map-type",
                "xKubernetesValidations" => "x-kubernetes-validations",
                _ => field_name,
            }
        },
        _ => field_name,
    }
}

fn store_field(
    parent_message: &str,
    object: &mut Map<String, Value>,
    field: &FieldDef,
    value: Value,
) {
    let key_name = json_field_name(parent_message, field.name);
    if field.map_value.is_some() {
        let Value::Object(entry) = value else {
            return;
        };
        let key = entry
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mapped = entry.get("value").cloned().unwrap_or(Value::Null);
        if mapped.is_null() {
            return;
        }
        let map = object
            .entry(key_name.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(map) = map.as_object_mut() {
            map.insert(key, mapped);
        }
        return;
    }
    if field.repeated {
        let list = object
            .entry(key_name.to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Some(list) = list.as_array_mut() {
            list.push(value);
        }
        return;
    }
    if value.is_null() {
        return;
    }
    if field.kind == WireKind::String && value.as_str().is_some_and(str::is_empty) {
        return;
    }
    if is_inline_field(field.name, field.type_name)
        && let Value::Object(inner) = value
    {
        for (k, v) in inner {
            object.insert(k, v);
        }
        return;
    }
    object.insert(key_name.to_string(), value);
}

fn string_field(bytes: &[u8], number: u64) -> Option<Value> {
    let mut input = bytes;
    while !input.is_empty() {
        let (key, rest) = read_varint(input).ok()?;
        input = rest;
        if key & 0x07 == 2 && key >> 3 == number {
            let (chunk, _) = read_len(input).ok()?;
            return Some(Value::String(String::from_utf8_lossy(chunk).into_owned()));
        }
        input = skip_wire(input, key & 0x07).ok()?;
    }
    None
}

fn bytes_field(bytes: &[u8], number: u64) -> Option<Vec<u8>> {
    let mut input = bytes;
    while !input.is_empty() {
        let (key, rest) = read_varint(input).ok()?;
        input = rest;
        if key & 0x07 == 2 && key >> 3 == number {
            let (chunk, _) = read_len(input).ok()?;
            return Some(chunk.to_vec());
        }
        input = skip_wire(input, key & 0x07).ok()?;
    }
    None
}

fn varint_field(bytes: &[u8], number: u64) -> Option<u64> {
    let mut input = bytes;
    while !input.is_empty() {
        let (key, rest) = read_varint(input).ok()?;
        input = rest;
        if key & 0x07 == 0 && key >> 3 == number {
            let (value, _) = read_varint(input).ok()?;
            return Some(value);
        }
        input = skip_wire(input, key & 0x07).ok()?;
    }
    None
}

fn zigzag(raw: u64) -> i64 {
    ((raw >> 1) as i64) ^ -((raw & 1) as i64)
}

fn read_varint(input: &[u8]) -> Result<(u64, &[u8]), ApiserverError> {
    let mut value = 0u64;
    let mut shift = 0;
    for (index, byte) in input.iter().enumerate() {
        if shift >= 64 {
            break;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, &input[index + 1..]));
        }
        shift += 7;
    }
    Err(ApiserverError::BadRequest {
        message: "kubernetes protobuf varint is truncated".to_string(),
    })
}

fn read_len(input: &[u8]) -> Result<(&[u8], &[u8]), ApiserverError> {
    let (len, rest) = read_varint(input)?;
    let len = usize::try_from(len).map_err(|_| truncated())?;
    if rest.len() < len {
        return Err(truncated());
    }
    Ok(rest.split_at(len))
}

fn skip_wire(input: &[u8], wire: u64) -> Result<&[u8], ApiserverError> {
    match wire {
        0 => {
            let (_, rest) = read_varint(input)?;
            Ok(rest)
        },
        1 => {
            if input.len() < 8 {
                return Err(truncated());
            }
            Ok(&input[8..])
        },
        2 => {
            let (_, rest) = read_len(input)?;
            Ok(rest)
        },
        5 => {
            if input.len() < 4 {
                return Err(truncated());
            }
            Ok(&input[4..])
        },
        _ => Err(ApiserverError::BadRequest {
            message: format!("unsupported kubernetes object wire type {wire}"),
        }),
    }
}

fn truncated() -> ApiserverError {
    ApiserverError::BadRequest {
        message: "kubernetes protobuf body is truncated".to_string(),
    }
}

fn rfc3339(seconds: i64, nanos: i32) -> String {
    let days = seconds.div_euclid(86_400);
    let tod = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    if nanos > 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }
}

fn rfc3339_micro(seconds: i64, nanos: i32) -> String {
    let days = seconds.div_euclid(86_400);
    let tod = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    let micros = nanos.max(0).rem_euclid(1_000_000_000) / 1_000;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z")
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year as i32, month as u32, day as u32)
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let n = (u32::from(bytes[index]) << 16)
            | (u32::from(bytes[index + 1]) << 8)
            | u32::from(bytes[index + 2]);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        index += 3;
    }
    if bytes.len() - index == 1 {
        let n = u32::from(bytes[index]) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if bytes.len() - index == 2 {
        let n = (u32::from(bytes[index]) << 16) | (u32::from(bytes[index + 1]) << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{MAX_RECURSION_DEPTH, decode_k8s_protobuf, decode_message};

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn length_delimited(field: u64, bytes: &[u8]) -> Vec<u8> {
        let mut out = varint((field << 3) | 2);
        out.extend(varint(bytes.len() as u64));
        out.extend(bytes);
        out
    }

    fn string_field(field: u64, text: &str) -> Vec<u8> {
        length_delimited(field, text.as_bytes())
    }

    fn wrap(kind: &str, raw: &[u8]) -> Vec<u8> {
        let mut type_meta = string_field(1, "v1");
        type_meta.extend(string_field(2, kind));
        let mut unknown = length_delimited(1, &type_meta);
        unknown.extend(length_delimited(2, raw));
        let mut body = b"k8s\x00".to_vec();
        body.extend(unknown);
        body
    }

    #[test]
    fn protobuf_service_keeps_the_headless_spec() {
        let metadata = string_field(1, "test");
        let mut spec = string_field(3, "None");
        let mut port = string_field(1, "http");
        port.extend(varint(3 << 3));
        port.extend(varint(80));
        spec.extend(length_delimited(1, &port));
        let mut service = length_delimited(1, &metadata);
        service.extend(length_delimited(2, &spec));
        let decoded = decode_k8s_protobuf(&wrap("Service", &service), "", "services")
            .expect("decode")
            .expect("service schema");
        assert_eq!(decoded["metadata"]["name"], "test");
        assert_eq!(decoded["spec"]["clusterIP"], "None");
        assert_eq!(decoded["spec"]["ports"][0]["port"], 80);
        assert_eq!(decoded["spec"]["ports"][0]["name"], "http");
    }

    #[test]
    fn protobuf_cronjob_keeps_suspend() {
        let metadata = string_field(1, "suspended");
        let mut spec = string_field(1, "* * * * *");
        spec.extend(varint(4 << 3));
        spec.extend(varint(1));
        let mut cronjob = length_delimited(1, &metadata);
        cronjob.extend(length_delimited(2, &spec));
        let mut type_meta = string_field(1, "batch/v1");
        type_meta.extend(string_field(2, "CronJob"));
        let mut unknown = length_delimited(1, &type_meta);
        unknown.extend(length_delimited(2, &cronjob));
        let mut body = b"k8s\x00".to_vec();
        body.extend(unknown);
        let decoded = decode_k8s_protobuf(&body, "batch", "cronjobs")
            .expect("decode")
            .expect("cronjob schema");
        assert_eq!(decoded["spec"]["suspend"], true);
        assert_eq!(decoded["spec"]["schedule"], "* * * * *");
    }

    #[test]
    fn protobuf_cluster_trust_bundle_decodes_v1_37_fields() {
        let metadata = string_field(1, "example-bundle");
        let mut spec = string_field(1, "example.com/signer");
        spec.extend(string_field(2, "-----BEGIN CERTIFICATE-----\n"));
        let mut bundle = length_delimited(1, &metadata);
        bundle.extend(length_delimited(2, &spec));
        let mut type_meta = string_field(1, "certificates.k8s.io/v1");
        type_meta.extend(string_field(2, "ClusterTrustBundle"));
        let mut unknown = length_delimited(1, &type_meta);
        unknown.extend(length_delimited(2, &bundle));
        let mut body = b"k8s\x00".to_vec();
        body.extend(unknown);
        let decoded = decode_k8s_protobuf(&body, "certificates.k8s.io", "clustertrustbundles")
            .expect("decode")
            .expect("clustertrustbundle schema");
        assert_eq!(decoded["metadata"]["name"], "example-bundle");
        assert_eq!(decoded["spec"]["signerName"], "example.com/signer");
        assert_eq!(
            decoded["spec"]["trustBundle"],
            "-----BEGIN CERTIFICATE-----\n"
        );
    }

    #[test]
    fn protobuf_int_or_string_preserves_empty_string_when_type_is_string() {
        let metadata = string_field(1, "test-svc");
        let mut target_port = varint(1 << 3);
        target_port.extend(varint(1)); // type = 1 (string)
        let mut port = string_field(1, "http");
        port.extend(varint(3 << 3));
        port.extend(varint(80));
        port.extend(length_delimited(4, &target_port));
        let spec = length_delimited(1, &port);
        let mut service = length_delimited(1, &metadata);
        service.extend(length_delimited(2, &spec));
        let decoded = decode_k8s_protobuf(&wrap("Service", &service), "", "services")
            .expect("decode")
            .expect("service schema");
        assert_eq!(decoded["spec"]["ports"][0]["targetPort"], "");
    }

    #[test]
    fn protobuf_packed_repeated_scalars_decode() {
        let mut packed = varint(1000);
        packed.extend(varint(2000));
        let security_context = length_delimited(4, &packed); // PodSecurityContext.supplementalGroups = field 4
        let spec = length_delimited(14, &security_context); // PodSpec.securityContext = field 14
        let mut pod = length_delimited(1, &string_field(1, "packed-pod"));
        pod.extend(length_delimited(2, &spec));
        let decoded = decode_k8s_protobuf(&wrap("Pod", &pod), "", "pods")
            .expect("decode")
            .expect("pod schema");
        assert_eq!(
            decoded["spec"]["securityContext"]["supplementalGroups"],
            serde_json::json!([1000, 2000])
        );
    }

    #[test]
    fn protobuf_rejects_excessive_nesting_depth() {
        // JSONSchemaProps.not (field 28) is self-referential.
        let mut nested = string_field(1, "leaf");
        for _ in 0..(MAX_RECURSION_DEPTH + 4) {
            nested = length_delimited(28, &nested);
        }
        let err = decode_message(
            "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.JSONSchemaProps",
            &nested,
            0,
        )
        .expect_err("deep nesting must be rejected");
        assert!(err.to_string().contains("maximum nesting depth"));
    }

    #[test]
    fn protobuf_pre_1970_microtime_decodes() {
        use super::decode_special;
        let sec: i64 = -2_208_988_800;
        let mut msg = varint(1 << 3);
        msg.extend(varint(sec as u64));
        let decoded = decode_special("k8s.io.apimachinery.pkg.apis.meta.v1.MicroTime", &msg)
            .expect("decode")
            .expect("some value");
        assert_eq!(decoded, serde_json::json!("1900-01-01T00:00:00.000000Z"));
    }
}
