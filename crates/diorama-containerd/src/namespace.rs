//! containerd namespace management.

use diorama_containerd_api::containerd::services::namespaces::v1::namespaces_client::NamespacesClient;
use diorama_containerd_api::containerd::services::namespaces::v1::{
    CreateNamespaceRequest, ListNamespacesRequest, Namespace,
};
use std::collections::BTreeMap;
use std::fmt;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;

pub const DEFAULT_K8S_NAMESPACE: &str = "k8s.io";

#[derive(Debug)]
pub enum NamespaceError {
    ListFailed(tonic::Status),
    CreateFailed(tonic::Status),
    InvalidMetadata(String),
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ListFailed(status) => write!(f, "failed to list containerd namespaces: {status}"),
            Self::CreateFailed(status) => {
                write!(f, "failed to create containerd namespace: {status}")
            },
            Self::InvalidMetadata(msg) => write!(f, "invalid namespace metadata: {msg}"),
        }
    }
}

impl std::error::Error for NamespaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ListFailed(status) | Self::CreateFailed(status) => Some(status),
            Self::InvalidMetadata(_) => None,
        }
    }
}

/// Attach containerd-namespace gRPC metadata to a request.
pub fn with_namespace<T>(message: T, namespace: &str) -> Result<Request<T>, NamespaceError> {
    let mut req = Request::new(message);
    let val = MetadataValue::try_from(namespace)
        .map_err(|e| NamespaceError::InvalidMetadata(e.to_string()))?;
    req.metadata_mut().insert("containerd-namespace", val);
    Ok(req)
}

/// Ensures that the specified namespace exists in containerd.
pub async fn ensure_k8s_namespace(channel: Channel, namespace: &str) -> Result<(), NamespaceError> {
    let mut client = NamespacesClient::new(channel);
    let list_req = Request::new(ListNamespacesRequest {
        filter: String::new(),
    });
    let response = client
        .list(list_req)
        .await
        .map_err(NamespaceError::ListFailed)?;

    let exists = response
        .into_inner()
        .namespaces
        .iter()
        .any(|ns| ns.name == namespace);

    if !exists {
        let create_req = Request::new(CreateNamespaceRequest {
            namespace: Some(Namespace {
                name: namespace.to_string(),
                labels: BTreeMap::new(),
            }),
        });
        client
            .create(create_req)
            .await
            .map_err(NamespaceError::CreateFailed)?;
    }

    Ok(())
}
