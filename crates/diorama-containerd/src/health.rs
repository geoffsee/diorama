//! Health and readiness probes for managed containerd runtime.

use crate::client::connect_unix;
use diorama_cri::runtime::v1::VersionRequest;
use diorama_cri::runtime::v1::runtime_service_client::RuntimeServiceClient;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::Instant;
use tonic::transport::Channel;

pub const DEFAULT_READINESS_TIMEOUT: Duration = Duration::from_mins(1);
pub const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeVersionInfo {
    pub version: String,
    pub runtime_name: String,
    pub runtime_version: String,
    pub runtime_api_version: String,
}

#[derive(Debug)]
pub enum HealthError {
    ConnectFailed {
        socket: PathBuf,
        source: tonic::transport::Error,
    },
    VersionCallFailed(tonic::Status),
    TimedOut {
        socket: PathBuf,
        elapsed: Duration,
    },
    SocketNotFound(PathBuf),
}

impl fmt::Display for HealthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectFailed { socket, source } => {
                write!(
                    f,
                    "failed to connect to socket {}: {source}",
                    socket.display()
                )
            },
            Self::VersionCallFailed(status) => {
                write!(f, "CRI runtime version call failed: {status}")
            },
            Self::TimedOut { socket, elapsed } => {
                write!(
                    f,
                    "containerd CRI health check timed out after {elapsed:?} on {}",
                    socket.display()
                )
            },
            Self::SocketNotFound(socket) => {
                write!(f, "containerd socket {} does not exist", socket.display())
            },
        }
    }
}

impl std::error::Error for HealthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ConnectFailed { source, .. } => Some(source),
            Self::VersionCallFailed(status) => Some(status),
            Self::TimedOut { .. } | Self::SocketNotFound(_) => None,
        }
    }
}

/// Probes CRI runtime version via an established gRPC channel.
pub async fn check_cri_version(channel: Channel) -> Result<RuntimeVersionInfo, HealthError> {
    let mut client = RuntimeServiceClient::new(channel);
    let request = tonic::Request::new(VersionRequest {
        version: "0.1.0".into(),
    });
    let response = client
        .version(request)
        .await
        .map_err(HealthError::VersionCallFailed)?;
    let body = response.into_inner();
    Ok(RuntimeVersionInfo {
        version: body.version,
        runtime_name: body.runtime_name,
        runtime_version: body.runtime_version,
        runtime_api_version: body.runtime_api_version,
    })
}

/// Probes containerd native version via an established gRPC channel.
pub async fn check_containerd_version(channel: Channel) -> Result<String, HealthError> {
    let mut client =
        diorama_containerd_api::containerd::services::version::v1::version_client::VersionClient::new(
            channel,
        );
    let request = tonic::Request::new(());
    let response = client
        .version(request)
        .await
        .map_err(HealthError::VersionCallFailed)?;
    Ok(response.into_inner().version)
}

/// Repeatedly probes the containerd socket until CRI readiness succeeds or `timeout` expires.
pub async fn probe_containerd_readiness(
    socket_path: impl AsRef<Path>,
    timeout: Duration,
    retry_interval: Duration,
) -> Result<(Channel, RuntimeVersionInfo), HealthError> {
    let socket = socket_path.as_ref().to_path_buf();
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        if socket.exists() {
            let attempt = async {
                let channel = connect_unix(&socket).await.ok()?;
                let info = check_cri_version(channel.clone()).await.ok()?;
                Some((channel, info))
            };
            if let Ok(Some(pair)) = tokio::time::timeout_at(deadline, attempt).await {
                return Ok(pair);
            }
        }
        tokio::time::sleep(retry_interval).await;
    }

    Err(HealthError::TimedOut {
        socket,
        elapsed: timeout,
    })
}
