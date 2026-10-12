//! Bounded readiness probing for external CRI runtimes.
//!
//! Validates availability of the CRI `RuntimeService` and `ImageService` endpoints
//! over Unix domain sockets within configurable deadlines, detects provider engine
//! identities, and rejects unsupported runtime combinations.

use crate::client::connect_unix;
use crate::endpoint::RuntimeEndpoints;
use crate::provider::{ProviderInfo, detect_provider};
use crate::runtime::v1::image_service_client::ImageServiceClient;
use crate::runtime::v1::runtime_service_client::RuntimeServiceClient;
use crate::runtime::v1::{ListImagesRequest, VersionRequest};
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tonic::transport::Channel;

pub const DEFAULT_READINESS_TIMEOUT: Duration = Duration::from_mins(1);
pub const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_millis(500);

/// Errors occurring during CRI readiness probing.
#[derive(Debug)]
pub enum ReadinessError {
    TimedOut {
        endpoint: PathBuf,
        elapsed: Duration,
    },
    UnsupportedProvider {
        runtime_name: String,
        runtime_version: String,
    },
    RpcFailed {
        service: &'static str,
        status: tonic::Status,
    },
    ConnectFailed {
        endpoint: PathBuf,
        source: tonic::transport::Error,
    },
}

impl fmt::Display for ReadinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut { endpoint, elapsed } => {
                write!(
                    f,
                    "CRI readiness probe timed out after {}s on '{}'",
                    elapsed.as_secs(),
                    endpoint.display()
                )
            },
            Self::UnsupportedProvider {
                runtime_name,
                runtime_version,
            } => {
                write!(
                    f,
                    "unsupported external CRI provider '{runtime_name}' (version: {runtime_version}); only containerd and CRI-O are supported"
                )
            },
            Self::RpcFailed { service, status } => {
                write!(
                    f,
                    "CRI {service} RPC failed: {} ({})",
                    status.message(),
                    status.code()
                )
            },
            Self::ConnectFailed { endpoint, source } => {
                write!(
                    f,
                    "failed to connect to CRI endpoint '{}': {source}",
                    endpoint.display()
                )
            },
        }
    }
}

impl std::error::Error for ReadinessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RpcFailed { status, .. } => Some(status),
            Self::ConnectFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Issues a CRI `RuntimeService::Version` RPC and resolves provider details.
pub async fn check_runtime_version(channel: Channel) -> Result<ProviderInfo, tonic::Status> {
    let mut client = RuntimeServiceClient::new(channel);
    let req = tonic::Request::new(VersionRequest {
        version: String::new(),
    });
    let resp = client.version(req).await?.into_inner();
    let provider = detect_provider(&resp.runtime_name);
    Ok(ProviderInfo {
        provider,
        runtime_name: resp.runtime_name,
        runtime_version: resp.runtime_version,
        runtime_api_version: resp.runtime_api_version,
    })
}

/// Issues a CRI `ImageService::ListImages` RPC to verify image endpoint readiness.
pub async fn check_image_service(channel: Channel) -> Result<(), tonic::Status> {
    let mut client = ImageServiceClient::new(channel);
    let req = tonic::Request::new(ListImagesRequest { filter: None });
    client.list_images(req).await?;
    Ok(())
}

async fn attempt_probe(
    runtime_socket: &std::path::Path,
    image_socket: &std::path::Path,
    timeout: Duration,
) -> Result<ProviderInfo, ReadinessError> {
    let runtime_channel =
        connect_unix(runtime_socket)
            .await
            .map_err(|_| ReadinessError::TimedOut {
                endpoint: runtime_socket.to_path_buf(),
                elapsed: timeout,
            })?;
    let info = check_runtime_version(runtime_channel.clone())
        .await
        .map_err(|status| ReadinessError::RpcFailed {
            service: "RuntimeService",
            status,
        })?;

    if !info.provider.is_supported() {
        return Err(ReadinessError::UnsupportedProvider {
            runtime_name: info.runtime_name,
            runtime_version: info.runtime_version,
        });
    }

    let image_channel = if runtime_socket == image_socket {
        runtime_channel
    } else {
        connect_unix(image_socket)
            .await
            .map_err(|_| ReadinessError::TimedOut {
                endpoint: image_socket.to_path_buf(),
                elapsed: timeout,
            })?
    };
    check_image_service(image_channel)
        .await
        .map_err(|status| ReadinessError::RpcFailed {
            service: "ImageService",
            status,
        })?;

    Ok(info)
}

/// Probes external CRI runtime and image service endpoints with bounded retries.
pub async fn probe_cri_readiness(
    endpoints: &RuntimeEndpoints,
    timeout: Duration,
    retry_interval: Duration,
) -> Result<ProviderInfo, ReadinessError> {
    let runtime_socket = endpoints.runtime.path().to_path_buf();
    let image_socket = endpoints.image.path().to_path_buf();
    let deadline = Instant::now() + timeout;
    let mut last_error: Option<ReadinessError> = None;

    while Instant::now() < deadline {
        if !runtime_socket.exists() {
            last_error = Some(ReadinessError::TimedOut {
                endpoint: runtime_socket.clone(),
                elapsed: timeout,
            });
        } else if !image_socket.exists() {
            last_error = Some(ReadinessError::TimedOut {
                endpoint: image_socket.clone(),
                elapsed: timeout,
            });
        } else {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let attempt = attempt_probe(&runtime_socket, &image_socket, timeout);
            if let Ok(result) = tokio::time::timeout(remaining, attempt).await {
                match result {
                    Ok(info) => return Ok(info),
                    Err(ReadinessError::UnsupportedProvider {
                        runtime_name,
                        runtime_version,
                    }) => {
                        return Err(ReadinessError::UnsupportedProvider {
                            runtime_name,
                            runtime_version,
                        });
                    },
                    Err(err) => last_error = Some(err),
                }
            }
        }

        let sleep_duration = retry_interval.min(deadline.saturating_duration_since(Instant::now()));
        if sleep_duration.is_zero() {
            break;
        }
        tokio::time::sleep(sleep_duration).await;
    }

    Err(last_error.unwrap_or(ReadinessError::TimedOut {
        endpoint: runtime_socket,
        elapsed: timeout,
    }))
}
