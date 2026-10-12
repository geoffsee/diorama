//! CRI client abstraction for pod sandbox and container workload execution.
//!
//! Provides typed operations against external host-managed containerd and CRI-O runtimes
//! using host-supplied images, network plugins, and runtime configurations.

use crate::cgroup::{ResolvedCgroupDriver, negotiate_cgroup_driver};
use crate::client::connect_unix;
use crate::consumer::NegotiatedRuntime;
use crate::endpoint::RuntimeEndpoints;
use crate::readiness::{ReadinessError, check_image_service, check_runtime_version};
use crate::runtime::v1::image_service_client::ImageServiceClient;
use crate::runtime::v1::runtime_service_client::RuntimeServiceClient;
use crate::runtime::v1::{
    AuthConfig, Container, ContainerFilter, ContainerStatus, ContainerStatusRequest,
    CreateContainerRequest, ExecSyncRequest, ExecSyncResponse, Image, ImageSpec,
    ImageStatusRequest, ListContainersRequest, ListImagesRequest, ListPodSandboxRequest,
    PodSandbox, PodSandboxConfig, PodSandboxFilter, PodSandboxStatus, PodSandboxStatusRequest,
    PullImageRequest, RemoveContainerRequest, RemoveImageRequest, RemovePodSandboxRequest,
    RunPodSandboxRequest, StartContainerRequest, StopContainerRequest, StopPodSandboxRequest,
    VersionRequest, VersionResponse,
};
use std::collections::BTreeMap;
use tonic::transport::Channel;

/// CRI client connecting to runtime and image service endpoints.
#[derive(Clone, Debug)]
pub struct CriClient {
    runtime_channel: Channel,
    image_channel: Channel,
    runtime: RuntimeServiceClient<Channel>,
    image: ImageServiceClient<Channel>,
}

/// Helper to construct an [`ImageSpec`] for a given image reference.
#[must_use]
pub fn image_spec(image: impl Into<String>) -> crate::runtime::v1::ImageSpec {
    crate::runtime::v1::ImageSpec {
        image: image.into(),
        annotations: BTreeMap::new(),
        user_specified_image: String::new(),
        runtime_handler: String::new(),
    }
}

impl CriClient {
    /// Connects to the given CRI endpoints over Unix domain sockets.
    pub async fn connect(endpoints: &RuntimeEndpoints) -> Result<Self, ReadinessError> {
        let runtime_path = endpoints.runtime.path();
        let image_path = endpoints.image.path();

        let runtime_channel =
            connect_unix(runtime_path)
                .await
                .map_err(|source| ReadinessError::ConnectFailed {
                    endpoint: runtime_path.to_path_buf(),
                    source,
                })?;

        let image_channel = if runtime_path == image_path {
            runtime_channel.clone()
        } else {
            connect_unix(image_path)
                .await
                .map_err(|source| ReadinessError::ConnectFailed {
                    endpoint: image_path.to_path_buf(),
                    source,
                })?
        };

        Ok(Self::new(runtime_channel, image_channel))
    }

    /// Creates a client from pre-established tonic gRPC channels.
    #[must_use]
    pub fn new(runtime_channel: Channel, image_channel: Channel) -> Self {
        Self {
            runtime: RuntimeServiceClient::new(runtime_channel.clone()),
            image: ImageServiceClient::new(image_channel.clone()),
            runtime_channel,
            image_channel,
        }
    }

    /// Negotiates runtime cgroup driver and validates readiness.
    pub async fn negotiate(
        &mut self,
        endpoints: &RuntimeEndpoints,
        host_fallback: ResolvedCgroupDriver,
    ) -> Result<NegotiatedRuntime, ReadinessError> {
        let info = check_runtime_version(self.runtime_channel())
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

        check_image_service(self.image_channel())
            .await
            .map_err(|status| ReadinessError::RpcFailed {
                service: "ImageService",
                status,
            })?;

        let (driver, source) = negotiate_cgroup_driver(self.runtime_channel(), host_fallback).await;

        Ok(NegotiatedRuntime::new(
            info,
            endpoints.clone(),
            driver,
            source,
        ))
    }

    /// Access the underlying `RuntimeService` channel.
    #[must_use]
    pub fn runtime_channel(&self) -> Channel {
        self.runtime_channel.clone()
    }

    /// Access the underlying `ImageService` channel.
    #[must_use]
    pub fn image_channel(&self) -> Channel {
        self.image_channel.clone()
    }

    // --- Pod Sandbox Lifecycle ---

    /// Runs a new pod sandbox on the external runtime.
    pub async fn run_pod_sandbox(
        &mut self,
        request: RunPodSandboxRequest,
    ) -> Result<String, tonic::Status> {
        let resp = self.runtime.run_pod_sandbox(request).await?;
        Ok(resp.into_inner().pod_sandbox_id)
    }

    /// Stops an existing pod sandbox.
    pub async fn stop_pod_sandbox(
        &mut self,
        pod_sandbox_id: impl Into<String>,
    ) -> Result<(), tonic::Status> {
        let req = StopPodSandboxRequest {
            pod_sandbox_id: pod_sandbox_id.into(),
        };
        self.runtime.stop_pod_sandbox(req).await?;
        Ok(())
    }

    /// Removes an existing pod sandbox.
    pub async fn remove_pod_sandbox(
        &mut self,
        pod_sandbox_id: impl Into<String>,
    ) -> Result<(), tonic::Status> {
        let req = RemovePodSandboxRequest {
            pod_sandbox_id: pod_sandbox_id.into(),
        };
        self.runtime.remove_pod_sandbox(req).await?;
        Ok(())
    }

    /// Lists pod sandboxes matching an optional filter.
    pub async fn list_pod_sandboxes(
        &mut self,
        filter: Option<PodSandboxFilter>,
    ) -> Result<Vec<PodSandbox>, tonic::Status> {
        let req = ListPodSandboxRequest { filter };
        let resp = self.runtime.list_pod_sandbox(req).await?;
        Ok(resp.into_inner().items)
    }

    /// Retrieves status for a specific pod sandbox.
    pub async fn pod_sandbox_status(
        &mut self,
        pod_sandbox_id: impl Into<String>,
        verbose: bool,
    ) -> Result<PodSandboxStatus, tonic::Status> {
        let req = PodSandboxStatusRequest {
            pod_sandbox_id: pod_sandbox_id.into(),
            verbose,
        };
        let resp = self.runtime.pod_sandbox_status(req).await?;
        resp.into_inner()
            .status
            .ok_or_else(|| tonic::Status::internal("missing sandbox status in response"))
    }

    // --- Container Lifecycle ---

    /// Creates a container inside an existing pod sandbox.
    pub async fn create_container(
        &mut self,
        request: CreateContainerRequest,
    ) -> Result<String, tonic::Status> {
        let resp = self.runtime.create_container(request).await?;
        Ok(resp.into_inner().container_id)
    }

    /// Starts an existing created container.
    pub async fn start_container(
        &mut self,
        container_id: impl Into<String>,
    ) -> Result<(), tonic::Status> {
        let req = StartContainerRequest {
            container_id: container_id.into(),
        };
        self.runtime.start_container(req).await?;
        Ok(())
    }

    /// Stops a running container with timeout.
    pub async fn stop_container(
        &mut self,
        container_id: impl Into<String>,
        timeout_secs: i64,
    ) -> Result<(), tonic::Status> {
        let req = StopContainerRequest {
            container_id: container_id.into(),
            timeout: timeout_secs,
        };
        self.runtime.stop_container(req).await?;
        Ok(())
    }

    /// Removes a stopped container.
    pub async fn remove_container(
        &mut self,
        container_id: impl Into<String>,
    ) -> Result<(), tonic::Status> {
        let req = RemoveContainerRequest {
            container_id: container_id.into(),
        };
        self.runtime.remove_container(req).await?;
        Ok(())
    }

    /// Lists containers matching an optional filter.
    pub async fn list_containers(
        &mut self,
        filter: Option<ContainerFilter>,
    ) -> Result<Vec<Container>, tonic::Status> {
        let req = ListContainersRequest { filter };
        let resp = self.runtime.list_containers(req).await?;
        Ok(resp.into_inner().containers)
    }

    /// Retrieves status for a specific container.
    pub async fn container_status(
        &mut self,
        container_id: impl Into<String>,
        verbose: bool,
    ) -> Result<ContainerStatus, tonic::Status> {
        let req = ContainerStatusRequest {
            container_id: container_id.into(),
            verbose,
        };
        let resp = self.runtime.container_status(req).await?;
        resp.into_inner()
            .status
            .ok_or_else(|| tonic::Status::internal("missing container status in response"))
    }

    /// Queries runtime version information.
    pub async fn version(
        &mut self,
        version: impl Into<String>,
    ) -> Result<VersionResponse, tonic::Status> {
        let req = VersionRequest {
            version: version.into(),
        };
        let resp = self.runtime.version(req).await?;
        Ok(resp.into_inner())
    }

    /// Executes a command synchronously inside a container.
    pub async fn exec_sync(
        &mut self,
        container_id: impl Into<String>,
        cmd: Vec<String>,
        timeout_secs: i64,
    ) -> Result<ExecSyncResponse, tonic::Status> {
        let req = ExecSyncRequest {
            container_id: container_id.into(),
            cmd,
            timeout: timeout_secs,
        };
        let resp = self.runtime.exec_sync(req).await?;
        Ok(resp.into_inner())
    }

    // --- Image Service Operations ---

    /// Lists images present in the external CRI runtime image store.
    pub async fn list_images(&mut self) -> Result<Vec<Image>, tonic::Status> {
        let req = ListImagesRequest { filter: None };
        let resp = self.image.list_images(req).await?;
        Ok(resp.into_inner().images)
    }

    /// Queries status for a specific image reference.
    pub async fn image_status(
        &mut self,
        image: impl Into<String>,
        verbose: bool,
    ) -> Result<Option<Image>, tonic::Status> {
        let req = ImageStatusRequest {
            image: Some(image_spec(image)),
            verbose,
        };
        let resp = self.image.image_status(req).await?;
        Ok(resp.into_inner().image)
    }

    /// Queries status for a specific image specification.
    pub async fn image_status_spec(
        &mut self,
        image: Option<ImageSpec>,
        verbose: bool,
    ) -> Result<Option<Image>, tonic::Status> {
        let req = ImageStatusRequest { image, verbose };
        let resp = self.image.image_status(req).await?;
        Ok(resp.into_inner().image)
    }

    /// Requests the external runtime to pull an image.
    pub async fn pull_image(&mut self, image: impl Into<String>) -> Result<String, tonic::Status> {
        let req = PullImageRequest {
            image: Some(image_spec(image)),
            auth: None,
            sandbox_config: None,
        };
        let resp = self.image.pull_image(req).await?;
        Ok(resp.into_inner().image_ref)
    }

    /// Requests the external runtime to pull an image with full spec, auth, and sandbox options.
    pub async fn pull_image_spec(
        &mut self,
        image: Option<ImageSpec>,
        auth: Option<AuthConfig>,
        sandbox_config: Option<PodSandboxConfig>,
    ) -> Result<String, tonic::Status> {
        let req = PullImageRequest {
            image,
            auth,
            sandbox_config,
        };
        let resp = self.image.pull_image(req).await?;
        Ok(resp.into_inner().image_ref)
    }

    /// Removes an image from the external CRI runtime image store.
    pub async fn remove_image(&mut self, image: impl Into<String>) -> Result<(), tonic::Status> {
        let req = RemoveImageRequest {
            image: Some(image_spec(image)),
        };
        self.image.remove_image(req).await?;
        Ok(())
    }
}
