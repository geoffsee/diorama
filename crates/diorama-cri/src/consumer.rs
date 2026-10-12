//! Resolved CRI consumer settings for Kubelet and CNI integration.
//!
//! Exposes validated endpoints, provider identities, and negotiated cgroup drivers
//! directly to consumer settings without fabricating protobuf-zero defaults.

use crate::cgroup::{CgroupDriverSource, ResolvedCgroupDriver};
use crate::endpoint::RuntimeEndpoints;
use crate::provider::ProviderInfo;

/// Fully negotiated external CRI runtime configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedRuntime {
    /// Provider identity (containerd or CRI-O).
    pub provider: ProviderInfo,
    /// Validated socket endpoints.
    pub endpoints: RuntimeEndpoints,
    /// Negotiated cgroup driver.
    pub cgroup_driver: ResolvedCgroupDriver,
    /// Provenance of the cgroup driver decision.
    pub driver_source: CgroupDriverSource,
}

/// Resolved configuration consumed by Kubelet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KubeletConsumerSettings {
    /// `--container-runtime-endpoint` URI string.
    pub container_runtime_endpoint: String,
    /// `--image-service-endpoint` URI string.
    pub image_service_endpoint: String,
    /// Resolved cgroup driver.
    pub cgroup_driver: ResolvedCgroupDriver,
}

/// Resolved configuration consumed by CNI network plugins and workload setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CniConsumerSettings {
    /// Primary CRI runtime endpoint URI string.
    pub runtime_endpoint: String,
    /// Indicates whether the runtime and its CNI plugins/images are host-managed.
    pub host_managed: bool,
}

impl NegotiatedRuntime {
    /// Creates a new `NegotiatedRuntime` descriptor.
    #[must_use]
    pub fn new(
        provider: ProviderInfo,
        endpoints: RuntimeEndpoints,
        cgroup_driver: ResolvedCgroupDriver,
        driver_source: CgroupDriverSource,
    ) -> Self {
        Self {
            provider,
            endpoints,
            cgroup_driver,
            driver_source,
        }
    }

    /// Exposes settings structured for Kubelet configuration.
    #[must_use]
    pub fn kubelet_settings(&self) -> KubeletConsumerSettings {
        KubeletConsumerSettings {
            container_runtime_endpoint: self.endpoints.runtime.uri(),
            image_service_endpoint: self.endpoints.image.uri(),
            cgroup_driver: self.cgroup_driver,
        }
    }

    /// Generates standard CLI flags for Kubelet process execution.
    #[must_use]
    pub fn kubelet_cli_args(&self) -> Vec<String> {
        let mut args = vec![
            format!(
                "--container-runtime-endpoint={}",
                self.endpoints.runtime.uri()
            ),
            self.cgroup_driver.as_kubelet_arg(),
        ];
        if self.endpoints.runtime != self.endpoints.image {
            args.push(format!(
                "--image-service-endpoint={}",
                self.endpoints.image.uri()
            ));
        }
        args
    }

    /// Exposes settings structured for CNI network consumers.
    #[must_use]
    pub fn cni_settings(&self) -> CniConsumerSettings {
        CniConsumerSettings {
            runtime_endpoint: self.endpoints.runtime.uri(),
            host_managed: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::CriEndpoint;
    use crate::provider::CriProvider;

    #[test]
    fn single_endpoint_consumer_settings() {
        let ep = CriEndpoint::from_path("/run/containerd/containerd.sock").unwrap();
        let endpoints = RuntimeEndpoints::single(ep);
        let provider = ProviderInfo::new("containerd", "1.7.20", "v1");
        let negotiated = NegotiatedRuntime::new(
            provider,
            endpoints,
            ResolvedCgroupDriver::Systemd,
            CgroupDriverSource::CriRuntimeConfig,
        );

        let kubelet = negotiated.kubelet_settings();
        assert_eq!(
            kubelet.container_runtime_endpoint,
            "unix:///run/containerd/containerd.sock"
        );
        assert_eq!(
            kubelet.image_service_endpoint,
            "unix:///run/containerd/containerd.sock"
        );
        assert_eq!(kubelet.cgroup_driver, ResolvedCgroupDriver::Systemd);

        let args = negotiated.kubelet_cli_args();
        assert_eq!(
            args,
            vec![
                "--container-runtime-endpoint=unix:///run/containerd/containerd.sock",
                "--cgroup-driver=systemd",
            ]
        );

        let cni = negotiated.cni_settings();
        assert_eq!(
            cni.runtime_endpoint,
            "unix:///run/containerd/containerd.sock"
        );
        assert!(cni.host_managed);
    }

    #[test]
    fn dual_endpoint_consumer_settings() {
        let runtime_ep = CriEndpoint::from_path("/var/run/crio/crio.sock").unwrap();
        let image_ep = CriEndpoint::from_path("/var/run/crio/image.sock").unwrap();
        let endpoints = RuntimeEndpoints::new(runtime_ep, Some(image_ep));
        let provider = ProviderInfo::new("cri-o", "1.30.0", "v1");
        let negotiated = NegotiatedRuntime::new(
            provider,
            endpoints,
            ResolvedCgroupDriver::Cgroupfs,
            CgroupDriverSource::HostFallback,
        );

        let kubelet = negotiated.kubelet_settings();
        assert_eq!(
            kubelet.container_runtime_endpoint,
            "unix:///var/run/crio/crio.sock"
        );
        assert_eq!(
            kubelet.image_service_endpoint,
            "unix:///var/run/crio/image.sock"
        );
        assert_eq!(kubelet.cgroup_driver, ResolvedCgroupDriver::Cgroupfs);

        let args = negotiated.kubelet_cli_args();
        assert_eq!(
            args,
            vec![
                "--container-runtime-endpoint=unix:///var/run/crio/crio.sock",
                "--cgroup-driver=cgroupfs",
                "--image-service-endpoint=unix:///var/run/crio/image.sock",
            ]
        );

        assert_eq!(negotiated.provider.provider, CriProvider::Crio);
    }
}
