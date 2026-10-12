use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::{Config, ConfigError, ValidatedConfig, resolve_runtime_endpoint};

/// Facts supplied by the platform layer. Conversion performs no probes or IO.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeProbe {
    pub hostname: String,
    pub node_ip: String,
    pub node_ip_pinned: bool,
    pub load_balancer_ip: String,
    pub mtu: i64,
    pub mtu_pinned: bool,
    pub container_mode: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeEndpoint {
    pub url: String,
    pub socket: PathBuf,
    pub external: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSettings {
    /// All thirty desired-state fields remain typed and available to their owners.
    pub desired: Config,
    pub probe: RuntimeProbe,
    pub node_name: String,
    pub runtime: RuntimeEndpoint,
    pub paths: BTreeMap<RuntimePath, PathBuf>,
    pub portainer_edge_enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuntimePath {
    Pki,
    CaCertificate,
    CaKey,
    AdminCertificate,
    AdminKey,
    AdminKubeconfig,
    ApiServerCertificate,
    ApiServerKey,
    ServiceAccountKey,
    KubeletCertificate,
    KubeletKey,
    KubeletKubeconfig,
    ControllerCertificate,
    ControllerKey,
    WebhookCertificate,
    WebhookKey,
    RequestHeaderCaCertificate,
    RequestHeaderCaKey,
    RequestHeaderClientCertificate,
    RequestHeaderClientKey,
    D2kServerCertificate,
    D2kServerKey,
    D2kClientCertificate,
    D2kClientKey,
    Containerd,
    ContainerdSocket,
    ContainerdBinary,
    ContainerdImages,
    ContainerdShim,
    ContainerdConfig,
    ContainerdRoot,
    ContainerdState,
    ContainerdRegistry,
    Cni,
    CniPlugins,
    CniConfigDirectory,
    CniConfig,
    CrunBinary,
    Kubelet,
    KubeletConfigDirectory,
    KubeletConfig,
    KubeletPlugins,
    ApiServer,
    KineDatabase,
    KineSocket,
    ControllerConfig,
    Webhook,
    PortainerImage,
    CoreDnsImage,
    SandboxImage,
    LocalPathImage,
    D2kImage,
    LocalPathStorage,
}
const PATHS: &[(RuntimePath, &str)] = &[
    (RuntimePath::Pki, "pki"),
    (RuntimePath::CaCertificate, "pki/ca/ca.crt"),
    (RuntimePath::CaKey, "pki/ca/ca.key"),
    (RuntimePath::AdminCertificate, "pki/admin/admin.crt"),
    (RuntimePath::AdminKey, "pki/admin/admin.key"),
    (RuntimePath::AdminKubeconfig, "pki/admin/admin.kubeconfig"),
    (
        RuntimePath::ApiServerCertificate,
        "pki/apiserver/apiserver.crt",
    ),
    (RuntimePath::ApiServerKey, "pki/apiserver/apiserver.key"),
    (
        RuntimePath::ServiceAccountKey,
        "pki/apiserver/service-account.key",
    ),
    (RuntimePath::KubeletCertificate, "pki/kubelet/kubelet.crt"),
    (RuntimePath::KubeletKey, "pki/kubelet/kubelet.key"),
    (
        RuntimePath::KubeletKubeconfig,
        "pki/kubelet/kubelet.kubeconfig",
    ),
    (
        RuntimePath::ControllerCertificate,
        "pki/controller-manager/controller-manager.crt",
    ),
    (
        RuntimePath::ControllerKey,
        "pki/controller-manager/controller-manager.key",
    ),
    (RuntimePath::WebhookCertificate, "pki/webhook/webhook.crt"),
    (RuntimePath::WebhookKey, "pki/webhook/webhook.key"),
    (
        RuntimePath::RequestHeaderCaCertificate,
        "pki/request-header/request-header-ca.crt",
    ),
    (
        RuntimePath::RequestHeaderCaKey,
        "pki/request-header/request-header-ca.key",
    ),
    (
        RuntimePath::RequestHeaderClientCertificate,
        "pki/request-header/request-header-client.crt",
    ),
    (
        RuntimePath::RequestHeaderClientKey,
        "pki/request-header/request-header-client.key",
    ),
    (RuntimePath::D2kServerCertificate, "pki/d2k/server.crt"),
    (RuntimePath::D2kServerKey, "pki/d2k/server.key"),
    (RuntimePath::D2kClientCertificate, "pki/d2k/client.crt"),
    (RuntimePath::D2kClientKey, "pki/d2k/client.key"),
    (RuntimePath::Containerd, "containerd"),
    (RuntimePath::ContainerdSocket, "containerd/containerd.sock"),
    (RuntimePath::ContainerdBinary, "containerd/containerd"),
    (RuntimePath::ContainerdImages, "containerd/images"),
    (
        RuntimePath::ContainerdShim,
        "containerd/containerd-shim-runc-v2",
    ),
    (RuntimePath::ContainerdConfig, "containerd/config.toml"),
    (RuntimePath::ContainerdRoot, "containerd/root"),
    (RuntimePath::ContainerdState, "containerd/state"),
    (RuntimePath::ContainerdRegistry, "containerd/registry"),
    (RuntimePath::Cni, "containerd/cni"),
    (RuntimePath::CniPlugins, "containerd/cni/plugins"),
    (RuntimePath::CniConfigDirectory, "containerd/cni/conf"),
    (
        RuntimePath::CniConfig,
        "containerd/cni/conf/10-bridge.conflist",
    ),
    (RuntimePath::CrunBinary, "containerd/crun"),
    (RuntimePath::Kubelet, "kubelet"),
    (RuntimePath::KubeletConfigDirectory, "kubelet/config"),
    (RuntimePath::KubeletConfig, "kubelet/config/config.yaml"),
    (RuntimePath::KubeletPlugins, "kubelet/volumeplugins"),
    (RuntimePath::ApiServer, "apiserver"),
    (RuntimePath::KineDatabase, "kine/db"),
    (RuntimePath::KineSocket, "kine/db/socket"),
    (RuntimePath::ControllerConfig, "controller-manager/config"),
    (RuntimePath::Webhook, "pki/webhook"),
    (
        RuntimePath::PortainerImage,
        "containerd/images/portainer-agent.tar.gz",
    ),
    (
        RuntimePath::CoreDnsImage,
        "containerd/images/coredns.tar.gz",
    ),
    (RuntimePath::SandboxImage, "containerd/images/pause.tar.gz"),
    (
        RuntimePath::LocalPathImage,
        "containerd/images/local-path-provisioner.tar.gz",
    ),
    (RuntimePath::D2kImage, "containerd/images/d2k.tar.gz"),
    (RuntimePath::LocalPathStorage, "local-path-storage"),
];
fn join(base: &str, tail: &str) -> PathBuf {
    let joined = format!("{base}/{tail}");
    let absolute = !base.is_empty() && base.starts_with('/');
    let mut parts = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {},
            ".." => {
                if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            },
            _ => parts.push(part),
        }
    }
    let path = format!("{}{}", if absolute { "/" } else { "" }, parts.join("/"));
    PathBuf::from(if path.is_empty() { ".".into() } else { path })
}
impl Config {
    /// The derived socket default is applied by #40 after input precedence.
    pub fn derive_socket_path(&mut self) {
        if self.api.socket_path.is_empty() {
            self.api.socket_path = join(&self.path, "config.sock")
                .to_string_lossy()
                .into_owned();
        }
    }
}
impl ValidatedConfig {
    pub fn into_runtime(self, probe: RuntimeProbe) -> Result<RuntimeSettings, ConfigError> {
        let config = self.config;
        let node_name = config.kubernetes.node_name.trim().to_lowercase();
        let node_name = if node_name.is_empty() {
            probe.hostname.trim().to_lowercase()
        } else {
            node_name
        };
        if node_name.is_empty() {
            return Err(ConfigError {
                kind: crate::ErrorKind::Type,
                path: "kubernetes.nodeName".into(),
                message: "node name and discovered hostname are empty".into(),
            });
        }
        let paths: BTreeMap<_, _> = PATHS
            .iter()
            .map(|(key, tail)| (*key, join(&config.path, tail)))
            .collect();
        let endpoint = resolve_runtime_endpoint(&config.runtime.endpoint)?;
        let external = endpoint.is_some();
        let url = endpoint.unwrap_or_else(|| {
            format!(
                "unix://{}",
                join(&config.path, "containerd/containerd.sock").display()
            )
        });
        let socket = PathBuf::from(url.strip_prefix("unix://").unwrap_or(&url));
        let portainer_edge_enabled =
            !config.portainer.edge_id.is_empty() && !config.portainer.edge_key.is_empty();
        Ok(RuntimeSettings {
            desired: config,
            probe,
            node_name,
            runtime: RuntimeEndpoint {
                url,
                socket,
                external,
            },
            paths,
            portainer_edge_enabled,
        })
    }
}
