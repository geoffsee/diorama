use std::collections::BTreeMap;
use std::fmt;

use diorama_platform::Architecture;

/// Standard namespace where Portainer Edge agent resources are deployed.
pub const PORTAINER_NAMESPACE: &str = "portainer";

/// Standard deployment name for Portainer Edge agent.
pub const PORTAINER_AGENT_DEPLOYMENT_NAME: &str = "portainer-agent";

/// Standard headless service name for Portainer Edge agent.
pub const PORTAINER_AGENT_SERVICE_NAME: &str = "portainer-agent";

/// Standard `ConfigMap` name holding Portainer Edge agent configuration.
pub const PORTAINER_AGENT_CONFIGMAP_NAME: &str = "portainer-agent-edge";

/// Standard Secret name holding Portainer Edge key.
pub const PORTAINER_AGENT_SECRET_NAME: &str = "portainer-agent-edge-key";

/// Standard `ServiceAccount` name for Portainer Edge agent.
pub const PORTAINER_AGENT_SERVICE_ACCOUNT_NAME: &str = "portainer-sa-clusteradmin";

/// Standard `ClusterRole` referenced by the Portainer Edge agent `ClusterRoleBinding`.
pub const CLUSTER_ADMIN_CLUSTER_ROLE_NAME: &str = "cluster-admin";

/// Standard `ClusterRoleBinding` name for Portainer Edge agent.
pub const PORTAINER_AGENT_CLUSTER_ROLE_BINDING_NAME: &str = "portainer-crb-clusteradmin";

/// Default upstream Portainer Edge agent container image reference.
pub const DEFAULT_PORTAINER_AGENT_IMAGE: &str = "docker.io/portainer/agent:lts";

/// Default TCP port for Edge communication.
pub const PORTAINER_AGENT_PORT_EDGE: i32 = 9001;

/// Default TCP port for HTTP communication.
pub const PORTAINER_AGENT_PORT_HTTP: i32 = 80;

/// Default value for `EDGE_INSECURE_POLL`.
pub const DEFAULT_EDGE_INSECURE_POLL: &str = "0";

/// Default readiness polling timeout for Portainer Edge agent deployment.
pub const DEFAULT_READINESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Configuration settings for deploying the Portainer Edge agent.
#[derive(Clone, PartialEq, Eq)]
pub struct PortainerAgentConfig {
    /// Portainer Edge identifier.
    pub edge_id: String,

    /// Portainer Edge key credential.
    pub edge_key: String,

    /// Optional Portainer Edge secret token.
    pub edge_secret: Option<String>,

    /// Value for `EDGE_INSECURE_POLL` environment variable. Defaults to `"0"`.
    pub edge_insecure_poll: String,

    /// Whether to run in asynchronous edge polling mode (`EDGE_ASYNC`).
    pub edge_async: bool,

    /// Full container image reference for the agent.
    pub image: String,

    /// Target host system architecture.
    pub architecture: Architecture,

    /// Optional extra environment variables to inject into the `ConfigMap`.
    pub env_vars: BTreeMap<String, String>,

    /// Readiness polling timeout for Portainer deployment.
    pub readiness_timeout: std::time::Duration,
}

impl fmt::Debug for PortainerAgentConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortainerAgentConfig")
            .field("edge_id", &self.edge_id)
            .field("edge_key", &"<redacted>")
            .field(
                "edge_secret",
                &self.edge_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("edge_insecure_poll", &self.edge_insecure_poll)
            .field("edge_async", &self.edge_async)
            .field("image", &self.image)
            .field("architecture", &self.architecture)
            .field("env_vars", &self.env_vars)
            .field("readiness_timeout", &self.readiness_timeout)
            .finish()
    }
}

impl PortainerAgentConfig {
    /// Create a new `PortainerAgentConfig` with required parameters and defaults.
    #[must_use]
    pub fn new(
        edge_id: impl Into<String>,
        edge_key: impl Into<String>,
        architecture: Architecture,
    ) -> Self {
        Self {
            edge_id: edge_id.into(),
            edge_key: edge_key.into(),
            edge_secret: None,
            edge_insecure_poll: DEFAULT_EDGE_INSECURE_POLL.to_string(),
            edge_async: false,
            image: DEFAULT_PORTAINER_AGENT_IMAGE.to_string(),
            architecture,
            env_vars: BTreeMap::new(),
            readiness_timeout: DEFAULT_READINESS_TIMEOUT,
        }
    }

    /// Construct a `PortainerAgentConfig` from `diorama_config::Portainer` and `Architecture`.
    #[must_use]
    pub fn from_diorama_config(
        config: &diorama_config::Portainer,
        architecture: Architecture,
    ) -> Self {
        Self {
            edge_id: config.edge_id.clone(),
            edge_key: config.edge_key.clone(),
            edge_secret: None,
            edge_insecure_poll: DEFAULT_EDGE_INSECURE_POLL.to_string(),
            edge_async: config.asynchronous,
            image: if config.image.is_empty() {
                DEFAULT_PORTAINER_AGENT_IMAGE.to_string()
            } else {
                config.image.clone()
            },
            architecture,
            env_vars: BTreeMap::new(),
            readiness_timeout: DEFAULT_READINESS_TIMEOUT,
        }
    }

    /// Set asynchronous polling mode.
    #[must_use]
    pub fn with_edge_async(mut self, edge_async: bool) -> Self {
        self.edge_async = edge_async;
        self
    }

    /// Set optional edge secret token.
    #[must_use]
    pub fn with_edge_secret(mut self, edge_secret: Option<String>) -> Self {
        self.edge_secret = edge_secret;
        self
    }

    /// Set insecure poll configuration value.
    #[must_use]
    pub fn with_edge_insecure_poll(mut self, poll: impl Into<String>) -> Self {
        self.edge_insecure_poll = poll.into();
        self
    }

    /// Set custom container image.
    #[must_use]
    pub fn with_image(mut self, image: impl Into<String>) -> Self {
        self.image = image.into();
        self
    }

    /// Set extra environment variables.
    #[must_use]
    pub fn with_env_vars(mut self, env_vars: BTreeMap<String, String>) -> Self {
        self.env_vars = env_vars;
        self
    }

    /// Set readiness polling timeout.
    #[must_use]
    pub fn with_readiness_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.readiness_timeout = timeout;
        self
    }

    /// Returns true if the target host architecture supports Portainer Edge agent.
    /// Portainer Agent images are published for amd64, arm64, and armv7, but not riscv64.
    #[must_use]
    pub fn is_architecture_supported(&self) -> bool {
        self.architecture != Architecture::Riscv64
    }

    /// Returns true if both edge ID and edge key are missing (empty).
    #[must_use]
    pub fn has_missing_credentials(&self) -> bool {
        self.edge_id.is_empty() && self.edge_key.is_empty()
    }

    /// Returns true if exactly one of edge ID or edge key is provided while the other is missing.
    #[must_use]
    pub fn has_partial_credentials(&self) -> bool {
        self.edge_id.is_empty() ^ self.edge_key.is_empty()
    }

    /// Returns true if the Portainer Edge agent should be enabled and deployed.
    /// Requirements:
    /// - Both `edge_id` and `edge_key` are non-empty
    /// - Host architecture is supported (not RISC-V 64)
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        !self.edge_id.is_empty() && !self.edge_key.is_empty() && self.is_architecture_supported()
    }

    /// Returns the selected image reference if the agent is enabled and supported,
    /// or `None` if the component is disabled or the architecture is unsupported.
    /// This prevents unsupported images from ever being selected for download or import.
    #[must_use]
    pub fn selected_image(&self) -> Option<&str> {
        if self.is_enabled() {
            Some(&self.image)
        } else {
            None
        }
    }
}
