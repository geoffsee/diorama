//! Supervised node runtime assembly and C02 lifecycle contract.
//!
//! Provides dependency-aware component coordination distinguishing fatal-core
//! and optional-deployment failure policies, structured JSONL lifecycle logging
//! with debug controls, credential-safe diagnostics, and production API client access.

use std::fmt;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use diorama_apiserver::client::KubernetesApiClient;
use diorama_apiserver::service::ApiserverService;
use diorama_apiserver::storage::KubernetesStorage;
use diorama_apiserver::supervisor::ApiserverAdapter;
use diorama_apiserver::{ApiserverConfig, PodExec, PodLogReader};
use diorama_config::ValidatedConfig;
use diorama_containerd::{
    ContainerdPaths, ContainerdService, ContainerdServiceOptions, ImageImportConfig,
};
use diorama_controller::ControllerManagerConfig;
use diorama_controller::service::ControllerManagerService;
use diorama_controller::supervisor::ControllerManagerAdapter;
use diorama_cri::{ExternalRuntimeOptions, ExternalRuntimeService, RuntimeEndpoints};
use diorama_datastore::config::DatastoreConfig;
use diorama_datastore::engine::DatastoreEngine;
use diorama_datastore::supervisor::DatastoreAdapter;
use diorama_dns::config::CoreDnsConfig;
use diorama_dns::service::CoreDnsService;
use diorama_dns::supervisor::CoreDnsAdapter;
use diorama_pki::cluster::{ClusterPki, ClusterPkiConfig};
use diorama_portainer::config::PortainerAgentConfig;
use diorama_portainer::service::PortainerService;
use diorama_portainer::supervisor::PortainerAdapter;
use diorama_proxy::{KubeProxyOptions, ProxyAdapter, ProxyMode, ProxyService};
use diorama_storage::config::LocalPathConfig;
use diorama_storage::service::LocalPathService;
use diorama_storage::supervisor::LocalPathAdapter;
use diorama_supervisor::{
    Adapter, ComponentKind, ComponentSpec, FailurePolicy, GraphError, LifecycleObserver,
    Registration, StopCause, StopReceiver, Supervisor, SupervisorReport, stop_channel,
};
use dioramalet::{
    CriRuntimeProvider, KubeletAdapter, KubeletConfigOptions, KubeletService, RuntimeProvider,
};

use crate::lifecycle_logs::{
    DeliveryReport, LifecycleRenderer, LogLevel, consume_lifecycle, log_channel,
};
use crate::lifecycle_policy::LifecyclePolicy;
use crate::lifecycle_sink::{FlushPolicy, SinkReport, configured_log_level, deliver_logs};

pub const COMPONENT_CONTAINERD: &str = diorama_containerd::COMPONENT_CONTAINERD;
pub const COMPONENT_EXTERNAL_CRI: &str = diorama_cri::COMPONENT_EXTERNAL_CRI;
pub const COMPONENT_DATASTORE: &str = "datastore";
pub const COMPONENT_APISERVER: &str = "apiserver";
pub const COMPONENT_CONTROLLER_MANAGER: &str = "controller-manager";
pub const COMPONENT_COREDNS: &str = "coredns";
pub const COMPONENT_LOCAL_PATH: &str = "local-path-provisioner";
pub const COMPONENT_PORTAINER: &str = "portainer-agent";
pub const COMPONENT_PROXY: &str = "kube-proxy";
pub const COMPONENT_KUBELET: &str = "kubelet";
pub const COMPONENT_METRICS: &str = "metrics";
pub const COMPONENT_CONFIG_API: &str = "configapi";

/// Errors encountered while constructing or initializing the node runtime.
#[derive(Debug)]
pub enum RuntimeError {
    Pki(diorama_pki::PkiError),
    Datastore(diorama_datastore::DatastoreError),
    Apiserver(diorama_apiserver::ApiserverError),
    Supervisor(GraphError),
    Network(diorama_network::NetworkError),
    Io(io::Error),
    ChannelCapacity,
}

impl RuntimeError {
    #[must_use]
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            Self::Pki(_) => "pki_failure",
            Self::Datastore(_) => "datastore_failure",
            Self::Apiserver(_) => "apiserver_failure",
            Self::Supervisor(_) => "supervisor_failure",
            Self::Network(_) => "network_failure",
            Self::Io(_) => "io_failure",
            Self::ChannelCapacity => "channel_capacity_error",
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pki(e) => write!(f, "PKI initialization failure: {e}"),
            Self::Datastore(e) => write!(f, "datastore initialization failure: {e}"),
            Self::Apiserver(e) => write!(f, "apiserver initialization failure: {e}"),
            Self::Supervisor(e) => write!(f, "supervisor configuration error: {e}"),
            Self::Network(e) => write!(f, "network initialization failure: {e}"),
            Self::Io(e) => write!(f, "I/O failure during runtime assembly: {e}"),
            Self::ChannelCapacity => write!(f, "invalid log channel capacity"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<diorama_pki::PkiError> for RuntimeError {
    fn from(e: diorama_pki::PkiError) -> Self {
        Self::Pki(e)
    }
}

impl From<diorama_datastore::DatastoreError> for RuntimeError {
    fn from(e: diorama_datastore::DatastoreError) -> Self {
        Self::Datastore(e)
    }
}

impl From<diorama_apiserver::ApiserverError> for RuntimeError {
    fn from(e: diorama_apiserver::ApiserverError) -> Self {
        Self::Apiserver(e)
    }
}

impl From<GraphError> for RuntimeError {
    fn from(e: GraphError) -> Self {
        Self::Supervisor(e)
    }
}

impl From<diorama_network::NetworkError> for RuntimeError {
    fn from(e: diorama_network::NetworkError) -> Self {
        Self::Network(e)
    }
}

impl From<io::Error> for RuntimeError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

use crate::metrics::{
    BuildInfoCollector, CertificateCollector, DatastoreCollector, MetricsAdapter, MetricsRegistry,
    UptimeCollector,
};

/// Builder for extensible node runtime assembly satisfying the C02 runtime contract.
#[derive(Debug)]
pub struct RuntimeBuilder {
    config: ValidatedConfig,
    policy: LifecyclePolicy,
    log_level: LogLevel,
    apiserver: Option<Arc<ApiserverService>>,
    client: Option<KubernetesApiClient>,
    metrics_registry: Option<Arc<MetricsRegistry>>,
    datastore_bound_addr: Option<Arc<Mutex<Option<SocketAddr>>>>,
    datastore_peer_bound_addr: Option<Arc<Mutex<Option<SocketAddr>>>>,
    kubelet_log_reader: Option<Arc<dyn PodLogReader>>,
    kubelet_exec: Option<Arc<dyn PodExec>>,
    registrations: Vec<Registration>,
}

impl RuntimeBuilder {
    /// Creates a new builder initialized with default policy and log level from configuration.
    #[must_use]
    pub fn new(config: ValidatedConfig) -> Self {
        let policy = LifecyclePolicy::from_config(&config);
        let log_level = configured_log_level(&config);
        Self {
            config,
            policy,
            log_level,
            apiserver: None,
            client: None,
            metrics_registry: None,
            datastore_bound_addr: None,
            datastore_peer_bound_addr: None,
            kubelet_log_reader: None,
            kubelet_exec: None,
            registrations: Vec::new(),
        }
    }

    #[must_use]
    pub fn config(&self) -> &ValidatedConfig {
        &self.config
    }

    #[must_use]
    pub fn policy(&self) -> &LifecyclePolicy {
        &self.policy
    }

    #[must_use]
    pub fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// Exposes registered component specifications.
    #[must_use]
    pub fn registrations(&self) -> &[Registration] {
        &self.registrations
    }

    /// Exposes the production client if an apiserver has been associated with the builder.
    #[must_use]
    pub fn client(&self) -> Option<&KubernetesApiClient> {
        self.client.as_ref()
    }

    #[must_use]
    pub fn apiserver(&self) -> Option<&Arc<ApiserverService>> {
        self.apiserver.as_ref()
    }

    #[must_use]
    pub fn with_apiserver(mut self, apiserver: Arc<ApiserverService>) -> Self {
        if let Some(reader) = &self.kubelet_log_reader {
            apiserver.set_pod_log_reader(reader.clone());
        }
        if let Some(exec) = &self.kubelet_exec {
            apiserver.set_pod_exec(exec.clone());
        }
        self.client = Some(apiserver.admin_client());
        self.apiserver = Some(apiserver);
        self
    }

    #[must_use]
    pub fn with_client(mut self, client: KubernetesApiClient) -> Self {
        self.client = Some(client);
        self
    }

    #[must_use]
    pub fn metrics_registry(&self) -> Option<&Arc<MetricsRegistry>> {
        self.metrics_registry.as_ref()
    }

    #[must_use]
    pub fn with_metrics_registry(mut self, registry: Arc<MetricsRegistry>) -> Self {
        self.metrics_registry = Some(registry);
        self
    }

    /// Selects the CRI runtime provider based on node configuration.
    #[must_use]
    pub fn select_runtime_provider(&self) -> Option<Arc<dyn RuntimeProvider>> {
        select_runtime_provider(self.config.config())
    }

    /// Registers a component directly with its existing specification.
    #[must_use]
    pub fn register_component(mut self, registration: Registration) -> Self {
        self.registrations.push(registration);
        self
    }

    /// Registers a fatal core component. Failure causes global supervisor shutdown.
    #[must_use]
    pub fn register_core<A: Adapter + 'static>(
        mut self,
        id: impl Into<String>,
        prerequisites: Vec<String>,
        adapter: A,
    ) -> Self {
        let spec = self.policy.apply(ComponentSpec {
            id: id.into(),
            prerequisites,
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout: self.policy.startup_timeout(),
        });
        self.registrations.push(Registration::new(spec, adapter));
        self
    }

    /// Registers an optional component. Failure degrades the node while core API remains operational.
    #[must_use]
    pub fn register_optional<A: Adapter + 'static>(
        mut self,
        id: impl Into<String>,
        prerequisites: Vec<String>,
        adapter: A,
    ) -> Self {
        let spec = self.policy.apply(ComponentSpec {
            id: id.into(),
            prerequisites,
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Degrade,
            startup_timeout: self.policy.startup_timeout(),
        });
        self.registrations.push(Registration::new(spec, adapter));
        self
    }

    /// Registers the local configuration HTTP API server.
    #[must_use]
    pub fn register_config_api(self, server: crate::config_api::ConfigApiServer) -> Self {
        self.register_optional(
            COMPONENT_CONFIG_API,
            vec![],
            crate::config_api::ConfigApiAdapter::new(server),
        )
    }

    /// Registers the optional Portainer Edge Agent component under supervision.
    #[must_use]
    pub fn register_portainer(self, service: PortainerService, prerequisites: Vec<String>) -> Self {
        let timeout = self.policy.startup_timeout();
        let reg =
            PortainerAdapter::registration(COMPONENT_PORTAINER, service, prerequisites, timeout);
        self.register_component(reg)
    }

    /// Registers the managed containerd runtime component under supervision.
    #[must_use]
    pub fn register_containerd(self, service: ContainerdService) -> Self {
        let timeout = self.policy.startup_timeout();
        let spec = self
            .policy
            .apply(ContainerdService::component_spec(timeout));
        self.register_component(Registration::new(spec, service))
    }

    /// Registers an in-process oci-cri runtime. Call `diorama_oci::startup`
    /// before starting the executor and make kubelet depend on `oci-cri`.
    #[cfg(feature = "oci-cri")]
    #[must_use]
    pub fn register_oci_cri(self, service: diorama_oci::OciCriService) -> Self {
        let timeout = self.policy.startup_timeout();
        let spec = self
            .policy
            .apply(diorama_oci::OciCriService::component_spec(timeout));
        self.register_component(Registration::new(spec, service))
    }

    /// Registers the external CRI runtime component under supervision.
    #[must_use]
    pub fn register_external_cri(self, service: ExternalRuntimeService) -> Self {
        let timeout = self.policy.startup_timeout();
        let spec = self
            .policy
            .apply(ExternalRuntimeService::component_spec(timeout));
        self.register_component(Registration::new(spec, service))
    }

    /// Registers the kube-proxy component under supervision.
    #[must_use]
    pub fn register_proxy(self, mut proxy: ProxyService) -> Self {
        if let (None, Some(client)) = (proxy.client(), self.client.clone()) {
            proxy = proxy.with_client(Arc::new(client));
        }
        let timeout = self.policy.startup_timeout();
        let reg = ProxyAdapter::registration(
            COMPONENT_PROXY,
            proxy,
            vec![COMPONENT_APISERVER.to_string()],
            timeout,
        );
        self.register_component(reg)
    }

    /// Registers the in-process kubelet component under supervision and connects
    /// its log reader and exec target to the API server so `kubectl logs` and
    /// `kubectl exec` resolve without cyclic references.
    #[must_use]
    pub fn register_kubelet(
        mut self,
        kubelet: KubeletService,
        runtime_component: impl Into<String>,
    ) -> Self {
        let log_reader: Arc<dyn PodLogReader> = Arc::new(kubelet.log_source());
        if let Some(apiserver) = &self.apiserver {
            apiserver.set_pod_log_reader(log_reader.clone());
        }
        self.kubelet_log_reader = Some(log_reader);
        let exec: Arc<dyn PodExec> = Arc::new(kubelet.exec_source());
        if let Some(apiserver) = &self.apiserver {
            apiserver.set_pod_exec(exec.clone());
        }
        self.kubelet_exec = Some(exec);

        let timeout = self.policy.startup_timeout();
        let reg = KubeletAdapter::registration(
            COMPONENT_KUBELET,
            kubelet,
            vec![COMPONENT_APISERVER.to_string(), runtime_component.into()],
            timeout,
        );
        self.register_component(reg)
    }

    /// Registers the `CoreDNS` component under supervision with the specified prerequisites.
    #[must_use]
    pub fn register_coredns(self, service: CoreDnsService, prerequisites: Vec<String>) -> Self {
        self.register_optional(
            COMPONENT_COREDNS,
            prerequisites,
            CoreDnsAdapter::new(service),
        )
    }

    #[must_use]
    pub fn datastore_bound_addr(&self) -> Option<SocketAddr> {
        self.datastore_bound_addr
            .as_ref()
            .and_then(|a| *a.lock().unwrap())
    }

    #[must_use]
    pub fn with_datastore_bound_addr(mut self, bound_addr: Arc<Mutex<Option<SocketAddr>>>) -> Self {
        self.datastore_bound_addr = Some(bound_addr);
        self
    }

    #[must_use]
    pub fn with_datastore_peer_bound_addr(
        mut self,
        bound_addr: Arc<Mutex<Option<SocketAddr>>>,
    ) -> Self {
        self.datastore_peer_bound_addr = Some(bound_addr);
        self
    }

    /// Builds the supervised node runtime.
    pub fn build(self) -> Result<NodeRuntime, RuntimeError> {
        let component_ids: Vec<String> = self
            .registrations
            .iter()
            .map(|r| r.spec.id.clone())
            .collect();
        let (supervisor, observer) = Supervisor::new(self.registrations)?.with_observer();
        Ok(NodeRuntime {
            config: self.config,
            policy: self.policy,
            log_level: self.log_level,
            apiserver: self.apiserver,
            client: self.client,
            metrics_registry: self.metrics_registry,
            datastore_bound_addr: self.datastore_bound_addr,
            datastore_peer_bound_addr: self.datastore_peer_bound_addr,
            component_ids,
            supervisor,
            observer,
        })
    }
}

/// Operational node runtime coordinating components under supervision.
#[derive(Debug)]
pub struct NodeRuntime {
    config: ValidatedConfig,
    policy: LifecyclePolicy,
    log_level: LogLevel,
    apiserver: Option<Arc<ApiserverService>>,
    client: Option<KubernetesApiClient>,
    metrics_registry: Option<Arc<MetricsRegistry>>,
    datastore_bound_addr: Option<Arc<Mutex<Option<SocketAddr>>>>,
    datastore_peer_bound_addr: Option<Arc<Mutex<Option<SocketAddr>>>>,
    component_ids: Vec<String>,
    supervisor: Supervisor,
    observer: LifecycleObserver,
}

impl NodeRuntime {
    /// Returns the registered component identifiers in supervision registration order.
    #[must_use]
    pub fn component_ids(&self) -> &[String] {
        &self.component_ids
    }

    /// Constructs a builder for customized runtime assembly.
    #[must_use]
    pub fn builder(config: ValidatedConfig) -> RuntimeBuilder {
        RuntimeBuilder::new(config)
    }

    /// Assembles the default production node runtime from validated configuration.
    pub fn from_config(config: ValidatedConfig) -> Result<Self, RuntimeError> {
        Self::from_config_with_context(
            config,
            PathBuf::from("/etc/diorama/config.yaml"),
            diorama_config::HostContext::detect(),
        )
    }

    /// Assembles runtime services with the file and host context selected at startup.
    /// This keeps stored configuration and API validation bound to that invocation.
    pub fn from_config_with_context(
        config: ValidatedConfig,
        config_path: PathBuf,
        host: diorama_config::HostContext,
    ) -> Result<Self, RuntimeError> {
        let state_dir = PathBuf::from(&config.config().path);
        // Reject unsupported explicit selections before creating node state.
        detect_workload_runtime(config.config(), &state_dir)?;
        std::fs::create_dir_all(&state_dir)?;

        let (node_ip, pki_dir, node_name) = initialize_pki(&state_dir, &config)?;

        let datastore_dir = state_dir.join("datastore");
        std::fs::create_dir_all(&datastore_dir)?;
        let mut datastore_cfg = DatastoreConfig::new(datastore_dir.clone()).with_client_tls(
            pki_dir.join("datastore-ca.crt"),
            pki_dir.join("datastore-server.crt"),
            pki_dir.join("datastore-server.key"),
        );
        datastore_cfg.listen_peer_addr = Some(SocketAddr::new(node_ip, 2380));
        if config.config().storage.db_wal_repair {
            datastore_cfg = datastore_cfg.with_wal_repair(true);
        }

        let (engine, _) = DatastoreEngine::open(datastore_cfg.clone())?;
        let storage = KubernetesStorage::new(engine.client(), "/registry");

        let mut apiserver_cfg = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
        apiserver_cfg.etcd_servers = vec!["https://127.0.0.1:2379".to_string()];
        apiserver_cfg.etcd_ca_file = Some(pki_dir.join("datastore-ca.crt"));
        apiserver_cfg.etcd_cert_file = Some(pki_dir.join("datastore-client.crt"));
        apiserver_cfg.etcd_key_file = Some(pki_dir.join("datastore-client.key"));

        let apiserver_service = Arc::new(ApiserverService::new(apiserver_cfg, storage));
        let client = apiserver_service.admin_client();

        let controller_cfg = ControllerManagerConfig::default_for_pki(&pki_dir, node_ip);
        let controller_service =
            ControllerManagerService::new(controller_cfg, apiserver_service.clone());

        let dns_config = CoreDnsConfig::new();
        let dns_service = CoreDnsService::new(dns_config, Arc::new(client.clone()));

        let policy = LifecyclePolicy::from_config(&config);
        let timeout = policy.startup_timeout();

        let datastore_adapter = DatastoreAdapter::from_engine(engine);
        let datastore_bound_handle = datastore_adapter.bound_addr_handle();
        let datastore_peer_handle = datastore_adapter.peer_bound_addr_handle();

        let mut builder = RuntimeBuilder::new(config)
            .with_apiserver(apiserver_service.clone())
            .with_client(client.clone())
            .with_datastore_bound_addr(datastore_bound_handle)
            .with_datastore_peer_bound_addr(datastore_peer_handle);

        let datastore_reg = DatastoreAdapter::registration_with_adapter(
            COMPONENT_DATASTORE,
            datastore_adapter,
            timeout,
        );
        let apiserver_reg = ApiserverAdapter::registration(
            COMPONENT_APISERVER,
            (*apiserver_service).clone(),
            vec![COMPONENT_DATASTORE.to_string()],
            timeout,
        );
        let controller_reg = ControllerManagerAdapter::registration(
            COMPONENT_CONTROLLER_MANAGER,
            controller_service,
            vec![COMPONENT_APISERVER.to_string()],
            timeout,
        );
        builder = builder
            .register_component(datastore_reg)
            .register_component(apiserver_reg)
            .register_component(controller_reg);

        let workload_ctx = WorkloadContext {
            state_dir: &state_dir,
            pki_dir: &pki_dir,
            node_name: &node_name,
            node_ip,
            host: &host,
            apiserver_service: &apiserver_service,
            dns_service,
        };
        builder = register_workload_path(builder, workload_ctx)?;

        if builder.config().config().storage.local_path.enabled {
            let managed_containerd = builder
                .registrations()
                .iter()
                .any(|registration| registration.spec.id == COMPONENT_CONTAINERD);
            let storage_config = local_path_config(builder.config().config(), managed_containerd);
            let storage_service = LocalPathService::new(storage_config, Arc::new(client.clone()));
            let storage_reg = LocalPathAdapter::registration(
                COMPONENT_LOCAL_PATH,
                storage_service,
                vec![COMPONENT_APISERVER.to_string()],
                timeout,
            );
            builder = builder.register_component(storage_reg);
        }

        builder = register_operational_metrics(builder, &datastore_cfg, &pki_dir, timeout);
        if builder.config().config().api.enabled {
            let socket_path = if builder.config().config().api.socket_path.is_empty() {
                state_dir.join("config.sock")
            } else {
                PathBuf::from(&builder.config().config().api.socket_path)
            };
            let server = crate::config_api::ConfigApiServer::new(socket_path, config_path, host);
            builder = builder.register_config_api(server);
        }

        builder = register_portainer_if_enabled(builder, client);

        builder.build()
    }

    #[must_use]
    pub fn config(&self) -> &ValidatedConfig {
        &self.config
    }

    #[must_use]
    pub fn is_metrics_enabled(&self) -> bool {
        self.config.config().metrics.enabled
    }

    #[must_use]
    pub fn metrics_bind_address(&self) -> &str {
        &self.config.config().metrics.bind_address
    }

    #[must_use]
    pub fn metrics_registry(&self) -> Option<&Arc<MetricsRegistry>> {
        self.metrics_registry.as_ref()
    }

    #[must_use]
    pub fn lifecycle_policy(&self) -> LifecyclePolicy {
        self.policy
    }

    #[must_use]
    pub fn log_level(&self) -> LogLevel {
        self.log_level
    }

    /// Exposes the authenticated production API client satisfying the C02 runtime contract.
    #[must_use]
    pub fn client(&self) -> Option<&KubernetesApiClient> {
        self.client.as_ref()
    }

    #[must_use]
    pub fn apiserver(&self) -> Option<&Arc<ApiserverService>> {
        self.apiserver.as_ref()
    }

    #[must_use]
    pub fn datastore_bound_addr(&self) -> Option<SocketAddr> {
        self.datastore_bound_addr
            .as_ref()
            .and_then(|a| *a.lock().unwrap())
    }

    #[must_use]
    pub fn datastore_bound_addr_handle(&self) -> Option<Arc<Mutex<Option<SocketAddr>>>> {
        self.datastore_bound_addr.clone()
    }

    #[must_use]
    pub fn datastore_peer_bound_addr(&self) -> Option<SocketAddr> {
        self.datastore_peer_bound_addr
            .as_ref()
            .and_then(|a| *a.lock().unwrap())
    }

    /// Assembles a node runtime, performing a k0s-style QUIC cluster join when a join token is provided.
    pub async fn from_config_with_join(
        config: ValidatedConfig,
        config_path: PathBuf,
        host: diorama_config::HostContext,
        join_token: Option<String>,
    ) -> Result<Self, RuntimeError> {
        let Some(raw_token) = join_token.filter(|s| !s.trim().is_empty()) else {
            return Self::from_config_with_context(config, config_path, host);
        };
        let token = diorama_pki::token::JoinToken::decode(&raw_token)?;
        let state_dir = PathBuf::from(&config.config().path);
        detect_workload_runtime(config.config(), &state_dir)?;
        std::fs::create_dir_all(&state_dir)?;

        let candidates = diorama_network::discover_host_interfaces();
        let node_ip = node_ip_for_config(&config.config().network.node_ip, &candidates);
        let node_name = if config.config().kubernetes.node_name.is_empty() {
            "diorama-node".to_string()
        } else {
            config.config().kubernetes.node_name.clone()
        };
        let listen_peer_addr = SocketAddr::new(node_ip, 2380);

        let join_req = diorama_pki::token::JoinRequest {
            token,
            node_name: node_name.clone(),
            node_ip,
            listen_peer_addr: Some(listen_peer_addr),
        };
        let join_resp =
            diorama_datastore::request_cluster_join(join_req.token.peer_addr, &join_req).await?;

        match join_resp {
            diorama_pki::token::JoinResponse::Controller(material) => assemble_joined_controller(
                config,
                config_path,
                host,
                node_ip,
                &node_name,
                listen_peer_addr,
                &material,
            ),
            diorama_pki::token::JoinResponse::Worker(material) => {
                assemble_joined_worker(config, config_path, host, &state_dir, &material)
            },
            diorama_pki::token::JoinResponse::Rejected(reason) => Err(RuntimeError::Io(
                io::Error::new(io::ErrorKind::PermissionDenied, reason),
            )),
        }
    }

    #[must_use]
    pub fn apiserver_bound_addr(&self) -> Option<SocketAddr> {
        self.apiserver.as_ref().and_then(|s| s.bound_addr())
    }

    #[must_use]
    pub fn pki_dir(&self) -> PathBuf {
        PathBuf::from(&self.config.config().path).join("pki")
    }

    #[must_use]
    pub fn observer(&self) -> LifecycleObserver {
        self.observer.clone()
    }

    /// Selects the CRI runtime provider based on node configuration.
    #[must_use]
    pub fn select_runtime_provider(&self) -> Option<Arc<dyn RuntimeProvider>> {
        select_runtime_provider(self.config.config())
    }

    /// Runs the supervised runtime until the stop receiver indicates shutdown.
    pub async fn run(self, control: StopReceiver) -> SupervisorReport {
        self.supervisor.run(control).await
    }

    /// Runs the runtime while streaming structured JSONL logs to a caller-owned sink.
    pub async fn run_with_sink<W>(
        self,
        control: StopReceiver,
        sink: W,
        flush_policy: FlushPolicy,
    ) -> (SupervisorReport, DeliveryReport, SinkReport)
    where
        W: Write + Send + 'static,
    {
        let Ok((sender, receiver)) = log_channel(64) else {
            unreachable!("64 is within valid queue capacity");
        };
        let logging_task = tokio::spawn(consume_lifecycle(
            self.observer,
            LifecycleRenderer::new(self.log_level),
            sender,
        ));
        let delivery_task = tokio::spawn(deliver_logs(receiver, sink, flush_policy));

        let report = self.supervisor.run(control).await;
        let delivery_report: DeliveryReport = logging_task.await.unwrap_or_default();
        let sink_report = match delivery_task.await {
            Ok(r) => r,
            Err(_) => SinkReport {
                written: 0,
                flushed_frames: 0,
                outcome: crate::lifecycle_sink::SinkOutcome::WorkerLost,
            },
        };

        (report, delivery_report, sink_report)
    }

    /// Runs the production node to completion, wiring Unix signals and delivering structured logs.
    pub async fn run_to_completion(self) -> io::Result<u8> {
        let (stop_handle, stop_receiver) = stop_channel();

        #[cfg(unix)]
        {
            let handle = stop_handle.clone();
            tokio::spawn(async move {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm = signal(SignalKind::terminate()).ok();
                let mut sigint = signal(SignalKind::interrupt()).ok();
                tokio::select! {
                    () = async {
                        if let Some(s) = sigterm.as_mut() {
                            s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {},
                    () = async {
                        if let Some(s) = sigint.as_mut() {
                            s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {},
                }
                handle.stop();
            });
        }

        let (report, _delivery, _sink) = self
            .run_with_sink(stop_receiver, io::stderr(), FlushPolicy::EachFrame)
            .await;

        Ok(runtime_exit_code(&report.cause))
    }
}

/// Selects the CRI runtime provider based on node configuration.
///
/// When an explicit containerd endpoint is configured in `runtime.endpoint`,
/// or if default managed socket exists (or fallback host socket exists),
/// returns a `CriRuntimeProvider` wrapped in an `Arc<dyn RuntimeProvider>`.
#[must_use]
pub fn select_runtime_provider(
    config: &diorama_config::Config,
) -> Option<Arc<dyn RuntimeProvider>> {
    let endpoint = config.runtime.endpoint.trim();
    let socket_path = if endpoint.is_empty() {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let managed = PathBuf::from(&config.path).join(if config.runtime.backend == "oci-cri" {
            "oci-cri/cri.sock"
        } else {
            "containerd/containerd.sock"
        });
        if managed.exists() || config.runtime.backend == "oci-cri" {
            managed
        } else {
            let host = PathBuf::from("/run/containerd/containerd.sock");
            if host.exists() {
                host
            } else {
                return None;
            }
        }
    } else {
        let stripped = endpoint.strip_prefix("unix://").unwrap_or(endpoint);
        PathBuf::from(stripped)
    };

    Some(Arc::new(CriRuntimeProvider::new(socket_path)))
}

fn register_operational_metrics(
    builder: RuntimeBuilder,
    datastore_cfg: &DatastoreConfig,
    pki_dir: &std::path::Path,
    timeout: std::time::Duration,
) -> RuntimeBuilder {
    if !builder.config().config().metrics.enabled {
        return builder;
    }
    let metrics_cfg = &builder.config().config().metrics;
    let registry = Arc::new(MetricsRegistry::new());
    registry.register(BuildInfoCollector::default());
    registry.register(UptimeCollector::new());
    registry.register(DatastoreCollector::with_wal(
        datastore_cfg.snapshot_path(),
        datastore_cfg.wal_path(),
    ));
    registry.register(CertificateCollector::new(
        pki_dir.to_path_buf(),
        builder.config().config().d2k.enabled,
    ));
    // Component health series require lifecycle updates; do not publish static zeros.
    let metrics_adapter = MetricsAdapter::new(metrics_cfg.bind_address.clone(), registry.clone());
    let metrics_reg = MetricsAdapter::registration(
        COMPONENT_METRICS,
        metrics_adapter,
        vec![COMPONENT_DATASTORE.to_string()],
        timeout,
    );
    builder
        .with_metrics_registry(registry)
        .register_component(metrics_reg)
}

/// Node address for PKI, the kubelet, and pod hostIP.
///
/// An empty or non-IPv4 `network.nodeIP` is auto-detected from `candidates`.
/// A valid explicit IPv4, including `127.0.0.1`, is kept. Detection with no
/// usable address falls back to loopback.
pub(crate) fn node_ip_for_config(
    configured: &str,
    candidates: &[diorama_network::InterfaceCandidate],
) -> IpAddr {
    match diorama_network::resolve_node_ip(Some(configured), candidates) {
        Ok((ip, _)) => IpAddr::V4(ip),
        Err(err) => {
            let reason = serde_json::to_string(&err.to_string())
                .unwrap_or_else(|_| "\"no usable IPv4 address\"".to_string());
            let _ = writeln!(
                io::stderr(),
                "{{\"schema\":1,\"level\":\"warn\",\"event\":\"node_ip_fallback\",\"detail_code\":\"{}\",\"reason\":{reason}}}",
                err.diagnostic_code()
            );
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        },
    }
}

fn initialize_pki(
    state_dir: &std::path::Path,
    config: &ValidatedConfig,
) -> Result<(IpAddr, PathBuf, String), RuntimeError> {
    let candidates = diorama_network::discover_host_interfaces();
    let node_ip = node_ip_for_config(&config.config().network.node_ip, &candidates);

    let node_name = if config.config().kubernetes.node_name.is_empty() {
        "diorama-node".to_string()
    } else {
        config.config().kubernetes.node_name.clone()
    };

    let pki_dir = state_dir.join("pki");
    std::fs::create_dir_all(&pki_dir)?;
    let pki_config = ClusterPkiConfig::new(pki_dir.clone(), node_name.clone(), node_ip);
    let pki = ClusterPki::new(pki_config);
    pki.reconcile()?;
    Ok((node_ip, pki_dir, node_name))
}

fn assemble_joined_controller(
    config: ValidatedConfig,
    config_path: PathBuf,
    host: diorama_config::HostContext,
    node_ip: IpAddr,
    node_name: &str,
    listen_peer_addr: SocketAddr,
    material: &diorama_pki::token::ControllerJoinMaterial,
) -> Result<NodeRuntime, RuntimeError> {
    let state_dir = PathBuf::from(&config.config().path);
    let pki_dir = state_dir.join("pki");
    ClusterPki::install_controller_join_material(&pki_dir, material)?;
    ClusterPki::new(ClusterPkiConfig::new(
        pki_dir.clone(),
        node_name.to_string(),
        node_ip,
    ))
    .reconcile()?;

    let datastore_dir = state_dir.join("datastore");
    std::fs::create_dir_all(&datastore_dir)?;
    let datastore_cfg = DatastoreConfig::new(datastore_dir)
        .with_client_tls(
            pki_dir.join("datastore-ca.crt"),
            pki_dir.join("datastore-server.crt"),
            pki_dir.join("datastore-server.key"),
        )
        .with_cluster(
            material.assigned_node_id,
            listen_peer_addr,
            material.peers.clone(),
        )
        .with_dynamic_join(true)
        .with_wal_repair(config.config().storage.db_wal_repair);

    let (engine, _) = DatastoreEngine::open(datastore_cfg.clone())?;
    let storage = KubernetesStorage::new(engine.client(), "/registry");

    let mut apiserver_cfg = ApiserverConfig::default_for_pki(&pki_dir, node_ip);
    apiserver_cfg.etcd_servers = vec!["https://127.0.0.1:2379".to_string()];
    apiserver_cfg.etcd_ca_file = Some(pki_dir.join("datastore-ca.crt"));
    apiserver_cfg.etcd_cert_file = Some(pki_dir.join("datastore-client.crt"));
    apiserver_cfg.etcd_key_file = Some(pki_dir.join("datastore-client.key"));

    let apiserver_service = Arc::new(ApiserverService::new(apiserver_cfg, storage));
    let client = apiserver_service.admin_client();

    let controller_cfg = ControllerManagerConfig::default_for_pki(&pki_dir, node_ip);
    let controller_service =
        ControllerManagerService::new(controller_cfg, apiserver_service.clone())
            .with_leader_election(node_name.to_string(), 15);

    let dns_service = CoreDnsService::new(CoreDnsConfig::new(), Arc::new(client.clone()));
    let policy = LifecyclePolicy::from_config(&config);
    let timeout = policy.startup_timeout();

    let datastore_adapter = DatastoreAdapter::from_engine(engine);
    let datastore_bound_handle = datastore_adapter.bound_addr_handle();
    let datastore_peer_handle = datastore_adapter.peer_bound_addr_handle();

    let mut builder = RuntimeBuilder::new(config)
        .with_apiserver(apiserver_service.clone())
        .with_client(client.clone())
        .with_datastore_bound_addr(datastore_bound_handle)
        .with_datastore_peer_bound_addr(datastore_peer_handle)
        .register_component(DatastoreAdapter::registration_with_adapter(
            COMPONENT_DATASTORE,
            datastore_adapter,
            timeout,
        ))
        .register_component(ApiserverAdapter::registration(
            COMPONENT_APISERVER,
            (*apiserver_service).clone(),
            vec![COMPONENT_DATASTORE.to_string()],
            timeout,
        ))
        .register_component(ControllerManagerAdapter::registration(
            COMPONENT_CONTROLLER_MANAGER,
            controller_service,
            vec![COMPONENT_APISERVER.to_string()],
            timeout,
        ));

    builder = register_workload_path(
        builder,
        WorkloadContext {
            state_dir: &state_dir,
            pki_dir: &pki_dir,
            node_name,
            node_ip,
            host: &host,
            apiserver_service: &apiserver_service,
            dns_service,
        },
    )?;
    builder = register_operational_metrics(builder, &datastore_cfg, &pki_dir, timeout);
    if builder.config().config().api.enabled {
        let socket_path = if builder.config().config().api.socket_path.is_empty() {
            state_dir.join("config.sock")
        } else {
            PathBuf::from(&builder.config().config().api.socket_path)
        };
        builder = builder.register_config_api(crate::config_api::ConfigApiServer::new(
            socket_path,
            config_path,
            host,
        ));
    }
    builder.build()
}

fn assemble_joined_worker(
    config: ValidatedConfig,
    config_path: PathBuf,
    host: diorama_config::HostContext,
    state_dir: &Path,
    material: &diorama_pki::token::WorkerJoinMaterial,
) -> Result<NodeRuntime, RuntimeError> {
    let pki_dir = state_dir.join("pki");
    ClusterPki::install_worker_join_material(&pki_dir, material)?;
    std::fs::write(state_dir.join(".cluster-role"), b"worker\n")?;

    let mut builder = RuntimeBuilder::new(config);
    if let Some((runtime_id, socket_path)) =
        detect_workload_runtime(builder.config().config(), state_dir)?
    {
        let mtu = u32::try_from(builder.config().config().network.mtu)
            .ok()
            .filter(|&m| m > 0)
            .unwrap_or(diorama_network::DEFAULT_MTU);
        builder = register_container_runtime(
            builder,
            state_dir,
            &socket_path,
            runtime_id,
            mtu,
            Some(diorama_network::DEFAULT_POD_CIDR),
        )?;
    }
    if builder.config().config().api.enabled {
        let socket_path = if builder.config().config().api.socket_path.is_empty() {
            state_dir.join("config.sock")
        } else {
            PathBuf::from(&builder.config().config().api.socket_path)
        };
        builder = builder.register_config_api(crate::config_api::ConfigApiServer::new(
            socket_path,
            config_path,
            host,
        ));
    }
    builder.build()
}

fn register_portainer_if_enabled(
    mut builder: RuntimeBuilder,
    client: KubernetesApiClient,
) -> RuntimeBuilder {
    let arch = match std::env::consts::ARCH {
        "aarch64" => diorama_platform::Architecture::Arm64,
        "arm" => diorama_platform::Architecture::ArmV7,
        "riscv64" => diorama_platform::Architecture::Riscv64,
        _ => diorama_platform::Architecture::Amd64,
    };
    let portainer_cfg =
        PortainerAgentConfig::from_diorama_config(&builder.config().config().portainer, arch);
    if portainer_cfg.is_enabled() {
        let portainer_service = PortainerService::new(portainer_cfg, Arc::new(client));
        builder =
            builder.register_portainer(portainer_service, vec![COMPONENT_APISERVER.to_string()]);
    }
    builder
}

struct WorkloadContext<'a> {
    state_dir: &'a Path,
    pki_dir: &'a Path,
    node_name: &'a str,
    node_ip: IpAddr,
    host: &'a diorama_config::HostContext,
    apiserver_service: &'a Arc<ApiserverService>,
    dns_service: CoreDnsService,
}

static PROBE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn is_dir_writable(dir: &Path) -> bool {
    if !dir.exists() && std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let count = PROBE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let probe_file = dir.join(format!(
        ".diorama_write_probe_{}_{}",
        std::process::id(),
        count
    ));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_file)
    {
        Ok(file) => {
            drop(file);
            let _ = std::fs::remove_file(&probe_file);
            true
        },
        Err(_) => false,
    }
}

fn detect_workload_runtime(
    config: &diorama_config::Config,
    state_dir: &Path,
) -> Result<Option<(&'static str, PathBuf)>, RuntimeError> {
    detect_workload_runtime_for_host(
        config,
        state_dir,
        cfg!(target_os = "linux"),
        cfg!(feature = "oci-cri"),
    )
}

fn detect_workload_runtime_for_host(
    config: &diorama_config::Config,
    state_dir: &Path,
    linux: bool,
    oci_enabled: bool,
) -> Result<Option<(&'static str, PathBuf)>, RuntimeError> {
    let invalid =
        |message| RuntimeError::from(io::Error::new(io::ErrorKind::InvalidInput, message));
    if matches!(config.runtime.backend.as_str(), "containerd" | "oci-cri")
        && !config.runtime.endpoint.trim().is_empty()
    {
        return Err(invalid(
            "managed runtime selection conflicts with runtime.endpoint",
        ));
    }
    if config.runtime.backend == "oci-cri" {
        if !linux {
            return Err(invalid("managed oci-cri requires Linux"));
        }
        if !oci_enabled {
            return Err(invalid(
                "managed oci-cri requires a build with --features oci-cri",
            ));
        }
        return Ok(Some(("oci-cri", state_dir.join("oci-cri/cri.sock"))));
    }
    if !linux {
        if config.runtime.backend == "containerd" {
            return Err(invalid("managed containerd requires Linux"));
        }
        return Ok(None);
    }
    let paths = ContainerdPaths::from_base(state_dir);
    if !config.runtime.endpoint.trim().is_empty() {
        let ep = config.runtime.endpoint.trim();
        let socket = ep.strip_prefix("unix://").unwrap_or(ep);
        Ok(Some((COMPONENT_EXTERNAL_CRI, PathBuf::from(socket))))
    } else if paths.binary_path.is_file() {
        Ok(Some((COMPONENT_CONTAINERD, paths.socket_path)))
    } else if config.runtime.backend == "containerd" {
        Err(invalid(
            "managed containerd binary is missing from the state directory",
        ))
    } else {
        Ok(None)
    }
}

fn register_container_runtime(
    builder: RuntimeBuilder,
    state_dir: &Path,
    socket_path: &Path,
    runtime_id: &str,
    mtu: u32,
    pod_cidr: Option<&str>,
) -> Result<RuntimeBuilder, RuntimeError> {
    let containerd_paths = ContainerdPaths::from_base(state_dir);
    let etc_cni = Path::new("/etc/cni/net.d");
    if runtime_id == "oci-cri" {
        #[cfg(feature = "oci-cri")]
        {
            let base = state_dir.join("oci-cri");
            let cni_conf = base.join("cni/net.d");
            let missing = diorama_network::warn_missing_cni_plugins(&containerd_paths.cni_bin_dir);
            if !missing.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("oci-cri CNI prerequisites: {}", missing.join("; ")),
                )
                .into());
            }
            std::fs::create_dir_all(&cni_conf)?;
            diorama_network::write_cni_config_file(
                &cni_conf.join(diorama_network::DEFAULT_CNI_CONFIG_NAME),
                mtu,
                pod_cidr,
            )?;
            let config = diorama_oci::Config {
                socket: socket_path.to_path_buf(),
                root: base.join("root"),
                state_root: base.join("state"),
                cni_bin_dir: Some(containerd_paths.cni_bin_dir),
                cni_conf_dir: Some(cni_conf),
                pod_cidr: pod_cidr.unwrap_or_default().to_string(),
                ..diorama_oci::Config::default()
            };
            let timeout = builder.policy.startup_timeout();
            return Ok(builder.register_oci_cri(diorama_oci::OciCriService::new(config, timeout)));
        }
        #[cfg(not(feature = "oci-cri"))]
        return Err(
            io::Error::new(io::ErrorKind::Unsupported, "oci-cri feature is disabled").into(),
        );
    }
    if runtime_id == COMPONENT_CONTAINERD {
        diorama_network::write_managed_cni_config(
            state_dir,
            mtu,
            pod_cidr,
            Some(containerd_paths.cni_conf_dir.as_path()),
        )?;
        if is_dir_writable(etc_cni) {
            diorama_network::write_managed_cni_config(state_dir, mtu, pod_cidr, None)?;
        }

        let image_config =
            ImageImportConfig::from_config(builder.config().config(), &containerd_paths.images_dir);
        let containerd_options = ContainerdServiceOptions::new(containerd_paths, image_config);
        let containerd_service = ContainerdService::new(containerd_options);
        Ok(builder.register_containerd(containerd_service))
    } else {
        let conf_target = if is_dir_writable(etc_cni) {
            etc_cni
        } else {
            containerd_paths.cni_conf_dir.as_path()
        };
        diorama_network::write_external_cni_config(conf_target, mtu, pod_cidr)?;

        let endpoint_str = format!("unix://{}", socket_path.display());
        let endpoints = RuntimeEndpoints::parse(&endpoint_str, None).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid CRI endpoint: {e}"),
            )
        })?;
        let cri_options = ExternalRuntimeOptions::new(endpoints);
        let cri_service = ExternalRuntimeService::new(cri_options);
        Ok(builder.register_external_cri(cri_service))
    }
}

fn register_workload_path(
    mut builder: RuntimeBuilder,
    ctx: WorkloadContext<'_>,
) -> Result<RuntimeBuilder, RuntimeError> {
    let detected_runtime = detect_workload_runtime(builder.config().config(), ctx.state_dir)?;

    if let Some((runtime_id, socket_path)) = detected_runtime {
        let mtu = u32::try_from(builder.config().config().network.mtu)
            .ok()
            .filter(|&m| m > 0)
            .unwrap_or(diorama_network::DEFAULT_MTU);
        let pod_cidr = Some(diorama_network::DEFAULT_POD_CIDR);

        builder = register_container_runtime(
            builder,
            ctx.state_dir,
            &socket_path,
            runtime_id,
            mtu,
            pod_cidr,
        )?;

        let proxy_kubeconfig = ctx.pki_dir.join("kube-proxy.kubeconfig");
        let is_container = builder
            .config()
            .config()
            .runtime
            .container_mode
            .unwrap_or(ctx.host.detected_container_mode);
        let executor = diorama_network::SystemCommandExecutor;
        let proxy_mode =
            diorama_proxy::detect_proxy_backend(None, &executor).unwrap_or(ProxyMode::IpTables);
        let proxy_opts = KubeProxyOptions::new(proxy_kubeconfig, is_container, proxy_mode);
        let proxy_service = ProxyService::new(proxy_opts)
            .with_client(Arc::new(ctx.apiserver_service.admin_client()));
        builder = builder.register_proxy(proxy_service);

        let kubelet_dir = ctx.state_dir.join("kubelet");
        std::fs::create_dir_all(&kubelet_dir)?;
        let mut kubelet_opts = KubeletConfigOptions::default_for_pki(
            ctx.pki_dir,
            ctx.node_name.to_string(),
            ctx.node_ip.to_string(),
            &kubelet_dir,
        );
        kubelet_opts.runtime_endpoint = format!("unix://{}", socket_path.display());
        kubelet_opts.container_mode = is_container;
        let runtime_provider: Arc<dyn RuntimeProvider> =
            Arc::new(CriRuntimeProvider::new(socket_path));
        let kubelet_service = KubeletService::new(
            kubelet_opts,
            ctx.apiserver_service.clone(),
            runtime_provider,
        );
        builder = builder.register_kubelet(kubelet_service, runtime_id);

        Ok(builder.register_coredns(
            ctx.dns_service,
            vec![
                COMPONENT_APISERVER.to_string(),
                COMPONENT_KUBELET.to_string(),
            ],
        ))
    } else {
        Ok(builder.register_coredns(ctx.dns_service, vec![COMPONENT_APISERVER.to_string()]))
    }
}

fn local_path_config(config: &diorama_config::Config, managed_containerd: bool) -> LocalPathConfig {
    let mut storage = LocalPathConfig::from_diorama_config(config);
    // Only managed containerd imports these archives. External runtimes and
    // oci-cri need the public image even when a containerd bundle is on disk.
    if managed_containerd {
        let images = ContainerdPaths::from_base(&config.path).images_dir;
        storage.provisioner_image = ImageImportConfig::from_config(config, images)
            .local_path_image()
            .into();
    }
    storage
}

fn runtime_exit_code(cause: &StopCause) -> u8 {
    u8::from(!matches!(cause, StopCause::Requested))
}

#[cfg(test)]
mod storage_config_tests {
    use super::*;

    #[test]
    fn storage_image_matches_the_selected_runtime_and_preserves_storage_settings() {
        let root = tempfile::tempdir().unwrap();
        let mut config = diorama_config::Config {
            path: root.path().to_str().unwrap().into(),
            ..Default::default()
        };
        config.storage.local_path.shared_path = "/shared/volumes".into();
        let public = "docker.io/rancher/local-path-provisioner:v0.0.36";
        for managed_containerd in [false, true] {
            let storage = local_path_config(&config, managed_containerd);
            assert_eq!(storage.provisioner_image, public);
            assert_eq!(
                storage.storage_path,
                root.path().join("local-path-storage").to_str().unwrap()
            );
            assert_eq!(storage.shared_path.as_deref(), Some("/shared/volumes"));
        }

        let images = ContainerdPaths::from_base(root.path()).images_dir;
        std::fs::create_dir_all(&images).unwrap();
        std::fs::write(
            images.join("local-path-provisioner.tar.gz"),
            b"bundled archive",
        )
        .unwrap();
        assert_eq!(
            local_path_config(&config, true).provisioner_image,
            diorama_containerd::image::BUNDLED_LOCAL_PATH_IMAGE
        );
        // A bundle on disk does not mean an external runtime or oci-cri loaded it.
        assert_eq!(local_path_config(&config, false).provisioner_image, public);
    }
}

#[cfg(test)]
mod exit_code_tests {
    use super::*;

    #[test]
    fn only_requested_shutdown_is_successful() {
        assert_eq!(runtime_exit_code(&StopCause::Requested), 0);
        assert_eq!(runtime_exit_code(&StopCause::ControlClosed), 1);
        assert_eq!(runtime_exit_code(&StopCause::Finished), 1);
        assert_eq!(
            runtime_exit_code(&StopCause::Fatal(diorama_supervisor::ComponentFailure {
                component: "test-core".into(),
                kind: diorama_supervisor::FailureKind::UnexpectedExit,
            })),
            1
        );
    }
}

#[cfg(test)]
mod node_ip_for_config_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use diorama_network::InterfaceCandidate;

    use super::node_ip_for_config;

    fn eth0(addr: Ipv4Addr) -> InterfaceCandidate {
        InterfaceCandidate::new("eth0", 1500, vec![IpAddr::V4(addr)])
    }

    fn loopback() -> InterfaceCandidate {
        InterfaceCandidate::new("lo", 65536, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
    }

    #[test]
    fn empty_config_uses_private_interface_address() {
        let ip = node_ip_for_config("", &[eth0(Ipv4Addr::new(10, 0, 2, 15)), loopback()]);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)));
    }

    #[test]
    fn explicit_config_wins_over_detected_address() {
        let ip = node_ip_for_config(
            "192.0.2.10",
            &[eth0(Ipv4Addr::new(10, 0, 2, 15)), loopback()],
        );
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[test]
    fn explicit_loopback_stays_loopback() {
        let ip = node_ip_for_config(
            "127.0.0.1",
            &[eth0(Ipv4Addr::new(10, 0, 2, 15)), loopback()],
        );
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn empty_config_with_only_loopback_stays_loopback() {
        let ip = node_ip_for_config("", &[loopback()]);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}

#[cfg(test)]
mod runtime_selection_tests {
    use super::*;

    #[test]
    fn explicit_oci_selection_checks_platform_feature_and_endpoint() {
        let mut config = diorama_config::Config::default();
        config.runtime.backend = "oci-cri".into();
        let base = Path::new("/test/node");
        assert!(detect_workload_runtime_for_host(&config, base, false, true).is_err());
        assert!(detect_workload_runtime_for_host(&config, base, true, false).is_err());
        assert_eq!(
            detect_workload_runtime_for_host(&config, base, true, true).unwrap(),
            Some(("oci-cri", base.join("oci-cri/cri.sock")))
        );
        config.runtime.endpoint = "/host/cri.sock".into();
        assert!(detect_workload_runtime_for_host(&config, base, true, true).is_err());
    }

    #[test]
    fn automatic_selection_preserves_external_and_containerd_behavior() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = diorama_config::Config::default();
        assert!(
            detect_workload_runtime_for_host(&config, dir.path(), true, true)
                .unwrap()
                .is_none()
        );
        config.runtime.backend = "containerd".into();
        assert!(detect_workload_runtime_for_host(&config, dir.path(), true, true).is_err());
        let paths = ContainerdPaths::from_base(dir.path());
        std::fs::create_dir_all(paths.binary_path.parent().unwrap()).unwrap();
        std::fs::write(&paths.binary_path, []).unwrap();
        assert_eq!(
            detect_workload_runtime_for_host(&config, dir.path(), true, true).unwrap(),
            Some((COMPONENT_CONTAINERD, paths.socket_path))
        );
        config.runtime.backend = "auto".into();
        config.runtime.endpoint = "unix:///host/cri.sock".into();
        assert_eq!(
            detect_workload_runtime_for_host(&config, dir.path(), true, true).unwrap(),
            Some((COMPONENT_EXTERNAL_CRI, PathBuf::from("/host/cri.sock")))
        );
    }
}
