use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ProxyError;

/// Protocol for service port definitions and dataplane routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

impl Protocol {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Sctp => "SCTP",
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("UDP") {
            Ok(Self::Udp)
        } else if s.eq_ignore_ascii_case("SCTP") {
            Ok(Self::Sctp)
        } else {
            Ok(Self::Tcp)
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Kubernetes Service type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    ClusterIP,
    NodePort,
    LoadBalancer,
    ExternalName,
}

/// Service port specification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServicePort {
    pub name: Option<String>,
    pub protocol: Protocol,
    pub port: u16,
    pub target_port: u16,
    pub node_port: Option<u16>,
}

/// Definition of a Kubernetes Service for dataplane routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub namespace: String,
    pub name: String,
    pub service_type: ServiceType,
    pub cluster_ip: Option<String>,
    pub ports: Vec<ServicePort>,
    /// `ClientIP` session affinity timeout; `None` when `sessionAffinity` is `None`.
    #[serde(default)]
    pub session_affinity_seconds: Option<u32>,
    /// `ExternalName` target if service type is `ExternalName`.
    #[serde(default)]
    pub external_name: Option<String>,
    /// Public/external `LoadBalancer` ingress IPs.
    #[serde(default)]
    pub load_balancer_ips: Vec<String>,
}

impl ServiceDefinition {
    #[must_use]
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        service_type: ServiceType,
        cluster_ip: Option<String>,
        ports: Vec<ServicePort>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            service_type,
            cluster_ip,
            ports,
            session_affinity_seconds: None,
            external_name: None,
            load_balancer_ips: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_session_affinity(mut self, timeout_seconds: Option<u32>) -> Self {
        self.session_affinity_seconds = timeout_seconds;
        self
    }

    #[must_use]
    pub fn with_external_name(mut self, external_name: impl Into<String>) -> Self {
        self.external_name = Some(external_name.into());
        self
    }

    #[must_use]
    pub fn with_load_balancer_ips(mut self, ips: Vec<String>) -> Self {
        self.load_balancer_ips = ips;
        self
    }

    #[must_use]
    pub fn namespaced_name(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

/// Key identifying a `HostPort` dataplane binding uniquely by `(host_ip, host_port, protocol)`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HostPortKey {
    pub host_ip: String,
    pub host_port: u16,
    pub protocol: Protocol,
}

impl HostPortKey {
    #[must_use]
    pub fn new(host_ip: impl Into<String>, host_port: u16, protocol: Protocol) -> Self {
        let ip = host_ip.into().trim().to_string();
        let ip = if ip.is_empty() {
            "0.0.0.0".to_string()
        } else {
            ip
        };
        Self {
            host_ip: ip,
            host_port,
            protocol,
        }
    }
}

/// Declared container or initContainer `HostPort` binding for dataplane rule generation and routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPortDefinition {
    pub pod_namespace: String,
    pub pod_name: String,
    pub host_ip: String,
    pub host_port: u16,
    pub protocol: Protocol,
    pub container_port: u16,
    pub pod_ip: String,
}

impl HostPortDefinition {
    #[must_use]
    pub fn new(
        pod_namespace: impl Into<String>,
        pod_name: impl Into<String>,
        host_ip: Option<&str>,
        host_port: u16,
        protocol: Option<Protocol>,
        container_port: u16,
        pod_ip: impl Into<String>,
    ) -> Self {
        let ip = host_ip.unwrap_or("").trim();
        let ip = if ip.is_empty() {
            "0.0.0.0".to_string()
        } else {
            ip.to_string()
        };
        Self {
            pod_namespace: pod_namespace.into(),
            pod_name: pod_name.into(),
            host_ip: ip,
            host_port,
            protocol: protocol.unwrap_or(Protocol::Tcp),
            container_port,
            pod_ip: pod_ip.into(),
        }
    }

    #[must_use]
    pub fn key(&self) -> HostPortKey {
        HostPortKey::new(&self.host_ip, self.host_port, self.protocol)
    }
}

/// Readiness and serving conditions for an endpoint in an `EndpointSlice`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointConditions {
    pub ready: Option<bool>,
    pub serving: Option<bool>,
    pub terminating: Option<bool>,
}

impl EndpointConditions {
    #[must_use]
    pub fn is_ready(&self) -> bool {
        // According to Kubernetes EndpointSlice API:
        // ready == true means the endpoint is ready to receive traffic.
        // If ready is None, it defaults to true only if serving is true or undefined and terminating is false.
        // If ready is explicitly Some(false), it MUST NOT receive traffic.
        match self.ready {
            Some(ready) => ready,
            None => {
                if self.terminating.unwrap_or(false) {
                    false
                } else {
                    self.serving.unwrap_or(true)
                }
            },
        }
    }
}

/// Endpoint item within an `EndpointSlice`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointItem {
    pub addresses: Vec<String>,
    pub conditions: EndpointConditions,
    pub node_name: Option<String>,
}

impl EndpointItem {
    #[must_use]
    pub fn new(addresses: Vec<String>, ready: bool, node_name: Option<String>) -> Self {
        Self {
            addresses,
            conditions: EndpointConditions {
                ready: Some(ready),
                serving: Some(ready),
                terminating: Some(false),
            },
            node_name,
        }
    }
}

/// Endpoint port in an `EndpointSlice`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointPort {
    pub name: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
}

/// Representation of an `EndpointSlice` resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointSliceDefinition {
    pub namespace: String,
    pub name: String,
    pub service_name: String,
    pub address_type: String,
    pub ports: Vec<EndpointPort>,
    pub endpoints: Vec<EndpointItem>,
}

impl EndpointSliceDefinition {
    #[must_use]
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        service_name: impl Into<String>,
        ports: Vec<EndpointPort>,
        endpoints: Vec<EndpointItem>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            service_name: service_name.into(),
            address_type: "IPv4".to_string(),
            ports,
            endpoints,
        }
    }
}

/// A resolved target backend endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TargetEndpoint {
    pub ip: String,
    pub port: u16,
    pub protocol: Protocol,
    pub node_name: Option<String>,
}

impl std::fmt::Display for TargetEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}/{}", self.ip, self.port, self.protocol)
    }
}

/// Session affinity map mapping `(client_ip, namespace, service_name)` to `(target_endpoint, creation_instant)`.
pub type AffinitySessionsMap =
    std::collections::HashMap<(String, String, String), (TargetEndpoint, std::time::Instant)>;

/// Shared handle to the session affinity cache.
pub type AffinitySessions = Arc<std::sync::Mutex<AffinitySessionsMap>>;

/// Dataplane service routing table tracking Services, `EndpointSlices`, and `HostPorts`.
#[derive(Clone, Debug, Default)]
pub struct ServiceRoutingTable {
    services: BTreeMap<(String, String), ServiceDefinition>,
    endpoint_slices: BTreeMap<(String, String), EndpointSliceDefinition>,
    host_ports: BTreeMap<(String, u16, Protocol), HostPortDefinition>,
    affinity_sessions: AffinitySessions,
    rr_counter: Arc<AtomicUsize>,
    generation: Arc<AtomicU64>,
}

impl ServiceRoutingTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            services: BTreeMap::new(),
            endpoint_slices: BTreeMap::new(),
            host_ports: BTreeMap::new(),
            affinity_sessions: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            rr_counter: Arc::new(AtomicUsize::new(0)),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns the current mutation generation counter of the routing table.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Registers or updates a Service in the routing table.
    pub fn apply_service(&mut self, service: ServiceDefinition) {
        let key = (service.namespace.clone(), service.name.clone());
        tracing::debug!(
            target: "kubeproxy::routing",
            namespace = %service.namespace,
            name = %service.name,
            cluster_ip = ?service.cluster_ip,
            "applying service to routing table"
        );
        if service.session_affinity_seconds.is_none()
            && let Ok(mut sessions) = self.affinity_sessions.lock()
        {
            sessions
                .retain(|(_, ns, name), _| !(ns == &service.namespace && name == &service.name));
        }
        self.services.insert(key, service);
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Removes a Service from the routing table.
    pub fn remove_service(&mut self, namespace: &str, name: &str) -> Option<ServiceDefinition> {
        tracing::debug!(
            target: "kubeproxy::routing",
            namespace = %namespace,
            name = %name,
            "removing service from routing table"
        );
        if let Ok(mut sessions) = self.affinity_sessions.lock() {
            sessions.retain(|(_, ns, n), _| !(ns == namespace && n == name));
        }
        let removed = self
            .services
            .remove(&(namespace.to_string(), name.to_string()));
        if removed.is_some() {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }
        removed
    }

    /// Registers or updates an `EndpointSlice` in the routing table.
    pub fn apply_endpoint_slice(&mut self, slice: EndpointSliceDefinition) {
        let key = (slice.namespace.clone(), slice.name.clone());
        tracing::debug!(
            target: "kubeproxy::routing",
            namespace = %slice.namespace,
            slice_name = %slice.name,
            service = %slice.service_name,
            endpoints_count = slice.endpoints.len(),
            "applying endpoint slice to routing table"
        );
        self.endpoint_slices.insert(key, slice);
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Removes an `EndpointSlice` from the routing table.
    pub fn remove_endpoint_slice(
        &mut self,
        namespace: &str,
        name: &str,
    ) -> Option<EndpointSliceDefinition> {
        tracing::debug!(
            target: "kubeproxy::routing",
            namespace = %namespace,
            slice_name = %name,
            "removing endpoint slice from routing table"
        );
        let removed = self
            .endpoint_slices
            .remove(&(namespace.to_string(), name.to_string()));
        if removed.is_some() {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }
        removed
    }

    /// Registers or updates a `HostPort` binding in the routing table.
    ///
    /// Keyed by `(host_ip, host_port, protocol)` defaulting `host_ip` to `0.0.0.0`
    /// and `protocol` to `TCP` if omitted, allowing Pods with same `host_port` on
    /// different `host_ip` or `protocol` (`TCP` vs `UDP` vs `SCTP`) to coexist without collision.
    pub fn apply_host_port(&mut self, hp: HostPortDefinition) {
        let key = (hp.host_ip.clone(), hp.host_port, hp.protocol);
        tracing::debug!(
            target: "kubeproxy::routing",
            pod = %format!("{}/{}", hp.pod_namespace, hp.pod_name),
            host_ip = %hp.host_ip,
            host_port = hp.host_port,
            protocol = %hp.protocol,
            target_pod_ip = %hp.pod_ip,
            container_port = hp.container_port,
            "applying hostport binding to routing table"
        );
        self.host_ports.insert(key, hp);
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Removes a `HostPort` binding from the routing table by `(host_ip, host_port, protocol)`.
    pub fn remove_host_port(
        &mut self,
        host_ip: &str,
        host_port: u16,
        protocol: Protocol,
    ) -> Option<HostPortDefinition> {
        let ip = host_ip.trim();
        let ip = if ip.is_empty() { "0.0.0.0" } else { ip };
        let removed = self
            .host_ports
            .remove(&(ip.to_string(), host_port, protocol));
        if removed.is_some() {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }
        removed
    }

    /// Removes all `HostPort` bindings associated with a specific Pod.
    pub fn remove_pod_host_ports(&mut self, namespace: &str, pod_name: &str) {
        let before_len = self.host_ports.len();
        self.host_ports
            .retain(|_, hp| !(hp.pod_namespace == namespace && hp.pod_name == pod_name));
        if self.host_ports.len() != before_len {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Lists all registered `HostPort` bindings.
    #[must_use]
    pub fn host_ports(&self) -> &BTreeMap<(String, u16, Protocol), HostPortDefinition> {
        &self.host_ports
    }

    /// Lists all registered services.
    #[must_use]
    pub fn services(&self) -> &BTreeMap<(String, String), ServiceDefinition> {
        &self.services
    }

    /// Lists all registered endpoint slices.
    #[must_use]
    pub fn endpoint_slices(&self) -> &BTreeMap<(String, String), EndpointSliceDefinition> {
        &self.endpoint_slices
    }

    /// Retrieves all ready target endpoints for a given service and port.
    pub fn get_ready_endpoints(
        &self,
        namespace: &str,
        service_name: &str,
        service_port: u16,
        protocol: Protocol,
    ) -> Result<Vec<TargetEndpoint>, ProxyError> {
        let svc_key = (namespace.to_string(), service_name.to_string());
        let service = self
            .services
            .get(&svc_key)
            .ok_or_else(|| ProxyError::Internal {
                reason: format!("service '{namespace}/{service_name}' not found in routing table"),
            })?;

        // Find matching port in service definition
        let port_spec = service
            .ports
            .iter()
            .find(|p| p.port == service_port && p.protocol == protocol)
            .ok_or_else(|| ProxyError::Internal {
                reason: format!(
                    "service '{namespace}/{service_name}' has no port {service_port}/{protocol}"
                ),
            })?;

        let mut ready_targets = Vec::new();

        // Search through endpoint slices matching this service
        for ((slice_ns, _), slice) in &self.endpoint_slices {
            if slice_ns != namespace || slice.service_name != service_name {
                continue;
            }

            // Determine target port from matching slice port, or skip slice
            let Some(slice_port) = slice.ports.iter().find(|p| {
                p.name == port_spec.name && p.protocol.unwrap_or(Protocol::Tcp) == protocol
            }) else {
                continue;
            };

            let ep_port = slice_port.port.unwrap_or(port_spec.target_port);

            for ep in &slice.endpoints {
                if !ep.conditions.is_ready() {
                    continue;
                }
                for addr in &ep.addresses {
                    ready_targets.push(TargetEndpoint {
                        ip: addr.clone(),
                        port: ep_port,
                        protocol,
                        node_name: ep.node_name.clone(),
                    });
                }
            }
        }

        if ready_targets.is_empty() {
            return Err(ProxyError::NoReadyEndpoints {
                service: format!("{namespace}/{service_name}:{service_port}/{protocol}"),
            });
        }

        // Sort for deterministic ordering before load-balancing
        ready_targets.sort_by(|a, b| (&a.ip, a.port).cmp(&(&b.ip, b.port)));
        Ok(ready_targets)
    }

    /// Resolves traffic directed to a `ClusterIP` to a ready backend endpoint with optional `client_ip` session affinity.
    pub fn route_cluster_ip_with_client(
        &self,
        client_ip: Option<&str>,
        cluster_ip: &str,
        dport: u16,
        protocol: Protocol,
    ) -> Result<TargetEndpoint, ProxyError> {
        // Locate matching Service by cluster_ip and port, or by matching LoadBalancer IP
        let mut matched_svc = None;
        for svc in self.services.values() {
            let matches_ip = svc.cluster_ip.as_deref() == Some(cluster_ip)
                || svc.load_balancer_ips.iter().any(|ip| ip == cluster_ip);
            if matches_ip
                && svc
                    .ports
                    .iter()
                    .any(|p| p.port == dport && p.protocol == protocol)
            {
                matched_svc = Some(svc);
                break;
            }
        }

        let svc = matched_svc.ok_or_else(|| ProxyError::Internal {
            reason: format!("no service found matching cluster IP {cluster_ip}:{dport}/{protocol}"),
        })?;

        let endpoints = self.get_ready_endpoints(&svc.namespace, &svc.name, dport, protocol)?;

        // Session affinity (ClientIP) evaluation
        if let (Some(c_ip), Some(timeout_secs)) = (client_ip, svc.session_affinity_seconds) {
            let session_key = (c_ip.to_string(), svc.namespace.clone(), svc.name.clone());
            if let Ok(mut sessions) = self.affinity_sessions.lock() {
                if let Some((target, _)) = sessions.get(&session_key).filter(|(target, instant)| {
                    instant.elapsed().as_secs() <= u64::from(timeout_secs)
                        && endpoints.contains(target)
                }) {
                    return Ok(target.clone());
                }
                // Miss or expired: select new endpoint and record affinity session
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % endpoints.len();
                let selected = endpoints[idx].clone();
                sessions.insert(session_key, (selected.clone(), std::time::Instant::now()));
                return Ok(selected);
            }
        }

        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % endpoints.len();
        Ok(endpoints[idx].clone())
    }

    /// Resolves traffic directed to a `ClusterIP` to a ready backend endpoint.
    pub fn route_cluster_ip(
        &self,
        cluster_ip: &str,
        dport: u16,
        protocol: Protocol,
    ) -> Result<TargetEndpoint, ProxyError> {
        self.route_cluster_ip_with_client(None, cluster_ip, dport, protocol)
    }

    /// Resolves traffic directed to a `NodePort` to a ready backend endpoint with optional `client_ip` session affinity.
    pub fn route_node_port_with_client(
        &self,
        client_ip: Option<&str>,
        node_port: u16,
        protocol: Protocol,
    ) -> Result<TargetEndpoint, ProxyError> {
        // Locate matching Service by node_port
        let mut matched_svc = None;
        let mut matched_port = None;

        for svc in self.services.values() {
            for port in &svc.ports {
                if port.node_port == Some(node_port) && port.protocol == protocol {
                    matched_svc = Some(svc);
                    matched_port = Some(port.port);
                    break;
                }
            }
            if matched_svc.is_some() {
                break;
            }
        }

        let (Some(svc), Some(svc_port)) = (matched_svc, matched_port) else {
            return Err(ProxyError::Internal {
                reason: format!("no service found matching NodePort {node_port}/{protocol}"),
            });
        };

        let endpoints = self.get_ready_endpoints(&svc.namespace, &svc.name, svc_port, protocol)?;

        if let (Some(c_ip), Some(timeout_secs)) = (client_ip, svc.session_affinity_seconds) {
            let session_key = (c_ip.to_string(), svc.namespace.clone(), svc.name.clone());
            if let Ok(mut sessions) = self.affinity_sessions.lock() {
                if let Some((target, _)) = sessions.get(&session_key).filter(|(target, instant)| {
                    instant.elapsed().as_secs() <= u64::from(timeout_secs)
                        && endpoints.contains(target)
                }) {
                    return Ok(target.clone());
                }
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % endpoints.len();
                let selected = endpoints[idx].clone();
                sessions.insert(session_key, (selected.clone(), std::time::Instant::now()));
                return Ok(selected);
            }
        }

        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % endpoints.len();
        Ok(endpoints[idx].clone())
    }

    /// Resolves traffic directed to a `NodePort` to a ready backend endpoint.
    pub fn route_node_port(
        &self,
        node_port: u16,
        protocol: Protocol,
    ) -> Result<TargetEndpoint, ProxyError> {
        self.route_node_port_with_client(None, node_port, protocol)
    }

    /// Resolves traffic directed to a `HostPort` to the mapped container backend endpoint.
    ///
    /// First searches for an exact `(host_ip, host_port, protocol)` match.
    /// If not found and `host_ip != "0.0.0.0"`, falls back to checking wildcard `("0.0.0.0", host_port, protocol)`.
    pub fn route_host_port(
        &self,
        host_ip: &str,
        host_port: u16,
        protocol: Protocol,
    ) -> Result<TargetEndpoint, ProxyError> {
        let ip = host_ip.trim();
        let normalized_ip = if ip.is_empty() { "0.0.0.0" } else { ip };

        if let Some(hp) = self
            .host_ports
            .get(&(normalized_ip.to_string(), host_port, protocol))
        {
            return Ok(TargetEndpoint {
                ip: hp.pod_ip.clone(),
                port: hp.container_port,
                protocol: hp.protocol,
                node_name: None,
            });
        }

        if normalized_ip != "0.0.0.0"
            && let Some(hp) = self
                .host_ports
                .get(&("0.0.0.0".to_string(), host_port, protocol))
        {
            return Ok(TargetEndpoint {
                ip: hp.pod_ip.clone(),
                port: hp.container_port,
                protocol: hp.protocol,
                node_name: None,
            });
        }

        Err(ProxyError::Internal {
            reason: format!(
                "no hostport binding found matching {normalized_ip}:{host_port}/{protocol}"
            ),
        })
    }

    /// Resolves packet routing across `ClusterIP`, `LoadBalancer`, `NodePort`, or `HostPort` destinations with optional `client_ip`.
    pub fn route_packet_with_client(
        &self,
        client_ip: Option<&str>,
        dst_ip: &str,
        dst_port: u16,
        protocol: Protocol,
    ) -> Result<TargetEndpoint, ProxyError> {
        let is_cluster_or_lb_ip = self.services.values().any(|s| {
            s.cluster_ip.as_deref() == Some(dst_ip)
                || s.load_balancer_ips.iter().any(|ip| ip == dst_ip)
        });

        if is_cluster_or_lb_ip {
            return self.route_cluster_ip_with_client(client_ip, dst_ip, dst_port, protocol);
        }

        // Try NodePort routing
        if let Ok(ep) = self.route_node_port_with_client(client_ip, dst_port, protocol) {
            return Ok(ep);
        }

        // Try HostPort routing
        self.route_host_port(dst_ip, dst_port, protocol)
    }

    /// Resolves packet routing for `ClusterIP`, `NodePort`, or `HostPort` destinations.
    pub fn route_packet(
        &self,
        dst_ip: &str,
        dst_port: u16,
        protocol: Protocol,
    ) -> Result<TargetEndpoint, ProxyError> {
        self.route_packet_with_client(None, dst_ip, dst_port, protocol)
    }
}

/// Extracts `(namespace, name)` from a datastore key path (e.g. `/registry/services/default/my-svc`).
#[must_use]
pub fn extract_namespace_and_name_from_key(key: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = key.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 2 {
        let name = parts[parts.len() - 1].to_string();
        let namespace = parts[parts.len() - 2].to_string();
        Some((namespace, name))
    } else {
        None
    }
}

/// Parses a `ServiceDefinition` from a Kubernetes `Service` JSON value.
#[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
pub fn service_from_value(val: &Value) -> Result<ServiceDefinition, ProxyError> {
    let metadata = val.get("metadata").ok_or_else(|| ProxyError::Internal {
        reason: "Service missing metadata".to_string(),
    })?;
    let name = metadata
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ProxyError::Internal {
            reason: "Service missing metadata.name".to_string(),
        })?
        .to_string();
    let namespace = metadata
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();

    let spec = val.get("spec").ok_or_else(|| ProxyError::Internal {
        reason: format!("Service {namespace}/{name} missing spec"),
    })?;

    let svc_type_str = spec
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("ClusterIP");

    let service_type = match svc_type_str {
        "NodePort" => ServiceType::NodePort,
        "LoadBalancer" => ServiceType::LoadBalancer,
        "ExternalName" => ServiceType::ExternalName,
        _ => ServiceType::ClusterIP,
    };

    let cluster_ip = spec
        .get("clusterIP")
        .and_then(Value::as_str)
        .and_then(|ip| {
            if ip.is_empty() || ip == "None" {
                None
            } else {
                Some(ip.to_string())
            }
        });

    let external_name = spec
        .get("externalName")
        .and_then(Value::as_str)
        .map(ToString::to_string);

    let mut load_balancer_ips = Vec::new();
    if let Some(ingress) = val
        .pointer("/status/loadBalancer/ingress")
        .and_then(Value::as_array)
    {
        for ing in ingress {
            let Some(ip) = ing.get("ip").and_then(Value::as_str) else {
                continue;
            };
            if !load_balancer_ips.contains(&ip.to_string()) {
                load_balancer_ips.push(ip.to_string());
            }
        }
    }
    let lb_ip = spec
        .get("loadBalancerIP")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !lb_ip.is_empty() && !load_balancer_ips.contains(&lb_ip.to_string()) {
        load_balancer_ips.push(lb_ip.to_string());
    }
    if let Some(ext_ips) = spec.get("externalIPs").and_then(Value::as_array) {
        for ip_val in ext_ips {
            let Some(ip) = ip_val.as_str() else {
                continue;
            };
            if !load_balancer_ips.contains(&ip.to_string()) {
                load_balancer_ips.push(ip.to_string());
            }
        }
    }

    let mut ports = Vec::new();
    if let Some(ports_arr) = spec.get("ports").and_then(Value::as_array) {
        for p in ports_arr {
            let port_num =
                p.get("port")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| ProxyError::Internal {
                        reason: format!("Service {namespace}/{name} port missing port number"),
                    })? as u16;

            let protocol = match p.get("protocol").and_then(Value::as_str) {
                Some(s) if s.eq_ignore_ascii_case("UDP") => Protocol::Udp,
                Some(s) if s.eq_ignore_ascii_case("SCTP") => Protocol::Sctp,
                _ => Protocol::Tcp,
            };

            let name = p
                .get("name")
                .and_then(Value::as_str)
                .map(ToString::to_string);

            let target_port = if let Some(tp) = p.get("targetPort") {
                if let Some(num) = tp.as_u64() {
                    num as u16
                } else if let Some(s) = tp.as_str() {
                    s.parse::<u16>().unwrap_or(port_num)
                } else {
                    port_num
                }
            } else {
                port_num
            };

            let node_port = p
                .get("nodePort")
                .and_then(Value::as_u64)
                .map(|np| np as u16);

            ports.push(ServicePort {
                name,
                protocol,
                port: port_num,
                target_port,
                node_port,
            });
        }
    }

    let session_affinity_seconds =
        (spec.get("sessionAffinity").and_then(Value::as_str) == Some("ClientIP")).then(|| {
            spec.pointer("/sessionAffinityConfig/clientIP/timeoutSeconds")
                .and_then(Value::as_u64)
                .and_then(|t| u32::try_from(t).ok())
                .filter(|t| *t > 0)
                .unwrap_or(10_800)
        });

    Ok(ServiceDefinition {
        namespace,
        name,
        service_type,
        cluster_ip,
        ports,
        session_affinity_seconds,
        external_name,
        load_balancer_ips,
    })
}

/// Parses an `EndpointSliceDefinition` from a Kubernetes `EndpointSlice` JSON value.
#[allow(clippy::cast_possible_truncation)]
pub fn endpoint_slice_from_value(val: &Value) -> Result<EndpointSliceDefinition, ProxyError> {
    let metadata = val.get("metadata").ok_or_else(|| ProxyError::Internal {
        reason: "EndpointSlice missing metadata".to_string(),
    })?;
    let name = metadata
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ProxyError::Internal {
            reason: "EndpointSlice missing metadata.name".to_string(),
        })?
        .to_string();
    let namespace = metadata
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();

    let service_name = metadata
        .get("labels")
        .and_then(|l| l.get("kubernetes.io/service-name"))
        .and_then(Value::as_str)
        .map_or_else(|| name.clone(), ToString::to_string);

    let address_type = val
        .get("addressType")
        .and_then(Value::as_str)
        .unwrap_or("IPv4")
        .to_string();

    let mut ports = Vec::new();
    if let Some(ports_arr) = val.get("ports").and_then(Value::as_array) {
        for p in ports_arr {
            let port_name = p
                .get("name")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let port = p.get("port").and_then(Value::as_u64).map(|p| p as u16);
            let protocol = p.get("protocol").and_then(Value::as_str).map(|pr| {
                if pr.eq_ignore_ascii_case("UDP") {
                    Protocol::Udp
                } else if pr.eq_ignore_ascii_case("SCTP") {
                    Protocol::Sctp
                } else {
                    Protocol::Tcp
                }
            });
            ports.push(EndpointPort {
                name: port_name,
                port,
                protocol,
            });
        }
    }

    let mut endpoints = Vec::new();
    if let Some(endpoints_arr) = val.get("endpoints").and_then(Value::as_array) {
        for ep in endpoints_arr {
            let addresses = ep
                .get("addresses")
                .and_then(Value::as_array)
                .map(|addrs| {
                    addrs
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default();

            let conditions = if let Some(cond) = ep.get("conditions") {
                let ready = cond.get("ready").and_then(Value::as_bool);
                let serving = cond.get("serving").and_then(Value::as_bool);
                let terminating = cond.get("terminating").and_then(Value::as_bool);
                EndpointConditions {
                    ready,
                    serving,
                    terminating,
                }
            } else {
                EndpointConditions::default()
            };

            let node_name = ep
                .get("nodeName")
                .and_then(Value::as_str)
                .map(ToString::to_string);

            endpoints.push(EndpointItem {
                addresses,
                conditions,
                node_name,
            });
        }
    }

    Ok(EndpointSliceDefinition {
        namespace,
        name,
        service_name,
        address_type,
        ports,
        endpoints,
    })
}

/// Extracts declared `HostPortDefinition`s from a Kubernetes `Pod` JSON value.
///
/// Keys hostPorts by `(host_ip, host_port, protocol)` defaulting `host_ip` to `0.0.0.0`
/// and `protocol` to `TCP` when omitted. Supports `TCP`, `UDP`, and `SCTP` protocols across
/// both regular `containers` and `initContainers`.
#[allow(clippy::cast_possible_truncation)]
pub fn host_ports_from_pod_value(val: &Value) -> Vec<HostPortDefinition> {
    let mut results = Vec::new();
    let Some(metadata) = val.get("metadata") else {
        return results;
    };
    let pod_name = metadata
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let pod_namespace = metadata
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();
    let pod_ip = val
        .pointer("/status/podIP")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let Some(spec) = val.get("spec") else {
        return results;
    };

    let mut extract_ports = |containers: &[Value]| {
        for c in containers {
            let Some(ports) = c.get("ports").and_then(Value::as_array) else {
                continue;
            };
            for p in ports {
                let Some(hp_num) = p.get("hostPort").and_then(Value::as_u64) else {
                    continue;
                };
                if hp_num == 0 || hp_num > 65535 {
                    continue;
                }
                let host_port = hp_num as u16;

                let container_port = p
                    .get("containerPort")
                    .and_then(Value::as_u64)
                    .map_or(host_port, |cp| cp as u16);

                let host_ip_str = p.get("hostIP").and_then(Value::as_str).unwrap_or("").trim();
                let host_ip = if host_ip_str.is_empty() {
                    "0.0.0.0".to_string()
                } else {
                    host_ip_str.to_string()
                };

                let protocol = match p.get("protocol").and_then(Value::as_str) {
                    Some(s) if s.eq_ignore_ascii_case("UDP") => Protocol::Udp,
                    Some(s) if s.eq_ignore_ascii_case("SCTP") => Protocol::Sctp,
                    _ => Protocol::Tcp,
                };

                results.push(HostPortDefinition {
                    pod_namespace: pod_namespace.clone(),
                    pod_name: pod_name.clone(),
                    host_ip,
                    host_port,
                    protocol,
                    container_port,
                    pod_ip: pod_ip.clone(),
                });
            }
        }
    };

    if let Some(containers) = spec.get("containers").and_then(Value::as_array) {
        extract_ports(containers);
    }
    if let Some(init_containers) = spec.get("initContainers").and_then(Value::as_array) {
        extract_ports(init_containers);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_namespace_and_name() {
        assert_eq!(
            extract_namespace_and_name_from_key("/registry/services/default/kubernetes"),
            Some(("default".to_string(), "kubernetes".to_string()))
        );
        assert_eq!(
            extract_namespace_and_name_from_key(
                "/registry/discovery.k8s.io/endpointslices/kube-system/coredns-abc"
            ),
            Some(("kube-system".to_string(), "coredns-abc".to_string()))
        );
        assert_eq!(extract_namespace_and_name_from_key("single"), None);
    }

    #[test]
    fn test_service_from_value() {
        let val = json!({
            "metadata": {
                "name": "my-service",
                "namespace": "test-ns"
            },
            "spec": {
                "type": "ClusterIP",
                "clusterIP": "10.96.0.100",
                "ports": [
                    {
                        "name": "http",
                        "port": 80,
                        "targetPort": 8080,
                        "protocol": "TCP"
                    }
                ]
            }
        });

        let svc = service_from_value(&val).expect("parse service");
        assert_eq!(svc.name, "my-service");
        assert_eq!(svc.namespace, "test-ns");
        assert_eq!(svc.service_type, ServiceType::ClusterIP);
        assert_eq!(svc.cluster_ip.as_deref(), Some("10.96.0.100"));
        assert_eq!(svc.ports.len(), 1);
        assert_eq!(svc.ports[0].port, 80);
        assert_eq!(svc.ports[0].target_port, 8080);
    }

    #[test]
    fn test_endpoint_slice_from_value() {
        let val = json!({
            "metadata": {
                "name": "my-service-slice",
                "namespace": "test-ns",
                "labels": {
                    "kubernetes.io/service-name": "my-service"
                }
            },
            "addressType": "IPv4",
            "ports": [
                {
                    "name": "http",
                    "port": 8080,
                    "protocol": "TCP"
                }
            ],
            "endpoints": [
                {
                    "addresses": ["10.244.0.5"],
                    "conditions": {
                        "ready": true
                    },
                    "nodeName": "node-1"
                }
            ]
        });

        let slice = endpoint_slice_from_value(&val).expect("parse slice");
        assert_eq!(slice.name, "my-service-slice");
        assert_eq!(slice.service_name, "my-service");
        assert_eq!(slice.namespace, "test-ns");
        assert_eq!(slice.endpoints.len(), 1);
        assert_eq!(slice.endpoints[0].addresses, vec!["10.244.0.5"]);
        assert!(slice.endpoints[0].conditions.is_ready());
    }

    #[test]
    fn test_hostport_coexistence_and_routing() {
        let mut table = ServiceRoutingTable::new();

        // Pod 1: HostPort 8080, TCP, hostIP 10.0.0.1 -> target container 80, pod IP 10.244.1.5
        let hp1 = HostPortDefinition::new(
            "default",
            "pod-tcp-ip1",
            Some("10.0.0.1"),
            8080,
            Some(Protocol::Tcp),
            80,
            "10.244.1.5",
        );
        // Pod 2: HostPort 8080, TCP, hostIP 10.0.0.2 -> target container 80, pod IP 10.244.1.6
        let hp2 = HostPortDefinition::new(
            "default",
            "pod-tcp-ip2",
            Some("10.0.0.2"),
            8080,
            Some(Protocol::Tcp),
            80,
            "10.244.1.6",
        );
        // Pod 3: HostPort 8080, UDP, hostIP 10.0.0.1 -> target container 80, pod IP 10.244.1.7
        let hp3 = HostPortDefinition::new(
            "default",
            "pod-udp-ip1",
            Some("10.0.0.1"),
            8080,
            Some(Protocol::Udp),
            80,
            "10.244.1.7",
        );
        // Pod 4: HostPort 8080, SCTP, wildcard hostIP (0.0.0.0) -> target container 80, pod IP 10.244.1.8
        let hp4 = HostPortDefinition::new(
            "default",
            "pod-sctp-wildcard",
            None,
            8080,
            Some(Protocol::Sctp),
            80,
            "10.244.1.8",
        );

        table.apply_host_port(hp1);
        table.apply_host_port(hp2);
        table.apply_host_port(hp3);
        table.apply_host_port(hp4);

        assert_eq!(table.host_ports().len(), 4);

        // Verify routing to each pod without collision
        let route1 = table
            .route_host_port("10.0.0.1", 8080, Protocol::Tcp)
            .unwrap();
        assert_eq!(route1.ip, "10.244.1.5");
        assert_eq!(route1.protocol, Protocol::Tcp);

        let route2 = table
            .route_host_port("10.0.0.2", 8080, Protocol::Tcp)
            .unwrap();
        assert_eq!(route2.ip, "10.244.1.6");
        assert_eq!(route2.protocol, Protocol::Tcp);

        let route3 = table
            .route_host_port("10.0.0.1", 8080, Protocol::Udp)
            .unwrap();
        assert_eq!(route3.ip, "10.244.1.7");
        assert_eq!(route3.protocol, Protocol::Udp);

        let route4 = table
            .route_host_port("10.0.0.3", 8080, Protocol::Sctp)
            .unwrap();
        assert_eq!(route4.ip, "10.244.1.8");
        assert_eq!(route4.protocol, Protocol::Sctp);
    }

    #[test]
    fn test_host_ports_from_pod_value() {
        let pod_val = json!({
            "metadata": {
                "name": "multi-hp-pod",
                "namespace": "prod"
            },
            "status": {
                "podIP": "10.244.3.15"
            },
            "spec": {
                "containers": [
                    {
                        "name": "c1",
                        "ports": [
                            {
                                "hostPort": 8080,
                                "containerPort": 80,
                                "protocol": "TCP",
                                "hostIP": "192.168.1.100"
                            },
                            {
                                "hostPort": 8080,
                                "containerPort": 80,
                                "protocol": "UDP"
                            }
                        ]
                    }
                ],
                "initContainers": [
                    {
                        "name": "init-c",
                        "ports": [
                            {
                                "hostPort": 9090,
                                "protocol": "SCTP"
                            }
                        ]
                    }
                ]
            }
        });

        let hps = host_ports_from_pod_value(&pod_val);
        assert_eq!(hps.len(), 3);

        assert_eq!(hps[0].host_ip, "192.168.1.100");
        assert_eq!(hps[0].host_port, 8080);
        assert_eq!(hps[0].protocol, Protocol::Tcp);
        assert_eq!(hps[0].container_port, 80);
        assert_eq!(hps[0].pod_ip, "10.244.3.15");

        // Omitted hostIP defaults to 0.0.0.0
        assert_eq!(hps[1].host_ip, "0.0.0.0");
        assert_eq!(hps[1].host_port, 8080);
        assert_eq!(hps[1].protocol, Protocol::Udp);

        // SCTP in initContainer, containerPort defaults to hostPort
        assert_eq!(hps[2].host_port, 9090);
        assert_eq!(hps[2].container_port, 9090);
        assert_eq!(hps[2].protocol, Protocol::Sctp);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_session_affinity_switching() {
        let mut table = ServiceRoutingTable::new();

        let svc = ServiceDefinition::new(
            "default",
            "affine-svc",
            ServiceType::ClusterIP,
            Some("10.96.10.10".to_string()),
            vec![ServicePort {
                name: Some("http".to_string()),
                protocol: Protocol::Tcp,
                port: 80,
                target_port: 8080,
                node_port: None,
            }],
        )
        .with_session_affinity(Some(10800));
        table.apply_service(svc);

        let slice = EndpointSliceDefinition::new(
            "default",
            "affine-slice",
            "affine-svc",
            vec![EndpointPort {
                name: Some("http".to_string()),
                port: Some(8080),
                protocol: Some(Protocol::Tcp),
            }],
            vec![
                EndpointItem::new(vec!["10.244.0.1".to_string()], true, None),
                EndpointItem::new(vec!["10.244.0.2".to_string()], true, None),
                EndpointItem::new(vec!["10.244.0.3".to_string()], true, None),
            ],
        );
        table.apply_endpoint_slice(slice);

        // 1. Client A sends consecutive requests -> all must route to the SAME endpoint
        let first = table
            .route_cluster_ip_with_client(Some("192.168.1.50"), "10.96.10.10", 80, Protocol::Tcp)
            .unwrap();
        for _ in 0..5 {
            let next = table
                .route_cluster_ip_with_client(
                    Some("192.168.1.50"),
                    "10.96.10.10",
                    80,
                    Protocol::Tcp,
                )
                .unwrap();
            assert_eq!(
                first.ip, next.ip,
                "Consecutive requests with ClientIP affinity must reach the same endpoint"
            );
        }

        // 2. Switch sessionAffinity to None
        let mut svc_none = ServiceDefinition::new(
            "default",
            "affine-svc",
            ServiceType::ClusterIP,
            Some("10.96.10.10".to_string()),
            vec![ServicePort {
                name: Some("http".to_string()),
                protocol: Protocol::Tcp,
                port: 80,
                target_port: 8080,
                node_port: None,
            }],
        );
        svc_none.session_affinity_seconds = None;
        table.apply_service(svc_none);

        // When affinity is None, requests round-robin across replicas
        let mut hit_ips = std::collections::HashSet::new();
        for _ in 0..6 {
            let ep = table
                .route_cluster_ip_with_client(
                    Some("192.168.1.50"),
                    "10.96.10.10",
                    80,
                    Protocol::Tcp,
                )
                .unwrap();
            hit_ips.insert(ep.ip);
        }
        assert!(
            hit_ips.len() > 1,
            "With sessionAffinity=None, multiple endpoints must be reached"
        );

        // 3. Switch back to ClientIP
        let svc_back = ServiceDefinition::new(
            "default",
            "affine-svc",
            ServiceType::ClusterIP,
            Some("10.96.10.10".to_string()),
            vec![ServicePort {
                name: Some("http".to_string()),
                protocol: Protocol::Tcp,
                port: 80,
                target_port: 8080,
                node_port: None,
            }],
        )
        .with_session_affinity(Some(10800));
        table.apply_service(svc_back);

        let restored_first = table
            .route_cluster_ip_with_client(Some("192.168.1.50"), "10.96.10.10", 80, Protocol::Tcp)
            .unwrap();
        for _ in 0..5 {
            let next = table
                .route_cluster_ip_with_client(
                    Some("192.168.1.50"),
                    "10.96.10.10",
                    80,
                    Protocol::Tcp,
                )
                .unwrap();
            assert_eq!(
                restored_first.ip, next.ip,
                "Restored ClientIP affinity must maintain consistent target"
            );
        }
    }
}
