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
}

impl Protocol {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
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
        }
    }

    #[must_use]
    pub fn namespaced_name(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
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

/// Dataplane service routing table tracking Services and `EndpointSlices`.
#[derive(Clone, Debug, Default)]
pub struct ServiceRoutingTable {
    services: BTreeMap<(String, String), ServiceDefinition>,
    endpoint_slices: BTreeMap<(String, String), EndpointSliceDefinition>,
    rr_counter: Arc<AtomicUsize>,
    generation: Arc<AtomicU64>,
}

impl ServiceRoutingTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            services: BTreeMap::new(),
            endpoint_slices: BTreeMap::new(),
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

    /// Resolves traffic directed to a `ClusterIP` to a ready backend endpoint.
    pub fn route_cluster_ip(
        &self,
        cluster_ip: &str,
        dport: u16,
        protocol: Protocol,
    ) -> Result<TargetEndpoint, ProxyError> {
        // Locate matching Service by cluster_ip and port
        let mut matched_svc = None;
        for svc in self.services.values() {
            if svc.cluster_ip.as_deref() == Some(cluster_ip)
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
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % endpoints.len();
        Ok(endpoints[idx].clone())
    }

    /// Resolves traffic directed to a `NodePort` to a ready backend endpoint.
    pub fn route_node_port(
        &self,
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
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % endpoints.len();
        Ok(endpoints[idx].clone())
    }

    /// Resolves packet routing for either `ClusterIP` or `NodePort` destinations.
    pub fn route_packet(
        &self,
        dst_ip: &str,
        dst_port: u16,
        protocol: Protocol,
    ) -> Result<TargetEndpoint, ProxyError> {
        let is_cluster_ip = self
            .services
            .values()
            .any(|s| s.cluster_ip.as_deref() == Some(dst_ip));

        if is_cluster_ip {
            return self.route_cluster_ip(dst_ip, dst_port, protocol);
        }

        // Second try NodePort routing
        self.route_node_port(dst_port, protocol)
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
#[allow(clippy::cast_possible_truncation)]
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
                Some("UDP") => Protocol::Udp,
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

    Ok(ServiceDefinition {
        namespace,
        name,
        service_type,
        cluster_ip,
        ports,
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
                if pr == "UDP" {
                    Protocol::Udp
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
}
