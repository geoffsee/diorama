use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::error::ProxyError;
use crate::routing::{
    Protocol, ServiceDefinition, ServicePort, ServiceRoutingTable, TargetEndpoint,
};

/// Transport strategy for dataplane verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeTransport {
    /// Verifies route translation against the in-memory dataplane routing table.
    Synthetic,
    /// Executes live network socket I/O (TCP connect or UDP ping) against the selected target endpoint.
    Live { timeout: Duration },
}

/// Specification of a workload dataplane probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadProbe {
    pub namespace: String,
    pub service_name: String,
    pub destination_ip: String,
    pub destination_port: u16,
    pub protocol: Protocol,
    pub is_node_port: bool,
}

impl WorkloadProbe {
    #[must_use]
    pub fn new_cluster_ip(
        namespace: impl Into<String>,
        service_name: impl Into<String>,
        cluster_ip: impl Into<String>,
        port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            service_name: service_name.into(),
            destination_ip: cluster_ip.into(),
            destination_port: port,
            protocol,
            is_node_port: false,
        }
    }

    #[must_use]
    pub fn new_node_port(
        namespace: impl Into<String>,
        service_name: impl Into<String>,
        node_ip: impl Into<String>,
        node_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            service_name: service_name.into(),
            destination_ip: node_ip.into(),
            destination_port: node_port,
            protocol,
            is_node_port: true,
        }
    }
}

/// Result of executing a workload dataplane probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub success: bool,
    pub reached_endpoint: Option<TargetEndpoint>,
    pub latency_ms: u64,
    pub details: String,
}

/// Summary report of verified dataplane probes across all services.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataplaneProbeReport {
    pub timestamp: SystemTime,
    pub tcp_clusterip_probes_passed: bool,
    pub tcp_nodeport_probes_passed: bool,
    pub udp_clusterip_probes_passed: bool,
    pub udp_nodeport_probes_passed: bool,
    pub total_probes: usize,
    pub successful_probes: usize,
    pub failed_probes: usize,
    pub endpoints_reached: Vec<TargetEndpoint>,
    pub details: Vec<String>,
}

impl DataplaneProbeReport {
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed_probes == 0 && self.total_probes > 0
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
struct ProbeAccumulator {
    total_probes: usize,
    successful_probes: usize,
    failed_probes: usize,
    tcp_clusterip_passed: bool,
    tcp_nodeport_passed: bool,
    udp_clusterip_passed: bool,
    udp_nodeport_passed: bool,
    endpoints_reached: Vec<TargetEndpoint>,
    details: Vec<String>,
}

impl ProbeAccumulator {
    fn record_endpoint(&mut self, ep: Option<TargetEndpoint>) {
        if let Some(endpoint) = ep.filter(|e| !self.endpoints_reached.contains(e)) {
            self.endpoints_reached.push(endpoint);
        }
    }
}

/// Executes dataplane routing probes against the current `ServiceRoutingTable`.
#[derive(Clone, Copy, Debug, Default)]
pub struct DataplaneProber {
    transport: Option<ProbeTransport>,
}

impl DataplaneProber {
    #[must_use]
    pub fn new() -> Self {
        Self {
            transport: Some(ProbeTransport::Synthetic),
        }
    }

    #[must_use]
    pub fn new_live(timeout: Duration) -> Self {
        Self {
            transport: Some(ProbeTransport::Live { timeout }),
        }
    }

    #[must_use]
    pub fn with_transport(mut self, transport: ProbeTransport) -> Self {
        self.transport = Some(transport);
        self
    }

    fn execute_live_probe(endpoint: &TargetEndpoint, timeout: Duration) -> Result<(), ProxyError> {
        let addr_str = format!("{}:{}", endpoint.ip, endpoint.port);
        let mut addrs =
            addr_str
                .to_socket_addrs()
                .map_err(|e| ProxyError::DataplaneProbeFailed {
                    service: addr_str.clone(),
                    reason: format!("failed to resolve endpoint address: {e}"),
                })?;
        let addr = addrs
            .next()
            .ok_or_else(|| ProxyError::DataplaneProbeFailed {
                service: addr_str.clone(),
                reason: "no socket address resolved".to_string(),
            })?;

        match endpoint.protocol {
            Protocol::Tcp => {
                TcpStream::connect_timeout(&addr, timeout).map_err(|e| {
                    ProxyError::DataplaneProbeFailed {
                        service: addr_str.clone(),
                        reason: format!("TCP connect to backend failed: {e}"),
                    }
                })?;
            },
            Protocol::Udp => {
                let bind_addr = if addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let socket =
                    UdpSocket::bind(bind_addr).map_err(|e| ProxyError::DataplaneProbeFailed {
                        service: addr_str.clone(),
                        reason: format!("UDP bind failed: {e}"),
                    })?;
                socket.set_read_timeout(Some(timeout)).map_err(|e| {
                    ProxyError::DataplaneProbeFailed {
                        service: addr_str.clone(),
                        reason: format!("UDP set_read_timeout failed: {e}"),
                    }
                })?;
                socket.set_write_timeout(Some(timeout)).map_err(|e| {
                    ProxyError::DataplaneProbeFailed {
                        service: addr_str.clone(),
                        reason: format!("UDP set_write_timeout failed: {e}"),
                    }
                })?;
                socket
                    .connect(addr)
                    .map_err(|e| ProxyError::DataplaneProbeFailed {
                        service: addr_str.clone(),
                        reason: format!("UDP connect failed: {e}"),
                    })?;
                socket
                    .send(&[0u8; 1])
                    .map_err(|e| ProxyError::DataplaneProbeFailed {
                        service: addr_str.clone(),
                        reason: format!("UDP probe send failed: {e}"),
                    })?;
                let mut buf = [0u8; 512];
                socket
                    .recv(&mut buf)
                    .map_err(|e| ProxyError::DataplaneProbeFailed {
                        service: addr_str,
                        reason: format!("UDP probe reply failed or timed out: {e}"),
                    })?;
            },
        }
        Ok(())
    }

    /// Probes packet routing through the dataplane routing table.
    pub fn probe_route(
        &self,
        table: &ServiceRoutingTable,
        dst_ip: &str,
        dst_port: u16,
        protocol: Protocol,
    ) -> Result<ProbeResult, ProxyError> {
        let start = Instant::now();
        tracing::debug!(
            target: "kubeproxy::dataplane",
            destination = %dst_ip,
            port = dst_port,
            protocol = %protocol,
            "dispatching dataplane workload probe"
        );

        let target_endpoint = table
            .route_packet(dst_ip, dst_port, protocol)
            .map_err(|e| {
                tracing::error!(
                    target: "kubeproxy::dataplane",
                    destination = %dst_ip,
                    port = dst_port,
                    protocol = %protocol,
                    reason = %e,
                    "dataplane probe failed to reach backend"
                );
                ProxyError::DataplaneProbeFailed {
                    service: format!("{dst_ip}:{dst_port}/{protocol}"),
                    reason: e.to_string(),
                }
            })?;

        if let Some(ProbeTransport::Live { timeout }) = self.transport {
            Self::execute_live_probe(&target_endpoint, timeout)?;
        }

        let latency_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let details =
            format!("probe successfully routed {protocol} to backend endpoint {target_endpoint}");

        tracing::info!(
            target: "kubeproxy::dataplane",
            destination = %dst_ip,
            port = dst_port,
            protocol = %protocol,
            endpoint = %target_endpoint,
            latency_ms = latency_ms,
            "dataplane workload probe succeeded"
        );

        Ok(ProbeResult {
            success: true,
            reached_endpoint: Some(target_endpoint),
            latency_ms,
            details,
        })
    }

    /// Probes a Service by its `ClusterIP` and specified protocol.
    pub fn probe_service_cluster_ip(
        &self,
        table: &ServiceRoutingTable,
        namespace: &str,
        service_name: &str,
        protocol: Protocol,
    ) -> Result<ProbeResult, ProxyError> {
        let svc_key = (namespace.to_string(), service_name.to_string());
        let svc = table
            .services()
            .get(&svc_key)
            .ok_or_else(|| ProxyError::Internal {
                reason: format!("service '{namespace}/{service_name}' not found"),
            })?;

        let cluster_ip = svc
            .cluster_ip
            .as_deref()
            .ok_or_else(|| ProxyError::Internal {
                reason: format!("service '{namespace}/{service_name}' has no ClusterIP"),
            })?;

        let port_spec = svc
            .ports
            .iter()
            .find(|p| p.protocol == protocol)
            .ok_or_else(|| ProxyError::Internal {
                reason: format!("service '{namespace}/{service_name}' has no {protocol} port"),
            })?;

        self.probe_route(table, cluster_ip, port_spec.port, protocol)
    }

    /// Probes a Service by its `NodePort` and specified protocol.
    pub fn probe_service_node_port(
        &self,
        table: &ServiceRoutingTable,
        namespace: &str,
        service_name: &str,
        protocol: Protocol,
    ) -> Result<ProbeResult, ProxyError> {
        let svc_key = (namespace.to_string(), service_name.to_string());
        let svc = table
            .services()
            .get(&svc_key)
            .ok_or_else(|| ProxyError::Internal {
                reason: format!("service '{namespace}/{service_name}' not found"),
            })?;

        let port_spec = svc
            .ports
            .iter()
            .find(|p| p.protocol == protocol && p.node_port.is_some())
            .ok_or_else(|| ProxyError::Internal {
                reason: format!("service '{namespace}/{service_name}' has no {protocol} NodePort"),
            })?;

        let node_port = port_spec.node_port.unwrap();
        self.probe_route(table, "127.0.0.1", node_port, protocol)
    }

    /// Verifies all registered services across `ClusterIP` and `NodePort` endpoints.
    pub fn verify_all_dataplane_routes(
        &self,
        table: &ServiceRoutingTable,
    ) -> Result<DataplaneProbeReport, ProxyError> {
        let mut acc = ProbeAccumulator {
            total_probes: 0,
            successful_probes: 0,
            failed_probes: 0,
            tcp_clusterip_passed: true,
            tcp_nodeport_passed: true,
            udp_clusterip_passed: true,
            udp_nodeport_passed: true,
            endpoints_reached: Vec::new(),
            details: Vec::new(),
        };

        for svc in table.services().values() {
            for port in &svc.ports {
                self.probe_service_port(table, svc, port, &mut acc);
            }
        }

        let report = DataplaneProbeReport {
            timestamp: SystemTime::now(),
            tcp_clusterip_probes_passed: acc.tcp_clusterip_passed,
            tcp_nodeport_probes_passed: acc.tcp_nodeport_passed,
            udp_clusterip_probes_passed: acc.udp_clusterip_passed,
            udp_nodeport_probes_passed: acc.udp_nodeport_passed,
            total_probes: acc.total_probes,
            successful_probes: acc.successful_probes,
            failed_probes: acc.failed_probes,
            endpoints_reached: acc.endpoints_reached,
            details: acc.details,
        };

        if report.all_passed() {
            tracing::info!(
                target: "kubeproxy::dataplane",
                total = report.total_probes,
                successful = report.successful_probes,
                "all dataplane probes passed successfully"
            );
            Ok(report)
        } else {
            tracing::error!(
                target: "kubeproxy::dataplane",
                total = report.total_probes,
                successful = report.successful_probes,
                failed = report.failed_probes,
                "dataplane probe verification encountered failures"
            );
            Err(ProxyError::DataplaneProbeFailed {
                service: "cluster-wide-services".to_string(),
                reason: format!(
                    "{} out of {} dataplane probes failed",
                    report.failed_probes, report.total_probes
                ),
            })
        }
    }

    fn probe_service_port(
        self,
        table: &ServiceRoutingTable,
        svc: &ServiceDefinition,
        port: &ServicePort,
        acc: &mut ProbeAccumulator,
    ) {
        if let Some(ref cluster_ip) = svc.cluster_ip {
            acc.total_probes += 1;
            match self.probe_route(table, cluster_ip, port.port, port.protocol) {
                Ok(res) => {
                    acc.successful_probes += 1;
                    acc.record_endpoint(res.reached_endpoint);
                    acc.details.push(format!(
                        "ClusterIP {}/{}:{}/{} OK",
                        svc.namespace, svc.name, port.port, port.protocol
                    ));
                },
                Err(e) => {
                    acc.failed_probes += 1;
                    match port.protocol {
                        Protocol::Tcp => acc.tcp_clusterip_passed = false,
                        Protocol::Udp => acc.udp_clusterip_passed = false,
                    }
                    acc.details.push(format!(
                        "ClusterIP {}/{}:{}/{} FAILED: {e}",
                        svc.namespace, svc.name, port.port, port.protocol
                    ));
                },
            }
        }

        if let Some(node_port) = port.node_port {
            acc.total_probes += 1;
            match self.probe_route(table, "127.0.0.1", node_port, port.protocol) {
                Ok(res) => {
                    acc.successful_probes += 1;
                    acc.record_endpoint(res.reached_endpoint);
                    acc.details.push(format!(
                        "NodePort {}/{}:{}/{} OK",
                        svc.namespace, svc.name, node_port, port.protocol
                    ));
                },
                Err(e) => {
                    acc.failed_probes += 1;
                    match port.protocol {
                        Protocol::Tcp => acc.tcp_nodeport_passed = false,
                        Protocol::Udp => acc.udp_nodeport_passed = false,
                    }
                    acc.details.push(format!(
                        "NodePort {}/{}:{}/{} FAILED: {e}",
                        svc.namespace, svc.name, node_port, port.protocol
                    ));
                },
            }
        }
    }
}
