#![allow(
    clippy::struct_excessive_bools,
    clippy::cast_possible_truncation,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::too_many_lines,
    clippy::excessive_nesting
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::config::CoreDnsConfig;
use crate::error::{DnsError, Result};
use crate::wire::{DnsMessage, DnsRcode, DnsRecordData, DnsRecordType};
use diorama_apiserver::client::KubernetesApiClient;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Protocol transport for DNS queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsProtocol {
    Udp,
    Tcp,
}

/// Strategy for executing DNS probes.
#[derive(Clone, Debug)]
pub enum ProbeTransport {
    /// Live network socket I/O over UDP or TCP against a running DNS server (e.g. `CoreDNS` or local mock).
    Live {
        server_addr: SocketAddr,
        timeout: Duration,
    },
    /// Semantic resolution evaluated against Kubernetes API services and `CoreDNS` configuration.
    Synthetic {
        client: Arc<KubernetesApiClient>,
        config: CoreDnsConfig,
    },
}

/// Category of resolution probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeCategory {
    SameNamespace,
    CrossNamespace,
    ExternalName,
    Upstream,
    ReverseLookup,
}

/// Specification of an integration DNS probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResolutionProbe {
    pub category: ProbeCategory,
    pub query_name: String,
    pub record_type: u16,
    pub protocol: DnsProtocol,
    pub client_namespace: String,
    pub expected_ip: Option<Ipv4Addr>,
    pub expected_cname: Option<String>,
    pub expected_ptr: Option<String>,
    pub expected_rcode: u8,
}

impl DnsResolutionProbe {
    /// Constructs a same-namespace `ClusterIP` service resolution probe.
    #[must_use]
    pub fn same_namespace(
        service_name: &str,
        namespace: &str,
        expected_ip: Ipv4Addr,
        protocol: DnsProtocol,
    ) -> Self {
        Self {
            category: ProbeCategory::SameNamespace,
            query_name: format!("{service_name}.{namespace}.svc.cluster.local"),
            record_type: DnsRecordType::A.as_u16(),
            protocol,
            client_namespace: namespace.to_string(),
            expected_ip: Some(expected_ip),
            expected_cname: None,
            expected_ptr: None,
            expected_rcode: DnsRcode::NoError.as_u8(),
        }
    }

    /// Constructs a cross-namespace `ClusterIP` service resolution probe.
    #[must_use]
    pub fn cross_namespace(
        service_name: &str,
        service_namespace: &str,
        client_namespace: &str,
        expected_ip: Ipv4Addr,
        protocol: DnsProtocol,
    ) -> Self {
        Self {
            category: ProbeCategory::CrossNamespace,
            query_name: format!("{service_name}.{service_namespace}.svc.cluster.local"),
            record_type: DnsRecordType::A.as_u16(),
            protocol,
            client_namespace: client_namespace.to_string(),
            expected_ip: Some(expected_ip),
            expected_cname: None,
            expected_ptr: None,
            expected_rcode: DnsRcode::NoError.as_u8(),
        }
    }

    /// Constructs an `ExternalName` service resolution probe expecting a CNAME.
    #[must_use]
    pub fn external_name(
        service_name: &str,
        namespace: &str,
        expected_cname: &str,
        protocol: DnsProtocol,
    ) -> Self {
        Self {
            category: ProbeCategory::ExternalName,
            query_name: format!("{service_name}.{namespace}.svc.cluster.local"),
            record_type: DnsRecordType::CNAME.as_u16(),
            protocol,
            client_namespace: namespace.to_string(),
            expected_ip: None,
            expected_cname: Some(expected_cname.trim_end_matches('.').to_string()),
            expected_ptr: None,
            expected_rcode: DnsRcode::NoError.as_u8(),
        }
    }

    /// Constructs an upstream / external name resolution probe.
    #[must_use]
    pub fn upstream(domain: &str, expected_ip: Ipv4Addr, protocol: DnsProtocol) -> Self {
        Self {
            category: ProbeCategory::Upstream,
            query_name: domain.to_string(),
            record_type: DnsRecordType::A.as_u16(),
            protocol,
            client_namespace: "default".to_string(),
            expected_ip: Some(expected_ip),
            expected_cname: None,
            expected_ptr: None,
            expected_rcode: DnsRcode::NoError.as_u8(),
        }
    }

    /// Constructs a reverse PTR lookup probe for IPv4.
    #[must_use]
    pub fn reverse_ipv4(ip: Ipv4Addr, expected_name: &str, protocol: DnsProtocol) -> Self {
        let octets = ip.octets();
        let query_name = format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        );
        Self {
            category: ProbeCategory::ReverseLookup,
            query_name,
            record_type: DnsRecordType::PTR.as_u16(),
            protocol,
            client_namespace: "default".to_string(),
            expected_ip: None,
            expected_cname: None,
            expected_ptr: Some(expected_name.trim_end_matches('.').to_string()),
            expected_rcode: DnsRcode::NoError.as_u8(),
        }
    }
}

/// Result of executing an individual DNS probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsProbeResult {
    pub probe: DnsResolutionProbe,
    pub success: bool,
    pub rcode: u8,
    pub resolved_ips: Vec<Ipv4Addr>,
    pub resolved_cnames: Vec<String>,
    pub resolved_ptrs: Vec<String>,
    pub latency_ms: u64,
    pub details: String,
}

/// Aggregated report of a complete DNS verification run.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResolutionReport {
    pub timestamp: SystemTime,
    pub udp_same_namespace_passed: bool,
    pub tcp_same_namespace_passed: bool,
    pub udp_cross_namespace_passed: bool,
    pub tcp_cross_namespace_passed: bool,
    pub udp_external_name_passed: bool,
    pub tcp_external_name_passed: bool,
    pub upstream_passed: bool,
    pub total_probes: usize,
    pub successful_probes: usize,
    pub failed_probes: usize,
    pub details: Vec<String>,
}

impl DnsResolutionReport {
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed_probes == 0 && self.total_probes > 0
    }
}

/// Prober that executes DNS verification probes using either live network I/O or synthetic resolution.
#[derive(Clone, Debug)]
pub struct DnsProber {
    transport: ProbeTransport,
}

impl DnsProber {
    #[must_use]
    pub fn new(transport: ProbeTransport) -> Self {
        Self { transport }
    }

    /// Executes an individual resolution probe.
    pub async fn execute_probe(&self, probe: &DnsResolutionProbe) -> Result<DnsProbeResult> {
        let start = Instant::now();
        match &self.transport {
            ProbeTransport::Live {
                server_addr,
                timeout,
            } => {
                self.execute_live_probe(probe, *server_addr, *timeout, start)
                    .await
            },
            ProbeTransport::Synthetic { client, config } => {
                self.execute_synthetic_probe(probe, client, config, start)
                    .await
            },
        }
    }

    /// Executes a batch of resolution probes and produces an aggregated report.
    pub async fn execute_suite(
        &self,
        probes: &[DnsResolutionProbe],
    ) -> Result<DnsResolutionReport> {
        let mut report = DnsResolutionReport {
            timestamp: SystemTime::now(),
            udp_same_namespace_passed: true,
            tcp_same_namespace_passed: true,
            udp_cross_namespace_passed: true,
            tcp_cross_namespace_passed: true,
            udp_external_name_passed: true,
            tcp_external_name_passed: true,
            upstream_passed: true,
            total_probes: probes.len(),
            successful_probes: 0,
            failed_probes: 0,
            details: Vec::new(),
        };

        for probe in probes {
            match self.execute_probe(probe).await {
                Ok(res) if res.success => {
                    report.successful_probes += 1;
                },
                Ok(res) => {
                    report.failed_probes += 1;
                    report.details.push(res.details.clone());
                    Self::record_probe_failure(&mut report, probe.category, probe.protocol);
                },
                Err(err) => {
                    report.failed_probes += 1;
                    report.details.push(format!(
                        "[{:?}] {:?} error: {err}",
                        probe.protocol, probe.query_name
                    ));
                    Self::record_probe_failure(&mut report, probe.category, probe.protocol);
                },
            }
        }

        Ok(report)
    }

    fn record_probe_failure(
        report: &mut DnsResolutionReport,
        category: ProbeCategory,
        protocol: DnsProtocol,
    ) {
        match (category, protocol) {
            (ProbeCategory::SameNamespace, DnsProtocol::Udp) => {
                report.udp_same_namespace_passed = false;
            },
            (ProbeCategory::SameNamespace, DnsProtocol::Tcp) => {
                report.tcp_same_namespace_passed = false;
            },
            (ProbeCategory::CrossNamespace, DnsProtocol::Udp) => {
                report.udp_cross_namespace_passed = false;
            },
            (ProbeCategory::CrossNamespace, DnsProtocol::Tcp) => {
                report.tcp_cross_namespace_passed = false;
            },
            (ProbeCategory::ExternalName, DnsProtocol::Udp) => {
                report.udp_external_name_passed = false;
            },
            (ProbeCategory::ExternalName, DnsProtocol::Tcp) => {
                report.tcp_external_name_passed = false;
            },
            (ProbeCategory::Upstream, _) => {
                report.upstream_passed = false;
            },
            (ProbeCategory::ReverseLookup, _) => {},
        }
    }

    async fn execute_live_probe(
        &self,
        probe: &DnsResolutionProbe,
        server_addr: SocketAddr,
        timeout: Duration,
        start: Instant,
    ) -> Result<DnsProbeResult> {
        let rtype = DnsRecordType::from_u16(probe.record_type);
        let query_id = (std::process::id() as u16) ^ (probe.record_type & 0xFF);
        let query = DnsMessage::new_query(query_id, &probe.query_name, rtype);

        let response = match probe.protocol {
            DnsProtocol::Udp => tokio::time::timeout(timeout, send_udp_query(server_addr, &query))
                .await
                .map_err(|_| {
                    DnsError::ProbeFailed(format!("UDP query timeout to {server_addr}"))
                })?,
            DnsProtocol::Tcp => tokio::time::timeout(timeout, send_tcp_query(server_addr, &query))
                .await
                .map_err(|_| {
                    DnsError::ProbeFailed(format!("TCP query timeout to {server_addr}"))
                })?,
        }?;

        let latency_ms = start.elapsed().as_millis() as u64;
        let rcode = response.header.rcode.as_u8();

        let mut resolved_ips = Vec::new();
        let mut resolved_cnames = Vec::new();
        let mut resolved_ptrs = Vec::new();

        for ans in &response.answers {
            match &ans.rdata {
                DnsRecordData::A(ip) => resolved_ips.push(*ip),
                DnsRecordData::CNAME(cname) => resolved_cnames.push(cname.clone()),
                DnsRecordData::PTR(ptr) => resolved_ptrs.push(ptr.clone()),
                _ => {},
            }
        }

        let mut success = rcode == probe.expected_rcode;
        let mut details = format!(
            "[{:?}] {:?} -> rcode={rcode}",
            probe.protocol, probe.query_name
        );

        if let Some(expected_ip) = probe.expected_ip {
            if !resolved_ips.contains(&expected_ip) {
                success = false;
                details.push_str(&format!(
                    " (expected IP {expected_ip} not found in {resolved_ips:?})"
                ));
            }
        }

        if let Some(ref expected_cname) = probe.expected_cname {
            if !resolved_cnames
                .iter()
                .any(|c| c.eq_ignore_ascii_case(expected_cname))
            {
                success = false;
                details.push_str(&format!(
                    " (expected CNAME {expected_cname} not found in {resolved_cnames:?})"
                ));
            }
        }

        if let Some(ref expected_ptr) = probe.expected_ptr {
            if !resolved_ptrs
                .iter()
                .any(|p| p.eq_ignore_ascii_case(expected_ptr))
            {
                success = false;
                details.push_str(&format!(
                    " (expected PTR {expected_ptr} not found in {resolved_ptrs:?})"
                ));
            }
        }

        Ok(DnsProbeResult {
            probe: probe.clone(),
            success,
            rcode,
            resolved_ips,
            resolved_cnames,
            resolved_ptrs,
            latency_ms,
            details,
        })
    }

    async fn execute_synthetic_probe(
        &self,
        probe: &DnsResolutionProbe,
        client: &KubernetesApiClient,
        config: &CoreDnsConfig,
        start: Instant,
    ) -> Result<DnsProbeResult> {
        let latency_ms = start.elapsed().as_millis() as u64;
        let mut resolved_ips = Vec::new();
        let mut resolved_cnames = Vec::new();
        let mut resolved_ptrs = Vec::new();
        let mut rcode = DnsRcode::NoError.as_u8();

        let clean_name = probe.query_name.trim_end_matches('.');

        // Parse Kubernetes service query: <svc>.<ns>.svc.<cluster-domain>
        if let Some(svc_part) = clean_name.strip_suffix(&format!(".svc.{}", config.cluster_domain))
        {
            let parts: Vec<&str> = svc_part.split('.').collect();
            if parts.len() == 2 {
                let (svc_name, svc_ns) = (parts[0], parts[1]);
                match client.get_service(svc_ns, svc_name).await {
                    Ok(svc_val) => {
                        let svc_type = svc_val
                            .pointer("/spec/type")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("ClusterIP");
                        if svc_type == "ExternalName" {
                            if let Some(ext_name) = svc_val
                                .pointer("/spec/externalName")
                                .and_then(serde_json::Value::as_str)
                            {
                                resolved_cnames.push(ext_name.trim_end_matches('.').to_string());
                            }
                        } else if let Some(cluster_ip_str) = svc_val
                            .pointer("/spec/clusterIP")
                            .and_then(serde_json::Value::as_str)
                        {
                            if let Ok(ip) = cluster_ip_str.parse::<Ipv4Addr>() {
                                resolved_ips.push(ip);
                            }
                        }
                    },
                    Err(_) => {
                        rcode = DnsRcode::NXDomain.as_u8();
                    },
                }
            } else {
                rcode = DnsRcode::NXDomain.as_u8();
            }
        } else if let Some(ip_part) = clean_name.strip_suffix(".in-addr.arpa") {
            // Reverse IPv4 lookup: find Service matching clusterIP
            let octets: Vec<&str> = ip_part.split('.').collect();
            if octets.len() == 4 {
                let ip_str = format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0]);
                let mut found = false;
                if let Ok(ns_list) = client.list_namespaces().await {
                    if let Some(namespaces) =
                        ns_list.get("items").and_then(serde_json::Value::as_array)
                    {
                        for ns_val in namespaces {
                            let ns_name = ns_val
                                .pointer("/metadata/name")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("");
                            if let Ok(svc_list) = client.list_services(ns_name).await {
                                if let Some(items) =
                                    svc_list.get("items").and_then(serde_json::Value::as_array)
                                {
                                    for svc in items {
                                        let cluster_ip = svc
                                            .pointer("/spec/clusterIP")
                                            .and_then(serde_json::Value::as_str);
                                        if cluster_ip == Some(&ip_str) {
                                            if let (Some(name), Some(ns)) = (
                                                svc.pointer("/metadata/name")
                                                    .and_then(serde_json::Value::as_str),
                                                svc.pointer("/metadata/namespace")
                                                    .and_then(serde_json::Value::as_str),
                                            ) {
                                                resolved_ptrs.push(format!(
                                                    "{name}.{ns}.svc.{}",
                                                    config.cluster_domain
                                                ));
                                                found = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            if found {
                                break;
                            }
                        }
                    }
                }
                if !found {
                    rcode = DnsRcode::NXDomain.as_u8();
                }
            } else {
                rcode = DnsRcode::FormErr.as_u8();
            }
        } else if let Some(ip_part) = clean_name.strip_suffix(".ip6.arpa") {
            // Reverse IPv6 lookup - absent (NXDomain) when IPv6 is disabled
            let corefile = config.generate_corefile();
            if corefile.contains("ip6.arpa") {
                let nibbles: Vec<&str> = ip_part.split('.').collect();
                if nibbles.len() == 32 {
                    let mut bytes = [0u8; 16];
                    let mut valid = true;
                    let parse_nibble = |s: &str| {
                        let mut chars = s.chars();
                        match (chars.next(), chars.next()) {
                            (Some(c), None) => {
                                c.to_digit(16).and_then(|d| u8::try_from(d).ok()).ok_or(())
                            },
                            _ => Err(()),
                        }
                    };
                    for i in 0..16 {
                        let low_nibble = parse_nibble(nibbles[2 * i]);
                        let high_nibble = parse_nibble(nibbles[2 * i + 1]);
                        if let (Ok(h), Ok(l)) = (high_nibble, low_nibble) {
                            bytes[15 - i] = (h << 4) | l;
                        } else {
                            valid = false;
                            break;
                        }
                    }
                    if valid {
                        let target_ipv6 = std::net::Ipv6Addr::from(bytes);
                        let mut found = false;
                        if let Ok(ns_list) = client.list_namespaces().await {
                            if let Some(namespaces) =
                                ns_list.get("items").and_then(serde_json::Value::as_array)
                            {
                                for ns_val in namespaces {
                                    let ns_name = ns_val
                                        .pointer("/metadata/name")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("");
                                    if let Ok(svc_list) = client.list_services(ns_name).await {
                                        if let Some(items) = svc_list
                                            .get("items")
                                            .and_then(serde_json::Value::as_array)
                                        {
                                            for svc in items {
                                                let mut matches = false;
                                                if let Some(cip) = svc
                                                    .pointer("/spec/clusterIP")
                                                    .and_then(serde_json::Value::as_str)
                                                {
                                                    if cip.parse::<std::net::Ipv6Addr>()
                                                        == Ok(target_ipv6)
                                                    {
                                                        matches = true;
                                                    }
                                                }
                                                if !matches {
                                                    if let Some(cips) = svc
                                                        .pointer("/spec/clusterIPs")
                                                        .and_then(serde_json::Value::as_array)
                                                    {
                                                        for ip_val in cips {
                                                            if let Some(ip_str) = ip_val.as_str() {
                                                                if ip_str
                                                                    .parse::<std::net::Ipv6Addr>()
                                                                    == Ok(target_ipv6)
                                                                {
                                                                    matches = true;
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                if matches {
                                                    if let (Some(name), Some(ns)) = (
                                                        svc.pointer("/metadata/name")
                                                            .and_then(serde_json::Value::as_str),
                                                        svc.pointer("/metadata/namespace")
                                                            .and_then(serde_json::Value::as_str),
                                                    ) {
                                                        resolved_ptrs.push(format!(
                                                            "{name}.{ns}.svc.{}",
                                                            config.cluster_domain
                                                        ));
                                                        found = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if found {
                                        break;
                                    }
                                }
                            }
                        }
                        if !found {
                            rcode = DnsRcode::NXDomain.as_u8();
                        }
                    } else {
                        rcode = DnsRcode::FormErr.as_u8();
                    }
                } else {
                    rcode = DnsRcode::FormErr.as_u8();
                }
            } else {
                rcode = DnsRcode::NXDomain.as_u8();
            }
        } else {
            // Upstream query: resolve via local upstream dependencies if available
            let resolvers = if !config.upstream_resolvers.is_empty() {
                config.upstream_resolvers.clone()
            } else if config.container_mode {
                vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()]
            } else {
                Vec::new()
            };

            let mut resolved = false;
            for resolver in &resolvers {
                let addr = if resolver.contains(':') {
                    resolver.parse::<SocketAddr>().ok()
                } else {
                    format!("{resolver}:53").parse::<SocketAddr>().ok()
                };
                if let Some(target_addr) = addr {
                    if target_addr.ip().is_loopback() {
                        let rtype = DnsRecordType::from_u16(probe.record_type);
                        let query = DnsMessage::new_query(1, &probe.query_name, rtype);
                        if let Ok(Ok(resp)) = tokio::time::timeout(
                            Duration::from_millis(500),
                            send_udp_query(target_addr, &query),
                        )
                        .await
                        {
                            rcode = resp.header.rcode.as_u8();
                            for ans in resp.answers {
                                if let DnsRecordData::A(ip) = ans.rdata {
                                    resolved_ips.push(ip);
                                }
                            }
                            resolved = true;
                            break;
                        }
                    }
                }
            }
            if !resolved {
                rcode = DnsRcode::ServFail.as_u8();
            }
        }

        let mut success = rcode == probe.expected_rcode;
        let mut details = format!(
            "[Synthetic {:?}] {:?} -> rcode={rcode}",
            probe.protocol, probe.query_name
        );

        if let Some(expected_ip) = probe.expected_ip {
            if !resolved_ips.contains(&expected_ip) {
                success = false;
                details.push_str(&format!(
                    " (expected IP {expected_ip} not found in {resolved_ips:?})"
                ));
            }
        }

        if let Some(ref expected_cname) = probe.expected_cname {
            if !resolved_cnames
                .iter()
                .any(|c| c.eq_ignore_ascii_case(expected_cname))
            {
                success = false;
                details.push_str(&format!(
                    " (expected CNAME {expected_cname} not found in {resolved_cnames:?})"
                ));
            }
        }

        if let Some(ref expected_ptr) = probe.expected_ptr {
            if !resolved_ptrs
                .iter()
                .any(|p| p.eq_ignore_ascii_case(expected_ptr))
            {
                success = false;
                details.push_str(&format!(
                    " (expected PTR {expected_ptr} not found in {resolved_ptrs:?})"
                ));
            }
        }

        Ok(DnsProbeResult {
            probe: probe.clone(),
            success,
            rcode,
            resolved_ips,
            resolved_cnames,
            resolved_ptrs,
            latency_ms,
            details,
        })
    }
}

async fn send_udp_query(server_addr: SocketAddr, query: &DnsMessage) -> Result<DnsMessage> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let payload = query.to_bytes();
    socket.send_to(&payload, server_addr).await?;

    let mut buf = [0u8; 1024];
    let (len, _) = socket.recv_from(&mut buf).await?;
    DnsMessage::from_bytes(&buf[..len])
}

async fn send_tcp_query(server_addr: SocketAddr, query: &DnsMessage) -> Result<DnsMessage> {
    let mut stream = TcpStream::connect(server_addr).await?;
    let payload = query.to_tcp_bytes();
    stream.write_all(&payload).await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > 4096 {
        return Err(DnsError::Wire(
            "TCP DNS response too large (> 4096 bytes)".into(),
        ));
    }

    let mut resp_buf = vec![0u8; len];
    stream.read_exact(&mut resp_buf).await?;
    DnsMessage::from_bytes(&resp_buf)
}
