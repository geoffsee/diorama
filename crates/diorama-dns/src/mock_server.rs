use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{RwLock, watch};
use tracing::debug;

use crate::error::Result;
use crate::wire::{DnsAnswer, DnsHeader, DnsMessage, DnsRcode, DnsRecordData, DnsRecordType};

type DnsRecordStore = Arc<RwLock<HashMap<(String, DnsRecordType), Vec<DnsRecordData>>>>;

/// In-memory DNS server for local testing of UDP and TCP resolution,
/// and providing local external dependencies in egress-denied offline environments.
pub struct LocalDnsServer {
    local_addr: SocketAddr,
    records: DnsRecordStore,
    shutdown_tx: watch::Sender<bool>,
}

impl std::fmt::Debug for LocalDnsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalDnsServer")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl LocalDnsServer {
    /// Starts a new local DNS server on `127.0.0.1` with dynamic loopback ports for both UDP and TCP.
    pub async fn start_loopback() -> Result<Self> {
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = udp_socket.local_addr()?;
        let tcp_listener = TcpListener::bind(local_addr).await?;
        Ok(Self::start_with_sockets(
            udp_socket,
            tcp_listener,
            local_addr,
        ))
    }

    /// Starts a new local DNS server on the specified socket address for both UDP and TCP.
    pub async fn start_on(addr: SocketAddr) -> Result<Self> {
        let udp_socket = UdpSocket::bind(addr).await?;
        let local_addr = udp_socket.local_addr()?;
        let tcp_listener = TcpListener::bind(local_addr).await?;
        Ok(Self::start_with_sockets(
            udp_socket,
            tcp_listener,
            local_addr,
        ))
    }

    fn start_with_sockets(
        udp_socket: UdpSocket,
        tcp_listener: TcpListener,
        local_addr: SocketAddr,
    ) -> Self {
        let records = Arc::new(RwLock::new(HashMap::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Spawn UDP server loop
        let udp_records = Arc::clone(&records);
        let mut udp_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                tokio::select! {
                    _ = udp_shutdown.changed() => {
                        if *udp_shutdown.borrow() {
                            break;
                        }
                    }
                    recv_res = udp_socket.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((len, peer)) => {
                                if let Ok(query) = DnsMessage::from_bytes(&buf[..len]) {
                                    let response = handle_query(&query, &udp_records).await;
                                    let resp_bytes = response.to_bytes();
                                    let _ = udp_socket.send_to(&resp_bytes, peer).await;
                                }
                            }
                            Err(e) => {
                                debug!("UDP DNS server recv error: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Spawn TCP server loop
        let tcp_records = Arc::clone(&records);
        let mut tcp_shutdown = shutdown_rx;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tcp_shutdown.changed() => {
                        if *tcp_shutdown.borrow() {
                            break;
                        }
                    }
                    accept_res = tcp_listener.accept() => {
                        match accept_res {
                            Ok((mut socket, _)) => {
                                let conn_records = Arc::clone(&tcp_records);
                                tokio::spawn(async move {
                                    let mut len_buf = [0u8; 2];
                                    if socket.read_exact(&mut len_buf).await.is_err() {
                                        return;
                                    }
                                    let len = u16::from_be_bytes(len_buf) as usize;
                                    if len > 4096 {
                                        return;
                                    }
                                    let mut query_buf = vec![0u8; len];
                                    if socket.read_exact(&mut query_buf).await.is_err() {
                                        return;
                                    }
                                    if let Ok(query) = DnsMessage::from_bytes(&query_buf) {
                                        let response = handle_query(&query, &conn_records).await;
                                        let resp_bytes = response.to_tcp_bytes();
                                        let _ = socket.write_all(&resp_bytes).await;
                                    }
                                });
                            }
                            Err(e) => {
                                debug!("TCP DNS server accept error: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        });

        Self {
            local_addr,
            records,
            shutdown_tx,
        }
    }

    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Adds an A record mapping `domain` -> `ip`.
    pub async fn add_a_record(&self, domain: &str, ip: Ipv4Addr) {
        let key = (normalize_domain(domain), DnsRecordType::A);
        let mut lock = self.records.write().await;
        lock.entry(key).or_default().push(DnsRecordData::A(ip));
    }

    /// Adds a CNAME record mapping `domain` -> `target`.
    pub async fn add_cname_record(&self, domain: &str, target: &str) {
        let key = (normalize_domain(domain), DnsRecordType::CNAME);
        let mut lock = self.records.write().await;
        lock.entry(key)
            .or_default()
            .push(DnsRecordData::CNAME(normalize_domain(target)));
    }

    /// Adds a PTR record mapping `reverse_domain` -> `target`.
    pub async fn add_ptr_record(&self, reverse_domain: &str, target: &str) {
        let key = (normalize_domain(reverse_domain), DnsRecordType::PTR);
        let mut lock = self.records.write().await;
        lock.entry(key)
            .or_default()
            .push(DnsRecordData::PTR(normalize_domain(target)));
    }

    /// Stops the local DNS server and shuts down sockets.
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for LocalDnsServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

async fn handle_query(query: &DnsMessage, records: &DnsRecordStore) -> DnsMessage {
    let mut answers = Vec::new();
    let mut rcode = DnsRcode::NoError;

    if let Some(question) = query.questions.first() {
        let normalized = normalize_domain(&question.name);
        let lock = records.read().await;

        // Check exact match
        if let Some(data_list) = lock.get(&(normalized.clone(), question.qtype)) {
            for data in data_list {
                answers.push(DnsAnswer {
                    name: question.name.clone(),
                    rtype: question.qtype,
                    rclass: 1,
                    ttl: 30,
                    rdata: data.clone(),
                });
            }
        } else if let Some(cnames) = lock.get(&(normalized.clone(), DnsRecordType::CNAME)) {
            // CNAME response
            for cname_data in cnames {
                answers.push(DnsAnswer {
                    name: question.name.clone(),
                    rtype: DnsRecordType::CNAME,
                    rclass: 1,
                    ttl: 30,
                    rdata: cname_data.clone(),
                });
            }
        } else {
            rcode = DnsRcode::NXDomain;
        }
    } else {
        rcode = DnsRcode::FormErr;
    }

    let header = DnsHeader::new_response(query.header.id, rcode, true, query.header.rd, true);

    DnsMessage {
        header,
        questions: query.questions.clone(),
        answers,
    }
}
