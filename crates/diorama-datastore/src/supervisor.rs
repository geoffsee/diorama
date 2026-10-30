use diorama_supervisor::{
    Adapter, AdapterContext, AdapterError, AdapterFuture, ComponentKind, ComponentSpec,
    FailurePolicy, Registration, StopPhase,
};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::config::DatastoreConfig;
use crate::engine::DatastoreEngine;
use crate::tls::{build_tls_acceptor, parse_listen_addr};

#[derive(Clone, Debug)]
pub struct DatastoreAdapter {
    config: DatastoreConfig,
    engine: Option<DatastoreEngine>,
    bound_addr: Arc<Mutex<Option<SocketAddr>>>,
    peer_bound_addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl DatastoreAdapter {
    pub fn new(config: DatastoreConfig) -> Self {
        Self {
            config,
            engine: None,
            bound_addr: Arc::new(Mutex::new(None)),
            peer_bound_addr: Arc::new(Mutex::new(None)),
        }
    }

    pub fn from_engine(engine: DatastoreEngine) -> Self {
        Self {
            config: engine.config().clone(),
            engine: Some(engine),
            bound_addr: Arc::new(Mutex::new(None)),
            peer_bound_addr: Arc::new(Mutex::new(None)),
        }
    }

    pub fn bound_addr(&self) -> Option<SocketAddr> {
        *self.bound_addr.lock().unwrap()
    }

    pub fn bound_addr_handle(&self) -> Arc<Mutex<Option<SocketAddr>>> {
        self.bound_addr.clone()
    }

    pub fn peer_bound_addr(&self) -> Option<SocketAddr> {
        *self.peer_bound_addr.lock().unwrap()
    }

    pub fn peer_bound_addr_handle(&self) -> Arc<Mutex<Option<SocketAddr>>> {
        self.peer_bound_addr.clone()
    }

    pub fn registration(
        id: impl Into<String>,
        config: DatastoreConfig,
        timeout: Duration,
    ) -> Registration {
        let spec = ComponentSpec {
            id: id.into(),
            prerequisites: Vec::new(),
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout: timeout,
        };
        Registration::new(spec, Self::new(config))
    }

    pub fn registration_for_engine(
        id: impl Into<String>,
        engine: DatastoreEngine,
        timeout: Duration,
    ) -> Registration {
        let spec = ComponentSpec {
            id: id.into(),
            prerequisites: Vec::new(),
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout: timeout,
        };
        Registration::new(spec, Self::from_engine(engine))
    }

    pub fn registration_with_adapter(
        id: impl Into<String>,
        adapter: Self,
        timeout: Duration,
    ) -> Registration {
        let spec = ComponentSpec {
            id: id.into(),
            prerequisites: Vec::new(),
            kind: ComponentKind::LongRunning,
            failure_policy: FailurePolicy::Fatal,
            startup_timeout: timeout,
        };
        Registration::new(spec, adapter)
    }
}

async fn bind_tls_listener(
    config: &DatastoreConfig,
) -> Result<(TcpListener, TlsAcceptor, SocketAddr), AdapterError> {
    let acceptor = build_tls_acceptor(config).map_err(|err| AdapterError {
        code: err.diagnostic_code(),
    })?;

    let url = config.listen_client_urls.first().ok_or(AdapterError {
        code: "datastore-missing-listen-urls",
    })?;
    let addr = parse_listen_addr(url).map_err(|err| AdapterError {
        code: err.diagnostic_code(),
    })?;

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
            let fallback = SocketAddr::new(addr.ip(), 0);
            TcpListener::bind(fallback).await.map_err(|fallback_err| {
                let _ = writeln!(
                    std::io::stderr(),
                    "failed to bind datastore TLS listener on fallback {fallback}: {fallback_err}"
                );
                AdapterError {
                    code: "datastore-bind-failed",
                }
            })?
        },
        Err(err) => {
            let _ = writeln!(
                std::io::stderr(),
                "failed to bind datastore TLS listener on {addr}: {err}"
            );
            return Err(AdapterError {
                code: "datastore-bind-failed",
            });
        },
    };

    let local_addr = listener.local_addr().map_err(|_| AdapterError {
        code: "datastore-bind-failed",
    })?;

    Ok((listener, acceptor, local_addr))
}

async fn handle_tls_connection(stream: TcpStream, acceptor: TlsAcceptor) {
    let handshake = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await;
    let Ok(Ok(mut tls_stream)) = handshake else {
        return;
    };
    let mut buf = [0u8; 1024];
    loop {
        match tls_stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let _ = tls_stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
                let _ = tls_stream.flush().await;
            },
        }
    }
}

const MAX_DATASTORE_CONNECTIONS: usize = 256;

async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    context: &mut AdapterContext,
    engine: &DatastoreEngine,
) {
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            phase = context.changed() => {
                if matches!(phase, StopPhase::Graceful | StopPhase::Force) {
                    let _ = engine.checkpoint_snapshot().await;
                    break;
                }
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {
                // Connection task finished
            }
            accept_res = listener.accept(), if connections.len() < MAX_DATASTORE_CONNECTIONS => {
                if let Ok((stream, _)) = accept_res {
                    let acc = acceptor.clone();
                    connections.spawn(handle_tls_connection(stream, acc));
                }
            }
        }
    }

    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn wait_for_stop(context: &mut AdapterContext, engine: &DatastoreEngine) {
    loop {
        if matches!(
            context.changed().await,
            StopPhase::Graceful | StopPhase::Force
        ) {
            let _ = engine.checkpoint_snapshot().await;
            break;
        }
    }
}

fn spawn_configured_peer_connections(
    config: &DatastoreConfig,
    cert: &std::path::Path,
    key: &std::path::Path,
    engine: &DatastoreEngine,
) -> JoinSet<()> {
    let mut peer_tasks = JoinSet::new();
    for (&peer_id, &remote_addr) in &config.peers {
        if !config.dial_all_peers && peer_id <= config.node_id {
            continue;
        }
        let eng = engine.clone();
        let c = Some(cert.to_path_buf());
        let k = Some(key.to_path_buf());
        peer_tasks.spawn(async move {
            let _ = crate::quic::connect_quic_peer(peer_id, remote_addr, c, k, eng).await;
        });
    }
    peer_tasks
}

impl Adapter for DatastoreAdapter {
    fn run(self: Box<Self>, mut context: AdapterContext) -> AdapterFuture {
        Box::pin(async move {
            let engine = match self.engine {
                Some(eng) => eng,
                None => match DatastoreEngine::open(self.config.clone()) {
                    Ok((eng, _summary)) => eng,
                    Err(err) => {
                        return Err(AdapterError {
                            code: err.diagnostic_code(),
                        });
                    },
                },
            };

            let listener_opt = if self.config.client_cert_auth {
                let (listener, acceptor, local_addr) = bind_tls_listener(&self.config).await?;
                *self.bound_addr.lock().unwrap() = Some(local_addr);
                let _ = writeln!(
                    std::io::stderr(),
                    "{{\"schema\":1,\"level\":\"info\",\"event\":\"datastore_listening\",\"address\":\"https://{local_addr}\"}}"
                );
                Some((listener, acceptor))
            } else {
                None
            };

            let mut quic_server_handle = None;
            let mut peer_tasks = JoinSet::new();
            if let (Some(peer_addr), Some(cert), Some(key)) = (
                engine.config().listen_peer_addr,
                engine.config().cert_file.clone(),
                engine.config().key_file.clone(),
            ) {
                let (bound_peer, handle) = crate::quic::start_quic_server_with_handle(
                    peer_addr,
                    cert.clone(),
                    key.clone(),
                    engine.clone(),
                )
                .await
                .map_err(|err| AdapterError {
                    code: err.diagnostic_code(),
                })?;
                *self.peer_bound_addr.lock().unwrap() = Some(bound_peer);
                quic_server_handle = Some(handle);
                peer_tasks =
                    spawn_configured_peer_connections(engine.config(), &cert, &key, &engine);
            }

            let ticker_handle = engine
                .raft()
                .start_election_ticker(Duration::from_millis(150), Duration::from_millis(300));

            if !context.ready() {
                ticker_handle.abort();
                if let Some(handle) = quic_server_handle {
                    handle.abort();
                }
                peer_tasks.abort_all();
                engine.release_lock().await;
                return Err(AdapterError {
                    code: "datastore-readiness-rejected",
                });
            }

            if let Some((listener, acceptor)) = listener_opt {
                serve_tls(listener, acceptor, &mut context, &engine).await;
            } else {
                wait_for_stop(&mut context, &engine).await;
            }
            ticker_handle.abort();
            if let Some(handle) = quic_server_handle {
                handle.abort();
            }
            peer_tasks.abort_all();
            engine.release_lock().await;

            Ok(())
        })
    }
}
