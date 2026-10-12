//! HTTP server exposing metrics and health check routes.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::negotiation::{Exposition, negotiate};
use super::registry::MetricsRegistry;
use super::timed_io::TimedIo;

const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
// Metrics is a small operational endpoint. Bound task/socket retention even
// when peers arrive faster than the read/idle deadlines can expire them.
const MAX_CONNECTIONS: usize = 64;

/// Operational metrics and health HTTP server.
#[derive(Debug)]
pub struct MetricsServer {
    addr: SocketAddr,
    registry: Arc<MetricsRegistry>,
}

impl MetricsServer {
    #[must_use]
    pub fn new(addr: SocketAddr, registry: Arc<MetricsRegistry>) -> Self {
        Self { addr, registry }
    }

    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    #[must_use]
    pub fn registry(&self) -> &Arc<MetricsRegistry> {
        &self.registry
    }

    /// Runs the HTTP server on the provided listener until shutdown is signaled.
    pub async fn run_with_listener(
        listener: TcpListener,
        registry: Arc<MetricsRegistry>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        // JoinSet aborts owned connection tasks if this server future is dropped.
        let mut connections = JoinSet::new();
        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            tokio::select! {
                biased;
                result = shutdown_rx.changed() => {
                    if result.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = connections.join_next(), if !connections.is_empty() => {},
                res = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                    let (stream, _) = match res {
                        Ok(conn) => conn,
                        Err(e) => {
                            // Transient accept errors do not stop the server
                            eprintln!("metrics server accept error: {e}");
                            accept_error_backoff(&mut shutdown_rx).await;
                            continue;
                        }
                    };

                    let io = TokioIo::new(TimedIo::new(stream));
                    let reg = registry.clone();
                    let mut connection_shutdown = shutdown_rx.clone();

                    connections.spawn(async move {
                        let service = service_fn(move |req: Request<Incoming>| {
                            let reg = reg.clone();
                            async move {
                                Ok::<Response<Full<Bytes>>, Infallible>(handle_request(&req, &reg))
                            }
                        });

                        let mut builder = hyper::server::conn::http1::Builder::new();
                        builder.timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT);
                        let connection = builder.serve_connection(io, service);
                        tokio::pin!(connection);
                        tokio::select! {
                            _ = &mut connection => {},
                            () = async {
                                while !*connection_shutdown.borrow() {
                                    if connection_shutdown.changed().await.is_err() {
                                        break;
                                    }
                                }
                            } => {
                                connection.as_mut().graceful_shutdown();
                                let _ = connection.await;
                            }
                        }
                    });
                }
            }
        }
        drop(listener);
        // Active responses may drain, but idle/slow peers cannot delay stop indefinitely.
        if tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
        Ok(())
    }
}

async fn accept_error_backoff(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    tokio::select! {
        _ = shutdown.changed() => {},
        () = tokio::time::sleep(Duration::from_millis(100)) => {},
    }
}

/// Handles incoming HTTP requests for metrics and health routes.
fn handle_request(req: &Request<Incoming>, registry: &MetricsRegistry) -> Response<Full<Bytes>> {
    let method = req.method();
    let path = req.uri().path();

    if method != Method::GET {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from("method not allowed\n")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
    }

    match path {
        "/metrics" => {
            let Some(format) = negotiate(req.headers()) else {
                return Response::builder()
                    .status(StatusCode::NOT_ACCEPTABLE)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Full::new(Bytes::from("no acceptable metrics format\n")))
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
            };
            let body = match format {
                Exposition::Prometheus => registry.render_prometheus(),
                Exposition::OpenMetrics => registry.render_openmetrics(),
            };
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, format.content_type())
                .header(header::VARY, "Accept")
                .body(Full::new(Bytes::from(body)))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
        },
        "/healthz" | "/livez" | "/readyz" => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from("ok\n")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
        "/" => {
            let html = concat!(
                "<html><body><h1>kubesolo metrics</h1>",
                "<ul>",
                "<li><a href=\"/metrics\">/metrics</a></li>",
                "<li><a href=\"/healthz\">/healthz</a></li>",
                "</ul></body></html>\n"
            );
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Full::new(Bytes::from(html)))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
        },
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from("404 not found\n")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
    }
}

#[cfg(test)]
mod accept_retry_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn repeated_accept_failures_are_rate_limited_and_shutdown_interrupts_delay() {
        let (tx, mut rx) = watch::channel(false);
        let start = tokio::time::Instant::now();
        for _ in 0..3 {
            accept_error_backoff(&mut rx).await;
        }
        assert_eq!(start.elapsed(), Duration::from_millis(300));
        let stop = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            tx.send(true).unwrap();
        };
        let start = tokio::time::Instant::now();
        tokio::join!(accept_error_backoff(&mut rx), stop);
        assert_eq!(start.elapsed(), Duration::from_millis(10));
    }
}
