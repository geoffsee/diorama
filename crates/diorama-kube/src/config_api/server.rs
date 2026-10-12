//! Configuration HTTP API server over a local Unix domain socket.

use std::convert::Infallible;
use std::fs::{self, Permissions};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use diorama_config::{
    Config, HostContext, apply_merge_patch, apply_put_replacement, compute_etag, describe_settings,
    diff_configs, format_api_response, has_redacted_secrets, read_file, redact_secrets,
    write_document,
};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinSet;

/// Bound listener and its owned socket inode. Dropping it closes and unlinks
/// the socket, including when the server future is never polled or is cancelled.
#[derive(Debug)]
pub struct ConfigApiListener {
    listener: UnixListener,
    socket: SocketGuard,
}

#[derive(Debug)]
struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path)
            && meta.file_type().is_socket()
            && meta.dev() == self.device
            && meta.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Maximum accepted request body size (1 MiB).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Verifies and cleans up any existing stale socket inode at `path`.
///
/// Refuses regular files, directories, symlinks, or live listeners.
/// Reclaims only unlistened (stale) Unix socket inodes.
pub fn clear_stale_socket(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("refusing to remove non-socket file at {}", path.display()),
                ));
            }

            // Probe whether a live listener is active on this socket
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("live listener active on {}", path.display()),
                )),
                Err(e)
                    if e.kind() == io::ErrorKind::ConnectionRefused
                        || e.kind() == io::ErrorKind::NotFound =>
                {
                    fs::remove_file(path)
                },
                Err(e) => Err(e),
            }
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Local configuration HTTP API server state.
#[derive(Clone, Debug)]
pub struct ConfigApiServer {
    socket_path: PathBuf,
    config_path: PathBuf,
    host: HostContext,
    lock: Arc<Mutex<()>>,
}

impl ConfigApiServer {
    #[must_use]
    pub fn new(socket_path: PathBuf, config_path: PathBuf, host: HostContext) -> Self {
        Self {
            socket_path,
            config_path,
            host,
            lock: Arc::new(Mutex::new(())),
        }
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Verifies and cleans up any existing stale socket inode for this server.
    pub fn clear_stale_socket(&self) -> io::Result<()> {
        clear_stale_socket(&self.socket_path)
    }

    /// Binds the Unix listener on `socket_path` with 0600 permissions.
    pub fn bind(&self) -> io::Result<ConfigApiListener> {
        clear_stale_socket(&self.socket_path)?;
        if let Some(parent) = self.socket_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(&self.socket_path)?;
        let meta = fs::symlink_metadata(&self.socket_path)?;
        let owned = ConfigApiListener {
            listener,
            socket: SocketGuard {
                path: self.socket_path.clone(),
                device: meta.dev(),
                inode: meta.ino(),
            },
        };
        fs::set_permissions(&self.socket_path, Permissions::from_mode(0o600))?;
        Ok(owned)
    }

    /// Runs the HTTP server using an already-bound listener until shutdown is signaled.
    pub async fn run_with_listener(
        self,
        listener: ConfigApiListener,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> io::Result<()> {
        let server = Arc::new(self);
        let ConfigApiListener { listener, socket } = listener;
        let mut connections = JoinSet::new();
        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
                res = listener.accept() => {
                    let (stream, _) = match res {
                        Ok(conn) => conn,
                        Err(e) => {
                            eprintln!("configapi accept error: {e}");
                            continue;
                        }
                    };

                    let io = TokioIo::new(stream);
                    let s = server.clone();

                    connections.spawn(async move {
                        let service = service_fn(move |req: Request<Incoming>| {
                            let s = s.clone();
                            async move {
                                Ok::<_, Infallible>(s.handle_request(req).await)
                            }
                        });

                        if let Err(err) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await
                        {
                            eprintln!("configapi connection error: {err}");
                        }
                    });
                }
            }
        }

        // Closing the listener and aborting owned connections also interrupts
        // incomplete bodies and idle keepalive streams. Join cancellation before
        // reporting shutdown so no connection can persist a later write.
        drop(listener);
        tokio::time::timeout(SHUTDOWN_TIMEOUT, connections.shutdown())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "config API connection cleanup timed out",
                )
            })?;
        drop(socket);
        Ok(())
    }

    fn read_stored(&self) -> io::Result<Config> {
        match read_file(&self.config_path) {
            Ok(Some(decoded)) => Ok(decoded.config),
            Ok(None) => Ok(Config::default()),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        }
    }

    async fn handle_request(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        let (parts, body) = req.into_parts();
        let method = parts.method;
        let uri = parts.uri;
        let path = uri.path();
        let query = uri.query();
        let headers = parts.headers;

        // Check body size limit
        let body_bytes = match http_body_util::Limited::new(body, MAX_BODY_BYTES)
            .collect()
            .await
        {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    "could not read the request body: http: request body too large",
                    None,
                );
            },
        };

        if path == "/healthz" {
            if method == Method::GET {
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Full::new(Bytes::from_static(b"ok\n")))
                    .unwrap();
            }
            return method_not_allowed();
        }

        if path == "/api/v1/config/schema" {
            if method == Method::GET {
                let schema = serde_json::json!({
                    "apiVersion": diorama_config::API_VERSION,
                    "settings": describe_settings(),
                });
                let mut body = serde_json::to_string(&schema).unwrap();
                body.push('\n');
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(body)))
                    .unwrap();
            }
            return method_not_allowed();
        }

        if path == "/api/v1/config:validate" {
            if method == Method::POST {
                return self.handle_validate(&body_bytes);
            }
            return method_not_allowed();
        }

        if path == "/api/v1/config" {
            let if_match = headers_get_str(&headers, header::IF_MATCH);
            let content_type = headers_get_str(&headers, header::CONTENT_TYPE);
            let show_secrets = query.is_some_and(|q| q.contains("showSecrets=true"));

            match method {
                Method::GET => self.handle_get(show_secrets),
                Method::PATCH => {
                    self.handle_patch(&body_bytes, if_match, content_type, show_secrets)
                        .await
                },
                Method::PUT => self.handle_put(&body_bytes, if_match, show_secrets).await,
                Method::DELETE => self.handle_delete(if_match, show_secrets).await,
                _ => method_not_allowed(),
            }
        } else {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from_static(b"404 Not Found\n")))
                .unwrap()
        }
    }

    fn handle_get(&self, show_secrets: bool) -> Response<Full<Bytes>> {
        let stored = match self.read_stored() {
            Ok(cfg) => cfg,
            Err(e) => return internal_error(&e.to_string()),
        };

        let etag = compute_etag(&stored);
        let mut response_config = stored;
        if !show_secrets {
            redact_secrets(&mut response_config);
        }

        let body = format_api_response(&response_config, &[]);
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ETAG, etag)
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    async fn handle_patch(
        &self,
        body_bytes: &[u8],
        if_match: Option<&str>,
        content_type: Option<&str>,
        show_secrets: bool,
    ) -> Response<Full<Bytes>> {
        // Enforce Content-Type
        if let Some(ct) = content_type
            && !ct.is_empty()
            && !ct.starts_with("application/merge-patch+json")
            && !ct.starts_with("application/json")
        {
            return json_error_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                &format!(
                    "content type \"{ct}\" is not supported; use application/merge-patch+json"
                ),
                None,
            );
        }

        let _guard = self.lock.lock().await;

        let stored = match self.read_stored() {
            Ok(cfg) => cfg,
            Err(e) => return internal_error(&e.to_string()),
        };

        let current_etag = compute_etag(&stored);
        if let Some(expected_etag) = if_match
            && expected_etag != current_etag
        {
            return json_error_response(
                StatusCode::PRECONDITION_FAILED,
                "the configuration changed since you read it; read it again and reapply your change",
                None,
            );
        }

        let patch_val: serde_json::Value = match serde_json::from_slice(body_bytes) {
            Ok(v) => v,
            Err(_) => {
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    "patch is not valid JSON",
                    None,
                );
            },
        };

        if has_redacted_secrets(&patch_val) {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "portainer.edgeKey was sent back as \"***\", the placeholder a redacted read returns; send the real value or omit the setting to keep the stored one",
                Some("portainer.edgeKey"),
            );
        }

        let candidate = match apply_merge_patch(&stored, &patch_val) {
            Ok(cfg) => cfg,
            Err(e) => {
                return json_error_response(StatusCode::BAD_REQUEST, &e.message, None);
            },
        };

        if candidate.path != stored.path {
            return json_error_response(
                StatusCode::CONFLICT,
                "path cannot be changed on an existing installation: every certificate, the database and all container state live below it, and none of them move",
                Some("path"),
            );
        }

        if let Err(e) = candidate.clone().validate(&self.host) {
            let msg = format_validation_error(&e);
            return json_error_response(StatusCode::UNPROCESSABLE_ENTITY, &msg, None);
        }

        if candidate == stored {
            let mut response_config = candidate;
            if !show_secrets {
                redact_secrets(&mut response_config);
            }
            let body = format_api_response(&response_config, &[]);
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ETAG, current_etag)
                .body(Full::new(Bytes::from(body)))
                .unwrap();
        }

        if let Err(e) = write_document(&self.config_path, &candidate) {
            return internal_error(&e.to_string());
        }

        let changed = diff_configs(&stored, &candidate);
        let new_etag = compute_etag(&candidate);

        let mut response_config = candidate;
        if !show_secrets {
            redact_secrets(&mut response_config);
        }

        let body = format_api_response(&response_config, &changed);
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ETAG, new_etag)
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    async fn handle_put(
        &self,
        body_bytes: &[u8],
        if_match: Option<&str>,
        show_secrets: bool,
    ) -> Response<Full<Bytes>> {
        let _guard = self.lock.lock().await;

        let stored = match self.read_stored() {
            Ok(cfg) => cfg,
            Err(e) => return internal_error(&e.to_string()),
        };

        let current_etag = compute_etag(&stored);
        if let Some(expected_etag) = if_match
            && expected_etag != current_etag
        {
            return json_error_response(
                StatusCode::PRECONDITION_FAILED,
                "the configuration changed since you read it; read it again and reapply your change",
                None,
            );
        }

        let put_val: serde_json::Value = match serde_json::from_slice(body_bytes) {
            Ok(v) => v,
            Err(e) => {
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("body is not a valid configuration document: {e}"),
                    None,
                );
            },
        };

        if has_redacted_secrets(&put_val) {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "portainer.edgeKey was sent back as \"***\", the placeholder a redacted read returns; send the real value or omit the setting to keep the stored one",
                Some("portainer.edgeKey"),
            );
        }

        let candidate = match apply_put_replacement(&stored, &put_val) {
            Ok(cfg) => cfg,
            Err(e) => {
                return json_error_response(StatusCode::BAD_REQUEST, &e.message, None);
            },
        };

        if candidate.path != stored.path {
            return json_error_response(
                StatusCode::CONFLICT,
                "path cannot be changed on an existing installation: every certificate, the database and all container state live below it, and none of them move",
                Some("path"),
            );
        }

        if let Err(e) = candidate.clone().validate(&self.host) {
            let msg = format_validation_error(&e);
            return json_error_response(StatusCode::UNPROCESSABLE_ENTITY, &msg, None);
        }

        if let Err(e) = write_document(&self.config_path, &candidate) {
            return internal_error(&e.to_string());
        }

        let changed = diff_configs(&stored, &candidate);
        let new_etag = compute_etag(&candidate);

        let mut response_config = candidate;
        if !show_secrets {
            redact_secrets(&mut response_config);
        }

        let body = format_api_response(&response_config, &changed);
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ETAG, new_etag)
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    async fn handle_delete(
        &self,
        if_match: Option<&str>,
        show_secrets: bool,
    ) -> Response<Full<Bytes>> {
        let _guard = self.lock.lock().await;

        let stored = match self.read_stored() {
            Ok(cfg) => cfg,
            Err(e) => return internal_error(&e.to_string()),
        };

        let current_etag = compute_etag(&stored);
        if let Some(expected_etag) = if_match
            && expected_etag != current_etag
        {
            return json_error_response(
                StatusCode::PRECONDITION_FAILED,
                "the configuration changed since you read it; read it again and reapply your change",
                None,
            );
        }

        let candidate = Config {
            path: stored.path.clone(),
            ..Config::default()
        };

        if let Err(e) = write_document(&self.config_path, &candidate) {
            return internal_error(&e.to_string());
        }

        let changed = diff_configs(&stored, &candidate);
        let new_etag = compute_etag(&candidate);

        let mut response_config = candidate;
        if !show_secrets {
            redact_secrets(&mut response_config);
        }

        let body = format_api_response(&response_config, &changed);
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ETAG, new_etag)
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    fn handle_validate(&self, body_bytes: &[u8]) -> Response<Full<Bytes>> {
        let val: serde_json::Value = match serde_json::from_slice(body_bytes) {
            Ok(v) => v,
            Err(e) => {
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("body is not a valid configuration document: {e}"),
                    None,
                );
            },
        };

        if has_redacted_secrets(&val) {
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "portainer.edgeKey was sent back as \"***\", the placeholder a redacted read returns; send the real value or omit the setting to keep the stored one",
                Some("portainer.edgeKey"),
            );
        }

        let candidate = match apply_merge_patch(&Config::default(), &val) {
            Ok(cfg) => cfg,
            Err(e) => {
                return json_error_response(StatusCode::BAD_REQUEST, &e.message, None);
            },
        };

        if let Err(e) = candidate.clone().validate(&self.host) {
            let msg = format_validation_error(&e);
            return json_error_response(StatusCode::UNPROCESSABLE_ENTITY, &msg, None);
        }

        let stored = match self.read_stored() {
            Ok(cfg) => cfg,
            Err(e) => return internal_error(&e.to_string()),
        };

        let changed = diff_configs(&stored, &candidate);
        let mut response_config = candidate;
        redact_secrets(&mut response_config);
        let body = format_api_response(&response_config, &changed);

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }
}

fn format_validation_error(error: &diorama_config::ConfigError) -> String {
    if error.path == "d2k.enabled" && error.message.contains("loadBalancer") {
        "d2k.enabled requires network.loadBalancer.enabled: the d2k Service endpoint is populated by the LoadBalancer webhook".to_string()
    } else {
        error.to_string()
    }
}

fn headers_get_str(headers: &header::HeaderMap, key: header::HeaderName) -> Option<&str> {
    headers.get(key).and_then(|v| v.to_str().ok())
}

fn json_error_response(
    status: StatusCode,
    message: &str,
    field: Option<&str>,
) -> Response<Full<Bytes>> {
    let body = if let Some(f) = field {
        serde_json::json!({
            "error": message,
            "field": f,
        })
    } else {
        serde_json::json!({
            "error": message,
        })
    };
    let mut s = serde_json::to_string(&body).unwrap();
    s.push('\n');

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(s)))
        .unwrap()
}

fn method_not_allowed() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .body(Full::new(Bytes::from_static(b"Method Not Allowed\n")))
        .unwrap()
}

fn internal_error(message: &str) -> Response<Full<Bytes>> {
    json_error_response(StatusCode::INTERNAL_SERVER_ERROR, message, None)
}
