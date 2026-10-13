//! Pod `exec` over the `v4.channel.k8s.io` websocket subprotocol.
//!
//! Upstream kube-apiserver proxies `.../pods/{name}/exec` to the kubelet, which
//! streams the command over SPDY or websocket channels. Here the kubelet runs in
//! the same process: it registers a [`PodExec`] implementation with
//! [`crate::ApiserverService`], the HTTPS gateway upgrades the request, runs the
//! command synchronously through CRI `exec_sync`, then replays the captured
//! output on the stdout/stderr channels followed by a status on the error
//! channel. Streaming stdin and TTY resizing are not supported; `stdin` bytes
//! sent by the client are drained and ignored.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::SinkExt;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use crate::error::ApiserverError;

pub const CHANNEL_STDIN: u8 = 0;
pub const CHANNEL_STDOUT: u8 = 1;
pub const CHANNEL_STDERR: u8 = 2;
pub const CHANNEL_ERROR: u8 = 3;

/// Captured output of one synchronous container exec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PodExecResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Runs a command in one container of a stored Pod object.
#[async_trait]
pub trait PodExec: std::fmt::Debug + Send + Sync {
    async fn exec_in_pod(
        &self,
        pod: &Value,
        container: &str,
        command: &[String],
    ) -> Result<PodExecResult, ApiserverError>;
}

/// Decoded `exec` query parameters.
// The four flags map one-to-one onto the Kubernetes `exec` query parameters.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PodExecOptions {
    pub container: Option<String>,
    pub command: Vec<String>,
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
    pub tty: bool,
}

impl PodExecOptions {
    /// Parses `command` (repeated), `container`, `stdin`, `stdout`, `stderr`, `tty`.
    pub fn from_query(query: Option<&str>) -> Result<Self, ApiserverError> {
        let pairs = crate::http::query::parse_pairs(query);
        let mut options = Self {
            container: None,
            command: Vec::new(),
            stdin: false,
            stdout: true,
            stderr: true,
            tty: false,
        };
        for (key, value) in pairs {
            match key.as_str() {
                "command" => options.command.push(value),
                "container" => options.container = Some(value),
                "stdin" => options.stdin = is_truthy(&value),
                "stdout" => options.stdout = is_truthy(&value),
                "stderr" => options.stderr = is_truthy(&value),
                "tty" => options.tty = is_truthy(&value),
                _ => {},
            }
        }
        if options.command.is_empty() {
            return Err(ApiserverError::BadRequest {
                message: "exec requires at least one command parameter".to_string(),
            });
        }
        Ok(options)
    }

    /// Resolves the target container: the requested one, or the pod's first.
    pub fn resolve_container(&self, pod: &Value) -> Result<String, ApiserverError> {
        let containers = pod
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(wanted) = self.container.as_deref().filter(|c| !c.is_empty()) {
            if containers
                .iter()
                .any(|c| c.get("name").and_then(Value::as_str) == Some(wanted))
            {
                return Ok(wanted.to_string());
            }
            return Err(ApiserverError::BadRequest {
                message: format!("container {wanted} is not in the pod spec"),
            });
        }
        containers
            .first()
            .and_then(|c| c.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| ApiserverError::BadRequest {
                message: "pod has no containers to exec into".to_string(),
            })
    }
}

fn is_truthy(value: &str) -> bool {
    matches!(value, "1" | "true" | "True" | "TRUE")
}

/// Selects the streaming subprotocol to speak. `v4.channel.k8s.io` is the only
/// dialect implemented; older `vN.channel.k8s.io` values share its framing for
/// non-interactive exec, so the newest offered channel protocol is selected.
pub fn select_subprotocol(header: Option<&str>) -> Option<String> {
    let offered: Vec<String> = header?
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect();
    for wanted in [
        "v4.channel.k8s.io",
        "v3.channel.k8s.io",
        "v2.channel.k8s.io",
        "v1.channel.k8s.io",
    ] {
        if offered.iter().any(|o| o == wanted) {
            return Some(wanted.to_string());
        }
    }
    offered.into_iter().next()
}

/// Status payload sent on the error channel when the command completes.
pub fn exit_status(exit_code: i32) -> Value {
    if exit_code == 0 {
        json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Success"
        })
    } else {
        json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": format!("command terminated with exit code {exit_code}"),
            "reason": "NonZeroExitCode"
        })
    }
}

fn channel_message(channel: u8, payload: &[u8]) -> Message {
    let mut framed = Vec::with_capacity(payload.len() + 1);
    framed.push(channel);
    framed.extend_from_slice(payload);
    Message::Binary(framed.into())
}

/// Runs the command and replays its output on a server-side websocket.
///
/// `stream` must already have completed the HTTP upgrade handshake.
pub async fn serve_exec<S>(
    stream: S,
    exec: Arc<dyn PodExec>,
    pod: Value,
    options: PodExecOptions,
    container: String,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt;

    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;
    let result = exec.exec_in_pod(&pod, &container, &options.command).await;
    match result {
        Ok(output) => {
            if options.stdout && !output.stdout.is_empty() {
                let _ = ws
                    .send(channel_message(CHANNEL_STDOUT, &output.stdout))
                    .await;
            }
            if !options.tty && options.stderr && !output.stderr.is_empty() {
                let _ = ws
                    .send(channel_message(CHANNEL_STDERR, &output.stderr))
                    .await;
            } else if options.tty && options.stderr && !output.stderr.is_empty() {
                // A TTY merges stderr into the terminal output stream.
                let _ = ws
                    .send(channel_message(CHANNEL_STDOUT, &output.stderr))
                    .await;
            }
            let status = serde_json::to_vec(&exit_status(output.exit_code)).unwrap_or_default();
            let _ = ws.send(channel_message(CHANNEL_ERROR, &status)).await;
        },
        Err(err) => {
            let status = json!({
                "kind": "Status",
                "apiVersion": "v1",
                "metadata": {},
                "status": "Failure",
                "message": err.to_string(),
                "reason": "InternalError"
            });
            let payload = serde_json::to_vec(&status).unwrap_or_default();
            let _ = ws.send(channel_message(CHANNEL_ERROR, &payload)).await;
        },
    }
    // Close with an explicit Normal code. Go clients (kubectl, the e2e
    // framework) treat a codeless close as abnormal (1005) and fail the exec
    // even though every channel message arrived intact.
    let _ = ws
        .close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "".into(),
        }))
        .await;
    // Drain stdin bytes the client may still send so the TCP half-close completes.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while ws.next().await.is_some() {}
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::{
        CHANNEL_ERROR, CHANNEL_STDERR, CHANNEL_STDOUT, PodExec, PodExecOptions, PodExecResult,
        exit_status, select_subprotocol, serve_exec,
    };
    use serde_json::json;

    #[test]
    fn parses_repeated_command_params_in_order() {
        let options =
            PodExecOptions::from_query(Some("command=echo&command=ok&container=app&stdin=1"))
                .unwrap();
        assert_eq!(options.command, vec!["echo".to_string(), "ok".to_string()]);
        assert_eq!(options.container.as_deref(), Some("app"));
        assert!(options.stdin);
        assert!(options.stdout);
        assert!(PodExecOptions::from_query(Some("container=app")).is_err());
        assert!(PodExecOptions::from_query(None).is_err());
    }

    #[test]
    fn resolves_default_and_named_containers() {
        let pod = json!({
            "spec": { "containers": [{"name": "app"}, {"name": "sidecar"}] }
        });
        let options = PodExecOptions::from_query(Some("command=echo")).unwrap();
        assert_eq!(options.resolve_container(&pod).unwrap(), "app");
        let options = PodExecOptions::from_query(Some("command=echo&container=sidecar")).unwrap();
        assert_eq!(options.resolve_container(&pod).unwrap(), "sidecar");
        let options = PodExecOptions::from_query(Some("command=echo&container=missing")).unwrap();
        assert!(options.resolve_container(&pod).is_err());
    }

    #[test]
    fn prefers_v4_channel_subprotocol() {
        assert_eq!(
            select_subprotocol(Some("v2.channel.k8s.io, v4.channel.k8s.io")).as_deref(),
            Some("v4.channel.k8s.io")
        );
        assert_eq!(
            select_subprotocol(Some("v3.channel.k8s.io")).as_deref(),
            Some("v3.channel.k8s.io")
        );
        assert_eq!(select_subprotocol(None), None);
    }

    #[test]
    fn exit_status_reports_success_and_failure() {
        assert_eq!(exit_status(0)["status"], "Success");
        let failed = exit_status(3);
        assert_eq!(failed["status"], "Failure");
        assert_eq!(failed["reason"], "NonZeroExitCode");
    }

    #[derive(Debug)]
    struct StaticExec {
        result: Result<PodExecResult, String>,
    }

    #[async_trait::async_trait]
    impl PodExec for StaticExec {
        async fn exec_in_pod(
            &self,
            _pod: &serde_json::Value,
            _container: &str,
            _command: &[String],
        ) -> Result<PodExecResult, crate::error::ApiserverError> {
            self.result
                .clone()
                .map_err(|message| crate::error::ApiserverError::Internal { reason: message })
        }
    }

    type ClientWs = tokio_tungstenite::WebSocketStream<tokio::io::DuplexStream>;

    async fn client_ws(client: tokio::io::DuplexStream) -> ClientWs {
        tokio_tungstenite::WebSocketStream::from_raw_socket(
            client,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await
    }

    /// Reads channel output until the server closes, returning
    /// `(stdout, stderr, status)`.
    async fn collect_output(ws: &mut ClientWs) -> (Vec<u8>, Vec<u8>, serde_json::Value) {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut status = serde_json::Value::Null;
        while let Some(Ok(message)) = ws.next().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
            let Message::Binary(data) = message else {
                continue;
            };
            let Some((channel, payload)) = data.split_first() else {
                continue;
            };
            if *channel == CHANNEL_STDOUT {
                stdout.extend_from_slice(payload);
            } else if *channel == CHANNEL_STDERR {
                stderr.extend_from_slice(payload);
            } else if *channel == CHANNEL_ERROR {
                status = serde_json::from_slice(payload).unwrap();
            }
        }
        (stdout, stderr, status)
    }

    #[tokio::test]
    async fn serve_exec_frames_stdout_stderr_and_status() {
        let (server, client) = tokio::io::duplex(64 * 1024);
        let exec = StaticExec {
            result: Ok(PodExecResult {
                exit_code: 0,
                stdout: b"ok\n".to_vec(),
                stderr: b"warn\n".to_vec(),
            }),
        };
        let options = PodExecOptions::from_query(Some("command=echo&command=ok")).unwrap();
        let server_task = tokio::spawn(serve_exec(
            server,
            std::sync::Arc::new(exec),
            json!({}),
            options,
            "app".to_string(),
        ));
        let mut ws = client_ws(client).await;
        let (stdout, stderr, status) = collect_output(&mut ws).await;
        drop(ws);
        server_task.await.unwrap();
        assert_eq!(stdout, b"ok\n");
        assert_eq!(stderr, b"warn\n");
        assert_eq!(status["status"], "Success");
    }

    #[tokio::test]
    async fn serve_exec_reports_failure_on_error_channel() {
        let (server, client) = tokio::io::duplex(64 * 1024);
        let exec = StaticExec {
            result: Ok(PodExecResult {
                exit_code: 3,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
        };
        let options = PodExecOptions::from_query(Some("command=false")).unwrap();
        let server_task = tokio::spawn(serve_exec(
            server,
            std::sync::Arc::new(exec),
            json!({}),
            options,
            "app".to_string(),
        ));
        let mut ws = client_ws(client).await;
        let (_, _, status) = collect_output(&mut ws).await;
        drop(ws);
        server_task.await.unwrap();
        assert_eq!(status["status"], "Failure");
    }
}
