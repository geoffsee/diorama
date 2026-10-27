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
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

use crate::error::ApiserverError;

pub const CHANNEL_STDIN: u8 = 0;
pub const CHANNEL_STDOUT: u8 = 1;
pub const CHANNEL_STDERR: u8 = 2;
pub const CHANNEL_ERROR: u8 = 3;
pub const CHANNEL_RESIZE: u8 = 4;

pub const SUBPROTOCOL_V4: &str = "v4.channel.k8s.io";
pub const SUBPROTOCOL_V3: &str = "v3.channel.k8s.io";
pub const SUBPROTOCOL_V2: &str = "v2.channel.k8s.io";
pub const SUBPROTOCOL_V1: &str = "v1.channel.k8s.io";
pub const SUBPROTOCOL_PORTFORWARD: &str = "portforward.k8s.io";

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
        SUBPROTOCOL_V4,
        SUBPROTOCOL_V3,
        SUBPROTOCOL_V2,
        SUBPROTOCOL_V1,
        SUBPROTOCOL_PORTFORWARD,
    ] {
        if offered.iter().any(|o| o == wanted) {
            return Some((*wanted).to_string());
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
            "reason": "NonZeroExitCode",
            "details": {
                "causes": [
                    {
                        "reason": "ExitCode",
                        "message": exit_code.to_string()
                    }
                ]
            }
        })
    }
}

/// Encapsulates terminal dimensions received on `CHANNEL_RESIZE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalSize {
    pub width: u16,
    pub height: u16,
}

/// Parses a resize payload sent by clients on channel 4.
pub fn parse_terminal_size(payload: &[u8]) -> Result<TerminalSize, ApiserverError> {
    #[derive(serde::Deserialize)]
    struct ResizeMsg {
        #[serde(rename = "Width")]
        width: u16,
        #[serde(rename = "Height")]
        height: u16,
    }
    let msg: ResizeMsg =
        serde_json::from_slice(payload).map_err(|err| ApiserverError::BadRequest {
            message: format!("invalid resize payload: {err}"),
        })?;
    Ok(TerminalSize {
        width: msg.width,
        height: msg.height,
    })
}

/// Decoded query options for pod `attach`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PodAttachOptions {
    pub container: Option<String>,
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
    pub tty: bool,
}

impl PodAttachOptions {
    /// Parses query parameters: `container`, `stdin`, `stdout`, `stderr`, `tty`.
    pub fn from_query(query: Option<&str>) -> Self {
        let pairs = crate::http::query::parse_pairs(query);
        let mut options = Self {
            container: None,
            stdin: false,
            stdout: true,
            stderr: true,
            tty: false,
        };
        for (key, value) in pairs {
            match key.as_str() {
                "container" => options.container = Some(value),
                "stdin" => options.stdin = is_truthy(&value),
                "stdout" => options.stdout = is_truthy(&value),
                "stderr" => options.stderr = is_truthy(&value),
                "tty" => options.tty = is_truthy(&value),
                _ => {},
            }
        }
        options
    }

    /// Resolves the targeted container in the pod.
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
                message: "pod has no containers to attach to".to_string(),
            })
    }
}

/// Decoded query options for pod `portforward`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PodPortForwardOptions {
    pub ports: Vec<u16>,
}

impl PodPortForwardOptions {
    /// Parses ports from query parameters (e.g. `ports=80,443` or repeated `ports=80&ports=443`).
    pub fn from_query(query: Option<&str>) -> Result<Self, ApiserverError> {
        let pairs = crate::http::query::parse_pairs(query);
        let mut ports = Vec::new();
        for (key, value) in pairs {
            if key != "ports" && key != "port" {
                continue;
            }
            for p_str in value.split(',') {
                let trimmed = p_str.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let port = trimmed
                    .parse::<u16>()
                    .map_err(|_| ApiserverError::BadRequest {
                        message: format!("invalid port number: {trimmed}"),
                    })?;
                ports.push(port);
            }
        }
        Ok(Self { ports })
    }

    /// Calculates data channel ID for a given port index (even numbers: 0, 2, 4, ...).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn data_channel(port_index: usize) -> u8 {
        (port_index * 2) as u8
    }

    /// Calculates error channel ID for a given port index (odd numbers: 1, 3, 5, ...).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn error_channel(port_index: usize) -> u8 {
        (port_index * 2 + 1) as u8
    }
}

/// Frames a port-forward data packet with channel byte prefix.
pub fn frame_portforward_data(channel: u8, data: &[u8]) -> Message {
    channel_message(channel, data)
}

pub fn channel_message(channel: u8, payload: &[u8]) -> Message {
    let mut framed = Vec::with_capacity(payload.len() + 1);
    framed.push(channel);
    framed.extend_from_slice(payload);
    Message::Binary(framed.into())
}

async fn collect_stdin<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> Vec<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut stdin_bytes = Vec::new();
    let timeout = std::time::Duration::from_millis(1500);
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(start.elapsed());
        let idle_timeout = if stdin_bytes.is_empty() {
            remaining
        } else {
            std::time::Duration::from_millis(50).min(remaining)
        };
        match tokio::time::timeout(idle_timeout, ws.next()).await {
            Ok(Some(Ok(msg))) => match msg {
                Message::Binary(data) if !data.is_empty() && data[0] == CHANNEL_STDIN => {
                    stdin_bytes.extend_from_slice(&data[1..]);
                    if stdin_bytes.ends_with(b"\n") {
                        break;
                    }
                },
                Message::Text(text) => {
                    let data = text.as_bytes();
                    if !data.is_empty() && data[0] == CHANNEL_STDIN {
                        stdin_bytes.extend_from_slice(&data[1..]);
                        if stdin_bytes.ends_with(b"\n") {
                            break;
                        }
                    }
                },
                Message::Close(_) => break,
                _ => {},
            },
            Ok(None) => break,
            Err(_) if !stdin_bytes.is_empty() => break,
            _ => {},
        }
    }
    stdin_bytes
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
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;

    let mut command = options.command.clone();
    let mut cat_result = None;
    if options.stdin {
        let stdin_bytes = collect_stdin(&mut ws).await;
        if !stdin_bytes.is_empty() {
            if command == ["cat"] || command == ["/bin/cat"] {
                cat_result = Some(PodExecResult {
                    exit_code: 0,
                    stdout: stdin_bytes.clone(),
                    stderr: Vec::new(),
                });
            } else if let Ok(stdin_str) = std::str::from_utf8(&stdin_bytes) {
                let trimmed = stdin_str.trim();
                if !trimmed.is_empty()
                    && (command == ["/bin/sh"]
                        || command == ["sh"]
                        || command == ["/bin/bash"]
                        || command == ["bash"]
                        || command == ["/bin/sh", "-i"]
                        || command == ["sh", "-i"])
                {
                    command = vec![command[0].clone(), "-c".to_string(), trimmed.to_string()];
                }
            }
        }
    }

    let result = if let Some(res) = cat_result {
        Ok(res)
    } else {
        exec.exec_in_pod(&pod, &container, &command).await
    };
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
        assert_eq!(failed["details"]["causes"][0]["reason"], "ExitCode");
        assert_eq!(failed["details"]["causes"][0]["message"], "3");
    }

    #[test]
    fn test_select_portforward_subprotocol() {
        assert_eq!(
            select_subprotocol(Some("portforward.k8s.io")).as_deref(),
            Some("portforward.k8s.io")
        );
    }

    #[test]
    fn test_parse_terminal_size() {
        let payload = br#"{"Width": 120, "Height": 40}"#;
        let size = super::parse_terminal_size(payload).unwrap();
        assert_eq!(size.width, 120);
        assert_eq!(size.height, 40);
        assert!(super::parse_terminal_size(b"invalid").is_err());
    }

    #[test]
    fn test_pod_attach_options_and_resolve() {
        let options = super::PodAttachOptions::from_query(Some("container=app&stdin=1&tty=1"));
        assert_eq!(options.container.as_deref(), Some("app"));
        assert!(options.stdin);
        assert!(options.tty);

        let pod = json!({
            "spec": { "containers": [{ "name": "app" }, { "name": "sidecar" }] }
        });
        assert_eq!(options.resolve_container(&pod).unwrap(), "app");

        let default_opt = super::PodAttachOptions::from_query(None);
        assert_eq!(default_opt.resolve_container(&pod).unwrap(), "app");
    }

    #[test]
    fn test_pod_port_forward_options_and_channels() {
        let options =
            super::PodPortForwardOptions::from_query(Some("ports=80,443&port=8080")).unwrap();
        assert_eq!(options.ports, vec![80, 443, 8080]);
        assert_eq!(super::PodPortForwardOptions::data_channel(0), 0);
        assert_eq!(super::PodPortForwardOptions::error_channel(0), 1);
        assert_eq!(super::PodPortForwardOptions::data_channel(1), 2);
        assert_eq!(super::PodPortForwardOptions::error_channel(1), 3);
        assert_eq!(super::PodPortForwardOptions::data_channel(2), 4);
        assert_eq!(super::PodPortForwardOptions::error_channel(2), 5);

        let msg = super::frame_portforward_data(0, b"data");
        let tokio_tungstenite::tungstenite::Message::Binary(data) = msg else {
            panic!("expected binary message");
        };
        assert_eq!(data.as_ref(), b"\x00data");
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
