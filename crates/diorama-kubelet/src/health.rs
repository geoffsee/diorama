use serde::{Deserialize, Serialize};

/// Health status and diagnostic report for the Kubelet service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubeletHealthReport {
    pub is_healthy: bool,
    pub node_name: String,
    pub node_ready: bool,
    pub runtime_endpoint: String,
    pub runtime_provider: String,
    pub cgroup_driver: String,
    pub active_pods: usize,
    pub message: Option<String>,
}

impl KubeletHealthReport {
    #[must_use]
    pub fn new_healthy(
        node_name: impl Into<String>,
        node_ready: bool,
        runtime_endpoint: impl Into<String>,
        runtime_provider: impl Into<String>,
        cgroup_driver: impl Into<String>,
        active_pods: usize,
    ) -> Self {
        Self {
            is_healthy: true,
            node_name: node_name.into(),
            node_ready,
            runtime_endpoint: runtime_endpoint.into(),
            runtime_provider: runtime_provider.into(),
            cgroup_driver: cgroup_driver.into(),
            active_pods,
            message: None,
        }
    }

    #[must_use]
    pub fn new_unhealthy(node_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            is_healthy: false,
            node_name: node_name.into(),
            node_ready: false,
            runtime_endpoint: String::new(),
            runtime_provider: String::new(),
            cgroup_driver: String::new(),
            active_pods: 0,
            message: Some(reason.into()),
        }
    }
}

use serde_json::Value;

/// Classification of container health probes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeKind {
    Startup,
    Liveness,
    Readiness,
}

impl ProbeKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Liveness => "liveness",
            Self::Readiness => "readiness",
        }
    }
}

/// Supported action mechanisms for evaluating container health.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeHandler {
    HttpGet {
        host: Option<String>,
        port: u16,
        path: String,
        scheme: String,
        http_headers: Vec<(String, String)>,
    },
    TcpSocket {
        host: Option<String>,
        port: u16,
    },
    Exec {
        command: Vec<String>,
    },
    Grpc {
        port: u16,
        service: Option<String>,
    },
}

/// Parsed configuration and thresholds for a probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeSpec {
    pub kind: ProbeKind,
    pub handler: ProbeHandler,
    pub initial_delay_seconds: u64,
    pub period_seconds: u64,
    pub timeout_seconds: u64,
    pub success_threshold: u32,
    pub failure_threshold: u32,
}

fn parse_http_headers(http_obj: &Value) -> Vec<(String, String)> {
    let mut http_headers = Vec::new();
    let Some(headers) = http_obj.get("httpHeaders").and_then(Value::as_array) else {
        return http_headers;
    };
    for h in headers {
        if let (Some(k), Some(v)) = (
            h.get("name").and_then(Value::as_str),
            h.get("value").and_then(Value::as_str),
        ) {
            http_headers.push((k.to_string(), v.to_string()));
        }
    }
    http_headers
}

impl ProbeSpec {
    /// Parses a probe specification from container JSON.
    #[must_use]
    pub fn parse(kind: ProbeKind, probe_val: &Value) -> Option<Self> {
        let handler = if let Some(http) = probe_val.get("httpGet") {
            let port = parse_port(http.get("port"))?;
            let path = http
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("/")
                .to_string();
            let scheme = http
                .get("scheme")
                .and_then(Value::as_str)
                .unwrap_or("HTTP")
                .to_uppercase();
            let host = http
                .get("host")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let http_headers = parse_http_headers(http);
            ProbeHandler::HttpGet {
                host,
                port,
                path,
                scheme,
                http_headers,
            }
        } else if let Some(tcp) = probe_val.get("tcpSocket") {
            let port = parse_port(tcp.get("port"))?;
            let host = tcp
                .get("host")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            ProbeHandler::TcpSocket { host, port }
        } else if let Some(exec) = probe_val.get("exec") {
            let cmd_arr = exec.get("command").and_then(Value::as_array)?;
            let command: Vec<String> = cmd_arr
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect();
            if command.is_empty() {
                return None;
            }
            ProbeHandler::Exec { command }
        } else {
            let grpc = probe_val.get("grpc")?;
            let port = parse_port(grpc.get("port"))?;
            let service = grpc
                .get("service")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            ProbeHandler::Grpc { port, service }
        };

        let initial_delay_seconds = probe_val
            .get("initialDelaySeconds")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let period_seconds = probe_val
            .get("periodSeconds")
            .and_then(Value::as_u64)
            .filter(|&p| p > 0)
            .unwrap_or(10);
        let timeout_seconds = probe_val
            .get("timeoutSeconds")
            .and_then(Value::as_u64)
            .filter(|&t| t > 0)
            .unwrap_or(1);
        let success_threshold = probe_val
            .get("successThreshold")
            .and_then(Value::as_u64)
            .filter(|&s| s > 0)
            .and_then(|s| u32::try_from(s).ok())
            .unwrap_or(1);
        let failure_threshold = probe_val
            .get("failureThreshold")
            .and_then(Value::as_u64)
            .filter(|&f| f > 0)
            .and_then(|f| u32::try_from(f).ok())
            .unwrap_or(3);

        Some(Self {
            kind,
            handler,
            initial_delay_seconds,
            period_seconds,
            timeout_seconds,
            success_threshold,
            failure_threshold,
        })
    }
}

fn parse_port(port_val: Option<&Value>) -> Option<u16> {
    port_val.and_then(|v| {
        v.as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .or_else(|| v.as_str().and_then(|s| s.parse::<u16>().ok()))
    })
}

/// Runtime tracking state for a probe on a specific container attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeEvaluationState {
    pub last_run_secs: u64,
    pub consecutive_successes: u32,
    pub consecutive_failures: u32,
    pub is_healthy: bool,
    pub has_run: bool,
}

impl ProbeEvaluationState {
    /// Determines whether the probe is due to be executed.
    #[must_use]
    pub fn should_probe(
        &self,
        now_secs: u64,
        container_started_at_secs: u64,
        spec: &ProbeSpec,
    ) -> bool {
        if container_started_at_secs > 0
            && now_secs < container_started_at_secs + spec.initial_delay_seconds
        {
            return false;
        }
        if self.has_run
            && spec.period_seconds > 0
            && now_secs < self.last_run_secs + spec.period_seconds
        {
            return false;
        }
        true
    }

    /// Records the probe execution outcome and updates health state according to thresholds.
    pub fn record_result(&mut self, success: bool, spec: &ProbeSpec, now_secs: u64) -> bool {
        self.last_run_secs = now_secs;
        self.has_run = true;
        if success {
            self.consecutive_failures = 0;
            self.consecutive_successes = self.consecutive_successes.saturating_add(1);
            if self.consecutive_successes >= spec.success_threshold {
                self.is_healthy = true;
            }
        } else {
            self.consecutive_successes = 0;
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            if self.consecutive_failures >= spec.failure_threshold {
                self.is_healthy = false;
            }
        }
        self.is_healthy
    }
}

/// Enforces startup probe gating: liveness and readiness probes must wait
/// until the startup probe (if defined) has succeeded.
#[must_use]
pub fn can_evaluate_liveness_readiness(
    startup_configured: bool,
    startup_state: Option<&ProbeEvaluationState>,
) -> bool {
    if !startup_configured {
        return true;
    }
    startup_state.is_some_and(|state| state.is_healthy)
}

/// Lifecycle hook phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleHookType {
    PreStop,
    PostStart,
}

/// Supported action for a container lifecycle hook.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleAction {
    Exec {
        command: Vec<String>,
    },
    HttpGet {
        host: Option<String>,
        port: u16,
        path: String,
        scheme: String,
        http_headers: Vec<(String, String)>,
    },
    Sleep {
        seconds: u64,
    },
}

/// Lifecycle hook configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleHookSpec {
    pub hook_type: LifecycleHookType,
    pub action: LifecycleAction,
}

impl LifecycleHookSpec {
    /// Parses a lifecycle hook from a JSON value.
    #[must_use]
    pub fn parse(hook_type: LifecycleHookType, val: &Value) -> Option<Self> {
        if let Some(exec) = val.get("exec") {
            let cmd_arr = exec.get("command").and_then(Value::as_array)?;
            let command: Vec<String> = cmd_arr
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect();
            if !command.is_empty() {
                return Some(Self {
                    hook_type,
                    action: LifecycleAction::Exec { command },
                });
            }
        } else if let Some(http) = val.get("httpGet") {
            let port = parse_port(http.get("port"))?;
            let path = http
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("/")
                .to_string();
            let scheme = http
                .get("scheme")
                .and_then(Value::as_str)
                .unwrap_or("HTTP")
                .to_uppercase();
            let host = http
                .get("host")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let http_headers = parse_http_headers(http);
            return Some(Self {
                hook_type,
                action: LifecycleAction::HttpGet {
                    host,
                    port,
                    path,
                    scheme,
                    http_headers,
                },
            });
        } else if let Some(sleep) = val.get("sleep") {
            let seconds = sleep.get("seconds").and_then(Value::as_u64).unwrap_or(0);
            return Some(Self {
                hook_type,
                action: LifecycleAction::Sleep { seconds },
            });
        }
        None
    }
}

/// Extracts postStart and preStop lifecycle hooks from a container specification.
#[must_use]
pub fn parse_container_lifecycle(
    container: &Value,
) -> (Option<LifecycleHookSpec>, Option<LifecycleHookSpec>) {
    let lifecycle = container.get("lifecycle");
    let post_start = lifecycle
        .and_then(|l| l.get("postStart"))
        .and_then(|ps| LifecycleHookSpec::parse(LifecycleHookType::PostStart, ps));
    let pre_stop = lifecycle
        .and_then(|l| l.get("preStop"))
        .and_then(|ps| LifecycleHookSpec::parse(LifecycleHookType::PreStop, ps));
    (post_start, pre_stop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_probe_spec_parse_http_tcp_exec_grpc() {
        let http_val = json!({
            "httpGet": {
                "path": "/healthz",
                "port": 8080,
                "scheme": "http",
                "httpHeaders": [{ "name": "X-Custom", "value": "check" }]
            },
            "initialDelaySeconds": 5,
            "periodSeconds": 15,
            "timeoutSeconds": 2,
            "successThreshold": 1,
            "failureThreshold": 4
        });
        let http_spec = ProbeSpec::parse(ProbeKind::Liveness, &http_val).unwrap();
        assert_eq!(http_spec.initial_delay_seconds, 5);
        assert_eq!(http_spec.period_seconds, 15);
        assert_eq!(http_spec.timeout_seconds, 2);
        assert_eq!(http_spec.success_threshold, 1);
        assert_eq!(http_spec.failure_threshold, 4);
        assert!(matches!(
            http_spec.handler,
            ProbeHandler::HttpGet { port: 8080, .. }
        ));

        let tcp_val = json!({
            "tcpSocket": { "port": 9000, "host": "127.0.0.1" }
        });
        let tcp_spec = ProbeSpec::parse(ProbeKind::Readiness, &tcp_val).unwrap();
        assert_eq!(tcp_spec.period_seconds, 10);
        assert_eq!(tcp_spec.failure_threshold, 3);
        assert!(matches!(
            tcp_spec.handler,
            ProbeHandler::TcpSocket { port: 9000, .. }
        ));

        let exec_val = json!({
            "exec": { "command": ["cat", "/tmp/healthy"] }
        });
        let exec_spec = ProbeSpec::parse(ProbeKind::Startup, &exec_val).unwrap();
        assert!(
            matches!(exec_spec.handler, ProbeHandler::Exec { ref command } if command == &["cat", "/tmp/healthy"])
        );

        let grpc_val = json!({
            "grpc": { "port": 50051, "service": "health" }
        });
        let grpc_spec = ProbeSpec::parse(ProbeKind::Liveness, &grpc_val).unwrap();
        assert!(
            matches!(grpc_spec.handler, ProbeHandler::Grpc { port: 50051, ref service } if service.as_deref() == Some("health"))
        );
    }

    #[test]
    fn test_probe_evaluation_state_transitions() {
        let spec = ProbeSpec {
            kind: ProbeKind::Readiness,
            handler: ProbeHandler::TcpSocket {
                host: None,
                port: 80,
            },
            initial_delay_seconds: 10,
            period_seconds: 5,
            timeout_seconds: 1,
            success_threshold: 2,
            failure_threshold: 2,
        };

        let mut state = ProbeEvaluationState::default();
        let started_at = 1000;

        // Before initialDelaySeconds
        assert!(!state.should_probe(1005, started_at, &spec));
        assert!(state.should_probe(1010, started_at, &spec));

        // First success: successThreshold is 2, so not yet ready
        assert!(!state.record_result(true, &spec, 1010));
        assert_eq!(state.consecutive_successes, 1);

        // Before period expires
        assert!(!state.should_probe(1012, started_at, &spec));
        assert!(state.should_probe(1015, started_at, &spec));

        // Second success: threshold reached, now ready!
        assert!(state.record_result(true, &spec, 1015));
        assert_eq!(state.consecutive_successes, 2);
        assert!(state.is_healthy);

        // One failure: failureThreshold is 2, so still ready
        assert!(state.record_result(false, &spec, 1020));
        assert_eq!(state.consecutive_failures, 1);
        assert!(state.is_healthy);

        // Second failure: failure threshold tripped, transitions to unready
        assert!(!state.record_result(false, &spec, 1025));
        assert_eq!(state.consecutive_failures, 2);
        assert!(!state.is_healthy);
    }

    #[test]
    fn test_startup_probe_gating() {
        // When startup probe not configured, liveness/readiness can evaluate
        assert!(can_evaluate_liveness_readiness(false, None));

        // When startup probe configured but hasn't succeeded
        let unready_startup = ProbeEvaluationState {
            is_healthy: false,
            ..ProbeEvaluationState::default()
        };
        assert!(!can_evaluate_liveness_readiness(
            true,
            Some(&unready_startup)
        ));

        // Once startup probe succeeds, liveness/readiness can evaluate
        let ready_startup = ProbeEvaluationState {
            is_healthy: true,
            ..ProbeEvaluationState::default()
        };
        assert!(can_evaluate_liveness_readiness(true, Some(&ready_startup)));
    }

    #[test]
    fn test_lifecycle_hooks_parse() {
        let container = json!({
            "name": "web",
            "lifecycle": {
                "postStart": {
                    "exec": { "command": ["/bin/sh", "-c", "echo start"] }
                },
                "preStop": {
                    "sleep": { "seconds": 15 }
                }
            }
        });

        let (post_start, pre_stop) = parse_container_lifecycle(&container);
        assert!(post_start.is_some());
        let ps = post_start.unwrap();
        assert_eq!(ps.hook_type, LifecycleHookType::PostStart);
        assert!(matches!(ps.action, LifecycleAction::Exec { ref command } if command.len() == 3));

        assert!(pre_stop.is_some());
        let pr = pre_stop.unwrap();
        assert_eq!(pr.hook_type, LifecycleHookType::PreStop);
        assert_eq!(pr.action, LifecycleAction::Sleep { seconds: 15 });
    }
}
