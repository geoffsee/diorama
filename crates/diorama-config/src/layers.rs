use crate::{
    Config, ConfigError, DecodedConfig, ErrorKind, FIELDS, FieldType, HostContext, ValidatedConfig,
    ValidationWarning, Warning,
};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputBinding {
    pub path: &'static str,
    pub environment: &'static str,
    pub flag: Option<&'static str>,
}
/// Baseline registry order, also the error precedence within an input layer.
pub const INPUT_BINDINGS: &[InputBinding] = &[
    InputBinding {
        path: "path",
        environment: "KUBESOLO_PATH",
        flag: Some("path"),
    },
    InputBinding {
        path: "logging.debug",
        environment: "KUBESOLO_DEBUG",
        flag: Some("debug"),
    },
    InputBinding {
        path: "logging.pprof",
        environment: "KUBESOLO_PPROF_SERVER",
        flag: Some("pprof-server"),
    },
    InputBinding {
        path: "network.nodeIP",
        environment: "KUBESOLO_NODE_IP",
        flag: Some("node-ip"),
    },
    InputBinding {
        path: "network.mtu",
        environment: "KUBESOLO_MTU",
        flag: Some("mtu"),
    },
    InputBinding {
        path: "network.disableIPv6",
        environment: "KUBESOLO_DISABLE_IPV6",
        flag: Some("disable-ipv6"),
    },
    InputBinding {
        path: "network.loadBalancer.enabled",
        environment: "KUBESOLO_LOAD_BALANCER",
        flag: Some("load-balancer"),
    },
    InputBinding {
        path: "network.loadBalancer.ip",
        environment: "KUBESOLO_LOAD_BALANCER_IP",
        flag: Some("load-balancer-ip"),
    },
    InputBinding {
        path: "runtime.endpoint",
        environment: "KUBESOLO_CONTAINER_RUNTIME_ENDPOINT",
        flag: Some("container-runtime-endpoint"),
    },
    InputBinding {
        path: "runtime.containerMode",
        environment: "KUBESOLO_CONTAINER_MODE",
        flag: Some("container-mode"),
    },
    InputBinding {
        path: "kubernetes.nodeName",
        environment: "KUBESOLO_NODE_NAME",
        flag: None,
    },
    InputBinding {
        path: "kubernetes.apiServer.extraSANs",
        environment: "KUBESOLO_APISERVER_EXTRA_SANS",
        flag: Some("apiserver-extra-sans"),
    },
    InputBinding {
        path: "kubernetes.apiServer.startupTimeoutSeconds",
        environment: "KUBESOLO_STARTUP_TIMEOUT",
        flag: Some("startup-timeout"),
    },
    InputBinding {
        path: "kubernetes.kubelet.cpuManager.policy",
        environment: "KUBESOLO_CPU_MANAGER_POLICY",
        flag: Some("cpu-manager-policy"),
    },
    InputBinding {
        path: "kubernetes.kubelet.cpuManager.policyOptions",
        environment: "KUBESOLO_CPU_MANAGER_POLICY_OPTIONS",
        flag: Some("cpu-manager-policy-options"),
    },
    InputBinding {
        path: "kubernetes.kubelet.cpuManager.reservedCPUs",
        environment: "KUBESOLO_RESERVED_CPUS",
        flag: Some("reserved-cpus"),
    },
    InputBinding {
        path: "kubernetes.kubelet.systemReserved",
        environment: "KUBESOLO_SYSTEM_RESERVED",
        flag: Some("system-reserved"),
    },
    InputBinding {
        path: "storage.localPath.enabled",
        environment: "KUBESOLO_LOCAL_STORAGE",
        flag: Some("local-storage"),
    },
    InputBinding {
        path: "storage.localPath.sharedPath",
        environment: "KUBESOLO_LOCAL_STORAGE_SHARED_PATH",
        flag: Some("local-storage-shared-path"),
    },
    InputBinding {
        path: "storage.dbWALRepair",
        environment: "KUBESOLO_DB_WAL_REPAIR",
        flag: Some("db-wal-repair"),
    },
    InputBinding {
        path: "portainer.edgeID",
        environment: "KUBESOLO_PORTAINER_EDGE_ID",
        flag: Some("portainer-edge-id"),
    },
    InputBinding {
        path: "portainer.edgeKey",
        environment: "KUBESOLO_PORTAINER_EDGE_KEY",
        flag: Some("portainer-edge-key"),
    },
    InputBinding {
        path: "portainer.async",
        environment: "KUBESOLO_PORTAINER_EDGE_ASYNC",
        flag: Some("portainer-edge-async"),
    },
    InputBinding {
        path: "portainer.image",
        environment: "KUBESOLO_PORTAINER_EDGE_IMAGE",
        flag: Some("portainer-edge-image"),
    },
    InputBinding {
        path: "d2k.enabled",
        environment: "KUBESOLO_D2K",
        flag: Some("d2k"),
    },
    InputBinding {
        path: "d2k.namespace",
        environment: "KUBESOLO_D2K_NAMESPACE",
        flag: Some("d2k-namespace"),
    },
    InputBinding {
        path: "metrics.enabled",
        environment: "KUBESOLO_METRICS_SERVER",
        flag: Some("metrics-server"),
    },
    InputBinding {
        path: "metrics.bindAddress",
        environment: "KUBESOLO_METRICS_BIND_ADDRESS",
        flag: Some("metrics-bind-address"),
    },
    InputBinding {
        path: "api.enabled",
        environment: "KUBESOLO_API_ENABLED",
        flag: None,
    },
    InputBinding {
        path: "api.socketPath",
        environment: "KUBESOLO_API_SOCKET_PATH",
        flag: None,
    },
];
/// Only explicit argv values belong here. Duplicate argv handling is the adapter's responsibility.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ExplicitFlags(pub BTreeMap<String, String>);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvironmentMode {
    Include,
    Omit,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolutionWarning {
    File(Warning),
    Validation(ValidationWarning),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedConfig {
    pub validated: ValidatedConfig,
    pub warnings: Vec<ResolutionWarning>,
}
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ParsedEnvironment {
    values: Vec<(&'static str, Value)>,
}
fn invalid(path: &str, message: impl Into<String>) -> ConfigError {
    ConfigError {
        kind: ErrorKind::Type,
        path: path.into(),
        message: message.into(),
    }
}
fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}
/// Parse a registry setting in its environment/legacy flag string form.
pub fn parse_setting(path: &str, raw: &str) -> Result<Value, ConfigError> {
    let field = FIELDS
        .iter()
        .find(|field| field.path == path)
        .ok_or_else(|| invalid(path, "unknown setting"))?;
    match field.kind {
        FieldType::Boolean | FieldType::OptionalBool => parse_bool(raw)
            .map(Value::Bool)
            .ok_or_else(|| invalid(path, "expected a boolean")),
        FieldType::Integer => raw
            .parse::<i64>()
            .map(|v| Value::Number(v.into()))
            .map_err(|_| invalid(path, "expected an integer")),
        FieldType::String => Ok(Value::String(raw.into())),
        FieldType::StringList => {
            let list: Vec<Value> = raw
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| Value::String(v.into()))
                .collect();
            Ok(if list.is_empty() {
                Value::Null
            } else {
                Value::Array(list)
            })
        },
        FieldType::StringMap => {
            let mut map = serde_json::Map::new();
            for pair in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
                let (key, value) = pair
                    .split_once('=')
                    .ok_or_else(|| invalid(path, "expected key=value pairs"))?;
                map.insert(key.trim().into(), Value::String(value.trim().into()));
            }
            Ok(if map.is_empty() {
                Value::Null
            } else {
                Value::Object(map)
            })
        },
    }
}
/// Independently callable before file IO. Does not read the process environment.
/// This covers registry setter syntax; argv-parser early environment handling remains an adapter concern.
pub fn parse_environment(
    environment: &BTreeMap<String, String>,
) -> Result<ParsedEnvironment, ConfigError> {
    let mut values = Vec::new();
    for binding in INPUT_BINDINGS {
        if let Some(raw) = environment.get(binding.environment) {
            let value = parse_setting(binding.path, raw).map_err(|mut e| {
                e.path = binding.environment.into();
                e
            })?;
            values.push((binding.path, value));
        }
    }
    Ok(ParsedEnvironment { values })
}
fn assign(document: &mut Value, path: &str, value: Value) -> Result<(), ConfigError> {
    let pointer = format!("/{}", path.replace('.', "/"));
    let slot = document
        .pointer_mut(&pointer)
        .ok_or_else(|| invalid(path, "setting is absent from typed configuration"))?;
    *slot = value;
    Ok(())
}
/// Resolve defaults/file/environment/explicit flags, derive dependent defaults, then validate once.
/// Decode the file before calling this function to preserve baseline file-before-setter errors.
pub fn resolve_layers(
    file: Option<DecodedConfig>,
    environment: &BTreeMap<String, String>,
    flags: &ExplicitFlags,
    mode: EnvironmentMode,
    host: &HostContext,
) -> Result<ResolvedConfig, ConfigError> {
    let (config, warnings) = file.map_or_else(
        || (Config::default(), Vec::new()),
        |file| (file.config, file.warnings),
    );
    let environment = if mode == EnvironmentMode::Include {
        parse_environment(environment)?
    } else {
        ParsedEnvironment::default()
    };
    resolve_parsed_layers(config, warnings, &environment, flags, host)
}
/// Compose already parsed environment with a decoded/default file model.
/// Early parsing is opt-in so the executable can match its own argv parser's failure ordering.
pub fn resolve_parsed_layers(
    config: Config,
    warnings: Vec<Warning>,
    environment: &ParsedEnvironment,
    flags: &ExplicitFlags,
    host: &HostContext,
) -> Result<ResolvedConfig, ConfigError> {
    let mut document = serde_json::to_value(config).map_err(|e| invalid("", e.to_string()))?;
    for (path, value) in &environment.values {
        assign(&mut document, path, value.clone())?;
    }
    for binding in INPUT_BINDINGS {
        if let Some(flag) = binding.flag
            && let Some(raw) = flags.0.get(flag)
        {
            let value = parse_setting(binding.path, raw).map_err(|mut e| {
                e.path = format!("--{flag}");
                e
            })?;
            assign(&mut document, binding.path, value)?;
        }
    }
    let mut config: Config =
        serde_json::from_value(document).map_err(|e| invalid("", e.to_string()))?;
    config.derive_socket_path();
    let validated = config.validate(host)?;
    let mut warnings: Vec<_> = warnings.into_iter().map(ResolutionWarning::File).collect();
    warnings.extend(
        validated
            .warnings
            .iter()
            .cloned()
            .map(ResolutionWarning::Validation),
    );
    Ok(ResolvedConfig {
        validated,
        warnings,
    })
}

impl std::fmt::Debug for ExplicitFlags {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExplicitFlags")
            .field("names", &self.0.keys().collect::<Vec<_>>())
            .finish()
    }
}
impl std::fmt::Debug for ParsedEnvironment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParsedEnvironment")
            .field(
                "paths",
                &self.values.iter().map(|(path, _)| path).collect::<Vec<_>>(),
            )
            .finish()
    }
}
