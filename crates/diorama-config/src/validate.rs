use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use crate::{Config, ConfigError, ErrorKind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostContext {
    pub cpu_count: usize,
    pub architecture: String,
    pub detected_container_mode: bool,
}

impl Default for HostContext {
    fn default() -> Self {
        Self::detect()
    }
}

impl HostContext {
    #[must_use]
    pub fn new(
        cpu_count: usize,
        architecture: impl Into<String>,
        detected_container_mode: bool,
    ) -> Self {
        Self {
            cpu_count,
            architecture: architecture.into(),
            detected_container_mode,
        }
    }

    #[must_use]
    pub fn detect() -> Self {
        let architecture = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => other,
        };
        let cpu_count = std::thread::available_parallelism().map_or(2, std::num::NonZero::get);
        let detected_container_mode = std::path::Path::new("/.dockerenv").metadata().is_ok()
            || std::path::Path::new("/run/.containerenv")
                .metadata()
                .is_ok()
            || std::env::var_os("container").is_some_and(|value| !value.is_empty());
        Self {
            cpu_count,
            architecture: architecture.to_string(),
            detected_container_mode,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationWarning {
    pub field: &'static str,
    pub message: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedConfig {
    pub(crate) config: Config,
    pub warnings: Vec<ValidationWarning>,
}
impl ValidatedConfig {
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn into_config(self) -> Config {
        self.config
    }
}
fn invalid(path: &str, message: impl Into<String>) -> ConfigError {
    ConfigError {
        kind: ErrorKind::Type,
        path: path.into(),
        message: message.into(),
    }
}
fn pattern(value: &str, expression: &str) -> Result<bool, ConfigError> {
    Regex::new(expression)
        .map(|r| r.is_match(value))
        .map_err(|e| invalid("", e.to_string()))
}

fn validate_digest(digest: &str) -> Result<(), ConfigError> {
    let Some((algorithm, hex)) = digest.split_once(':') else {
        return Err(invalid("portainer.image", "invalid image digest"));
    };
    let length = match algorithm {
        "sha256" => 64,
        "sha384" => 96,
        "sha512" => 128,
        _ => return Err(invalid("portainer.image", "unsupported digest algorithm")),
    };
    if hex.len() != length
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid(
            "portainer.image",
            "invalid digest length or encoding",
        ));
    }

    Ok(())
}

/// Docker distribution/reference v0.6 normalized-name rules, without registry IO.
pub fn normalize_image(input: &str) -> Result<String, ConfigError> {
    let (name_tag, digest) = input
        .split_once('@')
        .map_or((input, None), |(n, d)| (n, Some(d)));
    if let Some(digest) = digest {
        validate_digest(digest)?;
    }
    let slash = name_tag.rfind('/');
    let colon = name_tag.rfind(':');
    let (name, tag) = if colon.is_some_and(|c| slash.is_none_or(|s| c > s)) {
        let (name, tag) = name_tag
            .rsplit_once(':')
            .ok_or_else(|| invalid("portainer.image", "invalid tag"))?;
        (name, Some(tag))
    } else {
        (name_tag, None)
    };
    if tag.is_some_and(str::is_empty) || tag.is_some_and(|t| t.len() > 128) {
        return Err(invalid("portainer.image", "invalid image tag"));
    }
    if let Some(tag) = tag
        && !pattern(tag, r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")?
    {
        return Err(invalid("portainer.image", "invalid image tag"));
    }
    if input.len() == 64
        && input
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(invalid(
            "portainer.image",
            "bare 64-byte hexadecimal image name",
        ));
    }
    let (domain, path) = match name.split_once('/') {
        Some((first, tail))
            if first.contains('.')
                || first.contains(':')
                || first == "localhost"
                || first.bytes().any(|b| b.is_ascii_uppercase()) =>
        {
            (
                if first == "index.docker.io" {
                    "docker.io"
                } else {
                    first
                },
                tail,
            )
        },
        _ => ("docker.io", name),
    };
    if !pattern(
        domain,
        r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*(?::[0-9]+)?$|^\[[A-Fa-f0-9:]+\](?::[0-9]+)?$",
    )? {
        return Err(invalid("portainer.image", "invalid registry domain"));
    }
    if !pattern(
        path,
        r"^[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)*$",
    )? {
        return Err(invalid("portainer.image", "invalid image repository"));
    }
    let path = if domain == "docker.io" && !path.contains('/') {
        format!("library/{path}")
    } else {
        path.into()
    };
    let mut result = format!("{domain}/{path}");
    if path.len() > 255 {
        return Err(invalid(
            "portainer.image",
            "image repository exceeds 255 bytes",
        ));
    }
    if let Some(tag) = tag {
        result.push(':');
        result.push_str(tag);
    } else if digest.is_none() {
        result.push_str(":latest");
    }
    if let Some(digest) = digest {
        result.push('@');
        result.push_str(digest);
    }
    Ok(result)
}

pub fn resolve_runtime_endpoint(input: &str) -> Result<Option<String>, ConfigError> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }
    let socket = input.strip_prefix("unix://").unwrap_or(input);
    if !socket.starts_with('/') {
        return Err(invalid(
            "runtime.endpoint",
            "expected an absolute socket path or unix:// URL",
        ));
    }
    Ok(Some(format!("unix://{socket}")))
}

#[derive(Debug)]
struct Quantity {
    negative: bool,
    coefficient: String,
    decimal_power: i64,
    binary_power: u32,
}
impl Quantity {
    fn compare_abs(&self, integer: usize) -> std::cmp::Ordering {
        let multiplier = 1_u64 << self.binary_power;
        let mut carry = 0_u64;
        let mut reversed = Vec::new();
        for byte in self.coefficient.bytes().rev() {
            let value = u64::from(byte - b'0') * multiplier + carry;
            reversed.push(char::from(b'0' + u8::try_from(value % 10).unwrap_or(0)));
            carry = value / 10;
        }
        while carry > 0 {
            reversed.push(char::from(b'0' + u8::try_from(carry % 10).unwrap_or(0)));
            carry /= 10;
        }
        let left: String = reversed.into_iter().rev().collect();
        let left = left.trim_start_matches('0');
        let right = integer.to_string();
        let right = right.trim_start_matches('0');
        if left.is_empty() {
            return if right.is_empty() {
                std::cmp::Ordering::Equal
            } else {
                std::cmp::Ordering::Less
            };
        }
        if right.is_empty() {
            return std::cmp::Ordering::Greater;
        }
        let left_width = i64::try_from(left.len()).unwrap_or(i64::MAX) + self.decimal_power.max(0);
        let right_width =
            i64::try_from(right.len()).unwrap_or(i64::MAX) + (-self.decimal_power).max(0);
        match left_width.cmp(&right_width) {
            std::cmp::Ordering::Equal => left
                .bytes()
                .chain(std::iter::repeat(b'0'))
                .take(usize::try_from(left_width).unwrap_or(usize::MAX))
                .cmp(
                    right
                        .bytes()
                        .chain(std::iter::repeat(b'0'))
                        .take(usize::try_from(right_width).unwrap_or(usize::MAX)),
                ),
            ordering => ordering,
        }
    }
    fn reserves_all(&self, cpus: usize) -> bool {
        if cpus == 0 {
            return !self.negative || self.compare_abs(1).is_lt();
        }
        !self.negative && self.compare_abs(cpus - 1).is_gt()
    }
}
fn quantity(value: &str) -> Result<Quantity, ConfigError> {
    let expression = Regex::new(r"^([+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+))((?:[eE][+-]?[0-9]+)|(?:[numkMGTPEm]|[KMGTPE]i)?)$").map_err(|e| invalid("kubernetes.kubelet.systemReserved", e.to_string()))?;
    let captures = expression.captures(value).ok_or_else(|| {
        invalid(
            "kubernetes.kubelet.systemReserved",
            format!("invalid resource quantity {value:?}"),
        )
    })?;
    let mantissa = &captures[1];
    let suffix = &captures[2];
    let negative = mantissa.starts_with('-');
    let mantissa = mantissa.trim_start_matches(['+', '-']);
    let fraction = mantissa.split_once('.').map_or(0, |(_, v)| v.len());
    let coefficient = mantissa.replace('.', "");
    let (power, binary) = match suffix {
        "" => (0, 0),
        "n" => (-9, 0),
        "u" => (-6, 0),
        "m" => (-3, 0),
        "k" => (3, 0),
        "M" => (6, 0),
        "G" => (9, 0),
        "T" => (12, 0),
        "P" => (15, 0),
        "E" => (18, 0),
        "Ki" => (0, 10),
        "Mi" => (0, 20),
        "Gi" => (0, 30),
        "Ti" => (0, 40),
        "Pi" => (0, 50),
        "Ei" => (0, 60),
        _ => (
            suffix[1..].parse::<i32>().map_err(|_| {
                invalid(
                    "kubernetes.kubelet.systemReserved",
                    "invalid decimal exponent",
                )
            })?,
            0,
        ),
    };
    Ok(Quantity {
        negative,
        coefficient,
        decimal_power: i64::from(power)
            - i64::try_from(fraction).map_err(|_| {
                invalid(
                    "kubernetes.kubelet.systemReserved",
                    "resource quantity is too long",
                )
            })?,
        binary_power: binary,
    })
}
fn cpu_set(input: &str, count: usize) -> Result<BTreeSet<usize>, ConfigError> {
    let mut result = BTreeSet::new();
    for part in input.split(',') {
        let (first, last) = part.split_once('-').unwrap_or((part, part));
        let first = first.parse::<usize>().map_err(|_| {
            invalid(
                "kubernetes.kubelet.cpuManager.reservedCPUs",
                "invalid CPU set",
            )
        })?;
        let last = last.parse::<usize>().map_err(|_| {
            invalid(
                "kubernetes.kubelet.cpuManager.reservedCPUs",
                "invalid CPU range",
            )
        })?;
        if first > last || last >= count {
            return Err(invalid(
                "kubernetes.kubelet.cpuManager.reservedCPUs",
                "CPU range does not exist on supplied host",
            ));
        }
        result.extend(first..=last);
    }
    if result.len() >= count {
        return Err(invalid(
            "kubernetes.kubelet.cpuManager.reservedCPUs",
            "reservation leaves no workload CPUs",
        ));
    }
    Ok(result)
}
fn boolean(input: &str) -> Option<bool> {
    match input {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}
// The reference sorts and joins typed maps, then reuses its comma-separated flag parser.
fn flag_entries(
    values: BTreeMap<String, String>,
    path: &str,
) -> Result<Vec<(String, String)>, ConfigError> {
    let joined = values
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    if joined.is_empty() {
        return Ok(Vec::new());
    }
    joined
        .split(',')
        .map(|entry| {
            entry
                .split_once('=')
                .map(|(key, value)| (key.trim().into(), value.trim().into()))
                .ok_or_else(|| invalid(path, "expected key=value entry"))
        })
        .collect()
}
fn validate_cpu(kubelet: &mut crate::Kubelet, cpu_count: usize) -> Result<(), ConfigError> {
    let reserved = kubelet.system_reserved.take().unwrap_or_default();
    let mut normalized: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in flag_entries(reserved, "kubernetes.kubelet.systemReserved")? {
        let name = name.trim();
        let value = value.trim();
        if !matches!(name, "cpu" | "memory" | "ephemeral-storage" | "pid") {
            return Err(invalid(
                "kubernetes.kubelet.systemReserved",
                format!("unsupported resource {name:?}"),
            ));
        }
        quantity(value)?;
        normalized.insert(name.into(), value.into());
    }
    let cpu = &mut kubelet.cpu_manager;
    if cpu.reserved_cpus.is_empty()
        && let Some(value) = normalized.get("cpu")
    {
        let reserved = quantity(value)?;
        if reserved.reserves_all(cpu_count) {
            return Err(invalid(
                "kubernetes.kubelet.systemReserved.cpu",
                "reservation leaves no workload CPUs",
            ));
        }
    }
    if !matches!(cpu.policy.as_str(), "" | "none" | "static") {
        return Err(invalid(
            "kubernetes.kubelet.cpuManager.policy",
            "must be none or static",
        ));
    }
    if cpu.policy == "static" {
        let mut options = BTreeMap::new();
        for (key, value) in flag_entries(
            cpu.policy_options.take().unwrap_or_default(),
            "kubernetes.kubelet.cpuManager.policyOptions",
        )? {
            let key = key.trim();
            if !matches!(
                key,
                "full-pcpus-only"
                    | "strict-cpu-reservation"
                    | "distribute-cpus-across-numa"
                    | "prefer-align-cpus-by-uncorecache"
            ) {
                return Err(invalid(
                    "kubernetes.kubelet.cpuManager.policyOptions",
                    format!("unsupported policy option {key:?}"),
                ));
            }
            let enabled = boolean(value.trim()).ok_or_else(|| {
                invalid(
                    "kubernetes.kubelet.cpuManager.policyOptions",
                    "expected a boolean string",
                )
            })?;
            options.insert(key.into(), enabled.to_string());
        }
        if options
            .get("distribute-cpus-across-numa")
            .is_some_and(|v| v == "true")
            && options
                .get("prefer-align-cpus-by-uncorecache")
                .is_some_and(|v| v == "true")
        {
            return Err(invalid(
                "kubernetes.kubelet.cpuManager.policyOptions",
                "NUMA and uncore-cache options cannot both be enabled",
            ));
        }
        cpu.policy_options = if options.is_empty() {
            None
        } else {
            Some(options)
        };
        if cpu.reserved_cpus.is_empty() && !normalized.contains_key("cpu") {
            cpu.reserved_cpus = "0".into();
        }
        if !cpu.reserved_cpus.is_empty() {
            cpu_set(&cpu.reserved_cpus, cpu_count)?;
        }
    } else {
        if !cpu.reserved_cpus.is_empty()
            || cpu.policy_options.as_ref().is_some_and(|m| !m.is_empty())
        {
            return Err(invalid(
                "kubernetes.kubelet.cpuManager",
                "policy options and reserved CPUs require static policy",
            ));
        }
        cpu.policy = "none".into();
        cpu.policy_options = None;
    }
    kubelet.system_reserved = if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    };

    Ok(())
}

impl Config {
    pub fn resolve_container_mode(&self, detected: bool) -> bool {
        self.runtime.container_mode.unwrap_or(detected)
    }

    /// Validate only after all desired-state layers have been applied.
    pub fn validate(mut self, host: &HostContext) -> Result<ValidatedConfig, ConfigError> {
        let mut warnings = Vec::new();
        if self.d2k.enabled && matches!(host.architecture.as_str(), "arm" | "riscv64") {
            self.d2k.enabled = false;
            warnings.push(ValidationWarning {
                field: "d2k.enabled",
                message: format!(
                    "d2k is not supported on {}, disabling it",
                    host.architecture
                ),
            });
        }
        if self.d2k.enabled && !self.network.load_balancer.enabled {
            return Err(invalid(
                "d2k.enabled",
                "requires network.loadBalancer.enabled",
            ));
        }
        if self.resolve_container_mode(host.detected_container_mode)
            && self.kubernetes.kubelet.cpu_manager.policy == "static"
        {
            return Err(invalid(
                "kubernetes.kubelet.cpuManager.policy",
                "static policy is not supported in container mode",
            ));
        }
        self.portainer.image = normalize_image(&self.portainer.image)?;
        resolve_runtime_endpoint(&self.runtime.endpoint)?;
        validate_cpu(&mut self.kubernetes.kubelet, host.cpu_count)?;
        if self.api.enabled && self.api.socket_path.len() > 107 {
            return Err(invalid(
                "api.socketPath",
                "exceeds the 107-byte Unix socket path limit",
            ));
        }
        if self.network.mtu > 0 && self.network.mtu < 1280 && !self.network.disable_ipv6 {
            warnings.push(ValidationWarning {
                field: "network.mtu",
                message: "below the IPv6 minimum of 1280".into(),
            });
        }
        Ok(ValidatedConfig {
            config: self,
            warnings,
        })
    }
}
