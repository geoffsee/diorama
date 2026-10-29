use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::KubeletError;

/// Kubelet CPU manager checkpoint file name.
pub const CPU_MANAGER_CHECKPOINT_FILE: &str = "cpu_manager_state";

/// Settings that invalidate the CPU manager checkpoint when they change.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CpuManagerSettings {
    #[serde(default)]
    pub policy: String,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
    #[serde(default)]
    pub reserved_cpus: String,
}

/// Default upstream Kubelet ports and endpoints.
pub const DEFAULT_KUBELET_PORT: u16 = 10250;
pub const DEFAULT_KUBELET_READ_ONLY_PORT: u16 = 0;
pub const DEFAULT_HEALTHZ_PORT: u16 = 10248;
pub const DEFAULT_HEALTHZ_BIND_ADDRESS: &str = "127.0.0.1";
pub const DEFAULT_CLUSTER_DOMAIN: &str = "cluster.local";
pub const DEFAULT_CLUSTER_DNS: &str = "10.43.0.10";
pub const DEFAULT_KUBELET_ROOT_DIR: &str = "/var/lib/kubelet";
pub const DEFAULT_CONTAINERD_RUNTIME_ENDPOINT: &str = "unix:///run/containerd/containerd.sock";

/// Comprehensive Kubelet configuration options.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KubeletConfigOptions {
    #[serde(default)]
    pub bootstrap_token_file: Option<PathBuf>,
    pub node_name: String,
    pub node_ip: String,
    pub disable_ipv6: bool,
    pub root_dir: PathBuf,
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub kubeconfig: PathBuf,
    pub ca_file: PathBuf,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub runtime_endpoint: String,
    pub image_endpoint: Option<String>,
    pub cgroup_driver: String,
    pub runtime_cgroup_driver: Option<String>,
    pub resolv_conf: Option<PathBuf>,
    pub cluster_domain: String,
    pub cluster_dns: Vec<String>,
    pub container_mode: bool,
    pub cpu_manager_policy: String,
    pub cpu_manager_policy_options: BTreeMap<String, String>,
    pub reserved_cpus: String,
    pub system_reserved: BTreeMap<String, String>,
    pub kube_reserved: BTreeMap<String, String>,
    pub healthz_port: u16,
    pub healthz_bind_address: String,
    pub port: u16,
    pub read_only_port: u16,
}

impl Default for KubeletConfigOptions {
    fn default() -> Self {
        let root = PathBuf::from(DEFAULT_KUBELET_ROOT_DIR);
        Self {
            bootstrap_token_file: None,
            node_name: String::new(),
            node_ip: String::new(),
            disable_ipv6: false,
            config_dir: root.clone(),
            config_file: root.join("kubelet.yaml"),
            root_dir: root.clone(),
            kubeconfig: PathBuf::from("/etc/kubernetes/kubelet.kubeconfig"),
            ca_file: PathBuf::from("/etc/kubernetes/pki/ca.crt"),
            cert_file: PathBuf::from("/etc/kubernetes/pki/kubelet.crt"),
            key_file: PathBuf::from("/etc/kubernetes/pki/kubelet.key"),
            runtime_endpoint: DEFAULT_CONTAINERD_RUNTIME_ENDPOINT.to_string(),
            image_endpoint: None,
            cgroup_driver: "cgroupfs".to_string(),
            runtime_cgroup_driver: None,
            resolv_conf: None,
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            cluster_dns: vec![DEFAULT_CLUSTER_DNS.to_string()],
            container_mode: false,
            cpu_manager_policy: "none".to_string(),
            cpu_manager_policy_options: BTreeMap::new(),
            reserved_cpus: String::new(),
            system_reserved: BTreeMap::new(),
            kube_reserved: BTreeMap::new(),
            healthz_port: DEFAULT_HEALTHZ_PORT,
            healthz_bind_address: DEFAULT_HEALTHZ_BIND_ADDRESS.to_string(),
            port: DEFAULT_KUBELET_PORT,
            read_only_port: DEFAULT_KUBELET_READ_ONLY_PORT,
        }
    }
}

impl KubeletConfigOptions {
    #[must_use]
    pub fn default_for_pki(
        pki_dir: &Path,
        node_name: impl Into<String>,
        node_ip: impl Into<String>,
        root_dir: &Path,
    ) -> Self {
        let name = node_name.into();
        Self {
            bootstrap_token_file: None,
            node_name: name,
            node_ip: node_ip.into(),
            disable_ipv6: false,
            root_dir: root_dir.to_path_buf(),
            config_dir: root_dir.to_path_buf(),
            config_file: root_dir.join("kubelet.yaml"),
            kubeconfig: pki_dir.join("kubelet.kubeconfig"),
            ca_file: pki_dir.join("ca.crt"),
            cert_file: pki_dir.join("kubelet.crt"),
            key_file: pki_dir.join("kubelet.key"),
            runtime_endpoint: DEFAULT_CONTAINERD_RUNTIME_ENDPOINT.to_string(),
            image_endpoint: None,
            cgroup_driver: "cgroupfs".to_string(),
            runtime_cgroup_driver: None,
            resolv_conf: None,
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            cluster_dns: vec![DEFAULT_CLUSTER_DNS.to_string()],
            container_mode: false,
            cpu_manager_policy: "none".to_string(),
            cpu_manager_policy_options: BTreeMap::new(),
            reserved_cpus: String::new(),
            system_reserved: BTreeMap::new(),
            kube_reserved: BTreeMap::new(),
            healthz_port: DEFAULT_HEALTHZ_PORT,
            healthz_bind_address: DEFAULT_HEALTHZ_BIND_ADDRESS.to_string(),
            port: DEFAULT_KUBELET_PORT,
            read_only_port: DEFAULT_KUBELET_READ_ONLY_PORT,
        }
    }

    /// Resolves the cgroup driver to use.
    ///
    /// Precedence matches upstream `KubeSolo`:
    /// 1. Runtime-reported cgroup driver (from CRI runtime), if present.
    /// 2. If in container mode, defaults to "cgroupfs".
    /// 3. Explicit cgroup driver if configured (and not "auto").
    /// 4. Detected from host init system: "systemd" if `/run/systemd/private` exists, else "cgroupfs".
    #[must_use]
    pub fn resolve_cgroup_driver(&self) -> String {
        if let Some(ref driver) = self.runtime_cgroup_driver
            && !driver.is_empty()
        {
            return driver.clone();
        }
        if self.container_mode {
            return "cgroupfs".to_string();
        }
        if !self.cgroup_driver.is_empty() && self.cgroup_driver != "auto" {
            return self.cgroup_driver.clone();
        }
        if Path::new("/run/systemd/private").exists() {
            "systemd".to_string()
        } else {
            "cgroupfs".to_string()
        }
    }

    /// Constructs Kubelet configuration JSON document matching upstream `kubelet.config.k8s.io/v1beta1`.
    #[must_use]
    pub fn generate_kubelet_config(&self) -> Value {
        let mut map = serde_json::Map::new();

        map.insert(
            "apiVersion".to_string(),
            json!("kubelet.config.k8s.io/v1beta1"),
        );
        map.insert(
            "authentication".to_string(),
            json!({
                "anonymous": {
                    "enabled": false
                },
                "webhook": {
                    "cacheTTL": "5m0s",
                    "enabled": true
                },
                "x509": {
                    "clientCAFile": self.ca_file.to_string_lossy()
                }
            }),
        );
        map.insert(
            "authorization".to_string(),
            json!({
                "mode": "Webhook",
                "webhook": {
                    "cacheAuthorizedTTL": "10m0s",
                    "cacheUnauthorizedTTL": "1m0s"
                }
            }),
        );
        map.insert(
            "cgroupDriver".to_string(),
            json!(self.resolve_cgroup_driver()),
        );
        map.insert("clusterDNS".to_string(), json!(self.cluster_dns));
        map.insert("clusterDomain".to_string(), json!(self.cluster_domain));
        map.insert(
            "containerRuntimeEndpoint".to_string(),
            json!(self.runtime_endpoint),
        );
        map.insert("failSwapOn".to_string(), json!(false));
        map.insert("kind".to_string(), json!("KubeletConfiguration"));
        map.insert("readOnlyPort".to_string(), json!(self.read_only_port));

        self.populate_cpu_manager_config(&mut map);

        if !self.system_reserved.is_empty() {
            map.insert("systemReserved".to_string(), json!(self.system_reserved));
        }

        if self.container_mode {
            map.insert("cgroupsPerQOS".to_string(), json!(false));
            map.insert("enforceNodeAllocatable".to_string(), json!([]));
            map.insert(
                "evictionHard".to_string(),
                json!({
                    "imagefs.available": "0%",
                    "memory.available": "50Mi",
                    "nodefs.available": "0%",
                    "nodefs.inodesFree": "0%"
                }),
            );
            map.insert("imageGCHighThresholdPercent".to_string(), json!(100));
            if !map.contains_key("systemReserved") {
                map.insert("systemReserved".to_string(), json!({}));
            }
            map.insert("kubeReserved".to_string(), json!(self.kube_reserved));
            map.insert("resolvConf".to_string(), json!("/dev/null"));
            map.insert("rotateCertificates".to_string(), json!(true));
        } else {
            let resolv = self.resolv_conf.as_ref().map_or_else(
                || "/etc/resolv.conf".to_string(),
                |p| p.to_string_lossy().to_string(),
            );
            map.insert("resolvConf".to_string(), json!(resolv));
            map.insert("rotateCertificates".to_string(), json!(true));
            if !self.kube_reserved.is_empty() {
                map.insert("kubeReserved".to_string(), json!(self.kube_reserved));
            }
        }

        map.insert(
            "tlsCertFile".to_string(),
            json!(self.cert_file.to_string_lossy()),
        );
        map.insert(
            "tlsPrivateKeyFile".to_string(),
            json!(self.key_file.to_string_lossy()),
        );

        Value::Object(map)
    }

    fn populate_cpu_manager_config(&self, map: &mut serde_json::Map<String, Value>) {
        if self.cpu_manager_policy == "static" {
            map.insert("cpuManagerPolicy".to_string(), json!("static"));
            let effective_reserved = if !self.reserved_cpus.is_empty() {
                self.reserved_cpus.clone()
            } else if !self.system_reserved.contains_key("cpu") {
                "0".to_string()
            } else {
                String::new()
            };
            if !effective_reserved.is_empty() {
                map.insert("reservedSystemCPUs".to_string(), json!(effective_reserved));
            }
            if !self.cpu_manager_policy_options.is_empty() {
                map.insert(
                    "cpuManagerPolicyOptions".to_string(),
                    json!(self.cpu_manager_policy_options),
                );
            }
        }
    }

    /// Renders Kubelet configuration into canonical YAML matching the official golden fixture.
    #[must_use]
    pub fn render_yaml(&self) -> String {
        let val = self.generate_kubelet_config();
        render_canonical_yaml(&val)
    }

    /// Returns the CPU manager checkpoint path under the kubelet root directory.
    #[must_use]
    pub fn cpu_manager_checkpoint_path(&self) -> PathBuf {
        self.root_dir.join(CPU_MANAGER_CHECKPOINT_FILE)
    }

    /// Reads CPU manager settings from YAML config content.
    #[must_use]
    pub fn read_cpu_manager_settings(yaml_content: &str) -> CpuManagerSettings {
        let Ok(value) = diorama_config::decode_yaml_value(yaml_content) else {
            return CpuManagerSettings::default();
        };

        let Value::Object(map) = value else {
            return CpuManagerSettings::default();
        };

        let policy = match map.get("cpuManagerPolicy") {
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        };

        let reserved_cpus = match map.get("reservedSystemCPUs") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => String::new(),
        };

        let mut options = BTreeMap::new();
        if let Some(opts) = map
            .get("cpuManagerPolicyOptions")
            .and_then(Value::as_object)
        {
            for (k, v) in opts {
                let val_str = match v {
                    Value::String(s) => s.clone(),
                    Value::Bool(b) => b.to_string(),
                    Value::Number(n) => n.to_string(),
                    _ => String::new(),
                };
                options.insert(k.clone(), val_str);
            }
        }

        CpuManagerSettings {
            policy,
            options,
            reserved_cpus,
        }
    }

    /// Invalidates the CPU manager checkpoint if the effective CPU manager settings differ
    /// from the previously written configuration file.
    ///
    /// Returns whether settings changed; errors prevent configuration replacement and startup.
    pub fn invalidate_cpu_manager_checkpoint(&self, new_yaml: &str) -> Result<bool, KubeletError> {
        let previous = match fs::read_to_string(&self.config_file) {
            Ok(previous) => previous,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(KubeletError::InvalidConfiguration {
                    field: "config_file".to_string(),
                    reason: format!(
                        "failed to read previous configuration {}: {error}",
                        self.config_file.display()
                    ),
                });
            },
        };

        let previous_settings = Self::read_cpu_manager_settings(&previous);
        let new_settings = Self::read_cpu_manager_settings(new_yaml);

        if previous_settings == new_settings {
            return Ok(false);
        }

        let checkpoint = self.cpu_manager_checkpoint_path();
        match fs::remove_file(&checkpoint) {
            Ok(()) => eprintln!(
                "cpu manager settings changed, removed {}. exclusive cores are reassigned as pinned workloads restart; with an external container runtime, restart them yourself",
                checkpoint.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => {
                return Err(KubeletError::InvalidConfiguration {
                    field: "checkpoint".to_string(),
                    reason: format!(
                        "failed to remove stale CPU manager checkpoint {}: {error}",
                        checkpoint.display()
                    ),
                });
            },
        }

        Ok(true)
    }

    /// Writes the generated YAML document to `self.config_file`.
    ///
    /// Returns `true` if the CPU manager checkpoint was invalidated, `false` otherwise.
    pub fn write_kubelet_config_file(&self) -> Result<bool, KubeletError> {
        let parent =
            self.config_file
                .parent()
                .ok_or_else(|| KubeletError::InvalidConfiguration {
                    field: "config_file".to_string(),
                    reason: "config_file must have a parent directory".to_string(),
                })?;

        if parent.exists() && !parent.is_dir() {
            return Err(KubeletError::InvalidConfiguration {
                field: "config_file".to_string(),
                reason: format!(
                    "parent path {} is a file, not a directory",
                    parent.display()
                ),
            });
        }

        fs::create_dir_all(parent)?;
        let yaml = self.render_yaml();
        let invalidated = self.invalidate_cpu_manager_checkpoint(&yaml)?;
        fs::write(&self.config_file, yaml)?;
        Ok(invalidated)
    }

    /// Generates CLI arguments for Kubelet process execution.
    ///
    /// Evaluates IP validity and loopback:
    /// - Loopback addresses (`127.0.0.1`, `::1`) or invalid IP strings are omitted.
    /// - Valid non-loopback addresses are passed via `--node-ip`.
    /// - If `disable_ipv6` is set, IPv6 addresses are omitted.
    #[must_use]
    pub fn configure_kubelet_args(&self) -> Vec<String> {
        let mut args = vec![
            "--config".to_string(),
            self.config_file.to_string_lossy().to_string(),
            "--hostname-override".to_string(),
            self.node_name.clone(),
            "--root-dir".to_string(),
            self.root_dir.to_string_lossy().to_string(),
            "--kubeconfig".to_string(),
            self.kubeconfig.to_string_lossy().to_string(),
        ];

        if let Ok(ip) = self.node_ip.parse::<IpAddr>() {
            let is_loopback = ip.is_loopback();
            let is_ipv6_disabled = self.disable_ipv6 && ip.is_ipv6();
            if !is_loopback && !is_ipv6_disabled {
                args.push("--node-ip".to_string());
                args.push(self.node_ip.clone());
            }
        }

        args
    }

    /// Validates that upstream resource defaults are preserved without reviving removed KS-68 edge overrides.
    pub fn validate_upstream_resource_defaults(&self) -> Result<(), KubeletError> {
        self.validate_cpu_manager(detect_host_cpu_count())?;

        if !self.container_mode && self.read_only_port != 0 {
            return Err(KubeletError::InvalidConfiguration {
                field: "read_only_port".to_string(),
                reason: "read_only_port must default to 0 for security".to_string(),
            });
        }
        Ok(())
    }

    /// Validates CPU manager configuration against a host CPU count.
    pub fn validate_cpu_manager(&self, host_cpus: usize) -> Result<(), KubeletError> {
        if self.container_mode && self.cpu_manager_policy == "static" {
            return Err(KubeletError::InvalidConfiguration {
                field: "cpu_manager_policy".to_string(),
                reason: "static CPU manager policy is unsupported in container mode".to_string(),
            });
        }

        match self.cpu_manager_policy.as_str() {
            "" | "none" => {
                if !self.cpu_manager_policy_options.is_empty() || !self.reserved_cpus.is_empty() {
                    return Err(KubeletError::InvalidConfiguration {
                        field: "cpu_manager_policy".to_string(),
                        reason: "--cpu-manager-policy-options and --reserved-cpus require --cpu-manager-policy=static".to_string(),
                    });
                }
            },
            "static" => {
                if host_cpus < 2 {
                    return Err(KubeletError::InvalidConfiguration {
                        field: "cpu_manager_policy".to_string(),
                        reason: format!(
                            "static CPU manager policy requires at least 2 host CPUs, but host has {host_cpus}"
                        ),
                    });
                }

                validate_policy_options(&self.cpu_manager_policy_options)?;
                validate_system_reserved_keys(&self.system_reserved)?;
                validate_cpu_reservations(&self.reserved_cpus, &self.system_reserved, host_cpus)?;
            },
            other => {
                return Err(KubeletError::InvalidConfiguration {
                    field: "cpu_manager_policy".to_string(),
                    reason: format!(
                        "invalid --cpu-manager-policy \"{other}\": must be none or static"
                    ),
                });
            },
        }

        Ok(())
    }
}

fn validate_policy_options(options: &BTreeMap<String, String>) -> Result<(), KubeletError> {
    for (key, val) in options {
        match key.as_str() {
            "full-pcpus-only"
            | "strict-cpu-reservation"
            | "distribute-cpus-across-numa"
            | "prefer-align-cpus-by-uncorecache" => {},
            _ => {
                return Err(KubeletError::InvalidConfiguration {
                    field: "cpu_manager_policy_options".to_string(),
                    reason: format!(
                        "unsupported --cpu-manager-policy-options key \"{key}\": supported keys are full-pcpus-only, strict-cpu-reservation, distribute-cpus-across-numa, prefer-align-cpus-by-uncorecache"
                    ),
                });
            },
        }

        match val.as_str() {
            "true" | "false" | "1" | "0" => {},
            _ => {
                return Err(KubeletError::InvalidConfiguration {
                    field: "cpu_manager_policy_options".to_string(),
                    reason: format!(
                        "invalid value \"{val}\" for --cpu-manager-policy-options key \"{key}\": expected a boolean"
                    ),
                });
            },
        }
    }

    let uncore = options
        .get("prefer-align-cpus-by-uncorecache")
        .is_some_and(|v| v == "true" || v == "1");
    let numa = options
        .get("distribute-cpus-across-numa")
        .is_some_and(|v| v == "true" || v == "1");
    if uncore && numa {
        return Err(KubeletError::InvalidConfiguration {
            field: "cpu_manager_policy_options".to_string(),
            reason: "--cpu-manager-policy-options prefer-align-cpus-by-uncorecache and distribute-cpus-across-numa cannot both be enabled".to_string(),
        });
    }

    Ok(())
}

fn validate_system_reserved_keys(
    system_reserved: &BTreeMap<String, String>,
) -> Result<(), KubeletError> {
    for key in system_reserved.keys() {
        match key.as_str() {
            "cpu" | "memory" | "ephemeral-storage" | "pid" => {},
            _ => {
                return Err(KubeletError::InvalidConfiguration {
                    field: "system_reserved".to_string(),
                    reason: format!(
                        "unsupported --system-reserved resource \"{key}\": supported resources are cpu, memory, ephemeral-storage, pid"
                    ),
                });
            },
        }
    }
    Ok(())
}

fn validate_cpu_reservations(
    reserved_cpus: &str,
    system_reserved: &BTreeMap<String, String>,
    host_cpus: usize,
) -> Result<(), KubeletError> {
    if !reserved_cpus.is_empty() {
        let set = parse_cpuset(reserved_cpus).map_err(|e| KubeletError::InvalidConfiguration {
            field: "reserved_cpus".to_string(),
            reason: format!("invalid --reserved-cpus \"{reserved_cpus}\": {e}"),
        })?;

        for &cpu in &set {
            if cpu >= host_cpus {
                return Err(KubeletError::InvalidConfiguration {
                    field: "reserved_cpus".to_string(),
                    reason: format!(
                        "invalid --reserved-cpus \"{reserved_cpus}\": CPU {cpu} does not exist, this host has {host_cpus} CPUs"
                    ),
                });
            }
        }

        if set.len() >= host_cpus {
            return Err(KubeletError::InvalidConfiguration {
                field: "reserved_cpus".to_string(),
                reason: format!(
                    "--reserved-cpus \"{reserved_cpus}\" reserves all {host_cpus} CPUs, leaving none to pin workloads to"
                ),
            });
        }

        if let Some(sys_cpu) = system_reserved.get("cpu") {
            eprintln!(
                "--reserved-cpus \"{reserved_cpus}\" takes precedence over --system-reserved cpu={sys_cpu}, which is ignored"
            );
        }
    } else if let Some(sys_cpu) = system_reserved.get("cpu") {
        let milli = crate::workload::parse_cpu_quantity_milli(sys_cpu).ok_or_else(|| {
            KubeletError::InvalidConfiguration {
                field: "system_reserved.cpu".to_string(),
                reason: format!("invalid --system-reserved quantity \"{sys_cpu}\" for \"cpu\""),
            }
        })?;
        let count = usize::try_from(milli.div_ceil(1000)).unwrap_or(usize::MAX);
        if count >= host_cpus {
            return Err(KubeletError::InvalidConfiguration {
                field: "system_reserved.cpu".to_string(),
                reason: format!(
                    "--system-reserved cpu={sys_cpu} reserves {count} of this host's {host_cpus} CPUs, leaving none for workloads"
                ),
            });
        }
    } else {
        eprintln!(
            "neither --reserved-cpus nor --system-reserved cpu is set, defaulting to cpu \"0\""
        );
    }
    Ok(())
}

/// Parses a CPU list string (e.g. "0", "0-1", "0,2-3") into a set of CPU indexes.
pub fn parse_cpuset(s: &str) -> Result<BTreeSet<usize>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut cpus = BTreeSet::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = part.split_once('-') {
            let start = start_s
                .trim()
                .parse::<usize>()
                .map_err(|e| format!("invalid cpu index in range '{part}': {e}"))?;
            let end = end_s
                .trim()
                .parse::<usize>()
                .map_err(|e| format!("invalid cpu index in range '{part}': {e}"))?;
            if start > end {
                return Err(format!(
                    "invalid cpu range '{part}': start {start} > end {end}"
                ));
            }
            for cpu in start..=end {
                cpus.insert(cpu);
            }
        } else {
            let cpu = part
                .parse::<usize>()
                .map_err(|e| format!("invalid cpu index '{part}': {e}"))?;
            cpus.insert(cpu);
        }
    }
    Ok(cpus)
}

/// Formats a set of CPU indexes into a compact cpuset string (e.g. "0-1,3").
#[must_use]
pub fn format_cpuset(cpus: &BTreeSet<usize>) -> String {
    if cpus.is_empty() {
        return String::new();
    }
    let mut ranges = Vec::new();
    let mut iter = cpus.iter();
    if let Some(&first) = iter.next() {
        let mut start = first;
        let mut end = first;
        for &cpu in iter {
            if cpu == end + 1 {
                end = cpu;
            } else {
                if start == end {
                    ranges.push(format!("{start}"));
                } else {
                    ranges.push(format!("{start}-{end}"));
                }
                start = cpu;
                end = cpu;
            }
        }
        if start == end {
            ranges.push(format!("{start}"));
        } else {
            ranges.push(format!("{start}-{end}"));
        }
    }
    ranges.join(",")
}

/// Detects available CPUs on the host, defaulting to 2 if query fails.
#[must_use]
pub fn detect_host_cpu_count() -> usize {
    std::thread::available_parallelism().map_or(2, std::num::NonZero::get)
}

/// Renders a JSON Value into deterministic, alphabetically sorted YAML.
pub fn render_canonical_yaml(value: &Value) -> String {
    let mut out = String::new();
    render_value(value, 0, &mut out);
    out
}

fn render_scalar(val: &Value, out: &mut String) {
    match val {
        Value::String(s) => {
            if s.is_empty()
                || s == "true"
                || s == "false"
                || s == "null"
                || s == "yes"
                || s == "no"
                || s.starts_with('*')
                || s.starts_with('&')
                || s.starts_with('!')
                || s.starts_with('@')
                || s.starts_with('`')
                || s.starts_with('-')
                || s.starts_with('?')
                || s.starts_with('{')
                || s.starts_with('[')
                || s.contains(": ")
                || s.contains('#')
            {
                out.push_str(&serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\"")));
            } else {
                out.push_str(s);
            }
        },
        _ => {
            out.push_str(&val.to_string());
        },
    }
}

fn render_array_elements(arr: &[Value], indent: usize, out: &mut String) {
    out.push('\n');
    for elem in arr {
        out.push_str(&" ".repeat(indent));
        out.push_str("- ");
        render_scalar(elem, out);
        out.push('\n');
    }
}

fn render_value(value: &Value, indent: usize, out: &mut String) {
    if let Value::Object(map) = value {
        // Sort keys alphabetically
        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort();

        for key in keys {
            let v = &map[key];
            out.push_str(&" ".repeat(indent));
            out.push_str(key);
            out.push(':');

            match v {
                Value::Object(sub_map) if sub_map.is_empty() => {
                    out.push_str(" {}\n");
                },
                Value::Object(_) => {
                    out.push('\n');
                    render_value(v, indent + 2, out);
                },
                Value::Array(arr) if arr.is_empty() => {
                    out.push_str(" []\n");
                },
                Value::Array(arr) => {
                    render_array_elements(arr, indent + 2, out);
                },
                Value::String(_) | Value::Bool(_) | Value::Number(_) => {
                    out.push(' ');
                    render_scalar(v, out);
                    out.push('\n');
                },
                Value::Null => {
                    out.push_str(" null\n");
                },
            }
        }
    }
}
