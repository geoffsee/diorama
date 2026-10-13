//! Pod reconciler: drives pods through a CRI-shaped runtime the way the
//! upstream kubelet does.
//!
//! One pass per pod: ensure a ready sandbox, bring every spec container to its
//! latest attempt (pull, create, start), probe running containers, restart
//! exited ones under `restartPolicy` with the kubelet's back-off, then write
//! the status the runtime reports. Deletion stops containers with the grace
//! period, removes the sandbox and deletes the Pod object.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use diorama_apiserver::time::{now_unix, parse_rfc3339_seconds};
use diorama_apiserver::{ApiserverError, ApiserverService, KubernetesApiClient};

use crate::config::{
    DEFAULT_CLUSTER_DNS, DEFAULT_CLUSTER_DOMAIN, detect_host_cpu_count, format_cpuset,
};
use crate::error::KubeletError;
use crate::status::{
    ContainerView, CpuAssignment, PodViews, attempt_of, attempts_by_name, pending_status,
    pod_status,
};
use crate::workload::{
    ANNOTATION_RESTART_COUNT, CpuManager, ExecResult, LABEL_CONTAINER_NAME, LABEL_MANAGED_BY,
    LABEL_POD_NAME, LABEL_POD_NAMESPACE, LABEL_POD_UID, LogOptions, MANAGED_BY, ReconcileReport,
    RestartPolicy, RuntimeProvider, WorkloadRestartReport, check_pod_restart_need,
    container_labels, cri, determine_pod_qos, is_container_cpu_pinning_eligible,
    parse_cpu_quantity_milli, parse_memory_quantity_bytes, sandbox_labels, secs_from_nanos,
    stage_configmap_files, stage_projected_downward_api, stage_projected_sa_token,
    stage_secret_files,
};

const RESTART_BACKOFF_INITIAL_SECS: u64 = 10;
const RESTART_BACKOFF_MAX_SECS: u64 = 300;
const RESTART_BACKOFF_RESET_SECS: u64 = 600;
/// Upper bound for a probe command.
const EXEC_TIMEOUT_SECS: i64 = 10;
/// Attempts kept per container: the current one and the previous for `logs --previous`.
const KEPT_ATTEMPTS: usize = 2;

#[derive(Debug, Clone, Copy)]
struct RestartBackoff {
    delay_secs: u64,
    not_before: u64,
}

#[derive(Debug, Clone, Default)]
struct ProbeTracker {
    last_run_secs: u64,
    consecutive_failures: u32,
}

/// Next restart delay: doubles after each quick failure, resets after a long run.
fn next_restart_backoff(
    previous: Option<RestartBackoff>,
    ran_for: u64,
    now: u64,
) -> RestartBackoff {
    let delay_secs = match previous {
        Some(backoff) if ran_for < RESTART_BACKOFF_RESET_SECS => {
            (backoff.delay_secs * 2).min(RESTART_BACKOFF_MAX_SECS)
        },
        _ => RESTART_BACKOFF_INITIAL_SECS,
    };
    RestartBackoff {
        delay_secs,
        not_before: now + delay_secs,
    }
}

/// Per-pass bookkeeping while bringing containers to their desired attempts.
#[derive(Debug, Default)]
struct SyncState {
    ready: BTreeMap<String, bool>,
    backoffs: BTreeMap<String, String>,
    waiting: BTreeMap<String, (&'static str, String)>,
    started_now: BTreeSet<String>,
    restarted: BTreeSet<String>,
}

struct SyncContext<'a> {
    namespace: &'a str,
    pod: &'a Value,
    sandbox_id: &'a str,
    sandbox_config: &'a cri::PodSandboxConfig,
}

fn container_name_of(container: &Value) -> &str {
    container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("main")
}

/// Why a container attempt could not be started; reported as a waiting state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartFailure {
    pub reason: &'static str,
    pub message: String,
}

fn state_of(status: &cri::ContainerStatus) -> cri::ContainerState {
    cri::ContainerState::try_from(status.state).unwrap_or(cri::ContainerState::ContainerUnknown)
}

fn pod_name(pod: &Value) -> &str {
    pod.pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
}

fn pod_uid(pod: &Value) -> Result<&str, KubeletError> {
    pod.pointer("/metadata/uid")
        .and_then(Value::as_str)
        .ok_or_else(|| KubeletError::PodReconciliationFailed {
            pod: pod_name(pod).to_string(),
            reason: "pod missing metadata.uid".to_string(),
        })
}

fn uid_filter(pod_uid: &str) -> cri::PodSandboxFilter {
    cri::PodSandboxFilter {
        label_selector: BTreeMap::from([
            (LABEL_MANAGED_BY.to_string(), MANAGED_BY.to_string()),
            (LABEL_POD_UID.to_string(), pod_uid.to_string()),
        ]),
        ..cri::PodSandboxFilter::default()
    }
}

fn extract_custom_servers(custom: &Value) -> Vec<String> {
    custom
        .get("nameservers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn extract_custom_searches(custom: &Value) -> Vec<String> {
    custom
        .get("searches")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn extract_custom_options(custom: &Value) -> Vec<String> {
    custom
        .get("options")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|opt| {
                    let name = opt.get("name").and_then(Value::as_str)?;
                    if let Some(val) = opt.get("value").and_then(Value::as_str) {
                        Some(format!("{name}:{val}"))
                    } else {
                        Some(name.to_string())
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Builds the CRI DNS configuration for a pod based on `dnsPolicy`, `dnsConfig`,
/// cluster DNS IPs and cluster domain.
#[must_use]
pub fn build_dns_config(
    pod: &Value,
    cluster_dns: &[String],
    cluster_domain: &str,
) -> Option<cri::DnsConfig> {
    let namespace = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");

    let host_network = pod
        .pointer("/spec/hostNetwork")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let default_policy = if host_network {
        "Default"
    } else {
        "ClusterFirst"
    };
    let dns_policy = pod
        .pointer("/spec/dnsPolicy")
        .and_then(Value::as_str)
        .unwrap_or(default_policy);

    match dns_policy {
        "Default" => {
            if let Some(custom) = pod.pointer("/spec/dnsConfig") {
                let servers = extract_custom_servers(custom);
                let searches = extract_custom_searches(custom);
                let options = extract_custom_options(custom);
                if servers.is_empty() && searches.is_empty() && options.is_empty() {
                    None
                } else {
                    Some(cri::DnsConfig {
                        servers,
                        searches,
                        options,
                    })
                }
            } else {
                None
            }
        },
        "None" => {
            let mut servers = Vec::new();
            let mut searches = Vec::new();
            let mut options = Vec::new();
            if let Some(custom) = pod.pointer("/spec/dnsConfig") {
                servers = extract_custom_servers(custom);
                searches = extract_custom_searches(custom);
                options = extract_custom_options(custom);
            }
            Some(cri::DnsConfig {
                servers,
                searches,
                options,
            })
        },
        _ => {
            // "ClusterFirst", "ClusterFirstWithHostNet", or fallback
            if cluster_dns.is_empty() {
                return None;
            }
            let mut servers = cluster_dns.to_vec();
            let effective_domain = if cluster_domain.is_empty() {
                DEFAULT_CLUSTER_DOMAIN
            } else {
                cluster_domain
            };
            let mut searches = vec![
                format!("{namespace}.svc.{effective_domain}"),
                format!("svc.{effective_domain}"),
                effective_domain.to_string(),
            ];
            let mut options = vec!["ndots:5".to_string()];

            if let Some(custom) = pod.pointer("/spec/dnsConfig") {
                for s in extract_custom_servers(custom) {
                    if !servers.contains(&s) {
                        servers.push(s);
                    }
                }
                for search in extract_custom_searches(custom) {
                    if !searches.contains(&search) {
                        searches.push(search);
                    }
                }
                for opt in extract_custom_options(custom) {
                    if opt.starts_with("ndots:") {
                        options.retain(|o| !o.starts_with("ndots:"));
                    }
                    if !options.contains(&opt) {
                        options.push(opt);
                    }
                }
            }

            Some(cri::DnsConfig {
                servers,
                searches,
                options,
            })
        },
    }
}

fn sandbox_config_base(pod: &Value, attempt: u32) -> cri::PodSandboxConfig {
    let name = pod_name(pod);
    let namespace = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let uid = pod
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut port_mappings = Vec::new();
    let containers = pod.pointer("/spec/containers").and_then(Value::as_array);
    let init_containers = pod
        .pointer("/spec/initContainers")
        .and_then(Value::as_array);
    for c in containers
        .into_iter()
        .flatten()
        .chain(init_containers.into_iter().flatten())
    {
        if let Some(ports) = c.get("ports").and_then(Value::as_array) {
            for port in ports {
                let container_port = port
                    .get("containerPort")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                let container_port = i32::try_from(container_port).unwrap_or(0);
                if container_port <= 0 {
                    continue;
                }
                let host_port = port.get("hostPort").and_then(Value::as_i64).unwrap_or(0);
                let host_port = i32::try_from(host_port).unwrap_or(0);
                let proto_str = port
                    .get("protocol")
                    .and_then(Value::as_str)
                    .unwrap_or("TCP");
                let protocol = match proto_str.to_uppercase().as_str() {
                    "UDP" => cri::Protocol::Udp as i32,
                    "SCTP" => cri::Protocol::Sctp as i32,
                    _ => cri::Protocol::Tcp as i32,
                };
                let host_ip = port
                    .get("hostIP")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                port_mappings.push(cri::PortMapping {
                    protocol,
                    container_port,
                    host_port,
                    host_ip,
                });
            }
        }
    }

    cri::PodSandboxConfig {
        metadata: Some(cri::PodSandboxMetadata {
            name: name.to_string(),
            uid: uid.to_string(),
            namespace: namespace.to_string(),
            attempt,
        }),
        hostname: pod
            .pointer("/spec/hostname")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string(),
        log_directory: format!("/var/log/pods/{namespace}_{name}_{uid}"),
        labels: sandbox_labels(namespace, name, uid),
        port_mappings,
        ..cri::PodSandboxConfig::default()
    }
}

/// Builds the CRI sandbox configuration for a pod with custom cluster DNS and domain.
#[must_use]
pub fn sandbox_config_with_dns(
    pod: &Value,
    attempt: u32,
    cluster_dns: &[String],
    cluster_domain: &str,
) -> cri::PodSandboxConfig {
    let mut config = sandbox_config_base(pod, attempt);
    config.dns_config = build_dns_config(pod, cluster_dns, cluster_domain);
    config
}

/// Builds the CRI sandbox configuration for a pod with default cluster DNS and domain.
#[must_use]
pub fn sandbox_config(pod: &Value, attempt: u32) -> cri::PodSandboxConfig {
    sandbox_config_with_dns(
        pod,
        attempt,
        &[DEFAULT_CLUSTER_DNS.to_string()],
        DEFAULT_CLUSTER_DOMAIN,
    )
}

const SERVICE_ACCOUNT_MOUNT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
const SERVICE_ACCOUNT_VOLUME_NAME: &str = "kube-api-access-diorama";
const KUBERNETES_API_AUDIENCE: &str = "https://kubernetes.default.svc";

/// Stock kubelet service-link variables.
///
/// `enableServiceLinks` defaults to true. `default/kubernetes` is always published.
/// Services with an empty `ClusterIP`, or `ClusterIP` `None`, add no variables.
fn service_link_envs(pod: &Value, services: &[Value]) -> Vec<cri::KeyValue> {
    let pod_namespace = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let links_enabled = pod
        .pointer("/spec/enableServiceLinks")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let mut selected: Vec<&Value> = Vec::new();
    for service in services {
        if routable_cluster_ip(service).is_none() {
            continue;
        }
        let name = service
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let namespace = service
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("default");
        let kubernetes_api = namespace == "default" && name == "kubernetes";
        let same_namespace = links_enabled && namespace == pod_namespace;
        if !kubernetes_api && !same_namespace {
            continue;
        }
        if let Some(slot) = selected.iter_mut().find(|existing| {
            existing.pointer("/metadata/name").and_then(Value::as_str) == Some(name)
        }) {
            *slot = service;
        } else {
            selected.push(service);
        }
    }

    let mut envs = Vec::new();
    for service in selected {
        push_service_link_envs(&mut envs, service);
    }
    envs
}

fn routable_cluster_ip(service: &Value) -> Option<&str> {
    let ip = service.pointer("/spec/clusterIP").and_then(Value::as_str)?;
    if ip.is_empty() || ip == "None" {
        None
    } else {
        Some(ip)
    }
}

fn push_service_link_envs(envs: &mut Vec<cri::KeyValue>, service: &Value) {
    let Some(cluster_ip) = routable_cluster_ip(service) else {
        return;
    };
    let Some(ports) = service.pointer("/spec/ports").and_then(Value::as_array) else {
        return;
    };
    let Some(first) = ports.first() else {
        return;
    };
    let Some(first_port) = json_port(first) else {
        return;
    };
    let service_name = env_var_token(
        service
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    if service_name.is_empty() {
        return;
    }

    push_env(
        envs,
        format!("{service_name}_SERVICE_HOST"),
        cluster_ip.to_string(),
    );
    let port_key = format!("{service_name}_SERVICE_PORT");
    push_env(envs, port_key.clone(), first_port.to_string());
    for port in ports {
        let Some(number) = json_port(port) else {
            continue;
        };
        if let Some(name) = port
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        {
            push_env(
                envs,
                format!("{port_key}_{}", env_var_token(name)),
                number.to_string(),
            );
        }
    }
    for (index, port) in ports.iter().enumerate() {
        let Some(number) = json_port(port) else {
            continue;
        };
        let protocol = port
            .get("protocol")
            .and_then(Value::as_str)
            .filter(|protocol| !protocol.is_empty())
            .unwrap_or("TCP");
        let host_port = join_host_port(cluster_ip, number);
        if index == 0 {
            push_env(
                envs,
                format!("{service_name}_PORT"),
                format!("{}://{host_port}", protocol.to_ascii_lowercase()),
            );
        }
        let prefix = format!(
            "{service_name}_PORT_{number}_{}",
            protocol.to_ascii_uppercase()
        );
        push_env(
            envs,
            prefix.clone(),
            format!("{}://{host_port}", protocol.to_ascii_lowercase()),
        );
        push_env(
            envs,
            format!("{prefix}_PROTO"),
            protocol.to_ascii_lowercase(),
        );
        push_env(envs, format!("{prefix}_PORT"), number.to_string());
        push_env(envs, format!("{prefix}_ADDR"), cluster_ip.to_string());
    }
}

fn apply_service_links(envs: &mut Vec<cri::KeyValue>, pod: &Value, services: &[Value]) {
    let links = service_link_envs(pod, services);
    if links.is_empty() {
        return;
    }
    let explicit = std::mem::take(envs);
    *envs = links;
    for env in explicit {
        push_env_kv(envs, env);
    }
}

fn push_env(envs: &mut Vec<cri::KeyValue>, key: String, value: String) {
    push_env_kv(
        envs,
        cri::KeyValue {
            key,
            value: value.into_bytes(),
        },
    );
}

fn push_env_kv(envs: &mut Vec<cri::KeyValue>, env: cri::KeyValue) {
    if let Some(existing) = envs.iter_mut().find(|item| item.key == env.key) {
        existing.value = env.value;
    } else {
        envs.push(env);
    }
}

fn env_var_token(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch == '-' {
                '_'
            } else {
                ch.to_ascii_uppercase()
            }
        })
        .collect()
}

fn json_port(port: &Value) -> Option<u16> {
    port.get("port")
        .and_then(Value::as_u64)
        .and_then(|number| u16::try_from(number).ok())
}

fn join_host_port(ip: &str, port: u16) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn automount_service_account_token(pod: &Value) -> bool {
    pod.pointer("/spec/automountServiceAccountToken")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

fn pod_has_service_account_token(pod: &Value) -> bool {
    pod.pointer("/spec/volumes")
        .and_then(Value::as_array)
        .is_some_and(|volumes| {
            volumes.iter().any(|volume| {
                volume
                    .pointer("/projected/sources")
                    .and_then(Value::as_array)
                    .is_some_and(|sources| {
                        sources
                            .iter()
                            .any(|source| source.get("serviceAccountToken").is_some())
                    })
            })
        })
}

/// Builds the CRI container configuration for one attempt of a spec container,
/// optionally resolving volume mounts against the given root directory.
pub fn container_config_with_root(
    pod: &Value,
    container: &Value,
    attempt: u32,
    root_dir: Option<&Path>,
) -> Result<cri::ContainerConfig, KubeletError> {
    let name = container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("main");
    let image = container
        .get("image")
        .and_then(Value::as_str)
        .filter(|image| !image.is_empty())
        .ok_or_else(|| KubeletError::InvalidConfiguration {
            field: format!("spec.containers[{name}].image"),
            reason: "container has no image".to_string(),
        })?;
    let strings = |key: &str| -> Vec<String> {
        container
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut envs = Vec::new();
    for entry in container
        .get("env")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(key) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        envs.push(cri::KeyValue {
            key: key.to_string(),
            value: resolve_env_value(pod, name, key, entry)?.into_bytes(),
        });
    }
    let namespace = pod
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let uid = pod
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .unwrap_or("");

    let empty_vec = Vec::new();
    let spec_volumes = pod
        .pointer("/spec/volumes")
        .and_then(Value::as_array)
        .unwrap_or(&empty_vec);
    let default_root = Path::new("/var/lib/kubelet");
    let root = root_dir.unwrap_or(default_root);
    let mounts = build_container_mounts(container, spec_volumes, root, uid);
    let linux = build_container_resources(container).map(|resources| cri::LinuxContainerConfig {
        resources: Some(resources),
        ..cri::LinuxContainerConfig::default()
    });

    Ok(cri::ContainerConfig {
        metadata: Some(cri::ContainerMetadata {
            name: name.to_string(),
            attempt,
        }),
        image: Some(cri::ImageSpec {
            image: image.to_string(),
            user_specified_image: image.to_string(),
            ..cri::ImageSpec::default()
        }),
        command: strings("command"),
        args: strings("args"),
        working_dir: container
            .get("workingDir")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        envs,
        mounts,
        labels: container_labels(namespace, pod_name(pod), uid, name),
        annotations: BTreeMap::from([(ANNOTATION_RESTART_COUNT.to_string(), attempt.to_string())]),
        log_path: format!("{name}/{attempt}.log"),
        linux,
        ..cri::ContainerConfig::default()
    })
}

fn resolve_volume_host_path(
    root: &Path,
    uid: &str,
    vol: &Value,
    vol_name: &str,
    sub_path: &str,
) -> Option<PathBuf> {
    let mut base = if vol.get("secret").is_some() {
        root.join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~secret")
            .join(vol_name)
    } else if vol.get("configMap").is_some() {
        root.join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~configmap")
            .join(vol_name)
    } else if vol.get("projected").is_some() {
        root.join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~projected")
            .join(vol_name)
    } else if vol.get("emptyDir").is_some() {
        root.join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~empty-dir")
            .join(vol_name)
    } else if vol.get("persistentVolumeClaim").is_some() {
        let pvc_vol_path = root
            .join("pods")
            .join(uid)
            .join("volumes")
            .join("kubernetes.io~persistent-volume-claim")
            .join(vol_name);
        std::fs::canonicalize(&pvc_vol_path).unwrap_or(pvc_vol_path)
    } else {
        let hp = vol.get("hostPath")?;
        PathBuf::from(hp.get("path")?.as_str()?)
    };
    if !sub_path.is_empty() {
        base.push(sub_path);
    }
    Some(base)
}

fn build_container_mounts(
    container: &Value,
    spec_volumes: &[Value],
    root: &Path,
    uid: &str,
) -> Vec<cri::Mount> {
    let mut mounts = Vec::new();
    let Some(vol_mounts) = container.get("volumeMounts").and_then(Value::as_array) else {
        return mounts;
    };
    for vm in vol_mounts {
        let Some(mount_path) = vm.get("mountPath").and_then(Value::as_str) else {
            continue;
        };
        let Some(vol_name) = vm.get("name").and_then(Value::as_str) else {
            continue;
        };
        let readonly = vm.get("readOnly").and_then(Value::as_bool).unwrap_or(false);
        let sub_path = vm.get("subPath").and_then(Value::as_str).unwrap_or("");

        let Some(vol) = spec_volumes
            .iter()
            .find(|v| v.get("name").and_then(Value::as_str) == Some(vol_name))
        else {
            continue;
        };

        if let Some(host_path) = resolve_volume_host_path(root, uid, vol, vol_name, sub_path) {
            mounts.push(cri::Mount {
                container_path: mount_path.to_string(),
                host_path: host_path.to_string_lossy().to_string(),
                readonly,
                ..cri::Mount::default()
            });
        }
    }
    mounts
}

fn build_container_resources(container: &Value) -> Option<cri::LinuxContainerResources> {
    let res = container.get("resources")?;
    let mut resources = cri::LinuxContainerResources::default();
    let mut has_resources = false;

    if let Some(limits) = res.get("limits") {
        if let Some(cpu) = limits.get("cpu").and_then(Value::as_str)
            && let Some(milli) = parse_cpu_quantity_milli(cpu)
        {
            let quota = i64::try_from(milli.saturating_mul(100)).unwrap_or(i64::MAX);
            resources.cpu_quota = quota;
            resources.cpu_period = 100_000;
            has_resources = true;
        }
        if let Some(mem) = limits.get("memory").and_then(Value::as_str)
            && let Some(bytes) = parse_memory_quantity_bytes(mem)
        {
            resources.memory_limit_in_bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
            has_resources = true;
        }
    }
    let cpu_req = res
        .get("requests")
        .and_then(|r| r.get("cpu"))
        .and_then(Value::as_str)
        .or_else(|| {
            res.get("limits")
                .and_then(|l| l.get("cpu"))
                .and_then(Value::as_str)
        });
    if let Some(cpu) = cpu_req
        && let Some(milli) = parse_cpu_quantity_milli(cpu)
    {
        let shares = i64::try_from(milli.saturating_mul(1024) / 1000)
            .unwrap_or(i64::MAX)
            .max(2);
        resources.cpu_shares = shares;
        has_resources = true;
    }

    if has_resources { Some(resources) } else { None }
}

/// Builds the CRI container configuration for one attempt of a spec container.
///
/// Follows the kubelet: `command` and `args` map onto the CRI fields of the same
/// name, `env.valueFrom.fieldRef` resolves pod metadata and status fields, and
/// other `valueFrom` sources are configuration errors.
pub fn container_config(
    pod: &Value,
    container: &Value,
    attempt: u32,
) -> Result<cri::ContainerConfig, KubeletError> {
    container_config_with_root(pod, container, attempt, None)
}

fn resolve_env_value(
    pod: &Value,
    container: &str,
    key: &str,
    entry: &Value,
) -> Result<String, KubeletError> {
    if let Some(value) = entry.get("value").and_then(Value::as_str) {
        return Ok(value.to_string());
    }
    let Some(source) = entry.get("valueFrom") else {
        return Ok(String::new());
    };
    let Some(field) = source
        .pointer("/fieldRef/fieldPath")
        .and_then(Value::as_str)
    else {
        let kind = source
            .as_object()
            .and_then(|map| map.keys().next().cloned())
            .unwrap_or_else(|| "valueFrom".to_string());
        return Err(KubeletError::InvalidConfiguration {
            field: format!("spec.containers[{container}].env[{key}]"),
            reason: format!("env source {kind} is not supported by this runtime"),
        });
    };
    let value = match field {
        "metadata.name"
        | "metadata.namespace"
        | "metadata.uid"
        | "spec.nodeName"
        | "spec.serviceAccountName"
        | "status.hostIP"
        | "status.podIP" => pod
            .pointer(&format!("/{}", field.replace('.', "/")))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        other => {
            return Err(KubeletError::InvalidConfiguration {
                field: format!("spec.containers[{container}].env[{key}]"),
                reason: format!("fieldRef {other} is not supported"),
            });
        },
    };
    Ok(value)
}

/// Pull behaviour from `imagePullPolicy`, defaulting as the kubelet does:
/// `Always` for `:latest` or untagged images, `IfNotPresent` otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullPolicy {
    Always,
    IfNotPresent,
    Never,
}

impl PullPolicy {
    #[must_use]
    pub fn of(container: &Value) -> Self {
        let image = container.get("image").and_then(Value::as_str).unwrap_or("");
        match container.get("imagePullPolicy").and_then(Value::as_str) {
            Some("Never") => Self::Never,
            Some("Always") => Self::Always,
            None if is_latest(image) => Self::Always,
            _ => Self::IfNotPresent,
        }
    }
}

/// `:latest` or no tag at all, without a digest.
fn is_latest(image: &str) -> bool {
    if image.contains('@') {
        return false;
    }
    let last = image.rsplit('/').next().unwrap_or(image);
    match last.rsplit_once(':') {
        Some((_, tag)) => tag == "latest",
        None => true,
    }
}

/// Finds the container id for a pod uid and container name: the latest attempt,
/// or the one before it when `previous` is set.
pub async fn resolve_container(
    runtime: &dyn RuntimeProvider,
    pod_uid: &str,
    container_name: &str,
    previous: bool,
) -> Result<String, KubeletError> {
    let filter = cri::ContainerFilter {
        label_selector: BTreeMap::from([
            (LABEL_MANAGED_BY.to_string(), MANAGED_BY.to_string()),
            (LABEL_POD_UID.to_string(), pod_uid.to_string()),
            (LABEL_CONTAINER_NAME.to_string(), container_name.to_string()),
        ]),
        ..cri::ContainerFilter::default()
    };
    let mut containers = runtime.list_containers(Some(&filter)).await?;
    containers.sort_by_key(|c| c.metadata.as_ref().map_or(0, |m| m.attempt));
    let index = containers.len().checked_sub(if previous { 2 } else { 1 });
    index
        .and_then(|i| containers.get(i))
        .map(|c| c.id.clone())
        .ok_or_else(|| KubeletError::ContainerOperationFailed {
            container: container_name.to_string(),
            reason: format!(
                "no {}container for pod {pod_uid}",
                if previous { "previous " } else { "" }
            ),
        })
}

/// Pod reconciler driving pod lifecycle on the registered node.
#[derive(Clone, Debug)]
pub struct PodReconciler {
    client: Arc<KubernetesApiClient>,
    runtime: Arc<dyn RuntimeProvider>,
    node_name: String,
    node_ip: String,
    cpu_manager: Arc<CpuManager>,
    checkpoint_invalidated: Arc<AtomicBool>,
    root_dir: PathBuf,
    apiserver: Option<Arc<ApiserverService>>,
    cluster_dns: Vec<String>,
    cluster_domain: String,
    backoff: Arc<Mutex<BTreeMap<String, RestartBackoff>>>,
    terminating: Arc<Mutex<BTreeSet<String>>>,
    probe_trackers: Arc<Mutex<BTreeMap<String, ProbeTracker>>>,
}

impl PodReconciler {
    #[must_use]
    pub fn new(
        client: Arc<KubernetesApiClient>,
        runtime: Arc<dyn RuntimeProvider>,
        node_name: impl Into<String>,
        node_ip: impl Into<String>,
    ) -> Self {
        let node_ip_str = node_ip.into();
        let effective_ip = if node_ip_str.is_empty() {
            "127.0.0.1".to_string()
        } else {
            node_ip_str
        };
        let dummy_cpu_manager = Arc::new(CpuManager::new(
            "none",
            BTreeMap::new(),
            BTreeSet::new(),
            detect_host_cpu_count(),
            PathBuf::from("/tmp/diorama-node/cpu_manager_state"),
        ));
        Self {
            client,
            runtime,
            node_name: node_name.into(),
            node_ip: effective_ip,
            cpu_manager: dummy_cpu_manager,
            checkpoint_invalidated: Arc::new(AtomicBool::new(false)),
            root_dir: PathBuf::from("/var/lib/kubelet"),
            apiserver: None,
            cluster_dns: vec![DEFAULT_CLUSTER_DNS.to_string()],
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            backoff: Arc::new(Mutex::new(BTreeMap::new())),
            terminating: Arc::new(Mutex::new(BTreeSet::new())),
            probe_trackers: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    #[must_use]
    pub fn with_cluster_dns(mut self, cluster_dns: Vec<String>) -> Self {
        self.cluster_dns = cluster_dns;
        self
    }

    #[must_use]
    pub fn with_cluster_domain(mut self, cluster_domain: impl Into<String>) -> Self {
        self.cluster_domain = cluster_domain.into();
        self
    }

    #[must_use]
    pub fn cluster_dns(&self) -> &[String] {
        &self.cluster_dns
    }

    #[must_use]
    pub fn cluster_domain(&self) -> &str {
        &self.cluster_domain
    }

    #[must_use]
    pub fn with_cpu_manager(mut self, cpu_manager: Arc<CpuManager>) -> Self {
        self.cpu_manager = cpu_manager;
        self
    }

    #[must_use]
    pub fn with_root_dir(mut self, root_dir: impl Into<PathBuf>) -> Self {
        self.root_dir = root_dir.into();
        self
    }

    #[must_use]
    pub fn with_apiserver(mut self, apiserver: Arc<ApiserverService>) -> Self {
        self.apiserver = Some(apiserver);
        self
    }

    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    #[must_use]
    pub fn cpu_manager(&self) -> &CpuManager {
        &self.cpu_manager
    }

    pub fn mark_checkpoint_invalidated(&self, invalidated: bool) {
        self.checkpoint_invalidated
            .store(invalidated, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_checkpoint_invalidated(&self) -> bool {
        self.checkpoint_invalidated.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn runtime_provider_name(&self) -> &str {
        self.runtime.provider_name()
    }

    #[must_use]
    pub fn get_pod_volume_dir(
        &self,
        pod_uid_or_name: &str,
        plugin_name: &str,
        volume_name: &str,
    ) -> PathBuf {
        self.root_dir
            .join("pods")
            .join(pod_uid_or_name)
            .join("volumes")
            .join(plugin_name)
            .join(volume_name)
    }

    /// Finds the container id for a pod uid and container name: the latest attempt,
    /// or the one before it when `previous` is set.
    pub async fn resolve_container(
        &self,
        pod_uid: &str,
        container_name: &str,
        previous: bool,
    ) -> Result<String, KubeletError> {
        resolve_container(self.runtime.as_ref(), pod_uid, container_name, previous).await
    }

    pub async fn get_container_logs(
        &self,
        pod_uid: &str,
        container_name: &str,
        tail_lines: Option<usize>,
    ) -> Result<String, KubeletError> {
        let options = LogOptions {
            tail_lines,
            ..LogOptions::default()
        };
        self.read_container_logs(pod_uid, container_name, &options)
            .await
    }

    pub async fn read_container_logs(
        &self,
        pod_uid: &str,
        container_name: &str,
        options: &LogOptions,
    ) -> Result<String, KubeletError> {
        let id = self
            .resolve_container(pod_uid, container_name, options.previous)
            .await?;
        self.runtime.container_logs(&id, options).await
    }

    pub async fn exec_in_container(
        &self,
        pod_uid: &str,
        container_name: &str,
        cmd: &[String],
    ) -> Result<ExecResult, KubeletError> {
        let id = self
            .resolve_container(pod_uid, container_name, false)
            .await?;
        self.runtime.exec_sync(&id, cmd, EXEC_TIMEOUT_SECS).await
    }

    /// Reports workload-restart needs for surviving external-runtime containers when
    /// the CPU manager checkpoint was invalidated.
    pub async fn report_workload_restart_needs(
        &self,
        namespace: &str,
    ) -> Result<Vec<WorkloadRestartReport>, KubeletError> {
        let mut reports = Vec::new();
        if !self.runtime.is_external() || !self.is_checkpoint_invalidated() {
            return Ok(reports);
        }
        let pod_list = self.client.list_pods(namespace).await?;
        for pod in pod_list
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            reports.extend(check_pod_restart_need(
                pod,
                &self.node_name,
                self.runtime.provider_name(),
                namespace,
            ));
        }
        Ok(reports)
    }

    /// Reconciles all pods in the specified namespace assigned to this node.
    pub async fn reconcile_namespace(&self, namespace: &str) -> Result<usize, KubeletError> {
        let pod_list = self.client.list_pods(namespace).await?;
        let mut reconciled = 0;
        for pod in pod_list
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if pod.pointer("/spec/nodeName").and_then(Value::as_str) != Some(&self.node_name) {
                continue;
            }
            let outcome = if pod.pointer("/metadata/deletionTimestamp").is_some() {
                self.terminate_pod(namespace, pod).await
            } else {
                self.sync_pod(namespace, pod).await
            };
            match outcome {
                Ok(()) => reconciled += 1,
                Err(e) => eprintln!("Failed to sync pod {namespace}/{}: {e}", pod_name(pod)),
            }
        }
        Ok(reconciled)
    }

    /// Reconciles every pod in the cluster: binds unscheduled pods to this node,
    /// syncs or terminates the pods assigned here, and removes sandboxes whose Pod is gone.
    pub async fn reconcile_all(&self) -> Result<ReconcileReport, KubeletError> {
        let pod_list = self.client.list_all_pods().await?;
        let mut report = ReconcileReport::default();
        let mut live_uids = BTreeSet::new();
        for pod in pod_list
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(uid) = pod.pointer("/metadata/uid").and_then(Value::as_str) {
                live_uids.insert(uid.to_string());
            }
            let namespace = pod
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .unwrap_or("default")
                .to_string();
            let name = pod_name(pod).to_string();
            let pod = match pod.pointer("/spec/nodeName").and_then(Value::as_str) {
                Some(node) if node == self.node_name => pod.clone(),
                Some(_) => continue,
                None => match self.bind_pod_to_node(&namespace, pod).await {
                    Ok(bound) => {
                        report.bound += 1;
                        bound
                    },
                    Err(e) => {
                        report.failed += 1;
                        eprintln!("Failed to bind pod {namespace}/{name}: {e}");
                        continue;
                    },
                },
            };
            let outcome = if pod.pointer("/metadata/deletionTimestamp").is_some() {
                self.terminate_pod(&namespace, &pod).await
            } else {
                self.sync_pod(&namespace, &pod).await
            };
            match outcome {
                Ok(()) => report.synced += 1,
                Err(e) => {
                    report.failed += 1;
                    eprintln!("Failed to sync pod {namespace}/{name}: {e}");
                },
            }
        }
        report.orphans_stopped = self.stop_orphaned_pods(&live_uids).await?;
        Ok(report)
    }

    /// Assigns an unscheduled pod to this node. There is no scheduler in a
    /// single-node distribution, so the kubelet performs the binding itself.
    pub async fn bind_pod_to_node(
        &self,
        namespace: &str,
        pod: &Value,
    ) -> Result<Value, KubeletError> {
        let name = pod_name(pod);
        let mut bound = pod.clone();
        bound["spec"]["nodeName"] = json!(self.node_name);
        self.client
            .update_pod(namespace, name, bound)
            .await
            .map_err(|e| KubeletError::PodReconciliationFailed {
                pod: format!("{namespace}/{name}"),
                reason: format!("failed to bind pod to node {}: {e}", self.node_name),
            })
    }

    /// Removes sandboxes (and their containers) whose Pod object no longer exists.
    pub async fn stop_orphaned_pods(
        &self,
        live_uids: &BTreeSet<String>,
    ) -> Result<usize, KubeletError> {
        let filter = cri::PodSandboxFilter {
            label_selector: BTreeMap::from([(
                LABEL_MANAGED_BY.to_string(),
                MANAGED_BY.to_string(),
            )]),
            ..cri::PodSandboxFilter::default()
        };
        let mut orphaned: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut orphaned_pod_names: BTreeSet<(String, String)> = BTreeSet::new();
        for sandbox in self.runtime.list_pod_sandbox(Some(&filter)).await? {
            let Some(uid) = sandbox.labels.get(LABEL_POD_UID) else {
                continue;
            };
            if !live_uids.contains(uid) {
                if let (Some(ns), Some(p_name)) = (
                    sandbox.labels.get(LABEL_POD_NAMESPACE),
                    sandbox.labels.get(LABEL_POD_NAME),
                ) {
                    orphaned_pod_names.insert((ns.clone(), p_name.clone()));
                }
                orphaned.entry(uid.clone()).or_default().push(sandbox.id);
            }
        }
        for (ns, p_name) in orphaned_pod_names {
            let _ = self
                .cpu_manager
                .release_pod_cpus(&format!("{ns}/{p_name}/"));
        }
        for (uid, sandbox_ids) in &orphaned {
            for sandbox_id in sandbox_ids {
                self.remove_sandbox_tree(sandbox_id).await?;
            }
            eprintln!("removed sandbox of deleted pod {uid}");
        }
        Ok(orphaned.len())
    }

    /// Stops and removes a sandbox together with every container in it.
    async fn remove_sandbox_tree(&self, sandbox_id: &str) -> Result<(), KubeletError> {
        let _ = self.runtime.stop_pod_sandbox(sandbox_id).await;
        let filter = cri::ContainerFilter {
            pod_sandbox_id: sandbox_id.to_string(),
            ..cri::ContainerFilter::default()
        };
        for container in self.runtime.list_containers(Some(&filter)).await? {
            self.runtime.remove_container(&container.id).await?;
        }
        self.runtime.remove_pod_sandbox(sandbox_id).await
    }

    /// Full statuses of every container in a sandbox.
    async fn container_statuses(
        &self,
        sandbox_id: &str,
    ) -> Result<Vec<cri::ContainerStatus>, KubeletError> {
        let filter = cri::ContainerFilter {
            pod_sandbox_id: sandbox_id.to_string(),
            ..cri::ContainerFilter::default()
        };
        let mut statuses = Vec::new();
        for container in self.runtime.list_containers(Some(&filter)).await? {
            // A container removed between list and status shows up on the next pass.
            if let Ok(status) = self.runtime.container_status(&container.id).await {
                statuses.push(status);
            }
        }
        Ok(statuses)
    }

    /// Finds the pod's ready sandbox or creates one, removing stale sandboxes.
    async fn ensure_sandbox(
        &self,
        namespace: &str,
        pod: &Value,
    ) -> Result<(String, cri::PodSandboxConfig), KubeletError> {
        let name = pod_name(pod);
        let uid = pod_uid(pod)?;
        let sandboxes = self
            .runtime
            .list_pod_sandbox(Some(&uid_filter(uid)))
            .await?;
        if let Some(ready) = sandboxes
            .iter()
            .find(|s| s.state == cri::PodSandboxState::SandboxReady as i32)
        {
            let attempt = ready.metadata.as_ref().map_or(0, |m| m.attempt);
            return Ok((
                ready.id.clone(),
                sandbox_config_with_dns(pod, attempt, &self.cluster_dns, &self.cluster_domain),
            ));
        }
        let mut attempt = 0;
        for stale in &sandboxes {
            attempt = attempt.max(stale.metadata.as_ref().map_or(0, |m| m.attempt) + 1);
            self.remove_sandbox_tree(&stale.id).await?;
        }
        if pod.pointer("/status/phase").is_none() {
            let pending = pending_status(pod, &self.node_ip, "ContainerCreating", None);
            self.patch_status_if_changed(namespace, name, pod, pending)
                .await?;
        }
        let config = sandbox_config_with_dns(pod, attempt, &self.cluster_dns, &self.cluster_domain);
        let id = self.runtime.run_pod_sandbox(&config).await?;
        Ok((id, config))
    }

    /// Makes the image available under the container's pull policy.
    async fn ensure_image(
        &self,
        container: &Value,
        sandbox_config: &cri::PodSandboxConfig,
    ) -> Result<(), StartFailure> {
        let image = container.get("image").and_then(Value::as_str).unwrap_or("");
        let spec = cri::ImageSpec {
            image: image.to_string(),
            user_specified_image: image.to_string(),
            ..cri::ImageSpec::default()
        };
        let present = self
            .runtime
            .image_status(&spec)
            .await
            .map_err(|e| StartFailure {
                reason: "ErrImagePull",
                message: format!("failed to inspect image {image}: {e}"),
            })?
            .is_some();
        let pull = match PullPolicy::of(container) {
            PullPolicy::Always => true,
            PullPolicy::IfNotPresent => !present,
            PullPolicy::Never if present => false,
            PullPolicy::Never => {
                return Err(StartFailure {
                    reason: "ErrImageNeverPull",
                    message: format!(
                        "Container image \"{image}\" is not present with pull policy of Never"
                    ),
                });
            },
        };
        if pull {
            self.runtime
                .pull_image(&spec, Some(sandbox_config))
                .await
                .map_err(|e| StartFailure {
                    reason: "ErrImagePull",
                    message: format!("failed to pull image {image}: {e}"),
                })?;
        }
        Ok(())
    }

    /// Executes a container's preStop hook command synchronously if configured.
    async fn execute_pre_stop_hook(&self, container_id: &str, container: &Value) {
        if let Some(cmd) = container
            .pointer("/lifecycle/preStop/exec/command")
            .and_then(Value::as_array)
        {
            let command: Vec<String> = cmd
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect();
            if !command.is_empty() {
                let _ = self
                    .runtime
                    .exec_sync(container_id, &command, EXEC_TIMEOUT_SECS)
                    .await;
            }
        }
    }

    /// Pulls, creates and starts one attempt of a spec container.
    async fn start_attempt(
        &self,
        sandbox_id: &str,
        sandbox_config: &cri::PodSandboxConfig,
        pod: &Value,
        container: &Value,
        attempt: u32,
    ) -> Result<String, StartFailure> {
        self.ensure_image(container, sandbox_config).await?;
        let mut config = container_config_with_root(pod, container, attempt, Some(&self.root_dir))
            .map_err(|e| StartFailure {
                reason: "CreateContainerConfigError",
                message: e.to_string(),
            })?;
        let service_list = self
            .client
            .list_services("")
            .await
            .map_err(|err| StartFailure {
                reason: "CreateContainerConfigError",
                message: format!("failed to list services for service links: {err}"),
            })?;
        let services = service_list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        apply_service_links(&mut config.envs, pod, &services);
        let namespace = pod
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("default");
        let name = pod_name(pod);
        let assignment = self.cpu_assignment(namespace, name, pod, container);
        if !assignment.cpuset.is_empty() {
            let linux = config
                .linux
                .get_or_insert_with(cri::LinuxContainerConfig::default);
            let resources = linux
                .resources
                .get_or_insert_with(cri::LinuxContainerResources::default);
            resources.cpuset_cpus = assignment.cpuset;
        }
        let id = self
            .runtime
            .create_container(sandbox_id, &config, sandbox_config)
            .await
            .map_err(|e| StartFailure {
                reason: "CreateContainerError",
                message: e.to_string(),
            })?;
        self.runtime
            .start_container(&id)
            .await
            .map_err(|e| StartFailure {
                reason: "RunContainerError",
                message: e.to_string(),
            })?;
        Ok(id)
    }

    /// Decides whether an exited container restarts now (`Ok(next attempt)`) or
    /// waits (`Err(back-off message)`), recording the back-off.
    fn restart_decision(
        &self,
        namespace: &str,
        pod_name: &str,
        uid: &str,
        container_name: &str,
        latest: &cri::ContainerStatus,
    ) -> Result<u32, String> {
        let now = now_unix();
        let ran_for = secs_from_nanos(latest.started_at)
            .zip(secs_from_nanos(latest.finished_at))
            .map_or(0, |(started, finished)| finished.saturating_sub(started));
        let key = format!("{uid}/{container_name}");
        let mut backoffs = self
            .backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match backoffs.get(&key).copied() {
            Some(backoff) if now < backoff.not_before => Err(format!(
                "back-off {}s restarting failed container={container_name} pod={pod_name}_{namespace}({uid})",
                backoff.delay_secs
            )),
            previous => {
                backoffs.insert(key, next_restart_backoff(previous, ran_for, now));
                Ok(attempt_of(latest) + 1)
            },
        }
    }

    /// CPU-manager placement for a container, allocating exclusive cores when eligible.
    fn cpu_assignment(
        &self,
        namespace: &str,
        pod_name: &str,
        pod: &Value,
        container: &Value,
    ) -> CpuAssignment {
        let c_name = container
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("main");
        let key = format!("{namespace}/{pod_name}/{c_name}");
        if let Some(cores) = is_container_cpu_pinning_eligible(determine_pod_qos(pod), container) {
            match self.cpu_manager.allocate_exclusive_cpus(&key, cores) {
                Ok(cpus) => {
                    return CpuAssignment {
                        cpuset: format_cpuset(&cpus),
                        exclusive: true,
                    };
                },
                Err(e) => eprintln!("exclusive CPU allocation failed for {key}: {e}"),
            }
        }
        CpuAssignment {
            cpuset: format_cpuset(&self.cpu_manager.shared_pool()),
            exclusive: false,
        }
    }

    /// Synchronizes an individual pod's runtime state and updates its API status.
    pub async fn sync_pod(&self, namespace: &str, pod: &Value) -> Result<(), KubeletError> {
        let name = pod_name(pod);
        pod_uid(pod)?;
        if matches!(
            pod.pointer("/status/phase").and_then(Value::as_str),
            Some("Succeeded" | "Failed")
        ) {
            return Ok(());
        }
        let enriched = self.pod_with_service_account_volume(pod);
        let pod = &enriched;
        self.prepare_pod_volumes(namespace, pod).await?;
        let (sandbox_id, sandbox_config) = match self.ensure_sandbox(namespace, pod).await {
            Ok(sandbox) => sandbox,
            Err(e) => {
                let failed = pending_status(
                    pod,
                    &self.node_ip,
                    "FailedCreatePodSandBox",
                    Some(&e.to_string()),
                );
                self.patch_status_if_changed(namespace, name, pod, failed)
                    .await?;
                return Err(e);
            },
        };
        let empty = Vec::new();
        let spec_init_containers = pod
            .pointer("/spec/initContainers")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let spec_containers = pod
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .unwrap_or(&empty);

        let mut statuses = self.container_statuses(&sandbox_id).await?;
        let mut state = SyncState::default();

        let ctx = SyncContext {
            namespace,
            pod,
            sandbox_id: &sandbox_id,
            sandbox_config: &sandbox_config,
        };

        let all_inits_complete = self
            .reconcile_init_containers(&ctx, spec_init_containers, &statuses, &mut state)
            .await?;

        if all_inits_complete {
            self.reconcile_app_containers(&ctx, spec_containers, &statuses, &mut state)
                .await?;
        }

        if !state.started_now.is_empty() {
            statuses = self.container_statuses(&sandbox_id).await?;
            self.probe_started(spec_init_containers, &statuses, &mut state)
                .await?;
            self.probe_started(spec_containers, &statuses, &mut state)
                .await?;
        }
        self.prune_attempts(&statuses).await;
        let views = self.build_views(namespace, pod, spec_containers, &statuses, &state);
        let init_views = self.build_views(namespace, pod, spec_init_containers, &statuses, &state);
        let pod_ip = self
            .runtime
            .pod_sandbox_status(&sandbox_id)
            .await
            .ok()
            .and_then(|status| status.network)
            .map(|network| network.ip);
        let status = pod_status(
            pod,
            self.runtime.provider_name(),
            &self.node_ip,
            pod_ip.as_deref(),
            true,
            RestartPolicy::of(pod),
            PodViews {
                containers: &views,
                init_containers: &init_views,
            },
        );
        self.patch_status_if_changed(namespace, name, pod, status)
            .await
    }

    async fn reconcile_init_containers(
        &self,
        ctx: &SyncContext<'_>,
        spec_init_containers: &[Value],
        statuses: &[cri::ContainerStatus],
        state: &mut SyncState,
    ) -> Result<bool, KubeletError> {
        for init_container in spec_init_containers {
            let c_name = container_name_of(init_container);
            let latest = attempts_by_name(statuses)
                .get(c_name)
                .and_then(|attempts| attempts.last().copied());
            let is_complete = latest.is_some_and(|s| {
                state_of(s) == cri::ContainerState::ContainerExited && s.exit_code == 0
            });
            if is_complete {
                continue;
            }
            let Some(attempt) = self
                .next_attempt(ctx.namespace, ctx.pod, init_container, latest, state)
                .await?
            else {
                return Ok(false);
            };
            match self
                .start_attempt(
                    ctx.sandbox_id,
                    ctx.sandbox_config,
                    ctx.pod,
                    init_container,
                    attempt,
                )
                .await
            {
                Ok(_) => {
                    state.started_now.insert(c_name.to_string());
                },
                Err(failure) => {
                    state
                        .waiting
                        .insert(c_name.to_string(), (failure.reason, failure.message));
                },
            }
            return Ok(false);
        }
        Ok(true)
    }

    async fn reconcile_app_containers(
        &self,
        ctx: &SyncContext<'_>,
        spec_containers: &[Value],
        statuses: &[cri::ContainerStatus],
        state: &mut SyncState,
    ) -> Result<(), KubeletError> {
        for container in spec_containers {
            let c_name = container_name_of(container);
            let latest = attempts_by_name(statuses)
                .get(c_name)
                .and_then(|attempts| attempts.last().copied());
            let Some(attempt) = self
                .next_attempt(ctx.namespace, ctx.pod, container, latest, state)
                .await?
            else {
                continue;
            };
            match self
                .start_attempt(
                    ctx.sandbox_id,
                    ctx.sandbox_config,
                    ctx.pod,
                    container,
                    attempt,
                )
                .await
            {
                Ok(_) => {
                    state.started_now.insert(c_name.to_string());
                },
                Err(failure) => {
                    state
                        .waiting
                        .insert(c_name.to_string(), (failure.reason, failure.message));
                },
            }
        }
        Ok(())
    }

    /// Status inputs for every spec container after this pass.
    fn build_views<'a>(
        &self,
        namespace: &str,
        pod: &'a Value,
        spec_containers: &'a [Value],
        statuses: &'a [cri::ContainerStatus],
        state: &SyncState,
    ) -> Vec<ContainerView<'a>> {
        let grouped = attempts_by_name(statuses);
        spec_containers
            .iter()
            .map(|container| {
                let c_name = container_name_of(container);
                let attempts = grouped.get(c_name).map_or(&[][..], Vec::as_slice);
                ContainerView {
                    spec: container,
                    latest: attempts.last().copied(),
                    previous: attempts
                        .len()
                        .checked_sub(2)
                        .and_then(|i| attempts.get(i))
                        .copied(),
                    ready: state.ready.get(c_name).copied().unwrap_or(false),
                    backoff: state.backoffs.get(c_name).cloned(),
                    waiting: state.waiting.get(c_name).cloned(),
                    cpu: Some(self.cpu_assignment(namespace, pod_name(pod), pod, container)),
                }
            })
            .collect()
    }

    /// Decides what one spec container needs this pass: `Some(attempt)` to start a
    /// new attempt, `None` to leave it alone. Probes running containers and stops
    /// one whose liveness probe failed; records readiness and back-off in `state`.
    async fn next_attempt(
        &self,
        namespace: &str,
        pod: &Value,
        container: &Value,
        latest: Option<&cri::ContainerStatus>,
        state: &mut SyncState,
    ) -> Result<Option<u32>, KubeletError> {
        let c_name = container_name_of(container);
        let policy = RestartPolicy::of(pod);
        let Some(latest) = latest else {
            return Ok(Some(0));
        };
        match state_of(latest) {
            cri::ContainerState::ContainerCreated => {
                self.runtime.start_container(&latest.id).await?;
                state.started_now.insert(c_name.to_string());
                Ok(None)
            },
            cri::ContainerState::ContainerRunning => {
                let started_at_secs = secs_from_nanos(latest.started_at).unwrap_or(0);
                let (live, is_ready) = self
                    .evaluate_container_probes(&latest.id, container, started_at_secs)
                    .await?;
                if live || policy == RestartPolicy::Never {
                    state.ready.insert(c_name.to_string(), is_ready);
                    return Ok(None);
                }
                self.execute_pre_stop_hook(&latest.id, container).await;
                self.runtime.stop_container(&latest.id, 0).await?;
                state.restarted.insert(c_name.to_string());
                Ok(self.schedule_restart(namespace, pod, c_name, latest, state))
            },
            cri::ContainerState::ContainerExited if policy.restarts(latest.exit_code) => {
                Ok(self.schedule_restart(namespace, pod, c_name, latest, state))
            },
            cri::ContainerState::ContainerExited | cri::ContainerState::ContainerUnknown => {
                Ok(None)
            },
        }
    }

    /// Next attempt number when the back-off allows a restart now; otherwise
    /// records the `CrashLoopBackOff` message and returns `None`.
    fn schedule_restart(
        &self,
        namespace: &str,
        pod: &Value,
        c_name: &str,
        latest: &cri::ContainerStatus,
        state: &mut SyncState,
    ) -> Option<u32> {
        let uid = pod
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or("");
        match self.restart_decision(namespace, pod_name(pod), uid, c_name, latest) {
            Ok(attempt) => Some(attempt),
            Err(message) => {
                state.backoffs.insert(c_name.to_string(), message);
                None
            },
        }
    }

    /// Readiness of containers started this pass. A container restarted after a
    /// failed liveness probe is not ready until the next pass proves it; a fresh
    /// start is probed right away.
    async fn probe_started(
        &self,
        spec_containers: &[Value],
        statuses: &[cri::ContainerStatus],
        state: &mut SyncState,
    ) -> Result<(), KubeletError> {
        let grouped = attempts_by_name(statuses);
        for container in spec_containers {
            let c_name = container_name_of(container);
            if !state.started_now.contains(c_name) {
                continue;
            }
            let latest = grouped.get(c_name).and_then(|a| a.last());
            let is_ready = match latest {
                Some(latest) if !state.restarted.contains(c_name) => {
                    let started_at_secs = secs_from_nanos(latest.started_at).unwrap_or(0);
                    self.evaluate_container_probes(&latest.id, container, started_at_secs)
                        .await?
                        .1
                },
                _ => false,
            };
            state.ready.insert(c_name.to_string(), is_ready);
        }
        Ok(())
    }

    /// Keeps the current and previous attempt of each container; older ones only hold stale logs.
    async fn prune_attempts(&self, statuses: &[cri::ContainerStatus]) {
        for attempts in attempts_by_name(statuses).values() {
            let stale = attempts.len().saturating_sub(KEPT_ATTEMPTS);
            for old in attempts.iter().take(stale) {
                let _ = self.runtime.remove_container(&old.id).await;
                self.probe_trackers
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retain(|key, _| !key.starts_with(&format!("{}:", old.id)));
            }
        }
    }

    fn spawn_stop(&self, id: String, grace: i64, uid: &str) {
        // StopContainer blocks while TERM and then KILL run; keep the loop moving.
        let runtime = self.runtime.clone();
        let terminating = self.terminating.clone();
        let uid = uid.to_string();
        tokio::spawn(async move {
            if let Err(e) = runtime.stop_container(&id, grace).await {
                eprintln!("failed to stop container {id}: {e}");
                terminating
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&uid);
            }
        });
    }

    /// Drives a pod carrying `deletionTimestamp`: stop its containers with the
    /// remaining grace period (TERM, then KILL), then record the final status,
    /// remove the sandbox and delete the Pod object with a zero grace period.
    async fn terminate_pod(&self, namespace: &str, pod: &Value) -> Result<(), KubeletError> {
        let name = pod_name(pod);
        let uid = pod_uid(pod)?;
        let deadline = pod
            .pointer("/metadata/deletionTimestamp")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_seconds)
            .unwrap_or(0);
        let sandboxes = self
            .runtime
            .list_pod_sandbox(Some(&uid_filter(uid)))
            .await?;
        let mut statuses = Vec::new();
        for sandbox in &sandboxes {
            statuses.extend(self.container_statuses(&sandbox.id).await?);
        }
        let running: Vec<(String, Value)> = statuses
            .iter()
            .filter(|s| state_of(s) == cri::ContainerState::ContainerRunning)
            .map(|s| {
                let name = s.metadata.as_ref().map_or("", |m| m.name.as_str());
                let spec = pod
                    .pointer("/spec/containers")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .chain(
                        pod.pointer("/spec/initContainers")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten(),
                    )
                    .find(|c| c.get("name").and_then(Value::as_str) == Some(name))
                    .cloned()
                    .unwrap_or(Value::Null);
                (s.id.clone(), spec)
            })
            .collect();
        if !running.is_empty() {
            let now = now_unix();
            let overdue = deadline != 0 && now > deadline;
            let first_pass = self
                .terminating
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(uid.to_string());
            if first_pass || overdue {
                let grace = if overdue {
                    0
                } else {
                    i64::try_from(deadline.saturating_sub(now)).unwrap_or(0)
                };
                for (id, spec) in running {
                    self.execute_pre_stop_hook(&id, &spec).await;
                    self.spawn_stop(id, grace, uid);
                }
            }
            return Ok(());
        }
        let grouped = attempts_by_name(&statuses);
        let views = dead_container_views(pod, "/spec/containers", &grouped);
        let init_views = dead_container_views(pod, "/spec/initContainers", &grouped);
        let status = pod_status(
            pod,
            self.runtime.provider_name(),
            &self.node_ip,
            None,
            false,
            RestartPolicy::Never,
            PodViews {
                containers: &views,
                init_containers: &init_views,
            },
        );
        self.patch_status_if_changed(namespace, name, pod, status)
            .await?;
        for sandbox in &sandboxes {
            self.remove_sandbox_tree(&sandbox.id).await?;
        }
        {
            let mut trackers = self
                .probe_trackers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for s in &statuses {
                trackers.retain(|k, _| !k.starts_with(&format!("{}:", s.id)));
            }
        }
        self.finish_deletion(namespace, name, uid).await
    }

    async fn finish_deletion(
        &self,
        namespace: &str,
        name: &str,
        uid: &str,
    ) -> Result<(), KubeletError> {
        let _ = self
            .cpu_manager
            .release_pod_cpus(&format!("{namespace}/{name}/"));
        self.terminating
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(uid);
        self.backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|key, _| !key.starts_with(&format!("{uid}/")));
        self.probe_trackers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|key, _| !key.starts_with(&format!("{uid}/")));
        match self
            .client
            .delete_pod_options(namespace, name, Some(0))
            .await
        {
            Ok(_) | Err(ApiserverError::NotFound { .. }) => Ok(()),
            Err(e) => Err(KubeletError::PodReconciliationFailed {
                pod: format!("{namespace}/{name}"),
                reason: format!("failed to delete terminated pod: {e}"),
            }),
        }
    }

    async fn patch_status_if_changed(
        &self,
        namespace: &str,
        name: &str,
        pod: &Value,
        status: Value,
    ) -> Result<(), KubeletError> {
        if pod.get("status") == Some(&status) {
            return Ok(());
        }
        self.client
            .patch_pod_status(namespace, name, status)
            .await
            .map(drop)
            .map_err(|e| KubeletError::PodReconciliationFailed {
                pod: format!("{namespace}/{name}"),
                reason: format!("failed to patch pod status: {e}"),
            })
    }

    async fn evaluate_probe(
        &self,
        container_id: &str,
        container: &Value,
        probe: &Value,
    ) -> Result<bool, KubeletError> {
        let timeout_secs = probe
            .get("timeoutSeconds")
            .and_then(Value::as_i64)
            .unwrap_or(EXEC_TIMEOUT_SECS);
        let command: Option<Vec<String>> = if let Some(exec) = probe.get("exec") {
            exec.get("command").and_then(Value::as_array).map(|cmd| {
                cmd.iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect()
            })
        } else if let Some(http) = probe.get("httpGet") {
            let Some(port) = resolve_probe_port(container, http.get("port")) else {
                return Ok(false);
            };
            let scheme = http
                .get("scheme")
                .and_then(Value::as_str)
                .unwrap_or("HTTP")
                .to_lowercase();
            let host = http
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("127.0.0.1");
            let host = if host.is_empty() { "127.0.0.1" } else { host };
            let raw_path = http.get("path").and_then(Value::as_str).unwrap_or("/");
            let path = if raw_path.starts_with('/') {
                raw_path.to_string()
            } else {
                format!("/{raw_path}")
            };
            let url = format!("{scheme}://{host}:{port}{path}");
            Some(vec![
                "curl".to_string(),
                "-fsk".to_string(),
                "-o".to_string(),
                "/dev/null".to_string(),
                url,
            ])
        } else if let Some(tcp) = probe.get("tcpSocket") {
            let Some(port) = resolve_probe_port(container, tcp.get("port")) else {
                return Ok(false);
            };
            let host = tcp
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("127.0.0.1");
            let host = if host.is_empty() { "127.0.0.1" } else { host };
            Some(vec![
                "nc".to_string(),
                "-z".to_string(),
                host.to_string(),
                port.to_string(),
            ])
        } else {
            None
        };
        let Some(command) = command else {
            return Ok(true);
        };
        let exec_probe = probe.get("exec").is_some();
        match self
            .runtime
            .exec_sync(container_id, &command, timeout_secs)
            .await
        {
            Ok(result) => Ok(result.exit_code == 0),
            Err(e) if exec_probe => Err(e),
            // HTTP and TCP probes are emulated through exec; treat execution failure as probe failure.
            Err(_) => Ok(false),
        }
    }

    async fn evaluate_single_probe(
        &self,
        container_id: &str,
        container: &Value,
        probe: &Value,
        probe_kind: &str,
        started_at_secs: u64,
        now: u64,
    ) -> Result<bool, KubeletError> {
        let failure_threshold = probe
            .get("failureThreshold")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(1);
        let initial_delay_secs = probe
            .get("initialDelaySeconds")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let period_secs = probe
            .get("periodSeconds")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        let key = format!("{container_id}:{probe_kind}");

        if started_at_secs > 0 && now < started_at_secs + initial_delay_secs {
            return Ok(probe_kind == "liveness");
        }

        {
            let trackers = self
                .probe_trackers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(tracker) = trackers.get(&key).filter(|tracker| {
                period_secs > 0
                    && tracker.last_run_secs > 0
                    && now < tracker.last_run_secs + period_secs
            }) {
                return Ok(tracker.consecutive_failures < failure_threshold);
            }
        }

        let success = self.evaluate_probe(container_id, container, probe).await?;

        let mut trackers = self
            .probe_trackers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tracker = trackers.entry(key).or_default();
        tracker.last_run_secs = now;
        if success {
            tracker.consecutive_failures = 0;
            Ok(true)
        } else {
            tracker.consecutive_failures += 1;
            Ok(tracker.consecutive_failures < failure_threshold)
        }
    }

    async fn evaluate_container_probes(
        &self,
        container_id: &str,
        container: &Value,
        started_at_secs: u64,
    ) -> Result<(bool, bool), KubeletError> {
        let now = now_unix();
        let mut liveness_ok = true;
        if let Some(liveness) = container.get("livenessProbe") {
            liveness_ok = self
                .evaluate_single_probe(
                    container_id,
                    container,
                    liveness,
                    "liveness",
                    started_at_secs,
                    now,
                )
                .await?;
        }
        let mut readiness_ok = true;
        if !liveness_ok {
            readiness_ok = false;
        } else if let Some(readiness) = container.get("readinessProbe") {
            readiness_ok = self
                .evaluate_single_probe(
                    container_id,
                    container,
                    readiness,
                    "readiness",
                    started_at_secs,
                    now,
                )
                .await?;
        }
        Ok((liveness_ok, readiness_ok))
    }

    async fn stage_projected_source(
        &self,
        vol_dir: &Path,
        namespace: &str,
        pod: &Value,
        source: &Value,
    ) -> Result<(), KubeletError> {
        if let Some(sa_tok) = source.get("serviceAccountToken") {
            stage_projected_sa_token(vol_dir, namespace, pod, sa_tok, self.apiserver.as_ref())?;
        }

        if let Some(cm) = source.get("configMap") {
            let cm_name = cm.get("name").and_then(Value::as_str).unwrap_or("");
            if let Ok(cm_obj) = self.client.get_configmap(namespace, cm_name).await {
                let _ = stage_configmap_files(vol_dir, cm, &cm_obj);
            }
        }

        if let Some(sec) = source.get("secret") {
            let sec_name = sec.get("name").and_then(Value::as_str).unwrap_or("");
            if let Ok(sec_obj) = self.client.get_secret(namespace, sec_name).await {
                let _ = stage_secret_files(vol_dir, sec, &sec_obj);
            }
        }

        if let Some(dw) = source.get("downwardAPI")
            && let Some(items) = dw.get("items").and_then(Value::as_array)
        {
            stage_projected_downward_api(vol_dir, namespace, pod, items)?;
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn prepare_single_volume(
        &self,
        namespace: &str,
        pod_name: &str,
        pod_uid: &str,
        pod: &Value,
        vol: &Value,
    ) -> Result<(), KubeletError> {
        let vol_name = vol.get("name").and_then(Value::as_str).unwrap_or("unnamed");

        if let Some(sec) = vol.get("secret") {
            let vol_dir = self.get_pod_volume_dir(pod_uid, "kubernetes.io~secret", vol_name);
            std::fs::create_dir_all(&vol_dir).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create volume directory {}: {e}",
                        vol_dir.display()
                    ),
                }
            })?;
            let sec_name = sec
                .get("secretName")
                .and_then(Value::as_str)
                .unwrap_or(vol_name);
            let sec_obj = self
                .client
                .get_secret(namespace, sec_name)
                .await
                .map_err(|e| KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!("failed to fetch secret '{sec_name}': {e}"),
                })?;
            stage_secret_files(&vol_dir, sec, &sec_obj)?;
        } else if let Some(cm) = vol.get("configMap") {
            let vol_dir = self.get_pod_volume_dir(pod_uid, "kubernetes.io~configmap", vol_name);
            std::fs::create_dir_all(&vol_dir).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create volume directory {}: {e}",
                        vol_dir.display()
                    ),
                }
            })?;
            let cm_name = cm.get("name").and_then(Value::as_str).unwrap_or(vol_name);
            let cm_obj = self
                .client
                .get_configmap(namespace, cm_name)
                .await
                .map_err(|e| KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!("failed to fetch configmap '{cm_name}': {e}"),
                })?;
            stage_configmap_files(&vol_dir, cm, &cm_obj)?;
        } else if let Some(proj) = vol.get("projected")
            && let Some(sources) = proj.get("sources").and_then(Value::as_array)
        {
            let vol_dir = self.get_pod_volume_dir(pod_uid, "kubernetes.io~projected", vol_name);
            std::fs::create_dir_all(&vol_dir).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create volume directory {}: {e}",
                        vol_dir.display()
                    ),
                }
            })?;
            for source in sources {
                self.stage_projected_source(&vol_dir, namespace, pod, source)
                    .await?;
            }
        } else if vol.get("emptyDir").is_some() {
            let vol_dir = self.get_pod_volume_dir(pod_uid, "kubernetes.io~empty-dir", vol_name);
            std::fs::create_dir_all(&vol_dir).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create volume directory {}: {e}",
                        vol_dir.display()
                    ),
                }
            })?;
        } else if let Some(pvc) = vol.get("persistentVolumeClaim") {
            let claim_name = pvc
                .get("claimName")
                .and_then(Value::as_str)
                .unwrap_or(vol_name);
            let claim_doc = self
                .client
                .get_pvc(namespace, claim_name)
                .await
                .map_err(|e| KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!("failed to fetch pvc '{claim_name}': {e}"),
                })?;
            let pv_name = claim_doc
                .pointer("/spec/volumeName")
                .and_then(Value::as_str)
                .ok_or_else(|| KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!("pvc '{claim_name}' is not yet bound to a volume"),
                })?;
            let volume_doc = self.client.get_pv(pv_name).await.map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!("failed to fetch pv '{pv_name}': {e}"),
                }
            })?;
            let host_path_str = volume_doc
                .pointer("/spec/local/path")
                .or_else(|| volume_doc.pointer("/spec/hostPath/path"))
                .and_then(Value::as_str)
                .ok_or_else(|| KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!("pv '{pv_name}' missing local.path or hostPath.path"),
                })?;

            let host_path = PathBuf::from(host_path_str);
            std::fs::create_dir_all(&host_path).map_err(|e| {
                KubeletError::PodReconciliationFailed {
                    pod: pod_name.to_string(),
                    reason: format!(
                        "failed to create persistent volume host directory {}: {e}",
                        host_path.display()
                    ),
                }
            })?;

            let vol_dir =
                self.get_pod_volume_dir(pod_uid, "kubernetes.io~persistent-volume-claim", vol_name);
            if let Some(parent) = vol_dir.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    KubeletError::PodReconciliationFailed {
                        pod: pod_name.to_string(),
                        reason: format!(
                            "failed to create volume parent directory {}: {e}",
                            parent.display()
                        ),
                    }
                })?;
            }
            if let Ok(meta) = std::fs::symlink_metadata(&vol_dir) {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    let _ = std::fs::remove_file(&vol_dir);
                } else {
                    let _ = std::fs::remove_dir_all(&vol_dir);
                }
            }
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&host_path, &vol_dir).map_err(|e| {
                    KubeletError::PodReconciliationFailed {
                        pod: pod_name.to_string(),
                        reason: format!("failed to symlink volume {}: {e}", vol_dir.display()),
                    }
                })?;
            }
            #[cfg(not(unix))]
            {
                let _ = &host_path;
                std::fs::create_dir_all(&vol_dir).map_err(|e| {
                    KubeletError::PodReconciliationFailed {
                        pod: pod_name.to_string(),
                        reason: format!(
                            "failed to create volume directory {}: {e}",
                            vol_dir.display()
                        ),
                    }
                })?;
            }
        } else if let Some(path_str) = vol
            .get("hostPath")
            .and_then(|hp| hp.get("path"))
            .and_then(Value::as_str)
        {
            let hp_type = vol
                .pointer("/hostPath/type")
                .and_then(Value::as_str)
                .unwrap_or("");
            if hp_type == "DirectoryOrCreate" {
                let _ = std::fs::create_dir_all(path_str);
            }
        }

        Ok(())
    }

    /// Prepares and populates volume mounts (Secrets, `ConfigMaps`, Projected) on the host filesystem.
    fn pod_with_service_account_volume(&self, pod: &Value) -> Value {
        if self.apiserver.is_none()
            || !automount_service_account_token(pod)
            || pod_has_service_account_token(pod)
        {
            return pod.clone();
        }
        let mut enriched = pod.clone();
        let Some(spec) = enriched.get_mut("spec").and_then(Value::as_object_mut) else {
            return enriched;
        };
        if let Some(volumes) = spec
            .entry("volumes".to_string())
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            volumes.push(json!({
                "name": SERVICE_ACCOUNT_VOLUME_NAME,
                "projected": {
                    "defaultMode": 420,
                    "sources": [{
                        "serviceAccountToken": {
                            "path": "token",
                            "audience": KUBERNETES_API_AUDIENCE,
                            "expirationSeconds": 7200
                        }
                    }]
                }
            }));
        }
        for key in ["containers", "initContainers"] {
            let Some(containers) = spec.get_mut(key).and_then(Value::as_array_mut) else {
                continue;
            };
            for container in containers {
                let Some(container) = container.as_object_mut() else {
                    continue;
                };
                if let Some(mounts) = container
                    .entry("volumeMounts".to_string())
                    .or_insert_with(|| json!([]))
                    .as_array_mut()
                {
                    mounts.push(json!({
                        "name": SERVICE_ACCOUNT_VOLUME_NAME,
                        "mountPath": SERVICE_ACCOUNT_MOUNT_PATH,
                        "readOnly": true
                    }));
                }
            }
        }
        enriched
    }

    pub async fn prepare_pod_volumes(
        &self,
        namespace: &str,
        pod: &Value,
    ) -> Result<(), KubeletError> {
        let name = pod
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let pod_uid = pod
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
            .unwrap_or(name);

        let Some(volumes) = pod
            .get("spec")
            .and_then(|s| s.get("volumes"))
            .and_then(Value::as_array)
        else {
            return Ok(());
        };

        for vol in volumes {
            self.prepare_single_volume(namespace, name, pod_uid, pod, vol)
                .await?;
        }

        Ok(())
    }
}

fn resolve_probe_port(container: &Value, port_val: Option<&Value>) -> Option<u16> {
    let port_val = port_val?;
    if let Some(port) = port_val.as_u64() {
        return u16::try_from(port).ok();
    }
    let port_str = port_val.as_str()?;
    if let Ok(port) = port_str.parse::<u16>() {
        return Some(port);
    }
    let ports = container.get("ports").and_then(Value::as_array)?;
    for p in ports {
        if p.get("name").and_then(Value::as_str) == Some(port_str) {
            return p
                .get("containerPort")
                .and_then(Value::as_u64)
                .and_then(|cp| u16::try_from(cp).ok());
        }
    }
    None
}

fn dead_container_views<'a>(
    pod: &'a Value,
    pointer: &str,
    grouped: &BTreeMap<&str, Vec<&'a cri::ContainerStatus>>,
) -> Vec<ContainerView<'a>> {
    let containers = pod
        .pointer(pointer)
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    containers
        .iter()
        .map(|container| {
            let c_name = container
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("main");
            let attempts = grouped.get(c_name).map_or(&[][..], Vec::as_slice);
            ContainerView {
                spec: container,
                latest: attempts.last().copied(),
                previous: None,
                ready: false,
                backoff: None,
                waiting: None,
                cpu: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(envs: &[cri::KeyValue], key: &str) -> Option<String> {
        envs.iter()
            .find(|env| env.key == key)
            .map(|env| String::from_utf8_lossy(&env.value).into_owned())
    }

    #[test]
    fn service_links_skip_empty_and_headless_cluster_ips() {
        let pod = json!({
            "metadata": { "name": "app", "namespace": "default" },
            "spec": { "containers": [{ "name": "main" }] }
        });
        let services = vec![
            json!({
                "metadata": { "name": "kubernetes", "namespace": "default" },
                "spec": {
                    "clusterIP": "10.43.0.1",
                    "ports": [{ "name": "https", "port": 443, "protocol": "TCP" }]
                }
            }),
            json!({
                "metadata": { "name": "blank", "namespace": "default" },
                "spec": {
                    "clusterIP": "",
                    "ports": [{ "name": "http", "port": 80, "protocol": "TCP" }]
                }
            }),
            json!({
                "metadata": { "name": "headless", "namespace": "default" },
                "spec": {
                    "clusterIP": "None",
                    "ports": [{ "name": "http", "port": 8080, "protocol": "TCP" }]
                }
            }),
            json!({
                "metadata": { "name": "web", "namespace": "default" },
                "spec": {
                    "clusterIP": "10.43.0.2",
                    "ports": [{ "name": "http", "port": 8080, "protocol": "TCP" }]
                }
            }),
        ];

        let disabled = json!({
            "metadata": { "name": "app", "namespace": "default" },
            "spec": { "enableServiceLinks": false, "containers": [{ "name": "main" }] }
        });
        let off = service_link_envs(&disabled, &services);
        assert_eq!(
            env_of(&off, "KUBERNETES_SERVICE_HOST").as_deref(),
            Some("10.43.0.1")
        );
        assert_eq!(
            env_of(&off, "KUBERNETES_SERVICE_PORT").as_deref(),
            Some("443")
        );
        assert_eq!(
            env_of(&off, "KUBERNETES_SERVICE_PORT_HTTPS").as_deref(),
            Some("443")
        );
        assert!(env_of(&off, "WEB_SERVICE_HOST").is_none());
        assert!(env_of(&off, "HEADLESS_SERVICE_HOST").is_none());
        assert!(env_of(&off, "BLANK_SERVICE_HOST").is_none());

        let on = service_link_envs(&pod, &services);
        assert_eq!(
            env_of(&on, "WEB_SERVICE_HOST").as_deref(),
            Some("10.43.0.2")
        );
        assert_eq!(env_of(&on, "WEB_SERVICE_PORT").as_deref(), Some("8080"));
        assert_eq!(
            env_of(&on, "WEB_PORT").as_deref(),
            Some("tcp://10.43.0.2:8080")
        );
        assert!(env_of(&on, "HEADLESS_SERVICE_HOST").is_none());
        assert!(env_of(&on, "BLANK_SERVICE_HOST").is_none());
    }

    #[test]
    fn test_build_dns_config_cluster_first_default() {
        let pod = json!({
            "metadata": {
                "name": "test-pod",
                "namespace": "production"
            },
            "spec": {
                "containers": [{ "name": "app", "image": "busybox" }]
            }
        });
        let dns = build_dns_config(&pod, &["10.43.0.10".to_string()], "cluster.local").unwrap();
        assert_eq!(dns.servers, vec!["10.43.0.10"]);
        assert_eq!(
            dns.searches,
            vec![
                "production.svc.cluster.local",
                "svc.cluster.local",
                "cluster.local"
            ]
        );
        assert_eq!(dns.options, vec!["ndots:5"]);
    }

    #[test]
    fn test_build_dns_config_with_custom_dns_config() {
        let pod = json!({
            "metadata": {
                "name": "test-pod",
                "namespace": "default"
            },
            "spec": {
                "dnsConfig": {
                    "nameservers": ["8.8.8.8"],
                    "searches": ["custom.domain"],
                    "options": [
                        { "name": "ndots", "value": "2" },
                        { "name": "single-request-reopen" }
                    ]
                }
            }
        });
        let dns = build_dns_config(&pod, &["10.43.0.10".to_string()], "cluster.local").unwrap();
        assert_eq!(dns.servers, vec!["10.43.0.10", "8.8.8.8"]);
        assert_eq!(
            dns.searches,
            vec![
                "default.svc.cluster.local",
                "svc.cluster.local",
                "cluster.local",
                "custom.domain"
            ]
        );
        assert_eq!(dns.options, vec!["ndots:2", "single-request-reopen"]);
    }

    #[test]
    fn test_build_dns_config_default_policy_without_custom_config() {
        let pod = json!({
            "metadata": {
                "name": "coredns-pod",
                "namespace": "kube-system"
            },
            "spec": {
                "dnsPolicy": "Default"
            }
        });
        let dns = build_dns_config(&pod, &["10.43.0.10".to_string()], "cluster.local");
        assert!(dns.is_none(), "Default dnsPolicy should inherit host DNS");
    }

    #[test]
    fn test_build_dns_config_none_policy() {
        let pod = json!({
            "metadata": {
                "name": "custom-pod",
                "namespace": "default"
            },
            "spec": {
                "dnsPolicy": "None",
                "dnsConfig": {
                    "nameservers": ["1.1.1.1"],
                    "searches": ["foo.bar"]
                }
            }
        });
        let dns = build_dns_config(&pod, &["10.43.0.10".to_string()], "cluster.local").unwrap();
        assert_eq!(dns.servers, vec!["1.1.1.1"]);
        assert_eq!(dns.searches, vec!["foo.bar"]);
        assert!(dns.options.is_empty());
    }

    #[test]
    fn test_sandbox_config_populates_dns_config() {
        let pod = json!({
            "metadata": {
                "name": "nginx",
                "namespace": "default"
            },
            "spec": {
                "containers": [{ "name": "nginx", "image": "nginx" }]
            }
        });
        let config = sandbox_config(&pod, 0);
        let dns = config.dns_config.expect("dns_config is populated");
        assert_eq!(dns.servers, vec!["10.43.0.10"]);
        assert_eq!(dns.searches[0], "default.svc.cluster.local");
    }
}
