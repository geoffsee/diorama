//! Built-in collectors for build info, uptime, datastore, certificates, and component health.

use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use super::registry::Collector;
use super::types::{MetricFamily, MetricType, Sample};

#[allow(clippy::cast_possible_wrap)]
fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Collector exposing build metadata. Always 1.0; details in labels.
#[derive(Clone, Debug)]
pub struct BuildInfoCollector {
    pub version: String,
    pub commit: String,
    pub rust_version: String,
    pub arch: String,
}

impl Default for BuildInfoCollector {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: option_env!("GIT_COMMIT").unwrap_or("unknown").to_string(),
            rust_version: option_env!("diorama_RUSTC_VERSION")
                .unwrap_or("unknown")
                .to_string(),
            arch: match std::env::consts::ARCH {
                "aarch64" => "arm64".to_string(),
                "x86_64" => "amd64".to_string(),
                other => other.to_string(),
            },
        }
    }
}

impl Collector for BuildInfoCollector {
    fn collect(&self) -> Vec<MetricFamily> {
        let sample = Sample {
            labels: vec![
                ("version".to_string(), self.version.clone()),
                ("commit".to_string(), self.commit.clone()),
                ("rust_version".to_string(), self.rust_version.clone()),
                ("arch".to_string(), self.arch.clone()),
            ],
            value: 1.0,
        };

        vec![MetricFamily::new(
            "diorama_build_info",
            "diorama build information. Always 1; metadata is in the labels.",
            MetricType::Gauge,
            vec![sample],
        )]
    }
}

/// Collector exposing metrics endpoint start time and process uptime in seconds.
#[derive(Clone, Debug)]
pub struct UptimeCollector {
    start_time_seconds: i64,
}

impl Default for UptimeCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl UptimeCollector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_time_seconds: current_unix_timestamp(),
        }
    }

    #[must_use]
    pub fn with_start_time(start_time_seconds: i64) -> Self {
        Self { start_time_seconds }
    }
}

impl Collector for UptimeCollector {
    #[allow(clippy::cast_precision_loss)]
    fn collect(&self) -> Vec<MetricFamily> {
        let now = current_unix_timestamp();
        let uptime = (now - self.start_time_seconds).max(0);

        vec![
            MetricFamily::new(
                "diorama_start_time_seconds",
                "Unix timestamp at which the diorama metrics endpoint started.",
                MetricType::Gauge,
                vec![Sample::without_labels(self.start_time_seconds as f64)],
            ),
            MetricFamily::new(
                "diorama_uptime_seconds",
                "Seconds elapsed since the diorama metrics endpoint started.",
                MetricType::Gauge,
                vec![Sample::without_labels(uptime as f64)],
            ),
        ]
    }
}

/// Collector exposing the managed datastore snapshot and WAL size in bytes.
#[derive(Clone, Debug)]
pub struct DatastoreCollector {
    paths: Vec<PathBuf>,
}

impl DatastoreCollector {
    #[must_use]
    pub fn new(db_path: impl Into<PathBuf>) -> Self {
        Self {
            paths: vec![db_path.into()],
        }
    }

    #[must_use]
    /// Measures both persisted files written by the managed datastore engine.
    pub fn with_wal(snapshot: PathBuf, wal: PathBuf) -> Self {
        Self {
            paths: vec![snapshot, wal],
        }
    }
}

impl Collector for DatastoreCollector {
    #[allow(clippy::cast_precision_loss)]
    fn collect(&self) -> Vec<MetricFamily> {
        let size = self
            .paths
            .iter()
            .map(|path| std::fs::metadata(path).map_or(0.0, |m| m.len() as f64))
            .sum();

        vec![MetricFamily::new(
            "diorama_kine_db_size_bytes",
            "Size in bytes of the managed datastore snapshot and WAL. Unreadable files contribute 0.",
            MetricType::Gauge,
            vec![Sample::without_labels(size)],
        )]
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod datastore_tests {
    use super::*;

    #[test]
    fn managed_snapshot_and_wal_are_summed_and_missing_files_contribute_zero() {
        let dir = tempfile::tempdir().unwrap();
        let config = diorama_datastore::DatastoreConfig::new(dir.path());
        std::fs::create_dir_all(config.wal_path().parent().unwrap()).unwrap();
        std::fs::write(config.snapshot_path(), [0; 7]).unwrap();
        std::fs::write(config.wal_path(), [0; 11]).unwrap();
        let collector = DatastoreCollector::with_wal(config.snapshot_path(), config.wal_path());
        assert!((collector.collect()[0].samples[0].value - 18.0).abs() < f64::EPSILON);
        std::fs::remove_file(config.snapshot_path()).unwrap();
        assert!((collector.collect()[0].samples[0].value - 11.0).abs() < f64::EPSILON);
    }
}

/// Tracked certificate descriptor pairing metric label name with its file path.
#[derive(Clone, Debug)]
struct TrackedCertificate {
    name: &'static str,
    path: PathBuf,
}

/// Collector reporting certificate validity and expiry timestamps.
#[derive(Clone, Debug)]
pub struct CertificateCollector {
    pki_dir: PathBuf,
    d2k_enabled: bool,
}

impl CertificateCollector {
    #[must_use]
    pub fn new(pki_dir: impl Into<PathBuf>, d2k_enabled: bool) -> Self {
        Self {
            pki_dir: pki_dir.into(),
            d2k_enabled,
        }
    }

    fn tracked_certificates(&self) -> Vec<TrackedCertificate> {
        let find_cert = |candidates: &[&str]| -> PathBuf {
            for cand in candidates {
                let p = self.pki_dir.join(cand);
                if p.exists() {
                    return p;
                }
            }
            self.pki_dir.join(candidates[0])
        };

        let mut certs = vec![
            TrackedCertificate {
                name: "ca",
                path: find_cert(&["ca.crt", "ca/ca.crt"]),
            },
            TrackedCertificate {
                name: "apiserver",
                path: find_cert(&[
                    "kube-apiserver.crt",
                    "apiserver.crt",
                    "apiserver/apiserver.crt",
                ]),
            },
            TrackedCertificate {
                name: "controller-manager",
                path: find_cert(&[
                    "kube-controller-manager.crt",
                    "controller-manager.crt",
                    "controller-manager/controller-manager.crt",
                ]),
            },
            TrackedCertificate {
                name: "kubelet",
                path: find_cert(&["kubelet.crt", "kubelet/kubelet.crt"]),
            },
            TrackedCertificate {
                name: "admin",
                path: find_cert(&["admin.crt", "admin/admin.crt"]),
            },
            TrackedCertificate {
                name: "webhook",
                path: find_cert(&["webhook.crt", "webhook/webhook.crt"]),
            },
            TrackedCertificate {
                name: "request-header-ca",
                path: find_cert(&["request-header-ca.crt"]),
            },
            TrackedCertificate {
                name: "request-header-client",
                path: find_cert(&["request-header-client.crt"]),
            },
        ];

        if self.d2k_enabled {
            certs.push(TrackedCertificate {
                name: "d2k-server",
                path: find_cert(&["d2k-server.crt"]),
            });
            certs.push(TrackedCertificate {
                name: "d2k-client",
                path: find_cert(&["d2k-client.crt"]),
            });
        }

        certs
    }
}

impl Collector for CertificateCollector {
    #[allow(clippy::cast_precision_loss)]
    fn collect(&self) -> Vec<MetricFamily> {
        let now = current_unix_timestamp();
        let tracked = self.tracked_certificates();

        let mut valid_samples = Vec::with_capacity(tracked.len());
        let mut expiry_samples = Vec::with_capacity(tracked.len());

        for item in tracked {
            match diorama_pki::inspect_certificate_file(&item.path) {
                Ok(validity) => {
                    let is_valid = if validity.is_valid_at(now) { 1.0 } else { 0.0 };
                    valid_samples.push(Sample {
                        labels: vec![("name".to_string(), item.name.to_string())],
                        value: is_valid,
                    });
                    expiry_samples.push(Sample {
                        labels: vec![("name".to_string(), item.name.to_string())],
                        value: validity.not_after_seconds as f64,
                    });
                },
                Err(_) => {
                    // Missing or unparseable certificate reports 0 for valid and omits expiry
                    valid_samples.push(Sample {
                        labels: vec![("name".to_string(), item.name.to_string())],
                        value: 0.0,
                    });
                },
            }
        }

        vec![
            MetricFamily::new(
                "diorama_certificate_valid",
                "1 if the named control plane certificate is readable and currently inside its validity window, 0 otherwise.",
                MetricType::Gauge,
                valid_samples,
            ),
            MetricFamily::new(
                "diorama_certificate_expiry_timestamp_seconds",
                "Unix timestamp at which the named control plane certificate expires. Absent if the certificate cannot be read or parsed.",
                MetricType::Gauge,
                expiry_samples,
            ),
        ]
    }
}

/// Status of an observed control plane component.
#[derive(Clone, Debug, PartialEq)]
pub struct ComponentStatus {
    pub up: bool,
    pub ready_timestamp: i64,
    pub last_probe_timestamp: i64,
}

/// Collector tracking control plane component health and readiness timestamps.
#[derive(Debug)]
pub struct ComponentHealthCollector {
    components: RwLock<std::collections::BTreeMap<String, ComponentStatus>>,
}

impl Default for ComponentHealthCollector {
    fn default() -> Self {
        let mut map = std::collections::BTreeMap::new();
        let canonical_components = [
            "apiserver",
            "controller",
            "coredns",
            "kine",
            "kubelet",
            "kubeproxy",
            "runtime",
            "webhook",
        ];
        for comp in canonical_components {
            map.insert(
                comp.to_string(),
                ComponentStatus {
                    up: false,
                    ready_timestamp: 0,
                    last_probe_timestamp: 0,
                },
            );
        }

        Self {
            components: RwLock::new(map),
        }
    }
}

impl ComponentHealthCollector {
    pub fn update_status(
        &self,
        component: &str,
        up: bool,
        ready_timestamp: Option<i64>,
        last_probe_timestamp: Option<i64>,
    ) {
        if let Ok(mut lock) = self.components.write() {
            let entry = lock
                .entry(component.to_string())
                .or_insert_with(|| ComponentStatus {
                    up: false,
                    ready_timestamp: 0,
                    last_probe_timestamp: 0,
                });
            entry.up = up;
            if let Some(rt) = ready_timestamp {
                entry.ready_timestamp = rt;
            }
            if let Some(pt) = last_probe_timestamp {
                entry.last_probe_timestamp = pt;
            }
        }
    }

    pub fn mark_ready(&self, component: &str) {
        let now = current_unix_timestamp();
        self.update_status(component, true, Some(now), Some(now));
    }
}

impl Collector for ComponentHealthCollector {
    #[allow(clippy::cast_precision_loss)]
    fn collect(&self) -> Vec<MetricFamily> {
        let Ok(lock) = self.components.read() else {
            return Vec::new();
        };

        let mut up_samples = Vec::new();
        let mut ready_samples = Vec::new();
        let mut probe_samples = Vec::new();

        for (comp, status) in lock.iter() {
            let label = vec![("component".to_string(), comp.clone())];
            up_samples.push(Sample {
                labels: label.clone(),
                value: if status.up { 1.0 } else { 0.0 },
            });
            ready_samples.push(Sample {
                labels: label.clone(),
                value: status.ready_timestamp as f64,
            });
            probe_samples.push(Sample {
                labels: label,
                value: status.last_probe_timestamp as f64,
            });
        }

        vec![
            MetricFamily::new(
                "diorama_component_up",
                "1 if the named control plane component is reachable and healthy, 0 otherwise.",
                MetricType::Gauge,
                up_samples,
            ),
            MetricFamily::new(
                "diorama_component_ready_timestamp_seconds",
                "Unix timestamp at which the named component first signaled readiness. 0 until ready.",
                MetricType::Gauge,
                ready_samples,
            ),
            MetricFamily::new(
                "diorama_component_last_probe_timestamp_seconds",
                "Unix timestamp of the most recent diorama health probe for the named component.",
                MetricType::Gauge,
                probe_samples,
            ),
        ]
    }
}
