//! Performance baseline data types, metrics schema and statistical summaries.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Target architecture for performance measurement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    Amd64,
    Arm64,
    ArmV7,
    Riscv64,
}

impl Architecture {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
            Self::ArmV7 => "armv7",
            Self::Riscv64 => "riscv64",
        }
    }

    pub const fn is_primary(self) -> bool {
        matches!(self, Self::Amd64 | Self::Arm64)
    }
}

/// Implementation language of the measured distribution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImplementationKind {
    Go,
    Rust,
}

impl ImplementationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Rust => "rust",
        }
    }
}

/// Declared hardware environment where measurements were captured.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HardwareInfo {
    pub machine_model: String,
    pub cpu_cores: usize,
    pub ram_bytes: u64,
    pub storage_type: String,
    pub kernel_version: String,
    pub cgroup_version: String,
    pub architecture: Architecture,
    pub os: String,
}

/// Pinned workload parameters for repeatable benchmark runs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkloadSpec {
    pub probe_image: String,
    pub probe_digest: String,
    pub probe_resource_cpu: String,
    pub probe_resource_memory: String,
    pub probe_interval_seconds: u32,
    pub density_node_memory_limit_bytes: u64,
    pub settle_duration_seconds: u32,
    pub sample_interval_seconds: u32,
    pub sample_duration_seconds: u32,
}

/// Authoritative component versions included in the measurement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComponentVersions {
    pub kubernetes: String,
    pub containerd: String,
    pub kine: String,
    pub crun: String,
    pub cni_plugins: String,
    pub coredns: String,
    pub pause: String,
    pub local_path_provisioner: String,
    pub distribution_revision: String,
    pub compiler_version: String,
}

/// Statistical summary of sample values with variance and nearest-rank percentiles.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct VarianceSummary {
    pub samples: Vec<f64>,
    pub count: usize,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub variance: f64,
    pub std_dev: f64,
    pub p50: f64,
    pub p90: f64,
    pub p95: f64,
}

impl VarianceSummary {
    /// Calculate statistical summary from raw samples.
    /// Uses nearest-rank method for p95 as required by the compatibility contract.
    pub fn from_samples(mut raw: Vec<f64>) -> Option<Self> {
        if raw.is_empty() || raw.iter().any(|value| !value.is_finite() || *value < 0.0) {
            return None;
        }

        raw.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let count = raw.len();
        let min = raw[0];
        let max = raw[count - 1];

        let sum: f64 = raw.iter().sum();
        let mean = sum / count as f64;

        let variance = if count > 1 {
            let sum_squared_diff: f64 = raw.iter().map(|x| (x - mean).powi(2)).sum();
            sum_squared_diff / (count - 1) as f64
        } else {
            0.0
        };
        let std_dev = variance.sqrt();
        if !mean.is_finite() || !variance.is_finite() || !std_dev.is_finite() {
            return None;
        }

        let p50 = Self::nearest_rank(&raw, 50.0);
        let p90 = Self::nearest_rank(&raw, 90.0);
        let p95 = Self::nearest_rank(&raw, 95.0);

        Some(Self {
            samples: raw,
            count,
            min,
            max,
            mean,
            variance,
            std_dev,
            p50,
            p90,
            p95,
        })
    }

    /// Nearest-rank percentile: rank = ceil((P / 100) * N), 1-indexed.
    pub fn nearest_rank(sorted: &[f64], percentile: f64) -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let n = sorted.len() as f64;
        let rank = ((percentile / 100.0) * n).ceil() as usize;
        let index = if rank == 0 {
            0
        } else if rank > sorted.len() {
            sorted.len() - 1
        } else {
            rank - 1
        };
        sorted[index]
    }
}

/// Breakdown of individual retained process memory consumption.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ProcessMemoryBreakdown {
    pub process_name: String,
    pub pid: Option<u32>,
    pub rss_bytes: u64,
    pub pss_bytes: u64,
    pub vmsize_bytes: u64,
}

/// Whole-distribution idle memory footprint.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct IdleFootprint {
    pub settle_minutes: u32,
    pub sampling_minutes: u32,
    pub sample_count: usize,
    pub retained_processes: Vec<ProcessMemoryBreakdown>,
    pub system_pods_memory_bytes: u64,
    pub summed_pss_bytes: VarianceSummary,
    pub cgroup_memory_bytes: VarianceSummary,
    pub memory_accounting_mode: String,
}

/// Startup latency measurements across fresh boots.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StartupLatencies {
    pub boot_to_api_seconds: VarianceSummary,
    pub node_ready_seconds: VarianceSummary,
    pub first_pod_preloaded_seconds: VarianceSummary,
    pub first_pod_cold_seconds: VarianceSummary,
}

/// Artifact footprint and distribution payload sizes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactFootprint {
    pub compressed_archive_bytes: u64,
    pub extracted_executable_bytes: u64,
    pub default_image_payload_bytes: u64,
    pub component_binary_sizes: BTreeMap<String, u64>,
    pub component_image_sizes: BTreeMap<String, u64>,
}

/// Pod density measurement results.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PodDensity {
    pub node_memory_limit_bytes: u64,
    pub max_ready_replicas: VarianceSummary,
    pub probe_success_rate: f64,
    pub hold_duration_seconds: u32,
}

/// 24-hour soak and sustained growth measurements.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SustainedGrowth {
    pub duration_hours: u32,
    pub initial_settled_idle_median_bytes: u64,
    pub final_settled_idle_median_bytes: u64,
    pub growth_ratio: f64,
    pub oom_kill_count: u32,
    pub crash_count: u32,
    pub unexplained_failures: u32,
}

/// Process cleanup and shutdown latency measurements.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ShutdownMeasurement {
    pub graceful_duration_seconds: VarianceSummary,
    pub escalation_duration_seconds: VarianceSummary,
    pub surviving_owned_processes: usize,
    pub unrelated_processes_killed: usize,
}

/// Complete performance report for one target architecture and implementation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PerformanceReport {
    pub schema_version: u32,
    #[serde(default)]
    pub evidence_kind: EvidenceKind,
    pub id: String,
    pub implementation: ImplementationKind,
    pub architecture: Architecture,
    pub timestamp: String,
    pub hardware: HardwareInfo,
    pub workload: WorkloadSpec,
    pub versions: ComponentVersions,
    pub startup_latencies: StartupLatencies,
    pub idle_footprint: IdleFootprint,
    pub artifact_footprint: ArtifactFootprint,
    pub pod_density: PodDensity,
    pub sustained_growth: SustainedGrowth,
    pub shutdown: ShutdownMeasurement,
}

/// This tooling has no verified live-capture importer yet. Neither variant qualifies C13.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    SyntheticFixture,
    #[default]
    UnverifiedCapture,
}
