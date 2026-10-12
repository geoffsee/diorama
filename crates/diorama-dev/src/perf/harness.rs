use super::contract::{ContractThresholds, GateEvaluationReport};
use super::metrics::{
    Architecture, ArtifactFootprint, ComponentVersions, HardwareInfo, IdleFootprint,
    ImplementationKind, PerformanceReport, PodDensity, ProcessMemoryBreakdown, ShutdownMeasurement,
    StartupLatencies, SustainedGrowth, VarianceSummary, WorkloadSpec,
};
use super::secondary::SecondaryTargetsRegistry;
use crate::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Required retained processes that must be accounted for in whole-node measurements.
pub const REQUIRED_RETAINED_PROCESSES: [&str; 8] = [
    "apiserver",
    "controller-manager",
    "kubelet",
    "proxy",
    "kine",
    "containerd",
    "containerd-shim",
    "node-daemon", // diorama-kube or kubesolo
];

/// Execution sequencing to eliminate environmental and thermal bias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunOrder {
    ReferenceFirst,
    CandidateFirst,
}

impl RunOrder {
    pub const fn for_iteration(iteration: usize) -> Self {
        if iteration.is_multiple_of(2) {
            Self::ReferenceFirst
        } else {
            Self::CandidateFirst
        }
    }
}

/// Parse `VmRSS` from `/proc/[pid]/status` content if running on Linux.
pub fn parse_vm_rss_bytes(status_content: &str) -> Option<u64> {
    for line in status_content.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if let Some(kb_str) = parts.first()
                && let Ok(kb) = kb_str.parse::<u64>()
            {
                return kb.checked_mul(1024);
            }
        }
    }
    None
}

/// Parse PSS from `/proc/[pid]/smaps_rollup` content if running on Linux.
pub fn parse_pss_bytes(smaps_rollup_content: &str) -> Option<u64> {
    for line in smaps_rollup_content.lines() {
        if let Some(rest) = line.strip_prefix("Pss:") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if let Some(kb_str) = parts.first()
                && let Ok(kb) = kb_str.parse::<u64>()
            {
                return kb.checked_mul(1024);
            }
        }
    }
    None
}

/// Measure artifact footprint from a release archive file and extraction directory.
pub fn measure_artifact_footprint(
    archive_path: &Path,
    extracted_dir: &Path,
    image_payload_bytes: u64,
) -> Result<ArtifactFootprint> {
    let archive_meta = std::fs::metadata(archive_path)?;
    let compressed_archive_bytes = archive_meta.len();

    let mut extracted_executable_bytes = 0u64;
    let mut component_binary_sizes = BTreeMap::new();

    if extracted_dir.is_dir() {
        for entry in std::fs::read_dir(extracted_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let size = entry.metadata()?.len();
                extracted_executable_bytes = extracted_executable_bytes.saturating_add(size);
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    component_binary_sizes.insert(file_name.to_string(), size);
                }
            }
        }
    }

    Ok(ArtifactFootprint {
        compressed_archive_bytes,
        extracted_executable_bytes,
        default_image_payload_bytes: image_payload_bytes,
        component_binary_sizes,
        component_image_sizes: BTreeMap::new(),
    })
}

/// Verify that a performance report accounts for all required retained processes.
pub fn verify_retained_process_coverage(report: &PerformanceReport) -> Result<()> {
    let reported_names: BTreeSet<String> = report
        .idle_footprint
        .retained_processes
        .iter()
        .filter_map(|p| process_role(&p.process_name).map(str::to_owned))
        .collect();

    for required in REQUIRED_RETAINED_PROCESSES {
        let matched = reported_names.contains(required);
        if !matched {
            return Err(format!(
                "Report {} is missing required retained process accounting for '{required}'. All retained processes must be measured.",
                report.id
            )
            .into());
        }
    }

    Ok(())
}

/// Approved process aliases are disjoint: a runtime shim cannot represent its daemon.
pub fn process_role(name: &str) -> Option<&'static str> {
    match name {
        "kube-apiserver" | "apiserver" => Some("apiserver"),
        "kube-controller-manager" | "controller-manager" => Some("controller-manager"),
        "kubelet" => Some("kubelet"),
        "kube-proxy" | "proxy" => Some("proxy"),
        "kine" => Some("kine"),
        "containerd" => Some("containerd"),
        "containerd-shim-runc-v2" | "containerd-shim" => Some("containerd-shim"),
        "kubesolo" | "diorama-kube" | "kubesolo-node-daemon" | "diorama-kube-node-daemon" => {
            Some("node-daemon")
        },
        _ => None,
    }
}

/// Calculate aggregated PSS and RSS sums from a list of process memory breakdowns.
pub fn sum_process_memory(processes: &[ProcessMemoryBreakdown]) -> (u64, u64) {
    let mut total_pss = 0u64;
    let mut total_rss = 0u64;
    for p in processes {
        total_pss = total_pss.saturating_add(p.pss_bytes);
        total_rss = total_rss.saturating_add(p.rss_bytes);
    }
    (total_pss, total_rss)
}

/// Synthesize a statistical summary for test fixtures or simulation runs.
pub fn synthesize_summary(samples: &[f64]) -> Result<VarianceSummary> {
    VarianceSummary::from_samples(samples.to_vec())
        .ok_or_else(|| "cannot synthesize summary from empty sample list".into())
}

/// Construct a synthetic reference fixture report for a given architecture.
pub fn build_reference_fixture(arch: Architecture) -> PerformanceReport {
    let (
        machine_model,
        kernel,
        os,
        boot_samples,
        node_samples,
        first_pre_samples,
        first_cold_samples,
    ) = match arch {
        Architecture::Amd64 => (
            "c3-standard-8 (Intel Xeon Sapphire Rapids)",
            "Linux 6.8.0-45-generic",
            "Ubuntu 24.04 LTS (Noble Numbat)",
            vec![
                10.8, 11.2, 11.5, 11.8, 12.0, 12.1, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8, 13.0, 13.1,
                13.2, 13.4, 13.6, 13.8, 14.05, 14.2,
            ],
            vec![
                15.2, 15.6, 16.0, 16.2, 16.5, 16.8, 17.0, 17.1, 17.3, 17.5, 17.7, 17.9, 18.2, 18.5,
                18.8, 19.0, 19.2, 19.5, 19.82, 20.1,
            ],
            vec![
                18.5, 19.0, 19.4, 19.8, 20.1, 20.4, 20.7, 21.0, 21.2, 21.5, 21.7, 22.0, 22.3, 22.6,
                22.9, 23.1, 23.3, 23.6, 23.85, 24.2,
            ],
            vec![
                28.5, 29.0, 29.5, 30.0, 30.4, 30.8, 31.2, 31.6, 32.0, 32.4, 32.8, 33.2, 33.6, 34.0,
                34.4, 34.8, 35.1, 35.4, 35.75, 36.2,
            ],
        ),
        Architecture::Arm64 | Architecture::ArmV7 | Architecture::Riscv64 => (
            "c7g.2xlarge (AWS Graviton3 / Neoverse-V1)",
            "Linux 6.8.0-1015-aws",
            "Ubuntu 24.04 LTS (Noble Numbat)",
            vec![
                10.2, 10.6, 10.9, 11.2, 11.4, 11.6, 11.8, 12.0, 12.1, 12.3, 12.5, 12.6, 12.8, 13.0,
                13.1, 13.3, 13.4, 13.5, 13.62, 13.8,
            ],
            vec![
                14.8, 15.1, 15.4, 15.8, 16.1, 16.3, 16.6, 16.9, 17.1, 17.3, 17.5, 17.8, 18.0, 18.2,
                18.5, 18.7, 18.9, 19.0, 19.15, 19.4,
            ],
            vec![
                17.9, 18.3, 18.7, 19.1, 19.4, 19.7, 20.0, 20.3, 20.6, 20.8, 21.1, 21.4, 21.7, 22.0,
                22.2, 22.5, 22.7, 22.9, 23.10, 23.4,
            ],
            vec![
                27.2, 27.8, 28.3, 28.9, 29.3, 29.8, 30.2, 30.7, 31.1, 31.5, 32.0, 32.4, 32.8, 33.2,
                33.6, 33.9, 34.1, 34.3, 34.45, 34.9,
            ],
        ),
    };

    let pss_samples = vec![
        555_000_000.0,
        560_000_000.0,
        566_231_040.0,
        572_000_000.0,
        578_813_952.0,
    ];
    let cg_samples = vec![
        608_000_000.0,
        612_000_000.0,
        618_659_840.0,
        624_000_000.0,
        629_145_600.0,
    ];
    let density_samples = vec![110.0, 110.0, 108.0, 110.0, 109.0];
    let shutdown_samples = vec![
        6.5, 6.8, 7.1, 7.4, 7.6, 7.8, 8.0, 8.2, 8.3, 8.5, 8.7, 8.9, 9.1, 9.4, 9.6, 9.9, 10.2, 10.5,
        11.2, 12.0,
    ];

    let mut component_binaries = BTreeMap::new();
    component_binaries.insert("kube-apiserver".to_string(), 125_829_120);
    component_binaries.insert("kube-controller-manager".to_string(), 115_343_360);
    component_binaries.insert("kubelet".to_string(), 110_100_480);
    component_binaries.insert("kube-proxy".to_string(), 47_185_920);
    component_binaries.insert("kine".to_string(), 31_457_280);
    component_binaries.insert("containerd".to_string(), 52_428_800);
    component_binaries.insert("containerd-shim-runc-v2".to_string(), 10_485_760);
    component_binaries.insert("crun".to_string(), 3_145_728);
    component_binaries.insert("kubesolo".to_string(), 44_040_192);

    let mut component_images = BTreeMap::new();
    component_images.insert("docker.io/coredns/coredns:1.14.4".to_string(), 62_914_560);
    component_images.insert("docker.io/portainer/pause:latest".to_string(), 734_003);
    component_images.insert(
        "docker.io/rancher/local-path-provisioner:v0.0.31".to_string(),
        52_428_800,
    );
    component_images.insert("docker.io/library/busybox:1.37.0".to_string(), 4_194_304);
    component_images.insert("docker.io/portainer/agent:2.33.6".to_string(), 41_943_040);
    component_images.insert("docker.io/portainer/d2k:v0.1.3".to_string(), 31_771_853);

    PerformanceReport {
        schema_version: 1,
        evidence_kind: super::metrics::EvidenceKind::SyntheticFixture,
        id: format!("{}-reference-go", arch.as_str()),
        implementation: ImplementationKind::Go,
        architecture: arch,
        timestamp: "2026-10-03T12:00:00Z".to_string(),
        hardware: HardwareInfo {
            machine_model: machine_model.to_string(),
            cpu_cores: 8,
            ram_bytes: 17_179_869_184,
            storage_type: "NVMe SSD".to_string(),
            kernel_version: kernel.to_string(),
            cgroup_version: "cgroups-v2".to_string(),
            architecture: arch,
            os: os.to_string(),
        },
        workload: WorkloadSpec {
            probe_image: "docker.io/library/busybox:1.37.0".to_string(),
            probe_digest: "sha256:a5d4330f7bb1749544fb4f62a5f0859baceddd6a401d4fb8865e9b44f0b29803"
                .to_string(),
            probe_resource_cpu: "10m".to_string(),
            probe_resource_memory: "16Mi".to_string(),
            probe_interval_seconds: 5,
            density_node_memory_limit_bytes: 4_294_967_296,
            settle_duration_seconds: 600,
            sample_interval_seconds: 1,
            sample_duration_seconds: 900,
        },
        versions: ComponentVersions {
            kubernetes: "v1.35.7".to_string(),
            containerd: "v2.2.5".to_string(),
            kine: "v0.16.3".to_string(),
            crun: "1.26".to_string(),
            cni_plugins: "v1.9.0".to_string(),
            coredns: "1.14.4".to_string(),
            pause: "3.10".to_string(),
            local_path_provisioner: "v0.0.31".to_string(),
            distribution_revision: "2ef1c4787989f11f868f81bb84ae2afd4a49a81d".to_string(),
            compiler_version: "go1.26.5".to_string(),
        },
        startup_latencies: StartupLatencies {
            boot_to_api_seconds: VarianceSummary::from_samples(boot_samples).unwrap(),
            node_ready_seconds: VarianceSummary::from_samples(node_samples).unwrap(),
            first_pod_preloaded_seconds: VarianceSummary::from_samples(first_pre_samples).unwrap(),
            first_pod_cold_seconds: VarianceSummary::from_samples(first_cold_samples).unwrap(),
        },
        idle_footprint: IdleFootprint {
            settle_minutes: 10,
            sampling_minutes: 15,
            sample_count: 900,
            retained_processes: vec![
                ProcessMemoryBreakdown {
                    process_name: "kube-apiserver".to_string(),
                    pid: Some(101),
                    rss_bytes: 228_589_568,
                    pss_bytes: 218_103_808,
                    vmsize_bytes: 1_258_291_200,
                },
                ProcessMemoryBreakdown {
                    process_name: "kube-controller-manager".to_string(),
                    pid: Some(102),
                    rss_bytes: 89_128_960,
                    pss_bytes: 82_837_504,
                    vmsize_bytes: 805_306_368,
                },
                ProcessMemoryBreakdown {
                    process_name: "kubelet".to_string(),
                    pid: Some(103),
                    rss_bytes: 80_740_352,
                    pss_bytes: 74_448_896,
                    vmsize_bytes: 939_524_096,
                },
                ProcessMemoryBreakdown {
                    process_name: "kube-proxy".to_string(),
                    pid: Some(104),
                    rss_bytes: 31_457_280,
                    pss_bytes: 27_262_976,
                    vmsize_bytes: 754_974_720,
                },
                ProcessMemoryBreakdown {
                    process_name: "kine".to_string(),
                    pid: Some(105),
                    rss_bytes: 35_651_584,
                    pss_bytes: 31_457_280,
                    vmsize_bytes: 738_197_504,
                },
                ProcessMemoryBreakdown {
                    process_name: "containerd".to_string(),
                    pid: Some(106),
                    rss_bytes: 48_234_496,
                    pss_bytes: 41_943_040,
                    vmsize_bytes: 872_415_232,
                },
                ProcessMemoryBreakdown {
                    process_name: "containerd-shim-runc-v2".to_string(),
                    pid: Some(107),
                    rss_bytes: 14_680_064,
                    pss_bytes: 12_582_912,
                    vmsize_bytes: 721_420_288,
                },
                ProcessMemoryBreakdown {
                    process_name: "kubesolo-node-daemon".to_string(),
                    pid: Some(100),
                    rss_bytes: 49_283_072,
                    pss_bytes: 44_040_192,
                    vmsize_bytes: 771_751_936,
                },
            ],
            system_pods_memory_bytes: 33_554_432,
            summed_pss_bytes: VarianceSummary::from_samples(pss_samples).unwrap(),
            cgroup_memory_bytes: VarianceSummary::from_samples(cg_samples).unwrap(),
            memory_accounting_mode: "PSS with RSS fallback labeled; cgroup v2 verified".to_string(),
        },
        artifact_footprint: ArtifactFootprint {
            compressed_archive_bytes: 173_015_040,
            extracted_executable_bytes: 281_018_368,
            default_image_payload_bytes: 193_986_560,
            component_binary_sizes: component_binaries,
            component_image_sizes: component_images,
        },
        pod_density: PodDensity {
            node_memory_limit_bytes: 4_294_967_296,
            max_ready_replicas: VarianceSummary::from_samples(density_samples).unwrap(),
            probe_success_rate: 1.0,
            hold_duration_seconds: 600,
        },
        sustained_growth: SustainedGrowth {
            duration_hours: 24,
            initial_settled_idle_median_bytes: 566_231_040,
            final_settled_idle_median_bytes: 580_386_816,
            growth_ratio: 1.025,
            oom_kill_count: 0,
            crash_count: 0,
            unexplained_failures: 0,
        },
        shutdown: ShutdownMeasurement {
            graceful_duration_seconds: VarianceSummary::from_samples(shutdown_samples).unwrap(),
            escalation_duration_seconds: VarianceSummary::from_samples(vec![0.0; 20]).unwrap(),
            surviving_owned_processes: 0,
            unrelated_processes_killed: 0,
        },
    }
}

/// Construct a synthetic candidate fixture report for a given architecture.
pub fn build_candidate_fixture(arch: Architecture) -> PerformanceReport {
    let (
        machine_model,
        kernel,
        os,
        boot_samples,
        node_samples,
        first_pre_samples,
        first_cold_samples,
    ) = match arch {
        Architecture::Amd64 => (
            "c3-standard-8 (Intel Xeon Sapphire Rapids)",
            "Linux 6.8.0-45-generic",
            "Ubuntu 24.04 LTS (Noble Numbat)",
            vec![
                8.2, 8.4, 8.6, 8.8, 8.9, 9.1, 9.2, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 10.0, 10.1, 10.2,
                10.3, 10.35, 10.42, 10.5,
            ],
            vec![
                12.5, 12.8, 13.0, 13.2, 13.5, 13.7, 13.9, 14.1, 14.3, 14.5, 14.7, 14.9, 15.0, 15.1,
                15.2, 15.3, 15.4, 15.5, 15.65, 15.8,
            ],
            vec![
                15.2, 15.5, 15.8, 16.0, 16.3, 16.5, 16.7, 17.0, 17.2, 17.4, 17.6, 17.8, 18.0, 18.1,
                18.3, 18.4, 18.5, 18.7, 18.85, 19.0,
            ],
            vec![
                24.0, 24.5, 24.9, 25.3, 25.7, 26.0, 26.4, 26.8, 27.1, 27.4, 27.8, 28.1, 28.3, 28.5,
                28.7, 28.8, 28.9, 29.0, 29.15, 29.5,
            ],
        ),
        Architecture::Arm64 | Architecture::ArmV7 | Architecture::Riscv64 => (
            "c7g.2xlarge (AWS Graviton3 / Neoverse-V1)",
            "Linux 6.8.0-1015-aws",
            "Ubuntu 24.04 LTS (Noble Numbat)",
            vec![
                7.9, 8.1, 8.3, 8.5, 8.7, 8.8, 9.0, 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9,
                10.0, 10.05, 10.12, 10.2,
            ],
            vec![
                12.0, 12.3, 12.5, 12.8, 13.0, 13.2, 13.4, 13.6, 13.8, 14.0, 14.2, 14.4, 14.5, 14.6,
                14.7, 14.8, 14.9, 15.0, 15.05, 15.2,
            ],
            vec![
                14.5, 14.8, 15.1, 15.4, 15.7, 16.0, 16.2, 16.5, 16.7, 16.9, 17.1, 17.3, 17.5, 17.7,
                17.8, 17.9, 18.0, 18.1, 18.25, 18.4,
            ],
            vec![
                23.2, 23.7, 24.1, 24.6, 25.0, 25.4, 25.8, 26.1, 26.5, 26.8, 27.1, 27.3, 27.5, 27.7,
                27.8, 27.9, 28.0, 28.1, 28.25, 28.6,
            ],
        ),
    };

    let pss_samples = vec![
        460_000_000.0,
        465_000_000.0,
        471_859_200.0,
        478_000_000.0,
        484_000_000.0,
    ];
    let cg_samples = vec![
        505_000_000.0,
        512_000_000.0,
        519_045_120.0,
        526_000_000.0,
        532_000_000.0,
    ];
    let density_samples = vec![110.0, 110.0, 110.0, 109.0, 110.0];
    let shutdown_samples = vec![
        3.2, 3.4, 3.6, 3.8, 3.9, 4.0, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 5.0, 5.1, 5.2,
        5.4, 5.6,
    ];

    let mut component_binaries = BTreeMap::new();
    component_binaries.insert("kube-apiserver".to_string(), 125_829_120);
    component_binaries.insert("kube-controller-manager".to_string(), 115_343_360);
    component_binaries.insert("kubelet".to_string(), 110_100_480);
    component_binaries.insert("kube-proxy".to_string(), 47_185_920);
    component_binaries.insert("kine".to_string(), 31_457_280);
    component_binaries.insert("containerd".to_string(), 52_428_800);
    component_binaries.insert("containerd-shim-runc-v2".to_string(), 10_485_760);
    component_binaries.insert("crun".to_string(), 3_145_728);
    component_binaries.insert("diorama-kube".to_string(), 19_922_944);

    let mut component_images = BTreeMap::new();
    component_images.insert("docker.io/coredns/coredns:1.14.4".to_string(), 62_914_560);
    component_images.insert("docker.io/portainer/pause:latest".to_string(), 734_003);
    component_images.insert(
        "docker.io/rancher/local-path-provisioner:v0.0.31".to_string(),
        52_428_800,
    );
    component_images.insert("docker.io/library/busybox:1.37.0".to_string(), 4_194_304);
    component_images.insert("docker.io/portainer/agent:2.33.6".to_string(), 41_943_040);
    component_images.insert("docker.io/portainer/d2k:v0.1.3".to_string(), 31_771_853);

    PerformanceReport {
        schema_version: 1,
        evidence_kind: super::metrics::EvidenceKind::SyntheticFixture,
        id: format!("{}-candidate-rust", arch.as_str()),
        implementation: ImplementationKind::Rust,
        architecture: arch,
        timestamp: "2026-10-03T14:30:00Z".to_string(),
        hardware: HardwareInfo {
            machine_model: machine_model.to_string(),
            cpu_cores: 8,
            ram_bytes: 17_179_869_184,
            storage_type: "NVMe SSD".to_string(),
            kernel_version: kernel.to_string(),
            cgroup_version: "cgroups-v2".to_string(),
            architecture: arch,
            os: os.to_string(),
        },
        workload: WorkloadSpec {
            probe_image: "docker.io/library/busybox:1.37.0".to_string(),
            probe_digest: "sha256:a5d4330f7bb1749544fb4f62a5f0859baceddd6a401d4fb8865e9b44f0b29803"
                .to_string(),
            probe_resource_cpu: "10m".to_string(),
            probe_resource_memory: "16Mi".to_string(),
            probe_interval_seconds: 5,
            density_node_memory_limit_bytes: 4_294_967_296,
            settle_duration_seconds: 600,
            sample_interval_seconds: 1,
            sample_duration_seconds: 900,
        },
        versions: ComponentVersions {
            kubernetes: "v1.35.7".to_string(),
            containerd: "v2.2.5".to_string(),
            kine: "v0.16.3".to_string(),
            crun: "1.26".to_string(),
            cni_plugins: "v1.9.0".to_string(),
            coredns: "1.14.4".to_string(),
            pause: "3.10".to_string(),
            local_path_provisioner: "v0.0.31".to_string(),
            distribution_revision: "HEAD".to_string(),
            compiler_version: "rustc 1.97.1".to_string(),
        },
        startup_latencies: StartupLatencies {
            boot_to_api_seconds: VarianceSummary::from_samples(boot_samples).unwrap(),
            node_ready_seconds: VarianceSummary::from_samples(node_samples).unwrap(),
            first_pod_preloaded_seconds: VarianceSummary::from_samples(first_pre_samples).unwrap(),
            first_pod_cold_seconds: VarianceSummary::from_samples(first_cold_samples).unwrap(),
        },
        idle_footprint: IdleFootprint {
            settle_minutes: 10,
            sampling_minutes: 15,
            sample_count: 900,
            retained_processes: vec![
                ProcessMemoryBreakdown {
                    process_name: "kube-apiserver".to_string(),
                    pid: Some(201),
                    rss_bytes: 228_589_568,
                    pss_bytes: 218_103_808,
                    vmsize_bytes: 1_258_291_200,
                },
                ProcessMemoryBreakdown {
                    process_name: "kube-controller-manager".to_string(),
                    pid: Some(202),
                    rss_bytes: 89_128_960,
                    pss_bytes: 82_837_504,
                    vmsize_bytes: 805_306_368,
                },
                ProcessMemoryBreakdown {
                    process_name: "kubelet".to_string(),
                    pid: Some(203),
                    rss_bytes: 80_740_352,
                    pss_bytes: 74_448_896,
                    vmsize_bytes: 939_524_096,
                },
                ProcessMemoryBreakdown {
                    process_name: "kube-proxy".to_string(),
                    pid: Some(204),
                    rss_bytes: 31_457_280,
                    pss_bytes: 27_262_976,
                    vmsize_bytes: 754_974_720,
                },
                ProcessMemoryBreakdown {
                    process_name: "kine".to_string(),
                    pid: Some(205),
                    rss_bytes: 35_651_584,
                    pss_bytes: 31_457_280,
                    vmsize_bytes: 738_197_504,
                },
                ProcessMemoryBreakdown {
                    process_name: "containerd".to_string(),
                    pid: Some(206),
                    rss_bytes: 48_234_496,
                    pss_bytes: 41_943_040,
                    vmsize_bytes: 872_415_232,
                },
                ProcessMemoryBreakdown {
                    process_name: "containerd-shim-runc-v2".to_string(),
                    pid: Some(207),
                    rss_bytes: 14_680_064,
                    pss_bytes: 12_582_912,
                    vmsize_bytes: 721_420_288,
                },
                ProcessMemoryBreakdown {
                    process_name: "diorama-kube-node-daemon".to_string(),
                    pid: Some(200),
                    rss_bytes: 22_020_096,
                    pss_bytes: 18_874_368,
                    vmsize_bytes: 419_430_400,
                },
            ],
            system_pods_memory_bytes: 33_554_432,
            summed_pss_bytes: VarianceSummary::from_samples(pss_samples).unwrap(),
            cgroup_memory_bytes: VarianceSummary::from_samples(cg_samples).unwrap(),
            memory_accounting_mode: "PSS with RSS fallback labeled; cgroup v2 verified".to_string(),
        },
        artifact_footprint: ArtifactFootprint {
            compressed_archive_bytes: 155_189_248,
            extracted_executable_bytes: 256_901_120,
            default_image_payload_bytes: 193_986_560,
            component_binary_sizes: component_binaries,
            component_image_sizes: component_images,
        },
        pod_density: PodDensity {
            node_memory_limit_bytes: 4_294_967_296,
            max_ready_replicas: VarianceSummary::from_samples(density_samples).unwrap(),
            probe_success_rate: 1.0,
            hold_duration_seconds: 600,
        },
        sustained_growth: SustainedGrowth {
            duration_hours: 24,
            initial_settled_idle_median_bytes: 471_859_200,
            final_settled_idle_median_bytes: 479_199_232,
            growth_ratio: 1.016,
            oom_kill_count: 0,
            crash_count: 0,
            unexplained_failures: 0,
        },
        shutdown: ShutdownMeasurement {
            graceful_duration_seconds: VarianceSummary::from_samples(shutdown_samples).unwrap(),
            escalation_duration_seconds: VarianceSummary::from_samples(vec![0.0; 20]).unwrap(),
            surviving_owned_processes: 0,
            unrelated_processes_killed: 0,
        },
    }
}

/// An individual workload/idle cycle during sustained soak testing.
#[derive(Clone, Debug, serde::Deserialize, PartialEq, serde::Serialize)]
pub struct WorkloadIdleCycle {
    pub cycle_index: u32,
    pub workload_active_seconds: u32,
    pub idle_settle_seconds: u32,
    pub peak_workload_pss_bytes: u64,
    pub settled_idle_pss_bytes: u64,
    pub settled_cgroup_bytes: u64,
    pub oom_events: u32,
    pub crash_events: u32,
    pub failed_probes: u32,
    pub process_breakdown: Vec<ProcessMemoryBreakdown>,
}

/// Analysis summary of repeated workload/idle cycles across the full distribution.
#[derive(Clone, Debug, serde::Deserialize, PartialEq, serde::Serialize)]
pub struct SustainedCycleAnalysis {
    pub total_cycles: usize,
    pub duration_hours: u32,
    pub initial_settled_pss: u64,
    pub final_settled_pss: u64,
    pub growth_ratio: f64,
    pub max_cycle_growth_ratio: f64,
    /// Conservative fixture-analysis signal: aggregate and each retained role grow at most 10%.
    /// This is stricter than the whole-distribution contract gate and never qualifies live runs.
    pub is_bounded: bool,
    pub oom_total: u32,
    pub crash_total: u32,
    pub failed_probes_total: u32,
    pub process_growth_ratios: BTreeMap<String, f64>,
}

/// Validate a series of workload/idle cycles during a soak run across the full distribution.
pub fn analyze_workload_idle_cycles(
    cycles: &[WorkloadIdleCycle],
) -> Result<SustainedCycleAnalysis> {
    if cycles.is_empty() {
        return Err("soak run contains zero workload/idle cycles".into());
    }
    if cycles.len() < 2 {
        return Err("soak run requires at least 2 cycles to measure sustained growth".into());
    }

    let initial = &cycles[0];
    let final_cycle = &cycles[cycles.len() - 1];

    if initial.settled_idle_pss_bytes == 0 || final_cycle.settled_idle_pss_bytes == 0 {
        return Err("idle settled PSS must be strictly positive in all cycles".into());
    }

    let mut oom_total = 0u32;
    let mut crash_total = 0u32;
    let mut failed_probes_total = 0u32;
    let mut max_cycle_growth_ratio = 1.0f64;

    let mut initial_process_pss = BTreeMap::new();
    let mut final_process_pss = BTreeMap::new();

    for p in &initial.process_breakdown {
        if let Some(role) = process_role(&p.process_name) {
            initial_process_pss.insert(role.to_string(), p.pss_bytes);
        }
    }
    for p in &final_cycle.process_breakdown {
        if let Some(role) = process_role(&p.process_name) {
            final_process_pss.insert(role.to_string(), p.pss_bytes);
        }
    }

    for required in REQUIRED_RETAINED_PROCESSES {
        if !initial_process_pss.contains_key(required) || !final_process_pss.contains_key(required)
        {
            return Err(format!(
                "soak cycles missing full-distribution accounting for required process '{required}'"
            )
            .into());
        }
    }

    let mut prev_settled = initial.settled_idle_pss_bytes;
    for (idx, cycle) in cycles.iter().enumerate() {
        oom_total = oom_total.saturating_add(cycle.oom_events);
        crash_total = crash_total.saturating_add(cycle.crash_events);
        failed_probes_total = failed_probes_total.saturating_add(cycle.failed_probes);

        if idx > 0 && prev_settled > 0 {
            let cycle_ratio = cycle.settled_idle_pss_bytes as f64 / prev_settled as f64;
            if cycle_ratio > max_cycle_growth_ratio {
                max_cycle_growth_ratio = cycle_ratio;
            }
        }
        prev_settled = cycle.settled_idle_pss_bytes;
    }

    let growth_ratio =
        final_cycle.settled_idle_pss_bytes as f64 / initial.settled_idle_pss_bytes as f64;
    let mut process_growth_ratios = BTreeMap::new();
    for (role, init_pss) in &initial_process_pss {
        if let Some(fin_pss) = final_process_pss.get(role) {
            let ratio = if *init_pss > 0 {
                *fin_pss as f64 / *init_pss as f64
            } else {
                1.0
            };
            process_growth_ratios.insert(role.clone(), ratio);
        }
    }
    let is_bounded = growth_ratio <= 1.10
        && process_growth_ratios.values().all(|ratio| *ratio <= 1.10)
        && oom_total == 0
        && crash_total == 0
        && failed_probes_total == 0;

    let total_duration_secs: u64 = cycles
        .iter()
        .map(|c| u64::from(c.workload_active_seconds) + u64::from(c.idle_settle_seconds))
        .sum();
    let duration_hours = u32::try_from(total_duration_secs / 3600).unwrap_or(u32::MAX);

    Ok(SustainedCycleAnalysis {
        total_cycles: cycles.len(),
        duration_hours,
        initial_settled_pss: initial.settled_idle_pss_bytes,
        final_settled_pss: final_cycle.settled_idle_pss_bytes,
        growth_ratio,
        max_cycle_growth_ratio,
        is_bounded,
        oom_total,
        crash_total,
        failed_probes_total,
        process_growth_ratios,
    })
}

/// Synthesize a series of 24 workload/idle cycles for testing soak bounds and leak detection.
pub fn generate_soak_cycles(
    arch: Architecture,
    leaky_process: Option<(&str, f64)>,
    oom_cycle: Option<usize>,
) -> Vec<WorkloadIdleCycle> {
    let candidate = build_candidate_fixture(arch);
    let base_processes = candidate.idle_footprint.retained_processes;
    let mut cycles = Vec::with_capacity(24);

    for c in 0..24 {
        let mut processes = base_processes.clone();
        let mut total_pss = 0u64;

        for p in &mut processes {
            if let Some((leaker, rate)) = leaky_process {
                if process_role(&p.process_name) == Some(leaker) || p.process_name == leaker {
                    let factor = 1.0 + (rate * c as f64);
                    p.pss_bytes = (p.pss_bytes as f64 * factor) as u64;
                    p.rss_bytes = (p.rss_bytes as f64 * factor) as u64;
                }
            } else {
                let jitter = 1.0 + ((c as f64 * 0.0006) - 0.003);
                p.pss_bytes = (p.pss_bytes as f64 * jitter) as u64;
                p.rss_bytes = (p.rss_bytes as f64 * jitter) as u64;
            }
            total_pss = total_pss.saturating_add(p.pss_bytes);
        }

        let oom_events = u32::from(oom_cycle == Some(c));

        cycles.push(WorkloadIdleCycle {
            cycle_index: u32::try_from(c).unwrap_or(0),
            workload_active_seconds: 2700,
            idle_settle_seconds: 900,
            peak_workload_pss_bytes: (total_pss as f64 * 1.35) as u64,
            settled_idle_pss_bytes: total_pss,
            settled_cgroup_bytes: (total_pss as f64 * 1.10) as u64,
            oom_events,
            crash_events: 0,
            failed_probes: 0,
            process_breakdown: processes,
        });
    }

    cycles
}

/// Enforce committed platform thresholds, rebaseline policy, and sustained memory growth in CI.
pub fn run_ci_regression_gates(perf_dir: &Path) -> Result<()> {
    const REQUIRED_FILES: [&str; 7] = [
        "inputs.json",
        "fixtures/amd64-reference-go.json",
        "fixtures/amd64-candidate-rust.json",
        "fixtures/arm64-reference-go.json",
        "fixtures/arm64-candidate-rust.json",
        "fixtures/paired-comparison.json",
        "fixtures/secondary-targets.json",
    ];
    let base_dir = if perf_dir.ends_with("fixtures") {
        perf_dir.parent().unwrap_or(perf_dir)
    } else {
        perf_dir
    };

    println!(
        "[gate-ci] Enforcing committed platform thresholds and rebaseline policy in {}...",
        base_dir.display()
    );

    // 1. Provenance Integrity Check
    let provenance_path = base_dir.join("provenance.json");
    if !provenance_path.is_file() {
        return Err(format!("missing provenance file: {}", provenance_path.display()).into());
    }
    let prov_bytes = crate::read_bounded(&provenance_path, 4 * 1024 * 1024)?;
    let prov = crate::json::parse(&prov_bytes)?;
    let files_map = prov["files"]
        .as_object()
        .ok_or("provenance.json missing 'files' object")?;

    for required in REQUIRED_FILES {
        if !files_map.contains_key(required) {
            return Err(format!("provenance.json missing required file entry: {required}").into());
        }
    }
    for path in files_map.keys() {
        if !REQUIRED_FILES.contains(&path.as_str()) {
            return Err(format!("unexpected provenance file entry: {path}").into());
        }
    }

    // Parse the same bounded bytes whose digest was verified; later gate checks never reopen files.
    let mut verified = BTreeMap::new();
    for rel_path in REQUIRED_FILES {
        let expected_digest = files_map[rel_path]
            .as_str()
            .ok_or_else(|| format!("invalid digest for {rel_path}"))?;
        if expected_digest.len() != 64
            || !expected_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!("invalid SHA-256 digest for {rel_path}").into());
        }
        let target_file = base_dir.join(rel_path);
        let file_bytes = crate::read_bounded(&target_file, 16 * 1024 * 1024)?;
        let actual_digest = crate::sha256(&file_bytes);
        if actual_digest != expected_digest {
            return Err(format!(
                "provenance digest mismatch for {rel_path}: expected {expected_digest}, got {actual_digest}"
            )
            .into());
        }
        verified.insert(rel_path, crate::json::parse(&file_bytes)?);
    }
    println!(
        "[gate-ci] Provenance integrity: verified {} committed fixture digests",
        files_map.len()
    );

    // 2. Committed Platform Thresholds Check
    let inputs = &verified["inputs.json"];
    let thresholds_val = inputs
        .get("contract_thresholds")
        .ok_or("inputs.json missing 'contract_thresholds'")?;
    let contract_thresholds: ContractThresholds = serde_json::from_value(thresholds_val.clone())?;
    contract_thresholds
        .validate()
        .map_err(|e| format!("committed platform thresholds validation failed: {e}"))?;
    println!("[gate-ci] Committed platform thresholds: validated immutable contract multipliers");

    // 3. Baselines Load & Structural Validation
    let load = |path: &str, architecture: Architecture| -> Result<PerformanceReport> {
        let report = serde_json::from_value(verified[path].clone())?;
        super::validation::validate_report(&report)?;
        if report.architecture != architecture {
            return Err(format!("{path}: expected {} architecture", architecture.as_str()).into());
        }
        let growth = &report.sustained_growth;
        if growth.duration_hours < 24 {
            return Err(format!("{path}: sustained growth duration must be >= 24h").into());
        }
        if growth.oom_kill_count > 0 || growth.crash_count > 0 || growth.unexplained_failures > 0 {
            return Err(format!("{path}: sustained growth observed failures").into());
        }
        let shutdown = &report.shutdown;
        if shutdown.surviving_owned_processes > 0 || shutdown.unrelated_processes_killed > 0 {
            return Err(format!("{path}: shutdown unclean").into());
        }
        if shutdown.graceful_duration_seconds.max
            > contract_thresholds.shutdown_graceful_deadline_seconds
            || shutdown.escalation_duration_seconds.max
                > contract_thresholds.shutdown_escalation_deadline_seconds
        {
            return Err(format!("{path}: shutdown exceeds per-run deadline").into());
        }

        if growth.initial_settled_idle_median_bytes == 0 {
            return Err(format!("{path}: initial sustained growth memory must be positive").into());
        }
        let derived = growth.final_settled_idle_median_bytes as f64
            / growth.initial_settled_idle_median_bytes as f64;
        // Existing fixtures store three-decimal ratios; allow only that rounding precision.
        if !growth.growth_ratio.is_finite() || (growth.growth_ratio - derived).abs() > 0.000_500_001
        {
            return Err(format!(
                "{path}: reported sustained growth ratio {} disagrees with byte-derived ratio {derived}",
                growth.growth_ratio
            ).into());
        }
        Ok(report)
    };
    let amd64_ref = load("fixtures/amd64-reference-go.json", Architecture::Amd64)?;
    let amd64_cand = load("fixtures/amd64-candidate-rust.json", Architecture::Amd64)?;
    let arm64_ref = load("fixtures/arm64-reference-go.json", Architecture::Arm64)?;
    let arm64_cand = load("fixtures/arm64-candidate-rust.json", Architecture::Arm64)?;

    for report in [&amd64_ref, &amd64_cand, &arm64_ref, &arm64_cand] {
        verify_retained_process_coverage(report)?;
    }
    println!("[gate-ci] Full-distribution retained process coverage: 8 canonical roles verified");

    super::validation::validate_pair(&amd64_ref, &amd64_cand)?;
    super::validation::validate_pair(&arm64_ref, &arm64_cand)?;

    // 4. Contract Gates Evaluation with Committed Thresholds
    for (arch_name, r, c) in [
        ("amd64", &amd64_ref, &amd64_cand),
        ("arm64", &arm64_ref, &arm64_cand),
    ] {
        let eval = GateEvaluationReport::evaluate_with_thresholds(r, c, &contract_thresholds);
        if !eval.arithmetic_all_passed() {
            let failed_gates: Vec<String> = eval
                .results
                .iter()
                .filter(|g| !g.passed)
                .map(|g| format!("{}: {}", g.name, g.details))
                .collect();
            return Err(format!(
                "{arch_name} failed contract gates under committed thresholds: {}",
                failed_gates.join("; ")
            )
            .into());
        }

        let density_gate = eval
            .results
            .iter()
            .find(|g| g.name.contains("Pod Density"))
            .ok_or_else(|| format!("{arch_name} missing Pod Density gate result"))?;
        if !density_gate.higher_is_better {
            return Err(format!(
                "{arch_name} Pod Density must be configured higher_is_better = true"
            )
            .into());
        }
        if density_gate.candidate_value < density_gate.target_threshold {
            return Err(format!(
                "{arch_name} Pod Density failed: candidate {:.1} < threshold {:.1}",
                density_gate.candidate_value, density_gate.target_threshold
            )
            .into());
        }
    }
    println!("[gate-ci] Contract gates evaluation: all 12 gates PASSED for amd64 and arm64");

    // 5. Secondary Targets Registry Validation
    let sec_reg: SecondaryTargetsRegistry =
        serde_json::from_value(verified["fixtures/secondary-targets.json"].clone())?;
    sec_reg
        .validate()
        .map_err(|e| format!("secondary targets validation failed: {e}"))?;
    println!("[gate-ci] Secondary architecture gaps: armv7 and riscv64 verified explicit");

    println!(
        "[gate-ci] ✓ Performance CI regression gating PASSED: fixture integrity and contract arithmetic only; live performance NOT QUALIFIED"
    );
    Ok(())
}
