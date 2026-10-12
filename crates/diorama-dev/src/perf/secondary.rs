//! Explicit secondary architecture limitations and gap records for armv7 and riscv64.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Explicit performance gap and limitation record for non-primary architectures.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecondaryArchitectureGap {
    pub architecture: String,
    pub status: String,
    pub address_space_bits: u32,
    pub maximum_pod_density: u32,
    pub d2k_supported: bool,
    pub portainer_supported: bool,
    pub crun_source_build_required: bool,
    pub cold_boot_latency_overhead_multiplier: String,
    pub primary_gate_exceptions: Vec<String>,
    pub hardware_and_toolchain_constraints: Vec<String>,
}

/// Consolidated registry of all secondary architecture limitations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecondaryTargetsRegistry {
    pub schema_version: u32,
    pub targets: BTreeMap<String, SecondaryArchitectureGap>,
}

impl SecondaryTargetsRegistry {
    /// Return the explicit, unqualified secondary architecture gap examples.
    pub fn default_contract() -> Self {
        let mut targets = BTreeMap::new();

        targets.insert(
            "armv7".to_string(),
            SecondaryArchitectureGap {
                architecture: "armv7".to_string(),
                status: "not-qualified".to_string(),
                address_space_bits: 32,
                maximum_pod_density: 0,
                d2k_supported: false,
                portainer_supported: true,
                crun_source_build_required: true,
                cold_boot_latency_overhead_multiplier: "unmeasured".to_string(),
                primary_gate_exceptions: vec![
                    "Pod density is unmeasured; no accepted density exception".to_string(),
                    "D2K translator disabled by platform contract".to_string(),
                    "Startup latency is unmeasured; no accepted latency exception".to_string(),
                ],
                hardware_and_toolchain_constraints: vec![
                    "Requires hard-float ABI (armv7hl / armhf)".to_string(),
                    "crun runtime must be compiled from source for ARMv7 target".to_string(),
                    "Maximum 3 GiB accessible user virtual memory per process".to_string(),
                ],
            },
        );

        targets.insert(
            "riscv64".to_string(),
            SecondaryArchitectureGap {
                architecture: "riscv64".to_string(),
                status: "not-qualified".to_string(),
                address_space_bits: 64,
                maximum_pod_density: 0,
                d2k_supported: false,
                portainer_supported: false,
                crun_source_build_required: false,
                cold_boot_latency_overhead_multiplier: "unmeasured".to_string(),
                primary_gate_exceptions: vec![
                    "Portainer agent and UI unavailable on riscv64".to_string(),
                    "D2K translator disabled".to_string(),
                    "Startup latency is unmeasured; no accepted latency exception".to_string(),
                    "Pod density is unmeasured; no accepted density exception".to_string(),
                ],
                hardware_and_toolchain_constraints: vec![
                    "Requires rv64gc ISA baseline with Linux cgroups v2".to_string(),
                    "Official container images for Portainer and auxiliary components lack riscv64 manifests".to_string(),
                    "Toolchain/codegen optimizations are nascent compared to mature x86_64/aarch64 backends".to_string(),
                ],
            },
        );

        Self {
            schema_version: 1,
            targets,
        }
    }

    /// Validate that all required secondary architectures have explicit gap documentation.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!(
                "Unsupported schema version: {}",
                self.schema_version
            ));
        }

        let expected = Self::default_contract();
        for arch in ["armv7", "riscv64"] {
            let gap = self.targets.get(arch).ok_or_else(|| {
                format!("Missing required secondary architecture gap record for '{arch}'")
            })?;
            let required = &expected.targets[arch];
            if gap.architecture != required.architecture
                || gap.status != required.status
                || gap.address_space_bits != required.address_space_bits
                || gap.maximum_pod_density != required.maximum_pod_density
                || gap.d2k_supported != required.d2k_supported
                || gap.portainer_supported != required.portainer_supported
                || gap.crun_source_build_required != required.crun_source_build_required
                || gap.cold_boot_latency_overhead_multiplier
                    != required.cold_boot_latency_overhead_multiplier
            {
                return Err(format!(
                    "Architecture '{arch}' does not match the required secondary-target contract"
                ));
            }

            if gap.primary_gate_exceptions.is_empty() {
                return Err(format!(
                    "Architecture '{arch}' must explicitly record primary gate exceptions"
                ));
            }
            if gap.hardware_and_toolchain_constraints.is_empty() {
                return Err(format!(
                    "Architecture '{arch}' must explicitly record hardware/toolchain constraints"
                ));
            }
        }

        Ok(())
    }
}
