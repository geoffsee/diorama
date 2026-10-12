//! State preservation checks and isolated native snapshot experiments.
//!
//! Epic E30 / Issue #124:
//! - Validates supported starting versions (`v1.1.8`, `v1.2.0`, `v1.3.0`, `v1.3.1-v1.3.3`) and rejects unsupported ones.
//! - Validates configuration transition from legacy service flags and existing YAML config.
//! - Validates PKI trust roots and client credentials, accommodating **both YAML and JSON** kubeconfig formats.
//! - Exercises native snapshot conversion of in-memory fixtures and format non-interchangeability.
//!   Production Kine `SQLite` adoption and WAL checkpointing remain unqualified.
//! - Validates static workloads, Kubernetes resource identities, and state portability classification.
//! - Validates persistent volume (PV) storage data and byte checksum preservation.

pub mod config;
pub mod datastore;
pub mod live_rehearsal;
pub mod pki;
pub mod recovery;
pub mod report;
pub mod storage;
pub mod versions;
pub mod workloads;

pub use config::{ConfigTransitionAssertion, assert_flags_match_yaml, validate_config_transition};
pub use datastore::{
    DatastoreTransitionAssertion, KineRecord, assert_raw_sqlite_rejected, compute_file_sha256,
    export_kine_to_diorama_datastore, validate_datastore_transition,
};
pub use live_rehearsal::{
    LiveMigrationResult, OPTION_B_SCOPE_MARKER, SyntheticMigrationResult,
    build_criterion_8_receipt_payload, build_criterion_8_receipt_payload_with_inventory,
    generate_criterion_8_receipt, realistic_kine_records, run_live_migration_rehearsal,
    run_synthetic_migration_rehearsal,
};
pub use pki::{
    KubeconfigFormat, ParsedKubeconfig, PkiTransitionAssertion, assert_pki_transition,
    parse_kubeconfig, verify_cert_chain,
};
pub use recovery::{
    BackupCondition, DisposableInstallation, RehearsalResult, RehearsalScenario, TransitionStage,
    run_rehearsal, version_recovery_limitations,
};
pub use report::StateTransitionReport;
pub use storage::{PvFileRecord, PvStorageAssertion, assert_pv_storage_preserved, scan_pv_storage};
pub use versions::{
    MINIMUM_SUPPORTED_VERSION, SupportedStartingVersion, UnsupportedVersionError,
    classify_starting_version,
};
pub use workloads::{
    StateClassificationItem, StatePortabilityCategory, WorkloadIdentity,
    assert_static_manifests_preserved, assert_workload_identities_preserved,
    state_classification_inventory,
};
