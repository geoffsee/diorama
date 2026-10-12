//! Unqualified release fixture diagnostics and observed-byte checksum helpers.
pub mod attribution;
pub mod cell_build;
pub mod evidence;
pub mod manifest;
pub mod notes;
pub use attribution::{
    AttributedComponent, AttributionRecord, ComponentCategory, verify_attribution_completeness,
};
pub use cell_build::{
    CellBuildReceipt, CellInventory, CleanupReceipt, MatrixComparisonResult, ReceiptAssetInput,
    ReceiptAssetOutput, build_cell_inventory, verify_cell_inventory, verify_cleanup_receipt,
};
pub use evidence::{
    PerfQualificationDocument, StateEvidence, assemble_fixture_evidence, assemble_release_evidence,
    find_receipt_path, regenerate_release_reports, verify_fixture_evidence,
    verify_kubeconfig_dual_format_accommodation, verify_release_evidence,
    verify_report_candidate_digests,
};
pub use manifest::{
    DISTRIBUTION_VERSION, MANAGEMENT_PREFIX, NODE_PREFIX, assemble_checksum_manifest,
    build_release_package_manifest, sha256_hex, verify_checksum_inventory,
    verify_checksum_manifest_binding, verify_observed_artifacts,
};
pub use notes::{ReleaseNotes, verify_release_notes_completeness};
