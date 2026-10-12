//! Synthetic API/controller fixture evidence and planned C13/E28 conformance inventory.
//! No selected retained-executable node or upstream conformance suite is qualified here.

#[allow(clippy::pedantic)]
pub mod kubeconfig;
#[allow(clippy::pedantic)]
pub mod manifests;
#[allow(clippy::pedantic)]
pub mod runner;
#[allow(clippy::pedantic)]
pub mod selected_conformance;

pub use kubeconfig::{Kubeconfig, KubeconfigError};
pub use runner::{
    CONF_NAMESPACE, DomainReport, ManifestDomain, QualificationReport, QualificationRunner,
    SmokeCheck, SmokeReport, generate_suite_selection_markdown,
};
pub use selected_conformance::{
    CERTIFICATION_DISCLAIMER, CONFORMANCE_FOCUS_REGEX, CONFORMANCE_SKIP_REGEX,
    ConformanceExclusion, ConformanceInventory, ConformanceResult, ConformanceSummary,
    ConformanceTestCase, ExclusionCategory,
};
