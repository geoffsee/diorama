//! Candidate disclosures referencing the authoritative contracts.
use crate::Result;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseNotes;
impl ReleaseNotes {
    #[must_use]
    pub const fn build() -> Self {
        Self
    }
    /// Fixture diagnostics establish neither production readiness nor measured downtime.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        format!(
            "# Diorama v0.1.0 candidate release notes\n\n**Status: UNQUALIFIED_FIXTURE_ONLY. C13/C14/C16/C17 remain pending.**\n\nDiorama develops a single-node distribution supervising retained kube-apiserver, kube-controller-manager, kubelet, kube-proxy, Kine and containerd executables. Runtime shims, CNI programs, snapshotter helpers and default addon images remain part of distribution accounting. These diagnostics do not qualify an installed retained node, authentication, DNS/storage, container support, or platform behavior.\n\n## Migration and recovery boundaries\n\nThe modeled starting versions are v1.1.8, v1.2.0, v1.3.0 and v1.3.1 through v1.3.3. No live Go-to-Rust migration or downtime was measured. There is no qualified production cutover or promised downtime window. Preserve verified configuration, PKI, Kine SQLite/WAL and persistent-volume backups. Experimental RUBXSNP1 snapshots do not replace or adopt a Kine SQLite database. The selected production API-server/Kine contract requires loopback mTLS with a dedicated datastore CA and client identity; plaintext spike evidence cannot qualify that transport.\n\n## Compatibility, deprecations and deviations\n\nPreserve kubesolo.io/v1alpha1, KUBESOLO_* inputs, /etc/diorama-kube and /var/lib/diorama-kube defaults. KUBESOLO_FULL/--full are deprecated no-ops. NodeSetter and YAML/JSON kubeconfig parser fixtures are implementation diagnostics, not proof of live authentication or service behavior. D01 through D11 are defined by the [compatibility contract](../architecture/compatibility-contract.md); they are deliberate design obligations, not qualified release capabilities.\n\n## Performance\n\nThe [authoritative performance policy](../architecture/performance-rebaseline-policy.md) owns the twelve arithmetic gates:\n\n| Gate | Default pass condition |\n| --- | --- |\n| Boot-to-API latency, p95 | Candidate <= reference * 1.10 |\n| Node Ready latency, p95 | Candidate <= reference * 1.10 |\n| First Pod latency, preloaded image, p95 | Candidate <= reference * 1.10 |\n| First Pod latency, cold image, p95 | Candidate <= reference * 1.10 |\n| Idle summed PSS, median of run p95 values | Candidate <= reference * 1.10 |\n| Idle cgroup memory, median of run p95 values | Candidate <= reference * 1.10 |\n| Compressed distribution archive bytes | Candidate <= reference * 1.10 |\n| Extracted executable/helper bytes | Candidate <= reference * 1.10 |\n| Default image payload bytes | Candidate <= reference * 1.10 |\n| Pod density, median Ready replicas | Candidate >= reference * 0.90 |\n| Sustained memory growth | Final/initial settled idle median <= 1.10; >=24h; zero OOMs, crashes and unexplained failures |\n| Shutdown and cleanup | Graceful p95/maximum <=30 seconds; escalation p95/maximum <=35 seconds; zero surviving owned or killed unrelated processes |\n\nSystem-workload readiness, per-component memory and pod-cycle diagnostics are not additional implemented contract gates. Synthetic arithmetic passing does not qualify live performance.\n\n## Certification\n\n{}\n",
            crate::conformance::CERTIFICATION_DISCLAIMER
        )
    }
}
pub fn verify_release_notes_completeness(notes: &ReleaseNotes) -> Result<()> {
    if !notes.to_markdown().contains("UNQUALIFIED_FIXTURE_ONLY") {
        return Err("missing unqualified status".into());
    }
    Ok(())
}
