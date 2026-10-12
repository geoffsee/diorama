use std::fmt::Write;

use serde::{Deserialize, Serialize};

use crate::state_transition::config::ConfigTransitionAssertion;
use crate::state_transition::datastore::DatastoreTransitionAssertion;
use crate::state_transition::pki::PkiTransitionAssertion;
use crate::state_transition::storage::PvStorageAssertion;
use crate::state_transition::versions::SupportedStartingVersion;

/// Comprehensive report of a Go-to-Rust state transition evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateTransitionReport {
    pub starting_version: SupportedStartingVersion,
    pub target_distribution: String,
    pub config_assertion: Option<ConfigTransitionAssertion>,
    pub pki_assertion: Option<PkiTransitionAssertion>,
    pub datastore_assertion: Option<DatastoreTransitionAssertion>,
    pub pv_storage_assertion: Option<PvStorageAssertion>,
    pub nonportable_state_classified: usize,
    pub downtime_documented_minutes: u32,
    pub required_backups_verified: bool,
    pub overall_success: bool,
}

impl StateTransitionReport {
    /// Formats the report as human-readable Markdown.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "# State Transition Report: {} -> {}\n",
            self.starting_version, self.target_distribution
        );

        s.push_str("## 1. Supported Version & Starting State\n");
        let _ = writeln!(
            s,
            "- **Starting Version**: `{}`\n- **Layout**: {}\n- **Config File Native Support**: {}\n- **Flag Migration Required**: {}\n",
            self.starting_version.as_str(),
            self.starting_version.layout_description(),
            self.starting_version.supports_config_file(),
            self.starting_version.requires_flag_migration()
        );

        s.push_str("## 2. Configuration Transition\n");
        if let Some(cfg) = &self.config_assertion {
            let _ = writeln!(
                s,
                "- **Migrated from Service Flags**: {}\n- **Config File**: `{}`\n- **Service Backup**: `{:?}`\n- **File Permissions 0600**: {}\n- **Node IP**: `{}`\n- **Disable IPv6**: {}\n- **Edge ID**: `{}`\n",
                cfg.service_migrated,
                cfg.config_path.display(),
                cfg.backup_path.as_ref().map(|p| p.display().to_string()),
                cfg.permissions_valid_0600,
                cfg.node_ip,
                cfg.disable_ipv6,
                cfg.edge_id
            );
        } else {
            s.push_str("- *Not evaluated in this run.*\n\n");
        }

        s.push_str("## 3. PKI Trust Roots & Client Credentials\n");
        if let Some(pki) = &self.pki_assertion {
            let _ = writeln!(
                s,
                "- **CA Root Preserved**: {}\n- **CA Private Key Preserved**: {}\n- **ServiceAccount Key Preserved**: {}\n- **Kubeconfig Format Tested**: {}\n- **Client Cert Authenticated by CA**: {}\n",
                pki.ca_preserved,
                pki.ca_key_preserved,
                pki.sa_key_preserved,
                pki.kubeconfig_format,
                pki.client_cert_verified
            );
        } else {
            s.push_str("- *Not evaluated in this run.*\n\n");
        }

        s.push_str("## 4. Native Snapshot Experiment (not production Kine migration)\n");
        if let Some(ds) = &self.datastore_assertion {
            let _ = writeln!(
                s,
                "- **Raw SQLite Rejected by Diorama-Datastore**: {} *(proven rather than assumed)*\n- **Explicit Export Format**: `{}`\n- **Restored Active Keys**: {}\n- **Monotonic Revisions Preserved**: {}\n- **Restored Revision**: {}\n- **Keys Identical**: {}\n",
                ds.raw_sqlite_rejected_by_diorama_datastore,
                ds.explicit_export_format,
                ds.restored_keys,
                ds.revisions_monotonic,
                ds.restored_revision,
                ds.keys_identical
            );
        } else {
            s.push_str("- *Not evaluated in this run.*\n\n");
        }

        s.push_str("## 5. Persistent Volume Storage\n");
        if let Some(pv) = &self.pv_storage_assertion {
            let _ = writeln!(
                s,
                "- **Volumes**: {}\n- **Files Preserved**: {}\n- **Total Bytes**: {}\n- **All File Checksums Match**: {}\n- **All Permissions Match**: {}\n",
                pv.total_volumes,
                pv.total_files,
                pv.total_bytes,
                pv.all_checksums_match,
                pv.all_permissions_match
            );
        } else {
            s.push_str("- *Not evaluated in this run.*\n\n");
        }

        s.push_str("## 6. Operational Prerequisites\n");
        let _ = writeln!(
            s,
            "- **Nonportable State Items Classified**: {}\n- **Estimated Downtime**: ~{} minutes (unmeasured)\n- **Required Backups Verified**: {}\n- **Fixture Checks Successful**: {}\n- **Production Migration Qualification**: **UNQUALIFIED** (no live Kine transition evidence)",
            self.nonportable_state_classified,
            self.downtime_documented_minutes,
            self.required_backups_verified,
            if self.overall_success {
                "**PASS**"
            } else {
                "**FAIL**"
            }
        );

        s
    }
}
