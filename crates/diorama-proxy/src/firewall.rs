use std::collections::BTreeSet;

use diorama_network::{CommandExecutor, MASQUERADE_COMMENT};

use crate::backend::ProxyMode;
use crate::dataplane::{IptablesDataplane, NftablesDataplane};
use crate::error::ProxyError;
use crate::routing::ServiceRoutingTable;

/// Name of the dedicated nftables table owned by kube-proxy.
pub const KUBE_PROXY_NFT_TABLE: &str = "kube-proxy";

/// Name of the dedicated nftables table owned by E15 pod egress masquerade.
pub const KUBESOLO_MASQ_NFT_TABLE: &str = "kubesolo-masq";

/// Snapshot of host firewall state, tracking foreign rules and E15 egress rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallSnapshot {
    /// Whether E15 pod egress masquerade rule was found.
    pub e15_masquerade_present: bool,
    /// Unrelated / foreign iptables rules outside kube-proxy owned chains.
    pub foreign_iptables_rules: Vec<String>,
    /// Unrelated / foreign nftables tables outside kube-proxy owned table.
    pub foreign_nft_tables: BTreeSet<String>,
    /// Foreign nftables rules in tables outside kube-proxy.
    pub foreign_nft_rules: Vec<String>,
}

impl FirewallSnapshot {
    /// Captures the current firewall state using the provided command executor.
    #[must_use]
    pub fn capture(executor: &dyn CommandExecutor, mode: ProxyMode) -> Self {
        match mode {
            ProxyMode::IpTables => Self::capture_iptables(executor),
            ProxyMode::Nftables => Self::capture_nftables(executor),
        }
    }

    fn capture_iptables(executor: &dyn CommandExecutor) -> Self {
        let mut e15_masquerade_present = false;
        let mut foreign_iptables_rules = Vec::new();

        // Check NAT table rules
        if let Ok(out) = executor.run("iptables", &["-t", "nat", "-S"])
            && out.success
        {
            for line in out.stdout.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if trimmed.contains(MASQUERADE_COMMENT) || trimmed.contains("MASQUERADE") {
                    e15_masquerade_present = true;
                }
                // Categorize whether this rule belongs to kube-proxy or foreign/host
                if !Self::is_kube_proxy_iptables_rule(trimmed) {
                    foreign_iptables_rules.push(trimmed.to_string());
                }
            }
        }

        // Also inspect filter table
        if let Ok(out) = executor.run("iptables", &["-t", "filter", "-S"])
            && out.success
        {
            for line in out.stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !Self::is_kube_proxy_iptables_rule(trimmed) {
                    foreign_iptables_rules.push(trimmed.to_string());
                }
            }
        }

        // Additional direct check for E15 masquerade rule if not detected in -S dump
        if !e15_masquerade_present
            && let Ok(out) = executor.run(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-C",
                    "POSTROUTING",
                    "-m",
                    "comment",
                    "--comment",
                    MASQUERADE_COMMENT,
                ],
            )
            && out.success
        {
            e15_masquerade_present = true;
        }

        Self {
            e15_masquerade_present,
            foreign_iptables_rules,
            foreign_nft_tables: BTreeSet::new(),
            foreign_nft_rules: Vec::new(),
        }
    }

    fn capture_nftables(executor: &dyn CommandExecutor) -> Self {
        let mut foreign_nft_tables = BTreeSet::new();
        let mut foreign_nft_rules = Vec::new();
        let mut e15_masquerade_present = false;

        // List tables
        if let Ok(out) = executor.run("nft", &["list", "tables"])
            && out.success
        {
            for line in out.stdout.lines() {
                let trimmed = line.trim();
                let Some(table_name) = trimmed.strip_prefix("table ") else {
                    continue;
                };
                let mut parts = table_name.split_whitespace();
                let Some(name) = parts.nth(1) else {
                    continue;
                };
                if name == KUBESOLO_MASQ_NFT_TABLE {
                    e15_masquerade_present = true;
                }
                if name != KUBE_PROXY_NFT_TABLE {
                    foreign_nft_tables.insert(name.to_string());
                }
            }
        }

        // Direct check for kubesolo-masq table if not detected in tables list
        if !e15_masquerade_present
            && let Ok(out) = executor.run("nft", &["list", "table", "ip", KUBESOLO_MASQ_NFT_TABLE])
            && out.success
        {
            e15_masquerade_present = true;
            foreign_nft_tables.insert(KUBESOLO_MASQ_NFT_TABLE.to_string());
        }

        // List rules in foreign tables to track their preservation
        for table in &foreign_nft_tables {
            let Ok(out) = executor.run("nft", &["list", "table", "ip", table]) else {
                continue;
            };
            if !out.success {
                continue;
            }
            for line in out.stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with("table ") {
                    foreign_nft_rules.push(format!("{table}:{trimmed}"));
                }
            }
        }

        Self {
            e15_masquerade_present,
            foreign_iptables_rules: Vec::new(),
            foreign_nft_tables,
            foreign_nft_rules,
        }
    }

    #[must_use]
    pub fn is_kube_proxy_iptables_rule(rule: &str) -> bool {
        rule.contains("KUBE-SERVICES")
            || rule.contains("KUBE-NODEPORTS")
            || rule.contains("KUBE-POSTROUTING")
            || rule.contains("KUBE-MARK-MASQ")
            || rule.contains("KUBE-SVC-")
            || rule.contains("KUBE-SEP-")
    }

    /// Verifies that foreign firewall rules and E15 egress rules remain preserved.
    pub fn verify_preserved(&self, current: &Self) -> Result<(), ProxyError> {
        // 1. Verify E15 pod masquerade rule preservation
        if self.e15_masquerade_present && !current.e15_masquerade_present {
            return Err(ProxyError::ForeignFirewallCorrupted {
                reason: "E15 pod masquerade rule was destroyed or wiped by blanket flush"
                    .to_string(),
            });
        }

        // 2. Verify foreign iptables rules preservation
        for foreign_rule in &self.foreign_iptables_rules {
            if !current.foreign_iptables_rules.contains(foreign_rule) {
                return Err(ProxyError::ForeignFirewallCorrupted {
                    reason: format!(
                        "foreign iptables rule '{foreign_rule}' missing after kube-proxy operation; blanket flush detected"
                    ),
                });
            }
        }

        // 3. Verify foreign nftables tables preservation
        for foreign_table in &self.foreign_nft_tables {
            if !current.foreign_nft_tables.contains(foreign_table) {
                return Err(ProxyError::ForeignFirewallCorrupted {
                    reason: format!(
                        "foreign nftables table '{foreign_table}' missing after kube-proxy operation; blanket flush detected"
                    ),
                });
            }
        }

        // 4. Verify foreign nftables rules preservation
        for foreign_rule in &self.foreign_nft_rules {
            if !current.foreign_nft_rules.contains(foreign_rule) {
                return Err(ProxyError::ForeignFirewallCorrupted {
                    reason: format!(
                        "foreign nftables rule '{foreign_rule}' missing after kube-proxy operation; blanket flush detected"
                    ),
                });
            }
        }

        tracing::info!(
            target: "kubeproxy::firewall",
            foreign_iptables_retained = current.foreign_iptables_rules.len(),
            foreign_nft_tables_retained = current.foreign_nft_tables.len(),
            foreign_nft_rules_retained = current.foreign_nft_rules.len(),
            e15_masquerade_intact = current.e15_masquerade_present,
            "foreign firewall rules and E15 pod egress rules successfully preserved"
        );

        Ok(())
    }
}

/// Summary report of a dataplane reconciliation operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationSummary {
    /// Number of Services reconciled.
    pub services_reconciled: usize,
    /// Number of ready active endpoints programmed.
    pub active_endpoints: usize,
    /// Number of stale endpoints cleared during replacement.
    pub stale_endpoints_cleared: usize,
    /// Whether all foreign firewall rules were verified preserved.
    pub foreign_rules_preserved: bool,
}

/// Dataplane reconciler ensuring routing updates, backend replacements, and foreign firewall preservation.
#[derive(Clone, Copy, Debug, Default)]
pub struct DataplaneReconciler;

impl DataplaneReconciler {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Reconciles the dataplane routing rules against the current `ServiceRoutingTable`.
    ///
    /// Preserves all foreign rules and E15 pod egress rules, clearing only stale endpoint rules
    /// belonging to replaced or removed endpoints.
    pub fn reconcile(
        &self,
        table: &ServiceRoutingTable,
        mode: ProxyMode,
        executor: &dyn CommandExecutor,
        previous_endpoints: Option<&[String]>,
    ) -> Result<ReconciliationSummary, ProxyError> {
        let before_snapshot = FirewallSnapshot::capture(executor, mode);

        let mut active_endpoints = Vec::new();
        for svc in table.services().values() {
            for port in &svc.ports {
                let Ok(eps) =
                    table.get_ready_endpoints(&svc.namespace, &svc.name, port.port, port.protocol)
                else {
                    continue;
                };
                for ep in eps {
                    active_endpoints.push(format!("{}:{}", ep.ip, ep.port));
                }
            }
        }

        let mut stale_endpoints_cleared = 0;
        if let Some(prev) = previous_endpoints {
            for old_ep in prev {
                if !active_endpoints.contains(old_ep) {
                    stale_endpoints_cleared += 1;
                    tracing::info!(
                        target: "kubeproxy::dataplane",
                        stale_endpoint = %old_ep,
                        "cleared stale replaced endpoint from dataplane routing"
                    );
                }
            }
        }

        // Apply synthesized rules and verify active dataplane rules
        match mode {
            ProxyMode::IpTables => {
                let rules = IptablesDataplane::generate_rules(table);
                IptablesDataplane::apply_rules(&rules, executor)?;
                IptablesDataplane::verify_active_rules(table, executor)?;
                tracing::debug!(
                    target: "kubeproxy::dataplane",
                    rule_count = rules.len(),
                    "reconciled iptables service routing chains without blanket NAT flush"
                );
            },
            ProxyMode::Nftables => {
                let rules = NftablesDataplane::generate_rules(table);
                NftablesDataplane::apply_rules(&rules, executor)?;
                NftablesDataplane::verify_active_rules(table, executor)?;
                tracing::debug!(
                    target: "kubeproxy::dataplane",
                    rule_count = rules.len(),
                    "reconciled native nftables ip kube-proxy rules without touching foreign tables"
                );
            },
        }

        let after_snapshot = FirewallSnapshot::capture(executor, mode);
        before_snapshot.verify_preserved(&after_snapshot)?;

        Ok(ReconciliationSummary {
            services_reconciled: table.services().len(),
            active_endpoints: active_endpoints.len(),
            stale_endpoints_cleared,
            foreign_rules_preserved: true,
        })
    }
}
