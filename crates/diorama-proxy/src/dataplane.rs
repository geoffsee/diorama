use std::collections::BTreeSet;

use diorama_network::CommandExecutor;

use crate::error::ProxyError;
use crate::routing::{ServicePort, ServiceRoutingTable, TargetEndpoint};

/// Generates a deterministic 16-character hex hash from a key string for chain naming.
#[must_use]
pub fn service_chain_hash(key: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}").to_uppercase()
}

/// An iptables rule descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IptablesRule {
    pub table: &'static str,
    pub chain: String,
    pub rule: String,
}

/// Synthesizes and verifies iptables dataplane rules for Kubernetes Services and `EndpointSlices`.
#[derive(Clone, Copy, Debug, Default)]
pub struct IptablesDataplane;

impl IptablesDataplane {
    /// Generates the complete set of iptables NAT rules corresponding to the Service routing table.
    #[must_use]
    pub fn generate_rules(table: &ServiceRoutingTable) -> Vec<IptablesRule> {
        let mut rules = Vec::new();

        for svc in table.services().values() {
            for port in &svc.ports {
                Self::synthesize_service_rules(
                    table,
                    &svc.namespace,
                    &svc.name,
                    svc.cluster_ip.as_deref(),
                    port,
                    &mut rules,
                );
            }
        }

        rules
    }

    fn synthesize_service_rules(
        table: &ServiceRoutingTable,
        namespace: &str,
        name: &str,
        cluster_ip: Option<&str>,
        port: &ServicePort,
        rules: &mut Vec<IptablesRule>,
    ) {
        let proto = port.protocol.as_str().to_lowercase();
        let svc_key = format!("{namespace}/{name}:{}/{}", port.port, port.protocol);
        let svc_hash = service_chain_hash(&svc_key);
        let svc_chain = format!("KUBE-SVC-{svc_hash}");

        // ClusterIP rule
        if let Some(cip) = cluster_ip {
            rules.push(IptablesRule {
                table: "nat",
                chain: "KUBE-SERVICES".to_string(),
                rule: format!(
                    "-d {cip}/32 -p {proto} -m {proto} --dport {} -j {svc_chain}",
                    port.port
                ),
            });
        }

        // NodePort rule
        if let Some(node_port) = port.node_port {
            rules.push(IptablesRule {
                table: "nat",
                chain: "KUBE-NODEPORTS".to_string(),
                rule: format!("-p {proto} -m {proto} --dport {node_port} -j {svc_chain}"),
            });
        }

        // Ready endpoints distribution
        if let Ok(endpoints) = table.get_ready_endpoints(namespace, name, port.port, port.protocol)
        {
            Self::synthesize_endpoint_rules(&svc_chain, &endpoints, rules);
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn synthesize_endpoint_rules(
        svc_chain: &str,
        endpoints: &[TargetEndpoint],
        rules: &mut Vec<IptablesRule>,
    ) {
        let n = endpoints.len();
        for (i, ep) in endpoints.iter().enumerate() {
            let sep_key = format!("{}:{}/{}", ep.ip, ep.port, ep.protocol);
            let sep_hash = service_chain_hash(&sep_key);
            let sep_chain = format!("KUBE-SEP-{sep_hash}");
            let proto = ep.protocol.as_str().to_lowercase();

            if i < n - 1 {
                let prob = 1.0 / ((n - i) as f64);
                rules.push(IptablesRule {
                    table: "nat",
                    chain: svc_chain.to_string(),
                    rule: format!(
                        "-m statistic --mode random --probability {prob:.5} -j {sep_chain}"
                    ),
                });
            } else {
                rules.push(IptablesRule {
                    table: "nat",
                    chain: svc_chain.to_string(),
                    rule: format!("-j {sep_chain}"),
                });
            }

            // Endpoint DNAT rule
            rules.push(IptablesRule {
                table: "nat",
                chain: sep_chain.clone(),
                rule: format!(
                    "-p {proto} -m {proto} -j DNAT --to-destination {}:{}",
                    ep.ip, ep.port
                ),
            });

            // Endpoint MASQ rule
            rules.push(IptablesRule {
                table: "nat",
                chain: sep_chain,
                rule: "-j KUBE-MARK-MASQ".to_string(),
            });
        }
    }

    /// Programs the synthesized iptables NAT rules via the command executor, ensuring owned chains exist
    /// and are repopulated without wiping foreign tables.
    #[allow(clippy::too_many_lines)]
    pub fn apply_rules(
        rules: &[IptablesRule],
        executor: &dyn CommandExecutor,
    ) -> Result<(), ProxyError> {
        // Probe packet filter availability first
        let probe = executor
            .run("iptables", &["-t", "nat", "-S"])
            .map_err(|e| ProxyError::CommandExecutionFailed {
                command: "iptables -t nat -S".to_string(),
                reason: e.to_string(),
            })?;
        if !probe.success {
            return Err(ProxyError::CommandExecutionFailed {
                command: "iptables -t nat -S".to_string(),
                reason: probe.stderr,
            });
        }

        // Ensure base chains exist
        let _ = executor.run("iptables", &["-t", "nat", "-N", "KUBE-SERVICES"]);
        let _ = executor.run("iptables", &["-t", "nat", "-N", "KUBE-NODEPORTS"]);
        let _ = executor.run("iptables", &["-t", "nat", "-N", "KUBE-POSTROUTING"]);
        let _ = executor.run("iptables", &["-t", "nat", "-N", "KUBE-MARK-MASQ"]);

        // Program mark rules for KUBE-MARK-MASQ
        let mark_check = executor.run(
            "iptables",
            &[
                "-t",
                "nat",
                "-C",
                "KUBE-MARK-MASQ",
                "-j",
                "MARK",
                "--set-xmark",
                "0x4000/0x4000",
            ],
        );
        if !matches!(mark_check, Ok(ref out) if out.success) {
            let _ = executor.run(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "KUBE-MARK-MASQ",
                    "-j",
                    "MARK",
                    "--set-xmark",
                    "0x4000/0x4000",
                ],
            );
        }

        // Program mark and masquerade rules for KUBE-POSTROUTING
        let post_masq_check = executor.run(
            "iptables",
            &[
                "-t",
                "nat",
                "-C",
                "KUBE-POSTROUTING",
                "-m",
                "mark",
                "!",
                "--mark",
                "0x4000/0x4000",
                "-j",
                "RETURN",
            ],
        );
        if !matches!(post_masq_check, Ok(ref out) if out.success) {
            let _ = executor.run(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "KUBE-POSTROUTING",
                    "-m",
                    "mark",
                    "!",
                    "--mark",
                    "0x4000/0x4000",
                    "-j",
                    "RETURN",
                ],
            );
        }

        let masq_check = executor.run(
            "iptables",
            &["-t", "nat", "-C", "KUBE-POSTROUTING", "-j", "MASQUERADE"],
        );
        if !matches!(masq_check, Ok(ref out) if out.success) {
            let _ = executor.run(
                "iptables",
                &["-t", "nat", "-A", "KUBE-POSTROUTING", "-j", "MASQUERADE"],
            );
        }

        // Idempotently install jump rules into base chains
        let prerouting_jump = executor.run(
            "iptables",
            &["-t", "nat", "-C", "PREROUTING", "-j", "KUBE-SERVICES"],
        );
        if !matches!(prerouting_jump, Ok(ref out) if out.success) {
            let _ = executor.run(
                "iptables",
                &["-t", "nat", "-A", "PREROUTING", "-j", "KUBE-SERVICES"],
            );
        }

        let output_jump = executor.run(
            "iptables",
            &["-t", "nat", "-C", "OUTPUT", "-j", "KUBE-SERVICES"],
        );
        if !matches!(output_jump, Ok(ref out) if out.success) {
            let _ = executor.run(
                "iptables",
                &["-t", "nat", "-A", "OUTPUT", "-j", "KUBE-SERVICES"],
            );
        }

        let postrouting_jump = executor.run(
            "iptables",
            &["-t", "nat", "-C", "POSTROUTING", "-j", "KUBE-POSTROUTING"],
        );
        if !matches!(postrouting_jump, Ok(ref out) if out.success) {
            let _ = executor.run(
                "iptables",
                &["-t", "nat", "-A", "POSTROUTING", "-j", "KUBE-POSTROUTING"],
            );
        }

        // Flush only owned base chains to clear previous service/nodeport mappings
        let _ = executor.run("iptables", &["-t", "nat", "-F", "KUBE-SERVICES"]);
        let _ = executor.run("iptables", &["-t", "nat", "-F", "KUBE-NODEPORTS"]);

        let mut custom_chains = BTreeSet::new();
        for rule in rules {
            if rule.chain.starts_with("KUBE-SVC-") || rule.chain.starts_with("KUBE-SEP-") {
                custom_chains.insert(rule.chain.clone());
            }
        }

        Self::purge_stale_chains(executor, &custom_chains);

        for chain in &custom_chains {
            let _ = executor.run("iptables", &["-t", "nat", "-N", chain]);
            let _ = executor.run("iptables", &["-t", "nat", "-F", chain]);
        }

        for rule in rules {
            let mut args = vec!["-t", rule.table, "-A", &rule.chain];
            let parts: Vec<&str> = rule.rule.split_whitespace().collect();
            args.extend(parts);
            let out = executor.run("iptables", &args).map_err(|e| {
                ProxyError::CommandExecutionFailed {
                    command: format!("iptables {}", args.join(" ")),
                    reason: e.to_string(),
                }
            })?;
            if !out.success {
                return Err(ProxyError::RoutingVerificationFailed {
                    rule: format!("iptables {}", args.join(" ")),
                    reason: out.stderr,
                });
            }
        }
        Ok(())
    }

    fn purge_stale_chains(executor: &dyn CommandExecutor, custom_chains: &BTreeSet<String>) {
        let Ok(out) = executor.run("iptables", &["-t", "nat", "-S"]) else {
            return;
        };
        if !out.success {
            return;
        }
        let stale: BTreeSet<&str> = out
            .stdout
            .split_whitespace()
            .filter(|t| {
                (t.starts_with("KUBE-SEP-") || t.starts_with("KUBE-SVC-"))
                    && !custom_chains.contains(*t)
            })
            .collect();
        for chain in &stale {
            let _ = executor.run("iptables", &["-t", "nat", "-F", chain]);
        }
        for chain in &stale {
            let _ = executor.run("iptables", &["-t", "nat", "-X", chain]);
        }
    }

    /// Verifies that the required iptables NAT chains and rules exist using the command executor.
    pub fn verify_active_rules(
        table: &ServiceRoutingTable,
        executor: &dyn CommandExecutor,
    ) -> Result<(), ProxyError> {
        let output = executor
            .run("iptables", &["-t", "nat", "-S"])
            .map_err(|e| ProxyError::CommandExecutionFailed {
                command: "iptables -t nat -S".to_string(),
                reason: e.to_string(),
            })?;

        if !output.success {
            return Err(ProxyError::RoutingVerificationFailed {
                rule: "iptables -t nat -S".to_string(),
                reason: output.stderr,
            });
        }

        Self::verify_rules_output(table, &output.stdout)
    }

    fn verify_rules_output(
        table: &ServiceRoutingTable,
        existing_rules: &str,
    ) -> Result<(), ProxyError> {
        for svc in table.services().values() {
            let Some(ref cluster_ip) = svc.cluster_ip else {
                continue;
            };
            for port in &svc.ports {
                let proto = port.protocol.as_str().to_lowercase();
                let needle = format!(
                    "-d {cluster_ip}/32 -p {proto} -m {proto} --dport {} ",
                    port.port
                );
                if !existing_rules.lines().any(|l| l.contains(&needle)) {
                    return Err(ProxyError::RoutingVerificationFailed {
                        rule: format!("ClusterIP {cluster_ip}:{}", port.port),
                        reason: "matching rule missing from iptables nat table".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// An nftables rule descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftablesRule {
    pub table: &'static str,
    pub chain: &'static str,
    pub statement: String,
}

/// Synthesizes and verifies nftables dataplane rules for Kubernetes Services and `EndpointSlices`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NftablesDataplane;

impl NftablesDataplane {
    /// Generates the complete set of nftables rules corresponding to the Service routing table.
    #[must_use]
    pub fn generate_rules(table: &ServiceRoutingTable) -> Vec<NftablesRule> {
        let mut rules = Vec::new();

        for svc in table.services().values() {
            for port in &svc.ports {
                Self::synthesize_nft_service_rules(
                    table,
                    &svc.namespace,
                    &svc.name,
                    svc.cluster_ip.as_deref(),
                    port,
                    &mut rules,
                );
            }
        }

        rules
    }

    fn synthesize_nft_service_rules(
        table: &ServiceRoutingTable,
        namespace: &str,
        name: &str,
        cluster_ip: Option<&str>,
        port: &ServicePort,
        rules: &mut Vec<NftablesRule>,
    ) {
        let proto = port.protocol.as_str().to_lowercase();
        let endpoints = table
            .get_ready_endpoints(namespace, name, port.port, port.protocol)
            .unwrap_or_default();

        if endpoints.is_empty() {
            return;
        }

        // ClusterIP rule
        if let Some(cip) = cluster_ip {
            rules.push(Self::format_nft_rule(
                "services",
                &format!("ip daddr {cip} {proto} dport {}", port.port),
                &endpoints,
            ));
        }

        // NodePort rule
        if let Some(node_port) = port.node_port {
            rules.push(Self::format_nft_rule(
                "nodeports",
                &format!("{proto} dport {node_port}"),
                &endpoints,
            ));
        }
    }

    fn format_nft_rule(
        chain: &'static str,
        prefix: &str,
        endpoints: &[TargetEndpoint],
    ) -> NftablesRule {
        if endpoints.len() == 1 {
            NftablesRule {
                table: "ip kube-proxy",
                chain,
                statement: format!("{prefix} dnat to {}:{}", endpoints[0].ip, endpoints[0].port),
            }
        } else {
            let targets: Vec<String> = endpoints
                .iter()
                .map(|ep| format!("{}:{}", ep.ip, ep.port))
                .collect();
            let map_body = targets
                .iter()
                .enumerate()
                .map(|(idx, t)| format!("{idx} : {t}"))
                .collect::<Vec<_>>()
                .join(", ");
            NftablesRule {
                table: "ip kube-proxy",
                chain,
                statement: format!(
                    "{prefix} dnat to numgen random mod {} map {{ {map_body} }}",
                    endpoints.len()
                ),
            }
        }
    }

    /// Programs the synthesized nftables rules into the dedicated `ip kube-proxy` table via the command executor.
    #[allow(clippy::too_many_lines)]
    pub fn apply_rules(
        rules: &[NftablesRule],
        executor: &dyn CommandExecutor,
    ) -> Result<(), ProxyError> {
        // Probe packet filter availability first
        let probe = executor.run("nft", &["list", "tables"]).map_err(|e| {
            ProxyError::CommandExecutionFailed {
                command: "nft list tables".to_string(),
                reason: e.to_string(),
            }
        })?;
        if !probe.success {
            return Err(ProxyError::CommandExecutionFailed {
                command: "nft list tables".to_string(),
                reason: probe.stderr,
            });
        }

        // Ensure table and base chains exist
        let _ = executor.run("nft", &["add", "table", "ip", "kube-proxy"]);
        let _ = executor.run(
            "nft",
            &[
                "add",
                "chain",
                "ip",
                "kube-proxy",
                "prerouting",
                "{ type nat hook prerouting priority dstnat; policy accept; }",
            ],
        );
        let _ = executor.run(
            "nft",
            &[
                "add",
                "chain",
                "ip",
                "kube-proxy",
                "output",
                "{ type nat hook output priority dstnat; policy accept; }",
            ],
        );
        let _ = executor.run("nft", &["add", "chain", "ip", "kube-proxy", "services"]);
        let _ = executor.run("nft", &["add", "chain", "ip", "kube-proxy", "nodeports"]);

        // Flush only the owned ip kube-proxy table rules
        let _ = executor.run("nft", &["flush", "table", "ip", "kube-proxy"]);

        // Install dispatch jump rules from prerouting and output to services and nodeports
        let _ = executor.run(
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "kube-proxy",
                "prerouting",
                "jump",
                "services",
            ],
        );
        let _ = executor.run(
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "kube-proxy",
                "prerouting",
                "jump",
                "nodeports",
            ],
        );
        let _ = executor.run(
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "kube-proxy",
                "output",
                "jump",
                "services",
            ],
        );
        let _ = executor.run(
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "kube-proxy",
                "output",
                "jump",
                "nodeports",
            ],
        );

        for rule in rules {
            let mut args = vec!["add", "rule", "ip", "kube-proxy", rule.chain];
            let parts: Vec<&str> = rule.statement.split_whitespace().collect();
            args.extend(parts);
            let out =
                executor
                    .run("nft", &args)
                    .map_err(|e| ProxyError::CommandExecutionFailed {
                        command: format!("nft {}", args.join(" ")),
                        reason: e.to_string(),
                    })?;
            if !out.success {
                return Err(ProxyError::RoutingVerificationFailed {
                    rule: format!("nft {}", args.join(" ")),
                    reason: out.stderr,
                });
            }
        }
        Ok(())
    }

    /// Verifies that the required nftables rules exist using the command executor.
    pub fn verify_active_rules(
        table: &ServiceRoutingTable,
        executor: &dyn CommandExecutor,
    ) -> Result<(), ProxyError> {
        let output = executor
            .run("nft", &["list", "table", "ip", "kube-proxy"])
            .map_err(|e| ProxyError::CommandExecutionFailed {
                command: "nft list table ip kube-proxy".to_string(),
                reason: e.to_string(),
            })?;

        if !output.success {
            return Err(ProxyError::RoutingVerificationFailed {
                rule: "nft list table ip kube-proxy".to_string(),
                reason: output.stderr,
            });
        }

        Self::verify_nft_rules_output(table, &output.stdout)
    }

    fn verify_nft_rules_output(
        table: &ServiceRoutingTable,
        existing_rules: &str,
    ) -> Result<(), ProxyError> {
        for svc in table.services().values() {
            let Some(ref cluster_ip) = svc.cluster_ip else {
                continue;
            };
            for port in &svc.ports {
                let endpoints = table
                    .get_ready_endpoints(&svc.namespace, &svc.name, port.port, port.protocol)
                    .unwrap_or_default();
                if endpoints.is_empty() {
                    continue;
                }
                let proto = port.protocol.as_str().to_lowercase();
                let needle = format!("ip daddr {cluster_ip} {proto} dport {} ", port.port);
                if !existing_rules.lines().any(|l| l.contains(&needle)) {
                    return Err(ProxyError::RoutingVerificationFailed {
                        rule: format!("ClusterIP {cluster_ip}:{}", port.port),
                        reason: "matching rule missing from nftables table".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}
