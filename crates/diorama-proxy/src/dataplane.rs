use std::collections::BTreeSet;
use std::fmt::Write;

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
                Self::synthesize_service_rules(table, svc, port, &mut rules);
            }
        }

        rules
    }

    fn synthesize_service_rules(
        table: &ServiceRoutingTable,
        svc: &crate::routing::ServiceDefinition,
        port: &ServicePort,
        rules: &mut Vec<IptablesRule>,
    ) {
        let namespace = svc.namespace.as_str();
        let name = svc.name.as_str();
        let cluster_ip = svc.cluster_ip.as_deref();
        let proto = port.protocol.as_str().to_lowercase();
        let svc_key = format!("{namespace}/{name}:{}/{}", port.port, port.protocol);
        let svc_hash = service_chain_hash(&svc_key);
        let svc_chain = format!("KUBE-SVC-{svc_hash}");

        // Headless Services are not DNAT targets.
        if cluster_ip.is_none() && port.node_port.is_none() {
            return;
        }

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
            Self::synthesize_endpoint_rules(
                &svc_chain,
                &endpoints,
                svc.session_affinity_seconds,
                rules,
            );
        }
    }

    #[allow(clippy::cast_precision_loss)]
    fn synthesize_endpoint_rules(
        svc_chain: &str,
        endpoints: &[TargetEndpoint],
        affinity_seconds: Option<u32>,
        rules: &mut Vec<IptablesRule>,
    ) {
        let n = endpoints.len();
        let sep_chain_of = |ep: &TargetEndpoint| {
            let affinity = if affinity_seconds.is_some() {
                "/affinity"
            } else {
                ""
            };
            let sep_key = format!("{}:{}/{}{affinity}", ep.ip, ep.port, ep.protocol);
            format!("KUBE-SEP-{}", service_chain_hash(&sep_key))
        };
        if let Some(seconds) = affinity_seconds {
            for ep in endpoints {
                let sep_chain = sep_chain_of(ep);
                rules.push(IptablesRule {
                    table: "nat",
                    chain: svc_chain.to_string(),
                    rule: format!(
                        "-m recent --name {sep_chain} --mask 255.255.255.255 --rsource --rcheck --seconds {seconds} --reap -j {sep_chain}"
                    ),
                });
            }
        }
        for (i, ep) in endpoints.iter().enumerate() {
            let sep_chain = sep_chain_of(ep);
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

            // Share identical backend addresses across Services without duplicating SEP body.
            let sep_body_exists = rules.iter().any(|r| r.chain == sep_chain);
            if sep_body_exists {
                continue;
            }

            // Endpoint MASQ rule (must precede terminating DNAT target)
            rules.push(IptablesRule {
                table: "nat",
                chain: sep_chain.clone(),
                rule: "-j KUBE-MARK-MASQ".to_string(),
            });

            // Endpoint DNAT rule; affine SEPs record the client for affinity.
            let recent = if affinity_seconds.is_some() {
                format!("-m recent --set --name {sep_chain} --mask 255.255.255.255 --rsource ")
            } else {
                String::new()
            };
            rules.push(IptablesRule {
                table: "nat",
                chain: sep_chain.clone(),
                rule: format!(
                    "-p {proto} {recent}-m {proto} -j DNAT --to-destination {}:{}",
                    ep.ip, ep.port
                ),
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
        // Pod traffic DNATed to the loopback apiserver is otherwise dropped.
        let _ = diorama_network::ensure_route_localnet();

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

        if Self::apply_rules_atomically(rules, executor) {
            return Ok(());
        }

        // Flush only owned base chains to clear previous service/nodeport mappings
        let _ = executor.run("iptables", &["-t", "nat", "-F", "KUBE-SERVICES"]);
        let _ = executor.run("iptables", &["-t", "nat", "-F", "KUBE-NODEPORTS"]);

        let mut custom_chains = BTreeSet::new();
        for rule in rules {
            if rule.chain.starts_with("KUBE-SVC-") || rule.chain.starts_with("KUBE-SEP-") {
                custom_chains.insert(rule.chain.clone());
            }
            // ClusterIP/NodePort jumps are emitted even when a Service has no ready
            // endpoints. Those target chains must still exist or iptables-nft rejects
            // the jump (seen on second start for kube-dns before EndpointSlices recover).
            for token in rule.rule.split_whitespace() {
                if token.starts_with("KUBE-SVC-") || token.starts_with("KUBE-SEP-") {
                    custom_chains.insert(token.to_string());
                }
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

        // ClusterIP matches must stay ahead of this jump. Localhost NodePort traffic
        // (OUTPUT to 127.0.0.1:nodePort) only reaches KUBE-NODEPORTS through it.
        Self::ensure_kube_services_nodeports_jump(executor)?;
        Ok(())
    }

    /// Replaces the owned Service chains in a single `iptables-restore --noflush`
    /// transaction. Returns `false` when the restore tool is unavailable or rejects
    /// the payload so the caller can fall back to incremental programming.
    fn apply_rules_atomically(rules: &[IptablesRule], executor: &dyn CommandExecutor) -> bool {
        let Ok(existing) = executor.run("iptables", &["-t", "nat", "-S"]) else {
            return false;
        };
        if !existing.success {
            return false;
        }
        let payload = Self::restore_payload(rules, &existing.stdout);
        let Ok(mut tmp) = tempfile::Builder::new()
            .prefix("diorama-kube-proxy-")
            .suffix(".rules")
            .tempfile()
        else {
            return false;
        };
        if std::io::Write::write_all(&mut tmp, payload.as_bytes()).is_err() {
            return false;
        }
        let Some(path_str) = tmp.path().to_str() else {
            return false;
        };
        let result = executor.run("iptables-restore", &["--noflush", "-w", "5", path_str]);
        match result {
            Ok(out) if out.success => true,
            Ok(out) => {
                tracing::warn!(
                    target: "kubeproxy::dataplane",
                    reason = %out.stderr,
                    "atomic iptables-restore rejected; falling back to incremental rules"
                );
                false
            },
            Err(_) => false,
        }
    }

    /// Renders the `nat` table restore payload for the owned chains.
    #[must_use]
    pub fn restore_payload(rules: &[IptablesRule], existing_nat: &str) -> String {
        let mut chains = BTreeSet::new();
        for rule in rules {
            if rule.chain.starts_with("KUBE-SVC-") || rule.chain.starts_with("KUBE-SEP-") {
                chains.insert(rule.chain.clone());
            }
            for token in rule.rule.split_whitespace() {
                if token.starts_with("KUBE-SVC-") || token.starts_with("KUBE-SEP-") {
                    chains.insert(token.to_string());
                }
            }
        }
        let stale: BTreeSet<&str> = existing_nat
            .split_whitespace()
            .filter(|t| {
                (t.starts_with("KUBE-SEP-") || t.starts_with("KUBE-SVC-")) && !chains.contains(*t)
            })
            .collect();

        let mut out = String::from("*nat\n:KUBE-SERVICES - [0:0]\n:KUBE-NODEPORTS - [0:0]\n");
        for chain in chains
            .iter()
            .map(String::as_str)
            .chain(stale.iter().copied())
        {
            let _ = writeln!(out, ":{chain} - [0:0]");
        }
        for rule in rules {
            let _ = writeln!(out, "-A {} {}", rule.chain, rule.rule);
        }
        // ClusterIP matches stay ahead of the NodePort dispatch.
        out.push_str("-A KUBE-SERVICES -m addrtype --dst-type LOCAL -j KUBE-NODEPORTS\n");
        for chain in &stale {
            let _ = writeln!(out, "-X {chain}");
        }
        out.push_str("COMMIT\n");
        out
    }

    /// Appends the kube-proxy dispatch from `KUBE-SERVICES` into `KUBE-NODEPORTS`.
    ///
    /// Prefers the upstream `-m addrtype --dst-type LOCAL` match. Falls back to an
    /// unconditional jump when `xt_addrtype` is unavailable so single-node boots still
    /// serve `NodePorts` on the loopback address.
    fn ensure_kube_services_nodeports_jump(
        executor: &dyn CommandExecutor,
    ) -> Result<(), ProxyError> {
        let local_jump = executor.run(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "KUBE-SERVICES",
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "-j",
                "KUBE-NODEPORTS",
            ],
        );
        if matches!(local_jump, Ok(ref out) if out.success) {
            return Ok(());
        }

        let fallback = executor
            .run(
                "iptables",
                &["-t", "nat", "-A", "KUBE-SERVICES", "-j", "KUBE-NODEPORTS"],
            )
            .map_err(|e| ProxyError::CommandExecutionFailed {
                command: "iptables -t nat -A KUBE-SERVICES -j KUBE-NODEPORTS".to_string(),
                reason: e.to_string(),
            })?;
        if !fallback.success {
            let addrtype_reason = local_jump.map_or_else(
                |e| e.to_string(),
                |out| {
                    if out.stderr.is_empty() {
                        out.stdout
                    } else {
                        out.stderr
                    }
                },
            );
            return Err(ProxyError::RoutingVerificationFailed {
                rule: "KUBE-SERVICES -> KUBE-NODEPORTS".to_string(),
                reason: format!(
                    "failed to install NodePort dispatch jump (addrtype: {addrtype_reason}; fallback: {})",
                    fallback.stderr
                ),
            });
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

    fn require_nat_rule(present: bool, rule: String) -> Result<(), ProxyError> {
        if present {
            return Ok(());
        }
        Err(ProxyError::RoutingVerificationFailed {
            rule,
            reason: "matching rule missing from iptables nat table".to_string(),
        })
    }

    fn verify_rules_output(
        table: &ServiceRoutingTable,
        existing_rules: &str,
    ) -> Result<(), ProxyError> {
        let mut expects_nodeport = false;
        for svc in table.services().values() {
            for port in &svc.ports {
                let proto = port.protocol.as_str().to_lowercase();
                if let Some(ref cluster_ip) = svc.cluster_ip {
                    let needle = format!(
                        "-d {cluster_ip}/32 -p {proto} -m {proto} --dport {} ",
                        port.port
                    );
                    Self::require_nat_rule(
                        existing_rules.lines().any(|line| line.contains(&needle)),
                        format!("ClusterIP {cluster_ip}:{}", port.port),
                    )?;
                }
                if let Some(node_port) = port.node_port {
                    expects_nodeport = true;
                    let needle = format!("-p {proto} -m {proto} --dport {node_port} ");
                    let has_nodeport = existing_rules
                        .lines()
                        .any(|line| line.contains("KUBE-NODEPORTS") && line.contains(&needle));
                    Self::require_nat_rule(has_nodeport, format!("NodePort {node_port}/{proto}"))?;
                }
            }
        }
        if expects_nodeport
            && !existing_rules
                .lines()
                .any(|l| l.contains("KUBE-SERVICES") && l.contains("-j KUBE-NODEPORTS"))
        {
            return Err(ProxyError::RoutingVerificationFailed {
                rule: "KUBE-SERVICES -> KUBE-NODEPORTS".to_string(),
                reason: "NodePort dispatch jump missing from iptables nat table".to_string(),
            });
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
