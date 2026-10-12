use std::fmt::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::cni::DEFAULT_POD_CIDR;
use crate::error::NetworkError;

pub const DEFAULT_NFT_MASQ_TABLE: &str = "kubesolo-masq";
pub const MASQUERADE_COMMENT: &str = "kubesolo: pod masquerade";
pub const IPTABLES_WAIT_SECONDS: &str = "5";

/// Supported masquerade backend technology.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MasqueradeBackend {
    /// Kernel `ip_tables` module with iptables CLI.
    IpTables,
    /// Linux nftables backend with nft CLI.
    Nftables,
}

/// Decision reached when evaluating an egress IP packet against pod masquerade rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressDecision {
    /// Packet is egressing from pod CIDR to an external destination; SNAT/masquerade applied.
    Masquerade {
        source_ip: String,
        destination_ip: String,
    },
    /// Packet is pod-to-pod within pod CIDR; original source IP preserved (no masquerade).
    Direct {
        source_ip: String,
        destination_ip: String,
    },
    /// Packet source does not belong to pod CIDR; rule does not match.
    NoMatch,
}

/// Output of a command execution.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Trait abstracting command execution for testability and portability.
pub trait CommandExecutor: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, std::io::Error>;
}

/// Real system command executor invoking subprocesses.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, std::io::Error> {
        let output = std::process::Command::new(program).args(args).output()?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

/// Checks if an IPv4 address is within the specified CIDR network.
#[must_use]
pub fn ipv4_in_cidr(ip_str: &str, cidr_str: &str) -> bool {
    let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
        return false;
    };
    let Some((net_str, prefix_str)) = cidr_str.split_once('/') else {
        return false;
    };
    let Ok(net) = net_str.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    let ip_u32 = u32::from(ip);
    let net_u32 = u32::from(net);
    (ip_u32 & mask) == (net_u32 & mask)
}

/// Evaluates how a packet from `src_ip` to `dst_ip` is handled by the pod masquerade rule.
///
/// Rules specify `-s <pod_cidr> ! -d <pod_cidr> -j MASQUERADE`:
/// - Traffic from pod CIDR to external destinations is masqueraded.
/// - Traffic from pod CIDR to other pod IPs (pod-to-pod) is preserved directly without masquerade.
#[must_use]
pub fn evaluate_egress_traffic(src_ip: &str, dst_ip: &str, pod_cidr: &str) -> EgressDecision {
    if !ipv4_in_cidr(src_ip, pod_cidr) {
        return EgressDecision::NoMatch;
    }

    if ipv4_in_cidr(dst_ip, pod_cidr) {
        EgressDecision::Direct {
            source_ip: src_ip.to_string(),
            destination_ip: dst_ip.to_string(),
        }
    } else {
        EgressDecision::Masquerade {
            source_ip: src_ip.to_string(),
            destination_ip: dst_ip.to_string(),
        }
    }
}

/// Detects whether the host supports iptables or nftables.
///
/// Matches upstream `KubeSolo` logic:
/// If `/proc/net/ip_tables_names` exists and `iptables` runs, chooses `IpTables`.
/// Otherwise, falls back to `nft` (nftables).
pub fn detect_backend(
    sys_root: Option<&Path>,
    executor: &dyn CommandExecutor,
) -> Result<MasqueradeBackend, NetworkError> {
    let proc_root = sys_root.unwrap_or_else(|| Path::new("/"));
    let ip_tables_names = proc_root.join("proc/net/ip_tables_names");

    if ip_tables_names.exists()
        && let Ok(out) = executor.run("iptables", &["--version"])
        && out.success
    {
        return Ok(MasqueradeBackend::IpTables);
    }

    if let Ok(out) = executor.run("nft", &["--version"])
        && out.success
    {
        return Ok(MasqueradeBackend::Nftables);
    }

    // If /proc/net/ip_tables_names exists but iptables failed to execute, report actionable failure
    if ip_tables_names.exists() {
        return Err(NetworkError::MasqueradeError {
            reason: "/proc/net/ip_tables_names is present but iptables binary is unavailable"
                .to_string(),
        });
    }

    Err(NetworkError::MasqueradeError {
        reason: "neither iptables (/proc/net/ip_tables_names) nor nftables (nft) is available on the host".to_string(),
    })
}

/// Ensures pod egress masquerade rules are present on the host system.
///
/// Automatically detects whether the host uses iptables or nftables.
/// Idempotent: repeated calls do not duplicate rules.
pub fn ensure_pod_masquerade(pod_cidr: &str) -> Result<MasqueradeBackend, NetworkError> {
    let executor = SystemCommandExecutor;
    let backend = detect_backend(None, &executor)?;
    ensure_pod_masquerade_with_backend_and_executor(pod_cidr, backend, &executor)?;
    Ok(backend)
}

/// Ensures pod egress masquerade rules using a specific backend and command executor.
pub fn ensure_pod_masquerade_with_backend_and_executor(
    pod_cidr: &str,
    backend: MasqueradeBackend,
    executor: &dyn CommandExecutor,
) -> Result<(), NetworkError> {
    match backend {
        MasqueradeBackend::IpTables => ensure_iptables_masquerade(pod_cidr, executor),
        MasqueradeBackend::Nftables => ensure_nftables_masquerade(pod_cidr, executor),
    }
}

fn ensure_iptables_masquerade(
    pod_cidr: &str,
    executor: &dyn CommandExecutor,
) -> Result<(), NetworkError> {
    // Check if rule already exists: iptables -w 5 -t nat -C POSTROUTING -s <pod_cidr> ! -d <pod_cidr> -m comment --comment ... -j MASQUERADE
    let check_args = [
        "-w",
        IPTABLES_WAIT_SECONDS,
        "-t",
        "nat",
        "-C",
        "POSTROUTING",
        "-s",
        pod_cidr,
        "!",
        "-d",
        pod_cidr,
        "-m",
        "comment",
        "--comment",
        MASQUERADE_COMMENT,
        "-j",
        "MASQUERADE",
    ];

    let check_res =
        executor
            .run("iptables", &check_args)
            .map_err(|e| NetworkError::MasqueradeError {
                reason: format!("failed to execute iptables check: {e}"),
            })?;

    if check_res.success {
        tracing::debug!(
            component = "network",
            cidr = %pod_cidr,
            "pod masquerade rule already present (iptables)"
        );
        return Ok(());
    }

    // Append rule: iptables -w 5 -t nat -A POSTROUTING -s <pod_cidr> ! -d <pod_cidr> -m comment --comment ... -j MASQUERADE
    let mut add_args = check_args;
    add_args[4] = "-A";

    let add_res =
        executor
            .run("iptables", &add_args)
            .map_err(|e| NetworkError::MasqueradeError {
                reason: format!("failed to execute iptables add: {e}"),
            })?;

    if !add_res.success {
        return Err(NetworkError::MasqueradeError {
            reason: format!(
                "iptables: failed to add pod masquerade rule: {}",
                add_res.stderr
            ),
        });
    }

    tracing::info!(
        component = "network",
        cidr = %pod_cidr,
        "added pod masquerade rule (iptables)"
    );

    Ok(())
}

fn nft_already_exists(stderr: &str, stdout: &str) -> bool {
    let lower_err = stderr.to_lowercase();
    let lower_out = stdout.to_lowercase();
    lower_err.contains("file exists")
        || lower_err.contains("already exists")
        || lower_out.contains("file exists")
        || lower_out.contains("already exists")
}

fn ensure_nft_object(
    list_args: &[&str],
    add_args: &[&str],
    executor: &dyn CommandExecutor,
) -> Result<(), NetworkError> {
    if let Ok(out) = executor.run("nft", list_args)
        && out.success
    {
        return Ok(());
    }

    let add_res = executor
        .run("nft", add_args)
        .map_err(|e| NetworkError::MasqueradeError {
            reason: format!("failed to run nft {}: {e}", add_args.join(" ")),
        })?;

    if !add_res.success && !nft_already_exists(&add_res.stderr, &add_res.stdout) {
        return Err(NetworkError::MasqueradeError {
            reason: format!(
                "nft {}: failed with error: {}",
                add_args.join(" "),
                add_res.stderr
            ),
        });
    }

    Ok(())
}

fn ensure_nftables_masquerade(
    pod_cidr: &str,
    executor: &dyn CommandExecutor,
) -> Result<(), NetworkError> {
    // 1. Ensure table kubesolo-masq
    ensure_nft_object(
        &["list", "table", "ip", DEFAULT_NFT_MASQ_TABLE],
        &["add", "table", "ip", DEFAULT_NFT_MASQ_TABLE],
        executor,
    )?;

    // 2. Ensure postrouting chain in kubesolo-masq table
    ensure_nft_object(
        &["list", "chain", "ip", DEFAULT_NFT_MASQ_TABLE, "postrouting"],
        &[
            "add",
            "chain",
            "ip",
            DEFAULT_NFT_MASQ_TABLE,
            "postrouting",
            "{ type nat hook postrouting priority srcnat; policy accept; }",
        ],
        executor,
    )?;

    // 3. Check if rule is already present in chain
    let chain_out = executor
        .run(
            "nft",
            &["list", "chain", "ip", DEFAULT_NFT_MASQ_TABLE, "postrouting"],
        )
        .map_err(|e| NetworkError::MasqueradeError {
            reason: format!("failed to list nft chain: {e}"),
        })?;

    let expected_cidr_match = format!("ip saddr {pod_cidr} ip daddr != {pod_cidr}");
    if chain_out.stdout.contains(MASQUERADE_COMMENT)
        && chain_out.stdout.contains(&expected_cidr_match)
    {
        tracing::debug!(
            component = "network",
            table = %DEFAULT_NFT_MASQ_TABLE,
            "pod masquerade rule already present (nftables)"
        );
        return Ok(());
    }

    // 4. Add rule: nft add rule ip kubesolo-masq postrouting ip saddr <pod_cidr> ip daddr != <pod_cidr> masquerade comment "\"kubesolo: pod masquerade\""
    let comment_arg = format!("\"{MASQUERADE_COMMENT}\"");
    let add_rule_args = [
        "add",
        "rule",
        "ip",
        DEFAULT_NFT_MASQ_TABLE,
        "postrouting",
        "ip",
        "saddr",
        pod_cidr,
        "ip",
        "daddr",
        "!=",
        pod_cidr,
        "masquerade",
        "comment",
        &comment_arg,
    ];

    let add_res =
        executor
            .run("nft", &add_rule_args)
            .map_err(|e| NetworkError::MasqueradeError {
                reason: format!("failed to add nft rule: {e}"),
            })?;

    if !add_res.success {
        return Err(NetworkError::MasqueradeError {
            reason: format!(
                "nft add rule failed: {} (output: {})",
                add_res.stderr, add_res.stdout
            ),
        });
    }

    tracing::info!(
        component = "network",
        cidr = %pod_cidr,
        table = %DEFAULT_NFT_MASQ_TABLE,
        "added pod masquerade rule (nftables)"
    );

    Ok(())
}

/// Cleans pod egress masquerade rules from the host system.
///
/// Idempotent: repeated clean calls neither error nor flush unrelated NAT state.
pub fn clean_pod_masquerade(pod_cidr: &str) -> Result<(), NetworkError> {
    let executor = SystemCommandExecutor;
    let backend = detect_backend(None, &executor)?;
    clean_pod_masquerade_with_backend_and_executor(pod_cidr, backend, &executor)
}

/// Cleans pod egress masquerade rules using a specific backend and command executor.
///
/// Ensures unrelated NAT state is strictly preserved:
/// - In iptables: only the matching rule is deleted (`-D`); the chain and table are NEVER flushed.
/// - In nftables: only the owned `kubesolo-masq` table is removed; `table ip nat` and other tables are NEVER touched.
pub fn clean_pod_masquerade_with_backend_and_executor(
    pod_cidr: &str,
    backend: MasqueradeBackend,
    executor: &dyn CommandExecutor,
) -> Result<(), NetworkError> {
    match backend {
        MasqueradeBackend::IpTables => {
            let del_args = [
                "-w",
                IPTABLES_WAIT_SECONDS,
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                pod_cidr,
                "!",
                "-d",
                pod_cidr,
                "-m",
                "comment",
                "--comment",
                MASQUERADE_COMMENT,
                "-j",
                "MASQUERADE",
            ];

            // Loop to delete any duplicate rules that may exist, stopping when none remain
            loop {
                let out = match executor.run("iptables", &del_args) {
                    Ok(out) => out,
                    Err(e) => {
                        return Err(NetworkError::MasqueradeError {
                            reason: format!("failed to execute iptables delete: {e}"),
                        });
                    },
                };
                if out.success {
                    continue;
                }
                // Exit code 1 with "Bad rule" or "does a matching rule exist" indicates the rule is absent.
                if out.stderr.contains("Bad rule")
                    || out.stderr.contains("does a matching rule exist")
                    || out.stderr.contains("No chain/target/match by that name")
                {
                    break;
                }
                return Err(NetworkError::MasqueradeError {
                    reason: format!("iptables delete failed: {}", out.stderr),
                });
            }
            Ok(())
        },
        MasqueradeBackend::Nftables => {
            // Delete our dedicated table `ip kubesolo-masq`.
            // Crucial: this never flushes or touches system tables such as `table ip nat` or Podman netavark.
            let del_args = ["delete", "table", "ip", DEFAULT_NFT_MASQ_TABLE];
            let out =
                executor
                    .run("nft", &del_args)
                    .map_err(|e| NetworkError::MasqueradeError {
                        reason: format!("failed to execute nft delete table: {e}"),
                    })?;
            if !out.success
                && !out.stderr.contains("No such file or directory")
                && !out.stderr.contains("does not exist")
            {
                return Err(NetworkError::MasqueradeError {
                    reason: format!("nft delete table failed: {}", out.stderr),
                });
            }
            Ok(())
        },
    }
}

/// Report summarizing complete node network preparation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPreparationReport {
    pub backend: MasqueradeBackend,
    pub pod_cidr: String,
    pub ip_forward_verified: bool,
    pub ipv6_disabled: bool,
}

/// Prepares node networking before Kubelet starts and reconciles persisted pods:
/// 1. Optionally disables IPv6 sysctls (with read-only already-correct tolerance).
/// 2. Ensures `net.ipv4.ip_forward` is enabled (with read-only already-correct tolerance).
/// 3. Establishes owned pod egress masquerade rules (via iptables or nftables).
pub fn prepare_node_network(
    pod_cidr: Option<&str>,
    disable_ipv6: bool,
    sysctl_root: Option<&Path>,
    executor: &dyn CommandExecutor,
) -> Result<NetworkPreparationReport, NetworkError> {
    let cidr = pod_cidr.unwrap_or(DEFAULT_POD_CIDR);

    // 1. IPv6 disablement if requested
    if disable_ipv6 {
        let root = sysctl_root.unwrap_or_else(|| Path::new("/proc/sys"));
        crate::ipv6::disable_ipv6_sysctls_in_root(root)?;
    }

    // 2. IP forwarding
    let root = sysctl_root.unwrap_or_else(|| Path::new("/proc/sys"));
    crate::sysctl::ensure_ip_forward_in_root(root)?;

    // 3. Masquerade
    let backend = detect_backend(sysctl_root, executor)?;
    ensure_pod_masquerade_with_backend_and_executor(cidr, backend, executor)?;

    Ok(NetworkPreparationReport {
        backend,
        pod_cidr: cidr.to_string(),
        ip_forward_verified: true,
        ipv6_disabled: disable_ipv6,
    })
}

/// In-memory mock command executor for simulating iptables and nftables operations.
#[derive(Debug, Default)]
pub struct MockCommandExecutor {
    pub iptables_available: bool,
    pub nft_available: bool,
    pub iptables_rules: Mutex<Vec<String>>,
    pub nft_tables: Mutex<Vec<String>>,
    pub nft_chains: Mutex<Vec<String>>,
    pub nft_rules: Mutex<Vec<String>>,
    pub unrelated_nat_rules: Mutex<Vec<String>>,
    pub command_log: Mutex<Vec<String>>,
}

impl MockCommandExecutor {
    #[must_use]
    pub fn new_iptables_host() -> Self {
        let executor = Self {
            iptables_available: true,
            nft_available: false,
            ..Default::default()
        };
        executor
            .unrelated_nat_rules
            .lock()
            .unwrap()
            .push("unrelated-nat-rule-1".to_string());
        executor
    }

    #[must_use]
    pub fn new_nftables_host() -> Self {
        let executor = Self {
            iptables_available: false,
            nft_available: true,
            ..Default::default()
        };
        executor
            .unrelated_nat_rules
            .lock()
            .unwrap()
            .push("table ip nat { chain postrouting { ... } }".to_string());
        executor.nft_tables.lock().unwrap().push("nat".to_string());
        executor
    }

    #[must_use]
    pub fn has_owned_iptables_masq_rule(&self) -> bool {
        self.iptables_rules
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.contains(MASQUERADE_COMMENT))
    }

    #[must_use]
    pub fn owned_iptables_rule_count(&self) -> usize {
        self.iptables_rules
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.contains(MASQUERADE_COMMENT))
            .count()
    }

    #[must_use]
    pub fn has_owned_nft_masq_rule(&self) -> bool {
        self.nft_rules
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.contains(MASQUERADE_COMMENT))
    }

    #[must_use]
    pub fn owned_nft_rule_count(&self) -> usize {
        self.nft_rules
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.contains(MASQUERADE_COMMENT))
            .count()
    }

    #[must_use]
    pub fn unrelated_nat_rules_count(&self) -> usize {
        self.unrelated_nat_rules.lock().unwrap().len()
    }

    fn handle_iptables(
        &self,
        args: &[&str],
        cmd_str: &str,
    ) -> Result<CommandOutput, std::io::Error> {
        if !self.iptables_available {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "iptables command not found",
            ));
        }

        if args.first() == Some(&"--version") {
            return Ok(CommandOutput {
                success: true,
                stdout: "iptables v1.8.10 (nf_tables)\n".to_string(),
                stderr: String::new(),
            });
        }

        let mut rules = self.iptables_rules.lock().unwrap();

        if args.contains(&"-C") {
            let present = rules.iter().any(|r| r.contains(MASQUERADE_COMMENT));
            return Ok(CommandOutput {
                success: present,
                stdout: String::new(),
                stderr: if present {
                    String::new()
                } else {
                    "iptables: Bad rule (does a matching rule exist in that chain?)\n".to_string()
                },
            });
        }

        if args.contains(&"-S") {
            let mut out = String::new();
            for r in rules.iter() {
                let _ = writeln!(out, "{r}");
            }
            return Ok(CommandOutput {
                success: true,
                stdout: out,
                stderr: String::new(),
            });
        }

        if let Some(pos) = args.iter().position(|&a| a == "-F" || a == "-X") {
            let chain_opt = args.get(pos + 1).copied();
            if let Some(chain) = chain_opt
                && !chain.starts_with('-')
            {
                let pattern = format!("-A {chain}");
                rules.retain(|r| !r.contains(&pattern));
            } else {
                rules.clear();
                self.unrelated_nat_rules.lock().unwrap().clear();
            }
            return Ok(CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        if args.contains(&"-A") {
            rules.push(cmd_str.to_string());
            return Ok(CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        if args.contains(&"-D") {
            if let Some(idx) = rules.iter().position(|r| r.contains(MASQUERADE_COMMENT)) {
                rules.remove(idx);
                return Ok(CommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                });
            }
            return Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "iptables: Bad rule (does a matching rule exist in that chain?)\n"
                    .to_string(),
            });
        }

        Ok(CommandOutput {
            success: true,
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    fn handle_nft(&self, args: &[&str], cmd_str: &str) -> Result<CommandOutput, std::io::Error> {
        if !self.nft_available {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "nft command not found",
            ));
        }

        if args.first() == Some(&"--version") {
            return Ok(CommandOutput {
                success: true,
                stdout: "nftables v1.0.9 (Community Edition)\n".to_string(),
                stderr: String::new(),
            });
        }

        match args.first().copied() {
            Some("list") => Ok(self.handle_nft_list(args)),
            Some("add") => Ok(self.handle_nft_add(args, cmd_str)),
            Some("flush") if args.get(1) == Some(&"table") => {
                let target = args.get(3).copied().unwrap_or_default();
                self.nft_rules
                    .lock()
                    .unwrap()
                    .retain(|r| r.split_whitespace().nth(4) != Some(target));
                if target == "nat" {
                    self.unrelated_nat_rules.lock().unwrap().clear();
                }
                Ok(CommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            },
            Some("delete") if args.get(1) == Some(&"table") => {
                let target = args.get(3).copied().unwrap_or_default();
                self.nft_tables.lock().unwrap().retain(|t| t != target);
                self.nft_chains.lock().unwrap().clear();
                self.nft_rules
                    .lock()
                    .unwrap()
                    .retain(|r| r.split_whitespace().nth(4) != Some(target));
                Ok(CommandOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            },
            _ => Ok(CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
        }
    }

    fn handle_nft_list(&self, args: &[&str]) -> CommandOutput {
        if args.get(1) == Some(&"tables") {
            let tables = self.nft_tables.lock().unwrap();
            let mut out = String::new();
            for t in tables.iter() {
                let _ = writeln!(out, "table ip {t}");
            }
            return CommandOutput {
                success: true,
                stdout: out,
                stderr: String::new(),
            };
        }
        if args.get(1) == Some(&"table") {
            let tables = self.nft_tables.lock().unwrap();
            let target = args.get(3).copied().unwrap_or_default();
            let exists = tables.iter().any(|t| t == target);
            let rules = self.nft_rules.lock().unwrap();
            let mut body = String::new();
            for r in rules.iter() {
                if r.split_whitespace().nth(4) == Some(target) {
                    let _ = writeln!(body, "    {r}");
                }
            }
            return CommandOutput {
                success: exists,
                stdout: if exists {
                    format!("table ip {target} {{\n{body}}}\n")
                } else {
                    String::new()
                },
                stderr: if exists {
                    String::new()
                } else {
                    "Error: No such file or directory\n".to_string()
                },
            };
        }
        if args.get(1) == Some(&"chain") {
            let chains = self.nft_chains.lock().unwrap();
            let rules = self.nft_rules.lock().unwrap();
            let target = args.get(4).copied().unwrap_or_default();
            let exists = chains.iter().any(|c| c == target);
            let mut body = String::new();
            for r in rules.iter() {
                let _ = writeln!(body, "    {r}");
            }
            return CommandOutput {
                success: exists,
                stdout: if exists {
                    format!("chain {target} {{\n{body}}}\n")
                } else {
                    String::new()
                },
                stderr: if exists {
                    String::new()
                } else {
                    "Error: No such file or directory\n".to_string()
                },
            };
        }
        CommandOutput::default()
    }

    fn handle_nft_add(&self, args: &[&str], cmd_str: &str) -> CommandOutput {
        if args.get(1) == Some(&"table") {
            let target = args.get(3).copied().unwrap_or_default().to_string();
            let mut tables = self.nft_tables.lock().unwrap();
            if !tables.contains(&target) {
                tables.push(target);
            }
            return CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            };
        }
        if args.get(1) == Some(&"chain") {
            let target = args.get(4).copied().unwrap_or_default().to_string();
            let mut chains = self.nft_chains.lock().unwrap();
            if !chains.contains(&target) {
                chains.push(target);
            }
            return CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            };
        }
        if args.get(1) == Some(&"rule") {
            self.nft_rules.lock().unwrap().push(cmd_str.to_string());
            return CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            };
        }
        CommandOutput::default()
    }
}

impl CommandExecutor for MockCommandExecutor {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandOutput, std::io::Error> {
        let cmd_str = format!("{program} {}", args.join(" "));
        self.command_log.lock().unwrap().push(cmd_str.clone());

        match program {
            "iptables" => self.handle_iptables(args, &cmd_str),
            "nft" => self.handle_nft(args, &cmd_str),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unsupported mock command",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_in_cidr() {
        assert!(ipv4_in_cidr("10.42.0.1", "10.42.0.0/16"));
        assert!(ipv4_in_cidr("10.42.255.254", "10.42.0.0/16"));
        assert!(!ipv4_in_cidr("10.43.0.1", "10.42.0.0/16"));
        assert!(!ipv4_in_cidr("1.1.1.1", "10.42.0.0/16"));
        assert!(ipv4_in_cidr("192.168.1.50", "192.168.1.0/24"));
        assert!(!ipv4_in_cidr("192.168.2.50", "192.168.1.0/24"));
    }

    #[test]
    fn test_evaluate_egress_traffic() {
        let cidr = "10.42.0.0/16";

        // Pod to external: masquerade
        assert_eq!(
            evaluate_egress_traffic("10.42.0.10", "1.1.1.1", cidr),
            EgressDecision::Masquerade {
                source_ip: "10.42.0.10".to_string(),
                destination_ip: "1.1.1.1".to_string(),
            }
        );

        // Pod to pod: direct (unmasqueraded)
        assert_eq!(
            evaluate_egress_traffic("10.42.0.10", "10.42.1.25", cidr),
            EgressDecision::Direct {
                source_ip: "10.42.0.10".to_string(),
                destination_ip: "10.42.1.25".to_string(),
            }
        );

        // Non-pod traffic: no match
        assert_eq!(
            evaluate_egress_traffic("192.168.1.100", "8.8.8.8", cidr),
            EgressDecision::NoMatch
        );
    }

    #[test]
    fn test_iptables_setup_idempotency_and_cleanup_preserves_unrelated() {
        let executor = MockCommandExecutor::new_iptables_host();
        let cidr = "10.42.0.0/16";

        // Initial setup
        ensure_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::IpTables,
            &executor,
        )
        .expect("initial setup");
        assert!(executor.has_owned_iptables_masq_rule());
        assert_eq!(executor.owned_iptables_rule_count(), 1);

        // Repeated setup does NOT duplicate
        ensure_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::IpTables,
            &executor,
        )
        .expect("repeated setup");
        assert_eq!(executor.owned_iptables_rule_count(), 1);

        // Unrelated NAT rules are untouched
        assert_eq!(executor.unrelated_nat_rules_count(), 1);

        // Cleanup removes the rule without touching unrelated NAT rules
        clean_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::IpTables,
            &executor,
        )
        .expect("cleanup");
        assert!(!executor.has_owned_iptables_masq_rule());
        assert_eq!(executor.unrelated_nat_rules_count(), 1);

        // Repeated cleanup is a no-op and does not error
        clean_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::IpTables,
            &executor,
        )
        .expect("repeated cleanup");
        assert!(!executor.has_owned_iptables_masq_rule());
        assert_eq!(executor.unrelated_nat_rules_count(), 1);
    }

    #[test]
    fn test_nftables_setup_idempotency_and_cleanup_preserves_unrelated() {
        let executor = MockCommandExecutor::new_nftables_host();
        let cidr = "10.42.0.0/16";

        // Initial setup
        ensure_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::Nftables,
            &executor,
        )
        .expect("initial setup");
        assert!(executor.has_owned_nft_masq_rule());
        assert_eq!(executor.owned_nft_rule_count(), 1);

        // Repeated setup does NOT duplicate
        ensure_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::Nftables,
            &executor,
        )
        .expect("repeated setup");
        assert_eq!(executor.owned_nft_rule_count(), 1);

        // Unrelated NAT rules (e.g. table ip nat) are untouched
        assert_eq!(executor.unrelated_nat_rules_count(), 1);

        // Cleanup deletes only kubesolo-masq table, never table ip nat
        clean_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::Nftables,
            &executor,
        )
        .expect("cleanup");
        assert!(!executor.has_owned_nft_masq_rule());
        assert_eq!(executor.unrelated_nat_rules_count(), 1);

        // Repeated cleanup is a no-op and does not error
        clean_pod_masquerade_with_backend_and_executor(
            cidr,
            MasqueradeBackend::Nftables,
            &executor,
        )
        .expect("repeated cleanup");
        assert_eq!(executor.unrelated_nat_rules_count(), 1);
    }
}
