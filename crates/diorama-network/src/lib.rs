//! Node networking inputs, IP/MTU resolution, CNI configuration, resolv.conf handling and IPv4-only configuration.

pub mod cni;
pub mod discovery;
pub mod error;
pub mod ip;
pub mod ipv6;
pub mod masquerade;
pub mod model;
pub mod mtu;
pub mod resolver;
pub mod sysctl;

pub use cni::{
    CNI_CONFIG_EXTENSIONS, CniOrderingInspection, DEFAULT_BRIDGE_NAME, DEFAULT_CNI_CONFIG_NAME,
    DEFAULT_POD_CIDR, DEFAULT_STANDARD_CNI_BIN_DIR, DEFAULT_STANDARD_CNI_CONF_DIR,
    REQUIRED_CNI_PLUGINS, generate_cni_config, generate_cni_config_json, inspect_cni_dir_ordering,
    remove_if_symlink, warn_missing_cni_plugins, write_cni_config_file, write_external_cni_config,
    write_managed_cni_config,
};
pub use discovery::{discover_host_interfaces, get_node_ip, get_node_mtu};
pub use error::NetworkError;
pub use ip::{
    classify_ipv4, get_local_ips, is_dns_name, is_global_unicast, is_ipv4_address, is_local_ip,
    is_valid_nameserver, resolve_load_balancer_ip, resolve_node_ip, select_node_ip,
};
pub use ipv6::{disable_ipv6_sysctls, disable_ipv6_sysctls_in_root, is_ignorable_sysctl_error};
pub use masquerade::{
    CommandExecutor, CommandOutput, DEFAULT_NFT_MASQ_TABLE, EgressDecision, IPTABLES_WAIT_SECONDS,
    MASQUERADE_COMMENT, MasqueradeBackend, MockCommandExecutor, NetworkPreparationReport,
    SystemCommandExecutor, clean_pod_masquerade, clean_pod_masquerade_with_backend_and_executor,
    detect_backend, ensure_pod_masquerade, ensure_pod_masquerade_with_backend_and_executor,
    evaluate_egress_traffic, ipv4_in_cidr, prepare_node_network,
};
pub use model::{
    DEFAULT_MTU, FALLBACK_NAMESERVERS, INSTANCE_METADATA_SERVICE_IP, InterfaceCandidate,
    MAX_NAMESERVERS, MAX_VALID_MTU, MIN_VALID_MTU,
};
pub use mtu::{resolve_mtu, select_mtu};
pub use resolver::{
    get_host_resolv_conf, get_host_resolv_conf_with_candidates, is_valid_resolv_conf,
    sanitize_resolv_conf,
};
pub use sysctl::{
    IP_FORWARD_SYSCTL_REL_PATH, ensure_ip_forward, ensure_ip_forward_in_root, ensure_sysctl_value,
    read_sysctl,
};
