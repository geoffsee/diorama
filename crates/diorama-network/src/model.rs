use std::net::{IpAddr, Ipv4Addr};

/// Default fallback MTU when interface MTU detection fails or interface is missing.
pub const DEFAULT_MTU: u32 = 1500;

/// Minimum valid MTU per RFC 791 IPv4 specification.
pub const MIN_VALID_MTU: u32 = 68;

/// Maximum valid MTU representable in Linux netlink / network interfaces.
pub const MAX_VALID_MTU: u32 = 65535;

/// Maximum nameservers retained in `/etc/resolv.conf` (Linux `MAXNS` limit in libc/kubelet).
pub const MAX_NAMESERVERS: usize = 3;

/// Cloud provider instance metadata service IP (169.254.169.254).
/// Allowed as a valid upstream nameserver even though in link-local range.
pub const INSTANCE_METADATA_SERVICE_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// Public fallback DNS servers generated when no valid host resolv.conf is found.
pub const FALLBACK_NAMESERVERS: [&str; 2] = ["8.8.8.8", "1.1.1.1"];

/// Candidate network interface data for node IP and MTU selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceCandidate {
    pub name: String,
    pub mtu: u32,
    pub addrs: Vec<IpAddr>,
    pub is_up: bool,
    pub is_loopback: bool,
}

impl InterfaceCandidate {
    /// Creates a new candidate interface.
    #[must_use]
    pub fn new(name: impl Into<String>, mtu: u32, addrs: Vec<IpAddr>) -> Self {
        let name = name.into();
        let is_loopback = name == "lo" || addrs.iter().all(IpAddr::is_loopback);
        Self {
            name,
            mtu,
            addrs,
            is_up: true,
            is_loopback,
        }
    }
}
