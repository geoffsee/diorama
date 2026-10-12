#[cfg(target_os = "linux")]
use std::fs;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
#[cfg(target_os = "linux")]
use std::path::Path;

use crate::error::NetworkError;
use crate::ip::select_node_ip;
use crate::model::{DEFAULT_MTU, InterfaceCandidate};
use crate::mtu::select_mtu;

/// Discovers candidate network interfaces from the host environment.
#[must_use]
pub fn discover_host_interfaces() -> Vec<InterfaceCandidate> {
    #[cfg(target_os = "linux")]
    let mut candidates = discover_linux_sysfs_interfaces();

    #[cfg(not(target_os = "linux"))]
    let mut candidates: Vec<InterfaceCandidate> = Vec::new();

    // If no non-loopback candidate has an address, fallback to UDP routing detection
    let has_non_loopback_addr = candidates
        .iter()
        .any(|c| !c.is_loopback && !c.addrs.is_empty());
    if !has_non_loopback_addr {
        candidates = discover_udp_routing_interfaces();
    }

    candidates
}

/// Discovers the active outbound interface IP using safe UDP routing table lookup.
fn discover_udp_routing_interfaces() -> Vec<InterfaceCandidate> {
    let mut candidates = Vec::new();

    // Probe 1: Public internet gateway route
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0")
        && socket.connect("8.8.8.8:80").is_ok()
        && let Ok(local_addr) = socket.local_addr()
        && let IpAddr::V4(ipv4) = local_addr.ip()
        && !ipv4.is_loopback()
    {
        candidates.push(InterfaceCandidate {
            name: "default".to_string(),
            mtu: DEFAULT_MTU,
            addrs: vec![IpAddr::V4(ipv4)],
            is_up: true,
            is_loopback: false,
        });
    }

    // Probe 2: RFC 1918 private route probes (in case host default route is private only)
    for probe_dest in [
        "10.255.255.255:80",
        "172.31.255.255:80",
        "192.168.255.255:80",
    ] {
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0")
            && socket.connect(probe_dest).is_ok()
            && let Ok(local_addr) = socket.local_addr()
            && let IpAddr::V4(ipv4) = local_addr.ip()
            && !ipv4.is_loopback()
            && !candidates
                .iter()
                .any(|c| c.addrs.contains(&IpAddr::V4(ipv4)))
        {
            candidates.push(InterfaceCandidate {
                name: format!("probe-{}", candidates.len()),
                mtu: DEFAULT_MTU,
                addrs: vec![IpAddr::V4(ipv4)],
                is_up: true,
                is_loopback: false,
            });
        }
    }

    // Always include loopback
    candidates.push(InterfaceCandidate {
        name: "lo".to_string(),
        mtu: 65536,
        addrs: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        is_up: true,
        is_loopback: true,
    });

    candidates
}

#[cfg(target_os = "linux")]
fn get_default_route_interface() -> Option<String> {
    let content = fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let mut parts = line.split_whitespace();
        let iface = parts.next()?;
        let dest = parts.next()?;
        if dest == "00000000" {
            return Some(iface.to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn discover_linux_sysfs_interfaces() -> Vec<InterfaceCandidate> {
    let sys_net = Path::new("/sys/class/net");
    let Ok(entries) = fs::read_dir(sys_net) else {
        return Vec::new();
    };

    let default_iface = get_default_route_interface();

    // Check outbound route IP to associate with the appropriate interface
    let routed_ip = UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|s| s.connect("8.8.8.8:80").ok().map(|()| s))
        .and_then(|s| s.local_addr().ok())
        .and_then(|a| match a.ip() {
            IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
            _ => None,
        });

    let mut candidates = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();

        let mtu = fs::read_to_string(path.join("mtu"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(DEFAULT_MTU);

        let flags_hex = fs::read_to_string(path.join("flags"))
            .ok()
            .and_then(|s| {
                let stripped = s.trim().strip_prefix("0x").unwrap_or(s.trim());
                u32::from_str_radix(stripped, 16).ok()
            })
            .unwrap_or(0);

        let is_loopback = (flags_hex & 0x8) != 0 || name == "lo";
        let is_up = (flags_hex & 0x1) != 0;

        let mut addrs = Vec::new();
        if is_loopback {
            addrs.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
        } else if let Some(ip) = routed_ip
            && let Some(ref def_iface) = default_iface
            && name == *def_iface
        {
            addrs.push(IpAddr::V4(ip));
        }

        candidates.push(InterfaceCandidate {
            name,
            mtu,
            addrs,
            is_up,
            is_loopback,
        });
    }

    // If default_iface was not found or did not match any entry, assign routed_ip to the first active non-loopback interface
    if let Some(ip) = routed_ip
        && !candidates
            .iter()
            .any(|c| !c.is_loopback && !c.addrs.is_empty())
    {
        for candidate in &mut candidates {
            if !candidate.is_loopback && candidate.is_up {
                candidate.addrs.push(IpAddr::V4(ip));
                break;
            }
        }
    }

    candidates
}

/// Returns a non-loopback IPv4 address of the node, preferring private addresses.
pub fn get_node_ip() -> Result<Ipv4Addr, NetworkError> {
    let candidates = discover_host_interfaces();
    select_node_ip(&candidates)
}

/// Returns the MTU of the primary interface selected by `get_node_ip`.
pub fn get_node_mtu() -> Result<u32, NetworkError> {
    let candidates = discover_host_interfaces();
    select_mtu(&candidates)
}
