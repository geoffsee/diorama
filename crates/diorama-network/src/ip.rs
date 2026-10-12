use std::net::{IpAddr, Ipv4Addr};

use crate::error::NetworkError;
use crate::model::{INSTANCE_METADATA_SERVICE_IP, InterfaceCandidate};

/// Returns true if the string is a valid dot-decimal IPv4 address.
#[must_use]
pub fn is_ipv4_address(s: &str) -> bool {
    let Ok(ip) = s.parse::<IpAddr>() else {
        return false;
    };
    matches!(ip, IpAddr::V4(_))
}

/// Returns true if the string is a valid RFC 1123 compliant DNS name.
#[must_use]
pub fn is_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }

    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    true
}

/// Returns true if the IP is global unicast, matching Go/Kubernetes net.IP.IsGlobalUnicast semantics.
#[must_use]
pub fn is_global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_broadcast()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_unspecified()
        },
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                // Link-local unicast fe80::/10
                && ((v6.segments()[0] & 0xffc0) != 0xfe80)
        },
    }
}

/// Returns true if the address string is a valid upstream resolver address.
/// Global unicast addresses or the instance metadata service IP (169.254.169.254) are accepted.
#[must_use]
pub fn is_valid_nameserver(addr: &str) -> bool {
    let Ok(ip) = addr.trim().parse::<IpAddr>() else {
        return false;
    };
    if let IpAddr::V4(v4) = ip
        && v4 == INSTANCE_METADATA_SERVICE_IP
    {
        return true;
    }
    is_global_unicast(ip)
}

/// Classifies an IP address. If it is a non-loopback IPv4 address, returns (`Ipv4Addr`, `is_private`).
#[must_use]
pub fn classify_ipv4(addr: IpAddr) -> Option<(Ipv4Addr, bool)> {
    match addr {
        IpAddr::V4(v4) if !v4.is_loopback() => Some((v4, v4.is_private())),
        _ => None,
    }
}

/// Selects a node IP from candidate network interfaces, preferring private IPv4 addresses
/// and falling back to any non-loopback IPv4 address.
pub fn select_node_ip(candidates: &[InterfaceCandidate]) -> Result<Ipv4Addr, NetworkError> {
    let mut first_non_loopback: Option<Ipv4Addr> = None;

    for candidate in candidates {
        for &addr in &candidate.addrs {
            let Some((ipv4, is_private)) = classify_ipv4(addr) else {
                continue;
            };
            if is_private {
                return Ok(ipv4);
            }
            if first_non_loopback.is_none() {
                first_non_loopback = Some(ipv4);
            }
        }
    }

    if let Some(ip) = first_non_loopback {
        return Ok(ip);
    }

    Err(NetworkError::NoUsableInterface {
        reason: "could not find non-loopback IPv4 address".to_string(),
    })
}

/// Reports whether `ip` is bound to one of the host's candidate interfaces (or loopback).
#[must_use]
pub fn is_local_ip(ip: &str, candidates: &[InterfaceCandidate]) -> bool {
    let Ok(target) = ip.trim().parse::<IpAddr>() else {
        return false;
    };
    if target.is_loopback() {
        return true;
    }
    for candidate in candidates {
        if candidate.addrs.contains(&target) {
            return true;
        }
    }
    false
}

/// Returns all local IPv4 addresses across candidates, always appending 127.0.0.1.
#[must_use]
pub fn get_local_ips(candidates: &[InterfaceCandidate]) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    for candidate in candidates {
        for &addr in &candidate.addrs {
            if let IpAddr::V4(v4) = addr
                && !v4.is_loopback()
                && !ips.contains(&v4)
            {
                ips.push(v4);
            }
        }
    }
    ips.push(Ipv4Addr::LOCALHOST);
    ips
}

/// Resolves the node IP to advertise and whether it was explicitly pinned via a valid override.
///
/// If `override_ip` is empty or None, auto-detects via `select_node_ip`.
/// If `override_ip` is not a valid IPv4 address, logs a warning and falls back to auto-detection (not pinned).
/// If `override_ip` is a valid IPv4 address, returns it as pinned (warning if not bound locally, e.g. VIP).
pub fn resolve_node_ip(
    override_ip: Option<&str>,
    candidates: &[InterfaceCandidate],
) -> Result<(Ipv4Addr, bool), NetworkError> {
    let trimmed = override_ip.map_or("", str::trim);
    if trimmed.is_empty() {
        let ip = select_node_ip(candidates)?;
        return Ok((ip, false));
    }

    if !is_ipv4_address(trimmed) {
        tracing::warn!(
            component = "network",
            node_ip = trimmed,
            "--node-ip is not a valid IPv4 address; ignoring it and auto-detecting the node IP"
        );
        let ip = select_node_ip(candidates)?;
        return Ok((ip, false));
    }

    let parsed: Ipv4Addr = trimmed.parse().map_err(|e| NetworkError::InvalidNodeIP {
        ip: trimmed.to_string(),
        reason: format!("{e}"),
    })?;

    if !is_local_ip(trimmed, candidates) {
        tracing::warn!(
            component = "network",
            node_ip = trimmed,
            "--node-ip is not bound to a local interface; using it anyway (e.g. VIP)"
        );
    }

    Ok((parsed, true))
}

/// Resolves the `LoadBalancer` EXTERNAL-IP to publish.
///
/// Falls back to `node_ip` if the override is empty or not a valid IPv4 address.
#[must_use]
pub fn resolve_load_balancer_ip(
    override_ip: Option<&str>,
    node_ip: &str,
    candidates: &[InterfaceCandidate],
) -> String {
    let trimmed = override_ip.map_or("", str::trim);
    if trimmed.is_empty() {
        return node_ip.to_string();
    }

    if !is_ipv4_address(trimmed) {
        tracing::warn!(
            component = "network",
            load_balancer_ip = trimmed,
            "--load-balancer-ip is not a valid IPv4 address; falling back to the node IP"
        );
        return node_ip.to_string();
    }

    if !is_local_ip(trimmed, candidates) {
        tracing::warn!(
            component = "network",
            load_balancer_ip = trimmed,
            "--load-balancer-ip is not bound to a local interface; using it anyway (e.g. VIP)"
        );
    }

    trimmed.to_string()
}
