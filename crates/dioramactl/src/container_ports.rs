//! Container port specification parser and validator.
//!
//! Matches Portainer `KubeSolo` `internal/cli/service/ports.go` behavior at commit `2ef1c4787989f11f868f81bb84ae2afd4a49a81d`.
//! Validates specs before container or network creation and produces normalized port mappings.

use std::collections::HashSet;
use std::fmt;

/// Validated container port mapping.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PortMapping {
    /// Host IP to bind to; omitted addresses default to loopback.
    pub host_ip: String,
    /// Host port number.
    pub host_port: u16,
    /// Container port number.
    pub container_port: u16,
    /// Network protocol (`tcp` or `udp`).
    pub protocol: String,
}

impl PortMapping {
    /// Formats the port key for Docker Engine `PortBindings` map: `<container_port>/<protocol>`.
    pub fn container_port_key(&self) -> String {
        format!("{}/{}", self.container_port, self.protocol)
    }
}

/// Errors returned when parsing container port specifications.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortParseError {
    /// Port string or component is empty.
    EmptyPortSpec,
    /// Format does not match any valid port specification pattern.
    InvalidFormat(String),
    /// Invalid port number (not in 1..=65535 or not an integer).
    InvalidPortNumber(String),
    /// Port range start is greater than range end.
    InvalidRange(String),
    /// Unsupported protocol (only `tcp` and `udp` are supported).
    UnsupportedProtocol(String),
    /// Duplicate host port binding.
    DuplicateHostPort(u16, String),
    /// Duplicate container port binding.
    DuplicateContainerPort(u16, String),
}

impl fmt::Display for PortParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPortSpec => write!(f, "empty container port specification"),
            Self::InvalidFormat(s) => write!(f, "invalid port specification: \"{s}\""),
            Self::InvalidPortNumber(s) => write!(f, "invalid port number: \"{s}\""),
            Self::InvalidRange(s) => {
                write!(f, "invalid port range (start must be <= end): \"{s}\"")
            },
            Self::UnsupportedProtocol(s) => {
                write!(f, "unsupported protocol \"{s}\"; supported are tcp and udp")
            },
            Self::DuplicateHostPort(port, proto) => {
                write!(f, "duplicate host port {port}/{proto} in container ports")
            },
            Self::DuplicateContainerPort(port, proto) => {
                write!(
                    f,
                    "duplicate container port {port}/{proto} in container ports"
                )
            },
        }
    }
}

impl std::error::Error for PortParseError {}

/// Parses and validates a comma-separated list of container port specifications.
///
/// Supported formats:
/// - Bare port: `9001` -> `9001:9001/tcp`
/// - Bare range: `9000-9002` -> `9000:9000/tcp`, `9001:9001/tcp`, `9002:9002/tcp`
/// - Explicit mapping: `8080:80` -> `8080:80/tcp`
/// - Explicit range: `8000-8002:9000-9002` (ranges must have equal length)
/// - Host IP bound: `127.0.0.1:8080:80`
/// - Protocol suffix: `53/udp`, `53:53/udp`, `127.0.0.1:53:53/udp`
///
/// Validates:
/// - Protocols: `tcp`, `udp` (case-insensitive)
/// - Range bounds: start <= end, valid 1..=65535
/// - No duplicate host port bindings within the spec list
/// - No duplicate container port bindings within the spec list
pub fn parse_container_ports(input: &str) -> Result<Vec<PortMapping>, PortParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let mut mappings = Vec::new();
    let mut seen_host_ports = HashSet::new();
    let mut seen_container_ports = HashSet::new();

    for spec in trimmed.split(',') {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }

        let parsed = parse_single_spec(spec)?;
        for mapping in parsed {
            let host_key = (mapping.host_port, mapping.protocol.clone());
            if !seen_host_ports.insert(host_key) {
                return Err(PortParseError::DuplicateHostPort(
                    mapping.host_port,
                    mapping.protocol,
                ));
            }

            let container_key = (mapping.container_port, mapping.protocol.clone());
            if !seen_container_ports.insert(container_key) {
                return Err(PortParseError::DuplicateContainerPort(
                    mapping.container_port,
                    mapping.protocol,
                ));
            }

            mappings.push(mapping);
        }
    }

    Ok(mappings)
}

fn parse_single_spec(spec: &str) -> Result<Vec<PortMapping>, PortParseError> {
    // Check for protocol suffix, e.g. "/udp" or "/tcp"
    let (body, protocol) = if let Some((body, proto)) = spec.rsplit_once('/') {
        let proto = proto.trim().to_ascii_lowercase();
        if proto != "tcp" && proto != "udp" {
            return Err(PortParseError::UnsupportedProtocol(proto));
        }
        (body.trim(), proto)
    } else {
        (spec, "tcp".to_string())
    };

    if body.is_empty() {
        return Err(PortParseError::EmptyPortSpec);
    }

    // Split colons: [host_ip:]host_port:container_port or bare port/range
    let parts: Vec<&str> = body.split(':').map(str::trim).collect();

    match parts.len() {
        1 => {
            // Bare port or bare range: e.g. "9001" or "9000-9002"
            let (start, end) = parse_port_or_range(parts[0])?;
            let mut result = Vec::with_capacity((end - start + 1) as usize);
            for p in start..=end {
                result.push(PortMapping {
                    host_ip: "127.0.0.1".into(),
                    host_port: p,
                    container_port: p,
                    protocol: protocol.clone(),
                });
            }
            Ok(result)
        },
        2 => {
            // "host_port:container_port" or "host_range:container_range"
            let (h_start, h_end) = parse_port_or_range(parts[0])?;
            let (c_start, c_end) = parse_port_or_range(parts[1])?;
            if (h_end - h_start) != (c_end - c_start) {
                return Err(PortParseError::InvalidRange(spec.to_string()));
            }
            let count = (h_end - h_start + 1) as usize;
            let mut result = Vec::with_capacity(count);
            for offset in 0..=h_end - h_start {
                result.push(PortMapping {
                    host_ip: "127.0.0.1".into(),
                    host_port: h_start + offset,
                    container_port: c_start + offset,
                    protocol: protocol.clone(),
                });
            }
            Ok(result)
        },
        3 => {
            // "host_ip:host_port:container_port"
            let host_ip = parts[0];
            if host_ip.is_empty() {
                return Err(PortParseError::InvalidFormat(spec.to_string()));
            }
            let (h_start, h_end) = parse_port_or_range(parts[1])?;
            let (c_start, c_end) = parse_port_or_range(parts[2])?;
            if (h_end - h_start) != (c_end - c_start) {
                return Err(PortParseError::InvalidRange(spec.to_string()));
            }
            let count = (h_end - h_start + 1) as usize;
            let mut result = Vec::with_capacity(count);
            for offset in 0..=h_end - h_start {
                result.push(PortMapping {
                    host_ip: host_ip.to_string(),
                    host_port: h_start + offset,
                    container_port: c_start + offset,
                    protocol: protocol.clone(),
                });
            }
            Ok(result)
        },
        _ => Err(PortParseError::InvalidFormat(spec.to_string())),
    }
}

fn parse_port_or_range(part: &str) -> Result<(u16, u16), PortParseError> {
    let part = part.trim();
    if part.is_empty() {
        return Err(PortParseError::EmptyPortSpec);
    }
    if let Some((start_s, end_s)) = part.split_once('-') {
        let start = parse_port_u16(start_s)?;
        let end = parse_port_u16(end_s)?;
        if start > end {
            return Err(PortParseError::InvalidRange(part.to_string()));
        }
        Ok((start, end))
    } else {
        let single_port = parse_port_u16(part)?;
        Ok((single_port, single_port))
    }
}

fn parse_port_u16(s: &str) -> Result<u16, PortParseError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(PortParseError::EmptyPortSpec);
    }
    let val: u32 = s
        .parse()
        .map_err(|_| PortParseError::InvalidPortNumber(s.to_string()))?;
    if val == 0 || val > 65535 {
        return Err(PortParseError::InvalidPortNumber(s.to_string()));
    }
    u16::try_from(val).map_err(|_| PortParseError::InvalidPortNumber(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_ports() {
        assert_eq!(parse_container_ports("").unwrap(), vec![]);
        assert_eq!(parse_container_ports("   ").unwrap(), vec![]);
    }

    #[test]
    fn test_bare_port() {
        let res = parse_container_ports("9001").unwrap();
        assert_eq!(
            res,
            vec![PortMapping {
                host_ip: "127.0.0.1".into(),
                host_port: 9001,
                container_port: 9001,
                protocol: "tcp".into(),
            }]
        );
    }

    #[test]
    fn test_bare_range() {
        let res = parse_container_ports("9000-9002").unwrap();
        assert_eq!(
            res,
            vec![
                PortMapping {
                    host_ip: "127.0.0.1".into(),
                    host_port: 9000,
                    container_port: 9000,
                    protocol: "tcp".into(),
                },
                PortMapping {
                    host_ip: "127.0.0.1".into(),
                    host_port: 9001,
                    container_port: 9001,
                    protocol: "tcp".into(),
                },
                PortMapping {
                    host_ip: "127.0.0.1".into(),
                    host_port: 9002,
                    container_port: 9002,
                    protocol: "tcp".into(),
                },
            ]
        );
    }

    #[test]
    fn test_explicit_mapping() {
        let res = parse_container_ports("8080:80").unwrap();
        assert_eq!(
            res,
            vec![PortMapping {
                host_ip: "127.0.0.1".into(),
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".into(),
            }]
        );
    }

    #[test]
    fn test_host_ip_binding() {
        let res = parse_container_ports("127.0.0.1:8080:80").unwrap();
        assert_eq!(
            res,
            vec![PortMapping {
                host_ip: "127.0.0.1".into(),
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".into(),
            }]
        );
    }

    #[test]
    fn test_protocol_suffix() {
        let res = parse_container_ports("53/udp").unwrap();
        assert_eq!(
            res,
            vec![PortMapping {
                host_ip: "127.0.0.1".into(),
                host_port: 53,
                container_port: 53,
                protocol: "udp".into(),
            }]
        );

        let res2 = parse_container_ports("127.0.0.1:5353:53/udp").unwrap();
        assert_eq!(
            res2,
            vec![PortMapping {
                host_ip: "127.0.0.1".into(),
                host_port: 5353,
                container_port: 53,
                protocol: "udp".into(),
            }]
        );
    }

    #[test]
    fn test_multiple_specs() {
        let res = parse_container_ports("8080:80, 8443:443/tcp, 53/udp").unwrap();
        assert_eq!(res.len(), 3);
        assert_eq!(res[0].host_port, 8080);
        assert_eq!(res[1].host_port, 8443);
        assert_eq!(res[2].host_port, 53);
        assert_eq!(res[2].protocol, "udp");
    }

    #[test]
    fn test_invalid_protocol() {
        let err = parse_container_ports("80/sctp").unwrap_err();
        assert_eq!(err, PortParseError::UnsupportedProtocol("sctp".into()));
    }

    #[test]
    fn test_invalid_range_order() {
        let err = parse_container_ports("9002-9000").unwrap_err();
        assert_eq!(err, PortParseError::InvalidRange("9002-9000".into()));
    }

    #[test]
    fn test_mismatched_ranges() {
        let err = parse_container_ports("8000-8002:9000-9001").unwrap_err();
        assert_eq!(
            err,
            PortParseError::InvalidRange("8000-8002:9000-9001".into())
        );
    }

    #[test]
    fn test_invalid_port_numbers() {
        assert!(matches!(
            parse_container_ports("0").unwrap_err(),
            PortParseError::InvalidPortNumber(_)
        ));
        assert!(matches!(
            parse_container_ports("65536").unwrap_err(),
            PortParseError::InvalidPortNumber(_)
        ));
        assert!(matches!(
            parse_container_ports("abc").unwrap_err(),
            PortParseError::InvalidPortNumber(_)
        ));
    }

    #[test]
    fn test_duplicate_host_ports() {
        let err = parse_container_ports("8080:80, 8080:81").unwrap_err();
        assert_eq!(err, PortParseError::DuplicateHostPort(8080, "tcp".into()));
    }

    #[test]
    fn test_duplicate_container_ports() {
        let err = parse_container_ports("8080:80, 8081:80").unwrap_err();
        assert_eq!(
            err,
            PortParseError::DuplicateContainerPort(80, "tcp".into())
        );
    }
}
