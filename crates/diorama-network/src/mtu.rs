use crate::error::NetworkError;
use crate::ip::classify_ipv4;
use crate::model::{DEFAULT_MTU, InterfaceCandidate, MAX_VALID_MTU, MIN_VALID_MTU};

/// Picks the MTU of the interface that `select_node_ip` would pick:
/// the first candidate with a private IPv4 address, falling back to the first candidate
/// with any non-loopback IPv4 address. Candidates with a non-positive (zero) MTU are skipped.
pub fn select_mtu(candidates: &[InterfaceCandidate]) -> Result<u32, NetworkError> {
    let mut first_non_loopback: Option<u32> = None;

    for candidate in candidates {
        if candidate.mtu == 0 {
            continue;
        }
        for &addr in &candidate.addrs {
            let Some((_, is_private)) = classify_ipv4(addr) else {
                continue;
            };
            if is_private {
                return Ok(candidate.mtu);
            }
            if first_non_loopback.is_none() {
                first_non_loopback = Some(candidate.mtu);
            }
        }
    }

    if let Some(mtu) = first_non_loopback {
        return Ok(mtu);
    }

    Err(NetworkError::NoUsableInterface {
        reason: "could not find non-loopback IPv4 interface".to_string(),
    })
}

/// Resolves the MTU to apply to the embedded CNI bridge and pod veth interfaces,
/// and whether it was explicitly pinned via a valid override.
///
/// An override <= 0 means auto-detect via `select_mtu`, not pinned.
/// An override outside [68, 65535] is rejected with a warning and falls back to auto-detection (not pinned).
/// A valid override is used as-is and pinned, even if it differs from the auto-detected value.
pub fn resolve_mtu(
    override_mtu: Option<i64>,
    candidates: &[InterfaceCandidate],
) -> Result<(u32, bool), NetworkError> {
    let override_val = override_mtu.unwrap_or(0);

    if override_val <= 0 {
        let detected = select_mtu(candidates).unwrap_or(DEFAULT_MTU);
        return Ok((detected, false));
    }

    let min_valid = i64::from(MIN_VALID_MTU);
    let max_valid = i64::from(MAX_VALID_MTU);

    if override_val < min_valid || override_val > max_valid {
        tracing::warn!(
            component = "network",
            mtu = override_val,
            "--mtu is outside the valid range (68-65535); ignoring it and auto-detecting the MTU"
        );
        let detected = select_mtu(candidates).unwrap_or(DEFAULT_MTU);
        return Ok((detected, false));
    }

    let override_u32 = u32::try_from(override_val).unwrap_or(DEFAULT_MTU);

    if let Ok(detected) = select_mtu(candidates)
        && detected != override_u32
    {
        tracing::warn!(
            component = "network",
            mtu = override_u32,
            detected_mtu = detected,
            "--mtu differs from the auto-detected interface MTU; using the override anyway"
        );
    }

    Ok((override_u32, true))
}
