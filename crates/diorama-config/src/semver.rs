//! Semver comparison and legacy upgrade version gates.
//!
//! `KubeSolo` historical versions are compared numerically by `major.minor.patch`.
//! Non-numeric components like `develop` or `latest` return `None`, skipping
//! version-dependent guards.
//!
//! Upstream contract:
//! Binary versions before `v1.3.0` predated `--config` support (`MinConfigFileVersion`).
//! Upgrades to versions `< v1.3.0` must keep legacy flags in the service definition.
//! Upgrades to versions `>= v1.3.0` (or unparseable versions like `develop`) support
//! converting flags into `/etc/diorama/config.yaml`.

use std::cmp::Ordering;

/// Minimum version of `KubeSolo` that supports `--config=/etc/diorama/config.yaml`.
pub const MIN_CONFIG_FILE_VERSION: &str = "v1.3.0";

/// A parsed 3-part semantic version (major, minor, patch).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParsedVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

/// Parses a version string into (major, minor, patch).
///
/// Strips leading `v` or `V` and trailing prerelease/metadata suffixes (`-` or `+`).
/// If the version cannot be parsed into 3 numeric segments, returns `None`.
pub fn parse_version(v: &str) -> Option<ParsedVersion> {
    let s = v.trim();
    let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
    // Ignore prerelease and build metadata suffixes: -rc1, +build123
    let s = s.split(['-', '+']).next().unwrap_or(s);
    let mut parts = s.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(ParsedVersion {
        major,
        minor,
        patch,
    })
}

/// Compares two version strings numerically.
///
/// Returns:
/// - `Some(Ordering::Less)` if `v1 < v2`
/// - `Some(Ordering::Equal)` if `v1 == v2`
/// - `Some(Ordering::Greater)` if `v1 > v2`
/// - `None` if either version cannot be parsed (e.g. `develop`, `latest`).
pub fn compare_versions(v1: &str, v2: &str) -> Option<Ordering> {
    let p1 = parse_version(v1)?;
    let p2 = parse_version(v2)?;
    Some(p1.cmp(&p2))
}

/// Returns true if the target version supports `--config` file configuration (`>= v1.3.0`).
/// If the target version is unparseable (e.g. `develop`, `latest`, empty), it returns `true`
/// so development/unversioned builds are not blocked from using the configuration file.
pub fn supports_config_file(version: &str) -> bool {
    !matches!(
        compare_versions(version, MIN_CONFIG_FILE_VERSION),
        Some(Ordering::Less)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(
            parse_version("v1.2.3"),
            Some(ParsedVersion {
                major: 1,
                minor: 2,
                patch: 3
            })
        );
        assert_eq!(
            parse_version("1.2.3"),
            Some(ParsedVersion {
                major: 1,
                minor: 2,
                patch: 3
            })
        );
        assert_eq!(
            parse_version("v1.3.0-rc1"),
            Some(ParsedVersion {
                major: 1,
                minor: 3,
                patch: 0
            })
        );
        assert_eq!(
            parse_version("v1.3.0+build.4"),
            Some(ParsedVersion {
                major: 1,
                minor: 3,
                patch: 0
            })
        );
        assert_eq!(parse_version("latest"), None);
        assert_eq!(parse_version("develop"), None);
        assert_eq!(parse_version("v1.2"), None);
        assert_eq!(parse_version("v1.2.3.4"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn test_compare_versions() {
        assert_eq!(compare_versions("v1.2.0", "v1.3.0"), Some(Ordering::Less));
        assert_eq!(compare_versions("v1.3.0", "v1.3.0"), Some(Ordering::Equal));
        assert_eq!(
            compare_versions("v1.3.1", "v1.3.0"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_versions("v2.0.0", "v1.3.0"),
            Some(Ordering::Greater)
        );
        assert_eq!(compare_versions("1.2.0", "v1.3.0"), Some(Ordering::Less));
        assert_eq!(compare_versions("develop", "v1.3.0"), None);
        assert_eq!(compare_versions("v1.3.0", "latest"), None);
    }

    #[test]
    fn test_supports_config_file() {
        assert!(!supports_config_file("v1.0.0"));
        assert!(!supports_config_file("v1.1.8"));
        assert!(!supports_config_file("v1.2.0"));
        assert!(!supports_config_file("v1.2.9"));
        assert!(supports_config_file("v1.3.0"));
        assert!(supports_config_file("v1.3.1"));
        assert!(supports_config_file("v1.4.0"));
        assert!(supports_config_file("v2.0.0"));
        assert!(supports_config_file("develop"));
        assert!(supports_config_file("latest"));
        assert!(supports_config_file(""));
    }
}
