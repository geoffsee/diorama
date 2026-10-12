//! License and attribution completeness enforcement.
//!
//! Enforces:
//! - Upstream attribution completeness for all 17 retained components.
//! - Documentation of licenses, copyright holders, and source references.
//! - Workspace dependency license validation against permitted SPDX expressions.

use crate::Result;
use std::fs;
use std::path::Path;

/// Specification for a retained component that requires explicit upstream attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedComponentSpec {
    pub name: &'static str,
    pub upstream_ref: &'static str,
    pub license: &'static str,
    pub copyright: &'static str,
}

/// The 17 retained upstream components supervised by Diorama Kube.
pub const RETAINED_COMPONENTS: &[RetainedComponentSpec] = &[
    RetainedComponentSpec {
        name: "kube-apiserver",
        upstream_ref: "v1.35.7",
        license: "Apache-2.0",
        copyright: "The Kubernetes Authors",
    },
    RetainedComponentSpec {
        name: "kube-controller-manager",
        upstream_ref: "v1.35.7",
        license: "Apache-2.0",
        copyright: "The Kubernetes Authors",
    },
    RetainedComponentSpec {
        name: "kubelet",
        upstream_ref: "v1.35.7",
        license: "Apache-2.0",
        copyright: "The Kubernetes Authors",
    },
    RetainedComponentSpec {
        name: "kube-proxy",
        upstream_ref: "v1.35.7",
        license: "Apache-2.0",
        copyright: "The Kubernetes Authors",
    },
    RetainedComponentSpec {
        name: "kine",
        upstream_ref: "v0.16.3",
        license: "Apache-2.0",
        copyright: "Rancher Labs, Inc.",
    },
    RetainedComponentSpec {
        name: "sqlite",
        upstream_ref: "embedded",
        license: "Blessing",
        copyright: "SQLite Authors",
    },
    RetainedComponentSpec {
        name: "containerd",
        upstream_ref: "v2.2.5",
        license: "Apache-2.0",
        copyright: "The containerd Authors",
    },
    RetainedComponentSpec {
        name: "containerd-shim-runc-v2",
        upstream_ref: "v2.2.5",
        license: "Apache-2.0",
        copyright: "The containerd Authors",
    },
    RetainedComponentSpec {
        name: "crun",
        upstream_ref: "1.26",
        license: "GPL-2.0-or-later",
        copyright: "Red Hat, Inc.",
    },
    RetainedComponentSpec {
        name: "cni-plugins",
        upstream_ref: "v1.9.0",
        license: "Apache-2.0",
        copyright: "The CNI Authors",
    },
    RetainedComponentSpec {
        name: "containerd-fuse-overlayfs-grpc",
        upstream_ref: "v2.1.7",
        license: "Apache-2.0",
        copyright: "The containerd Authors",
    },
    RetainedComponentSpec {
        name: "coredns",
        upstream_ref: "1.14.4",
        license: "Apache-2.0",
        copyright: "The CoreDNS Authors",
    },
    RetainedComponentSpec {
        name: "pause",
        upstream_ref: "latest",
        license: "Apache-2.0",
        copyright: "Portainer.io",
    },
    RetainedComponentSpec {
        name: "local-path-provisioner",
        upstream_ref: "v0.0.36",
        license: "Apache-2.0",
        copyright: "Rancher Labs, Inc.",
    },
    RetainedComponentSpec {
        name: "busybox",
        upstream_ref: "busybox",
        license: "GPL-2.0-only",
        copyright: "Erik Andersen",
    },
    RetainedComponentSpec {
        name: "portainer-agent",
        upstream_ref: "lts",
        license: "Zlib",
        copyright: "Portainer.io",
    },
    RetainedComponentSpec {
        name: "d2k",
        upstream_ref: "1.2.3",
        license: "Apache-2.0",
        copyright: "Portainer.io",
    },
];

/// Verifies that `docs/architecture/attribution.md` exists and contains complete
/// attribution records for all 17 retained upstream components.
pub fn verify_retained_attribution(root: &Path) -> Result<usize> {
    let path = root.join("docs/architecture/attribution.md");
    if !path.is_file() {
        return Err(format!("missing attribution document at {}", path.display()).into());
    }

    let content = fs::read_to_string(&path).map_err(|e| {
        format!(
            "failed to read attribution document at {}: {e}",
            path.display()
        )
    })?;

    let mut records = std::collections::BTreeMap::new();
    for line in content.lines().filter(|line| line.starts_with('|')) {
        let fields: Vec<_> = line.trim_matches('|').split('|').map(str::trim).collect();
        let Some(name) = fields.first().and_then(|field| field.split('`').nth(1)) else {
            continue;
        };
        if !RETAINED_COMPONENTS
            .iter()
            .any(|component| component.name == name)
        {
            continue;
        }
        if fields.len() != 5 || records.insert(name, fields).is_some() {
            return Err(format!("malformed or duplicate attribution record for {name}").into());
        }
    }
    for component in RETAINED_COMPONENTS {
        let row = records.get(component.name).ok_or_else(|| {
            format!(
                "attribution document missing retained component record '{}'",
                component.name
            )
        })?;
        let license_matches = row[2]
            .split('/')
            .any(|license| license.trim() == component.license);
        if !row[1]
            .to_ascii_lowercase()
            .contains(&component.upstream_ref.to_ascii_lowercase())
            || !license_matches
            || !row[3].contains(component.copyright)
            || row[4] != upstream_repository(component.name)
        {
            return Err(format!(
                "incomplete attribution fields for component '{}'",
                component.name
            )
            .into());
        }
    }

    Ok(RETAINED_COMPONENTS.len())
}

fn upstream_repository(name: &str) -> &'static str {
    match name {
        "kube-apiserver" | "kube-controller-manager" | "kubelet" | "kube-proxy" | "pause" => {
            "https://github.com/kubernetes/kubernetes"
        },
        "kine" => "https://github.com/k3s-io/kine",
        "sqlite" => "https://sqlite.org",
        "containerd" | "containerd-shim-runc-v2" => "https://github.com/containerd/containerd",
        "crun" => "https://github.com/containers/crun",
        "cni-plugins" => "https://github.com/containernetworking/plugins",
        "containerd-fuse-overlayfs-grpc" => {
            "https://github.com/containerd/fuse-overlayfs-snapshotter"
        },
        "coredns" => "https://github.com/coredns/coredns",
        "local-path-provisioner" => "https://github.com/rancher/local-path-provisioner",
        "busybox" => "https://busybox.net",
        "portainer-agent" => "https://github.com/portainer/agent",
        "d2k" => "https://github.com/portainer/d2k",
        _ => "",
    }
}

/// Verifies workspace dependency license policy defined in `deny.toml`.
pub fn verify_workspace_license_policy(root: &Path) -> Result<usize> {
    let deny_path = root.join("deny.toml");
    let content = fs::read_to_string(&deny_path)
        .map_err(|e| format!("failed to read {}: {e}", deny_path.display()))?;

    let parsed: toml::Table =
        toml::from_str(&content).map_err(|e| format!("failed to parse deny.toml: {e}"))?;

    let licenses = parsed
        .get("licenses")
        .and_then(|l| l.as_table())
        .ok_or("deny.toml missing [licenses] table")?;

    let allow_list = licenses
        .get("allow")
        .and_then(|a| a.as_array())
        .ok_or("deny.toml missing licenses.allow list")?;

    if allow_list.is_empty() {
        return Err("deny.toml licenses.allow list is empty".into());
    }

    // Required core open source licenses
    let allowed_strings: Vec<&str> = allow_list.iter().filter_map(|v| v.as_str()).collect();

    for required in ["Apache-2.0", "MIT", "BSD-3-Clause"] {
        if !allowed_strings.contains(&required) {
            return Err(format!("deny.toml missing expected permitted license: {required}").into());
        }
    }

    Ok(allowed_strings.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retained_components_count() {
        assert_eq!(RETAINED_COMPONENTS.len(), 17);
    }

    #[test]
    fn test_retained_attribution_checks() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let count = verify_retained_attribution(root)?;
        assert_eq!(count, 17);
        Ok(())
    }

    #[test]
    fn test_license_policy_checks() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let count = verify_workspace_license_policy(root)?;
        assert!(count >= 3);
        Ok(())
    }
}
