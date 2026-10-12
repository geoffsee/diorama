//! Static workloads, Kubernetes resource identities, and nonportable state classification.
//!
//! Validates:
//! 1. Preservation of Kubernetes core resource identities:
//!    - UIDs (`metadata.uid`)
//!    - Namespaces and names
//!    - Resource versions (`metadata.resourceVersion`)
//!    - Spec specifications (containers, ports, volumes, images)
//! 2. Preservation of static pod manifests (e.g. `/etc/kubernetes/manifests`).
//! 3. Explicit classification of nonportable transient runtime state:
//!    - Sockets: `containerd.sock`, `config.sock`, `kine.sock`
//!    - PIDs: `/var/run/diorama-kube.pid`
//!    - Runtime task shims: `containerd-shim-runc-v2`
//!    - Network iptables/nftables masquerade rules: `kubesolo-masq`
//!
//!    These must be recreated by the supervisor and not assumed portable across transitions.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Canonical representation of a Kubernetes resource object for identity preservation testing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    pub api_version: String,
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub resource_version: String,
    pub spec_hash: String,
}

/// Category of host/runtime state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatePortabilityCategory {
    /// State that MUST be preserved verbatim across transition (config, PKI, datastore, PVs).
    PortablePersistent,
    /// Ephemeral runtime state that CANNOT be preserved and must be recreated (sockets, PIDs, shims).
    NonportableEphemeral,
}

/// Item in the state portability classification registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateClassificationItem {
    pub path_or_resource: String,
    pub category: StatePortabilityCategory,
    pub justification: String,
}

/// Returns the authoritative state classification inventory.
#[must_use]
pub fn state_classification_inventory() -> Vec<StateClassificationItem> {
    vec![
        StateClassificationItem {
            path_or_resource: "/etc/diorama-kube/config.yaml".into(),
            category: StatePortabilityCategory::PortablePersistent,
            justification: "Desired node configuration; survives upgrade and reset.".into(),
        },
        StateClassificationItem {
            path_or_resource: "P/pki/ca/ca.crt".into(),
            category: StatePortabilityCategory::PortablePersistent,
            justification: "Root CA certificate; maintains cluster cryptographic trust.".into(),
        },
        StateClassificationItem {
            path_or_resource: "P/pki/admin/admin.kubeconfig".into(),
            category: StatePortabilityCategory::PortablePersistent,
            justification: "Admin client credentials; allows ongoing cluster access.".into(),
        },
        StateClassificationItem {
            path_or_resource: "P/kine/db/state.db".into(),
            category: StatePortabilityCategory::PortablePersistent,
            justification: "Durable SQLite database containing all Kubernetes state.".into(),
        },
        StateClassificationItem {
            path_or_resource: "P/local-path-storage".into(),
            category: StatePortabilityCategory::PortablePersistent,
            justification: "Persistent volume directory storing application workloads.".into(),
        },
        StateClassificationItem {
            path_or_resource: "P/containerd/containerd.sock".into(),
            category: StatePortabilityCategory::NonportableEphemeral,
            justification: "UNIX domain socket owned by running containerd process.".into(),
        },
        StateClassificationItem {
            path_or_resource: "P/config.sock".into(),
            category: StatePortabilityCategory::NonportableEphemeral,
            justification: "Config API UNIX domain socket; must be unbound and recreated.".into(),
        },
        StateClassificationItem {
            path_or_resource: "/var/run/diorama-kube.pid".into(),
            category: StatePortabilityCategory::NonportableEphemeral,
            justification: "Process identifier file; invalid after service stop.".into(),
        },
        StateClassificationItem {
            path_or_resource: "P/containerd/state".into(),
            category: StatePortabilityCategory::NonportableEphemeral,
            justification: "Ephemeral container task state; rebuilt on supervisor start.".into(),
        },
        StateClassificationItem {
            path_or_resource: "iptables/kubesolo-masq".into(),
            category: StatePortabilityCategory::NonportableEphemeral,
            justification: "Kernel firewall rules; re-established by diorama-network.".into(),
        },
    ]
}

/// Asserts that all workload identities before transition match the identities after transition.
pub fn assert_workload_identities_preserved(
    before: &[WorkloadIdentity],
    after: &[WorkloadIdentity],
) -> Result<(), String> {
    let mut before_map = BTreeMap::new();
    for item in before {
        let key = (&item.api_version, &item.kind, &item.namespace, &item.name);
        if before_map.insert(key, item).is_some() {
            return Err(format!("duplicate workload before transition: {key:?}"));
        }
    }

    if before.len() != after.len() {
        return Err(format!(
            "workload count mismatch: before={}, after={}",
            before.len(),
            after.len()
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    for item in after {
        let key = (&item.api_version, &item.kind, &item.namespace, &item.name);
        if !seen.insert(key) {
            return Err(format!("duplicate workload after transition: {key:?}"));
        }
        match before_map.get(&key) {
            Some(prev) => {
                if prev.uid != item.uid {
                    return Err(format!(
                        "UID changed for {key:?}: before={}, after={}",
                        prev.uid, item.uid
                    ));
                }
                if prev.resource_version != item.resource_version {
                    return Err(format!(
                        "resourceVersion changed for {key:?}: before={}, after={}",
                        prev.resource_version, item.resource_version
                    ));
                }
                if prev.spec_hash != item.spec_hash {
                    return Err(format!(
                        "specHash changed for {key:?}: before={}, after={}",
                        prev.spec_hash, item.spec_hash
                    ));
                }
            },
            None => {
                return Err(format!("unexpected new workload after transition: {key:?}"));
            },
        }
    }

    Ok(())
}

/// Compare complete regular-file manifest inventories; missing roots and links fail closed.
pub fn assert_static_manifests_preserved(dir_before: &Path, dir_after: &Path) -> io::Result<()> {
    let before = manifest_inventory(dir_before)?;
    let after = manifest_inventory(dir_after)?;
    if before != after {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "static manifest inventory or content changed",
        ));
    }
    Ok(())
}

fn manifest_inventory(root: &Path) -> io::Result<BTreeMap<std::ffi::OsString, Vec<u8>>> {
    if !fs::symlink_metadata(root)?.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "manifest root must be a directory",
        ));
    }
    let mut inventory = BTreeMap::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "static manifest entries must be regular files",
            ));
        }
        inventory.insert(entry.file_name(), fs::read(entry.path())?);
    }
    Ok(inventory)
}
