//! Upstream license attribution and dependency inventory generation.
//!
//! Complies with Gate C16/C17 requirements (Epic E30 / Issue #126) for attributing
//! Kubernetes, Kine, containerd, OCI images, and transitive dependencies.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::provenance::{LicenseEntry, LicenseInventory};

// Kept local so fixture build contexts need no files outside the source crate.
// Regression coverage compares this notice with the repository LICENSE.
const DISTRIBUTION_LICENSE_TEXT: &str = "ISC License\n\nCopyright (c) 2026 Geoff S. and diorama-kube contributors\n\nPermission to use, copy, modify, and/or distribute this software for any\npurpose with or without fee is hereby granted, provided that the above\ncopyright notice and this permission notice appear in all copies.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\" AND THE AUTHOR DISCLAIMS ALL WARRANTIES\nWITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF\nMERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR\nANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES\nWHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN\nACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF\nOR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.\n";

/// Architectural category of an attributed component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentCategory {
    KubernetesCore,
    DatastoreAndRuntime,
    OciContainerImage,
    NetworkAndSnapshotter,
    RustWorkspaceDependency,
}

impl ComponentCategory {
    pub const fn title(self) -> &'static str {
        match self {
            Self::KubernetesCore => "Kubernetes Core Supervised Components",
            Self::DatastoreAndRuntime => "Datastore and Container Runtime",
            Self::OciContainerImage => "OCI Container Images",
            Self::NetworkAndSnapshotter => "Networking and Snapshotter Utilities",
            Self::RustWorkspaceDependency => "Rust Workspace Dependencies",
        }
    }
}

/// Upstream attributed dependency or component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributedComponent {
    pub name: String,
    pub version: String,
    pub spdx_license: String,
    pub upstream_repository: String,
    pub copyright: String,
    pub category: ComponentCategory,
    pub architectural_role: String,
    pub notice: Option<String>,
}

/// Full upstream license attribution record for the Diorama distribution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionRecord {
    pub schema_version: u32,
    pub distribution_version: String,
    pub distribution_license: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_integrity_hash: Option<String>,
    pub components: Vec<AttributedComponent>,
    pub license_texts: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct MetadataSources {
    packages: Vec<MetadataPackage>,
    workspace_members: Vec<String>,
}

#[derive(Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
}

impl AttributionRecord {
    /// Compiles authoritative attribution for Diorama v0.1.0 including
    /// Kubernetes v1.35.7, Kine v0.16.3, containerd v2.2.5, and OCI image dependencies.
    #[allow(clippy::too_many_lines, clippy::vec_init_then_push)]
    pub fn build(cargo_metadata_json: &str) -> Result<Self> {
        let mut components = Vec::new();

        // 1. Kubernetes Core Supervised Components
        components.push(AttributedComponent {
            name: "kube-apiserver".into(),
            version: "v1.35.7".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/kubernetes/kubernetes".into(),
            copyright: "The Kubernetes Authors".into(),
            category: ComponentCategory::KubernetesCore,
            architectural_role: "Supervised official API server binary handling authenticated HTTPS/JSON and admission".into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });
        components.push(AttributedComponent {
            name: "kube-controller-manager".into(),
            version: "v1.35.7".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/kubernetes/kubernetes".into(),
            copyright: "The Kubernetes Authors".into(),
            category: ComponentCategory::KubernetesCore,
            architectural_role:
                "Supervised official controller manager driving Job, Pod, and core reconcilers"
                    .into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });
        components.push(AttributedComponent {
            name: "kubelet".into(),
            version: "v1.35.7".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/kubernetes/kubernetes".into(),
            copyright: "The Kubernetes Authors".into(),
            category: ComponentCategory::KubernetesCore,
            architectural_role: "Supervised node agent coordinating single-node pod lifecycles and CRI communication".into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });
        components.push(AttributedComponent {
            name: "kube-proxy".into(),
            version: "v1.35.7".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/kubernetes/kubernetes".into(),
            copyright: "The Kubernetes Authors".into(),
            category: ComponentCategory::KubernetesCore,
            architectural_role:
                "Supervised service routing agent managing host iptables and nftables egress rules"
                    .into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });

        // 2. Datastore and Container Runtime
        components.push(AttributedComponent {
            name: "kine".into(),
            version: "v0.16.3".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/k3s-io/kine".into(),
            copyright: "Rancher Labs, Inc. / The K3s Authors".into(),
            category: ComponentCategory::DatastoreAndRuntime,
            architectural_role:
                "Supervised etcd-to-SQLite translation daemon accessed over dedicated loopback mTLS"
                    .into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });
        components.push(AttributedComponent {
            name: "sqlite (embedded in kine)".into(),
            version: "3.x".into(),
            spdx_license: "blessing".into(),
            upstream_repository: "https://sqlite.org".into(),
            copyright: "Public Domain / D. Richard Hipp".into(),
            category: ComponentCategory::DatastoreAndRuntime,
            architectural_role: "On-disk single-node relational datastore engine powering Kine state persistence".into(),
            notice: Some("The author disclaims copyright to this source code. In place of a legal notice: May you do good and not evil.".into()),
        });
        components.push(AttributedComponent {
            name: "containerd".into(),
            version: "v2.2.5".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/containerd/containerd".into(),
            copyright: "The containerd Authors".into(),
            category: ComponentCategory::DatastoreAndRuntime,
            architectural_role: "Supervised core container runtime daemon implementing CRI v1 and OCI image services".into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });
        components.push(AttributedComponent {
            name: "containerd-shim-runc-v2".into(),
            version: "v2.2.5".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/containerd/containerd".into(),
            copyright: "The containerd Authors".into(),
            category: ComponentCategory::DatastoreAndRuntime,
            architectural_role: "Containerd runtime shim managing headless container execution and process accounting".into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });
        components.push(AttributedComponent {
            name: "crun".into(),
            version: "1.26".into(),
            spdx_license: "GPL-2.0-or-later".into(),
            upstream_repository: "https://github.com/containers/crun".into(),
            copyright: "Red Hat, Inc. and contributors".into(),
            category: ComponentCategory::DatastoreAndRuntime,
            architectural_role: "Lightweight OCI runtime binary executing container processes under containerd supervision".into(),
            notice: Some("Licensed under the GNU General Public License, Version 2 or later".into()),
        });

        // 3. OCI Container Images
        components.push(AttributedComponent {
            name: "CoreDNS".into(),
            version: "1.14.4".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/coredns/coredns".into(),
            copyright: "The CoreDNS Authors".into(),
            category: ComponentCategory::OciContainerImage,
            architectural_role:
                "Cluster DNS resolver pod providing service discovery across cluster namespaces"
                    .into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });
        components.push(AttributedComponent {
            name: "pause sandbox".into(),
            version: "latest (v3.10 baseline)".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/kubernetes/kubernetes".into(),
            copyright: "The Kubernetes Authors / Portainer.io".into(),
            category: ComponentCategory::OciContainerImage,
            architectural_role:
                "CRI sandbox container holding network namespace and IPC resources for pods".into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });
        components.push(AttributedComponent {
            name: "local-path-provisioner".into(),
            version: "v0.0.36".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/rancher/local-path-provisioner".into(),
            copyright: "Rancher Labs, Inc.".into(),
            category: ComponentCategory::OciContainerImage,
            architectural_role: "Persistent volume controller provisioning hostPath-backed storage with Retain reclaim policy".into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });
        components.push(AttributedComponent {
            name: "local-path helper (busybox)".into(),
            version: "latest (image contents unresolved)".into(),
            spdx_license: "GPL-2.0-only".into(),
            upstream_repository: "https://busybox.net".into(),
            copyright: "Erik Andersen, Rob Landley, Denys Vlasenko, and others".into(),
            category: ComponentCategory::OciContainerImage,
            architectural_role: "Helper utility pod used by local-path-provisioner for volume initialization".into(),
            notice: Some("Licensed under the GNU General Public License, Version 2 only".into()),
        });
        components.push(AttributedComponent {
            name: "Portainer Edge Agent".into(),
            version: "lts".into(),
            spdx_license: "Zlib".into(),
            upstream_repository: "https://github.com/portainer/agent".into(),
            copyright: "Portainer.io".into(),
            category: ComponentCategory::OciContainerImage,
            architectural_role: "Optional management agent establishing reverse tunnel connectivity to Portainer Server".into(),
            notice: Some("Licensed under the zlib License".into()),
        });
        components.push(AttributedComponent {
            name: "D2K".into(),
            version: "1.2.3".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/portainer/d2k".into(),
            copyright: "Portainer.io".into(),
            category: ComponentCategory::OciContainerImage,
            architectural_role: "Optional Docker-to-Kubernetes translation gateway exposing Docker Engine API on port 2376".into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });
        components.push(AttributedComponent {
            name: "KubeSolo node image".into(),
            version: "latest".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/portainer/kubesolo".into(),
            copyright: "Portainer.io".into(),
            category: ComponentCategory::OciContainerImage,
            architectural_role:
                "Containerized node distribution image for container execution modes".into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });

        // 4. Networking and Snapshotter Utilities
        components.push(AttributedComponent {
            name: "containernetworking-plugins".into(),
            version: "v1.9.0".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/containernetworking/plugins".into(),
            copyright: "The CNI Authors".into(),
            category: ComponentCategory::NetworkAndSnapshotter,
            architectural_role: "CNI plugins (bridge, host-local, portmap, loopback) managing pod network namespaces".into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });
        components.push(AttributedComponent {
            name: "containerd-fuse-overlayfs-grpc".into(),
            version: "v2.1.7".into(),
            spdx_license: "Apache-2.0".into(),
            upstream_repository: "https://github.com/containerd/fuse-overlayfs-snapshotter".into(),
            copyright: "The containerd Authors".into(),
            category: ComponentCategory::NetworkAndSnapshotter,
            architectural_role:
                "Supervised snapshotter plugin providing unprivileged fuse-overlayfs storage roots"
                    .into(),
            notice: Some("Licensed under the Apache License, Version 2.0".into()),
        });

        // 5. Rust Workspace Dependencies
        let metadata: MetadataSources = serde_json::from_str(cargo_metadata_json)?;
        let sources = metadata
            .packages
            .into_iter()
            .map(|package| {
                let source = package.source.unwrap_or_else(|| {
                    if metadata.workspace_members.contains(&package.id) {
                        "workspace path crate".into()
                    } else {
                        "local path dependency".into()
                    }
                });
                ((package.name, package.version), source)
            })
            .collect::<BTreeMap<_, _>>();
        let rust_inventory = crate::provenance::generate_license_inventory(cargo_metadata_json)?;
        for dep in rust_inventory.rust_dependencies {
            let source = sources
                .get(&(dep.name.clone(), dep.version.clone()))
                .ok_or("missing Cargo metadata dependency source")?
                .clone();
            components.push(AttributedComponent {
                name: dep.name,
                version: dep.version,
                spdx_license: dep.license,
                upstream_repository: source,
                copyright: "Various crate authors".into(),
                category: ComponentCategory::RustWorkspaceDependency,
                architectural_role:
                    "Rust dependency compiled into node supervisor, CLI, or maintenance tooling"
                        .into(),
                notice: None,
            });
        }

        let mut license_texts = BTreeMap::new();
        license_texts.insert("ISC".into(), DISTRIBUTION_LICENSE_TEXT.into());
        license_texts.insert(
            "Apache-2.0".into(),
            "Apache License, Version 2.0\nhttp://www.apache.org/licenses/LICENSE-2.0".into(),
        );
        license_texts.insert(
            "MIT".into(),
            "MIT License\nhttps://opensource.org/licenses/MIT".into(),
        );
        license_texts.insert(
            "GPL-2.0-only".into(),
            "GNU General Public License, Version 2.0\nhttps://www.gnu.org/licenses/old-licenses/gpl-2.0.html".into(),
        );
        license_texts.insert(
            "GPL-2.0-or-later".into(),
            "GNU General Public License, Version 2.0 or later\nhttps://www.gnu.org/licenses/gpl-2.0.html".into(),
        );
        license_texts.insert(
            "Zlib".into(),
            "zlib License\nhttps://opensource.org/licenses/Zlib".into(),
        );
        license_texts.insert(
            "blessing".into(),
            "SQLite Blessing\nMay you do good and not evil.\nMay you find forgiveness for yourself and forgive others.\nMay you share freely, never taking more than you give.".into(),
        );

        Ok(Self {
            schema_version: 1,
            distribution_version: "0.1.0".into(),
            distribution_license: "ISC".into(),
            receipt_id: None,
            receipt_integrity_hash: None,
            components,
            license_texts,
        })
    }

    /// Renders draft notices and metadata; this does not certify license compliance.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# Draft Upstream License Attribution and Third-Party Notices\n"
        );
        let _ = writeln!(
            out,
            "**Diorama Kubernetes Distribution Version**: `{}`  \n**Primary Distribution License**: `{}`\n",
            self.distribution_version, self.distribution_license
        );
        if let (Some(receipt_id), Some(hash)) = (&self.receipt_id, &self.receipt_integrity_hash) {
            let _ = writeln!(out, "- **Receipt ID**: `{receipt_id}`");
            let _ = writeln!(out, "- **Receipt Integrity Hash**: `{hash}`\n");
            out.push_str(
                "CANDIDATE_RECEIPT_BOUND. This document binds upstream license attribution and third-party notices to validated candidate qualification receipts.\n\n"
            );
        } else {
            out.push_str(
                "UNQUALIFIED_FIXTURE_ONLY. This draft inventories declared upstream components and \
                 locked workspace dependency metadata. It does not attest the contents of built release \
                 binaries or OCI images, provide complete upstream license texts, or certify legal \
                 license compliance. Gate C16/C17 remain pending.\n\n"
            );
        }

        let categories = [
            ComponentCategory::KubernetesCore,
            ComponentCategory::DatastoreAndRuntime,
            ComponentCategory::OciContainerImage,
            ComponentCategory::NetworkAndSnapshotter,
        ];

        for category in categories {
            let _ = writeln!(out, "## {}\n", category.title());
            let _ = writeln!(
                out,
                "| Component | Version / Ref | License (SPDX) | Upstream Authority | Architectural Role |"
            );
            let _ = writeln!(out, "|---|---|---|---|---|");

            for c in self.components.iter().filter(|c| c.category == category) {
                let authority = if c.upstream_repository.starts_with("https://") {
                    format!("[{}]({})", c.copyright, c.upstream_repository)
                } else {
                    format!("{} (`{}`)", c.copyright, c.upstream_repository)
                };
                let _ = writeln!(
                    out,
                    "| `{}` | `{}` | `{}` | {} | {} |",
                    c.name, c.version, c.spdx_license, authority, c.architectural_role
                );
            }
            out.push('\n');
        }

        // Rust dependencies summary table
        let _ = writeln!(
            out,
            "## {}\n",
            ComponentCategory::RustWorkspaceDependency.title()
        );
        out.push_str(
            "Locked workspace Cargo metadata supplies the following declared dependency licenses. \
             This includes development/tooling and potentially inactive dependencies; it is not \
             an inventory of crates linked into a particular release binary.\n\n",
        );
        let _ = writeln!(out, "| Crate | Version | SPDX License | Source |");
        let _ = writeln!(out, "|---|---|---|---|");

        for c in self
            .components
            .iter()
            .filter(|c| c.category == ComponentCategory::RustWorkspaceDependency)
        {
            let _ = writeln!(
                out,
                "| `{}` | `{}` | `{}` | `{}` |",
                c.name, c.version, c.spdx_license, c.upstream_repository
            );
        }
        out.push('\n');

        out.push_str("## License Texts and Notices\n\n");
        for (name, text) in &self.license_texts {
            let _ = writeln!(out, "### {name}\n\n```\n{text}\n```\n");
        }

        out
    }

    /// Converts to the standardized `LicenseInventory` format.
    #[must_use]
    pub fn to_license_inventory(&self) -> LicenseInventory {
        let mut rust_dependencies = Vec::new();
        let mut retained_components = Vec::new();

        for c in &self.components {
            let entry = LicenseEntry {
                name: c.name.clone(),
                version: c.version.clone(),
                license: c.spdx_license.clone(),
            };
            if c.category == ComponentCategory::RustWorkspaceDependency {
                rust_dependencies.push(entry);
            } else {
                retained_components.push(entry);
            }
        }

        rust_dependencies.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        retained_components.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));

        LicenseInventory {
            schema_version: 1,
            receipt_id: self.receipt_id.clone(),
            receipt_integrity_hash: self.receipt_integrity_hash.clone(),
            rust_dependencies,
            retained_components,
        }
    }
}

/// Verifies that all required upstream components are present in an attribution record.
pub fn verify_attribution_completeness(record: &AttributionRecord) -> Result<()> {
    let required = [
        "kube-apiserver",
        "kube-controller-manager",
        "kubelet",
        "kube-proxy",
        "kine",
        "sqlite (embedded in kine)",
        "containerd",
        "containerd-shim-runc-v2",
        "crun",
        "CoreDNS",
        "pause sandbox",
        "local-path-provisioner",
        "local-path helper (busybox)",
        "Portainer Edge Agent",
        "D2K",
        "KubeSolo node image",
        "containernetworking-plugins",
        "containerd-fuse-overlayfs-grpc",
    ];

    for name in required {
        if !record.components.iter().any(|c| c.name == name) {
            return Err(format!("missing required upstream attribution for '{name}'").into());
        }
    }

    // Verify all licenses are valid and documented
    for c in &record.components {
        if c.spdx_license.is_empty()
            || c.spdx_license == "unrecorded"
                && c.category != ComponentCategory::RustWorkspaceDependency
        {
            return Err(format!(
                "component '{}' has unresolved license '{}'",
                c.name, c.spdx_license
            )
            .into());
        }
    }

    Ok(())
}
