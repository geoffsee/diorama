//! Optional and external-dependency asset selection policy (E06.03 / #50).

use crate::{
    AssetId, CatalogEntry, FeatureSupport, NodeTarget, OptionalFeature, Scope, Variant, catalog,
    feature_support,
};
use std::fmt;

/// Delivery mode requirement determined by asset selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectedDelivery {
    /// Payload is expected to be bundled in the distribution archive.
    Bundled,
    /// Image payload must be pulled from a container registry.
    RegistryPull { reference: String, custom: bool },
    /// Dependency is supplied by the host environment (external dependency builds).
    HostSupplied,
    /// Optional feature is disabled by configuration; no payload or pull requested.
    Disabled,
    /// Optional feature is unsupported on the target architecture.
    UnsupportedTarget,
}

impl SelectedDelivery {
    /// Whether this delivery mode requires a bundled payload in the archive.
    pub fn is_bundled(&self) -> bool {
        matches!(self, Self::Bundled)
    }

    /// Whether this delivery mode requires an external registry pull.
    pub fn is_registry_pull(&self) -> bool {
        matches!(self, Self::RegistryPull { .. })
    }

    /// Whether this asset is active in the cluster (bundled, registry pull, or host supplied).
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Bundled | Self::RegistryPull { .. } | Self::HostSupplied
        )
    }
}

/// Errors occurring during asset selection or airgapped validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectionError {
    /// Egress is denied (airgapped/offline) but an asset requires registry pull.
    EgressDeniedRegistryRequired {
        asset: AssetId,
        reference: String,
        custom: bool,
    },
    /// An optional feature was enabled on an unsupported architecture.
    UnsupportedTargetFeature {
        feature: OptionalFeature,
        architecture: diorama_platform::Architecture,
    },
    /// Asset missing from catalog.
    UnknownAsset(AssetId),
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EgressDeniedRegistryRequired {
                asset,
                reference,
                custom,
            } => {
                if *custom {
                    write!(
                        f,
                        "custom image for {asset:?} ({reference}) requires explicit registry pull; cannot be satisfied in egress-denied environment"
                    )
                } else {
                    write!(
                        f,
                        "asset {asset:?} requires registry pull ({reference}) in egress-denied environment"
                    )
                }
            },
            Self::UnsupportedTargetFeature {
                feature,
                architecture,
            } => {
                write!(
                    f,
                    "optional feature {feature:?} is unsupported on architecture {architecture:?}"
                )
            },
            Self::UnknownAsset(id) => write!(f, "unknown asset: {id:?}"),
        }
    }
}

impl std::error::Error for SelectionError {}

/// Configuration determining asset selection across variants, scopes, and features.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetSelector {
    target: NodeTarget,
    variant: Variant,
    scope: Scope,
    local_storage_enabled: bool,
    portainer_agent_enabled: bool,
    custom_portainer_image: Option<String>,
    d2k_enabled: bool,
    egress_denied: bool,
}

impl AssetSelector {
    /// Construct a default selector for the given target, variant, and scope.
    pub fn new(target: NodeTarget, variant: Variant, scope: Scope) -> Self {
        Self {
            target,
            variant,
            scope,
            local_storage_enabled: true,
            portainer_agent_enabled: false,
            custom_portainer_image: None,
            d2k_enabled: false,
            egress_denied: false,
        }
    }

    /// Enable or disable local path storage (provisioner & helper images).
    #[must_use]
    pub fn with_local_storage(mut self, enabled: bool) -> Self {
        self.local_storage_enabled = enabled;
        self
    }

    /// Enable or disable the Portainer agent, optionally specifying a custom image reference.
    #[must_use]
    pub fn with_portainer_agent(mut self, enabled: bool, custom_image: Option<String>) -> Self {
        self.portainer_agent_enabled = enabled;
        self.custom_portainer_image = custom_image;
        self
    }

    /// Enable or disable D2K (Docker-to-Kubernetes translator).
    #[must_use]
    pub fn with_d2k(mut self, enabled: bool) -> Self {
        self.d2k_enabled = enabled;
        self
    }

    /// Declare whether network egress is denied (e.g. strict offline / airgapped operation).
    #[must_use]
    pub fn with_egress_denied(mut self, egress_denied: bool) -> Self {
        self.egress_denied = egress_denied;
        self
    }

    pub fn target(&self) -> NodeTarget {
        self.target
    }

    pub fn variant(&self) -> Variant {
        self.variant
    }

    pub fn scope(&self) -> Scope {
        self.scope
    }

    pub fn local_storage_enabled(&self) -> bool {
        self.local_storage_enabled
    }

    pub fn portainer_agent_enabled(&self) -> bool {
        self.portainer_agent_enabled
    }

    pub fn custom_portainer_image(&self) -> Option<&str> {
        self.custom_portainer_image.as_deref()
    }

    pub fn d2k_enabled(&self) -> bool {
        self.d2k_enabled
    }

    pub fn egress_denied(&self) -> bool {
        self.egress_denied
    }

    /// Evaluate the selected delivery mode for a specific asset.
    pub fn select_delivery(&self, id: AssetId) -> SelectedDelivery {
        let entry = catalog().iter().find(|e| e.id == id);
        let default_ref = entry.map_or("", |e| e.reference);

        if self.scope == Scope::LegacyExternalDeps {
            self.select_external_delivery(id, default_ref)
        } else {
            self.select_supervised_delivery(id, default_ref)
        }
    }

    fn select_external_delivery(&self, id: AssetId, default_ref: &str) -> SelectedDelivery {
        match id {
            // Executables are supplied by host in external deps builds
            AssetId::KubeApiserver
            | AssetId::KubeControllerManager
            | AssetId::Kubelet
            | AssetId::KubeProxy
            | AssetId::Kine
            | AssetId::Containerd
            | AssetId::ContainerdShim
            | AssetId::Crun
            | AssetId::CniBridge
            | AssetId::CniHostLocal
            | AssetId::CniPortmap
            | AssetId::CniLoopback
            | AssetId::FuseOverlayfsSnapshotter => SelectedDelivery::HostSupplied,

            // Core images are pull-only in external builds
            AssetId::ImageCoredns | AssetId::ImagePause => SelectedDelivery::RegistryPull {
                reference: default_ref.to_string(),
                custom: false,
            },

            // Optional images depend on feature enablement
            AssetId::ImageLocalPath | AssetId::ImageLocalPathHelper => {
                if self.local_storage_enabled {
                    SelectedDelivery::RegistryPull {
                        reference: default_ref.to_string(),
                        custom: false,
                    }
                } else {
                    SelectedDelivery::Disabled
                }
            },
            AssetId::ImagePortainerAgent => {
                if self.portainer_agent_enabled {
                    if feature_support(self.target.architecture, OptionalFeature::PortainerAgent)
                        == FeatureSupport::UnsupportedTarget
                    {
                        SelectedDelivery::UnsupportedTarget
                    } else {
                        let (reference, custom) = self.custom_portainer_image.as_ref().map_or_else(
                            || (default_ref.to_string(), false),
                            |custom| (custom.clone(), true),
                        );
                        SelectedDelivery::RegistryPull { reference, custom }
                    }
                } else {
                    SelectedDelivery::Disabled
                }
            },
            AssetId::ImageKubesolo => {
                if self.variant == Variant::Offline {
                    SelectedDelivery::Bundled
                } else {
                    SelectedDelivery::RegistryPull {
                        reference: default_ref.to_string(),
                        custom: false,
                    }
                }
            },
            AssetId::ImageD2k => {
                if self.d2k_enabled {
                    if feature_support(self.target.architecture, OptionalFeature::D2k)
                        == FeatureSupport::UnsupportedTarget
                    {
                        SelectedDelivery::UnsupportedTarget
                    } else {
                        SelectedDelivery::RegistryPull {
                            reference: default_ref.to_string(),
                            custom: false,
                        }
                    }
                } else {
                    SelectedDelivery::Disabled
                }
            },
        }
    }

    fn select_supervised_delivery(&self, id: AssetId, default_ref: &str) -> SelectedDelivery {
        match id {
            // 13 executable roles and 2 core images are always bundled in supervised bundle
            AssetId::KubeApiserver
            | AssetId::KubeControllerManager
            | AssetId::Kubelet
            | AssetId::KubeProxy
            | AssetId::Kine
            | AssetId::Containerd
            | AssetId::ContainerdShim
            | AssetId::Crun
            | AssetId::CniBridge
            | AssetId::CniHostLocal
            | AssetId::CniPortmap
            | AssetId::CniLoopback
            | AssetId::FuseOverlayfsSnapshotter
            | AssetId::ImageCoredns
            | AssetId::ImagePause => SelectedDelivery::Bundled,

            // Local path provisioner & helper images
            AssetId::ImageLocalPath | AssetId::ImageLocalPathHelper => {
                if self.local_storage_enabled {
                    match self.variant {
                        Variant::Offline => SelectedDelivery::Bundled,
                        Variant::Online => SelectedDelivery::RegistryPull {
                            reference: default_ref.to_string(),
                            custom: false,
                        },
                    }
                } else {
                    SelectedDelivery::Disabled
                }
            },

            // Portainer agent
            AssetId::ImagePortainerAgent => {
                if self.portainer_agent_enabled {
                    if feature_support(self.target.architecture, OptionalFeature::PortainerAgent)
                        == FeatureSupport::UnsupportedTarget
                    {
                        SelectedDelivery::UnsupportedTarget
                    } else if let Some(ref custom_ref) = self.custom_portainer_image {
                        // Custom Portainer images remain explicit registry pulls (E09)
                        SelectedDelivery::RegistryPull {
                            reference: custom_ref.clone(),
                            custom: true,
                        }
                    } else {
                        match self.variant {
                            Variant::Offline => SelectedDelivery::Bundled,
                            Variant::Online => SelectedDelivery::RegistryPull {
                                reference: default_ref.to_string(),
                                custom: false,
                            },
                        }
                    }
                } else {
                    SelectedDelivery::Disabled
                }
            },

            // D2K image
            AssetId::ImageKubesolo => {
                if self.variant == Variant::Offline {
                    SelectedDelivery::Bundled
                } else {
                    SelectedDelivery::RegistryPull {
                        reference: default_ref.to_string(),
                        custom: false,
                    }
                }
            },
            AssetId::ImageD2k => {
                if self.d2k_enabled {
                    if feature_support(self.target.architecture, OptionalFeature::D2k)
                        == FeatureSupport::UnsupportedTarget
                    {
                        SelectedDelivery::UnsupportedTarget
                    } else {
                        match self.variant {
                            Variant::Offline => SelectedDelivery::Bundled,
                            Variant::Online => SelectedDelivery::RegistryPull {
                                reference: default_ref.to_string(),
                                custom: false,
                            },
                        }
                    }
                } else {
                    SelectedDelivery::Disabled
                }
            },
        }
    }

    /// Whether this asset should be bundled in the distribution archive for this selection.
    pub fn is_bundled(&self, id: AssetId) -> bool {
        self.select_delivery(id).is_bundled()
    }

    /// Iterate over all catalog entries that are selected to be bundled.
    pub fn selected_bundled_assets(&self) -> impl Iterator<Item = CatalogEntry> + '_ {
        catalog()
            .iter()
            .copied()
            .filter(move |entry| self.is_bundled(entry.id))
    }

    /// Validate configuration and egress constraints.
    pub fn validate(&self) -> Result<(), SelectionError> {
        // Check for enabled features on unsupported targets
        if self.portainer_agent_enabled
            && feature_support(self.target.architecture, OptionalFeature::PortainerAgent)
                == FeatureSupport::UnsupportedTarget
        {
            return Err(SelectionError::UnsupportedTargetFeature {
                feature: OptionalFeature::PortainerAgent,
                architecture: self.target.architecture,
            });
        }

        if self.d2k_enabled
            && feature_support(self.target.architecture, OptionalFeature::D2k)
                == FeatureSupport::UnsupportedTarget
        {
            return Err(SelectionError::UnsupportedTargetFeature {
                feature: OptionalFeature::D2k,
                architecture: self.target.architecture,
            });
        }

        // If egress is denied, no active asset may require registry pull
        if self.egress_denied {
            for entry in catalog() {
                let delivery = self.select_delivery(entry.id);
                if let SelectedDelivery::RegistryPull { reference, custom } = delivery {
                    return Err(SelectionError::EgressDeniedRegistryRequired {
                        asset: entry.id,
                        reference,
                        custom,
                    });
                }
            }
        }

        Ok(())
    }
}
