//! Strict declared asset inventory, encoded/decoded-byte checks and bounded ELF observations.
//!
//! These results do not authorize installation or prove runtime/ABI compatibility or OCI integrity.
mod archive;
pub use archive::{
    ArchiveError, ArchiveLayerObservation, ArchiveLimits, ArchivePolicyError,
    DockerArchiveObservation, ImageConfigObservation, ImagePlatformStatus,
};
mod catalog;
mod decode;
pub use decode::{
    CompressedElfError, DecodeError, DecodeLimits, DecodePolicyError, DecodeSession,
    DecodedElfInspection, DecodedObservation,
};
mod elf;
pub use elf::{ArmFloatAbi, ElfError, ElfInspection, ElfLimits, LoaderFamily, LoaderRelation};
mod inventory;
mod verify;
pub use catalog::{AssetId, CatalogEntry, Encoding, Kind, catalog};
pub use diorama_platform::{Architecture, Libc, NodeTarget};
pub use inventory::{
    DeclaredInventory, Delivery, FeatureSupport, InventoryError, InventoryRequest, Limits,
    Manifest, OptionalFeature, Scope, Variant, feature_support,
};
pub use verify::{EncodedBlobMatch, VerificationError, VerificationSession};

mod layer;
pub use layer::{
    LayerCodec, LayerDecodeLimits, LayerDigestArchiveObservation, LayerDigestObservation,
    LayerPolicyError,
};

mod manifest_binding;
pub use manifest_binding::{
    DeclaredImageManifestPin, ImageManifestBinding, ImageManifestFormat, ManifestBindingError,
    ManifestBindingLimits,
};

mod matrix;
pub use matrix::{
    ArtifactNaming, ArtifactNamingError, ManagementArch, ManagementOs, ManagementTarget,
    ManagementTargetError, Matrix, MatrixError, NodeVariant, ParsedManagementBinary,
    ParsedNodeArchive,
};

mod materialize;
pub use materialize::{
    AssetLayout, EXECUTABLE_PERMISSIONS, MaterializationError, MaterializationLimits,
    MaterializationOutcome, MaterializedAsset, Materializer, PAYLOAD_PERMISSIONS,
};

mod selection;
pub use selection::{AssetSelector, SelectedDelivery, SelectionError};

mod package;
pub use package::{
    ManagementArtifact, NodeArchiveArtifact, OciImageIndexArtifact, OciPlatformDescriptor,
    PackageError, ReleasePackageManifest, ReleasePackager,
};
