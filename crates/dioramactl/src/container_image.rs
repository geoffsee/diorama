use crate::contract::InstallOptions;
use diorama_assets::{ArchiveLimits, AssetId, DecodeSession, LayerDecodeLimits};

pub const DEFAULT_CONTAINER_IMAGE: &str = "ghcr.io/geoffsee/diorama";

/// Capability bound to the exact image bytes verified by a decoding session.
pub struct VerifiedContainerImage<'a> {
    reference: String,
    bytes: &'a [u8],
}

impl std::fmt::Debug for VerifiedContainerImage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedContainerImage")
            .field("reference", &self.reference)
            .field("encoded_bytes", &self.bytes.len())
            .finish()
    }
}

impl VerifiedContainerImage<'_> {
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

pub fn verify_container_image<'a>(
    session: &mut DecodeSession<'_>,
    bytes: &'a [u8],
) -> Result<VerifiedContainerImage<'a>, String> {
    let observation = session
        .verify_crane_image_layer_digests(
            AssetId::ImageDiorama,
            bytes,
            ArchiveLimits::default(),
            LayerDecodeLimits::default(),
        )
        .map_err(|e| format!("image payload verification failed: {e}"))?;
    let tags = observation.archive().repo_tags();
    if tags.len() != 1 {
        return Err("offline bundle must contain exactly one image repo tag".into());
    }
    let reference = tags[0].clone();
    Ok(VerifiedContainerImage { reference, bytes })
}

/// Resolves the container image to use based on the offline bundle or provided overrides.
///
/// If `--image` is explicitly provided, it takes precedence.
/// Otherwise, if an offline installation bundle is provided, we verify its layers
/// and extract the manifest tags to determine the exact image reference.
/// Finally, if neither is provided, we default to the well-known image and version.
pub fn select_container_image(
    options: &InstallOptions,
    offline_bundle: Option<(&mut DecodeSession<'_>, &[u8])>,
) -> Result<String, String> {
    if let Some(img) = &options.container_image
        && !img.is_empty()
    {
        return Ok(img.clone());
    }

    if let Some((session, bytes)) = offline_bundle {
        return Ok(verify_container_image(session, bytes)?.reference);
    }

    Ok(format!("{}:{}", DEFAULT_CONTAINER_IMAGE, options.version))
}

/// Resolve the image source and bind verified offline bytes to the actual install flow.
pub fn install_selected_container(
    engine: &mut dyn crate::container::ContainerEngineClient,
    options: &InstallOptions,
    mut params: crate::container::ContainerInstallParams,
    offline_bundle: Option<(&mut DecodeSession<'_>, &[u8])>,
) -> Result<crate::container::ContainerInstallResult, crate::container::ContainerLifecycleError> {
    let custom = options
        .container_image
        .as_ref()
        .is_some_and(|s| !s.is_empty());
    if !custom && let Some((session, bytes)) = offline_bundle {
        let image = verify_container_image(session, bytes)
            .map_err(crate::container::ContainerLifecycleError::Engine)?;
        params.image = image.reference().into();
        crate::container::install_container_with_bundled_image(engine, &params, &image)
    } else {
        params.image = select_container_image(options, None)
            .map_err(crate::container::ContainerLifecycleError::Engine)?;
        crate::container::install_container(engine, &params)
    }
}
