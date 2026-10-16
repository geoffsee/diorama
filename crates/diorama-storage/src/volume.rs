use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use diorama_apiserver::KubernetesApiClient;
use diorama_apiserver::time::now_rfc3339;

use crate::config::{
    IS_DEFAULT_CLASS_ANNOTATION, LOCAL_PATH_PROVISIONER_NAME, LOCAL_PATH_STORAGE_CLASS_NAME,
    LocalPathConfig, PV_PROTECTION_FINALIZER, PVC_PROTECTION_FINALIZER,
    STORAGE_PROVISIONED_BY_ANNOTATION, VOLUME_SELECTED_NODE_ANNOTATION,
};
use crate::error::{Result, StorageError};
use crate::manifests::{
    generate_csi_driver, generate_csi_node, generate_csi_storage_capacity,
    generate_volume_attachment, generate_volume_attributes_class, provisioner_labels,
};

/// Action taken during persistent volume claim deletion and reclaim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum VolumeReclaimAction {
    /// Volume data and `PersistentVolume` object are retained on the host.
    Retained { pv_name: String, path: String },
    /// Volume directory on host and `PersistentVolume` object were deleted.
    Deleted { pv_name: String, path: String },
}

/// Safely resolve a subpath under an allowed base storage root.
///
/// Ensures the path:
/// 1. Contains no null bytes or path traversal sequences (`..`).
/// 2. Is not absolute.
/// 3. Resolves strictly inside `base_dir` and is not equal to `base_dir` itself.
pub fn safe_resolve_volume_path(base_dir: &Path, relative_subpath: &str) -> Result<PathBuf> {
    if relative_subpath.is_empty() {
        return Err(StorageError::PathSecurityViolation(
            "subpath cannot be empty".to_string(),
        ));
    }

    if relative_subpath.contains('\0') {
        return Err(StorageError::PathSecurityViolation(
            "subpath contains null bytes".to_string(),
        ));
    }

    let sub_path = Path::new(relative_subpath);
    if sub_path.is_absolute() {
        return Err(StorageError::PathSecurityViolation(format!(
            "subpath cannot be absolute: {relative_subpath}"
        )));
    }

    for component in sub_path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(StorageError::PathSecurityViolation(format!(
                    "path traversal detected in subpath: {relative_subpath}"
                )));
            },
            std::path::Component::Normal(_) | std::path::Component::CurDir => {},
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(StorageError::PathSecurityViolation(format!(
                    "invalid path component in subpath: {relative_subpath}"
                )));
            },
        }
    }

    let candidate = base_dir.join(sub_path);

    if candidate == base_dir {
        return Err(StorageError::PathSecurityViolation(
            "subpath resolves to the storage root itself".to_string(),
        ));
    }

    if !candidate.starts_with(base_dir) {
        return Err(StorageError::PathSecurityViolation(format!(
            "candidate path {} escapes storage root {}",
            candidate.display(),
            base_dir.display()
        )));
    }

    Ok(candidate)
}

/// Safely teardown a volume directory on host without endangering unrelated host data.
///
/// Refuses to remove the base directory, paths outside the base directory,
/// or paths with directory traversal components.
pub fn safe_teardown_volume_dir(base_dir: &Path, vol_dir: &Path) -> Result<()> {
    if vol_dir == base_dir {
        return Err(StorageError::PathSecurityViolation(format!(
            "refusing to teardown base storage root {}",
            base_dir.display()
        )));
    }

    for component in vol_dir.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(StorageError::PathSecurityViolation(format!(
                "path traversal in volume directory: {}",
                vol_dir.display()
            )));
        }
    }

    if !vol_dir.starts_with(base_dir) {
        return Err(StorageError::PathSecurityViolation(format!(
            "volume directory {} escapes storage root {}",
            vol_dir.display(),
            base_dir.display()
        )));
    }

    // Validate that no component between base_dir and vol_dir is a symlink
    let mut current = base_dir.to_path_buf();
    if let Ok(rel) = vol_dir.strip_prefix(base_dir) {
        for component in rel.components() {
            current.push(component);
            if std::fs::symlink_metadata(&current).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(StorageError::PathSecurityViolation(format!(
                    "symlink component detected in volume path: {}",
                    current.display()
                )));
            }
        }
    }

    if vol_dir.exists() {
        let meta = std::fs::symlink_metadata(vol_dir).map_err(|e| {
            StorageError::ReclaimFailed(format!(
                "failed to inspect volume directory metadata {}: {e}",
                vol_dir.display()
            ))
        })?;
        if meta.file_type().is_symlink() {
            return Err(StorageError::PathSecurityViolation(format!(
                "refusing to remove symlinked volume path {}",
                vol_dir.display()
            )));
        }
        if !meta.is_dir() {
            return Err(StorageError::PathSecurityViolation(format!(
                "volume path {} is not a directory",
                vol_dir.display()
            )));
        }
        std::fs::remove_dir_all(vol_dir).map_err(|e| {
            StorageError::ReclaimFailed(format!(
                "failed to remove volume directory {}: {e}",
                vol_dir.display()
            ))
        })?;
        info!(
            "successfully removed volume directory {} during reclaim",
            vol_dir.display()
        );
    } else {
        warn!(
            "volume directory {} did not exist during reclaim teardown",
            vol_dir.display()
        );
    }

    Ok(())
}

/// Volume provisioner and binding manager for local-path storage.
///
/// Implements:
/// - First-consumer volume binding (`WaitForFirstConsumer`).
/// - Placement integration (binding only when pod is scheduled to a node).
/// - Normal host path vs `sharedFileSystemPath` volume creation.
/// - Volume directory boundary protection ensuring no unrelated host data is touched.
/// - Reclaim execution for `Retain` and `Delete` policies.
#[derive(Debug, Clone)]
pub struct LocalPathVolumeManager {
    config: LocalPathConfig,
    client: KubernetesApiClient,
}

impl LocalPathVolumeManager {
    /// Create a new `LocalPathVolumeManager` with the specified configuration and API client.
    #[must_use]
    pub fn new(config: LocalPathConfig, client: KubernetesApiClient) -> Self {
        Self { config, client }
    }

    /// Effective base directory for volume provisioning (shared path or standard storage path).
    #[must_use]
    pub fn effective_base_path(&self) -> PathBuf {
        if let Some(ref shared) = self.config.shared_path {
            PathBuf::from(shared)
        } else {
            PathBuf::from(&self.config.storage_path)
        }
    }

    /// Access reference to current configuration.
    #[must_use]
    pub fn config(&self) -> &LocalPathConfig {
        &self.config
    }

    /// Access reference to API client.
    #[must_use]
    pub fn client(&self) -> &KubernetesApiClient {
        &self.client
    }

    async fn resolve_default_storage_class(&self) -> (String, String, String) {
        let mut default_name = LOCAL_PATH_STORAGE_CLASS_NAME.to_string();
        let mut policy = self.config.reclaim_policy.clone();
        let mut mode = self.config.volume_binding_mode.clone();

        let Ok(sc_list) = self.client.list_storage_classes().await else {
            return (default_name, policy, mode);
        };
        let Some(items) = sc_list.get("items").and_then(Value::as_array) else {
            return (default_name, policy, mode);
        };
        for item in items {
            let is_default = item
                .get("metadata")
                .and_then(|m| m.get("annotations"))
                .and_then(|a| a.get(IS_DEFAULT_CLASS_ANNOTATION))
                .and_then(Value::as_str)
                == Some("true");
            if !is_default {
                continue;
            }
            if let Some(name) = item.pointer("/metadata/name").and_then(Value::as_str) {
                default_name = name.to_string();
            }
            if let Some(p) = item.get("reclaimPolicy").and_then(Value::as_str) {
                policy = p.to_string();
            }
            if let Some(m) = item.get("volumeBindingMode").and_then(Value::as_str) {
                mode = m.to_string();
            }
            break;
        }
        (default_name, policy, mode)
    }

    /// Provision a persistent volume for a PVC, placing it on the designated node.
    #[allow(clippy::too_many_lines, clippy::similar_names, clippy::collapsible_if)]
    pub async fn provision_volume_for_pvc(
        &self,
        pvc_namespace: &str,
        pvc_name: &str,
        node_name: &str,
    ) -> Result<Value> {
        if !self.config.enabled {
            return Err(StorageError::Disabled);
        }

        let mut pvc = self.client.get_pvc(pvc_namespace, pvc_name).await?;

        // If already bound, return existing PV
        let phase = pvc
            .get("status")
            .and_then(|s| s.get("phase"))
            .and_then(Value::as_str);
        let bound_vol = pvc
            .get("spec")
            .and_then(|s| s.get("volumeName"))
            .and_then(Value::as_str);
        if let (Some("Bound"), Some(vol_name)) = (phase, bound_vol) {
            if let Ok(pv) = self.client.get_pv(vol_name).await {
                return Ok(pv);
            }
        }

        // Validate and resolve storage class:
        // - Some(""): disables dynamic provisioning in Kubernetes
        // - Some(name): match local-path or custom storage class registered with our provisioner
        // - None: resolve default StorageClass from cluster, or fallback to configured default
        let requested_sc = pvc
            .get("spec")
            .and_then(|s| s.get("storageClassName"))
            .and_then(Value::as_str);

        let (effective_sc_name, reclaim_policy, volume_binding_mode) = match requested_sc {
            Some("") => {
                return Err(StorageError::VolumeBindingFailed(format!(
                    "PVC '{pvc_name}' has empty storageClassName (dynamic provisioning disabled)"
                )));
            },
            Some(LOCAL_PATH_STORAGE_CLASS_NAME) => (
                LOCAL_PATH_STORAGE_CLASS_NAME.to_string(),
                self.config.reclaim_policy.clone(),
                self.config.volume_binding_mode.clone(),
            ),
            Some(other) => match self.client.get_storage_class(other).await {
                Ok(sc_doc) => {
                    let provisioner = sc_doc
                        .get("provisioner")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if provisioner != LOCAL_PATH_PROVISIONER_NAME {
                        return Err(StorageError::VolumeBindingFailed(format!(
                            "PVC '{pvc_name}' requests unsupported StorageClass '{other}' with provisioner '{provisioner}'"
                        )));
                    }
                    let policy = sc_doc
                        .get("reclaimPolicy")
                        .and_then(Value::as_str)
                        .unwrap_or(&self.config.reclaim_policy)
                        .to_string();
                    let mode = sc_doc
                        .get("volumeBindingMode")
                        .and_then(Value::as_str)
                        .unwrap_or(&self.config.volume_binding_mode)
                        .to_string();
                    (other.to_string(), policy, mode)
                },
                Err(_) => {
                    return Err(StorageError::VolumeBindingFailed(format!(
                        "PVC '{pvc_name}' requests StorageClass '{other}' which was not found"
                    )));
                },
            },
            None => self.resolve_default_storage_class().await,
        };

        // Node placement & WaitForFirstConsumer resolution:
        // 1. Explicit node_name argument (e.g. from scheduled pod)
        // 2. Or pre-existing volume.kubernetes.io/selected-node annotation on PVC
        let effective_node = if !node_name.trim().is_empty() {
            node_name.trim().to_string()
        } else if let Some(selected) = pvc
            .pointer("/metadata/annotations/volume.kubernetes.io~1selected-node")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
        {
            selected.to_string()
        } else if volume_binding_mode == "WaitForFirstConsumer" {
            return Err(StorageError::VolumeBindingFailed(format!(
                "cannot provision volume for PVC '{pvc_name}' without node placement (WaitForFirstConsumer waiting)"
            )));
        } else {
            return Err(StorageError::VolumeBindingFailed(
                "cannot provision volume without node placement".to_string(),
            ));
        };

        let pvc_uid = pvc
            .get("metadata")
            .and_then(|m| m.get("uid"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                StorageError::VolumeBindingFailed(format!(
                    "PVC '{pvc_name}' in namespace '{pvc_namespace}' is missing metadata.uid"
                ))
            })?;

        let base_dir = self.effective_base_path();
        let pv_name = format!("pvc-{pvc_uid}");
        let dir_name = format!("{pvc_namespace}_{pvc_name}_{pv_name}");

        let vol_dir = safe_resolve_volume_path(&base_dir, &dir_name)?;

        // Recover existing deterministic PV if it was created in a previous attempt
        if let Ok(existing_pv) = self.client.get_pv(&pv_name).await {
            let claim_ns = existing_pv
                .pointer("/spec/claimRef/namespace")
                .and_then(Value::as_str);
            let claim_name = existing_pv
                .pointer("/spec/claimRef/name")
                .and_then(Value::as_str);
            if claim_ns != Some(pvc_namespace) || claim_name != Some(pvc_name) {
                return Err(StorageError::VolumeBindingFailed(format!(
                    "PV '{pv_name}' already exists with mismatched claimRef ({claim_ns:?}/{claim_name:?})"
                )));
            }

            std::fs::create_dir_all(&vol_dir)?;

            if let Some(spec) = pvc.get_mut("spec").and_then(Value::as_object_mut) {
                spec.insert("volumeName".to_string(), json!(pv_name));
            }
            if let Some(meta) = pvc.get_mut("metadata").and_then(Value::as_object_mut) {
                let annotations = meta
                    .entry("annotations".to_string())
                    .or_insert_with(|| json!({}));
                if let Some(ann) = annotations.as_object_mut() {
                    ann.insert(
                        VOLUME_SELECTED_NODE_ANNOTATION.to_string(),
                        json!(effective_node),
                    );
                }
                let finalizers = meta
                    .entry("finalizers".to_string())
                    .or_insert_with(|| json!([]));
                if let Some(arr) = finalizers.as_array_mut()
                    && !arr
                        .iter()
                        .any(|v| v.as_str() == Some(PVC_PROTECTION_FINALIZER))
                {
                    arr.push(json!(PVC_PROTECTION_FINALIZER));
                }
            }
            if let Some(status) = pvc.get_mut("status").and_then(Value::as_object_mut) {
                status.insert("phase".to_string(), json!("Bound"));
            } else if let Some(pvc_obj) = pvc.as_object_mut() {
                pvc_obj.insert("status".to_string(), json!({ "phase": "Bound" }));
            }
            self.client.update_pvc(pvc_namespace, pvc_name, pvc).await?;
            return Ok(existing_pv);
        }

        // Create volume directory with 0777 permissions (per setup script)
        std::fs::create_dir_all(&vol_dir)?;

        let capacity = pvc
            .get("spec")
            .and_then(|s| s.get("resources"))
            .and_then(|r| r.get("requests"))
            .and_then(|req| req.get("storage"))
            .cloned()
            .unwrap_or_else(|| json!("1Gi"));

        let access_modes = pvc
            .get("spec")
            .and_then(|s| s.get("accessModes"))
            .cloned()
            .unwrap_or_else(|| json!(["ReadWriteOnce"]));

        let pv_doc = json!({
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": {
                "name": pv_name,
                "annotations": {
                    STORAGE_PROVISIONED_BY_ANNOTATION: LOCAL_PATH_PROVISIONER_NAME,
                    VOLUME_SELECTED_NODE_ANNOTATION: effective_node,
                },
                "finalizers": [PV_PROTECTION_FINALIZER],
                "labels": provisioner_labels(),
            },
            "spec": {
                "capacity": {
                    "storage": capacity,
                },
                "accessModes": access_modes,
                "persistentVolumeReclaimPolicy": reclaim_policy,
                "storageClassName": effective_sc_name,
                "local": {
                    "path": vol_dir.display().to_string(),
                },
                "nodeAffinity": {
                    "required": {
                        "nodeSelectorTerms": [
                            {
                                "matchExpressions": [
                                    {
                                        "key": "kubernetes.io/hostname",
                                        "operator": "In",
                                        "values": [&effective_node]
                                    }
                                ]
                            }
                        ]
                    }
                },
                "claimRef": {
                    "apiVersion": "v1",
                    "kind": "PersistentVolumeClaim",
                    "namespace": pvc_namespace,
                    "name": pvc_name,
                    "uid": pvc_uid,
                }
            },
            "status": {
                "phase": "Bound"
            }
        });

        let created_pv = self.client.create_pv(pv_doc).await?;

        // Update PVC to Bound status referencing the newly created PV with protection finalizer
        if let Some(spec) = pvc.get_mut("spec").and_then(Value::as_object_mut) {
            spec.insert("volumeName".to_string(), json!(pv_name));
        }
        if let Some(meta) = pvc.get_mut("metadata").and_then(Value::as_object_mut) {
            let annotations = meta
                .entry("annotations".to_string())
                .or_insert_with(|| json!({}));
            if let Some(ann) = annotations.as_object_mut() {
                ann.insert(
                    VOLUME_SELECTED_NODE_ANNOTATION.to_string(),
                    json!(effective_node),
                );
            }
            let finalizers = meta
                .entry("finalizers".to_string())
                .or_insert_with(|| json!([]));
            if let Some(arr) = finalizers.as_array_mut()
                && !arr
                    .iter()
                    .any(|v| v.as_str() == Some(PVC_PROTECTION_FINALIZER))
            {
                arr.push(json!(PVC_PROTECTION_FINALIZER));
            }
        }
        if let Some(status) = pvc.get_mut("status").and_then(Value::as_object_mut) {
            status.insert("phase".to_string(), json!("Bound"));
        } else if let Some(pvc_obj) = pvc.as_object_mut() {
            pvc_obj.insert("status".to_string(), json!({ "phase": "Bound" }));
        }

        self.client.update_pvc(pvc_namespace, pvc_name, pvc).await?;
        info!(
            "provisioned and bound volume {} on node {} at {}",
            pv_name,
            effective_node,
            vol_dir.display()
        );

        Ok(created_pv)
    }

    /// Trigger first-consumer volume binding for all PVCs referenced by a Pod.
    ///
    /// Requires that the Pod has been assigned a `spec.nodeName` (placement integration).
    pub async fn bind_volumes_for_pod(
        &self,
        pod_namespace: &str,
        pod_name: &str,
    ) -> Result<Vec<Value>> {
        if !self.config.enabled {
            return Err(StorageError::Disabled);
        }

        let pod = self.client.get_pod(pod_namespace, pod_name).await?;

        let node_name = pod
            .get("spec")
            .and_then(|s| s.get("nodeName"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                StorageError::VolumeBindingFailed(format!(
                    "pod '{pod_name}' has no node placement assigned (WaitForFirstConsumer waiting)"
                ))
            })?;

        if node_name.trim().is_empty() {
            return Err(StorageError::VolumeBindingFailed(format!(
                "pod '{pod_name}' node placement is empty"
            )));
        }

        let mut bound_pvs = Vec::new();
        let volumes = pod
            .get("spec")
            .and_then(|s| s.get("volumes"))
            .and_then(Value::as_array);

        if let Some(volumes) = volumes {
            for vol in volumes {
                let claim_name = vol
                    .get("persistentVolumeClaim")
                    .and_then(|pvc| pvc.get("claimName"))
                    .and_then(Value::as_str);
                if let Some(claim) = claim_name {
                    let pv = self
                        .provision_volume_for_pvc(pod_namespace, claim, node_name)
                        .await?;
                    bound_pvs.push(pv);
                }
            }
        }

        Ok(bound_pvs)
    }

    /// Reclaim a PVC and its associated PV according to the configured reclaim policy.
    ///
    /// - `Retain`: Deletes the PVC; marks PV as `Released`; host data is retained untouched.
    /// - `Delete`: Deletes the volume directory on host; deletes the PV; protects all unrelated host data.
    pub async fn reclaim_pvc(
        &self,
        pvc_namespace: &str,
        pvc_name: &str,
    ) -> Result<VolumeReclaimAction> {
        if !self.config.enabled {
            return Err(StorageError::Disabled);
        }

        let mut pvc = self.client.get_pvc(pvc_namespace, pvc_name).await?;

        // Protect against reclaim/deletion while actively in use by a Pod
        if self.is_pvc_in_use(pvc_namespace, pvc_name).await? {
            return Err(StorageError::VolumeBindingFailed(format!(
                "PVC '{pvc_name}' in namespace '{pvc_namespace}' is currently in use by an active pod (pvc-protection prevents deletion)"
            )));
        }

        let vol_name = pvc
            .get("spec")
            .and_then(|s| s.get("volumeName"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                StorageError::VolumeNotFound(format!(
                    "PVC '{pvc_name}' does not have a bound volumeName"
                ))
            })?
            .to_string();

        let mut pv = self.client.get_pv(&vol_name).await?;

        let vol_path_str = pv
            .get("spec")
            .and_then(|s| s.get("local"))
            .and_then(|l| l.get("path"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let reclaim_policy = pv
            .get("spec")
            .and_then(|s| s.get("persistentVolumeReclaimPolicy"))
            .and_then(Value::as_str)
            .unwrap_or(&self.config.reclaim_policy);

        let base_dir = self.effective_base_path();

        let action = if reclaim_policy == "Delete" {
            if !vol_path_str.is_empty() {
                let vol_path = PathBuf::from(&vol_path_str);
                safe_teardown_volume_dir(&base_dir, &vol_path)?;
            }
            // Remove pv-protection finalizer if present before deletion
            if let Some(finalizers) = pv
                .pointer_mut("/metadata/finalizers")
                .and_then(Value::as_array_mut)
            {
                finalizers.retain(|f| f.as_str() != Some(PV_PROTECTION_FINALIZER));
                let _ = self.client.update_pv(&vol_name, pv).await;
            }
            self.client.delete_pv(&vol_name).await?;
            VolumeReclaimAction::Deleted {
                pv_name: vol_name,
                path: vol_path_str,
            }
        } else {
            // Retain behavior
            if let Some(status) = pv.get_mut("status").and_then(Value::as_object_mut) {
                status.insert("phase".to_string(), json!("Released"));
            } else if let Some(pv_obj) = pv.as_object_mut() {
                pv_obj.insert("status".to_string(), json!({ "phase": "Released" }));
            }
            self.client.update_pv(&vol_name, pv).await?;
            info!(
                "retained volume {} on host at {} with phase Released",
                vol_name, vol_path_str
            );
            VolumeReclaimAction::Retained {
                pv_name: vol_name,
                path: vol_path_str,
            }
        };

        // Remove pvc-protection finalizer from PVC before final deletion
        if let Some(finalizers) = pvc
            .pointer_mut("/metadata/finalizers")
            .and_then(Value::as_array_mut)
        {
            finalizers.retain(|f| f.as_str() != Some(PVC_PROTECTION_FINALIZER));
            let _ = self.client.update_pvc(pvc_namespace, pvc_name, pvc).await;
        }

        // Delete the PVC only after the PV reclaim step succeeds
        self.client.delete_pvc(pvc_namespace, pvc_name).await?;

        Ok(action)
    }

    /// Check whether a PVC is actively referenced by any non-completed Pod in the namespace.
    pub async fn is_pvc_in_use(&self, pvc_namespace: &str, pvc_name: &str) -> Result<bool> {
        let Ok(pod_list) = self.client.list_pods(pvc_namespace).await else {
            return Ok(false);
        };
        let Some(pods) = pod_list.get("items").and_then(Value::as_array) else {
            return Ok(false);
        };

        for pod in pods {
            let phase = pod
                .pointer("/status/phase")
                .and_then(Value::as_str)
                .unwrap_or("Pending");
            if phase == "Succeeded" || phase == "Failed" {
                continue;
            }
            let Some(volumes) = pod.pointer("/spec/volumes").and_then(Value::as_array) else {
                continue;
            };
            let in_use = volumes.iter().any(|vol| {
                vol.pointer("/persistentVolumeClaim/claimName")
                    .and_then(Value::as_str)
                    == Some(pvc_name)
            });
            if in_use {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Verifies bi-directional binding consistency between a PVC and its bound PV.
    pub async fn verify_binding(&self, pvc_namespace: &str, pvc_name: &str) -> Result<bool> {
        let pvc = self.client.get_pvc(pvc_namespace, pvc_name).await?;
        let vol_name = pvc
            .pointer("/spec/volumeName")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                StorageError::VolumeNotFound(format!("PVC '{pvc_name}' has no volumeName"))
            })?;
        let pv = self.client.get_pv(vol_name).await?;

        let pvc_uid = pvc
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or("");
        let claim_ns = pv
            .pointer("/spec/claimRef/namespace")
            .and_then(Value::as_str)
            .unwrap_or("");
        let claim_name = pv
            .pointer("/spec/claimRef/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let claim_uid = pv
            .pointer("/spec/claimRef/uid")
            .and_then(Value::as_str)
            .unwrap_or("");

        let claim_phase = pvc.pointer("/status/phase").and_then(Value::as_str);
        let volume_phase = pv.pointer("/status/phase").and_then(Value::as_str);

        Ok(claim_ns == pvc_namespace
            && claim_name == pvc_name
            && (claim_uid.is_empty() || claim_uid == pvc_uid)
            && claim_phase == Some("Bound")
            && volume_phase == Some("Bound"))
    }

    /// Ensures the PVC protection finalizer (`kubernetes.io/pvc-protection`) is present.
    pub async fn ensure_pvc_protection(
        &self,
        pvc_namespace: &str,
        pvc_name: &str,
    ) -> Result<Value> {
        let mut pvc = self.client.get_pvc(pvc_namespace, pvc_name).await?;
        if let Some(obj) = pvc.as_object_mut() {
            let meta = obj
                .entry("metadata".to_string())
                .or_insert_with(|| json!({}));
            if let Some(meta_obj) = meta.as_object_mut() {
                let finalizers = meta_obj
                    .entry("finalizers".to_string())
                    .or_insert_with(|| json!([]));
                if let Some(arr) = finalizers.as_array_mut()
                    && !arr
                        .iter()
                        .any(|v| v.as_str() == Some(PVC_PROTECTION_FINALIZER))
                {
                    arr.push(json!(PVC_PROTECTION_FINALIZER));
                    return self
                        .client
                        .update_pvc(pvc_namespace, pvc_name, pvc)
                        .await
                        .map_err(StorageError::Apiserver);
                }
            }
        }
        Ok(pvc)
    }

    /// Removes the PVC protection finalizer (`kubernetes.io/pvc-protection`).
    pub async fn remove_pvc_protection(
        &self,
        pvc_namespace: &str,
        pvc_name: &str,
    ) -> Result<Value> {
        let mut pvc = self.client.get_pvc(pvc_namespace, pvc_name).await?;
        if let Some(finalizers) = pvc
            .pointer_mut("/metadata/finalizers")
            .and_then(Value::as_array_mut)
        {
            finalizers.retain(|f| f.as_str() != Some(PVC_PROTECTION_FINALIZER));
            return self
                .client
                .update_pvc(pvc_namespace, pvc_name, pvc)
                .await
                .map_err(StorageError::Apiserver);
        }
        Ok(pvc)
    }

    /// Ensures the PV protection finalizer (`kubernetes.io/pv-protection`) is present.
    pub async fn ensure_pv_protection(&self, pv_name: &str) -> Result<Value> {
        let mut pv = self.client.get_pv(pv_name).await?;
        if let Some(obj) = pv.as_object_mut() {
            let meta = obj
                .entry("metadata".to_string())
                .or_insert_with(|| json!({}));
            if let Some(meta_obj) = meta.as_object_mut() {
                let finalizers = meta_obj
                    .entry("finalizers".to_string())
                    .or_insert_with(|| json!([]));
                if let Some(arr) = finalizers.as_array_mut()
                    && !arr
                        .iter()
                        .any(|v| v.as_str() == Some(PV_PROTECTION_FINALIZER))
                {
                    arr.push(json!(PV_PROTECTION_FINALIZER));
                    return self
                        .client
                        .update_pv(pv_name, pv)
                        .await
                        .map_err(StorageError::Apiserver);
                }
            }
        }
        Ok(pv)
    }

    /// Removes the PV protection finalizer (`kubernetes.io/pv-protection`).
    pub async fn remove_pv_protection(&self, pv_name: &str) -> Result<Value> {
        let mut pv = self.client.get_pv(pv_name).await?;
        if let Some(finalizers) = pv
            .pointer_mut("/metadata/finalizers")
            .and_then(Value::as_array_mut)
        {
            finalizers.retain(|f| f.as_str() != Some(PV_PROTECTION_FINALIZER));
            return self
                .client
                .update_pv(pv_name, pv)
                .await
                .map_err(StorageError::Apiserver);
        }
        Ok(pv)
    }

    /// Register or ensure a `CSIDriver` object exists in the cluster.
    pub async fn ensure_csi_driver(
        &self,
        driver_name: &str,
        attach_required: bool,
        pod_info_on_mount: bool,
        storage_capacity: bool,
    ) -> Result<Value> {
        if let Ok(existing) = self
            .client
            .get_cluster_object("storage.k8s.io", "csidrivers", driver_name)
            .await
        {
            Ok(existing)
        } else {
            let doc = generate_csi_driver(
                driver_name,
                attach_required,
                pod_info_on_mount,
                storage_capacity,
            );
            self.client
                .create_cluster_object("storage.k8s.io", "CSIDriver", "csidrivers", doc)
                .await
                .map_err(StorageError::Apiserver)
        }
    }

    /// Get a `CSIDriver` object.
    pub async fn get_csi_driver(&self, driver_name: &str) -> Result<Value> {
        self.client
            .get_cluster_object("storage.k8s.io", "csidrivers", driver_name)
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Delete a `CSIDriver` object.
    pub async fn delete_csi_driver(&self, driver_name: &str) -> Result<()> {
        self.client
            .delete_cluster_object("storage.k8s.io", "csidrivers", driver_name)
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Register or ensure a `CSINode` object exists in the cluster.
    pub async fn ensure_csi_node(
        &self,
        node_name: &str,
        driver_name: &str,
        node_id: &str,
        topology_keys: &[&str],
    ) -> Result<Value> {
        if let Ok(existing) = self
            .client
            .get_cluster_object("storage.k8s.io", "csinodes", node_name)
            .await
        {
            Ok(existing)
        } else {
            let doc = generate_csi_node(node_name, driver_name, node_id, topology_keys);
            self.client
                .create_cluster_object("storage.k8s.io", "CSINode", "csinodes", doc)
                .await
                .map_err(StorageError::Apiserver)
        }
    }

    /// Get a `CSINode` object.
    pub async fn get_csi_node(&self, node_name: &str) -> Result<Value> {
        self.client
            .get_cluster_object("storage.k8s.io", "csinodes", node_name)
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Delete a `CSINode` object.
    pub async fn delete_csi_node(&self, node_name: &str) -> Result<()> {
        self.client
            .delete_cluster_object("storage.k8s.io", "csinodes", node_name)
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Record or update storage capacity in `CSIStorageCapacity`.
    pub async fn record_storage_capacity(
        &self,
        namespace: &str,
        name: &str,
        storage_class: &str,
        capacity_bytes: i64,
        node_topology: Option<&BTreeMap<String, String>>,
    ) -> Result<Value> {
        let doc = generate_csi_storage_capacity(
            namespace,
            name,
            storage_class,
            capacity_bytes,
            node_topology,
        );
        match self
            .client
            .get_namespaced_object("storage.k8s.io", "csistoragecapacities", namespace, name)
            .await
        {
            Ok(_) => self
                .client
                .replace_namespaced_object(
                    "storage.k8s.io",
                    "CSIStorageCapacity",
                    "csistoragecapacities",
                    namespace,
                    name,
                    doc,
                )
                .await
                .map_err(StorageError::Apiserver),
            Err(_) => self
                .client
                .create_namespaced_object(
                    "storage.k8s.io",
                    "CSIStorageCapacity",
                    "csistoragecapacities",
                    namespace,
                    doc,
                )
                .await
                .map_err(StorageError::Apiserver),
        }
    }

    /// Get recorded storage capacity in bytes.
    pub async fn get_storage_capacity(&self, namespace: &str, name: &str) -> Result<Option<i64>> {
        let doc = self
            .client
            .get_namespaced_object("storage.k8s.io", "csistoragecapacities", namespace, name)
            .await
            .map_err(StorageError::Apiserver)?;
        let capacity_str = doc.get("capacity").and_then(Value::as_str);
        if let Some(cap) = capacity_str {
            let bytes = cap.parse::<i64>().unwrap_or(0);
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }

    /// Delete a `CSIStorageCapacity` object.
    pub async fn delete_storage_capacity(&self, namespace: &str, name: &str) -> Result<()> {
        self.client
            .delete_namespaced_object("storage.k8s.io", "csistoragecapacities", namespace, name)
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Create a `VolumeAttachment` resource.
    pub async fn create_volume_attachment(
        &self,
        name: &str,
        attacher: &str,
        node_name: &str,
        pv_name: &str,
    ) -> Result<Value> {
        let doc = generate_volume_attachment(name, attacher, node_name, pv_name);
        self.client
            .create_cluster_object(
                "storage.k8s.io",
                "VolumeAttachment",
                "volumeattachments",
                doc,
            )
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Get a `VolumeAttachment` resource.
    pub async fn get_volume_attachment(&self, name: &str) -> Result<Value> {
        self.client
            .get_cluster_object("storage.k8s.io", "volumeattachments", name)
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Update attachment status of a `VolumeAttachment` (`attached: true | false`).
    pub async fn set_volume_attachment_status(&self, name: &str, attached: bool) -> Result<Value> {
        let mut doc = self
            .client
            .get_cluster_object("storage.k8s.io", "volumeattachments", name)
            .await
            .map_err(StorageError::Apiserver)?;
        if let Some(status) = doc.get_mut("status").and_then(Value::as_object_mut) {
            status.insert("attached".to_string(), json!(attached));
        } else if let Some(obj) = doc.as_object_mut() {
            obj.insert("status".to_string(), json!({ "attached": attached }));
        }
        self.client
            .replace_cluster_object(
                "storage.k8s.io",
                "VolumeAttachment",
                "volumeattachments",
                name,
                doc,
            )
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Delete a `VolumeAttachment` resource.
    pub async fn delete_volume_attachment(&self, name: &str) -> Result<()> {
        self.client
            .delete_cluster_object("storage.k8s.io", "volumeattachments", name)
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Create a `VolumeAttributesClass` resource (Issue #503).
    pub async fn create_volume_attributes_class(
        &self,
        name: &str,
        driver_name: &str,
        parameters: &std::collections::BTreeMap<String, String>,
    ) -> Result<Value> {
        let doc = generate_volume_attributes_class(name, driver_name, parameters);
        self.client
            .create_cluster_object(
                "storage.k8s.io",
                "VolumeAttributesClass",
                "volumeattributesclasses",
                doc,
            )
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Get a `VolumeAttributesClass` resource (Issue #503).
    pub async fn get_volume_attributes_class(&self, name: &str) -> Result<Value> {
        self.client
            .get_cluster_object("storage.k8s.io", "volumeattributesclasses", name)
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Delete a `VolumeAttributesClass` resource (Issue #503).
    pub async fn delete_volume_attributes_class(&self, name: &str) -> Result<()> {
        self.client
            .delete_cluster_object("storage.k8s.io", "volumeattributesclasses", name)
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Update PVC status condition (Issue #456).
    pub async fn update_pvc_condition(
        &self,
        namespace: &str,
        name: &str,
        condition_type: &str,
        status: &str,
        reason: &str,
        message: &str,
    ) -> Result<Value> {
        let mut pvc = self
            .client
            .get_pvc(namespace, name)
            .await
            .map_err(StorageError::Apiserver)?;
        let condition = json!({
            "type": condition_type,
            "status": status,
            "reason": reason,
            "message": message,
            "lastTransitionTime": now_rfc3339()
        });
        if let Some(obj) = pvc.as_object_mut() {
            let status_obj = obj.entry("status".to_string()).or_insert_with(|| json!({}));
            if let Some(s) = status_obj.as_object_mut() {
                let conditions = s
                    .entry("conditions".to_string())
                    .or_insert_with(|| json!([]));
                if let Some(arr) = conditions.as_array_mut() {
                    arr.retain(|c| c.get("type").and_then(Value::as_str) != Some(condition_type));
                    arr.push(condition);
                }
            }
        }
        self.client
            .update_pvc(namespace, name, pvc)
            .await
            .map_err(StorageError::Apiserver)
    }

    /// Update PV status phase and optional reason/message (Issue #456).
    pub async fn update_pv_status_details(
        &self,
        name: &str,
        phase: &str,
        reason: Option<&str>,
        message: Option<&str>,
    ) -> Result<Value> {
        let mut pv = self
            .client
            .get_pv(name)
            .await
            .map_err(StorageError::Apiserver)?;
        if let Some(obj) = pv.as_object_mut() {
            let status_obj = obj.entry("status".to_string()).or_insert_with(|| json!({}));
            if let Some(status) = status_obj.as_object_mut() {
                status.insert("phase".to_string(), json!(phase));
                if let Some(r) = reason {
                    status.insert("reason".to_string(), json!(r));
                }
                if let Some(m) = message {
                    status.insert("message".to_string(), json!(m));
                }
            }
        }
        self.client
            .update_pv(name, pv)
            .await
            .map_err(StorageError::Apiserver)
    }
}
