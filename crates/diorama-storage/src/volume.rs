use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use diorama_apiserver::KubernetesApiClient;

use crate::config::{LOCAL_PATH_PROVISIONER_NAME, LOCAL_PATH_STORAGE_CLASS_NAME, LocalPathConfig};
use crate::error::{Result, StorageError};
use crate::manifests::provisioner_labels;

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

        if node_name.trim().is_empty() {
            return Err(StorageError::VolumeBindingFailed(
                "cannot provision volume without node placement".to_string(),
            ));
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

        // Validate storage class
        let requested_sc = pvc
            .get("spec")
            .and_then(|s| s.get("storageClassName"))
            .and_then(Value::as_str)
            .unwrap_or(LOCAL_PATH_STORAGE_CLASS_NAME);

        if requested_sc != LOCAL_PATH_STORAGE_CLASS_NAME && !requested_sc.is_empty() {
            return Err(StorageError::VolumeBindingFailed(format!(
                "PVC '{pvc_name}' requests unsupported StorageClass '{requested_sc}'"
            )));
        }

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
                    "pv.kubernetes.io/provisioned-by": LOCAL_PATH_PROVISIONER_NAME,
                },
                "labels": provisioner_labels(),
            },
            "spec": {
                "capacity": {
                    "storage": capacity,
                },
                "accessModes": access_modes,
                "persistentVolumeReclaimPolicy": self.config.reclaim_policy,
                "storageClassName": LOCAL_PATH_STORAGE_CLASS_NAME,
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
                                        "values": [node_name]
                                    }
                                ]
                            }
                        ]
                    }
                },
                "claimRef": {
                    "namespace": pvc_namespace,
                    "name": pvc_name,
                }
            },
            "status": {
                "phase": "Bound"
            }
        });

        let created_pv = self.client.create_pv(pv_doc).await?;

        // Update PVC to Bound status referencing the newly created PV
        if let Some(spec) = pvc.get_mut("spec").and_then(Value::as_object_mut) {
            spec.insert("volumeName".to_string(), json!(pv_name));
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
            node_name,
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

        let pvc = self.client.get_pvc(pvc_namespace, pvc_name).await?;

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

        // Delete the PVC only after the PV reclaim step succeeds
        self.client.delete_pvc(pvc_namespace, pvc_name).await?;

        Ok(action)
    }
}
