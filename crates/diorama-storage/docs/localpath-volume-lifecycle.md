# Local-Path Volume Lifecycle, First-Consumer Binding, and Reclaim Semantics

This document details the volume binding lifecycle, pod placement integration, data persistence guarantees, reclaim policies, and filesystem security boundaries in `diorama-storage`.

---

## 1. First-Consumer Binding (`WaitForFirstConsumer`) & Placement Integration

KubeSolo configures the default `local-path` `StorageClass` with `volumeBindingMode: WaitForFirstConsumer`.

### Lifecycle States
1. **PVC Creation (`Pending`)**:
   - When a consumer submits a `PersistentVolumeClaim` referencing `storageClassName: local-path`, the claim remains in the `Pending` phase.
   - Storage resources (directories and PVs) are **not** created at claim time.
2. **Pod Scheduling & Placement (`WaitForFirstConsumer`)**:
   - The PVC awaits a workload Pod referencing it.
   - If the referencing Pod has no node placement (`spec.nodeName` is unset or empty), provisioning is blocked.
   - Once the Pod is scheduled onto a node (e.g. `spec.nodeName: "worker-node-1"`), placement is resolved.
3. **Volume Provisioning & Binding (`Bound`)**:
   - `LocalPathVolumeManager` verifies node placement and resolves the target directory.
   - Creates the host directory with `0777` permissions (per `DEFAULT_SETUP_SCRIPT`).
   - Creates the `PersistentVolume` with:
     - `spec.local.path`: resolved directory on the host.
     - `spec.nodeAffinity`: requires `kubernetes.io/hostname` to match the placed node.
     - `spec.claimRef`: binds to the referencing PVC.
     - `spec.persistentVolumeReclaimPolicy`: configured policy (`Retain` by default).
   - Updates the PVC's `spec.volumeName` and transitions phase to `Bound`.

---

## 2. Workload Data Persistence Across Pod Termination

Because volumes are backed directly by host paths rather than ephemeral container layers:
1. **Writing Workload**:
   - Pod 1 mounts the bound PVC and writes data to its mount point.
2. **Pod Deletion**:
   - When Pod 1 is deleted, terminated, or evicted, only the Pod object is removed from the cluster API.
   - The PVC, PV, and host volume directory remain completely intact.
3. **Replacement Workload**:
   - A replacement Pod (e.g. created by a Deployment, StatefulSet, or restart) references the same PVC.
   - The volume manager idempotently discovers the already-bound PV and mounts the exact same host directory.
   - All written data is immediately accessible to the replacement pod.

---

## 3. Reclaim Policies: Retain vs. Delete

### `Retain` Policy (KubeSolo Default)
- When a PVC is deleted:
  1. The `PersistentVolumeClaim` object is removed from the API server.
  2. The `PersistentVolume` object is **retained** in the API server, with its status phase updated to `Released`.
  3. The underlying directory on the host filesystem and all stored files are **retained untouched**.
  4. Sibling directories, parent paths, and unrelated host data are untouched.

### `Delete` Policy (Ephemeral / Testing)
- When a PVC is deleted under `Delete` policy:
  1. The volume manager executes safe teardown on the volume directory (`safe_teardown_volume_dir`).
  2. Only the specific volume directory allocated to that PVC is removed.
  3. Sibling directories, parent paths, and unrelated host files remain completely untouched.
  4. After successful directory cleanup, the `PersistentVolume` object is deleted from the API server.

---

## 4. Filesystem Security and Unrelated Host Data Protection

To protect the host operating system and unrelated workloads sharing the node:
- **No Path Traversal**:
  `safe_resolve_volume_path` and `safe_teardown_volume_dir` reject any subpaths containing:
  - Parent directory traversal (`..`)
  - Absolute paths (`/etc/...`)
  - Null bytes (`\0`)
  - Empty or root components
- **Boundary Containment**:
  Every volume directory must resolve strictly inside the configured `storage_path` or `shared_path`.
- **Root Protection**:
  Neither provisioning nor teardown can ever target the base storage root directory itself (`candidate == base_dir` is forbidden).

---

## 5. Normal Host Path vs. `sharedFileSystemPath`

- **Normal Path Mode**:
  `config.storage_path` allocates volumes under `<basePath>/local-path-storage/<namespace>_<pvc-name>_<pv-name>`.
- **Shared Filesystem Mode** (`sharedFileSystemPath`, upstream #79 / KS-79):
  When `config.shared_path` is configured (e.g. NFS, shared cluster mount), volumes are allocated under `<sharedPath>/<namespace>_<pvc-name>_<pv-name>`, enabling multi-node shared storage.

API deletion of a PVC is reconciled by marking its owned local-path PV `Released`
only after no active pod references the claim. API lookup failures do not count as
absence. The external provisioner then handles `Delete` through its BusyBox cleanup
helper; `Retain` preserves the data. New native PVs explicitly set
`volumeMode: Filesystem`, and release reconciliation supplies this default for
older native PVs before handing them to the upstream provisioner.
