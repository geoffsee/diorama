# diorama-storage

Local-path persistent storage provisioner resources and configuration for KubeSolo clusters.

## Overview

`diorama-storage` provides host-backed persistent storage for KubeSolo by generating and managing the `rancher.io/local-path` provisioner components in the dedicated `local-path-storage` namespace.

It generates and manages:
- **Namespace**: `local-path-storage`
- **ServiceAccount**: `local-path-provisioner-service-account`
- **Role**: `local-path-provisioner-role` in `local-path-storage` granting pod management permissions
- **ClusterRole**: `local-path-provisioner-role` granting node, PVC, PV, event, and StorageClass permissions
- **RoleBinding**: `local-path-provisioner-bind` binding the provisioner ServiceAccount to the namespaced Role
- **ClusterRoleBinding**: `local-path-provisioner-bind` binding the provisioner ServiceAccount to the ClusterRole
- **ConfigMap**: `local-path-config` containing `config.json` (`nodePathMap` or `sharedFileSystemPath`), helper pod scripts (`setup` and `teardown`), and `helperPod.yaml` template
- **Deployment**: `local-path-provisioner` running `docker.io/rancher/local-path-provisioner:v0.0.36` with 128Mi memory limit and 50m / 32Mi requests to avoid historical OOM errors
- **StorageClass**: `local-path` with provisioner `rancher.io/local-path`, `volumeBindingMode: WaitForFirstConsumer`, `reclaimPolicy: Retain`, and default StorageClass annotation (`storageclass.kubernetes.io/is-default-class: "true"`)

## Configuration and Defaults

Storage configuration honors upstream KubeSolo contract decisions (including D04):
- **Enabled by Default**: In accordance with D04, storage is enabled by default (`storage.local_path.enabled = true`). Explicitly disabling it prevents resource generation and deployment.
- **Normal vs. Shared Filesystem Modes**:
  - In normal host mode, `config.json` specifies `nodePathMap` pointing to `<basePath>/local-path-storage` (e.g. `/var/lib/diorama/local-path-storage`).
  - When `sharedPath` is configured, `config.json` specifies `sharedFileSystemPath` and omits `nodePathMap`, enabling shared storage across nodes or containers.
- **Resource Limits & Parity**:
  - Memory limit is set to `128Mi` with requests of `32Mi` memory and `50m` CPU. This eliminates historical edge memory override OOM bugs.
  - Online image reference defaults to `docker.io/rancher/local-path-provisioner:v0.0.36`.
    Managed containerd selects the smaller `ghcr.io/geoffsee/diorama-local-path-provisioner:v0.0.36-1`
    when its nonempty bundled archive is present. That reference is an offline artifact identity,
    not a public registry fallback. External runtimes and managed oci-cri use the public image.

## Architecture & Documentation

- [docs/localpath-generation.md](docs/localpath-generation.md): Manifest generation, RBAC rules, helper pods, and Go parity.
- [docs/localpath-reconciliation.md](docs/localpath-reconciliation.md): Lifecycle service, idempotent reconciliation, optional provisioner deployment, and supervisor degradation policies.
- [docs/localpath-volume-lifecycle.md](docs/localpath-volume-lifecycle.md): First-consumer binding (`WaitForFirstConsumer`), replacement pods, Retain/Delete reclaim, and host data protection.
