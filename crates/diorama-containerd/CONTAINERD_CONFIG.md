# Containerd Managed Runtime Configuration

This document specifies how `diorama-containerd` configures the managed containerd daemon, resolves shims, manages registry proxies, and handles custom root installations.

---

## 1. Architectural Principles

1. **Self-Contained Roots**: No dependencies on global host symlinks in `/usr/local/bin` (for `runc` or `containerd-shim-runc-v2`) or `/opt/cni/bin` (for CNI plugins). All runtime artifacts, binaries, and state reside inside the managed base path (e.g. `/var/lib/diorama/containerd` or custom path).
2. **Standard Shim Resolution via `PATH`**:
   - `runtime_type` is configured as the registered containerd type `"io.containerd.runc.v2"`.
   - `runtime_path` is deliberately omitted. Setting `runtime_path` forces containerd to run a spurious `<shim> -info` probe that looks for `runc` (which is not shipped; `crun` is used instead).
   - containerd resolves the extracted `containerd-shim-runc-v2` by having its binary directory prepended to `PATH` in the execution environment.
3. **crun as OCI Runtime**: Configured under `options.BinaryName` pointing to the embedded or extracted `crun` binary.
4. **Registry Hosts Separation**: Registry mirrors, pull-through proxies, and TLS configurations use containerd's `hosts.toml` directory model under `containerd/registry/<host>/hosts.toml`. These files are preserved across restarts and configuration regenerations.

---

## 2. Configuration Format (TOML Version 3)

```toml
version = 3
root = "/var/lib/diorama/containerd/root"
state = "/var/lib/diorama/containerd/state"
imports = ["/etc/containerd/config.d/*.toml"]

[grpc]
address = "/var/lib/diorama/containerd/containerd.sock"

[plugins."io.containerd.cri.v1.images"]
image_pull_progress_timeout = "2m0s"

[plugins."io.containerd.cri.v1.images".pinned_images]
sandbox = "portainer/pause:latest"

[plugins."io.containerd.cri.v1.images".registry]
config_path = "/var/lib/diorama/containerd/registry"

[plugins."io.containerd.cri.v1.runtime".cni]
bin_dirs = ["/var/lib/diorama/containerd/cni/plugins"]
conf_dir = "/etc/cni/net.d"

[plugins."io.containerd.cri.v1.runtime".containerd]
default_runtime_name = "crun"

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.crun]
runtime_type = "io.containerd.runc.v2"
snapshotter = "overlayfs"

[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.crun.options]
BinaryName = "/var/lib/diorama/containerd/crun"
SystemdCgroup = false

[plugins."io.containerd.runtime.v2.task"]
platforms = ["linux/amd64", "linux/arm64", "linux/arm"]
```

---

## 3. Snapshotter Selection Matrix

When selecting the snapshotter for containerd's root filesystem:

| Condition | Selected Snapshotter | Rationale |
| :--- | :--- | :--- |
| Normal root filesystem | `overlayfs` | Kernel overlayfs provides the highest performance CoW layering. |
| OverlayFS root (e.g. Alpine live-boot) with `fuse-overlayfs` in `PATH` | `fuse-overlayfs` | Kernel overlay-on-overlay returns `EINVAL` from `mount(2)`. Userspace FUSE overlay preserves copy-on-write semantics. |
| OverlayFS root without `fuse-overlayfs` in `PATH` | `native` | Safe universal fallback that copies layers instead of stacking them. |

Filesystem type detection checks for the Linux statfs magic `0x794c7630` (`OVERLAYFS_SUPER_MAGIC`).

---

## 4. Cgroup Driver Evaluation

Containerd and crun configure `SystemdCgroup = true` only when:
1. The host unified cgroup v2 hierarchy is present (`/sys/fs/cgroup/cgroup.controllers`).
2. Systemd is the active init system (`/run/systemd/private`).

On non-systemd systems (such as Alpine running OpenRC), `SystemdCgroup` is set to `false` even if cgroup v2 is active, falling back to crun's direct cgroupfs management.

---

## 5. Registry Configuration (`hosts.toml`)

Containerd's `config_path` is configured to `<base_path>/containerd/registry`.

Operators create per-registry directories with `hosts.toml`:

```text
/var/lib/diorama/containerd/registry/
├── docker.io/
│   └── hosts.toml
├── ghcr.io/
│   └── hosts.toml
└── _default/
    └── hosts.toml
```

Example `docker.io/hosts.toml`:

```toml
server = "https://registry-1.docker.io"

[host."https://mirror.corp.internal"]
  capabilities = ["pull", "resolve"]
  override_path = true
  ca = "/etc/ssl/certs/harbor-ca.crt"
```

These configuration files are read dynamically by containerd at pull time. The `diorama-containerd` generator and state cleanup routines guarantee that these files are never overwritten, truncated, or removed during configuration regeneration or daemon restarts.

---

## 6. Compatibility Paths

- **System containerd socket**: `/run/containerd/containerd.sock` is symlinked to the managed socket path for tooling compatibility (`crictl`, host utilities).
- **Immutable roots**: `ensure_symbolic_link` detects if an existing symlink already targets the desired source and avoids recreating it, ensuring smooth operation on read-only root filesystems.

---

## 7. Supervised Runtime Lifecycle & Readiness Probing

The managed containerd service is coordinated by `diorama-supervisor` via `ContainerdService` and `OwnedProcessAdapter`.

### Startup Sequence
1. **Filesystem Preparation**: Ensures `root/`, `state/`, and `registry/` directories exist, evaluates cgroup/snapshotter settings, and renders `config.toml`.
2. **Process Group Execution**: Starts `containerd --config <config.toml>` with an isolated process group and `PATH` prepended with the containerd binary directory.
3. **CRI Readiness Probe**:
   - Probes the containerd gRPC socket over Unix domain transport (`connect_unix`).
   - Issues a CRI `RuntimeService::Version` RPC (`check_cri_version`) to verify that the runtime and CRI endpoints are operational.
   - Retries with a default interval of `500ms` up to a configurable deadline (`DEFAULT_READINESS_TIMEOUT = 1 minute`).
   - If the deadline expires without successful readiness, the probe returns `HealthError::TimedOut` and exits through supervision with fatal error code `containerd_readiness_failed`.
4. **Namespace Verification**: Issues a `NamespacesClient::list` and `CreateNamespaceRequest` to verify the `k8s.io` namespace is registered.
5. **Image Ingestion**: Imports enabled image archives or triggers CRI registry pulls.
6. **Supervisor Notification**: Marks the component `Ready` in the supervisor coordinator.

---

## 8. Image Handling and Registry Fallback

Managed containerd automatically provisions required system images into the `k8s.io` namespace on startup.

### Enabled vs Disabled Image Mapping

| Image Asset | Catalog Reference | Filename | Selection Criterion |
| :--- | :--- | :--- | :--- |
| `ImageCoredns` | `docker.io/coredns/coredns:1.14.4` | `coredns.tar.gz` | Always enabled (core DNS) |
| `ImagePause` | `docker.io/portainer/pause:latest` | `pause.tar.gz` | Always enabled (sandbox pod infrastructure) |
| `ImageLocalPath` | `ghcr.io/geoffsee/diorama-local-path-provisioner:v0.0.36-1` | `local-path-provisioner.tar.gz` | Enabled when `storage.local_path.enabled = true` |
| `ImageLocalPathHelper` | `docker.io/library/busybox:latest` | `busybox.tar.gz` | Enabled when `storage.local_path.enabled = true` |
| `ImagePortainerAgent` | `docker.io/portainer/agent:lts` (or custom reference) | `portainer-agent.tar.gz` (or empty if custom) | Enabled when `!portainer.edge_id.is_empty()` |
| `ImageD2k` | `docker.io/portainer/d2k:1.2.3` | `d2k.tar.gz` | Enabled when `d2k.enabled = true` |

### Import & Pull Semantics
- **Embedded Archives**: If the local archive file exists in `<base_path>/images/<filename>`, the image is loaded from local disk.
- **Registry Pull Fallback**: Online installations may issue a CRI `ImageServiceClient::PullImage` request when an archive is absent. The `images/offline` marker disables this fallback and produces an actionable error for enabled integrations without images.
- **Retained Add-ons**: The loader saves verified images in `images/addons`. Startup imports them with bundled `ctr` into `k8s.io`, independently of legacy integration flags, because runtime cleanup rebuilds the disposable cache.
- **Disabled Image Guarantee**: Disabled images are strictly omitted from `enabled_targets()` and never imported or pulled.
- **Custom Edge Agent**: A custom Portainer agent image is pulled as a warm cache; pull errors do not abort node startup, allowing the kubelet to retry on pod creation.

---

## 9. Fixtures Matrix

The implementation is verified across four distinct operating environments:

1. **Ordinary Host**: Linux with cgroup v2 and active systemd (`SystemdCgroup = true`, `snapshotter = "overlayfs"`).
2. **Alpine / OpenRC**: Musl libc and non-systemd init (`SystemdCgroup = false`, `snapshotter = "overlayfs"`).
3. **Nested Container**: Running inside Docker/Podman where rootfs is an overlay mount (`SystemdCgroup = false`, `snapshotter = "fuse-overlayfs"` when installed).
4. **Overlay Root**: Ephemeral overlay mount without `fuse-overlayfs` (`SystemdCgroup = false`, `snapshotter = "native"` fallback).

---

## 10. Managed Runtime Restart Cleanup Boundaries

To survive unclean host shutdowns, daemon crashes, and service restarts without pod synchronization failures, diorama Kube establishes strict cleanup boundaries between disposable runtime state and durable configuration inputs.

### Disposable vs Preserved Paths

| Category | Path | Action on Restart | Rationale |
| :--- | :--- | :--- | :--- |
| **Disposable** | `<base>/containerd/root` | Purged | Contains bbolt `meta.db`, dead tasks, and container metadata. Purging prevents stale container IDs from conflicting with kubelet pod reconciliation. |
| **Disposable** | `<base>/containerd/state` | Purged | Contains stale Unix domain sockets (`containerd.sock`), FIFO task pipes, and dead process locks. |
| **Disposable** | `/run/containerd/containerd.sock` | Removed if owned | Removed only if it is a symbolic link pointing to `<base>/containerd/state/containerd.sock`. Host-managed sockets are preserved. |
| **Preserved** | `<base>/containerd/registry` | Preserved | User and mirror `hosts.toml` configuration files are preserved intact. |
| **Preserved** | `<base>/images` | Preserved | Source tarball archives (CoreDNS, Pause, etc.) remain intact for re-importing on startup. |
| **Preserved** | `<base>/bin` | Preserved | Binaries (`containerd`, `containerd-shim-runc-v2`, `crun`) are preserved intact. |
| **Preserved** | `<base>/containerd/config.d` | Preserved | Drop-in configuration directory for user containerd configuration overrides. |

### Pod Synchronization Recovery

Containerd tracks sandboxes and containers in `meta.db`. Following a crash, containerd's internal database may reference tasks that the kernel has already terminated. When the kubelet tries to reconcile running pods against its desired state, mismatched container task references cause continuous `pod sync failure` errors.

By wiping `root/` and `state/` prior to starting containerd:
1. Containerd starts with a fresh database and clean socket environment.
2. The readiness probe re-verifies CRI availability and ensures the `k8s.io` namespace.
3. Enabled image archives in `<base>/images/` are re-imported.
4. Kubelet resynchronizes cleanly with the Kubernetes API server / etcd state, spawning new sandboxes and containers without state conflicts.

### External Runtime Protection

diorama Kube verifies symbolic link ownership before removing the system compatibility link (`/run/containerd/containerd.sock`). If the file is a regular file, a live Unix domain socket, or a symbolic link targeting an external runtime, the cleanup boundary leaves it untouched. Arbitrary pulled images stored within disposable `root/` are intentionally evicted and not guaranteed to persist across restarts.

