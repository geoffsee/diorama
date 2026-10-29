# External Runtime Ownership and Lifecycle Boundaries

This document defines the architectural responsibilities, non-ownership invariants, and lifecycle boundaries when diorama operates with an external host-managed Container Runtime Interface (CRI) runtime (containerd or CRI-O), as implemented in `diorama-cri` under Epic E10 ([#10](https://github.com/geoffsee/diorama/issues/10)).

## 1. Architectural Overview

diorama supports two operational runtime modes:
1. **Managed Mode (Bundled containerd)**: diorama spawns, supervises, configures, and cleans up its own embedded containerd instance within its dedicated data directories.
2. **External Mode (Host containerd or CRI-O)**: diorama connects strictly as a gRPC client over Unix domain sockets to an existing runtime managed by the host system (e.g., via `systemd`).

In External Mode, diorama observes strict non-ownership boundaries across the entire process lifecycle (start, stop, restart, crash recovery, and uninstall).

---

## 2. Matrix of Host vs. diorama Responsibilities

| Responsibility Area | Host System Responsibility | diorama Responsibility |
| :--- | :--- | :--- |
| **Runtime Daemon Installation** | Installs and upgrades containerd or CRI-O packages/binaries. | Out of scope. Never installs external runtimes. |
| **Daemon Execution & Lifecycle** | Spawns, monitors, and restarts the runtime process (e.g. systemd). | Never signals, kills, or supervises host runtime processes. |
| **Socket Management** | Creates, binds, and maintains the domain socket (`containerd.sock` / `crio.sock`). | Connects as a read/write client over Unix domain sockets. Never deletes, renames, or unlinks host sockets. |
| **Runtime Configuration** | Manages daemon configuration (`/etc/containerd/config.toml`, `/etc/crio/crio.conf`). | Out of scope. Never overwrites, edits, or alters host daemon configuration. |
| **Registry Configurations** | Configures mirror endpoints, TLS certificates (`certs.d`), and authentication. | Out of scope. External runtime pulls images using host-configured credentials/mirrors. |
| **Cgroups & System Settings** | Configures systemd/cgroupfs drivers, kernel sysctls, and storage drivers. | Queries `RuntimeConfig` to negotiate driver (`systemd` vs `cgroupfs`) and propagates setting to Kubelet. |
| **CNI Installation** | Installs host network plugins and system CNI if host-managed networking is chosen. | Out of scope. External mode manages only diorama-owned CNI configuration (`/opt/diorama/cni/bin` and `/etc/diorama/cni/net.d`); never mutates `/etc/cni/net.d`. |
| **Workload Isolation** | Executes other system or third-party containers and sandboxes on the node. | Scopes container/sandbox management to diorama-owned workloads. Never terminates or alters unrelated workloads. |
| **State Cleanup & Teardown** | Purges host state directories (`/var/lib/containerd`, `/var/lib/crio`) upon node decommissioning. | Never executes bundled-runtime cleanup (`clean_stale_runtime_state`) against host paths on restart or uninstall. |

---

## 3. Lifecycle Invariants

### 3.1 Start / Preflight
- Validates the provided Unix domain socket via `probe_cri_readiness`.
- Confirms runtime engine is supported (`containerd`, `cri-o`, or `oci-cri`).
- Queries `RuntimeService::RuntimeConfig` to negotiate cgroup driver (`systemd` vs `cgroupfs`), falling back seamlessly to host cgroup detection if absent or unimplemented.
- **Never** executes bundled containerd cleanup routines or purges host `/var/lib/containerd` or `/var/lib/crio`.
- **Never** creates or mutates host registry host files.

### 3.2 Running
- Issues typed CRI v1 RPCs for pod sandbox and container lifecycle operations.
- Interacts only with workloads owned by diorama (identified by namespace and management labels).
- Unrelated containers running under the same host runtime remain completely undisturbed.

### 3.3 Stop / Restart / Crash Recovery
- When diorama shuts down or restarts, `ExternalRuntimeService` cooperatively releases gRPC connections and yields `Ok(())`.
- **No process termination**: diorama does not send `SIGTERM`, `SIGKILL`, or any POSIX signals to the host runtime PID.
- **No socket unlinking**: Host sockets remain open and accessible for other consumers.
- **No state purge**: Ephemeral container state owned by host runtime is preserved across restarts.

### 3.4 Uninstall
- During `diorama uninstall` or reset, diorama cleans only its own state directories (`/var/lib/diorama`).
- Host runtime sockets, binaries, data directories, registry certificates, and unrelated workloads are explicitly preserved.

---

## 4. Build Profiles vs. Runtime Modes

The distribution distinguishes build profiles from runtime modes:

| Build Profile | Description | Allowed Runtime Modes |
| :--- | :--- | :--- |
| `BuildProfile::Bundled` | Standard binary including embedded containerd and crun payloads. | `Managed` (standalone default), `External` (user-specified endpoint). |
| `BuildProfile::ExternalDeps` | Minimal binary built without embedded payloads (`--no-default-features` or external-deps mode). | `External` only. (Requesting `Managed` is rejected as an invalid combination). |

---

## 5. Verification & Testing

The ownership invariants are tested under `crates/diorama-cri/tests/runtime_ownership.rs`:
1. **Preservation of host process, sockets, and registry files** across start/stop/restart.
2. **Abortion of bundled cleanup** in external mode during uninstall.
3. **Preservation of unrelated workloads** running on the host runtime.
4. **Validation of the build profile and runtime mode matrix**.
5. **Enforcement of owned CNI path restrictions**.

## Foreign workers

A foreign worker is distinct from an ordinary worker attached to an external CRI.
Its operator owns both kubelet and CRI, joins using an exported standard bootstrap
kubeconfig, and supplies the foreign label and taint. Diorama has no foreign socket
or supervisor entry. Credential export never starts, stops, or probes either
process. Ordinary readiness explicitly rejects `v8-matrix-wasi`. Foreign runtimes
retain their own sandbox validation, including rejection of nonempty DNS.
