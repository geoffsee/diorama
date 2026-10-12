# diorama-containerd

Managed containerd runtime configuration, shim resolution, image handling, and lifecycle integration for diorama Kube.

## Features

- **TOML Configuration Generator**: Generates containerd v3 configuration matching official KubeSolo contracts (`version = 3`, `io.containerd.runc.v2`, `crun` binary options, CRI images and runtime plugins).
- **Shim Resolution**: Enforces `runtime_type = "io.containerd.runc.v2"` without `runtime_path` overrides, building execution `PATH` to resolve `containerd-shim-runc-v2` cleanly.
- **Snapshotter Detection**: Detects OverlayFS mounts via statfs magic (`0x794c7630`) and dynamically chooses `overlayfs`, `fuse-overlayfs`, or `native`.
- **Registry Proxies & Mirrors**: Supports containerd `hosts.toml` configuration directory model, ensuring user snippets survive configuration regeneration and service restarts.
- **Read-Only / Immutable Link Resilience**: Preserves existing correct symlinks on read-only filesystems.
- **Custom Root Isolation**: Fully self-contained execution without requiring global `/usr/local/bin` or `/opt/cni/bin` symlinks.
- **Supervised Lifecycle & Process Ownership**: Integrates with `diorama-supervisor` via `OwnedProcessAdapter` and `ContainerdService` for graceful signal management and clean termination.
- **CRI Readiness Probing**: Unix domain socket gRPC readiness probing via Kubernetes CRI `RuntimeService::Version` (with optional containerd `VersionClient` probe) with configurable retry intervals and bounded timeouts.
- **Namespace Management**: Ensures the required `k8s.io` namespace exists in containerd on startup.
- **Image Import & Registry Pull**: Automatically imports enabled embedded image archives (CoreDNS, Pause, LocalPath, Portainer Agent, D2K) while strictly omitting disabled components and providing CRI registry pull fallback.
- **Restart Cleanup Boundaries**: Cleans disposable runtime state (`root/` with stale `meta.db`, `state/` with dead sockets/FIFOs, and stale system socket links) on restart to prevent pod synchronization failures while preserving source image archives, binaries, and registry configurations.
- **Multi-Environment Fixtures**: Verified against ordinary Linux hosts, Alpine/OpenRC hosts, nested-container environments, and overlay root filesystems.

## Documentation

- [CONTAINERD_CONFIG.md](CONTAINERD_CONFIG.md) - Detailed specification of configuration format, shim resolution, snapshotter selection, readiness probing, image handling, and restart cleanup boundaries.
