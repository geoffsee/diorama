# diorama-cri

Client bindings, endpoint validation, provider detection, cgroup negotiation, and external CRI runtime attachment for Kubernetes CRI v1.

## Features

- **CRI v1 Protocol Client**: Client bindings for the official Kubernetes v1.35.7 CRI protocol (`runtime.v1`), generated deterministically and verified with `diorama-upstream check-cri`.
- **Endpoint Parsing & Validation**:
  - Validates Unix domain socket endpoints supporting raw absolute paths (e.g. `/run/containerd/containerd.sock`) and canonical `unix://` URIs (e.g. `unix:///var/run/crio/crio.sock`).
  - Supports separate runtime and image service endpoints, automatically defaulting image service to runtime socket if not explicitly specified.
  - Rejects unsupported URI schemes (`tcp://`, `http://`, etc.), relative paths, and empty paths with actionable errors.
- **Provider Detection & Classification**:
  - Classifies external CRI providers into `CriProvider::Containerd` and `CriProvider::Crio`.
  - Rejects unsupported or legacy runtimes (such as `dockershim`, `docker`, `frakti`) with clear error messaging.
- **Bounded Readiness Probing**:
  - Validates connectivity and responsiveness against both `RuntimeService` (`Version` RPC) and `ImageService` (`ListImages` RPC).
  - Enforces bounded timeouts and configurable retry intervals.
- **Cgroup Driver Negotiation**:
  - Queries `RuntimeService::RuntimeConfig` to discover runtime-reported cgroup driver settings (`systemd` vs `cgroupfs`).
  - Falls back seamlessly to host cgroup detection (inspecting `/sys/fs/cgroup` unified hierarchy and `/run/systemd/system`) if Linux configuration is absent on the wire or the RPC returns unimplemented.
  - Never fabricates protobuf enum zero `systemd`.
  - Propagates resolved driver and endpoint arguments to downstream consumers (Kubelet and CNI).
- **Workload Lifecycle Management**:
  - Typed `CriClient` abstraction for pod sandbox creation, container lifecycle, and image listing/pulling against external containerd and CRI-O runtimes using host-supplied images and network plugins.
- **Strict Non-Ownership Boundaries & Lifecycle Invariants**:
  - Supervised by `diorama-supervisor` via `ExternalRuntimeService` (`COMPONENT_EXTERNAL_CRI`).
  - Acts strictly as an external client: does not launch child processes, extract local payloads, mutate host sockets, or purge host runtime state.
  - Across start, stop, restart, crash recovery, and uninstall, host runtime processes, sockets, registry files, and unrelated workloads remain completely untouched.
  - Validates build profiles (`Bundled` vs `ExternalDeps`) against runtime modes (`Managed` vs `External`), ensuring external-dependency builds require external runtime endpoints.
  - Restricts CNI mutations in external mode to diorama-owned configuration paths only (deferred to E15).

For a complete breakdown of host versus diorama responsibilities, see [External Runtime Ownership Documentation](docs/external-runtime-ownership.md).
