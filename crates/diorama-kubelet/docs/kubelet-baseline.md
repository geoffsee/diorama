# Kubelet Configuration, Identity, and Node Registration Baseline

Tracks [E13.01](https://github.com/geoffsee/diorama/issues/69).

## Architecture & Responsibilities

`dioramalet` provides the Rust orchestration layer for Kubelet configuration generation, identity and RBAC integration, CRI runtime attachment, Node registration, and single-node workload execution.

### Component Boundaries

- **Configuration Generation**: Generates `kubelet.config.k8s.io/v1beta1` `KubeletConfiguration` YAML documents matching the official Kubernetes v1.35.7 schema and diorama golden fixture specifications.
- **Identity & RBAC**: Operates as `system:node:<node-name>` within the `system:nodes` group. Authorizes Node creation, status patching, and Lease renewals in `kube-node-lease` without granting administrative cluster privileges.
- **Runtime Provider Attachment**: Connects to CRI endpoints for both managed containerd (`unix:///run/containerd/containerd.sock`) and external runtime providers (containerd, CRI-O) negotiated via `diorama-cri`.
- **Node Registration & Heartbeat**: Registers the single-node `Node` resource with status `Ready=True`, absence of disk/memory/PID pressure, capacity and allocatable definitions, and updates 40-second renewal leases in `kube-node-lease`.
- **Manually Assigned Workload Execution**: Detects and synchronizes pods assigned to this node (`spec.nodeName == self.node_name`), drives container creation through the runtime provider, and records running container statuses and conditions.
- **Health & Diagnostic Reporting**: Exposes `/healthz` status, tracks node readiness, and reports actionable diagnostic error codes upon prerequisite and startup failures.

## Configuration Parity & Defaults

Kubelet configuration adheres to the upstream Kubernetes v1.35.7 defaults contract (D09) without reviving removed edge memory overrides (commit `35d1093` / KS-68).

| Setting | Default Value | Upstream & Security Rationale |
| --- | --- | --- |
| `apiVersion` | `kubelet.config.k8s.io/v1beta1` | Official v1beta1 configuration API |
| `authentication.anonymous.enabled` | `false` | Disables unauthenticated access |
| `authentication.webhook.enabled` | `true` | Validates client bearer tokens against apiserver |
| `authentication.x509.clientCAFile` | `/etc/kubernetes/pki/ca.crt` (or `<pki_dir>/ca.crt`) | Verifies client certificates against cluster CA |
| `authorization.mode` | `Webhook` | Delegated authorization against API server |
| `readOnlyPort` | `0` | Eliminates unauthenticated read-only probe surface (port 10255) |
| `cgroupDriver` | `cgroupfs` or `systemd` | Negotiated with CRI runtime or detected from host |
| `resolvConf` | `/etc/resolv.conf` (host) / `/dev/null` (container) | Preserves DNS resolution model |
| `rotateCertificates` | `true` | Automated certificate renewal |
| `failSwapOn` | `false` | Permissive swap handling on host nodes |

### CLI Argument Rules

- `--config`: Points to generated `kubelet.yaml`.
- `--hostname-override`: Normalized node hostname.
- `--root-dir`: Kubelet data root (e.g. `/var/lib/kubelet`).
- `--kubeconfig`: Path to authenticated `kubelet.kubeconfig`.
- `--node-ip`:
  - Included if `node_ip` is a valid non-loopback IP (e.g., `192.0.2.8` or `2001:db8::8`).
  - Omitted if `node_ip` is loopback (`127.0.0.1`), empty, or invalid.
  - Omitted for IPv6 addresses when `--disable-ipv6` is configured.

## Diagnostic Error Codes

Startup and prerequisite checks isolate failure causes to the responsible subsystem:

| Diagnostic Code | Responsible Subsystem | Failure Cause |
| --- | --- | --- |
| `kubelet-credential-missing` | PKI / Credentials | Missing `kubelet.kubeconfig`, `ca.crt`, `kubelet.crt`, or `kubelet.key` |
| `kubelet-auth-failed` | Authentication / RBAC | Kubeconfig missing `system:node:<name>` or `kubelet` identity |
| `kubelet-apiserver-unavailable` | Control Plane | API server is unreachable or rejects node queries |
| `kubelet-runtime-unavailable` | CRI Runtime | CRI runtime socket does not exist or fails gRPC connection |
| `kubelet-config-invalid` | Configuration | Invalid file paths, blocked parent directories, or malformed parameters |
| `kubelet-node-registration-failed` | Control Plane | Failed to post Node status or Lease heartbeat |
| `kubelet-pod-reconciliation-failed` | Workload Execution | Runtime container creation error or status update failure |
