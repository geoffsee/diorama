# Kube-Proxy Configuration and Backend Selection Baseline

Tracks [E16.01](https://github.com/geoffsee/diorama/issues/79).

## Architecture & Responsibilities

`diorama-proxy` provides the Rust orchestration layer for kube-proxy configuration generation, backend technology selection (`iptables` vs `nftables`), connection-tracking (conntrack) tuning adaptation across host and container modes, and supervised component lifecycle management.

### Component Boundaries

- **Configuration Generation**: Generates `kubeproxy.config.k8s.io/v1alpha1` `KubeProxyConfiguration` documents matching official Kubernetes v1.35.7 schema and KubeSolo golden fixtures.
- **Backend Detection & Selection**:
  - Automatically identifies whether the host kernel and userland support `iptables` or native `nftables`.
  - On standard hosts where `/proc/net/ip_tables_names` exists and `iptables` runs, selects `iptables` and configures `--masquerade-all=true`.
  - On nftables-only hosts (where `/proc/net/ip_tables_names` is absent but `nft` is available), selects `nftables` mode (stable in Kubernetes since v1.31), flushes conflicting native nat tables, and omits iptables masquerade-all.
  - Provides actionable diagnostic errors when neither backend is supported or when kernel module state disagrees with userland tooling.
- **Container vs Host Mode Conntrack Adaptation**:
  - **Host Mode**: Preserves upstream Kubernetes defaults (`maxPerCore = 32768`, `min = 131072`, `tcpEstablishedTimeout = 24h0m0s`, `tcpCloseWaitTimeout = 1h0m0s`, `udpTimeout = 0s`, `udpStreamTimeout = 0s`), tuning kernel connection tracking appropriately.
  - **Container Mode**: Explicitly sets all six conntrack settings to zero (`0` or `0s`), preventing kube-proxy from attempting to write to `/proc/sys/net/netfilter/nf_conntrack_*` which is mounted read-only in containerized runtimes (runc/Docker/Podman).
- **Supervised Lifecycle & Post-Setup Verification**:
  - Encapsulates component execution within `diorama-supervisor::Adapter`.
  - Verifies readiness only after confirming both proxy process health and SNAT pod egress masquerade rules.

## Conntrack Settings Matrix

| Conntrack Setting | Upstream Host Default | Container Mode Setting | CLI Flag |
| --- | --- | --- | --- |
| `maxPerCore` | `32768` | `0` | `--conntrack-max-per-core=0` |
| `min` | `131072` | `0` | `--conntrack-min=0` |
| `tcpEstablishedTimeout` | `24h0m0s` | `0s` | `--conntrack-tcp-timeout-established=0s` |
| `tcpCloseWaitTimeout` | `1h0m0s` | `0s` | `--conntrack-tcp-timeout-close-wait=0s` |
| `udpTimeout` | `0s` | `0s` | `--conntrack-udp-timeout=0s` |
| `udpStreamTimeout` | `0s` | `0s` | `--conntrack-udp-timeout-stream=0s` |

## Diagnostic Error Codes

Startup and prerequisite checks isolate failure causes to the responsible subsystem:

| Diagnostic Code | Failure Cause | Actionable Operator Guidance |
| --- | --- | --- |
| `proxy-unsupported-capability` | Neither `iptables` nor `nftables` is present on the host system | Install `iptables` or `nftables` kernel modules and CLI packages |
| `proxy-readonly-sysctl` | `/proc/sys/net/netfilter` is read-only in host mode | Enable `--container-mode` so kube-proxy sets conntrack settings to zero and skips sysctl writes |
| `proxy-missing-credential` | Configured `kubeconfig` file is not present | Ensure control plane PKI and kubeconfig generation completed |
| `proxy-invalid-config` | Unrecognized or malformed proxy configuration parameter | Correct configuration syntax and mode specification |
| `proxy-backend-detection-failed` | Subprocess failure during backend detection probe | Check execution permissions and system environment |
| `proxy-health-check-failed` | Kube-proxy failed health check or process exited | Inspect kube-proxy log output and network binding |
| `proxy-masquerade-failed` | Pod egress masquerade rule injection failed | Verify iptables/nftables root privileges and filter tables |
