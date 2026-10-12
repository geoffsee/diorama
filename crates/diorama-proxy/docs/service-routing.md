# Kubernetes Service Routing and EndpointSlice Verification Baseline

Tracks [E16.02](https://github.com/geoffsee/diorama/issues/80).

## Architecture & Routing Dataplane

`diorama-proxy` provides comprehensive Service routing and dynamic EndpointSlice reconciliation across both supported backends: `iptables` and native `nftables`.

### Service Routing Models

1. **ClusterIP Routing**:
   - Matches packets targeting the Service virtual IP (`cluster_ip`) on designated service ports and protocols (TCP/UDP).
   - Translates destination addresses (DNAT) to healthy, ready backend endpoints (`target_port`).
   - Distributes requests across all ready endpoints using random or round-robin balancing.

2. **NodePort Routing**:
   - Matches packets arriving on the host node port (`node_port`) across all interfaces.
   - Forwards traffic through the same Service and Endpoint backend chains as ClusterIP.
   - Applies masquerade (SNAT) to ensure return traffic routes correctly.

3. **Protocol Isolation**:
   - TCP traffic destined for a TCP service routes to TCP backends.
   - UDP traffic destined for a UDP service (e.g. CoreDNS) routes to UDP backends.
   - Mismatched protocol requests (e.g. TCP connection to UDP DNS port) fail gracefully without corrupting routing tables.

### Dual-Backend Implementation Details

| Component | `iptables` Implementation | `nftables` Implementation |
| --- | --- | --- |
| **ClusterIP Chain** | `KUBE-SERVICES` (`-d <cluster_ip>/32 -p <proto> --dport <port> -j KUBE-SVC-<hash>`) | Table `ip kube-proxy`, Chain `services` (`ip daddr <cluster_ip> <proto> dport <port> dnat to ...`) |
| **NodePort Chain** | `KUBE-NODEPORTS` (`-p <proto> --dport <node_port> -j KUBE-SVC-<hash>`) | Table `ip kube-proxy`, Chain `nodeports` (`<proto> dport <node_port> dnat to ...`) |
| **Load Balancing** | `KUBE-SVC-<hash>` rules using `-m statistic --mode random --probability <p>` to `KUBE-SEP-<hash>` | `numgen random mod <n> map { ... }` or discrete verdict maps |
| **Endpoint DNAT** | `KUBE-SEP-<hash>` (`-p <proto> -j DNAT --to-destination <ip>:<target_port>`) | Inline `dnat to <ip>:<target_port>` in verdict statements |

### EndpointSlice Lifecycle & Dynamic Updates

The `ServiceRoutingTable` dynamically reflects changes in `EndpointSlice` resources:

- **Endpoint Addition (Scale-Out)**: When new pod replicas are scheduled and become ready, new endpoints are registered in the routing table and immediately begin receiving a proportional share of traffic.
- **Endpoint Removal (Scale-Down / Termination)**: When pods terminate, endpoints are removed from the slice and immediately excluded from subsequent routing decisions.
- **Unready Endpoints (`ready: false`)**: Pods failing readiness probes or undergoing graceful termination (`terminating: true`) are filtered out, preventing blackholing of traffic.
- **Total Endpoint Outage**: If all endpoints of a service become unready, routing fails fast with an actionable `ProxyError::NoReadyEndpoints` error rather than timing out.

## Diagnostic Distinction: Component Startup vs Dataplane Probes

To provide actionable observability for cluster operators, `diorama-proxy` strictly distinguishes between:

1. **Component Startup Readiness**:
   - Indicates that the `kube-proxy` supervisor process is alive, listening on its healthz socket, and pod egress masquerade (SNAT) rules are established.
   - Logged under target `kubeproxy::startup`.
   - Reported via `report.startup_ready = true`.

2. **Dataplane Probe Verification**:
   - Executes live synthetic TCP and UDP workload probes against registered ClusterIP and NodePort destinations.
   - Confirms that network packets actually traverse kernel chains and successfully reach backend endpoints.
   - Logged under target `kubeproxy::dataplane`.
   - Reported via `report.dataplane_ready = true` and `report.details["dataplane_status"]`.

If backend pods fail or network interfaces are blocked while the kube-proxy daemon is still running, `check_readiness()` clearly reports `startup_ready: true, dataplane_ready: false` with exact error diagnostics (`proxy-dataplane-probe-failed`), allowing operators to pinpoint dataplane blackholes without misidentifying them as process crashes.
