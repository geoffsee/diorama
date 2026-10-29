# CoreDNS Resource Generation and Corefile Architecture

## Overview

The `diorama-dns` crate generates the full complement of Kubernetes manifests required to run CoreDNS as the authoritative in-cluster DNS service within `kube-system`:
1. **`ServiceAccount`**: `coredns` in `kube-system`
2. **`ClusterRole`**: `system:coredns` with list/watch access to `endpoints`, `services`, `pods`, `namespaces`, and `discovery.k8s.io/endpointslices`
3. **`ClusterRoleBinding`**: `system:coredns` binding the `ServiceAccount` to the `ClusterRole`
4. **`ConfigMap`**: `coredns` in `kube-system` containing the generated `Corefile`
5. **`Service`**: `kube-dns` on static ClusterIP `10.43.0.10`, exposing port 53 over UDP and TCP
6. **`Deployment`**: `coredns` in `kube-system`, single-replica rolling update with liveness and readiness probes

## Corefile Specification

CoreDNS configuration is rendered by `CoreDnsConfig::generate_corefile()`.

### Block Directives

```coredns
.:53 {
	errors
	loop
	cache 30 {
		disable denial cluster.local
	}
	kubernetes cluster.local in-addr.arpa [ip6.arpa] {
		pods insecure
		fallthrough in-addr.arpa [ip6.arpa]
		ttl 30
	}
	forward . <upstream-targets>
	minimal
	reload
	health :8080
	ready :8181
}
```

### IP Family Handling (`--disable-ipv6`)

- **Dual-Stack (`disable_ipv6 = false`)**: CoreDNS serves reverse DNS zones for both IPv4 and IPv6:
  `kubernetes cluster.local in-addr.arpa ip6.arpa` and `fallthrough in-addr.arpa ip6.arpa`.
- **IPv4-Only (`disable_ipv6 = true`)**: CoreDNS omits `ip6.arpa` entirely, preventing spurious upstream queries for non-existent IPv6 reverse subnets:
  `kubernetes cluster.local in-addr.arpa` and `fallthrough in-addr.arpa`.

### Forwarder Resolution

- **Host Mode (`container_mode = false`)**: Forwards upstream queries to the host resolver: `forward . /etc/resolv.conf`.
- **Container Mode (`container_mode = true`)**: Forwards upstream queries to public resolvers `forward . 1.1.1.1 8.8.8.8` to handle container environments where `/etc/resolv.conf` is empty or points to loopback.
- **Explicit Upstream Resolvers**: When custom resolvers are configured, queries are forwarded directly to those targets.

## Resource Limits and Container Mode

- **Host Mode**: Sets `requests: {cpu: "50m", memory: "20Mi"}` and `limits: {memory: "64Mi"}`.
- **Container Mode**: Sets `requests: {cpu: "50m", memory: "20Mi"}` but omits memory limits to prevent cgroup-based premature termination in constrained environments.

## Golden Test Parity

Manifest generation matches upstream diorama output character-for-character across all four execution variants:
- `host-dual`
- `container-dual`
- `host-ipv4`
- `container-ipv4`

Parity is validated against `tools/parity/fixtures/rust-evidence/coredns.json`.
