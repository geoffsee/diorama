# CoreDNS Resolution Verification and Probes

`diorama-dns` includes integration probe facilities (`DnsProber`, `DnsResolutionProbe`, `LocalDnsServer`) to verify cluster DNS resolution and readiness behavior across node and service restarts.

## Verification Scope

The probe engine covers:
1. **Same-Namespace Resolution**: Querying `<service>.<namespace>.svc.cluster.local` over UDP and TCP, resolving to the service's `ClusterIP`.
2. **Cross-Namespace Resolution**: Querying `<service>.<service_namespace>.svc.cluster.local` from a client in a different namespace over UDP and TCP (e.g. tier 5 upstream tests).
3. **ExternalName Services**: Querying a Kubernetes Service configured with `type: ExternalName`, returning CNAME records over UDP and TCP.
4. **Egress-Denied Offline Paths**: In air-gapped or egress-denied environments where external network access is blocked, external DNS dependencies are provided locally via `LocalDnsServer` or designated upstream resolvers, and resolution of external domains succeeds.
5. **Restart & Recovery**: Validates that stopping CoreDNS/Node interrupts DNS resolution, and restarting the service completely recovers resolution across both UDP and TCP without permanent connection or socket leaks.
6. **Historical Readiness Regression Prevention**: Avoids the historical regression (e.g. upstream KS-16 / #98) where CoreDNS falsely reported ready when its pods or `status.readyReplicas` were still 0. Probing rejects premature readiness and only succeeds once replicas are genuinely healthy.
7. **IPv6 Reverse Forwarding Boundary**: Validates that when `disable_ipv6` is enabled, reverse queries for `ip6.arpa` are absent (returning `NXDomain`), while `in-addr.arpa` reverse resolution continues normally.

## Architecture and Components

- **`DnsProber`**: Executes individual `DnsResolutionProbe` instances or batches via `execute_suite`, producing a structured `DnsResolutionReport`.
- **`ProbeTransport`**:
  - `Live`: Performs actual UDP/TCP network socket I/O against a DNS listener using RFC 1035 wire format encoding and decoding.
  - `Synthetic`: Evaluates resolution against live `KubernetesApiClient` Service definitions and `CoreDnsConfig` parameters.
- **`LocalDnsServer`**: An in-memory UDP and TCP DNS server fixture binding to loopback addresses, supporting dynamic A, AAAA, CNAME, and PTR record registration for deterministic offline integration testing.
