# Routing and Foreign Firewall Preservation Across Restart

Tracks [E16.03](https://github.com/geoffsee/diorama/issues/81).

## Architecture & Lifecycle Preservation

`diorama-proxy` ensures that Kubernetes Service routing (`ClusterIP` and `NodePort`) recovers deterministically across proxy process restarts and repeated backend pod churn, while guaranteeing that unrelated host firewall rules and E15 pod egress masquerade (`diorama-network`) rules remain completely intact.

### Ancestry & Elimination of Blanket NAT-Table Flushes

In early diorama iterations ([`3fd84ca`](https://github.com/geoffsee/diorama/commit/3fd84cae6bf61a4452eecc6ac144691cfa0efe75)), a blanket `nft flush table ip nat` was introduced under the assumption of clearing conflicting rules. However, in subsequent production validation ([`2adcd35`](https://github.com/geoffsee/diorama/commit/2adcd355f706824303babf1c053f307b891efa22)), this blanket flush was removed because:
1. In native nftables mode, `kube-proxy` operates inside its own dedicated table (`ip kube-proxy`) and never programs rules in `table ip nat`.
2. Flushing `table ip nat` wiped host firewall rules and CNI pod egress SNAT masquerade rules (`network.EnsurePodMasquerade(types.DefaultPodCIDR)` / E15), disrupting network connectivity for running pods upon proxy restart.

In accordance with later ancestry superseding earlier behavior and Acceptance Criterion 2 of E16.03:
- **No Blanket NAT Flush**: `diorama-proxy` strictly forbids blanket NAT table flushes (`iptables -t nat -F`, `nft flush table ip nat`, `nft flush ruleset`) during startup, restart, or reconciliation.
- **Dedicated Ownership**:
  - `iptables`: Kube-proxy only manages its owned chains (`KUBE-SERVICES`, `KUBE-NODEPORTS`, `KUBE-POSTROUTING`, `KUBE-MARK-MASQ`, `KUBE-SVC-*`, `KUBE-SEP-*`). The parent `POSTROUTING` chain rule for pod egress masquerade (`diorama: pod masquerade`) and foreign chains (`INPUT`, `FORWARD`, `DOCKER`, etc.) are never flushed.
  - `nftables`: Kube-proxy operates exclusively in its dedicated `ip kube-proxy` table. Foreign tables, including the E15 pod masquerade table `ip diorama-masq` and host `ip nat` / `inet filter` tables, remain completely unmolested.

### Foreign Firewall State Tracking (`FirewallSnapshot`)

`FirewallSnapshot` captures the host firewall state before and after proxy operations:
- Verifies that E15 pod masquerade rules are present and untouched across restarts.
- Confirms that foreign iptables rules and foreign nftables tables are preserved.
- Emits an actionable `ProxyError::ForeignFirewallCorrupted` if any foreign rules are modified or missing.

### Restart Recovery & Backend Churn Reconciliation

When pod replicas churn or are replaced (e.g., rolling deployments, pod rescheduling, IP reassignments):
1. **Routing Table Invalidation**: Any addition, update, or removal of an `EndpointSlice` updates the monotonic generation counter of `ServiceRoutingTable`, immediately clearing `dataplane_ready`.
2. **Dataplane Reconciliation (`DataplaneReconciler`)**:
   - Compares previous endpoint targets against the active desired state.
   - Prunes stale DNAT rules belonging to terminated/replaced endpoints.
   - Synthesizes updated DNAT rules and probability balances for new endpoints.
   - Preserves all foreign rules throughout the reconciliation cycle.
3. **Traffic Probe Verification**:
   - `DataplaneProber` executes TCP and UDP workload probes against `ClusterIP` and `NodePort` targets.
   - Probes confirm that traffic routes exclusively to healthy replacement endpoints and that previous endpoints are no longer reached.
   - Dataplane readiness (`report.dataplane_ready = true`) is restored.
