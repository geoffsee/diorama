# CoreDNS Reconciliation and Startup Lifecycle

This document describes the idempotent reconciliation, readiness polling, and supervisor lifecycle for CoreDNS within `diorama`.

## Overview

CoreDNS is deployed as an in-cluster workload in the `kube-system` namespace to provide cluster internal and external DNS resolution. The reconciliation pipeline applies owned resources idempotently in correct dependency order, updates configurations without destroying user-added metadata, handles Service ClusterIP immutability, and coordinates startup readiness through the supervisor.

## Dependency Ordering

CoreDNS resources are reconciled in the following strict order:

1. **ConfigMap (`kube-system/coredns`)**:
   - **Cold Start**: Creates the ConfigMap with the generated `Corefile`.
   - **Repeated Start / Updates**: Applies an RFC 7386 JSON Merge Patch (`{"data": {"Corefile": ...}}`). This preserves user-added keys (e.g. custom plugin files or server blocks) and custom metadata (labels, annotations).
2. **ServiceAccount (`kube-system/coredns`)**:
   - Creates the service account if absent.
3. **ClusterRole (`system:coredns`)**:
   - Creates or updates permissions to `list` and `watch` endpoints, services, pods, namespaces, and endpoint slices.
4. **ClusterRoleBinding (`system:coredns`)**:
   - Creates or updates the binding between `system:coredns` and `kube-system/coredns`.
5. **Service (`kube-system/kube-dns`)**:
   - Checks if the service exists.
   - If `ClusterIP` changed: deletes the existing service and recreates it with static IP `10.43.0.10` (since `spec.clusterIP` is immutable in Kubernetes).
   - If `ClusterIP` matches: updates mutable fields (ports, selectors) in-place without deleting or dropping active connections.
6. **Deployment (`kube-system/coredns`)**:
   - Creates or updates the single-replica Deployment.
   - Preserves existing controller-reported `.status` during spec updates.
   - Sets appropriate image reference (e.g. offline mirror or default `docker.io/coredns/coredns:1.14.4`).
   - In container mode: omits memory limits to prevent constrained OOM kills.
   - In host mode: enforces 64Mi memory limit and 20Mi request.

## Readiness Verification and Supervisor Integration

`CoreDnsService` and `CoreDnsAdapter` integrate with `diorama-supervisor`:

- **Readiness Polling**: Polls `Deployment.status.readyReplicas` until at least 1 replica is ready or `readiness_timeout` expires (default: 90 seconds).
- **Component Failure Policy**: If readiness fails or times out, the adapter returns `AdapterError` with diagnostic code `dns-readiness-timeout` (or `dns-api-error`). The adapter never signals ready on failure.
- **Graceful Shutdown**: Upon receiving a supervisor stop signal, the service latches stopped state and cooperatively completes.
