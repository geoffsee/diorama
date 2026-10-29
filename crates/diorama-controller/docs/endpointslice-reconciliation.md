# EndpointSlice and Endpoints Reconciliation

## Overview

The `diorama-controller` crate implements `EndpointSlice` (`discovery.k8s.io/v1`) and legacy `Endpoints` (`core/v1`) controllers adhering to Kubernetes v1.35.7 reconciliation semantics on single-node clusters.

## Upstream Batching and Latency Elimination (KS-29 / PR #111)

In early diorama iterations, the controller manager enforced an artificial 5-second batch delay:
- `--endpoint-updates-batch-period=5s`
- `--endpointslice-updates-batch-period=5s`
- `--mirroring-endpointslice-updates-batch-period=5s`

This introduced noticeable latency when scaling workloads or updating readiness conditions. Upstream PR #111 (`790b2b0`) and KS-68 PR #166 (`35d1093`) removed these artificial overrides, returning to upstream Kubernetes defaults:
- `endpointslice_updates_batch_period: 0s`
- `endpoint_updates_batch_period: 0s`
- `concurrent_endpoint_syncs: 5`

In `diorama-controller`:
1. `ControllerManagerConfig::validate_batch_periods()` strictly validates that neither period exceeds `0s`. Configurations specifying non-zero batch delays are rejected during prerequisite checks.
2. `EndpointSliceReconciler` and `EndpointsReconciler` execute immediate synchronization passes (< 500ms latency bound), propagating backend additions, removals, readiness changes, and terminations in real time.
3. Controller restart and backend churn recover immediately without accumulating batch backlog or restoring historical delays.

## Reconciliation Model

### EndpointSlice Reconciler (`discovery.k8s.io/v1`)

For each `Service` with a non-empty `spec.selector`:
1. **Pod Discovery**: Scans Pods within the namespace matching all key-value selector labels.
2. **Backend Address Extraction**: Extracts Pod IP from `.status.podIP` or Calico annotation `cni.projectcalico.org/podIP`.
3. **Condition Evaluation**:
   - `ready`: Pod is not terminating (`deletionTimestamp == None`) and has a `Ready: True` condition; if no conditions are present, falls back to `phase == Running`.
   - `serving`: True if ready.
   - `terminating`: True if `deletionTimestamp != None`.
4. **Port Mapping**: Translates `service.spec.ports` (name, port, protocol) into `EndpointPort` entries.
5. **Ownership & Garbage Collection**: Configures `ownerReferences` targeting the parent `Service` (`controller: true`, `blockOwnerDeletion: true`). Deleting the Service cascades garbage collection of owned `EndpointSlice` and `Endpoints` resources.

### Legacy Endpoints Reconciler (`core/v1`)

Maintains core `Endpoints` resources with `subsets`:
- `addresses`: Contains ready backend Pod IP addresses.
- `notReadyAddresses`: Contains unready backend Pod IP addresses.
- `ports`: Maps service ports.

## Verification Matrix

| Acceptance Criterion | Verification Method | Result |
| --- | --- | --- |
| Adding/removing ready backends changes EndpointSlices within declared bound (<500ms) | `test_endpointslice_addition_and_latency_bound` | Verified |
| Readiness condition changes separate ready vs notReady endpoints | `test_endpointslice_readiness_churn_and_cascading_gc` | Verified |
| Cascading garbage collection deletes owned slices on Service removal | `test_endpointslice_readiness_churn_and_cascading_gc` | Verified |
| Controller restart and churn recover immediately without batch delay | `test_controller_restart_and_backend_churn_without_batch_delay` | Verified |
| Batch period > 0s rejected per KS-29 / PR #111 | `test_controller_restart_and_backend_churn_without_batch_delay` | Verified |
| Headless manual Service without selector is preserved without automated overwrite | `test_service_without_selector_is_skipped` | Verified |
