# diorama-apiserver

`diorama-apiserver` provides the Kubernetes API server integration, options negotiation, storage readiness gating, PKI prerequisites enforcement, and supervised lifecycle adapter for diorama.

## Overview

- **Official Kubernetes v1.35.7 Baseline**: Implements standard API-server options, endpoint negotiation, and RBAC security models without obsolete edge overrides.
- **etcd Datastore Engine**: Directly backed by `diorama-datastore`'s revision engine, ensuring strong MVCC, resource versioning, and watch event delivery.
- **Supervised Lifecycle**: Integrates with `diorama-supervisor` via `ApiserverAdapter`, ensuring strict ordering with datastore readiness and PKI generation.
- **Prerequisite Validation**: Rejects startup and fails readiness when PKI credentials or etcd storage are invalid or unavailable.
- **Client & Admission Integration**: Supports discovery, authenticated CRUD/list/watch, and security rejection for unauthenticated/unauthorized callers.
- **HTTPS gateway for kubectl**: `ApiserverAdapter` binds a loopback mTLS listener (client certificates from the cluster CA, bearer tokens, or anonymous) and maps Kubernetes paths onto `KubernetesApiClient`. It serves legacy and aggregated discovery, JSON and a partial Kubernetes protobuf create path, `GET .../{name}/status`, `GET .../pods/{name}/log` (with `container`, `tailLines`, `timestamps`, `sinceSeconds`, `previous`), and `?watch=true` on collections as a chunked stream of `ADDED`/`MODIFIED`/`DELETED`/`BOOKMARK` events honouring `resourceVersion`, `timeoutSeconds`, `fieldSelector=metadata.name=`, and `sendInitialEvents=true` (emitting a bookmark with `k8s.io/initial-events-end: "true"`). Pod deletion follows the kubelet contract: a pod a kubelet has acknowledged is marked with `deletionTimestamp`/`deletionGracePeriodSeconds` (from `gracePeriodSeconds` or `spec.terminationGracePeriodSeconds`, default 30) and removed only when the kubelet deletes it with grace 0; unscheduled, unacknowledged and terminal pods are removed at once. Pod logs come from a `PodLogReader` that the in-process kubelet registers with `ApiserverService::set_pod_log_reader`; the reader must not hold the service itself, or shutdown cannot release the datastore lock. `/openapi/v3` and `/openapi/v3/api/v1` serve a minimal document that only tells kubectl the core kinds accept `fieldValidation`, so `kubectl create` works without `--validate=false`; there is no schema and no OpenAPI v2.

## Independent node boundary

HTTPS authenticates both kubelet client certificates and live bootstrap-token
Secrets. Node authorization checks the stored Pod assignment and resource-reference
graph. Nodes write only their own Node/Lease and assigned Pod status; bootstrap
credentials can request certificates but cannot register Nodes or bind Pods.
Pod binding uses `POST /api/v1/namespaces/{namespace}/pods/{name}/binding`, checks
`create pods/binding`, and atomically compares the stored revision. A concurrent
or repeated assignment returns 409. Successful binding publishes a watch update.
The scheduler role includes the default v1.35 informer and binding permissions.
