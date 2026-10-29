# Kubernetes Admission Control & API Extension Architecture

## 1. Admission Control Pipeline

The Kubernetes API server executes admission controllers in a strict, two-phase pipeline before persisting any resource:

```
[ Incoming Request (Authenticated & Authorized) ]
                       │
                       ▼
        Phase 1: Mutating Webhooks
   (MutatingAdmissionWebhook / plugins)
                       │  (Applies RFC 6902 JSONPatch mutations)
                       ▼
        Phase 2: Schema Validation
       (OpenAPI v3 Schema on CRDs)
                       │
                       ▼
       Phase 3: Validating Webhooks
  (ValidatingAdmissionWebhook / plugins)
                       │  (Evaluates allowed: true/false)
                       ▼
   [ Persistence Engine (diorama-datastore) ]
```

### Execution Order Invariant
1. **Mutating Webhooks Run First**:
   - Mutating admission plugins (including `MutatingAdmissionWebhook`) receive the resource and can mutate it by emitting standard RFC 6902 JSONPatch operations (`add`, `replace`, `remove`).
   - Mutations are applied sequentially to `req.object`.
2. **Schema Validation Runs Second**:
   - The mutated object is validated against its schema (e.g., OpenAPI v3 schema registered on CustomResourceDefinitions).
   - Resources failing schema requirements (missing required properties, type mismatches, out-of-range numerical values, or invalid enum variants) are rejected immediately with `ApiserverError::InvalidInput`.
3. **Validating Webhooks Run Third**:
   - Validating admission plugins (including `ValidatingAdmissionWebhook`) inspect the final mutated and schema-validated object.
   - If any validating webhook returns `allowed: false`, the operation is denied immediately with `ApiserverError::AdmissionDenied` and the object is **not** written to the datastore.
4. **Failure Policies**:
   - `failurePolicy: Fail` (default): Any webhook invocation failure (connection error, timeout, or TLS trust error) halts the request with `ApiserverError::WebhookFailure`.
   - `failurePolicy: Ignore`: Webhook errors are logged and skipped, allowing the request to proceed.

---

## 2. API Extension & Aggregation Layer

### Front-Proxy Request Header Authentication
As part of the Kubernetes Aggregated API Server pattern (and upstream commit `0654d51`, PR #60):
- Upstream API aggregation forwards client requests through an authenticating front-proxy to extension API servers (e.g. `metrics-server`, custom metrics).
- **Request Header Authentication**:
  - The API server verifies the front-proxy client certificate against `--requestheader-client-ca-file` (`request-header-ca.crt`).
  - The Common Name (CN) or SAN DNS names of the certificate must match `--requestheader-allowed-names` (defaults to `system:auth-proxy`).
  - When verified, identity headers are trusted:
    - `X-Remote-User`: Authenticated username
    - `X-Remote-Group`: Authenticated group list
    - `X-Remote-Extra-`: Supplemental attributes
  - Untrusted client certificates or unauthorized Common Names are rejected with `ApiserverError::Unauthenticated`.

### Aggregated API Server Routing (`APIService`)
- Extension APIs register via `APIService` objects (`apiregistration.k8s.io/v1`).
- Dynamic discovery (`/apis`) discovers and publishes registered aggregated API groups and versions.
- Request dispatch (`dispatch_aggregated_request`) routes requests to backend aggregated services while enforcing:
  - CA bundle verification (`caBundle` field on `APIServiceSpec` verified against backend server certificates).
  - Mutual TLS trust enforcement unless explicitly bypassed via `insecureSkipTLSVerify: true`.
  - Preservation of caller context (`caller_username`, `caller_groups`).

---

## 3. Custom Resource Definitions (CRDs)

diorama supports dynamic CustomResourceDefinitions (`apiextensions.k8s.io/v1`):
1. **Schema Registration**:
   - CRDs define `spec.group`, `spec.names.plural`, and `spec.versions`.
   - Each version may declare an `openAPIV3Schema` defining types, properties, required fields, and constraints.
2. **Dynamic Discovery**:
   - Created CRDs are dynamically surfaced in `discover_apis` (`/apis`) and `discover_group_resources` (`/apis/<group>/<version>`).
3. **Instance Lifecycle**:
   - Custom resource instances undergo mutating admission, OpenAPI v3 schema validation, validating admission, and revision-tracked persistence in `diorama-datastore`.
   - Deleting a CRD cascades and cleans up all existing instances of that custom resource under the storage prefix.

---

## 4. Upstream Commits & Tracking

| Upstream Commit | PR / Issue | Scope | diorama Implementation |
|---|---|---|---|
| `b01ed88` | PR #55 | Enable `ValidatingAdmissionWebhook` | Enabled in admission engine; supports `ValidatingWebhookConfiguration` with TLS `caBundle` validation and fail/ignore policies. |
| `0654d51` | PR #60 | Request Header Authentication & Front-Proxy | Supported via `ClientIdentity::FrontProxy`, `request-header-ca.crt` verification, and allowed names check (`system:auth-proxy`). |
| `35d1093` | PR #166 (KS-68) | Remove edge memory overrides | diorama adheres strictly to official Kubernetes v1.35.7 baseline defaults; no low-memory hacks. |

### Scope Isolation: NodeSetter
- In legacy diorama, a custom admission plugin (`NodeSetter`) was used to force pods onto the single node.
- In diorama, workload scheduling and `NodeSetter` implementation remain scoped strictly to **Epic E14** (Workload Scheduling & Execution).
- No custom scheduling hacks or hardcoded node bindings exist in the core API server admission engine.
