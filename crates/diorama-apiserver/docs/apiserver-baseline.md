# Kubernetes API Server Baseline & Integration Architecture

## 1. Upstream Kubernetes Baseline

diorama targets the official **Kubernetes v1.35.7** control plane baseline. The API server component integrates via standard Kubernetes options, endpoints, and security contracts:

- **Secure Port & Binding**:
  - `--bind-address=0.0.0.0` (or local `127.0.0.1` for single-node / container loops)
  - `--secure-port=6443`
  - `--advertise-address`: explicit host node IP
- **Networking & Service Ranges**:
  - `--service-cluster-ip-range=10.43.0.0/16` (default Kubernetes service CIDR)
- **Authentication & Authorization**:
  - `--authorization-mode=Node,RBAC`
  - `--anonymous-auth=false` (rejecting unauthenticated requests unless explicitly permitted)
  - `--allow-privileged=true`
- **Request Header Authentication (Aggregation Layer)**:
  - `--requestheader-client-ca-file`: CA bundle for front-proxy / aggregation layer
  - `--requestheader-allowed-names`: `system:auth-proxy`
  - `--requestheader-extra-headers-prefix`: `X-Remote-Extra-`
  - `--requestheader-group-headers`: `X-Remote-Group`
  - `--requestheader-username-headers`: `X-Remote-User`
  - `--proxy-client-cert-file` and `--proxy-client-key-file`
- **Service Account Signing & Token Projection**:
  - `--service-account-issuer=https://kubernetes.default.svc`
  - `--service-account-signing-key-file`: RSA private key (PEM)
  - `--service-account-key-file`: RSA public or private key (PEM)
  - `--api-audiences=https://kubernetes.default.svc`

---

## 2. Storage Architecture: etcd vs SQLite

### User Invariant: etcd Revision Datastore
Per system requirements and architectural decisions:
- diorama uses a dedicated **etcd revision datastore engine** (`diorama-datastore`) rather than an embedded SQLite database.
- Key properties:
  - Multi-version concurrency control (MVCC) with monotonic revision progression (`mod_revision`, `create_revision`).
  - Key-prefix listing and revision-filtered streaming watch notifications (`ADDED`, `MODIFIED`, `DELETED`).
  - WAL (Write-Ahead Log) durability and atomic snapshot checkpoints.
  - Consistent transactional operations (`Txn` / CAS updates).
- In diorama, Kine was previously used to translate etcd gRPC calls to SQLite. In diorama, `diorama-datastore` provides the native etcd datastore engine, ensuring full Kubernetes storage readiness and eliminating SQLite translation overhead.

---

## 3. Upstream Defaults & Fork Differences (Deviation D09)

In accordance with **Deviation D09** and upstream PR `#166` (commit `35d1093`, KS-68):
- **No Edge Memory Overrides**: Earlier K3s/diorama forks injected low-memory overrides (e.g. limiting cache sizes, forcing aggressive garbage collection). diorama strictly adheres to official Kubernetes defaults.
- **Feature Gates**:
  - Upstream diorama disabled `SizeBasedListCostEstimate` (`SizeBasedListCostEstimate=false`) to silence log warnings generated against early kine shims.
  - In diorama, feature gate configuration defaults to upstream Kubernetes v1.35.7 standards, while allowing explicit configuration overrides when required.
- **NodeSetter & Admission**:
  - Upstream diorama implemented a custom admission plugin (`NodeSetter`) to force unassigned workloads to the single node.
  - Workload scheduling and admission extensions remain scoped to their respective epics (E14) rather than hardcoded in the core API server startup.

---

## 4. Prerequisites & Readiness Lifecycle

The API server's lifecycle is guarded by two mandatory prerequisite categories:

1. **PKI Prerequisites**:
   - `ca.crt`, `ca.key`: Root cluster Certificate Authority.
   - `kube-apiserver.crt`, `kube-apiserver.key`: Server TLS certificates with required SANs (Kubernetes service IP, localhost, node IP).
   - `service-account.key`: RSA key pair for token signing and verification.
   - Missing or corrupt credential files immediately fail startup and readiness with `InvalidCredentials`.

2. **Storage Prerequisites**:
   - Active connection to the `diorama-datastore` engine.
   - Storage readiness verifies the datastore is uncorrupted, unlocked, and able to process read/write operations.
   - If storage is unavailable or corrupt, the API server readiness probe `/readyz` fails immediately with `StorageUnusable`.

3. **Lifecycle & Restart**:
   - Clean shutdown terminates background connections gracefully.
   - Restart restores state directly from the persistent datastore without requiring reinitialization or credential rotation.

---

## 5. Admission Control & Extension Integration

For detailed architecture, upstream commit tracking, and verification specifications regarding:
- Mutating and validating admission webhook pipelines
- Front-proxy authentication and mutual TLS
- Dynamic CRD OpenAPI v3 schema validation and lifecycle
- Aggregated API server routing (`APIService`)

See [admission-extension.md](file:///Volumes/safe-vol/workspace/archives/playground/diorama/crates/diorama-apiserver/docs/admission-extension.md).
