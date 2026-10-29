# diorama-oci

An in-process `oci-cri` adapter for diorama's supervisor. The existing
`diorama-cri` client remains the protocol boundary for kubelet workloads.

The runtime is pinned to upstream commit
`5f4872c4b12ac962d624e1f756784116a900beae`, which contains
[the native fixes](https://github.com/geoffsee/oci-lib/pull/21) and
[the embedding API](https://github.com/geoffsee/oci-lib/pull/22).
It also includes [managed pod fixes](https://github.com/geoffsee/oci-lib/pull/23),
[native conformance and security fixes](https://github.com/geoffsee/oci-lib/pull/24),
and [short image-name resolution](https://github.com/geoffsee/oci-lib/pull/26).
A sibling checkout is no longer required.

## External runtime

On Linux, start `oci-cri` independently and configure diorama's existing
`runtime.endpoint` to `unix:///run/oci-cri/oci-cri.sock`. Keep the runtime's
advertised name as `oci-cri`; arbitrary branded names remain unsupported.
Supply its pause image, CNI binaries, and CNI configuration. Diorama attaches
as a client and does not own that process.

## Managed adapter

Build diorama with `--features oci-cri` to expose
`RuntimeBuilder::register_oci_cri`. The executable calls early
`diorama_oci::startup()` before argument parsing or executor creation.
Library hosts must call it themselves.

Construct `OciCriService` with `oci_cri::Config` paths dedicated to diorama
and a startup timeout. Register the kubelet with `oci-cri` as its prerequisite.
The adapter probes both CRI services before reporting ready and cooperatively
shuts down the server when stopped. Kubelet must finish workload cleanup first.
The native engine requires Linux; the fake engine is only for tests.

On Linux, select the managed runtime explicitly:

```sh
diorama --container-runtime=oci-cri --path=/var/lib/diorama
```

The equivalent file setting is `runtime.backend: oci-cri`; the environment
variable is `DIORAMA_CONTAINER_RUNTIME=oci-cri`. Empty or `auto` preserves
existing selection, and `containerd` explicitly selects managed containerd.
A managed selection cannot be combined with `runtime.endpoint`.

Install `bridge`, `host-local`, `portmap`, and `loopback` in `<path>/cni/bin`.
Diorama writes its CNI configuration under `<path>/oci-cri/cni/net.d` and stores
runtime data under `<path>/oci-cri`. Its CRI socket is `<path>/oci-cri/cri.sock`.
The pause image uses upstream's default `registry.k8s.io/pause:3.10.1` and must
be pullable. Offline image imports and broader conformance remain prerequisites
for changing the default backend.

Linux builds require Go >= 1.26 and a C compiler. Install `pkg-config` and
`libseccomp-dev` to build seccomp support; CI installs these along with Go
1.26.10 for the all-features lint and test jobs. Use LLVM when linking the
native Go archive (for example a release build); diorama's development profile
uses Cranelift and documents native archive linking limitations.

## Verification

`cargo test -p diorama-oci` exercises diorama's generated CRI client against
oci-cri's real gRPC service with its fake execution engine. It covers provider
identity, cgroup negotiation, images, sandbox/container lifecycle, exec,
supervisor shutdown, listener cleanup, and streaming bind failure. These tests
do not establish native container isolation or CNI correctness.

## Native smoke result (2026-10-28)

A complete managed diorama node was built on Linux arm64 with Rust 1.97.1,
Go 1.26.10, and libseccomp, in a disposable privileged Podman container with a
private cgroup namespace. The node became Ready and advertised `oci-cri`.
The final native binary used a temporary path patch to the same upstream
sources pinned above.

An explicitly Unconfined BusyBox pod passed projected service-account mounts,
CNI address allocation, HTTP across the bridge, exec, CRI logs, CPU/memory stats,
and API-driven removal. Direct kernel inspection confirmed a domain cgroup,
`memory.max=67108864` and `cpu.max=10000 100000`. CNI teardown retained the
node interface. SIGTERM exited the node with code 0 and removed its CRI socket.

The repeatable pod smoke test requires a running node and access to its state,
pod log files, and network, plus curl, jq, iproute2, and crictl:

```sh
DIORAMA_STATE=/var/lib/diorama sh crates/diorama-oci/scripts/native-smoke.sh
```

Diorama forwards pod and container seccomp selections through its active
reconciler. RuntimeDefault uses the upstream containers-common profile;
Localhost paths resolve under the kubelet seccomp directory. The native smoke
starts a RuntimeDefault pod and verifies its exec process inherits a filter.
Upstream's separate native probe checks an actually denied syscall in init and
exec, plus unconfined/privileged controls and invalid-profile rejection.
Builds without libseccomp reject confined requests. Omitted profiles retain
Unconfined behavior; diorama does not yet implement `seccompDefault`.

### Seccomp review (2026-10-28)

CoreDNS and local-path storage do not request seccomp profiles. Their startup
failures came from runtime and image handling. Explicit syscall filtering still
matters for workloads that request RuntimeDefault or Localhost. Privileged
containers follow Kubernetes semantics and ignore those filters. See the
[Kubernetes seccomp tutorial](https://kubernetes.io/docs/tutorials/security/seccomp/).

The follow-up fixes preserve image entrypoints for args-only requests, supply
capability defaults, reset failed starts, and mount each sandbox's DNS settings
into its containers. A fresh full-node run brought both nodes to Ready and
CoreDNS to Running. A BusyBox pod resolved `kubernetes.default.svc.cluster.local`
through its configured resolver without a server override, and resolved an
external name through CoreDNS forwarding. The extended native smoke passed
networking, exec, logs, resources, stats, DNS, removal, and RuntimeDefault
profile enforcement. Shutdown exited 0 and removed the socket.

Storage validation now passes on a fresh native node. Online installs use the
public `docker.io/rancher/local-path-provisioner:v0.0.36`; the smaller GHCR-tagged
image remains available through managed containerd's offline archive. Helper
pods use `docker.io/library/busybox:latest` so no host short-name aliases are
needed. Testing also found an upstream threaded-init state race: a transient
zombie thread was mistaken for process exit. The upstream fix tracks the actual
child wait result, with a native regression that fails on the old implementation.

The repeatable storage test verifies provisioner readiness, PVC binding, a write,
data surviving pod replacement, and Delete reclaim removing the PV and directory.
It uses its own StorageClass and leaves the default Retain policy intact:

```sh
DIORAMA_STATE=/var/lib/diorama sh crates/diorama-oci/scripts/storage-smoke.sh
```

The upstream conformance fixes cover long sandbox names, image identity,
namespace selection, mount propagation, exec deadlines, user/group resolution,
OOM status, and SPDY exec/attach/port-forward. The full suite now runs in a
reproducible CNI fixture and its failures fail CI. The Linux arm64 run passed
93 tests with zero failures; 20 were skipped (nine AppArmor tests disabled by
the host, six unsupported user-namespace tests, and five benchmarks). The
[Linux amd64 CI run](https://github.com/geoffsee/oci-lib/actions/runs/40798029695)
passed 102 tests with zero failures and 11 skips (six user-namespace cases and
five benchmarks). That host also passed native seccomp and AppArmor denial
probes for init and exec, with Unconfined/privileged controls. CoreDNS startup
and threaded-init exit reporting regressions passed on both architectures.
Namespace handles remain valid through the thread-leader transition during
exec. Attach delivers partial output without waiting for a
newline and closes stdin when a `stdinOnce` client disconnects.

Mapped user namespaces remain explicitly unsupported. Terminal streams still
use pipes; PTY allocation and resizing remain incomplete. Daemon-restart
recovery and offline imports are not qualified. Managed oci-cri stays opt-in.

## Diorama live-node probe result (2026-10-28)

The `make conformance` target runs 22 probes from `diorama-conformance` against
a real node. It is ignored by ordinary test runs. The fresh Linux arm64 run with
managed oci-cri at `5f4872c4b12ac962d624e1f756784116a900beae` passed
**22 probes with zero failures** in 51 seconds. Deployment startup, DaemonSet
startup, logs, exec, and PVC binding all passed.

The previous four failures came from unresolved short image names. The CRI
service now normalizes names such as `busybox:1.36` to
`docker.io/library/busybox:1.36` consistently for pulls and local lookups.
The successful run had no `/etc/containers/registries.conf`, and used the
original probes without changing their images. Unit and CRI API tests cover
name, tag, digest, and ID handling; the upstream native CI fixture also checks
short-name pull, container creation, exec/logs, and removal.

To run these probes against an image configured with `runtime.backend: oci-cri`:

```sh
DIORAMA_IMAGE=your-oci-cri-node-image cargo test --locked -p diorama-conformance \
  --test suite client_gaps::client_gaps -- --ignored --nocapture
```

These are Diorama's 22 live-node probes, not the complete Kubernetes
certification suite.
