# diorama

diorama is a developing Kubernetes distribution with one control-plane process group
and independently joining workers. It retains its Rust datastore, API server,
controller manager, and native ordinary-node kubelet, and runs upstream
kube-scheduler **v1.35.7** as a supervised executable.

The control plane may also run an ordinary kubelet. Each process has its own state
and node identity. There is no node roster, synthetic companion node, or configured
membership limit. The datastore retains its exclusive installation lock; sharing
its directory between control planes is unsupported. Control-plane HA and WASM
are outside the baseline.

## Build and start

Use the pinned toolchain in [rust-toolchain.toml](rust-toolchain.toml):

```sh
cargo build --locked -p diorama -p dioramactl
cargo run --locked -p diorama -- --print-config
```

Node execution requires Linux. Install the pinned release assets into the chosen
state directory, including `bin/kube-scheduler`. A source-only Cargo build does
not download or install runtime assets. Ordinary nodes require managed containerd,
managed oci-cri with its build feature, or a supported host-managed containerd/CRI-O
endpoint. Host-managed runtimes must already consume `/opt/diorama/cni/bin` and
`/etc/diorama/cni/net.d`; diorama preserves their daemon configuration, sockets,
standard host CNI directories, and unrelated workloads.

Example control-plane configuration:

```yaml
apiVersion: kubesolo.io/v1alpha1
kind: Config
path: /var/lib/diorama
kubernetes:
  role: control-plane
  nodeName: control-plane-1
  disableLocalKubelet: true
network:
  nodeIP: 192.0.2.10 # Replace with an address reachable from every worker.
  podAddressPool: 10.42.0.0/16
```

Run `diorama --config=/etc/diorama/config.yaml`. Set `disableLocalKubelet: false`
and configure an ordinary runtime to execute workloads on the control-plane host.
An omitted node name uses existing hostname discovery; an empty discovered identity
is an error. Configuration precedence remains defaults, file, environment, explicit
flags. Legacy `KUBESOLO_*` inputs and the `kubesolo.io/v1alpha1` schema are retained.
See [configuration](crates/diorama-config/README.md).

## Join workers

On the control plane, using its administrative kubeconfig:

```sh
umask 077
dioramactl token create --role=worker --expiry=24h \
  --kubeconfig /var/lib/diorama/pki/admin.kubeconfig > worker.token
```

Securely transfer the token file to each joining worker. An ordinary worker uses
its own state directory and locally installed runtime:

```yaml
apiVersion: kubesolo.io/v1alpha1
kind: Config
path: /var/lib/diorama
kubernetes:
  role: worker
  nodeName: ordinary-1
  tokenFile: /etc/diorama/worker.token
network:
  nodeIP: 192.0.2.11
runtime:
  endpoint: unix:///run/containerd/containerd.sock
```

Start it with `diorama --config=/etc/diorama/config.yaml`. It generates its own key,
requests a kubelet client certificate over HTTPS, and registers only its own Node
and Lease. It never initializes a datastore or control-plane services. Kubelets
renew certificates through the API; signing keys stay on the control plane.

Foreign workers are entirely operator-owned. Export the standard bootstrap
kubeconfig and supply it to an independently launched kubelet:

```sh
dioramactl token export --token-file worker.token > bootstrap.kubeconfig
kubelet --bootstrap-kubeconfig=bootstrap.kubeconfig --kubeconfig=kubelet.kubeconfig \
  --config=kubelet.yaml --hostname-override=foreign-1 \
  --node-labels=diorama.io/runtime=foreign \
  --register-with-taints=diorama.io/foreign-runtime=true:NoSchedule
```

The operator supplies `kubelet.yaml`, the CRI, and all runtime-specific settings.
Exporting credentials starts no process. Foreign sockets and process identities
are never supplied to diorama. `v8-matrix-wasi` is explicitly rejected as an
ordinary external runtime. Compatible foreign workloads need the foreign taint
toleration and must satisfy their runtime's restrictions, including DNS settings.

List or revoke bootstrap credentials with `dioramactl token list` and
`dioramactl token invalidate TOKEN_ID`, passing `--kubeconfig` when needed. Expired
tokens are rejected immediately and cleaned up by the controller. Revocation
prevents new bootstrap authentication; it does not revoke already issued node
certificates. Treat exported token files as secrets.

## Scheduling and networking

Upstream kube-scheduler binds Pods through the atomic API binding endpoint. Both
the scheduler and controller manager use leader Leases. Kubelets execute only
Pods whose `spec.nodeName` exactly matches their identity. HTTPS node authorization
limits writes to their Node, Lease, and assigned Pods, and workload reads to
referenced resources. Bootstrap identities cannot register Nodes, bind Pods, or
approve/sign certificates.

The single network profile is **Cilium 1.20.4**, eBPF with VXLAN and cluster-pool
IPAM, with one operator replica and scheduled kube-proxy
(`kubeProxyReplacement=false`). Cilium bootstrap Pods use host networking and the
direct API endpoint. Ordinary kubelets register and reconcile host-network Pods
before CNI is ready. Their Ready condition follows CRI runtime/network readiness;
address-pool exhaustion is a networking readiness failure. Foreign nodes receive
neither ordinary CNI installation nor ordinary PodCIDRs.
The control plane's existing `network.mtu` setting overrides Cilium's detected
underlying MTU when nonzero; zero retains automatic detection.

CoreDNS **1.14.4** retains its Deployment, Service, configuration, and
`10.43.0.10:53` address. CoreDNS, Cilium, kube-proxy, local-path storage, and ordinary
addons require `diorama.io/runtime=ordinary` and do not tolerate the foreign taint.
Local-path storage uses `WaitForFirstConsumer`: the scheduler selects an ordinary
node and the provisioner workload launches node-local helpers there. The control
plane does not create volume directories on behalf of remote workers.

## Verification

```sh
cargo fmt-check
cargo lint
cargo test --locked --workspace --all-features
cargo run --locked -p diorama-dev --bin diorama-language-policy
```

The [multi-node fixture](tests/multinode/README.md) uses real independent ordinary
workers and externally supplied foreign kubelet/CRI artifacts. It records failures
and unexecuted checks explicitly. Local unit tests and macOS builds do not establish
Linux network, storage, or foreign-runtime qualification. See the fixture's
[qualification record](tests/multinode/QUALIFICATION.md) for actual results.
