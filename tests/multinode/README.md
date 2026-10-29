# Independent-worker Linux qualification

Build `diorama-multinode` from `diorama-dev` on a disposable Linux host. The fixture
requires root, systemd, cgroup v2, Podman, curl, network access to image registries,
and an eBPF/VXLAN-capable kernel. It builds ordinary worker containers with
containerd, runc, CRI tools, and a CNI loopback binary. The Fedora 44 fixture image
is test infrastructure, not an additional distribution platform claim.

```sh
cargo build --locked -p diorama -p dioramactl -p diorama-dev \
  --bin diorama --bin dioramactl --bin diorama-multinode
sudo target/debug/diorama-multinode \
  --state /var/tmp/diorama-multinode-new \
  --diorama target/debug/diorama --ctl target/debug/dioramactl \
  --scheduler /path/to/kube-scheduler-v1.35.7 \
  --foreign-kubelet /path/to/kubelet-v1.35.7 \
  --foreign-runtime /path/to/v8-matrix-cri \
  --foreign-artifacts /path/to/v8-matrix/target/cri-artifacts
```

Keep the v8-matrix project and artifacts outside this repository. The supplied
runtime must implement that project's four-argument socket/artifact/log/host-file
root interface. The operator fixture applies `MemorySwapMax=0` to each runtime
service. Diorama receives no foreign endpoint or process registration.

`--ordinary-nodes` and `--foreign-nodes` default to two and accept larger values;
the fixture joins one additional foreign worker using the same bootstrap flow.
`--ordinary-image` can reuse a prepared fixture image. `--subnet`, `--gateway`, and
`--pod-pool` select unused test address ranges (gateway and subnet must describe
the same IPv4 /24). Each run requires a new state directory and retains credentials
there with restricted permissions. Do not publish that directory.
The fixture copies the supplied diorama binary into every ordinary container even
when reusing an image. Containerd stores its state on the fixture's mounted node
directory, which avoids nesting overlay snapshots inside the container's overlay.

Checks require actual kubelet-created Nodes, advancing Leases, status updates,
scheduler binding, foreign workload execution on alternate available workers,
system-workload placement, DNS rejection, cross-node Pod and Service traffic,
CoreDNS resolution, and scheduler-selected local storage. The fixture never inserts
Node objects. It makes foreign sockets inaccessible to the control-plane mount
namespace and checks that foreign process IDs survive its shutdown/restart.
Ordinary containers have no mount exposing foreign sockets.

`results.json` reports PASS or the first failed stage; later checks are unexecuted,
not passed. API object snapshots and service logs are retained. The fixture alone
stops its own foreign units during final cleanup, after ownership assertions.
It removes only its containers and network. Built fixture images remain available
for later runs. [QUALIFICATION.md](QUALIFICATION.md) records the latest attempt.
