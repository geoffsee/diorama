# Multi-node qualification record

Qualification date: 2026-10-29. **PASS** on the tested Linux arm64 setup. The fresh
run completed every fixture assertion without manual API, runtime, or process
changes. [Sanitized machine-readable results](linux-arm64-result.json) contain
the completed checks.

## Platform and supplied artifacts

The disposable Lima VM `v8-matrix-cri` ran Fedora 44 Cloud Edition, Linux
`6.19.10-300.fc44.aarch64`, cgroup v2, systemd 259.5, and Podman 5.8.1, with four
vCPUs and 8 GiB RAM. Ordinary worker containers used containerd 2.4.2 and runc
1.5.2. The fixture requires root, working eBPF and VXLAN support, writable BPF and
cgroup mounts, and registry access. It starts each ordinary container with empty
CNI configuration in diorama-owned directories. This qualifies the tested Linux
arm64 setup; it is not a claim about every Linux kernel or distribution.

The external v8-matrix project was discovered at
`/Volumes/safe-vol/workspace/orgs/global-scale-insights-org/_parking-lot/v8-matrix`.
Its HEAD was `3cb21a9072027ca8c240d13c658495f7de3fb14a`. Existing uncommitted files
were left untouched. Supplied artifacts came from its `target/cri-artifacts`
directory and `/var/tmp/cri-target/debug/v8-matrix-cri` in the VM; they were not
copied into this repository or replaced by a CRI double.

| Executable | Version / provenance | SHA-256 |
| --- | --- | --- |
| kube-scheduler | Upstream Linux arm64 v1.35.7 | `571faf2a0d19951aade0b3d4f5f2e0b2504ee3a14ccdd2cdd0668ccd04a3c33c` |
| Foreign kubelet | Upstream Linux arm64 v1.35.7 | `0dc3f53fc51f6a6c26c437ec9eded016106ef931db2dd9b3905c656796bed438` |
| Foreign CRI | Supplied v8-matrix executable | `5222bcd0620e577252cb65f77dbc72bc0c8100f188d0b3ee928055a0158cf3bc` |

Cilium 1.20.4 used the checked-in single-profile manifests. CoreDNS remained
1.14.4 at `10.43.0.10:53`. Local-path provisioner was v0.0.36. No control-plane HA
or general WASM workload support is qualified.

## Linux results

The fixture uses one control plane without a local kubelet, two independently
joining ordinary workers, two operator-launched foreign kubelets/CRIs, and a third
foreign worker joined later without changing the control-plane configuration.
No fixture code inserts Nodes. Foreign units belong to the operator fixture;
diorama receives neither their CRI endpoints nor their process identities.

The run at `/var/tmp/diorama-multinode-run10` failed during local storage. Before
that failure it passed actual registration/status/advancing Leases on all five
workers, alternate foreign workload placement, the additional join, both foreign
DNS negative controls, socket isolation, foreign-process survival across control-
plane restart, new scheduler leadership, cross-node Pod traffic, Service routing,
and CoreDNS resolution. Investigation found an incorrect legacy CSI capacity
advertisement and the missing PVC storage-provisioner annotation. That attempt
included manual diagnostic changes and is not an end-to-end qualification pass.

Run 11 reached the provisioner and exposed a missing standard PVC
`volumeMode: Filesystem` default. After a manual PVC correction and provisioner
restart, it completed every fixture check, including a file written/read on the
scheduler-selected ordinary-2 volume and exclusion of foreign IPAM allocations.
Its reported PASS is diagnostic evidence, not an unattended qualification pass.
Admission now applies the default, with an HTTPS create/patch/list regression
that also preserves explicit block-volume mode.

Earlier attempts exposed API interoperability gaps in TokenRequest decoding,
partial-metadata watches, patch authorization, and null JSON Patch tests, plus
projected-token permissions for non-root containers and unnecessary rewrites of
mounted ConfigMaps. Regression checks cover those corrections. The previous
DNS failure and the storage failure above were actual-runtime failures, not
unavailable checks.

The final run uses the documented fixture command with state directory
`/var/tmp/diorama-multinode-run12`, subnet `172.30.246.0/24`, gateway `172.30.246.1`,
and the prepared ordinary image `localhost/diorama-multi-37955:fixture`. Every
ordinary container receives the current binary even when that image is reused.
Private API snapshots, container logs, unit logs, and `results.json` remain in the
VM state directory. That directory contains credentials and must not be published.
It passed actual kubelet registration and advancing Leases on all five workers,
foreign workload placement on either initial worker, a third foreign join, DNS
negative controls, socket isolation, foreign process survival across restart,
API recovery and scheduler leadership, cross-node Pod traffic, Service access,
CoreDNS resolution, and a scheduler-selected PVC with data on ordinary-2. System
workloads stayed on ordinary nodes; foreign workers received no ordinary PodCIDR
allocation. The fixture also checked that no volume directory was created on the
control-plane host. It stopped its own foreign units only during final operator
cleanup, after the survival assertions, and removed its containers/network.
The VM was returned to its original stopped state; private evidence and cached
images remain on its disk.

## Regression checks and limits

`cargo fmt-check`, `cargo lint`, and the repository language-policy check passed.
The final `cargo test --locked --workspace --all-features --no-fail-fast` run
passed **1,502 tests**, with zero failures and 11 ignored entries across 77 suites.
This includes the storage and datastore fixes. Earlier focused
API/controller/kubelet/dev tests passed 480 tests; storage/datastore/runtime tests
passed 184 tests with two fixture-only tests ignored. These runs overlap and their
counts must not be added together.
After the PVC default correction, all 357 tests in the API, controller, and storage
packages passed, followed by clean formatting and lint checks.
Concurrent regression runs also exposed wildcard/loopback listener collisions
and a process-kill window between WAL header and payload writes. Loopback control
planes now bind loopback explicitly, and WAL frames are submitted together. The
datastore format, exclusive lock, and strict corruption checks remain intact;
the crash/restart and corruption regressions passed after these changes.

Real TLS tests cover node identity and cross-node rejection, referenced workload
resources, bound TokenRequests, bootstrap token revocation/expiry, forbidden
bootstrap actions, atomic competing bindings, and watch authorization. PKI and
controller tests cover CSR validation, signing, renewal, expired-token cleanup,
and controller leader exclusion/takeover. Exact node ownership, mount propagation,
projected credentials, and containerd/CRI-O/oci-cri ownership/provider regressions
remain covered. `v8-matrix-wasi` explicitly fails ordinary-runtime readiness.

The ignored workspace entries comprise disposable host/process/signal fixture
entrypoints, two pinned-crane archive inspections, and upstream conformance
fixtures requiring their separate environments. They are not additional passing
checks. Full upstream conformance, Linux amd64 runtime qualification, real CRI-O
and oci-cri multi-node runs, long-duration certificate rotation, pool exhaustion,
and control-plane HA were not exercised by this Linux fixture. Automated tests
cover certificate renewal; the fixture does not wait through a 24-hour certificate
lifetime.

During cold image pulls, the optional CoreDNS/storage supervisor adapters can
report their startup readiness timeout before their Kubernetes Deployments become
ready. Deployment reconciliation and workload startup continue; this diagnostic
limitation is separate from the network/DNS/storage workload checks.
