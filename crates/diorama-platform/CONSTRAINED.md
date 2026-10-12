# Constrained-host observations and responsibility policy

`constrained::collect_constrained(ProbeLimits)` reads four fixed sysctl files,
`/proc/net/ip_tables_names` existence, four default CNI plugin locations and the
names in `/etc/cni/net.d`. It runs only on Linux. Sysctl reads use the existing
nonblocking, regular-file, bounded reader, capped further at 4096 bytes. Directory
entries use the caller's validated count budget and a 255-byte name budget; invalid
UTF-8 names make the observation unknown rather than disappearing. Filesystem
absence, permission failures, malformed input and exhausted budgets stay distinct.
No command, write/access test, socket connection, CRI request or CNI file read runs.
These bounds constrain memory/counts, not arbitrary kernel/filesystem latency.

`evaluate_constrained` is a pure interpretation of those facts plus explicit
runtime ownership, an independently supplied `iptables --version` observation and
the existing preflight `xt_comment` check status. It returns no overall readiness
boolean and no executable preparation action. Facts remain subject to races.

The independent policies are:

- IPv4 forwarding must exist with value 1. Each IPv6 disable control should be 1
  when present; an absent IPv6 control needs no write. A value of 0 requires later
  preparation. Correct values need no write, even on a read-only mount. Read errors
  stay unknown and malformed values do not pass. There is deliberately no inferred
  writability or promise that preparation will succeed.
- Proxy/egress selection follows existence of `/proc/net/ip_tables_names`: present
  chooses iptables, observed absence chooses nftables. Unknown does not select.
  This heuristic is not proof of rule-programming capability.
- Module-family selection independently follows the supplied version output:
  `(nf_tables)` chooses that family; other successful output follows the baseline's
  legacy hint. A failed/missing probe remains unknown/absent. No module is loaded,
  and indexes or hints do not prove loadability. In particular, nft selection does
  not waive the carried `xt_comment` result or establish CNI xtables compatibility.
- External mode leaves runtime processes/configuration, OCI runtimes, CNI plugin
  binaries and sandbox images host-owned. No stop, install, registry rewrite or
  image import exists in this API. Managed mode only reports responsibility; it
  likewise grants no authority to perform an action.
- The exact baseline-owned CNI filename is `10-bridge.conflist`. Default-location
  plugins are `bridge`, `host-local`, `portmap` and `loopback` under `/opt/cni/bin`.
  Missing plugins are advisory because the host runtime may use another directory.
  Earlier `.conf`, `.conflist` and `.json` entries warn about competing selection;
  later entries are informational. The report contains counts, not arbitrary names.
  Missing/unreadable directory observations cannot be presented as an empty directory.
  Other CNI files remain externally owned. Actual owned-file writing and previous
  symlink migration belong to E15, not this module.

The pinned KubeSolo baseline is `2ef1c4787989f11f868f81bb84ae2afd4a49a81d`:
`internal/runtime/network/ipv6.go`, `internal/system/modules.go`,
`pkg/kubernetes/kubeproxy/flags.go`, `internal/core/embedded/host.go` and
`types/const.go`. Its IPv6 helper skips permission errors and accepts any leading
`1`; its proxy selector treats every stat failure as absence, and failed iptables
version execution assumes nft. Rust deliberately preserves uncertainty and uses
exact trimmed sysctl values instead. The baseline's unconditional IPv4 write in
`embedded/load.go` is not reproduced: already-correct required sysctls must work on
read-only mounts under the accepted E01 constrained-host contract.

`tools/parity/fixtures/constrained-policy` captures real Go helper observations in
owned disposable containers. Subset extraction preserves selected declaration ASTs
and records original source hashes; it does not compile or qualify an entire node.
Rust tests independently cover corrected semantics, ownership, backend disagreement,
no xtables waiver, name bounds and non-mutating directory observation. Commands:

```sh
cargo test -p diorama-platform --locked
cargo run --locked -p diorama-dev --bin diorama-fixture -- verify-evidence constrained-policy tools/parity/fixtures/constrained-policy/rust-evidence
```

Remaining consumers include bounded command probes, actual CRI/socket validation,
capability checks, explicit preparation and reobservation, routing and CNI writes.
No check command, full #47 acceptance, real nft rule setup or parent E05 qualification
is claimed. Existing Alpine/OpenRC/cgroup policy stays with `preflight`.
