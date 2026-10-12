# Explicit configured host assessment

`host_preflight::assess_node(&ValidatedConfig, cancellation)` is an explicit async
library operation. `assess_node_with` injects observation providers without a
`Send` requirement on the whole workflow. `cargo run -p diorama --example
assess_host -- <existing startup arguments>` is a diagnostic consumer. It uses the
existing configuration parser; help/version/print-config never install signals or
run assessment. Production `diorama` startup remains unimplemented and unchanged.
The example's CPU count uses Rust available parallelism, not the production CLI's
Go-compatible affinity count; it is not a replacement release CLI.

The example installs SIGINT/SIGTERM after resolving `Start`, before assessment,
and retains listeners until return. Tokio handlers remain installed for process
lifetime, including a partially successful registration. The library installs no
handlers. A pending cancellation wins at phase boundaries, requests the fixed
probe supervisor to stop, and waits for its bounded cleanup observation. Dropping
the whole assessment future is not equivalent to awaiting that cleanup: the owned
adapter requests force on cancellation, but callers must respect its kernel limits.
Synchronous filesystem reads and kernel reap cannot be given a hard wall-clock
bound. Incomplete owned cleanup produces `CleanupIncomplete`; the example exits 2
without further output or observation. This is not proof an uninterruptible or
escaped process disappeared.

Read-only discovery and supplemental observations precede preflight evaluation.
Earlier baseline blockers suppress the command and port phase. Constrained facts
are read only after those checks permit continuing. Unknown required sysctls,
container detection or proxy facts suppress further probes. The fixed command is
`iptables --version`, working directory `/`, environment cleared except
`PATH=/usr/sbin:/usr/bin:/sbin:/bin` and `LANG=C`, with a 4096-byte merged output cap.
A two-second execution timer reports a readiness error to force owned cleanup;
it is distinct from the supervisor's shutdown scheduler and kernel bounds.
Only successful exit, complete output, joined/reaped ownership, and no supervisor
failure admit a module-family hint. Captured bytes are never in the public report.
The ASCII `(nf_tables)` marker is scanned as bytes, matching Go even in otherwise
non-UTF-8 output; successful empty/unmarked output retains the legacy heuristic.

Pinned baseline `internal/system/modules.go:77–84` searches inherited PATH and
assumes nft after command failure. Fixed system PATH and retaining Unknown after
failure are explicit corrections. Proxy selection from `/proc/net/ip_tables_names`
is independent of version-based module family. Neither proves rule programming,
module loadability or permits waiving `xt_comment`.

Runtime ownership derives from the validated endpoint. An explicit container-mode
value overrides detected facts; uncertain detection stays unknown. IPv6 disable
requirements appear only when requested (`ipv6_disable`); `constrained.sysctls`
retains the underlying candidate-value observations for diagnostic comparison,
including unrequested controls. Correct values need no write. Container preparation
is reported as a requirement, never performed. External runtime process/config,
OCI/CNI binaries and sandbox images remain host-owned; missing default plugin paths
are advisory because the host may configure other paths. Distribution CNI config
ownership remains distinct, but this layer does not write it.

`Observed` means this bounded assessment completed, not that a host or cluster is
ready. Remaining module loading, mount propagation, current-node cgroup PID moves,
sysctl preparation, runtime/CRI validation, CNI generation and startup belong to
later owners. No target restrictions are added: the accepted amd64/arm64/ARMv7/
riscv64 glibc/musl matrix remains required; this fixture qualifies Linux arm64 only.
