# Explicit host network preparation

`host_network::prepare_node_network(&ValidatedConfig, cancellation)` explicitly
attempts the fixed shared host-network operations below. It runs a fresh configured
assessment first; callers cannot pass an old or fabricated assessment as permission.
`prepare_node_network_with` supplies a trusted typed provider for tests or embedders.
Production `diorama` main does not call this API yet. Only run the real API on an
explicitly authorized host; development qualification must use disposable VMs.

Root/platform/preflight, container-mode, IPv4, proxy and backend checks retain the
assessment guards. Only the requested IPv6 observations are privately deferred to
the per-control decisions below. Public `assess_node` semantics remain unchanged.
Unknown module family prevents all preparation effects. A configured external
runtime still requires these shared host-network attempts; runtime processes,
configuration, OCI/CNI binaries and images remain host-owned.

Modules follow pinned diorama `internal/system/modules.go`: `br_netfilter`,
`overlay`, six CNI xtables modules, then five nft modules or four legacy modules.
Every attempt runs fixed `modprobe <enum-selected-name>` with working directory
`/`, a cleared environment, system-only PATH and `LANG=C`. A five-second execution
timer requests supervised cleanup and merged stdout/stderr is capped at 4096 bytes.
Raw output is not returned or formatted. Ordinary settled failures, deadline or
capture errors remain typed warnings and permit the next attempt, matching the
baseline warning-and-continue policy. Successful exit does not assert a module
loaded: bounded discovery separately records exact loaded names, built-in index
entries and available index entries after each settled attempt. These observations
cannot resolve aliases, prove loadability or guarantee complete module indexes.

Requested IPv6 controls are exactly `all`, `default`, then `lo` under
`/proc/sys/net/ipv6/conf/*/disable_ipv6`. A complete scalar of at most 64 bytes,
with surrounding ASCII whitespace, must equal `0` or `1`. `1` skips a write;
`0` permits a fixed write of `1`, followed by a fresh bounded readback. Missing
or permission-denied initial reads are reported skips. Malformed, oversized or
other unreadable values are warnings without speculative writes. Failed writes
and readbacks are recorded and subsequent controls are still attempted. Linux
opens use no-create/no-truncate, CLOEXEC, NOFOLLOW, NONBLOCK and NOCTTY and verify
regular-file type. A 65th byte detects over-limit input. This does not promise a
hard deadline for synchronous kernel I/O or defeat hostile mount replacement.

Cancellation is checked before each effect and between IPv6 read/write/readback.
During modprobe it requests stop and awaits owned cleanup. Uncertain ownership
stops all further observations and effects and retains the cleanup observer in the
report. Consumers must treat `CleanupIncomplete` as a quiet terminal failure,
retain the observer if continuing to observe cleanup, and avoid further host work.
The library itself performs no logging and installs no signal listeners. Callers
must retain cancellation delivery until return; dropping the future is not a
substitute for awaiting cleanup. Kernel stalls and escaped descendants cannot be
proven absent by a wall-clock timeout.

`shared_effects_possible` latches after a spawned module command or attempted
sysctl write, including failed or cancelled writes. There is no rollback: unloading
modules or restoring sysctls could disrupt other host users. `Completed` only means
the attempted sequence settled; warnings may remain and it does not mean the
network or node is ready. The embedded assessment records pre-effect observations,
not post-preparation requalification.

Compatibility corrections to baseline `internal/runtime/network/ipv6.go` include
complete-value parsing instead of accepting any first byte `1`, refusing writes
after malformed/other unreadable input, no create/truncate, and readback instead of
claiming a successful write changed the value. Fixed command environment, bounded
capture and deadline/cleanup handling replace inherited unbounded execution.
Baseline `cmd/diorama/main.go:508–515` establishes modules before IPv6 and warnings
without aborting startup; this API preserves that order without starting a node.
Unknown backend detection stays unknown rather than assuming nft on failure.

Scope excludes mounts, moving the current PID, cgroups, IPv4 essential-helper
writes, runtime setup, CRI connection, CNI installation, image import and node
startup. Those remain separate completion gates under E05.

Host-safe tests inject all effects. They cover both fixed module families and
external runtime ownership, fresh guard failures, warning continuation, unjoined
cleanup, cancellation before/during commands and around successful/failed writes,
IPv6 skip/malformed/write/readback decisions, strict scalar parsing and owner-thread
launch failure. Real Linux modprobe/sysctl behavior still requires dedicated
source-bound disposable VM evidence; host-safe tests do not claim that qualification.

The explicit `prepare_host_network` example consumes the existing startup parser.
Help/version/print-config return before signal registration or preparation. A start
action installs SIGINT/SIGTERM listeners through cleanup, then emits one JSON
record containing fixed typed outcomes and redacted observations. Cleanup uncertainty
returns exit 2 quietly. Completed attempts return 0, including typed warnings;
callers must inspect IPv6 outcomes and must not infer readiness from that exit.
Guard stops and cancellation return 1. The example uses Rust available parallelism
for configuration, so it is a diagnostic/preparation consumer rather than the final
release CLI. Dedicated real-Linux qualification lives in `tools/node-network`.
