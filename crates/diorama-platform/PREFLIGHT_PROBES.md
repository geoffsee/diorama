# Supplemental preflight observations

`preflight_probe::collect_supplemental(ProbeLimits)` fills the two filesystem facts
required by the pure preflight policy. `probe_ports(pprof)` performs the separately
requested socket phase. Both return `UnsupportedHost` outside Linux. Neither
executes commands, loads modules, prepares directories, changes permissions, or
stops another process. A caller can finish earlier checks before choosing to probe
ports. No CLI command or preparation executor is wired by this slice.

The filesystem collector reads `/proc/version` (the baseline's third whitespace
field, not uname), then checks exactly
`/lib/modules/<release>/kernel/net/netfilter/xt_comment.ko` with suffixes empty,
`.xz`, `.zst`, `.gz`, followed by one directory level matching
`/lib/modules/<release>/*/xt_comment.ko*`. It preserves the baseline existence
heuristic: exact candidates may be directories or symlinks to existing targets;
glob matches may include broken symlinks and non-UTF8 filenames. This does not
prove module loadability. The other fact is existence at exactly
`/sbin/rc-service`, not a PATH lookup or executable permission check.

Reads are bounded to `bytes_per_file + 1` before rejecting excess. Nonblocking,
no-controlling-terminal opens plus a regular-file check reject FIFOs/devices.
The total directory-entry budget covers the base and every visited child directory,
including irrelevant entries. The default limits and hard ceilings are the same as
`ProbeLimits`; `requested_paths` is validated for consistency but unused here.
No recursive traversal occurs. Stored names are bounded by entry count and filesystem
component sizes; public output has only two observations. Missing paths, inaccessible
or malformed data and exhausted limits remain distinct. A positive candidate can
establish existence despite an earlier failed candidate; otherwise failure is not
silently converted to absence.

For safe path construction, empty/missing, dot/dot-dot, slash, backslash, NUL or
longer-than-255-byte release components are rejected as malformed. Invalid UTF8 in
`/proc/version` is rejected. Rust uses a literal release directory and does not
interpret metacharacters in it as a glob. These conservative corrections avoid the
baseline's unchecked path interpolation and ignored read/traversal errors. The
trusted system namespace remains a sequence of observations, not an atomic snapshot
or sandbox against concurrent mount/symlink changes. Byte/count limits do not impose
a kernel-filesystem latency deadline.

The socket phase checks `[2379, 6443, 10443, 6060]`. With pprof disabled the last
slot stays `Unknown(UnsupportedPlatform)` as an unperformed probe, not availability.
For each requested port a close-on-exec owned TCP descriptor sets `SO_REUSEADDR`,
explicitly disables and confirms `IPV6_V6ONLY`, then binds the IPv6 wildcard and
listens. Thus an IPv4-only conflicting listener cannot be missed. Only IPv6
family/protocol/option unsupported or wildcard-address unavailable errors allow an
IPv4 wildcard fallback. Address-in-use, permissions, descriptor exhaustion and
other errors never trigger a misleading fallback success. The descriptor closes
on every success/error path. A setup, bind or listen failure is `BindFailed`, not
proof of a particular PID, service or even occupancy. Successful observation
reserves nothing and cannot promise a later bind will succeed.

The reference is KubeSolo `2ef1c4787989f11f868f81bb84ae2afd4a49a81d`,
`internal/cli/preflight/preflight.go`: `kernelRelease`, `CheckIptablesComment`,
`CheckPorts`, and Alpine's exact rc-service check. Existing independent actual-Go
fixtures in `tools/parity/fixtures/preflight-policy` retain `.zst`/one-level disk
candidates and free/conflicting mandatory/pprof ports. Their semantics are not
inferred from this Rust implementation.

Pure host tests use injected filesystem facts and port outcomes. Actual filesystem
and socket tests are ignored by default, require an explicit disposable flag,
container landmark and UID 65532, and run only via
`tools/parity/fixtures/preflight-probes`. That harness uses private network/mount
namespaces, read-only root, no host mounts, no capabilities and bounded output/time.
It checks both address-family conflicts, optional pprof behavior, immediate rebind,
private filesystem suffix/glob semantics, permissions, non-UTF8 data, FIFO rejection
and limits. One case injects only an unsupported initial IPv6 result, then executes
the real IPv4 bind/conflict/close path. It does not qualify a kernel actually booted
without IPv6. Broader kernel/platform support, host actions, preflight command
presentation and constrained-host integration remain with their owners.
