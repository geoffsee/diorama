# Read-only platform observations

This first E05.01/#45 slice separates observations from startup policy. `discover`
reads the current Linux process's namespace; `classify` accepts captured evidence
without performing IO. `node_target` validates an explicitly requested Linux node
artifact target independently of kernel machine and the running executable ABI.
All four accepted architectures (`amd64`, `arm64`, ARMv7 hard-float `arm`,
`riscv64`) support both glibc and musl under accepted deviation D01. Detection does
not prove an artifact can run on the observed hardware. Non-Linux live discovery
returns `UnsupportedHost`; classifiers and target selection work on other hosts.

`Observation<T>` distinguishes present values, absent paths and unknown facts
(permission denied, IO error, malformed text, oversized input or unsupported probe).
An unreadable higher-priority init landmark cannot become a confident lower-priority
init result. No missing libc observation becomes proof of glibc: `host_libc_hint`
is explicitly the baseline linker-presence heuristic, independent of Rust's target
environment. Init landmarks describe baseline classification, not a successful
connection to a running service manager.

Evidence retains kernel uname identity, real/effective UID, raw hostname, executable
OS/architecture/environment, fixed init/container/tool landmarks, musl linker names,
cgroup controllers, loaded modules, available module dependency indexes, built-in
module indexes, mountinfo, and requested-path metadata. `modules.dep` and
`modules.builtin` are read under the running kernel release, not the executable
architecture. Index entries retain relative paths and dependencies; they do not
prove the module file is present, loadable, or needed. Unsupported/malformed index
syntax is explicit unknown evidence, never silently skipped.
Installer environment classification and runtime container indication are distinct:
the former checks cgroup docker text and device-tree model; the latter checks the
`container` environment variable. Both use Docker/Podman marker files. Raw hostname
is not normalized or validated here: the existing config runtime conversion owns
trim/lowercase/fallback selection; installer RFC1123 policy belongs to preflight.

Requested paths retain their exact spelling, including relative paths, which are
observed against the caller's current directory. Metadata describes a symlink itself
and its target spelling. The probe does not create missing directories, follow a
requested symlink for write access, chmod, mount, load modules, run commands, bind
ports or alter runtime configuration. Mount and superblock read-only flags remain
separate; neither modes, flags nor successful reads guarantee a later write succeeds.
No path is inferred to be distribution-owned. External runtimes are untouched.

Default read limits are 1 MiB per fixed system file, 4096 total libc directory entries
and 64 requested paths. Caller limits have hard ceilings (4 MiB, 16384 entries,
256 paths; each requested path <=4096 bytes). A read consumes at most limit+1 bytes
and rejects oversized input. Linux opens fixed text paths nonblocking/no-controlling-
terminal and verifies regular-file type; this includes procfs virtual regular files.
These are byte/count limits, not deadlines on kernel filesystem operations. The
system namespace is trusted; this is not a sandbox for adversarial mounts, symlink
races or arbitrary caller-provided `HostEvidence`. Discovery is a sequence of
observations, not an atomic host snapshot. Callers must not put secrets in paths or
synthetic evidence intended for diagnostic display.

Baseline references at `2ef1c4787989f11f868f81bb84ae2afd4a49a81d` are
`internal/cli/detect/detect.go`, `internal/cli/preflight/preflight.go` and
`internal/system/host.go`. Sixteen actual Go detection cases are captured twice in
private child roots inside disposable containers; nine actual `ForTarget` cases
retain the baseline ARM/RISC-V musl rejection. Rust tests independently assert D01's
correction instead of laundering that difference as identical behavior. Other tests
exercise missing/unreadable facts, cgroup generations, malformed module/mount data,
byte limits and read-only path preservation. See
`tools/parity/fixtures/platform-discovery` for source hashes and receipts.

Broader real platform/ABI qualification, deployment-specific module loadability and
capability consumption remain parent-epic and later-consumer qualification work.
This slice supplies module index, loaded module and networking-match observations, not a guarantee
that missing modules are unavailable or required. #46 owns actionable preflight
policy/check output and owned preparation; #47 owns constrained/external-runtime
policy. Networking IP/MTU selection, CRI negotiation, installers, service generation,
mount/cgroup preparation and live cluster startup remain with their consumers.
Parent E05 retains E03/E04 integration/completion gates.

Baseline init command landmarks deliberately use fixed directories and existence only:
`/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`.
They ignore caller PATH and do not check executable permission, ACLs or file type.
This matches actual `detect.commandExists`, unlike an `exec.LookPath` query.
Captured negative fixtures retain its acceptance of a nonexecutable `systemctl` file
and even a directory, and its rejection of a command present only in custom PATH.
These are classification hints, never authority to execute a discovered path.

Module text indexes are heuristic observations: [kmod documents](https://man7.org/linux/man-pages/man5/modules.dep.5.html)
`modules.dep` as human-readable metadata whose format can change. Consumers must
retain unknown/index-missing outcomes rather than interpret them as unavailable
modules or successful preparation. Actual module loading stays outside this crate.
