# Explicit host preparation

`host_preparation::prepare_node_host(validated_config, cancellation)` is an explicit
library boundary. It performs a fresh assessment and the existing network sequence,
then prepares mounts and cgroups only when the freshly resolved container mode
requires them. `prepare_node_host_with` accepts trusted typed inputs for tests and
embedders. Neither entry accepts a caller-created assessment as authorization.
Production `main` does not invoke this API.

Network warnings permit container preparation after owned command cleanup settles.
Guard failure, cancellation and uncertain command cleanup stop the sequence. The
network report retains any cleanup observer. External runtime selection does not
waive these shared host effects. A resolved noncontainer configuration has a
`NotRequested` container report and never acquires a container session.

## Caller and execution contract

Call during quiescent startup, before runtime/child spawning. All executor threads
that may poll this operation must have the intended mount and cgroup namespaces.
Do not concurrently change namespaces, root/chroot, mount topology, cgroup layout or
membership. Each synchronous operation validates the executing thread through
`/proc/thread-self`, retained namespace descriptors, and the root mount identity.
Cgroup operations additionally compare the fixed cgroup root and existing init
identities. These observations detect change or unavailable evidence; they do not
lock the kernel state or guarantee race-free authorization under a violating caller.
No private namespace is created. Shared propagation can affect existing peer mounts.

The same cancellation future and latch span assessment, network and container work.
Async checkpoints yield between operations so timers/signals can progress. Cancellation
cannot preempt synchronous kernel I/O. Byte/record limits are enforced, but there is
no hard deadline for a mount, filesystem read or write. The library installs no signal
listeners. Keep cancellation and the operation owned through completion.

## Mounts

The Linux provider attempts the baseline recursive shared operation on `/` through
safe rustix `mount_change(SHARED | REC)`. A complete mountinfo snapshot must retain the
anchored root and topology and show every visible descendant shared. Accepted syscall
with unknown, incomplete, changed or nonshared readback is a fatal partial effect,
and no cgroup mutation follows. Subsequent guards also require the verified shared
state. Parsing bounds are 1 MiB, 4096 records, 16 KiB per record, 128 fields per record,
and 256 parent edges. Kernel octal path escapes are decoded; bytes need not be UTF-8.
Mount IDs are sorted for bounded binary parent lookup; cycles/disconnected trees fail.

## Cgroups

Fixed `/sys/fs/cgroup` acquisition walks directory descriptors without following
symlinks. Crossing the legitimate `/sys`/cgroup mounts is allowed while acquiring that
root. Below the validated cgroup2 root, safe `openat2` requires BENEATH, NO_SYMLINKS,
NO_MAGICLINKS and NO_XDEV. Unsupported kernel support is reported without a weaker
path fallback. Control files must be regular files on cgroup2 and are opened without
create or truncate. No arbitrary path or caller PID is accepted.

Mutation admission requires `cgroup.type=domain` and the actual process already in
that anchored root or its existing fixed `init` child, proven by bounded cgroup.procs
reads. Existing init must also be a domain. This is a deliberate bounded safety
deviation from the Go baseline's unconditional relocation. Threaded/domain-invalid
roots, unrelated membership and a missing cgroup.type are unsupported or fatal; even
namespace-relative `/` is not treated as proof of the true hierarchy root exemption.
A positively observed cgroup-v1 filesystem is the sole explicit skip. A tmpfs layout
with v1 controller submounts is not inferred to be v1; missing, permission, malformed,
wrong-type and wrong-filesystem observations remain distinct errors.

The provider creates only `init` (0755), or validates the existing directory. It writes
`std::process::id()` once to init/cgroup.procs, checks for short writes, and independently
reads the actual process back there before delegation. No helper, PID 1 assumption,
other-process evacuation or child migration is used. All threads in the process move;
existing child processes remain in their original cgroups. Existing init controller
constraints can reject migration and are reported without repair. PID reads are capped
at 64 KiB/4096 entries; ordering and duplicates are allowed.

Available controllers and subtree_control use complete reads capped at 4 KiB, 32 names
and 64 bytes/name. Names must be unique ASCII kernel tokens. A bulk enable request is
followed by per-controller fallback on ordinary write/open permission, read-only,
I/O or short-write failures, with cancellation checkpoints between attempts. Admission,
context, type and interface failures stop. Root/domain/membership are revalidated for
every operation, and after observed migration only init membership is admitted.
Kernel bulk operation failure is atomic; individual fallback successes can persist.
Nothing disables controllers or changes resource limits.

The report retains each attempt, enabled-before and independent enabled-after state.
Successful writes do not imply delegation. Missing controllers and unreadable final
state are visible partial warnings; lost authorization at final observation is fatal.
`Completed` means the scoped sequence settled, possibly with warnings, not that a node
or runtime is ready. `shared_effects_possible` latches every reached mutation syscall,
including failed writes and later cancellation. There is no rollback, mount reversal,
process move-back, init deletion, controller disable, module unload or network undo.

## Evidence and remaining qualification

The behavior traces KubeSolo `cmd/kubesolo/main.go` container setup after network
preparation, `internal/system/host.go` SetupContainerMounts/SetupContainerCgroups, and
`internal/system/mount_linux.go`. The Rust report corrects the baseline's misleading
successful-delegation log after failed writes. Safe injected tests cover sequence,
guards, cancellation progress, partial failures and readback; Linux-only parser tests
exercise complete bounded records. These tests do not claim actual kernel effects.

Actual effects require a separately reviewed owned disposable VM fixture. Its consumer
must execute as the observed PID in a delegated non-root cgroup, within a newly isolated
mount namespace made recursively private before bind-remapping the cgroup root. An
outside observer and a live-consumer barrier must confirm PID membership, mount sharing,
controller readback, unchanged siblings and cleanup. First/repeat real cases and
separately labeled failure/cancellation doubles remain qualification work.
