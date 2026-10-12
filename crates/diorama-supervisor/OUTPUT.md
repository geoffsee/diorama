# Bounded process output

`OwnedProcessAdapter::new_with_bounded_output` accepts a validated `OutputLimit`
(1 through 65536 bytes) and returns the adapter, its existing cleanup observer,
and a separate `ProcessOutput` observer. The ordinary constructor continues to
use null streams. Construction has no process, pipe, thread, or probe effects.

The existing exclusive owner thread creates one merged stdout/stderr pipe. Only
its read end is nonblocking; child writes retain ordinary pipe semantics. Each
owner turn performs at most four 1024-byte reads, including interrupted attempts,
then returns to identity and cancellation handling. There is no reader task or
additional thread. Parent write descriptors are dropped immediately after spawn.
The merged stream preserves bytes, including invalid UTF-8; concurrent writes can
interleave. It cannot attribute bytes to stdout versus stderr.

Exactly the configured limit is valid only after EOF. One additional byte marks
`LimitExceeded`, keeps only the prefix, and requests owned-group force cleanup while the leader identity remains owned.
If overflow is discovered after leader retirement, group cleanup and the sole wait
have already happened; the capture failure never causes a signal to a retired identity.
Read errors also request force cleanup. Neither failure changes exclusive wait or
process-group identity ownership. Setup and launch failures publish separate
terminal statuses without pretending a child was spawned. An owner panic without
published output becomes `OwnerFailed` once the existing observer joins the owner.

A stop request marks output `Cancelled` and stops retaining bytes. The owner
continues bounded discard while performing ordinary TERM/force handling; it does
not close the pipe before TERM and thereby inject SIGPIPE into a cooperative
writer. An earlier capture failure remains the first capture status. After leader
retirement, pending output receives at most 250 milliseconds of further drain
opportunity. A still-held pipe becomes `IncompleteAfterExit` unless already
cancelled. No signal uses a retired PID or process-group identity. This bound is
an elapsed userspace polling policy, not a kernel scheduling or reap guarantee.
Escaped sessions remain outside the adapter's containment boundary.

`OutputSnapshot::Finished` means the retained bytes and capture status are settled;
it does not independently prove the owner thread has joined or the leader was
reaped. Consumers must inspect `ProcessCleanup` and the supervisor outcome. In
particular `Complete` only establishes capture EOF, not a successful command.
Raw bytes require an explicit `bytes()` call and are excluded from Debug and error
codes. This does not redact panic hooks, arbitrary application logs, or explicit
consumer output. Prefix retention is not a general secret protection mechanism.

Local tests cover allocation limits, exact EOF/overflow, nonblocking held writers,
cancellation discard, read failure and owner panic. The ignored integration test
requires `diorama_OUTPUT_DISPOSABLE=1` and an owned container namespace; the dedicated
`tools/supervisor-output` runner qualifies actual adverse child behavior. It must
not be run directly on the development host. No domain command consumer or
cluster startup is implemented by this layer.
