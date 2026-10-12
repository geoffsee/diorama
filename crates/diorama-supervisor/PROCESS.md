# Owned process adapters

`process::OwnedProcessAdapter::new(command, readiness)` returns an adapter and a
separate `ProcessCleanup` observer. Construction is effect-free. The command runs
only after the adapter future is polled with a running supervisor context; the
readiness future is polled only after successful process creation. Keep the
observer outside the supervisor task so cancellation does not erase the cleanup
result. `ExternalServiceAdapter` can await readiness and acknowledge stop; it has
no process identity or signaling capability.

`ProcessCommand` preserves OS argument/environment values, defaults stdin/stdout/
stderr to null, and deliberately omits command contents from Debug. Inherited
environment is retained unless the caller selects `env_clear`. There is no shell
interpretation, arbitrary pre-exec callback, global signal handler, or PID-based
public kill method. Component-specific log capture and readiness/health protocols
remain later integrations; readiness here is an injected cooperative future.

A dedicated standard-library thread owns each `std::process::Child`. The child
starts in its own process group through `process_group(0)`. The owner uses pinned
rustix 1.1.5 `waitid(EXITED|NOHANG|NOWAIT)` to observe an exited leader without
reaping it, then signals the group before its final `Child::wait`. It retries
interrupted observations. Keeping that exclusive child waitable prevents its PID
from being reused for an unrelated process group. PID 1 is explicitly rejected.
After reaping, the child handle is retired permanently; no further group signals
are permitted. `ECHILD` revokes ownership and records incomplete cleanup.

This requires exclusive reaping ownership: no `try_wait`, Tokio child wrapper,
competing `wait(-1)` reaper, SIGCHLD auto-reap/ignore configuration, or external
wait operation may consume this child. It also assumes cooperating children stay
in the created process group. It does not promise containment of daemonization,
new sessions, changed groups, descendants after parent death, or unrelated
processes deliberately joining an owned group. Process-group signaling is not a
replacement for stronger OS service/container containment.

Graceful stop sends TERM; force sends KILL. An exited leader triggers a final
owned-group KILL sweep before reaping, including after natural or early exit.
This is why `kill_attempted` and `force_requested` are separate facts. Exit 0,
expected TERM, and explicitly forced KILL are recognized separately; other
abnormal exits remain errors even during requested stop. The original readiness
error stays primary if cleanup also fails; the observer retains the cleanup
error. One-shot versus long-running exit semantics remain the core's concern.

Dropping/aborting the async waiter drops the sole control sender, causing the
owner to request forced cleanup. Async Drop never blocks on OS wait or thread
join. The owner thread may block in the kernel, even after KILL; the supervisor's
35-second cooperative deadline is not a bound on kernel exit or reaping.
`ProcessCleanup::wait(timeout)` returns a snapshot at its observation deadline.
`started`, `spawned`, `leader_reaped`, `thread_finished`, `thread_joined`,
`ownership_lost`, signal-attempt facts, exit status and errors remain distinct.
`complete()` means successful owner completion and leader reaping when spawned;
it does not assert that arbitrary descendants are gone. A never-launched adapter
remains not started and does not claim completed cleanup. Retain and inspect
incomplete observers; dropping them cannot create an OS cleanup guarantee.

The emergency owner guard runs on the dedicated thread during ordinary unwinding.
Process abort, SIGKILL, machine failure and `panic=abort` skip Rust destructors.
The disposable worker-panic test exercises unwind/task-failure propagation, not
recovery from the production release profile's abort behavior. No library-wide
signal registry is installed; executable SIGTERM/SIGINT wiring remains separate.
The module is available on Linux and macOS; actual process qualification in this
layer is Linux arm64 only.

The process-free tests check effect-free construction/rejected graphs, diagnostic
redaction, interrupted observation and failure precedence. The ignored integration
test is only run by `diorama-supervisor-fixture process capture` in an unprivileged
container with its own PID namespace, init reaper, no network or host bind mounts,
read-only root and bounded private temporary storage. It covers delayed readiness,
cooperating descendants reaped by their parent, ignored TERM with real 30-second
escalation, TERM followed by nonzero exit, early leader exit, a leader exiting
before its same-group descendant, one-shot completion, readiness failure,
worker panic, supervisor cancellation, and an unrelated sentinel that remains
live across component cleanup and external-service stop. The driver checks the
final namespace inventory and removes/inspects its owned Docker resources even
when a test fails. This containment is a test boundary, not a production orphan
cleanup claim.
