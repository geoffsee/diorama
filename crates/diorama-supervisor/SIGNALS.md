# Explicit Unix shutdown signals

`signals::run_with_signals(Supervisor)` installs SIGINT and SIGTERM listeners,
then polls the supervisor and both listeners in a single task. It returns
`Result<SignalRunReport, SignalInstallError>`. The report contains the complete
supervisor report, the first signal observed by the bridge, and an optional
unexpected-listener-closure diagnosis. No signal-handler forwarding task is spawned
or detached. Adapter failures can complete supervision without any signal.

Both listeners must install before an adapter is polled. Installation errors carry
the signal kind and `std::io::ErrorKind`, excluding raw OS error text, command lines,
environment values and credentials. Injected failure tests establish no adapter
side effects; they do not establish rollback of process-wide signal registration.
If SIGINT installs and SIGTERM installation fails, the SIGINT handler can remain
registered despite the returned error.

Call this API only inside a Tokio runtime with its I/O driver enabled (for example,
`Builder::new_current_thread().enable_all()`). Tokio requires that runtime context;
missing I/O/runtime support is a caller precondition violation, not a recoverable
`SignalInstallError`. The module is Unix-only. Nothing installs signal handlers on
crate import or supervisor construction, and this slice does not wire production
CLI startup or choose a Kubernetes component graph.

The first observed signal requests the existing idempotent stop channel. Subsequent
signals never reset or shorten the core's 30-second graceful and 35-second total
scheduler budgets. Unix and Tokio may coalesce deliveries, so no exact signal count
or physical delivery ordering is promised. A completed supervisor report is polled
before another signal; worker failure and the first core stop cause retain the
core's existing observation-order policy. Unexpected listener end requests stop
without fabricating a signal and disables that stream to avoid a busy loop.

Signal handling changes process-wide behavior. Dropping Tokio listeners or this
future does not restore the OS default handlers. This interface is intended for a
dedicated node executable's lifetime, not a temporary library subscription.
Dropping the outer future also does not await adapter cleanup: keep it alive until
it returns. The bridge does not add second-signal immediate exit; an operator's
SIGKILL remains outside cooperative cleanup. Repository panic-abort behavior and
normal panic-hook output retain the core's documented limits.

The budgets require cooperative adapter futures and a scheduled runtime. They are
not a hard OS process termination guarantee. The standalone bridge tests use
cooperative task adapters. The combined Linux qualification also exercises
`OwnedProcessAdapter` and its explicit cleanup observers through real signals;
it retains the [process ownership assumptions](PROCESS.md). Concrete Kubernetes
component probes, detached work and arbitrary descendant containment remain outside
this qualification.

## Reference and policy

The baseline is KubeSolo `2ef1c4787989f11f868f81bb84ae2afd4a49a81d`:
`cmd/kubesolo/main.go` registers interrupt/SIGTERM around line 170, cancels from a
signal goroutine, and later waits on the same signal channel again. Worker-side
cancel-only lifecycle corrections avoid self-wait but do not make those competing
signal readers a desirable contract. This bridge follows the accepted E04 bounded
shutdown behavior instead: one coordinator returns on either requested stop or
fatal worker outcome. It preserves signal support and repeated-stop safety without
reproducing a wait for a second signal after cancellation. No init-system or
Prometheus integration is included.

## Verification and evidence

```sh
cargo test -p diorama-supervisor --locked --lib
cargo test -p diorama-supervisor --locked --test suite signals:: -- --nocapture
cargo test -p diorama-supervisor --locked --release
cargo clippy -p diorama-supervisor --locked --all-targets --all-features -- -D warnings
cargo run --locked -p diorama-dev --bin diorama-supervisor-fixture -- signals capture /tmp/new-signal-capture
```

Three injected tests check install failure, unexpected listener closure and repeated
notifications through the unchanged virtual 35-second deadline. Real signals are
tested only in dedicated child test processes; handlers are never installed in the
parallel parent test runner. The parent waits for an adapter marker emitted after
listener installation, sends SIGINT/SIGTERM only to its unreaped child PID, and
waits for cleanup. A child that exits between liveness check and delivery remains
waitable, so its PID cannot be reused by an unrelated process. Timeout cleanup
kills and reaps only that owned test child.

Twenty repetitions exercise full and partial startup, each initial signal, each
with and without repeated mixed signals (160 cases), plus 20 worker-failure cases
that receive no signal. Each child asserts that registered adapter guards are
dropped, pending dependents never ran during partial startup, the first signal or
fatal cause is preserved, and cleanup has no reported failure. The parent requires
successful exit and a result marker, and reaps every child. The clean-case five-
second test deadline is a regression guard, not the supervisor's escalation policy.
The child output is trusted finite test text with an aggregate 64KiB assertion;
line reads are not a hostile-output sandbox.

The public Linux arm64 capture in `tools/supervisor-signals/evidence` runs this
release-mode test binary in a read-only, nonprivileged, network-disabled container
with no host mounts/devices. Its outer runner bounds streamed logs, records the
exact source inventory, locked toolchain/image and test binary digest, and retains
cleanup receipts. The qualification summary means all 180 child assertions passed;
individual successful child streams are consumed by the parent rather than retained
as separate artifacts. Failure output is included in the parent's test failure.
Darwin arm64 was also exercised locally. The Linux capture additionally runs 61
owned-process cases: 20 repetitions each of full startup, partial startup and fatal
worker failure, plus one real TERM-to-KILL escalation. Full-startup cases require
coordinator-accepted readiness; every case checks exact cause/cleanup evidence,
owner joining/reaping, external-sentinel survival and namespace cleanup. The earlier
two-by-eleven process suite is recaptured on the same integrated source. These are
bounded supervision qualification results, not a claim that #42/#43/#44 or parent
E04 is complete.
