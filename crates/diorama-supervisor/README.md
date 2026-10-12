# Supervisor core

The core coordinates injected, cooperative async adapters with validated startup
dependencies, readiness deadlines, fatal/degraded outcomes, and bounded cancellation
through one task-joining coordinator. The crate also provides an opt-in
[owned-process adapter](PROCESS.md) and [Unix signal bridge](SIGNALS.md). Kubernetes
component assembly and production CLI startup remain separate integration work.
It does not close issues #42, #43, #44, or their parent epic.

The selected external-component boundary is documented in the
[component ADR](../../experiments/component-boundary/ADR.md). Reference behavior comes
from pinned KubeSolo [main.go](https://github.com/portainer/kubesolo/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/cmd/kubesolo/main.go),
[lifecycle.go](https://github.com/portainer/kubesolo/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/internal/runtime/service/lifecycle.go),
and component executors' worker-side cancel-only shutdown correction. The core
intentionally implements the accepted bounded supervisor contract rather than the
baseline's competing signal readers, signal-only waits after cancellation, or
retry-count approximation of elapsed startup time.

## Interface

Construct `Registration::new(ComponentSpec, adapter)` entries and pass them to
`Supervisor::new`. This validates all identifiers, dependency references, duplicate
edges, cycles, zero timeouts and unrepresentable timeout values before invoking any
adapter. The graph is generic; it contains no speculative Kubernetes startup graph.
An empty graph finishes without work. Identifiers are operator-visible nonsecret
labels; callers must not use credentials or raw URLs as component IDs.

An `Adapter` consumes itself and returns a boxed `Send` future producing
`Result<(), AdapterError>`. `AdapterContext::ready()` reports usable readiness once;
repeated calls return false. `stop_phase()` and `changed().await` expose `Running`,
`Graceful`, and `Force`. Context-channel disappearance reports `Force`. Adapters must
observe those phases and release owned resources before returning. Workers cannot
join the coordinator or sibling tasks through this interface.

`stop_channel()` produces a clonable `StopHandle` and a single `StopReceiver` passed
to `Supervisor::run`. `stop()` is idempotent and returns true only for the first
request. Dropping every handle requests shutdown with `ControlClosed`. Keep a handle
alive while supervision should continue. Use the handle and await the final report;
dropping the supervisor future is not the supported shutdown protocol.

## Startup and failures

Independent eligible components may start together. A long-running prerequisite
unblocks dependents only after usable readiness. A one-shot prerequisite unblocks
them only after successful completion; an early readiness notification is insufficient.
A long-running adapter returning success before stop is an unexpected exit.

Each component has a monotonic deadline beginning at its own launch, not at graph
startup. The launch rechecks representability in case construction happened earlier.
One-shot tasks must finish before their deadline. Long-running readiness includes
its send timestamp, so coordinator scheduling delay does not erase timely readiness.
Readiness or completion exactly at the deadline is late. Already-completed workers
are processed before queued readiness and dependent launches; an already-observable
exit wins over queued readiness. This does not make readiness and a concurrent future
exit atomic across executor threads. Later failure after valid readiness remains
a component failure, not retroactive proof that the earlier readiness was invalid.

Fatal failures initiate global shutdown. Degraded failures affect their dependent
subgraph while independent components continue. Failure of a prerequisite propagates
through completed one-shot intermediaries; unavailable dependents never start.
A required dependent of a failed optional prerequisite can itself make the failure
fatal. Disabled components should be omitted by the graph builder; missing referenced
prerequisites are configuration errors, not silently satisfied dependencies.

The first observed stop cause is preserved. Later worker/cleanup errors are retained
separately. If completion crosses the startup deadline, timeout is primary and any
adapter failure remains secondary evidence. Ordering of concurrently occurring
independent failures follows observation order; no cross-thread total-order claim is
made. `AdapterError` carries a static diagnostic code rather than arbitrary command
lines, environment dumps, or credentials. Reports omit panic payloads. Normal Rust
panic hooks can still print adapter payloads to stderr; report safety is not global
stderr redaction. Repository release profiles use `panic=abort`, so adapter panics
cannot be recovered in those profiles; expected failures must return `Result`.

## Shutdown and ownership

Once stop is observed, pending components are not launched. Graceful stop proceeds
in reverse dependency waves, waiting for active dependents to finish before asking
their providers to stop. Transitive dependencies through completed one-shot tasks
are included. Workers merely return outcomes; the coordinator alone joins them,
including the worker whose error initiated shutdown.

The entire graph shares 30 seconds of graceful shutdown and 35 seconds total, as
selected in the compatibility contract. These are not renewed per component or
wave. At 30 seconds all remaining adapters receive `Force`, including providers
whose dependents stalled; escalation is recorded. At 35 seconds remaining futures
are aborted and joined, recording `AbortedAtDeadline`. A local optional failure has
the same cleanup budget without stopping independent components; a later global
stop uses the earlier applicable deadline. A stalled dependent can consume its
provider's graceful opportunity: the report records escalation rather than calling
that clean shutdown.

These bounds require cooperative, nonblocking futures and a scheduled Tokio runtime.
No async library can interrupt blocking code in a future poll or blocking destructor.
Abort/join proves only that the registered task future was dropped; it proves nothing
about detached tasks, owner threads, OS processes, sockets or files an adapter created.
Adapters must not detach untracked work. `AbortedAtDeadline` is incomplete adapter
cleanup evidence, never successful process reaping. The owned-process adapter
provides separate child identity, termination/escalation, reaping and cancellation
ownership guarantees, with disposable evidence described in [PROCESS.md](PROCESS.md).
[SIGNALS.md](SIGNALS.md) covers real signal delivery through that adapter. These
interfaces do not claim arbitrary escaped-descendant containment or whole-node
shutdown qualification.

`SupervisorReport` contains the original cause, terminal component outcomes,
component failures, cleanup failures and timestamped transitions. This slice returns
diagnostics at completion; live logging/metrics integration remains a later consumer.

## Verification

```sh
cargo test -p diorama-supervisor --locked
cargo test -p diorama-supervisor --locked --release
cargo clippy -p diorama-supervisor --locked --all-targets --all-features -- -D warnings
```

Tests use independently specified event-order/state expectations and Tokio's paused
clock. They cover graph rejection before effects; readiness and exact deadline
boundaries; one-shot completion; ready/exit races; startup and post-ready failures;
optional isolation and dependency propagation; partial startup; repeated stop;
worker-originated failure and original-cause preservation; reverse transitive stop
ordering; force-aware and stalled cleanup; and deadline overflow. A Drop sentinel
proves registered futures have been dropped after abort/join. No sleeps consume
30 seconds of wall time in the core tests, and no real-process result is inferred
from them. Separate disposable process and signal tests are documented in the
linked adapter guides. Configuration-to-supervision policy and component protocol
integration require their own evidence before the relevant issues close.
