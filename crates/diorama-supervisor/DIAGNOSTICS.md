# Lifecycle observation

`Supervisor::with_observer()` opts into publication and returns the supervisor plus
an independently cloneable `LifecycleObserver`. Existing `new` and `run` callers
retain their interfaces and need no subscriber. Repeating `with_observer` subscribes
to the existing publisher. No adapters run during construction or subscription.

`snapshot()` returns an owned `Arc<LifecycleSnapshot>` without marking it seen.
`changed().await` returns and marks the latest unseen snapshot. Intermediate values
may coalesce; this is current state, not an event log. The coordinator publishes a
coherent snapshot after processing its lifecycle work and before waiting again,
then publishes `finished=true` before returning the final report. There is no
heartbeat. A slow or absent reader introduces no queue, await or consumer
backpressure into supervision. The private watch borrow is held only while cloning
an Arc, and no public API exposes a borrow guard that a caller can retain across
an await. Internal channel synchronization still uses short critical sections;
this is not a lock-free or hard real-time scheduling guarantee.

An unseen final snapshot remains available after publisher closure. `ObserverClosed`
means no further updates will arrive. Inspect the last snapshot: `finished=false`
means supervision did not publish completion, including cancellation or dropping an
unrun supervisor. It must never be interpreted as clean shutdown. `finished=true`
means the coordinator returned its report; cleanup errors and the process adapter's
separate OS ownership limits still apply. Dropping observers does not request stop.
Use the existing stop handle and await the supervisor for coordinated shutdown.

The snapshot contains component identity, kind, failure policy, current state,
monotonic state-change instant and startup deadline. `published_at` records when
that view was published. Consumers can compare the monotonic timestamps with the
current Tokio instant to describe slow starts without requiring periodic publisher
updates. These instants are process-local, not wall-clock or durable timestamps.
`Ready` means startup readiness was reported; it does not imply continuous health
checking, API responsiveness, successful workload reconciliation or runtime liveness.

Failures, cleanup failures and the original stop cause are retained with the same
codes and ordering as the final report. Optional failures set `degraded`, which
stays true even after their components reach `Stopped`. No additional failure policy
is imposed by observation. Healthy components continue according to the existing
graph and policy; fatal failures preserve the original cause through cleanup.
The final snapshot's diagnostics match the final report. The snapshot omits the
transition history and raw adapter values, configuration, arguments, environment,
readiness error messages and panic payloads. Component IDs and static diagnostic
codes are public caller-supplied identifiers: callers must not put secrets there.
This is not a sanitizer for deliberately secret-bearing IDs or global panic-hook
stderr output.

The channel retains one latest Arc, with state and finite failure evidence bounded
by the registered graph and its lifecycle. Consumers retaining old Arcs allocate
their own additional memory; publication cannot reclaim those references. Allocation
and snapshot copying scale with the graph. This slice adds no dependencies or
unbounded delivery queue.

## Evidence and remaining integration

The baseline at `2ef1c4787989f11f868f81bb84ae2afd4a49a81d` logs optional deployment
errors and continues for local-path, Portainer and D2k in `cmd/diorama/main.go`
(lines 319, 332 and 343). `internal/logging/logging.go` defines log levels and
pretty/no-color/JSON output; main enables DEBUG from configuration. This observer
makes retained optional failures available during operation without reproducing
raw error logging. It is partial groundwork for issue #44, not its completion.
Structured JSONL formatting and debug filtering are covered by
`crates/diorama/LIFECYCLE_LOGS.md`. Caller-owned writer delivery is covered by
`crates/diorama/LIFECYCLE_SINK.md`. The production CLI consumer, actual API
usability under optional failure, process-adapter composition, and ongoing component
health remain integration work.

`tests/diagnostics.rs` exercises a responding healthy worker during visible optional
failure, original fatal cause plus cleanup failure, coalescing and retained snapshots,
monotonic slow-start visibility, cancellation versus final closure, unpolled/dropped
subscribers across the unchanged 35-second shutdown budget, repeated subscription,
and absence of an adapter-captured synthetic secret from diagnostic output.
These are cooperative task tests, not real Kubernetes or OS process qualification.
