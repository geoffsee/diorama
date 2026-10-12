# Explicit lifecycle log delivery

The `lifecycle_logs` library module renders supervisor observations and delivers
JSONL frames to a bounded caller-owned channel. It installs no logger, changes no
global level, writes no stdout/stderr, and starts no background task or thread.
The caller explicitly creates the renderer/channel and owns or spawns
`consume_lifecycle(observer, renderer, sender)`. It must retain the returned
`DeliveryReport`; ignoring it discards delivery-loss evidence.

`LifecycleRenderer::render(&LifecycleSnapshot)` is pure with respect to the outside
world: no clock, environment, path or writer access. JSON escaping is performed by
serde_json. Fields are deterministically sorted and each frame has one trailing LF,
`schema: 1`, `event` and `level`. Input timestamps determine `state_age_ms` and
`startup_remaining_ms`; durations saturate at u64 milliseconds. They are monotonic
elapsed diagnostics, not wall-clock timestamps. Starting-state output can describe
a slow observation, but there is no heartbeat or periodic health checker.

The renderer is bound to one registered graph, including component order, ID, kind
and failure policy. Duplicate/unknown identities, excessive inputs, a changed graph,
rewritten retained failure history, replaced original cause or backwards publication
time return typed errors without echoing offending data. A new supervisor requires
a new renderer. Last accepted state is copied into bounded bookkeeping, rather than
retaining caller-provided Arc/vector spare capacities. Observations may coalesce:
only observed state changes can be emitted. Retained failure and cleanup prefixes
are deduplicated by position, preserving distinct equal-valued failures. Identical
snapshots emit nothing. The original cause is emitted once. Completion and optional
degradation are emitted once; no transition reconstruction is claimed.

Thresholds include their own severity and all higher severities:

| Records | Level |
| --- | --- |
| Component failures, including optional failures; fatal stop cause | Error |
| Cleanup adapter errors, panic, cancellation, final deadline abort | Error |
| Forced cleanup and lost stop control | Warn |
| Requested/finished stop, degradation summary, final completion | Info |
| Component state, kind/policy and startup timing | Debug |

`LogLevel::from_debug(false)` selects Info and `true` selects Debug. A renderer's
threshold is fixed; changing it requires a new renderer and can re-emit retained
facts. Severe failure/cause records are considered before state details so debug
traffic cannot consume a batch's space before those facts. Filtering counts records
intentionally hidden. It does not change component policy, supervision or readiness.

The pinned Go baseline's `cmd/kubesolo/main.go` sets DEBUG in bootstrap at line 495,
then unconditionally sets INFO at line 505. Honoring the resolved debug setting here
is an explicit correction of that reset, not a claim of byte-identical runtime Go
output. Baseline `internal/logging/logging.go` also supports pretty/no-color/JSON
stderr output; this bounded structured renderer does not reproduce console colors,
wall-clock timestamps, caller paths or raw error strings. Existing CLI startup
version/help/configuration warning/error/print paths remain unchanged and precede
runtime bootstrap. The actual startup JSON fixtures are not evidence of post-
bootstrap runtime logger formatting.

## Bounds and loss semantics

These are selected implementation limits, not measured baseline limits: at most
256 components, 1,024 combined retained failure/cleanup entries, and 256 UTF-8 bytes
per public ID or diagnostic code. A frame is capped at 4 KiB and a rendered batch
at 64 KiB. Frames exceeding the remaining batch/frame budget are counted as
`oversize`. Input-limit errors stop rendering with `RenderError::InputLimit` rather
than allocating unbounded bookkeeping. Count caps also bound rendered record count;
a batch considers at most 1,283 records (components + diagnostics + three summaries).
Only a capped current record is serialized before testing the byte budget.

`log_channel` accepts capacities 1 through 64; queued frame contents therefore use
at most 256 KiB, plus bounded bookkeeping/container overhead. Its receiver exposes
async `recv` and `blocking_recv`. Call `blocking_recv` only from a blocking worker:
Tokio panics if it runs inside an asynchronous execution context. Callers decide
whether and how to write frames elsewhere. `deliver_logs` is the owned writer.
The observer consumer calls `try_send`, never awaits a sink writer or channel space.
An unread or slow queue cannot block the supervisor coordinator. `enqueued` counts
accepted frames; `dropped_full` counts frames lost to capacity. Oversized/full frames
are not retried; deduplication advances after a successfully validated snapshot.
Thus a consumer must not equate a healthy supervisor or a final snapshot with
complete log delivery. The retained supervisor report remains authoritative.

`closed` counts undelivered frames in a batch when the receiver is closed; if closure
is detected while waiting without a batch, it increments once to record the closure
notification. It is a loss/closure counter, not an exact count of future records
that might have been emitted. Closed sinks terminate the consumer promptly even
when no lifecycle update arrives. Counters saturate rather than wrap. A publisher
status of `Finished` means the observed snapshot had `finished=true`; `Cancelled`
means the observer closed without final publication. `Open` can remain when a sink
closed or rendering failed before observing final publication. This status describes
the observed publisher, not success of the sink. `render_error` independently retains
an input/identity/history error. Dropping the consumer future provides no final
DeliveryReport and no delivery guarantee.

No raw adapter errors, panic payloads, config, command arguments or environment are
available to this renderer. IDs/static codes are explicitly public caller input;
putting secrets there violates the contract. JSON escaping prevents line/field
injection but is not credential redaction. Arbitrary downstream writers, OS pipe
blocking, durable flushing and stderr ownership are outside this slice. Enqueued
frames have not necessarily been read, written or flushed.

## Qualification

Focused tests cover exact JSONL escaping/ordering, deterministic monotonic timing,
all thresholds, repeated/coalesced histories, invalid identities and input caps,
batch overflow, exact delivery counters, closed sinks and cancelled publishers.
A synthetic healthy worker answers requests while an optional failure is logged;
its captured synthetic secret is absent. An unread capacity-one queue does not
extend the existing 35-second shutdown deadline. These are cooperative unit tests,
not Kubernetes API availability qualification.

Run `cargo test -p diorama --locked --test suite lifecycle_logs::` and the corresponding
release-mode test, then strict package Clippy. No registry package is added: this
uses existing serde_json and the already-locked supervisor/Tokio dependencies.
Caller-owned writer delivery and flush policy now live in `LIFECYCLE_SINK.md`.
This is partial issue #44 work. Production CLI runtime invocation, real component
readiness/ongoing health, and actual API usability under optional failure remain
integration gates. No issue closure or whole-node logging qualification is claimed.
