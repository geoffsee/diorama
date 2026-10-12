# Lifecycle frame delivery

`deliver_logs` copies already rendered JSONL frames to a caller-owned `std::io::Write`.
It does not render, filter, subscribe to a supervisor, choose a global logger, or
change the startup command adapter. `configured_log_level` reads the resolved
`logging.debug` value: false selects Info and true selects Debug. The caller
constructs the renderer with that level and still owns `consume_lifecycle`.

`FlushPolicy::EachFrame` flushes after every successful `write_all` and does not
flush an empty stream. `FlushPolicy::OnClose` writes every frame and flushes once
when the sender closes, including when no frame arrived.
A frame counts as flushed only after the flush that covers it succeeds. A flush
failure leaves that frame in `written` and stops delivery, so later frames are not
attempted and a failed frame is not retried. `SinkOutcome` stores `std::io::ErrorKind`
only. Writer display text, paths, and frame bodies stay in the caller-owned writer.

The future must run on a Tokio runtime. Frame IO runs through one `spawn_blocking`
worker so a slow pipe does not occupy an async worker and cannot stall supervision:
the existing bounded queue still drops or closes without awaiting this writer.
Dropping the future detaches that worker. The worker still reads until the sender
closes and still performs a pending `OnClose` flush, but the dropped call returns
no report. `WorkerLost` means the worker panicked or was cancelled; its counters
are discarded rather than reported as a partial success.

No redaction is added here. Frames are written exactly as rendered. Public component
IDs and static codes remain the caller's responsibility, as in the renderer contract.
Production CLI startup still exits before runtime supervision. Real component health
and Kubernetes API availability are not established by these tests.

Run:

```sh
cargo test -p diorama --locked --test suite lifecycle_sink::
```

This is another bounded slice of issue #44, not its closure.
