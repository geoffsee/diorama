# Startup command adapter

`cargo run -p diorama -- --version`, `--help`, and `--print-config` execute the
startup-only adapter. A normal invocation resolves and validates configuration,
then launches the supervised node runtime, emitting structured JSONL lifecycle
diagnostics and executing dependency-aware component supervision.

The adapter preserves the captured KubeSolo ordering: command grammar and
primitive flag parsing, version/help exit, deprecated `--full` warning, optional
configuration file, file/environment/explicit-flag resolution, validation,
warnings, and effective YAML printing. `-v` is the legacy version alias; `-h`
is an error. Boolean flags use `--name`/`--no-name`, not `--name=false`. Repeating
a canonical flag, including a positive/negative pair, is an error. Missing
configuration files are allowed, including an explicitly selected missing file.
The printed document includes effective values and can contain credentials;
`StartupAction` debug output deliberately omits the resolved configuration.

`execute` accepts an argument vector, environment snapshot, version string,
`StartupInputs`, and output writers. It returns `Exit` or a validated `Start`
action. This boundary lets tests prove that version/help do not read files or
probe the host, and that printing returns before the runtime startup boundary.
Writer failures propagate to the executable, which exits nonzero. The process
adapter only reads the selected file and host properties.

The process uses Go architecture names (`arm64`/`amd64`) and the baseline container
indicators (`/.dockerenv`, `/run/.containerenv`, or nonempty `container`). On Linux
it counts the affinity list from `/proc/self/status`, preserving Go's CPU-count
behavior when a cgroup quota is smaller than the allowed CPU set. If that list is
unavailable or malformed, and on other platforms, it uses Rust's
`available_parallelism`; that fallback has not been established as equivalent to
Go on every host. Arguments and configuration environment values must be UTF-8.
The actual Linux qualification is arm64; other operating systems and architectures
have not received this blackbox comparison.

Compatibility evidence is the pinned Go startup suite at
`tools/parity/fixtures/cli-startup` (the copied immutable suite is
`tests/fixtures/startup.json`) and the 51-case configuration command suite at
`tools/parity/fixtures/config-command.json`. Tests replay their independent exit,
stream, and semantic expectations. This establishes those observable cases, not
byte-identical diagnostics or every hidden Kingpin completion/help command.
Diagnostics preserve their expected classification and useful legacy wording,
while using the Rust configuration decoder's details. Structured log object key
order and timestamps are not a compatibility assertion. The approved effective
YAML renderer preserves escaped NEL data where the baseline's JSON-to-YAML path
loses it; see the configuration layer's compatibility notes.

Run focused checks with:

```sh
cargo test -p diorama --locked
cargo clippy -p diorama --all-targets --all-features --locked -- -D warnings
```

Live CRI connection, host installation, and multi-node cluster lifecycle
remain separate implementation and qualification work.

`tests/evidence/linux-arm64.json` records a fresh disposable comparison against
committed main revision `cd673944bed3c5ab85b35b550edc3f9511f5ea02`.
Go and Rust each passed all 39 startup and 51 configuration cases, and all 90
corresponding stdout files were byte-identical. Stderr satisfies independent fixture
predicates; full diagnostic byte equivalence is not asserted. The Linux arm64 Rust
release binary was built with the digest-pinned Rust 1.97.1 image and locked Cargo
inputs. Every copied repository build input was verified byte-for-byte against
that commit, including the final duplicate-warning and parser entry-point fixes;
`uncommitted_implementation` is therefore false.

The compressed public archive contains raw streams, runner/process cleanup receipts,
exact suite and artifact descriptors, build/package commands and scripts, source
hash inventory, and the exact runner/helper sources. All owned build and test
containers, images, and evidence volumes were independently checked absent after
the runs. The receipt identifies the tested commit even when this documentation and
archive are committed later; subsequent documentation changes are not new production
code qualification. Local source archives and binaries remain outside the repository.
No binary or private keys are committed. Reproduce with a release Linux arm64
binary described by the checksum-bound artifact schema, then run:

```sh
cargo run --locked -p diorama-dev --bin diorama-parity -- run --artifact /path/to/artifact.json \
  --suite crates/diorama/tests/fixtures/startup.json --output /tmp/startup-run
cargo run --locked -p diorama-dev --bin diorama-parity -- run --artifact /path/to/artifact.json \
  --suite tools/parity/fixtures/config-command.json --output /tmp/config-run
```

Run those commands separately for the pinned Go and new Rust artifacts, using
fresh output directories. The suite arguments contain only print/version/help
and deliberate failure paths; do not substitute a normal Go startup invocation
on the host.

## Optional metrics HTTP lifecycle

Datastore size measures the managed snapshot and WAL files. Component health
series are not registered until they are connected to supervisor lifecycle state;
the endpoint does not publish static zero values as current component health.

Runtime endpoint tests retry at most three fresh ports only after the supervisor
reports `metrics_bind_failed` and the failed runtime is joined. Existing in-process
fixtures record forced cleanup for local-path, DNS, API-server and datastore services,
and deadline abortion for local-path and DNS. Retry checks retain those diagnostics
and reject other failures, including metrics cleanup failures. These fixtures do
not qualify live-cluster shutdown behavior.

The runtime's metrics adapter binds only when `metrics.enabled` is true, at
`127.0.0.1:9105` by default. Bind failures use optional-component degradation.
The listener and accepted connections belong to the adapter: stop closes the
listener, drains active responses for at most five seconds, then cancels and
joins remaining connections. Dropping the adapter/server also cancels its owned
connection tasks. At most 64 connection tasks run concurrently; excess clients
wait in the socket backlog until a slot becomes available.

Request headers have a total five-second deadline, including trickling headers.
Read inactivity is bounded to 30 seconds and response writes to ten seconds
through the flush. These GET endpoints do not consume request bodies; incomplete
unread bodies close their connections rather than being drained indefinitely.

`/metrics` supports Prometheus text `version=0.0.4` and OpenMetrics
`version=1.0.0`. Without `Accept`, it uses Prometheus text. Negotiation considers
all `Accept` fields, supported media parameters, specificity and quality values;
an explicit `q=0` exclusion overrides a less specific wildcard. A request with
no acceptable supported format receives HTTP 406. The listener serves plain HTTP;
certificate expiry series describe certificate files and do not establish TLS
protection or live Linux cluster qualification.
