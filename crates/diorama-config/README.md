# Versioned distribution configuration

This crate implements the E03.01 desired-state model from KubeSolo
`2ef1c4787989f11f868f81bb84ae2afd4a49a81d`. The crate also provides pure
environment/flag precedence and effective YAML rendering (see [LAYERING.md](LAYERING.md)),
[atomic persistence](PERSISTENCE.md), and [model-derived schema output](SCHEMA.md).
It does not start components or discover host facts.

`Config::default()` and the typed nested structs cover all 35 registry settings;
`FIELDS` is the field/type/consumer-epic inventory. E03 owns the shared model and
schema metadata (`apiVersion`, `kind`); each field names the component owner that
consumes it. Explicit `Option<bool>` distinguishes detected container mode from
false. Optional lists/maps distinguish null from empty collections. `DecodedConfig`
additionally records omitted, null and value presence at each supplied container
and field path, including explicit false, zero and empty strings.

`decode` decodes the first YAML document over defaults. `decode_bytes` accepts
UTF-8 and BOM-marked UTF-16. `read_file` returns `None` for a missing file without
adding a missing-schema warning. Errors carry a category and field path; callers
must propagate them before component startup. Unsupported schema versions are
checked before known field types, as in the reference. Missing versions, wrong
kinds and unknown/duplicate keys return structured warnings. Diagnostic wording is
Rust-owned; warning/error categories and effective values are the compatibility
contract, not byte-identical Go decoder internals.

The event-based parser preserves duplicates, scalar style, tags and aliases before
resolution. The resolver retains the reference's YAML 1.1 booleans, octal/hex,
string coercion, null semantics, case-insensitive field names, last duplicate value,
and first-document behavior. Go's merge-key ordering is explicitly characterized:
a merge appearing after an explicit key overwrites it, and earlier mappings in a
merge sequence win. Unknown keys are ignored with warnings. Quoted/tagged strings
remain strings; quoted `<<` is not a merge. Alias expansion is checked before
cloning, including the expanded depth of chains.

`Config::validate(&HostContext)` validates the final desired-state combination and
returns `ValidatedConfig`. The caller supplies architecture, CPU count and detected
container mode. This stage normalizes image references and CPU options, checks CRI
socket syntax and CPU reservations, disables D2K on baseline-unsupported targets,
and reports IPv6 MTU warnings. It must run after the #40 input layers, not after
each intermediate layer. `derive_socket_path` similarly belongs after precedence.
`ValidatedConfig::into_runtime(RuntimeProbe)` converts supplied discovery facts,
normalizes node names and builds typed owned-state paths. `RuntimeSettings.desired`
retains all typed settings for future consumers; no executable arguments or
production component startup are claimed here.

Dependency selection: `saphyr-parser =0.0.11` is the maintained pure-Rust event
parser, with no hashlink loader dependency. The packaged 0.1.0 changelog shows that
0.0.12 only raised thiserror and 0.1.0 changed empty-node events from `~` to empty
strings; this resolver handles both. 0.0.11 contains the preceding directive,
multiline, CR, malformed-closing-bracket and fuzz/panic fixes. Pinning this release
allows root's thiserror/impl 2.0.18 (syn2) lock alongside existing generators.
Serde 1.0.228 likewise avoids a syn3 duplicate. serde_json 1.0.151 and existing
regex 1.13.1 complete the graph; cargo-deny remains authoritative. See
[saphyr sources](https://github.com/saphyr-rs/saphyr) and the immutable crate archives
linked by Cargo.lock. A pinned local scanner compatibility patch restores YAML 1.1
physical NEL/LS/PS line breaks through the iterator/BufferedInput entry point; see
[the patch rationale](../../third_party/saphyr-parser/diorama-COMPATIBILITY.md).
It adds no dependency or ban exception; original decode/alias limits remain.

Three explicit policy decisions differ from the baseline:

* `DecodeLimits::default()` imposes 1 MiB input, 128 expanded nesting levels and
  100,000 cumulative allocated nodes and 4 MiB cumulative scalar/tag bytes.
  Initial nodes, anchor storage and alias clones are charged before cloning;
  file reads stop at the input budget plus one byte. These are protective library
  defaults, **not measured Go limits**. `decode_with_limits` exposes caller-selected budgets and returns a
  separate `Limit` error; file/CLI integration must retain or explicitly adjust them.
* CPU reservation comparison uses exact decimal/binary magnitude. Go accepts
  `systemReserved.cpu: 1e1000` through an overflowing `Quantity.MilliValue` count;
  Rust rejects the overreservation. The raw Go observation and regression retain
  this explicit safety deviation instead of reproducing integer overflow.

* Runtime conversion trims and lowercases the selected configured/discovered node
  name and rejects an empty result. The baseline lowercases OS discovery upstream
  of conversion and does not reject an empty successful hostname. The Rust probe
  boundary requires usable discovery facts instead of returning an empty node name.

Debug formatting redacts the Portainer edge key, including nested configuration
and runtime settings. Explicit serialization and requested effective configuration
output retain the value; callers must not use those as diagnostic log payloads.

Tests consume durable Go artifact captures (all-field and failure configuration
fixtures plus fresh scalar/alias/merge probes), check every field independently,
and exercise host-dependent negative validation and runtime conversion. Fixture
provenance pins the Go artifact/revision, source hashes and disposable runner receipts.
Successful Go stdout is independently converted to frozen typed JSON by
`tests/fixtures/extract_expected.rb` (system Ruby Psych 3.1.0). Tests deserialize
that JSON without running the Rust YAML decoder or validator on expected values;
only the five source-declared omitted zero fields are restored. Filesystem
reads in tests use owned temporary files or deliberately absent paths; all Go execution
occurred in the established network-isolated disposable container runner.

Run `cargo test -p diorama-config --locked`, `cargo fmt --package diorama-config`, and
`cargo clippy -p diorama-config --all-targets --locked -- -D warnings`.

Precedence and effective YAML rendering are implemented in this crate; the
[startup command adapter](../diorama/README.md) consumes them for version/help,
configuration selection and printing before the runtime boundary. Shared persistence
and schema output are implemented; their API/CLI editing consumers remain separate work.
Remaining integration includes #7 credentials, component consumers and full
platform/runtime qualification. The Rust serde representation remains a
typed interchange model; the shared YAML renderer owns legacy omission/formatting
rules and their documented preservation policies. No cluster lifecycle, ARM32
integer-boundary release qualification, or distribution parity completion is implied.
E02 and parent E03 integration completion remain separate gates.

## Independent process roles

`kubernetes.role` is `control-plane` (default) or `worker`.
`kubernetes.tokenFile` supplies the encoded bootstrap kubeconfig for an ordinary
worker; `kubernetes.disableLocalKubelet` disables only the control plane's ordinary
kubelet. Workers require a token-file path and cannot disable their kubelet.
`network.podAddressPool` defaults to `10.42.0.0/16`; Cilium cluster-pool IPAM uses
aligned IPv4 pools with prefixes 8 through 24 and per-node /24 allocations.
These immutable fields extend the retained baseline with no node roster.
`--role`, `--token-file`, `--disable-local-kubelet`, and `--pod-address-pool`
(and their `KUBESOLO_*` forms) follow existing precedence. The discovered hostname
is the only fallback for node identity; an empty identity fails validation.
