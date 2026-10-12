# Pure legacy input resolution

`INPUT_BINDINGS` retains the baseline registry order and every one of its 30
file/environment bindings and optional legacy flag names. Its contents are checked
against the independently captured Go configuration API schema.

`ExplicitFlags(BTreeMap<String, String>)` contains only values actually supplied on
the command line. Parser defaults must never be inserted. Duplicate-argument and
negated-boolean syntax are the executable adapter's responsibility. Unknown flag
names are ignored by the loader, as in Go; the argv parser must reject them.

`resolve_layers(file, environment, flags, mode, host)` applies the already decoded
file over defaults, then environment, then explicit flags. Each layer replaces a
whole setting, including lists/maps; an empty, false or zero value is supplied.
String setters preserve raw strings, booleans use Go ParseBool spellings, integers
use signed decimal parsing, lists trim and discard empty comma entries, and maps
trim key/value pairs with the last duplicate winning. Empty lists/maps become
null. The final empty API socket path derives from the final state path; final
semantic validation runs once, allowing a higher layer to repair a lower layer's
semantic error. Lower-layer syntax/type errors remain fatal.

`EnvironmentMode::Omit` deliberately ignores the supplied environment for future
installer callers. No API in this module reads process environment or filesystem.
`parse_environment` is independently callable and `resolve_parsed_layers` composes
its result; neither function models Kingpin's early parsing automatically. The
executable must preserve the distinction between native Boolean/integer argument
parsing and string-backed registry map/list setters, especially for help/version
short circuits. File warnings precede final validation warnings in the returned
`ResolutionWarning` sequence. Full/version/help diagnostics belong to the adapter.

`render_effective_yaml` emits the legacy effective document, including secret
values, with deterministic mapping order, source-defined omission rules, YAML 1.1
scalar quoting, block chomping and line wrapping. It performs no writes. The
printer is tested against actual Go stdout and the expected typed values come
from independent Ruby YAML conversion or direct Go `config.Read` JSON captures,
never from applying the Rust validator to the expected output.

E03.02 makes two explicit data-preservation deviations:

* Always emit `path`, including `path: ""`. Go's `omitempty` drops an explicitly
  empty path and reparsing silently restores `/var/lib/diorama`. The actual Go
  Read/print oracle captures the empty internal path and omitted printed key.
* Double-quote and escape every string containing physical NEL, LS or PS
  (`\N`, `\L`, `\P`). Go can lose escaped NEL through its JSON-to-YAML conversion;
  reproducing Unicode separator layout also risks losing adjacent spaces during
  reparsing. Conservative escaping preserves the exact typed values. Ordinary
  ASCII, Unicode text without these separators, and multiline LF formatting retain
  the baseline layout. Exact-byte comparisons explicitly exclude this documented
  Unicode formatting policy, while independent typed-value and roundtrip assertions
  always run.

The new six-case raw Go oracle covers empty path, empty SAN list and four Unicode
spacing cases; 57 earlier raw Go cases cover escaped and physical controls. The
renderer also tests all 216 three-character combinations of text, space, LF, NEL,
LS and PS. Escaped CR, CRLF, tab, NUL and BEL remain independent control cases.
Empty extra-SAN lists retain baseline omission and reparse as null: both mean no
extra SANs, but structural list presence is not retained by the legacy printer.

The [executable adapter](../diorama/README.md) now consumes these APIs and owns
argument parsing, version/help/full output, file selection, CPU/architecture/container
facts, and printing before service startup. Its separate 90-case Linux arm64 Go/Rust
comparison records artifact and source identity. Broader host discovery and actual
component execution remain future consumers. Shared [persistence](PERSISTENCE.md)
and [schema output](SCHEMA.md) are also implemented. No service startup, installed-node
lifecycle or platform release qualification is claimed here.
