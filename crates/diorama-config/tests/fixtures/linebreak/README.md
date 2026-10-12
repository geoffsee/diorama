These 57 observations execute the pinned baseline's actual `config.Read` and
capture `Config.D2K.Namespace` directly through JSON, before calling its YAML
printer. This distinction matters: escaped NEL survives decoding but the baseline
printer loses it in its JSON-to-YAML conversion. Reparsing printed YAML alone
would give a false decoder oracle.

The suite covers literal and escaped NEL/LS/PS in plain, quoted and block values,
between fields, explicit and extra block indentation, strip/clip/keep chomping,
CR/CRLF mixtures, Unicode prefixes, escaped marker characters and double-quoted
backslash continuations. Escaped CR, CRLF, tab, NUL and BEL provide control cases.
`capture-receipt.json` pins the source archive, builder and exact additive harness
files, and records verified empty owned Docker inventories. The vendored source
was unchanged; harnesses were added only to the disposable fetched source copy.

Reproduce from the repository root with
`cargo run --locked -p diorama-dev --bin diorama-fixture -- capture config-linebreak --output /tmp/unique-linebreak`.
It requires Docker and network access while building, then executes
without network, host mounts or capabilities, on a read-only filesystem with a
bounded temporary filesystem. This tests configuration parsing, not service startup.
