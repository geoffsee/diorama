# Integer scalar capture

These 17 observations execute KubeSolo `config.Read` at revision
`2ef1c4787989f11f868f81bb84ae2afd4a49a81d` in disposable Linux arm64 containers.
The two directories preserve the exact capture sources, build/run logs, cleanup
receipts, source hashes and raw results. Those receipts identify the historical
capture drivers. Current reproduction uses the Rust maintenance binary from the
repository root:

```sh
cargo run --locked -p diorama-dev --bin diorama-fixture -- capture config-scalar-base --output /tmp/unique-scalar-base
cargo run --locked -p diorama-dev --bin diorama-fixture -- capture config-scalar-extra --output /tmp/unique-scalar-extra
```

The Dockerfiles pin the source archive and Go toolchain. New receipts bind the
Rust driver and owned command settlement; historical evidence remains unchanged.

Each scalar is read into a string field, an integer field, and an explicitly tagged
integer field. Rust compares returned values and success/failure; temporary error
paths are intentionally not compared. The malformed double-minus i128 minimum
magnitude remains a string and fails integer conversion without a Rust panic.
Uppercase radix prefixes and go-yaml's peculiar unsigned lowercase binary prefix
followed by a sign are retained as observed behavior.
