Six direct pinned Go `config.Read` observations capture internal path, namespace
and extra SANs before YAML printing. Empty path is actually retained internally
but omitted by the baseline printer. The four Unicode cases preserve separate
expected typed strings so tests cannot confuse printer formatting with input data.

The capture receipt binds the additive harness, pinned source archive and builder,
and verifies deletion of owned Docker resources. Reproduce with
`cargo run --locked -p diorama-dev --bin diorama-fixture -- capture config-print-preservation --output /tmp/unique-print-preservation`
from the repository root. The environment is disposable,
network-disabled during execution, read-only, without host mounts or capabilities.
These data are configuration behavior evidence, not cluster lifecycle evidence.
