# Synthetic fixture evidence

This module exercises in-process API, admission and controller behavior with disposable
directories. It does not launch the selected retained kube-apiserver, Kine, kubelet,
containerd or network components, and does not qualify C13/E28 or execute upstream
Kubernetes conformance tests. Storage markers are written/read by the host fixture;
DNS uses the synthetic transport. Pod egress is explicitly unexecuted.

`rubix-conformance fixture --output <fresh-directory>` writes `fixture-report.json`
and `fixture-report.md`. `verify-fixture <report>` checks exact unique fixture domains,
counts and the planned selection/exclusion inventory. It checks consistency of supplied
evidence, not its authenticity or production execution provenance.

`rubix-conformance run` and `verify <report>` fail closed because a qualification
runner for the selected retained executables is not implemented. The planned 24
conformance candidates have zero executed results in every generated fixture report.
The summary validator separately rejects missing, duplicate, mismatched or failed
individual results; passing that consistency check alone is not node qualification.

`check-kubeconfig <path>` checks JSON/YAML round trips, including escaped scalar values
and preferences. It does not test credential authentication to a production node.
