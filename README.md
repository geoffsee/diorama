# diorama

diorama aims to be a single-node Kubernetes distribution
inspired by KubeSolo. It provides distribution configuration,
component supervision, host preparation, networking, addon management and operator
commands while preserving established configuration and data ownership contracts.

The selected architecture uses Rust to manage upstream Kubernetes components,
Kine and containerd through process and protocol boundaries. Kubernetes components
remain upstream executables; generated Rust API clients supply their interfaces.

[//]: # (See the [architecture decision]&#40;experiments/component-boundary/ADR.md&#41; for the)

[//]: # (responsibility split and its qualification limits.)

**Status: Under Development** 

The `diorama` executable currently parses and
validates configuration and supports help, version and effective configuration
printing. Normal invocation exits with `runtime startup is not implemented`.
The separate `dioramactl` executable provides management checks, version and help,
including explicit prerequisite preparation where supported. Component libraries
and fixtures are implemented in bounded slices; this repository does not yet
provide an end-to-end node startup or general installer.

## Getting started

For development, use Git and a Rust installation that honors
[rust-toolchain.toml](rust-toolchain.toml): nightly 2026-10-12 with Clippy, rustfmt, and the Cranelift codegen backend.
The workspace uses edition 2024 and a committed dependency lockfile.

```sh
git clone https://github.com/geoffsee/diorama.git
cd diorama
cargo build --locked -p diorama -p dioramactl
cargo run --locked -p diorama -- --help
cargo run --locked -p diorama -- --version
cargo run --locked -p dioramactl -- --help
```

To inspect effective node configuration without starting services:

```sh
cargo run --locked -p diorama -- --print-config
```

Configuration precedence is defaults, file, environment, then explicit flags.
Legacy `KUBESOLO_*` environment variables and the `kubesolo.io/v1alpha1`
configuration schema remain compatibility inputs. The default configuration file
is `/etc/diorama/config.yaml`; a missing file is allowed. Printed effective
configuration can contain credentials, so review it before sharing output.
See the [startup adapter](crates/diorama/README.md) and
[configuration layer](crates/diorama-config/README.md) for supported behavior.

Linux host and runtime qualification uses disposable containers or VMs. Docker
and additional pinned tools are required for some integration fixtures; consult
the relevant fixture README before running them. macOS development checks do not
establish Linux node compatibility.

## Contributing

Contributions to implementation, compatibility fixtures, documentation and
qualification evidence are welcome. Start with a
[project issue](https://github.com/geoffsee/diorama/issues) describing the
intended behavior and acceptance criteria, then submit a focused pull request.
Include the behavior changed, relevant issue links, validation and remaining gaps.

Read the [development tooling policy](docs/architecture/development-tooling.md) for
repository tooling, and [CI and repository rules](.github/README.md) for required
checks. Repository-owned executable tooling and tests use Rust. Reusable
maintenance logic belongs in `tools/dev`, outside the node runtime dependency
graph. Preserve existing compatibility fixtures and independent evidence.

Run focused package tests while developing. Workspace checks include:

```sh
cargo fmt-check
cargo lint
cargo test-ci
cargo test --locked --workspace --doc --all-features
cargo run --locked -p diorama-dev --bin diorama-language-policy
```

Bare Cargo build and test commands select `diorama`, the default workspace
member. Use `-p <package>` or `--workspace` deliberately. CI also tests release
builds and checks dependencies and security; live qualification has separate
fixture and environment requirements.

## Scope

### In scope

The implementation and qualification plan covers:

- Single-node Kubernetes, with NodeSetter admission in place of a scheduler.
- Configuration, PKI, lifecycle supervision and explicit host prerequisites.
- Managed containerd and attachment to host-managed containerd or CRI-O.
- Pod and Service networking, CoreDNS, local-path storage and optional addons.
- Management commands and preservation of existing configuration, credentials
  and persistent data through documented lifecycle operations.
- Pinned upstream inputs, generated clients, independent compatibility fixtures
  and reproducible runtime evidence.

The node release contract targets Linux amd64, arm64, ARMv7 hard-float and riscv64
with glibc and musl variants. Management CLI release targets are Linux and macOS
amd64 and arm64. These are qualification obligations, not a statement that all
artifacts are available or all platform cells have passed.

[//]: # (### Out of scope)

[//]: # ()
[//]: # (- Multi-node clustering, high availability and a Kubernetes scheduler.)

[//]: # (- GPU or WASM support in the baseline distribution.)

[//]: # (- Native Windows node or management binaries.)

[//]: # (- Reimplementing Kubernetes in Rust or claiming generated bindings provide its)

[//]: # (  runtime behavior.)

[//]: # (The [compatibility contract]&#40;docs/architecture/compatibility-contract.md&#41; defines)

[//]: # (the pinned KubeSolo baseline, retained behavior and deliberate deviations. The)

[//]: # ([acceptance matrix]&#40;docs/architecture/acceptance-matrix.md&#41; records the gates for)

[//]: # (implementation and qualification. Preserve these boundaries when proposing scope)

[//]: # (changes.)

## Communications

Use [GitHub issues](https://github.com/geoffsee/diorama/issues) for bugs,
questions and proposed work, and
[pull requests](https://github.com/geoffsee/diorama/pulls) for implementation
and review. This repository does not currently document a mailing list, chat
channel or public meeting schedule.

## Resources

> TODO

[//]: # (- [Roadmap and work items]&#40;https://github.com/geoffsee/diorama/issues&#41;)

[//]: # (- [Compatibility and acceptance matrix]&#40;docs/architecture/acceptance-matrix.md&#41;)

[//]: # (- [Selected component boundary]&#40;experiments/component-boundary/ADR.md&#41;)

[//]: # (- [Upstream provenance and generation contract]&#40;docs/architecture/upstream-inputs.md&#41;)

[//]: # (- [Upstream preparation and client generation]&#40;tools/upstream/README.md&#41;)

[//]: # (- [Live integration evidence]&#40;tools/integration/README.md&#41;)

[//]: # (- [Management CLI]&#40;crates/dioramactl/README.md&#41;)

[//]: # (- [CI, dependency and security checks]&#40;.github/README.md&#41;)

## License

`diorama` is licensed under the [ISC License](LICENSE). Third-party code retains
its own license terms; see, for example, the vendored
[saphyr-parser license](third_party/saphyr-parser/LICENSE).

## Conduct

Software is better built together. Ask questions. Be curious. Give specific, useful feedback;
receive it with openness. Respect others. Listen. Take ownership. Make room for repair.
Harassment and personal attacks have no place here.
