# Management checks and explicit prerequisites

Offline archives use `diorama-<version>-linux-<arch>[-musl]-offline.tar.gz`.
`bundle::build_offline_bundle` builds these archives from local files and writes
the checksummed `bundle.manifest` consumed by `install --offline-install`.
Host installation verifies and extracts the bundle into `--path`; it does not
yet register or start a system service. For example, on a matching Linux host:

```sh
./dioramactl install --offline-install=./diorama-v0.1.0-linux-arm64-offline.tar.gz --path=./node
```

Download selection uses `geoffsee/diorama` releases and defaults to the management
CLI's package version. The requested archive must be published there, or supplied
through `--custom-url`. Local offline installation makes no download request.

The [release workflow](../../.github/workflows/release.yml) publishes glibc offline
bundles for Linux amd64 and arm64 alongside the standalone binaries. Each bundle
contains `bin/diorama`, `bin/dioramactl`, the runtime executables, all seven image
archives, `asset-inventory.json`, `release-inputs.json`, and `bundle.manifest`.
Runtime files are ready to execute after host extraction; the inventory also
includes the encoded payloads required by asset validation. Checksums for the
complete archives are included in the release's `SHA256SUMS`.

Inputs are pinned in [release-inputs.json](../diorama-dev/release-inputs.json):
upstream binary downloads use SHA-256 checksums, and workload images use platform
manifest digests. Update those pins when changing catalog versions. The release
tool verifies executable architecture, image platform, tags and layer digests before
producing an archive. CI then runs host extraction in a network namespace with no
egress and loads the node image. The image carries workload archives outside the
data volume and copies them into the configured state directory at startup.
Musl, ARMv7 and RISC-V bundles are not produced by the current release matrix.

For a local reproduction on a build host with Rust, curl and tar:

```sh
CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm cargo run --locked -p diorama-dev --bin diorama-release-bundle -- prepare arm64 /tmp/release-assets
# Build/export the node image as shown in the release workflow, then:
CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm cargo run --locked -p diorama-dev --bin diorama-release-bundle -- package v0.1.0 arm64 \
  target/aarch64-unknown-linux-gnu/dist /tmp/release-assets dist
```

Container-mode installation dispatches through the Docker CLI and the existing owned
network/volume/container request boundary. A Linux Engine is required on Linux,
macOS or WSL2; its architecture is queried instead of inferred from the management host.
This implements image import and container creation, not live node readiness qualification.

An offline container bundle must include a hash-listed `asset-inventory.json` with
the complete supervised offline asset inventory, and the declared `image-diorama`
gzip payload at its inventory path. Private archive staging, link/traversal rejection
and bundle hash checks run before import. The decoder then verifies the exact image
bytes, config platform and layer DiffIDs before passing those same bytes to Docker.
No pull fallback is allowed after import; container creation uses `--pull=never`.
Exactly one archive tag is required before import; additional tags that Docker would
restore are rejected. A missing imported tag or import failure stops before owned
resource creation. Docker image load/pull commands have ten-minute execution deadlines;
other commands have one-minute deadlines plus a one-second child cleanup budget. An
owner thread kills and reaps the CLI child; delayed kernel cleanup returns an explicit
unconfirmed error to the caller while the owner retains the child and capture files.
Separate private stdout/stderr capture is monitored every ten milliseconds and requests
termination above eight MiB per stream, with bounded final reads. Files can overshoot
that threshold between polls; this is not a strict filesystem quota. This owns the CLI
child, not arbitrary descendants or remote Engine operations: killing the client does
not prove an already-accepted daemon mutation was cancelled.

An explicit `--image` override retains registry-pull behavior and takes precedence
over the offline bundle. Default online selection uses
`ghcr.io/geoffsee/diorama:<version>`. Offline selection uses the verified archive's
tag. Neither path requires a kubesolo executable or image.
Tests use synthetic image archives and Engine fixtures; live Docker, retained-node
startup and egress-denied workload qualification remain unexecuted.

`dioramactl` is a separate management executable with checks and explicit lifecycle
commands. The existing `diorama` startup parser, startup YAML and its
90-case qualification remain separate. Container creation does not establish a running
Kubernetes node. Explicit
opt-in can install missing Alpine networking packages and enable its cgroups
service; ordinary checks never prepare a host or stop conflicting processes.

The name is an explicit diorama management CLI choice replacing `kubesoloctl` for
this executable. Help/version text is branded accordingly. KubeSolo environment
keys, on-disk paths, service/runtime/CNI identities and configuration schemas do not
change. No compatibility alias or release packaging is implied; installers and
existing scripts must choose the correct executable when packaging is introduced.
The crate remains private workspace code and adds no registry dependency.

## Interface and effects

The command shell also supports completion and artifact download, with a
`CommandHandler` seam for the remaining management commands. Download archive
selection covers all 16 Linux architecture/libc/online/offline cells. Because the
current bundle stages the running `dioramactl`, download execution requires a Linux
executable matching the selected architecture and libc ABI. macOS and cross-architecture
invocations fail before downloading or copying files; run the command with a
matching Linux `dioramactl`. Selecting a node archive alone does not verify the
included management executable, and this restriction remains until matching
management release artifacts can be fetched and verified.

`parse_command` accepts argument strings and an explicit environment map.
`execute` injects `CheckInputs` and output writers; `execute_check` consumes parsed
options. Help, version, parse errors and unsupported preparation require no host
observations. Errors use static categories rather than echoing arbitrary arguments,
file contents, environment values, hostnames or raw OS errors. Output failures
propagate to a nonzero process exit.

`check` accepts `--pprof-server` and `--install-prereqs`. Environment defaults are
`KUBESOLO_PPROF_SERVER` and `KUBESOLO_INSTALL_PREREQS`; exact lowercase `true`, `1`
and `yes` enable them, `false`, `0`, `no` and other values default false. Explicit
flags override environment. Boolean `=value` uses Go ParseBool spellings; separate
boolean-looking words remain positional arguments and are ignored, as by Cobra.
Repeated flags use the final value. `--` ends flag parsing. There is no YAML or
startup-flag processing here.

Explicit `--install-prereqs` (or its existing environment opt-in) authorizes only
missing Alpine networking packages and the Alpine cgroups service. The executable
installs invocation-wide signal handling before observations or actions. See
[PREPARATION.md](PREPARATION.md) for fixed commands, reobservation, partial effects
and incomplete-cleanup exit status. The synchronous library `execute` boundary
remains read-only and rejects this opt-in; the executable uses the async workflow.

The host check uses Linux discovery and supplemental filesystem observations.
It evaluates earlier checks before briefly binding wildcard ports; any earlier
blocker/unknown/preparation requirement prevents all port probing. The port phase
checks 2379, 6443, 10443 and optionally 6060, releases its own listeners, and
reevaluates the report. The command explicitly selects managed baseline context; supplemental input
contains only filesystem observations, never execution controls or port evidence. It has no authority to kill another listener. Passing observations do not
reserve ports or establish runtime readiness.

Non-Linux host checking is explicitly unsupported. Unlike baseline macOS
`kubesoloctl check`, this slice does not contact a container engine; that consumer
remains separate. Help and version remain usable without Linux host support.

## Compatibility evidence

The read-only baseline `2ef1c4787989f11f868f81bb84ae2afd4a49a81d` supplies
`internal/cli/{root.go,cmd_check.go,cmd_version.go,helpers.go}`, CLI config and UI.
The actual Cobra 1.10.2/pflag 1.0.10 source oracle under
`tools/parity/fixtures/management-check` captures 56 parsing/output cases twice.
It injects a harmless check effect marker and inert sibling registrations rather
than running an installer or claiming full management-command support. Rust consumes
independently specified expected parser outcomes, not its own rendered output.

Observed precedence includes `--help check` producing root help while
`--help=true check` produces check help; malformed flags still fail when help is
present. Extra check/version arguments are ignored. Unknown help topics retain
Cobra's exit 0 but use a static safe diagnostic. `version` is a management subcommand;
`check --version` is an error. Startup Kingpin behavior is not reused here.

Intentional changes are bounded argv acceptance (256 arguments/64KiB), UTF-8 command
input, rebranded/smaller help, static safe diagnostics, propagated output failures,
explicit unsupported container-engine checks, and a qualified success
message. The baseline's universal "Host is ready" message would overstate these
observations. ANSI styling, byte-identical management UI and unimplemented sibling
commands are not claimed. E05 integration and E23 installation remain open.

```sh
cargo test -p dioramactl --locked
cargo clippy -p dioramactl --all-targets --locked -- -D warnings
```

Real host-check executable qualification runs only in disposable Linux containers;
ordinary tests use injected effects or invoke only help/version.

Legacy service migration stages a private, exclusive backup and replacement
before publishing configuration. A matching `.migration-pending` marker allows
retry after interruption between config and service publication. Conflicting
backups, markers and existing configs are preserved. This is file-level evidence;
live init-system restart qualification remains outstanding.
Service definitions and lifecycle plans cover the six Linux init backends.
Daemon and foreground definitions describe paths only; lifecycle operations in
those two modes return explicit unsupported-action errors pending a process
executor. These plans do not establish live init-system or reboot qualification.
Container port mappings without a host IP (`8080:80` or `80`) default to
`127.0.0.1`. Explicit host addresses are preserved. User mappings may
not add a binding for the built-in API server or enabled D2K port. Reinstalling
recreates only the selected container, retaining its volume and reconciling its
instance bridge MTU; a bridge still in use causes an explicit Engine error.

Upgrade stages the artifact before stopping the selected deployment, then copies
the quiesced `pki` and `kine/db` directories into a unique private backup. After
failed replacement, migration, start or commit, the upgrade attempts to restore
deployment artifacts, the configuration's previous presence and contents, and
captured PKI/datastore state. If rollback fails, it returns an error and retains
the receipt and backup for manual recovery.
Systemd unit changes are reloaded before start. Container upgrades persist their
new version record and check that the replacement is running before discarding
the previous container; this check does not establish Kubernetes readiness.

An exclusive file lock serializes upgrades and cleanup for a data path. Before replacement,
`.upgrade-pending` records the source version, target and backup directory. Before
commit removes the previous container, a durable `.upgrade-committing` receipt
protects recovery while pending-receipt cleanup is checked. Interruption retains
an active receipt and backup; subsequent upgrades refuse mutation until recovery.
After commit, `.upgrade-completed` marks receipt cleanup as safe to retry on the
next invocation. Post-commit cleanup or output failures do not report a failed
transaction or attempt rollback against a discarded old container. A cleanup
warning requires inspecting the retained receipt, not undoing the commit. These
file and fake-runner checks do not qualify live Linux, Docker, datastore recovery
or all supported init systems.

Reset deletes the established `kine/db` cluster datastore, kubelet state and
disposable managed runtime root/state. It retains runtime executables, image
archives, registry configuration, PKI and `local-path-storage` volume data.
Ordinary uninstall retains installation data; `--purge` explicitly removes the
selected instance's owned state, including upgrade receipts and recovery backups.
Uninstall removes the selected configuration unless
`--keep-config` is set, including when combined with `--purge`. Host commands select
`/etc/diorama`; container commands select only an explicit configuration bind
recorded in `container.spec`, preserving unrelated host configuration. Named volumes
and ambiguous configuration bindings require explicit operator cleanup and fail
before lifecycle effects. Directory binds select `config.yaml` and `config.yaml.bak`;
file binds select only their exact source file, including custom source names,
and never claim an adjacent backup. Other files in the configuration directory are retained.
Library cleanup without an explicit configuration directory performs no configuration I/O.
Reset and ordinary uninstall retain those recovery records. The upgrade lock
file remains in place so concurrent operations cannot acquire a different inode.
An active pending or committing upgrade receipt blocks reset and ordinary
uninstall; explicit purge discards the selected instance's recovery state.
Cleanup unmounts only mount points under paths
selected for removal, preserving the data-root mount and retained or neighboring
mounts. Symlinked parent directories are rejected before service operations;
selected symlink entries themselves are unlinked without following them.

Host cleanup uses the detected systemd, OpenRC, SysV, Upstart, runit or s6 lifecycle
plan. Uninstall unregisters startup before deleting state or service artifacts;
systemd and Upstart caches are also refreshed after definition removal. s6 stop
waits up to 30 seconds for the service and finish script to exit before state
deletion. Unsupported init detection and lifecycle command errors abort cleanup.

Container stop or removal failures abort before data deletion. An already absent
container is tolerated for uninstall only after the Engine confirms its absence;
reset of a missing container fails without deleting state. Cleanup regressions
use temporary directories and injected host/Engine effects. Live Linux mount,
service and Docker qualification remains outstanding.

When running under sudo, preserve the allowlisted Edge settings explicitly:

```sh
sudo --preserve-env=KUBESOLO_PORTAINER_EDGE_ID,KUBESOLO_PORTAINER_EDGE_KEY,KUBESOLO_PORTAINER_EDGE_ASYNC,KUBESOLO_PORTAINER_EDGE_IMAGE dioramactl <command>
```

The sudo policy must permit preserving those variables. If it does not, an
administrator can add these exact names to `env_keep` in sudoers. Parent-process
`/proc` environment reads are not a supported source: sudo parents can be
non-dumpable, and Linux can deny access even to a privileged child. Existing
values passed to the command remain authoritative; never include key values in
command arguments or diagnostics.

Downloads permit an explicitly selected HTTP custom URL for compatibility with
local mirrors; operators choosing it trust that network and mirror. Redirects
must use HTTPS, so a secure download cannot silently downgrade to HTTP. TLS
protects transport to the chosen endpoint, but this download slice does not
verify release signatures or independently trusted artifact digests. A staged
bundle is not authenticated release qualification and must not be treated as
such by a future installer.

`dioramactl d2k fetch|install --name <instance>` exports the Docker client credential files
`ca.pem`, `cert.pem` and `key.pem`. The default output is
`~/.docker/d2k/<instance>` for the invoking user; `--output` selects a certificate
**directory**. All exported files are private (0600) in a private directory (0700).
Symlinked directory components are rejected and leaf symlinks are atomically
replaced without modifying their targets. Existing directories must belong to
that user. For privileged export to a different user's identity, precreate the
output directory as that user; missing directories fail closed instead of
chowning entries in a directory that the user can rename concurrently.
Container exports use the managed `kubesolo[-<instance>]` identity and
require a valid, unambiguous loopback-reachable published port. Docker context
configuration runs with the invoking user's identity and Docker configuration,
not root's configuration under sudo. Exported credentials may remain after a
Docker context error, but the command reports failure and never claims the
context was configured. These unit-tested adapters do not qualify live D2K nodes.
