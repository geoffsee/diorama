# Offline installation and management

Use a matching release of `dioramactl` for the new version-two bundle format.
The new CLI also accepts legacy combined `*-offline.tar.gz` archives. Older CLIs
cannot select or validate the new formats. Releases publish Linux amd64 and arm64:

| Archive suffix | Contents | Install mode |
| --- | --- | --- |
| `-host-offline.tar.gz` | Both CLIs, runtime executables, CNI, CoreDNS, pause, local-path provisioner and BusyBox | service (extraction) |
| `-container-offline.tar.gz` | One core node image with those runtime assets inside it | container |
| `-addon-portainer-agent-offline.tar.gz` | One Portainer installer/workload image and installation Job | `addon load` |
| `-addon-d2k-offline.tar.gz` | One D2K installer/workload image and installation Job | `addon load` |

Full names are `diorama-<version>-linux-<arch><suffix>`. Portainer and D2K are
disabled by default and absent from core bundles. Enabling their legacy bootstrap
options without an offline image fails with instructions to install an add-on.
New release downloads always select an offline core bundle; `--offline` remains
a compatibility flag. `download --run-mode=container` selects the container pack.

```sh
# Host extraction on a matching Linux machine:
dioramactl install --offline-install=./diorama-v0.1.0-linux-arm64-host-offline.tar.gz --path=./node
# Container installation (a Linux Docker Engine is required):
dioramactl install --run-mode=container --offline-install=./diorama-v0.1.0-linux-arm64-container-offline.tar.gz
```

Host installation verifies and extracts files into `--path`; it does not yet
register or start a system service. Container installation imports the verified
image and creates the node using `--pull=never`. It queries the Engine's architecture,
which may differ from the management host. `--image` cannot override an offline pack.
A fresh container data volume receives its core images and runtime tools from the image.

Validation checks bundle kind, version, architecture, declared capabilities,
checksums, executable architecture, image tags, platform and layer digests before
installation state changes. Duplicate assets, duplicate archive paths, links and
path traversal are rejected. Schema-one combined archives retain their existing
validation path. `bundle.manifest` and `asset-inventory.json` provide integrity;
obtain the archive and published `SHA256SUMS` from a trusted release source.

Core upgrades use the archive matching the existing installation mode:

```sh
dioramactl upgrade --version=v0.2.0 --offline-install=./diorama-v0.2.0-linux-arm64-host-offline.tar.gz
```

Host upgrades replace runtime assets as well as the node executable, with rollback
copies. Container upgrades import the local image before replacement. Both retain
the datastore and existing add-on resources. Upgrade add-ons separately with a new
pack and a new installation Job. Existing legacy configuration-driven installations
remain supported; remove their resources explicitly and disable legacy bootstrap
before switching them to Job ownership. The installer refuses to adopt unowned
resources, and core Portainer bootstrap skips Job-managed Deployments.

## Installing add-ons

Load the pack on the node that will run both the installer and workload. This
validates the pack and imports its single image into containerd's `k8s.io` namespace.
It retains verified images under `<node-data>/images/addons` for restart and core
upgrade recovery, since the managed runtime rebuilds its disposable cache. It
does not enable an integration or contact a registry. Retained old versions can
be removed explicitly after their Jobs and workloads no longer reference them.

```sh
# A host installation, using its runtime socket and bundled ctr:
sudo dioramactl addon load ./diorama-v0.1.0-linux-arm64-addon-d2k-offline.tar.gz --path=/var/lib/diorama
# A named container; --engine=podman is also supported:
dioramactl addon load ./diorama-v0.1.0-linux-arm64-addon-portainer-agent-offline.tar.gz --container=kubesolo
```

Use the published `*-job.json`, or extract `install-job.json` from the add-on
archive. Replace `replace-with-loaded-node` with the actual Kubernetes node name
from `kubectl get nodes`. The Job and Deployment use that node, the same explicit
versioned image, and `imagePullPolicy: Never`. A missing image cannot cause a pull.

Create credentials separately before applying the Job. For Portainer, obtain the
Edge ID and key from your Portainer server and store them in private files:

```sh
kubectl create namespace portainer
kubectl -n portainer create secret generic portainer-agent-edge-key \
  --from-file=edge.id=./edge.id --from-file=edge.key=./edge.key
kubectl apply -f portainer-job.json
kubectl -n portainer wait --for=condition=complete job/diorama-install-portainer-agent --timeout=360s
```

Portainer readiness requires connectivity to that configured server; registry
access is unnecessary. Its `portainer-agent-edge` ConfigMap controls `EDGE_ASYNC`
and `EDGE_INSECURE_POLL`. The installer preserves this configuration on reruns.

D2K defaults to namespace `d2k`. To choose another namespace, replace the namespace
name and the Job's `DIORAMA_ADDON_NAMESPACE` value in its manifest, including the
installer RoleBinding subject. Create its TLS Secret there using the node's existing
CA and D2K server certificates (or equivalent certificates signed by that CA):

```sh
kubectl create namespace d2k
kubectl -n d2k create secret generic d2k-tls \
  --from-file=ca.crt=/var/lib/diorama/pki/ca.crt \
  --from-file=tls.crt=/var/lib/diorama/pki/d2k-server.crt \
  --from-file=tls.key=/var/lib/diorama/pki/d2k-server.key
kubectl apply -f d2k-job.json
kubectl -n d2k wait --for=condition=complete job/diorama-install-d2k --timeout=360s
```

D2K exposes TLS on port 2376 through a LoadBalancer Service. Keep the existing
load-balancer and client-certificate conventions; container hosts that need a
published D2K port must configure it explicitly. `dioramactl d2k fetch` exports
existing client credentials but does not enable the add-on.

The Jobs install RBAC, service accounts, Services, Deployments and configuration
through the Kubernetes API, then wait up to 300 seconds for readiness. Inspect
`kubectl -n <namespace> logs <installer-pod>` and pod events on failure. Missing
Secrets fail before workload writes. Installation Jobs have privileged bootstrap
RBAC; apply them as an administrator and remove the installer Job, service account,
ClusterRole and ClusterRoleBinding after successful installation if no longer needed.

To rerun or upgrade, load the selected pack, delete the previous Job, and apply its
manifest again. Kubernetes Job pod templates are immutable. Resources labelled
`diorama.io/managed-by=addon-job` and `diorama.io/addon=<name>` are updated in place;
supplied Secrets and unrelated resources remain intact.

To remove an add-on, delete its Job and bootstrap RBAC from the installation
manifest, then remove only resources carrying both ownership labels:

```sh
kubectl -n d2k delete deployment,service,serviceaccount,role,rolebinding,configmap \
  -l 'diorama.io/managed-by=addon-job,diorama.io/addon=d2k'
kubectl delete clusterrole,clusterrolebinding \
  -l 'diorama.io/managed-by=addon-job,diorama.io/addon=d2k'
```

Use namespace `portainer` and add-on label `portainer-agent` for Portainer. Delete
installer Jobs and service accounts by their `diorama-install-<name>` names,
and installer ClusterRoles/ClusterRoleBindings by
`diorama-install-<name>-<namespace>`. Retain the namespace
and Secrets unless you explicitly intend to discard them; avoid deleting the
entire manifest's Namespace when unrelated workloads share it.

## Release inputs and verification

The [release workflow](../../.github/workflows/release.yml) publishes four packs per
architecture, Job manifests, provenance, size reports and checksums. Pins live in
[release-inputs.json](../diorama-dev/release-inputs.json). The storage recipe copies
only the provisioner executable and CA certificates from the pinned upstream image
into pinned Alpine, with its Apache license. It retains BusyBox and storage defaults.
The release builder rejects a provisioner image at or above 25 MB and host bundles
over 120 MB (ARM64) or 140 MB (amd64), measured in decimal bytes.

For local reproduction, build both CLIs and a static `diorama-addon` executable,
then use `diorama-release-bundle prepare`, `build-images`, and `package
<host|container|portainer-agent|d2k>` as shown in the workflow. The node image embeds
only core runtime files and workload archives. Host packs ship each executable
once: the inventory's identity payload is the installed file, verified by size,
SHA-256 and ELF checks, then compressed by the outer archive. There is no separate
`payloads/*.zst` copy. Use the matching CLI release to install these packs; newer
CLIs also accept older packs containing the compressed copies. Musl, ARMv7 and
RISC-V release packs are not currently published.

# Management checks and explicit prerequisites

Offline archives use the host/container/add-on names described above. Legacy
combined archives use `diorama-<version>-linux-<arch>[-musl]-offline.tar.gz`.
`bundle::build_offline_bundle` builds archives from local files and writes
the checksummed `bundle.manifest` consumed by `install --offline-install`.
Host installation verifies and extracts the bundle into `--path`; it does not
yet register or start a system service. For example, on a matching Linux host:

```sh
./dioramactl install --offline-install=./diorama-v0.1.0-linux-arm64-host-offline.tar.gz --path=./node
```

Download selection uses `geoffsee/diorama` releases and defaults to the management
CLI's package version. The requested archive must be published there, or supplied
through `--custom-url`. Local offline installation makes no download request.

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
CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm cargo run --locked -p diorama-dev --bin diorama-release-bundle -- package host v0.1.0 arm64 \
  target/aarch64-unknown-linux-musl/dist /tmp/release-assets dist
```

Container-mode installation dispatches through the Docker CLI and the existing owned
network/volume/container request boundary. A Linux Engine is required on Linux,
macOS or WSL2; its architecture is queried instead of inferred from the management host.
This implements image import and container creation, not live node readiness qualification.

An offline container bundle must include a hash-listed `asset-inventory.json` with
the inventory appropriate to its bundle kind, and the declared `image-diorama`
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
Tests use synthetic image archives and Engine fixtures. The release workflow also
runs `container/verify-offline.sh` against a node with network access disabled.

`dioramactl` is a separate management executable with checks and explicit lifecycle
commands. The existing `diorama` startup parser, startup YAML and its
90-case qualification remain separate. Container creation does not establish a running
Kubernetes node. Explicit
opt-in can install missing Alpine networking packages and enable its cgroups
service; ordinary checks never prepare a host or stop conflicting processes.

The name is an explicit diorama management CLI choice replacing `kubesoloctl` for
this executable. Help/version text is branded accordingly. KubeSolo environment
keys, on-disk paths, service/runtime/CNI identities and configuration schemas do not
change. No compatibility executable alias is supplied; existing scripts must select the
matching dioramactl release.
The crate remains private workspace code and adds no registry dependency.

## Interface and effects

The command shell also supports completion and artifact download, with a
`CommandHandler` seam for the remaining management commands. Download archive
selection uses the installation mode and target architecture/libc. Because the
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

## Worker credentials

`token create --role=worker --expiry=24h --kubeconfig PATH` creates a live bootstrap
Secret and prints a base64-encoded kubeconfig containing the endpoint, CA, and
token. Duration suffixes are `s`, `m`, `h`, and `d`. `token list` prints IDs and
expiry timestamps without token secrets; `token invalidate ID` revokes bootstrap
access. The default administrative kubeconfig is
`/var/lib/diorama/pki/admin.kubeconfig`.

`token export --token-file PATH` writes the decoded standard bootstrap kubeconfig
to stdout. It performs no runtime operations and starts no process. Protect both
outputs as credentials. Revoking a bootstrap token does not revoke already issued
client certificates. See [worker joining](../../README.md#join-workers).
