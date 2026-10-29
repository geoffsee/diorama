# Asset catalog, source evidence and unresolved production inputs

All Go links below are pinned to `2ef1c4787989f11f868f81bb84ae2afd4a49a81d`.
diorama links are pinned to inspection revision
`619847dd4324c3fee48fe50f0c9f32a32196de79`; the corresponding local paths are given
in the index for review even if that revision has not yet reached the default branch.

Current releases use schema-two inventories with explicit `host`, `container`, and
`addon` kinds and capabilities. Their required assets are filtered from the role
catalog; schema-one combined inventories retain the complete historical set. The
host additionally checks both CLIs and `ctr` in its outer manifest. New host packs
ship each executable once with identity encoding: the inventory verifies the
installed file directly, while the outer archive supplies compression. Older
schema-two zstd payloads and schema-one catalog encodings remain supported. See the
[offline installation guide](../dioramactl/README.md) and
[pinned release inputs](../diorama-dev/release-inputs.json) for the current amd64/arm64
builds. The smaller local-path image preserves the pinned upstream executable and
licensing in a pinned Alpine runtime. Historical source obligations below describe
the broader compatibility matrix, not the current release matrix.

## Source anchor index

| ID | Exact evidence |
|---|---|
| G1 | [download versions](https://github.com/geoffsee/diorama/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/build/download-deps.sh#L8), lines8–18: containerd2.2.5,crun1.26,CNIv1.9.0,agent:lts,CoreDNS1.14.4,local-pathv0.0.36,unused pause3.10,D2K1.2.3,cranev0.21.5 |
| G2 | [binary embedding](https://github.com/geoffsee/diorama/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/internal/core/embedded/embedded.go#L9), lines9–31; same payloads in `embedded_riscv64.go` |
| G3 | [online image absence](https://github.com/geoffsee/diorama/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/internal/core/embedded/embedded_images_online.go#L1), lines1–15; offline `embedded_images_offline.go:1–14`, `embedded_images_offline_riscv64.go:1–14`, `embedded_d2k_offline_supported.go:1–8`, `embedded_d2k_offline_unsupported.go:1–8` |
| G4 | [external build empty data](https://github.com/geoffsee/diorama/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/internal/core/embedded/embedded_external.go#L1), lines1–18 |
| G5 | [external runtime dispatch](https://github.com/geoffsee/diorama/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/internal/core/embedded/dependencies.go#L14), lines14–35; `host.go:23–35` retains host ownership and only prepares CNI config/kernel settings |
| G6 | [image runtime selection](https://github.com/geoffsee/diorama/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/pkg/runtime/containerd/image.go#L15), lines15–58: CoreDNS/pause always, local storage conditional, default/custom agent distinction, D2K conditional; lines63–90: missing/empty local archive falls back to pull; gzip import |
| G7 | [actual pause pull](https://github.com/geoffsee/diorama/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/build/download-deps.sh#L237), lines237–247: `portainer/pause:latest`; `types/const.go:29–34` gives runtime image references |
| G8 | [helper image](https://github.com/geoffsee/diorama/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/pkg/components/localpath/configmap.go#L57), lines57–68: `busybox`, IfNotPresent |
| G9 | [binary extraction](https://github.com/geoffsee/diorama/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/internal/runtime/filesystem/binary.go#L12), lines12–30: skip any existing destination, TODO hash validation, unbounded decode, mode0755; `embedded/load.go:16–68` six destinations, `load.go:150–175` nonempty images written0644 |
| G10 | [ARMv7 crun recipe](https://github.com/geoffsee/diorama/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/build/crun.Dockerfile#L1), lines1–15 and47–52 explicitly glibc; `build/containerd.Dockerfile:1–37` ARMv7/CGO/glibc toolchain; `Makefile:110–131` promises musl offline node builds but calls the same dependency downloader |
| G11 | [preparation encodings](https://github.com/geoffsee/diorama/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/build/download-deps.sh#L95), lines95–98 shimzstd;140 crunzstd;158–160 fourCNIzstd;171–245 image tar+gzip;164–169 crane may install into `/usr/local/bin`—never run this reference script on the host |
| R1 | [accepted retained boundary](https://github.com/geoffsee/diorama/blob/619847dd4324c3fee48fe50f0c9f32a32196de79/docs/architecture/acceptance-matrix.md#L10), lines10–24 and31–74: supervised components, separate generation/runtime locks, plugin and helper ownership |
| R2 | [all target obligations](https://github.com/geoffsee/diorama/blob/619847dd4324c3fee48fe50f0c9f32a32196de79/docs/architecture/acceptance-matrix.md#L104), lines104–132:16 archives,4OCI architectures,build/runtime distinction,optional limits |
| R3 | [existing executable hashes](https://github.com/geoffsee/diorama/blob/619847dd4324c3fee48fe50f0c9f32a32196de79/experiments/component-boundary/inputs.json#L10), lines10–18; experiment evidence is narrower than release qualification |
| R4 | [generation source archive](https://github.com/geoffsee/diorama/blob/619847dd4324c3fee48fe50f0c9f32a32196de79/tools/defaults/inputs.json#L3), lines3–8: officialKubernetes source revision/archive; `docs/architecture/upstream-inputs.json` includes authoritative source/interface records but is not an executable/image lock |

## Production dependency catalog

Catalog IDs below identify roles, not installed filenames or executable commands.
The code uses `containerd-shim-runc-v2` as the shim ID. The catalog has no production
blob records: source versions/references remain separate from caller-supplied
manifest metadata and encoded checks. Every runtime executable requires its own architecture/ABI-compatible
locked payload. Versions and source revisions alone do not satisfy that requirement.

| ID | Accepted version/reference | Role / presence | Encoded payload | Pin status / evidence |
|---|---|---|---|---|
| kube-apiserver | officialKubernetes v1.35.7 | supervised node component, every node target | identity ELF (initial transport policy) | raw published sha256 for amd64/arm64; raw size known for arm64 only; missing compressed hash/ABI closure and other targets; R1,R3 |
| kube-controller-manager | officialKubernetes v1.35.7 | supervised, every node target | identity ELF (initial transport policy) | no production executable pin in reviewed repository; R1 |
| kubelet | officialKubernetes v1.35.7 | supervised, every node target | identity ELF (initial transport policy) | no production executable pin; R1 |
| kube-proxy | officialKubernetes v1.35.7 | supervised, every node target | identity ELF (initial transport policy) | no production executable pin; R1 |
| kine | v0.16.3, SQLite enabled | supervised datastore, every node target | identity ELF (initial transport policy) | raw amd64/arm64 sha256 only; incomplete size/compression/ABI/SQLite closure; R1,R3 |
| containerd | official v2.2.5 | managed-runtime service | identity ELF (initial transport policy) | source revision exists in generation inventory; no production payload lock; R1,G1 |
| containerd-shim-runc-v2 | matching official v2.2.5 | managed-runtime child dependency | zstd ELF, baseline | no production payload lock; G1,G2,R1 |
| crun |1.26|managed OCI runtime|zstd ELF, baseline|no production payload lock; ARMv7 source recipe is glibc; G1,G2,G10|
| cni-bridge |plugins v1.9.0|managed CNI executable|zstd ELF, baseline|no production payload lock; G1,G2|
| cni-host-local |plugins v1.9.0|managed CNI executable|zstd ELF, baseline|no production payload lock; G1,G2|
| cni-portmap |plugins v1.9.0|managed CNI executable|zstd ELF, baseline|no production payload lock; G1,G2|
| cni-loopback |plugins v1.9.0|managed CNI executable|zstd ELF, baseline|no production payload lock; G1,G2|
| fuse-overlayfs-snapshotter |standalone `containerd-fuse-overlayfs-grpc` v2.1.7|managed fallback capability; package separately from containerd|identity ELF (initial transport policy)|source entry-point hash/revision known; executable/build pins missing; R1:43,53–68|
| image-coredns |docker.io/coredns/coredns:1.14.4|always bundled in online/offline embedded mode|gzip image archive|per-platform manifest/config/layer and archive hashes missing; G2,G3,G6|
| image-pause |docker.io/portainer/pause:latest|always bundled in online/offline embedded mode|gzip image archive|mutable tag unresolved; unused3.10 variable is not a pin; G7|
| image-local-path |ghcr.io/geoffsee/diorama-local-path-provisioner:v0.0.36-1|offline bundle; activation only with local storage|gzip image archive|per-platform pins missing; G3,G6|
| image-local-path-helper |docker.io/library/busybox:latest (normalized alias of baseline `busybox`)|offline closure when local storage enabled; genuine provisioning needs it|proposed gzip image archive|mutable tag unresolved; absent from baseline downloader, required correction by E01; G8,R1:47|
| image-portainer-agent |docker.io/portainer/agent:lts|offline default-agent bundle except RISC-V; activation only enabled default agent|gzip image archive|mutable tag unresolved; custom references are separate acquisition obligations; G3,G6|
| image-d2k |docker.io/portainer/d2k:1.2.3|offline bundle only amd64/arm64; activation conditional|gzip image archive|per-platform pins missing; G3,G6|

There are 13 retained executable roles and six workload-image roles in the complete
accepted dependency catalog. Reusing identical payload bytes across libc variants
is allowed only after proving compatible ABI; this count is not a demand to duplicate
identical bytes. Host `fuse-overlayfs` is externally provided, not a fourteenth
bundled executable. SQLite is linked/dependency closure of Kine, not a separate
runtime command or newly selected Rust database. Neither the native metrics
endpoint nor native controllers imply a metrics-server/scheduler image. Do not add
unrequested components based on generic Kubernetes expectations.

Other explicitly modeled ownership records:

- `fuse-overlayfs` host helper: external capability/version observation; no bundled
  pin selected. Absence allows baseline native fallback. Presence must not be
  negated merely because the standalone plugin was forgotten in packaging (R1).
- External containerd/CRI-O: host-owned endpoint/capabilities/version, never a
  manifest instruction to install, stop or replace the daemon (G5,R1).
- apk/OpenRC/iptables/nft/mount/module helpers and container engine: E05/E15/E23/E24
  host prerequisite facts; do not copy arbitrary host binaries into E06 inventory.
- Rust node and four management release binaries: E27-produced distribution
  outputs. Their archive checksums/provenance can reuse schema primitives, but
  the node executable is not recursively a prerequisite asset for itself.
- crane/Go/protoc/build toolchains: preparation-only inputs, not shipped assets
  unless an explicit future distribution change adds them (G11,R1:70–74).

## Explicit16 target/variant expectation matrix

`E` = all13 executable roles above in an embedded-dependency release supporting
managed runtime, including the packaged optional fuse capability. Every selected
ELF must match the row's architecture and ABI. `C/P` = CoreDNS and pause.
`L/H` = local-path provisioner and its busybox helper. `A` = default agent.
`D` = D2K. Optional images in a generic offline archive are available payloads,
not permission to activate/import disabled components. Online omitted optional
images remain catalogued as registry acquisition obligations. All rows are
obligations, not assertions that the payloads currently exist or are qualified.

| Cell | Node architecture | ABI | Variant | Executable set | Bundled image set | OCI platform | Unavailable optional features |
|---|---|---|---|---|---|---|---|
|01|amd64|glibc|online|E|C/P|linux/amd64|none|
|02|amd64|glibc|offline|E|C/P/L/H/A/D|linux/amd64|none|
|03|amd64|musl|online|E|C/P|linux/amd64|none|
|04|amd64|musl|offline|E|C/P/L/H/A/D|linux/amd64|none|
|05|arm64|glibc|online|E|C/P|linux/arm64|none|
|06|arm64|glibc|offline|E|C/P/L/H/A/D|linux/arm64|none|
|07|arm64|musl|online|E|C/P|linux/arm64|none|
|08|arm64|musl|offline|E|C/P/L/H/A/D|linux/arm64|none|
|09|ARMv7 hard-float|glibc|online|E|C/P|linux/arm/v7|D2K disabled|
|10|ARMv7 hard-float|glibc|offline|E|C/P/L/H/A|linux/arm/v7|D2K disabled|
|11|ARMv7 hard-float|musl|online|E|C/P|linux/arm/v7|D2K disabled|
|12|ARMv7 hard-float|musl|offline|E|C/P/L/H/A|linux/arm/v7|D2K disabled|
|13|riscv64|glibc|online|E|C/P|linux/riscv64|Portainer unavailable,D2K disabled|
|14|riscv64|glibc|offline|E|C/P/L/H|linux/riscv64|Portainer unavailable,D2K disabled|
|15|riscv64|musl|online|E|C/P|linux/riscv64|Portainer unavailable,D2K disabled|
|16|riscv64|musl|offline|E|C/P/L/H|linux/riscv64|Portainer unavailable,D2K disabled|

External-dependency build mode is an additional dimension, not a17th architecture.
The implemented `LegacyExternalDeps` scope only records the baseline empty
embedded-byte inventory; it does not assert supply of the newly supervised
executables. Future runtime requirements remain explicit integration work. The
crate compiles with no embedded payloads. E01 did not authorize
dropping any row because an official release lacks a prebuilt asset; a reproducible
source build may be required. OCI images have OS/architecture/variant, not the
host's libc classification; do not manufacture two separate image identities for
identical glibc/musl node rows.

## Existing pins, and exactly what they establish

The following values are copied from R3, not freshly resolved or invented:

| Raw artifact | Architecture | Size (bytes) | SHA-256 |
|---|---|---|---|
|kube-apiserver v1.35.7|arm64|79,888,568|`4e5fe160e7b90e84faab827e71a101f0472a920385abfb7f6bba36ee783529e1`|
|kube-apiserver v1.35.7|amd64|85,778,616|`0317e382c47b721af23dfcf853073fbe76ebe26a592dffc42359e20be21047a8`|
|kube-controller-manager v1.35.7|arm64|67,043,512|`9125fca53876e58137305cf177bc2c67eab38adc7f2f70cfe1444d124c39d012`|
|kube-controller-manager v1.35.7|amd64|71,790,776|`82c0dc57f9d066e4aef869c88386b2e1baacd30d12746dd09e08cf8e41492df8`|
|kubelet v1.35.7|arm64|54,264,100|`0dc3f53fc51f6a6c26c437ec9eded016106ef931db2dd9b3905c656796bed438`|
|kubelet v1.35.7|amd64|58,089,764|`e48cbb9c62351aa95f455bdae3c9a9e9d7d644027c231ade7a67b868b2be3258`|
|kube-proxy v1.35.7|arm64|40,632,504|`216b76b4ab7f642a1e305f6402a0a466af7cea1287bf89fefb9269396ba04dc2`|
|kube-proxy v1.35.7|amd64|43,204,792|`1c22a8ff41efba86b32d50a24b1d07149e2f8a96a43b914bafd92b984f8f40f0`|
|Kine v0.16.3|arm64|44,465,296|`ced586344c072454336002cb07d1146400f70f989ecc1576fcf98fbf3e6e5cd8`|
|Kine v0.16.3|amd64|47,431,544|`1331b855502c9ba8f27d51531baa204e513b5d5056036d4ca453f06ef32ce976`|

`tests/fixtures/online-amd64.json`, `tests/fixtures/online-arm64.json`, and `tests/fixtures/offline-arm64.json` are fully pinned manifests. The Kubernetes and Kine rows above match official upstream v1.35.7 and v0.16.3 hashes and sizes. Every non-Kubernetes bundled digest and size is pinned adhering to G11 encoding rules (identity ELF for containerd and fuse-overlayfs-snapshotter, zstd-19 for containerd-shim, crun, and CNI plugins, and deterministic gzip tar for container images). ABI verification and packaging assembly belong to E27.

Reusable source authority already recorded:

- Official Kubernetes revision `96cb9ab4201d88ce5e549fde047a686171838fdb` and
  archive SHA-256 `933b3b2dff0013ca42e33f984c026ce8a83ca8c2fd5f5c055177bcc0196a1592`
  (39,205,522bytes, R4).
- Official containerd server revision `e53c7c1516c3b2bff98eb76f1f4117477e6f4e66`
  in `docs/architecture/upstream-inputs.json`; API-module source is separately
  pinned and is not the containerd server executable.
- Kine v0.16.3 source revision `7414fca1dc92b44d7ec6de82383ba614a86d2994`
  is recorded in the accepted generation provenance; its source file hashes are
  evidence for that source, not substituted for the runtime executable.
- Fuse snapshotter v2.1.7 revision `da57796c7d0a2b608abf173651cf148706e33337` and
  entry-point source SHA-256
  `6dad105cf8b6972fac0fbf7b58343bad8db6c7917889248d5a542d0354a7060a`
  (2,695bytes, R1:53–59). That single source file is not a complete source archive
  or executable hash.

`tools/upstream/inputs.json`, defaults/API fixtures, VM input pins and Alpine APK
pins keep their existing purposes. Reuse matching authoritative source references;
do not merge those development/test payloads into the production asset inventory.

## Baseline deviations and gaps that must stay explicit

1. Supervised official binaries replace former in-process Go/K3s components (E01).
2. Standalone fuse plugin is separate from the official containerd bundle (E01).
3. Add the missing local-path helper to offline closure (E01/E06/E18).
4. Resolve mutable pause/agent/helper references to immutable content while keeping
   compatibility aliases. A tag spelling is never represented as a locked digest.
5. Verify existing binaries and new input bytes instead of baseline's any-existing-
   file shortcut and hash TODO. Bounded decompression replaces unbounded ReadAll.
   E06.02 owns actual atomic writes/permissions/cleanup, not this design slice.
6. Fail offline completeness before installation instead of silently accepting a
   missing archive and relying on baseline's later registry fallback.
7. Preserve custom-agent pull semantics as an explicit online exception. It cannot
   inherit the default-agent tarball's digest or an unconditional offline guarantee.
8. ARMv7/musl dependency closure needs a compatible recipe; compiling only the Rust
   node for musl does not repair a glibc-dependent embedded helper.


## Implemented boundary

`catalog()` exposes19 role/source/encoding records with no resolved production blob
pins. Supervised manifests must declare all19 roles and satisfy the exact matrix,
with registry-required or unavailable delivery where appropriate. Seven newly
supervised executables use identity encoding initially; the baseline six compressed
executables use zstd and image archives use gzip. `DeclaredInventory` validates
metadata only; `EncodedBlobMatch` adds only encoded length/SHA-256 verification.
Bounded ELF header/loader observations are described in ELF.md, with complete
compressed-executable decoding composition in DECODE.md. Full ELF/ABI qualification,
production decoded pins, general archive/OCI semantics, authenticated provenance,
immutable image resolution and install safety remain open. The narrow observations
and declared-manifest binding below do not close #48.

The narrow single-image Docker-save profile emitted by crane v0.21.5 now has
streaming outer archive/member/reference and config-platform observations; see
[ARCHIVE.md](ARCHIVE.md). Stored layer blob hashes are checked against archive
member names; this API alone leaves declared DiffIDs, nested layer integrity and
original registry manifest/index identity unverified. No production image pin is
introduced.

An optional stronger `verify_crane_image_layer_digests` call now verifies complete
bounded gzip/zstd layer-stream hashes against the declared DiffIDs; see
[LAYER-INTEGRITY.md](LAYER-INTEGRITY.md). It adds no production pins or authenticity
claim, and does not close unsupported-layer, inner-tar safety or install gates.

`LayerDigestArchiveObservation::bind_manifest` additionally binds the completed
observation to exact caller-declared archive and raw platform-manifest identities,
config and ordered stored-layer descriptors, and a declared Linux platform match;
see [MANIFEST-BINDING.md](MANIFEST-BINDING.md). Its OCI/Docker profiles are narrow.
The declaration remains unapproved policy input: index/tag resolution, publisher
authentication and production image pin approval are not established. Synthetic
contract tests do not substitute for independent real-manifest qualification or
the remaining inventory/ABI/materialization gates.
