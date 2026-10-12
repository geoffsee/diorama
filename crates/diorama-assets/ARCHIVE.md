# Single-image crane archive observations

`DecodeSession::inspect_crane_image_archive(id, encoded, ArchiveLimits)` adds
read-only inspection for bundled gzip image roles. It uses the same retained
encoded and decoded budgets as other session calls. It does not open paths,
extract files, import images, fetch references or execute content. The caller
already owns the immutable encoded input slice; the library never allocates a
whole decoded archive or retains layer bodies.

The private parser processes decoded chunks incrementally using one512-byte tar
header buffer. It hashes and discards layer payloads and retains bounded config
and manifest JSON plus member metadata. Every state is provisional until the
outer decoder has completed its checksum/framing checks and the parser has
verified complete tar termination, metadata and reference closure. No observer
callback is exposed. No opaque result is returned on any error; charged encoded
attempts, decoded chunks and completion probes remain spent on parse/decode failure.

## Pinned source authority and the supported profile

The compatibility reference is KubeSolo `2ef1c4787989f11f868f81bb84ae2afd4a49a81d`:
its [downloader](https://github.com/portainer/kubesolo/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/build/download-deps.sh#L164)
invokes `crane pull --platform ...` then gzip. Its
[consumer](https://github.com/portainer/kubesolo/blob/2ef1c4787989f11f868f81bb84ae2afd4a49a81d/pkg/runtime/containerd/image.go#L63)
gunzips before containerd Import. The downloader selects crane v0.21.5 only when
crane is absent; it does not verify an already-installed crane's version. These
sources establish intended behavior, not provenance of unrecorded old payloads.

Crane v0.21.5's [pull command](https://github.com/google/go-containerregistry/blob/v0.21.5/cmd/crane/cmd/pull.go#L71)
defaults to `tarball`, calling MultiSave. Its
[writer](https://github.com/google/go-containerregistry/blob/v0.21.5/pkg/v1/tarball/write.go#L139)
writes config as `sha256:<hex>`, stored layer bytes as `<digest-hex>.tar.gz`, and
Docker `manifest.json` last. It deduplicates stored layer members while preserving
ordered repeated layer references in the manifest. The filename suffix does not
establish the actual nested layer codec: the writer copies `Layer.Compressed()`
bytes. This API accepts manifest-first ordering too, because the final references
are reconciled after all members have been observed.

The initial profile accepts exactly one config, one single-image manifest and all
its distinct layer members. Empty layer inventories and null/empty RepoTags are
allowed. Repeated layer references preserve order and must have consistent declared
DiffIDs. Tags remain untrusted metadata, without registry/catalog-role resolution.

Only regular USTAR entries with empty prefix/link fields and canonical top-level
names above are accepted. The config name's fixed colon is intentional; inventory
relative-path rules are not reused as archive-member rules. Header checksums,
octal numeric fields, exact declared sizes, zero member padding, and exactly two
zero terminating blocks are checked. Any decoded bytes after termination fail,
even additional zero padding. Duplicate/unreferenced/missing members, links,
directories, devices, sparse records, PAX/GNU extensions and other names fail.
Nonempty `LayerSources` fails explicitly; no foreign-layer acquisition is inferred.

This is deliberately narrower than general Docker-save/OCI tar compatibility.
Crane's [release Go version](https://github.com/google/go-containerregistry/blob/v0.21.5/.go-version)
is1.26.2; that version's [tar writer](https://github.com/golang/go/blob/go1.26.2/src/archive/tar/writer.go#L65)
selects USTAR when representable and writes the corresponding padding/terminators.
Actual pinned-crane fixture qualification must still precede any baseline payload
compatibility claim. General extension records and alternative archive layouts
need a separately reviewed compatibility expansion.

## Results and identity boundaries

`DockerArchiveObservation` exposes the completed outer encoded/decoded observations,
Docker archive manifest JSON hash, config raw SHA-256/size/platform fields, ordered
layer member SHA-256/sizes and declared DiffIDs, and bounded tag strings. Config
and stored layer hashes must match their canonical member names. The config's
OS/architecture must match the requested image target; host libc is not an image
identity. ARMv7 requires architecture `arm`; explicit non-v7 variants fail and
missing variants yield `VariantUnresolved`. Other nonempty variants remain
unresolved CPU requirements. `DeclaredMatch` concerns those configuration fields,
not instructions actually present in the image or runtime compatibility.

The manifest references and config `rootfs.diff_ids` must have matching lengths;
rootfs type must be `layers`. Unknown config extension fields remain accepted.
Duplicate JSON keys, including escaped aliases and nested keys in unknown fields,
fail. Both JSON documents are completely consumed under byte and depth bounds.
The manifest descriptor accepts only its supported Config/RepoTags/Layers/
LayerSources fields. Malformed metadata cannot create a public success type.

The [OCI configuration specification](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md#layer-diffid)
defines DiffIDs over uncompressed layer tar bytes; they are not stored compressed
layer digests. This slice does not decode nested layers, verify their checksums or
DiffIDs, inspect their tar paths/whiteouts, or establish rootfs safety. The tests
intentionally accept an internally referenced `abc` member with a different
*declared* DiffID to keep this limitation observable.

Docker archive `manifest.json` is not the original registry manifest/index.
[Containerd v2.2.5's importer](https://github.com/containerd/containerd/blob/v2.2.5/core/images/archive/importer.go#L150)
constructs new image manifests and an index from archive blobs. This API neither
reconstructs nor reports an original registry digest. Declared inventory hashes
still do not authenticate a publisher. Immutable registry/image pins and their
provenance remain separate unresolved inputs.

## Bounds, errors and tests

Defaults are engineering policy:8GiB decoded archive (also limited by the session's
image and remaining aggregate budgets),256 members,128 ordered layer references,
1MiB config and1MiB manifest, JSON depth32,16 tags of at most512bytes. Custom limits
must be positive; JSON depth cannot exceed64 and archive bytes must allow a checked
completion probe. Metadata declared sizes and member counts are checked before
buffer growth. Byte arithmetic and decoder caps are checked. Payload buffers and
result vectors grow fallibly for actual admitted content; JSON/string/map
allocations are bounded by metadata/count policies but may still abort on allocator
failure. This is not a blanket recoverable-OOM or hard-RSS guarantee.

The API is synchronous, with no mid-call cancellation or hard CPU deadline.
Decoder internal work and caller-owned encoded input remain additional resources.
`ArchiveError` separates final policy errors from decoding/provisional-parser
errors. Display contains fixed descriptions and sources preserve typed errors;
raw config content and decompressor messages are not interpolated in errors.
Returned strings are untrusted and need escaping before display.

Independent tests assemble USTAR headers and stored-DEFLATE gzip vectors without
using archive/compression encoders under test. They cover complete and large
streamed archives, chunk boundaries1–8192, repeated references, fields/hashes,
duplicate JSON/depth, wrong platforms with recomputed hashes, unsafe headers and
names, reference closure, corrupt final gzip trailers, and retained failure budgets.
A compile-fail doctest prevents constructing unrelated observations as a success.
They do not replace pinned-crane qualification, production image pins, nested
layer verification, E06.02 materialization or E09 runtime import evidence.

The separate `verify_crane_image_layer_digests` API adds bounded nested gzip/zstd
stream completion and ordered DiffID matching; see [LAYER-INTEGRITY.md](LAYER-INTEGRITY.md).
It reuses these outer archive checks and leaves this inspector's original
stored-byte/declared-DiffID contract unchanged. Neither API validates inner tar
filesystem semantics or grants import/materialization permission.
