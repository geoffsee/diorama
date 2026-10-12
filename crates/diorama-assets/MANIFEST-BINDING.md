# Declared platform-manifest binding

`LayerDigestArchiveObservation::bind_manifest` consumes a completed layer-digest
observation, a `DeclaredImageManifestPin`, a raw platform-manifest byte slice, and
`ManifestBindingLimits`. Success returns an opaque `ImageManifestBinding` containing
the observation and matched declaration. Callers cannot construct the binding or
substitute an unrelated archive observation into it.

The pin is caller-declared policy: image role, Linux architecture, encoded archive
SHA-256/size, raw platform-manifest SHA-256/size, and `OciV1` or `DockerV2` format.
Public construction of a pin neither approves its provenance nor makes it a
production asset pin. The archive identity covers the exact encoded input already
verified by the decoding session. The separate manifest identity includes all raw
JSON bytes, including whitespace; it is not the Docker-save `manifest.json` digest.

## Checks and supported profiles

Before returning a binding, the method requires:

- The completed observation's image role and encoded archive size/hash match the pin.
- The config declares Linux and the selected architecture, with `DeclaredMatch`
  status. ARMv7 requires variant `v7`; an unresolved variant remains rejected.
  The architecture declaration does not establish the image's libc or ABI closure.
- The raw manifest size/hash match the pin and its JSON has unique keys and bounded
  depth. Schema version must be the integer 2 and the manifest media type must
  match the selected format.
- The config descriptor's size/hash equal the exact observed config member, with
  the format's image-config media type.
- The ordered layer descriptors exactly match every observed stored layer's
  size/hash and codec media type. Repeated references remain repeated and ordered;
  the inherited observation has already verified each complete decoded DiffID.

OCI accepts `application/vnd.oci.image.manifest.v1+json`, its image-config media
type, and gzip or zstd image-layer media types. Docker schema 2 accepts
`application/vnd.docker.distribution.manifest.v2+json`, its container-image config
media type, and gzip rootfs layers. Docker zstd and identity/raw layers are rejected.

The manifest permits only `schemaVersion`, `mediaType`, `config`, `layers`, and
optional `annotations`. Descriptors permit only `mediaType`, `digest`, `size`, and
optional `annotations`. Annotations must be objects with string values. Digests
must be SHA-256 with exactly 64 lowercase hexadecimal digits; sizes are positive
integers no larger than `i64::MAX`. Floats, booleans, and numeric strings cannot
stand in for version or size fields. Missing required fields, unknown fields,
indexes, artifact/subject fields, descriptor URLs/embedded data/platform fields,
foreign/nondistributable/encrypted media types, and codec mismatches fail.

This deliberately narrow profile is not a validator for every valid OCI document.

## Limits, ownership, and errors

Default limits are 1 MiB of raw manifest bytes, 1024 ordered layer references, and
JSON depth 32. Byte and reference limits must be positive; depth must be 1..64.
Both the declared and actual manifest length are bounded before hashing or parsing.
The reference count is checked after JSON parsing, within the raw-byte bound.
These limits bound admitted metadata; they do not promise hard CPU/RSS limits,
recoverable allocation failure, or mid-call cancellation.

The method performs no I/O, decoding, callback, session creation, or budget refund.
Failure consumes and discards the completed observation; prior session charges
remain retained. `ManifestBindingError` identifies invalid policy/pin, limits,
identity, platform, JSON/profile, descriptor, config, layer, and codec failures
without including untrusted document contents in its display text.

## Evidence and remaining gates

The existing [archive](ARCHIVE.md) and [layer](LAYER-INTEGRITY.md) APIs retain their
original guarantees when called without this additional binding. The new binding
proves agreement with the caller's separately supplied platform-manifest bytes.
It does not select an index entry, authenticate a registry/tag/publisher, approve
production pins, inspect inner-tar paths or filesystem effects, establish ABI
compatibility, or authorize import, extraction, installation, or deployment.

The read-only KubeSolo baseline `2ef1c4787989f11f868f81bb84ae2afd4a49a81d` pulls a
platform image with crane and gzips its Docker-save output in
`build/download-deps.sh`; `internal/core/embedded/load.go` materializes embedded
archives. This binding adds an explicit identity check to that archive boundary;
it does not execute either baseline workflow or grant materialization permission.

Focused synthetic tests cover OCI/Docker profiles, repeated-layer ordering,
rehashed descriptor substitutions, role/archive/manifest mismatches, unresolved
platform variants, malformed JSON/numeric fields, exact limits, and opaque
construction. These tests establish the API contract, not real registry provenance.
The [manifest fixture](../../tools/assets-manifest/README.md) independently checks
retained CoreDNS raw manifest/config/blob bytes, complete DiffIDs and a separately
audited pinned-crane archive. Its mandatory gate requires fresh source-bound Rust
capture receipts. Fixture identities do not authenticate publishers or approve
production pins. The full inventory, platform/ABI and installation consumers
required by E06.01/#48 remain open.
