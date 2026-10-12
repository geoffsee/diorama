# Nested layer byte-stream integrity

`DecodeSession::verify_crane_image_layer_digests` adds an opaque
`LayerDigestArchiveObservation` for bundled gzip image roles. It verifies the same
outer archive/member/config/reference contract as `inspect_crane_image_archive`,
then additionally matches the SHA-256 of every complete decoded layer stream to
its ordered declared DiffID. The existing archive API and its declared-only
DiffID observations retain their original meaning.

The method takes the existing asset ID and immutable encoded byte slice,
`ArchiveLimits`, and `LayerDecodeLimits`. Both limit sets and the image role are
validated before session effects. Failure uses `ArchiveError`; nested policy
failures appear as `ArchivePolicyError::Layer(LayerPolicyError)` either directly
or through the private decoder observer. Fixed error descriptions do not include
untrusted member names or decoder error text.

The result exposes the complete outer archive observation and ordered layer
observations: stored SHA-256/size, observed gzip or zstd codec, decoded size,
verified DiffID and frame/member count. Callers cannot construct observations or
combine unrelated prior results. No observation escapes until outer gzip trailer,
outer tar end markers, stored member identities, JSON/platform validation, exact
reference closure, every inner stream trailer/checksum and every ordered DiffID
have all succeeded. Late errors discard provisional hashes and preserve session
charges. Repeated layer references decode the one unique stored member once and
reuse its verified result in manifest order. Config and manifest may appear before
or after layer members.

## Codec and allocation boundaries

This policy accepts a bounded sequence of gzip members or zstd frames within each
stored layer, with one codec throughout that layer. Gzip optional fields and FHCRC
are checked within the header cap; each member must pass CRC32 and ISIZE. ISIZE is
compared modulo 2^32, while the separate decoded-byte count uses checked u64
accounting. Zstd known sizes and window limits are checked before creating its
stream decoder; dictionary-bearing headers, skippable frames, reserved headers,
truncation and malformed checksums fail. Identity/raw layers, mixed codecs and
unrecognized trailing bytes are unsupported. The outer image gzip remains the
existing single-member profile.

Default policy bounds are 8 GiB stored bytes per layer, 8 GiB decoded bytes per
layer, 16 GiB unique decoded layer bytes per image, 32 GiB decoded bytes summed in
reference order, 1024 members/frames per layer, 8192 bytes per gzip header and a
maximum zstd window log of 26 (64 MiB). Zstd headers use a fixed small prefix within
the header buffer. Limits must be positive, byte caps cannot equal u64::MAX,
gzip header caps are 10..8192 and zstd window logs are 10..26.

The implementation holds one active nested decoder, an 8192-byte header buffer,
a fixed 8192-byte output buffer, hash/counter state and bounded small observations.
It never stores a whole layer or decoded image and never extracts inner tar
members. Existing archive metadata caps remain in force. The caller still owns
the original encoded input slice. Decoder/library and JSON allocations are not
universally fallible; these policies do not promise recoverable OOM or a hard RSS
bound. Execution is synchronous without mid-call cancellation or a hard CPU-time
guarantee. Frame counts and byte/header/window caps bound admitted work.

## Retained accounting

The same retained `DecodeSession` owns all charges; there are no fresh layer
sessions, shared interior mutability, or user callbacks:

- Encoded verification charges the outer encoded blob as before.
- Outer decoding charges all tar bytes, including compressed stored layer bytes.
- Successful nested decoding additionally charges every admitted returned output byte.
- Failed nested raw calls conservatively retain their entire offered output
  capacity, capped by the current allowance. The one excess byte, when offered,
  is already covered by the frame's retained probe; it is not charged twice.
- One byte is reserved before each outer decode attempt and each admitted inner
  frame/member for EOF/excess detection, including empty frames and bad headers.

The outer driver recomputes its read allowance from the shared remaining budget
after each private observer call. Nested output cannot consume budget behind a
cached outer allowance. Failed raw calls cannot rely on their reported output
position: the locked zstd implementation can write bytes and return a checksum
error while leaving its output position zero. Failed buffers are never hashed;
the conservative capacity reservation survives error propagation and retries.
This is a bound on the offered output buffer, not a count of actual output and not
a bound on hidden internal codec block work or CPU time. No failure or retry
replenishes encoded/decoded budgets.
Per-image unique decoded caps count each stored member once; the ordered cap
counts its decoded size again for every reference, without repeating decompression.
Thus successful accounting is outer tar bytes + unique nested decoded bytes +
one outer probe + inner member/frame probes. Ordered caps are a separate size
policy, not repeated actual-work charges.

## Meaning and compatibility gaps

A DiffID is the hash of the exact complete decoded stream, including tar headers,
padding and all bytes after any logical inner tar end marker. This method does not
parse those inner tar bytes. It does not validate path safety, whiteouts, links,
devices, inner archive structure or root filesystem semantics. Deliberately
non-tar decoded vectors can match declared digests; this keeps the proof boundary
observable. The observation does not authorize import or materialization.

Docker-save member names do not establish the original layer media type. This
method performs no decryption and cannot establish original encryption/foreign
provenance from omitted metadata. Nonempty `LayerSources` remains rejected by the
outer archive policy. No registry resolution, original registry manifest digest,
publisher authentication, production image pins, runtime ABI or release readiness
is supplied. Identity layers and zstd skippable/dictionary formats remain explicit
compatibility gaps; this slice does not claim every OCI/containerd layer format.

Primary references:

- [OCI v1.1.1 DiffID and ordered rootfs declarations](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md#layer-diffid)
- [OCI layer codecs and filesystem changeset semantics](https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md)
- [crane v0.21.5 stored bytes, deduplication and manifest ordering](https://github.com/google/go-containerregistry/blob/v0.21.5/pkg/v1/tarball/write.go)
- [Go 1.26.2 gzip concatenation and complete-trailer requirement](https://github.com/golang/go/blob/go1.26.2/src/compress/gzip/gunzip.go)
- [containerd v2.2.5 decompression, including wider skippable/raw support](https://github.com/containerd/containerd/blob/v2.2.5/pkg/archive/compression/compression.go)

Tests use independent stored-DEFLATE and raw zstd vectors, a fixed independently
produced dynamic-DEFLATE expansion vector, the exact zstd zero-position/error
counterexample with mutated output bytes, known checksum constants, optional
headers, arbitrary input chunk boundaries, concatenation, repeated references,
metadata order, exact limits and retained late-error charges. No actual upstream
artifact is executed. The independent pinned Go/crane gzip/zstd compatibility
fixture for this API lives in `tools/assets-layer`. Its Rust verifier requires
fresh captures bound to the current sources, including both runtime observations
and confirmed cleanup. Historical captures alone do not satisfy that gate. The
separate archive fixture exercises the archive-inspection API only.
