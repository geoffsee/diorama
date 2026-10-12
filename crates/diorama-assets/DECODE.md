# Bounded compressed-byte inspection

`DeclaredInventory::decoding_session(DecodeLimits)` creates a caller-owned budget
for repeated `inspect_compressed_blob(id, encoded_slice, observer)` calls. The
session first checks the catalogued encoding and reserves a decoded completion
probe, then verifies exact encoded length and SHA-256 on that immutable slice
using its retained `VerificationSession`. It never reopens a path or trusts an
older verification token. Only gzip and zstd are accepted; identity uses its own
existing inspection boundary.

Every callback chunk is **provisional**. A later checksum, trailer, framing or
callback failure returns no `DecodedObservation`. Callers must discard provisional
state on failure; the library neither commits nor rolls back callback effects,
catches callback panics, flushes files, or authorizes installation. A callback
error retains its concrete error value. Error Display and Debug contain fixed descriptions,
not native decoder/callback messages; Error::source remains available to callers.
Successful observations expose the encoded binding and decoded byte count/SHA-256.
The latter are newly observed values, not comparisons against missing production
uncompressed pins or guarantees of ELF, tar, OCI, safety or publisher authenticity.

## Budgets and completion

Default policy:256MiB decoded executable,8GiB decoded image blob,32GiB decoded
session total. These are provisional engineering gates, not release measurements.
Custom positive per-blob limits must leave room for a checked one-byte excess
probe. A session reserves one decoded-budget byte before any encoded read/hash,
header parse, decoder allocation or callback. Empty successful streams cost that
one byte. The effective output limit is min(role limit, remaining session budget).
Returned decoded bytes are charged before callbacks; charges are retained on
observer/checksum/trailing/other errors. A failed decoder read can write bytes without
reporting their length, so it conservatively retains the offered output capacity
within the remaining allowance, without invoking the observer or hashing that
failed buffer. This can charge more than the bytes actually produced; it does not
measure hidden codec work or establish a CPU deadline. The reserved byte pays for the EOF/excess
probe, including when the output exactly reaches its limit. Failed encoded
verification also retains its probe reservation and the existing encoded attempt
reservation. Unavailable/identity roles do not start a decoding attempt.

The stack output buffer is fixed8KiB. Reads request at most remaining allowed
output+1; an excess byte fails without passing that final over-limit chunk to the
observer. No decoded output Vec is allocated. A decoder error may internally
process bytes without returning them; accounting measures returned output plus
probe reservations, not native-library CPU/internal work. These synchronous APIs
provide no wall-clock deadline or hard RSS guarantee. Caller-created new sessions
explicitly create new budgets. Callback memory retention/time belongs to callers.

## Framing and dependencies

- `flate2 =1.1.10`, defaults disabled, `rust_backend`: one buffered GzDecoder member.
  A nonallocating precheck caps the **entire** gzip header at8192bytes, including
  fixed fields, extra/name/comment/CRC fields, before constructing the decoder.
  Reserved flags, missing fields and oversized/unterminated headers fail. Header
  names are never used as paths. The decoder verifies header CRC when present,
  data CRC and ISIZE while draining to genuine EOF. Recovering the underlying slice
  must yield no remainder: second members, padding and arbitrary suffixes fail.
- `zstd =0.13.3`, defaults disabled: normal modern zstd magic only, no skippable or
  legacy frame. Precheck validates bounded header fields, rejects reserved/unused
  descriptor bits and nonzero dictionary IDs, bounds advertised window at64MiB,
  and rejects known content sizes exceeding the effective output limit. The native
  decoder also receives `window_log_max(26)` before its first read, no dictionary,
  and `single_frame()`. Unknown frame sizes are allowed only with the same output
  bound. EOF is followed by an empty-underlying-slice check. Checksums are validated
  when present; checksum-less standard frames remain allowed. Dictionary ID zero
  is not proof of no dictionary dependency: no dictionary is supplied, so actual
  decompression must still succeed.

Native decoder context/window overhead exists in addition to the output buffer;
64MiB is a window limit, not total allocation. Locked transitive crates and native
zstd source are in the root-owned Cargo.lock. Broader target/toolchain qualification
for the native zstd build remains open, especially ARMv7/musl. Ordinary builds do
not fetch upstream production payloads. Compression acceptance does not validate
ELF-on-compressed content, an image archive or an OCI platform.

## Independent vectors and remaining gates

`tests/decode.rs` contains manually assembled RFC1952 stored-deflate and Zstandard
raw/RLE frame bytes. Expected decoded bytes/SHA256 and CRC/checksum constants are
independent of the decoders, not generated by round-tripping their encoders. All
malformed variants receive recomputed manifest hashes so tests reach parsing.
Tests cover tiny/exact/empty output budgets, aggregate/failed-attempt retention,
provisional callbacks, gzip optional fields/FHCRC/CRC/ISIZE, unknown zstd content
sizes/checksum/dictionaries/windows, truncations, expansion, concatenation and
trailing data. Production decoded hashes/sizes and actual baseline compressed
payload qualification remain absent. E06.01 remains open pending those inputs and
further content/ABI/OCI validation; E06.02 separately owns atomic installation.

## Compressed executable ELF composition

`DecodeSession::inspect_compressed_elf(id, encoded_slice, ElfLimits)` accepts the
six catalogued zstd executable roles. It validates all ELF limits before any
hashing/decoding effects and rejects image roles and identity encodings before
starting an attempt. Gzip images keep the streaming interface; their decoded bytes
are not passed to an executable parser. No catalog encoding exception is introduced.

The method uses the session's retained encoded and decoded budgets. Its effective
output cap is the minimum of `DecodeLimits.executable_bytes`, `ElfLimits.bytes`
and the remaining decoded budget after reserving the completion probe. Unknown
frame sizes receive the same cap as advertised sizes. Checked length arithmetic
and integer conversions precede fallible buffer growth. Only actually returned
chunks are retained, with no full-limit or advertised-size allocation up front.
The logical buffer length is bounded; allocator capacity and native decoder
context remain additional resources, so this is not a hard RSS/time guarantee.

Chunks are held in a private provisional buffer. Decoding must finish and pass
checksum/framing checks before the shared ELF parser sees that same owned decoded
content. No external observer runs, no provisional bytes escape, and no path is
opened or executable started. On any failure the buffer is dropped and no combined
observation is returned. All already-charged bytes and completion/encoded-attempt
reservations remain spent, including allocation and later ELF-parser failures.
The existing streaming callback contract is unchanged.

Success returns opaque `DecodedElfInspection` with `decoded_observation()` and
`elf()` getters. This binds the encoded digest/length, observed decoded digest/length
and bounded ELF facts to one attempt. It neither compares the decoded digest with
a production pin nor authorizes installation. The existing `KnownMismatch` and
`Unresolved` loader relations and unresolved ARM/RISC-V ABI requirements remain.
A correct header with no interpreter is still not proof of static linkage or
runtime compatibility. Materialization must reverify the actual output it commits.

`CompressedElfError` distinguishes nonexecutable roles, decoding, ELF parsing,
checked buffer bounds and allocation failure. Display uses fixed descriptions;
structured sources retain decoder/verification/allocation errors. No raw decoder
source messages are included in Debug. Tests do not induce host memory exhaustion.

`tests/decoded_elf.rs` uses independently assembled zstd raw/RLE frames and
handwritten ELF layouts, with a fixed independent decoded SHA-256 vector. Coverage
includes four machine headers, same-hash wrong-target inputs, opposite-libc loader
observations, corrupt/truncated/trailing frames taking precedence over ELF parsing,
role/limit rejection before effects, exact/tighter/aggregate caps, repeated encoded
and decoded budget exhaustion, retained parser-failure charges and bounded RLE
expansion. Existing gzip CRC/FHCRC/trailer/provisional-callback regressions continue
to exercise the unchanged streaming path. These synthetic tests do not qualify a
production compressed payload or close E06.01.

The separate [crane archive inspector](ARCHIVE.md) now uses the retained session's
gzip stream with a private incremental tar parser. It retains bounded metadata and
hashes/discards layer bodies, with no whole decoded-image allocation. Only complete
outer decoding plus archive/member/reference closure yields its opaque result;
nested layer decoding and DiffID verification remain separate.

The additive [layer digest verifier](LAYER-INTEGRITY.md) shares this retained budget
between outer tar output and every nested layer's decoded output. A private
budget-aware observer lets the driver recompute its allowance after nested work;
the public callback API is unchanged. Each admitted nested frame/member reserves
its own excess/EOF probe, and all failure charges survive retries. No decoded
layer bytes are retained or exposed provisionally.

Nested raw decoder failures conservatively retain the offered output-buffer
capacity within the available allowance, in addition to prior admitted output and
reserved probes. Error positions can underreport mutated bytes; failed buffers
are not hashed. This reservation does not measure hidden internal codec work.
