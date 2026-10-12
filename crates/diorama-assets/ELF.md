# Identity ELF observations

`DeclaredInventory::inspect_identity_elf(id, bytes, ElfLimits)` accepts one immutable
borrowed byte slice. It checks the selected record's identity encoding and reruns
exact size/SHA-256 verification on that slice before parsing it. The result has
private fields and read-only getters. Earlier `EncodedBlobMatch` values cannot be
substituted for bytes. Each call creates its own explicit verification budget;
callers own aggregate invocation budgets and the allocation/time used to obtain bytes.

This is a bounded header inspection, not an executable validator or installation
permit. A malicious ELF can satisfy these checks. No code is executed or loaded,
no path is opened by this API, and this identity entry point decodes no compression. The caller's
manifest is still a declaration: matching its digest does not authenticate a publisher.

ELF32/ELF64 little-endian machine/class must match the declared target. Accepted
object types are ET_EXEC or ET_DYN with a nonzero entry in an executable PT_LOAD
memory range. ET_DYN here is an observation, not proof of PIE executable identity.
File-backed ranges, memory arithmetic, alignment congruence, table counts, and
interpreter termination are checked. Dynamic entries come from PT_DYNAMIC, so
stripped section tables do not hide DT_NEEDED. Names are resolved through an
unambiguous file-backed PT_LOAD mapping of DT_STRTAB/DT_STRSZ. DT_NEEDED names and
interpreter bytes are untrusted data; callers must escape them before display.

The maintained `object 0.39.1` low-level ELF header/segment/section interfaces are
used with default features disabled (`read_core`, `elf`, `std`). No unified
multi-format parser or implicit section decompression is enabled. Integer dynamic
tags are decoded directly from bounded little-endian entries.

Default limits: 256MiB borrowed executable, 128 program headers, 4096 section
headers, 4096 dynamic entries, 4096 interpreter bytes, 64 dependency names (each
at most4096 bytes, controlled independently by `dependency_name_bytes`),
and256KiB aggregate ARM attribute section bytes. These are
selected engineering policies, not measured release requirements. Counts are
checked before iteration/allocation; additions and ranges are checked. Extended
ELF counts use the parser's checked section-zero access, then the same limits.
Custom nonzero limits remain caller-selected resource policy.

`LoaderFamily` recognizes a small explicit set of standard musl/glibc loader paths.
A known opposite-libc loader yields `LoaderRelation::KnownMismatch`. Every other
case yields `Unresolved`, including a matching family or absent interpreter.
Unknown/custom loader paths are preserved. No PT_INTERP does not establish static
linkage or libc independence. Dynamic dependency names are observations only:
transitive closure, library availability, symbol versions, RPATH/RUNPATH, CPU
instructions, OSABI/ABI-version meaning and kernel requirements are not resolved.

For ARM, raw e_flags and hard/soft/missing/conflicting float flags are exposed.
A soft flag is visibly incompatible with the hard-float target obligation; no
public API promotes it (or any other flags) to compatibility. EABI version is
available in raw flags. SHT_ARM_ATTRIBUTES presence and aggregate byte bounds are
checked, but tag payloads are not interpreted. Missing/conflicting flags, ARMv7
CPU level and PCS agreement remain unresolved. RISC-V ISA/float ABI and GNU property
CPU requirements likewise remain outside this slice. A future policy must reject
or qualify unresolved facts before deployment; no blanket success token exists.

Independent tests construct raw ELF bytes using fixed System V offsets, not the
object writer. Their manifest hashes are recomputed after malformed mutations so
checks reach the ELF layer. Four exact published API/Kine artifacts are qualified
separately by `tools/assets-elf`; the trusted Rust test reads but never executes them,
and Python struct-based observations supply the independent comparison.

The additive [`DecodeSession::inspect_compressed_elf`](DECODE.md#compressed-executable-elf-composition)
uses the same private ELF parser after complete bounded decoding of a compressed
executable. Its aggregate budgets are retained by the decoding session. The shared
parser does not weaken these observations into a runtime compatibility claim.
