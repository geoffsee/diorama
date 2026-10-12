# Rubix YAML 1.1 scanner compatibility

This is the crates.io `saphyr-parser` 0.0.11 release, archive SHA-256
`ebfd783fcf1b3f6bafd557be0e1427ec54f826f513c3cdd749f9844484df2a13`.
`RUBIX-PROVENANCE.json` records every original packaged file hash. Original
licenses, notices, manifest and dependency requirements remain intact. The
separate `RUBIX-COMPATIBILITY.patch` contains the complete local source delta;
`src/char_traits.rs`, `src/scanner.rs` and `src/input/str.rs` differ from the published release.

Rubix selects `Parser::new_from_iter(input.chars())`, using `BufferedInput`.
The `StrInput` break predicates and document-marker suffix checks also decode
complete Unicode characters, keeping the public string constructor consistent with
the shared YAML 1.1 break classification. ASCII-only predicates keep their byte
fast paths. Both public parser constructors replay all 57 independent Go
line-break observations and Unicode document/comment/flow cases in an isolated
regression subprocess with a ten-second deadline; a stalled scanner is killed
and reaped rather than hanging CI. Rubix retains the iterator constructor.
No runtime dependencies were added. The root lock retains thiserror 2.0.18 to
avoid duplicate syn major versions alongside the Kubernetes generators.

The patch restores source-character semantics required by the pinned Go baseline:
NEL is a normalized LF; LS/PS remain distinct line breaks; CRLF remains one break,
while CR followed by another Unicode separator remains two. Plain/quoted/block
folding and chomping distinguish LF from LS/PS. A closing quote may terminate a
scalar below its parent indentation, matching baseline-emitted YAML; nonclosing
text still follows the upstream indentation checks. Quoted escapes remain data
and backslash line continuations use the scanner's existing state machine.

The rejected preprocessing prototype is not present. Original input-size,
expanded-node/string-byte and depth budgets remain in `rubix-config`; aliases are
charged before copying. There is no sentinel namespace or normalization-expansion
allocation. Upstream library unit tests pass (5); 57 direct pinned Go `config.Read`
observations and the preexisting 17 Rubix compatibility tests pass. The Go capture
includes raw typed JSON before YAML printing, because its emitter loses escaped
NEL. That printer difference is separately owned by E03.02.

The upstream YAML 1.2 conformance suite is not claimed as a qualification gate for
these deliberately selected YAML 1.1 semantics. An upgrade must replay the direct
Go oracle, resource-limit tests and upstream tests, review the source patch and
qualify the selected input implementation. Replacing this fork with an upstream
YAML 1.1 mode is preferred if equivalent behavior becomes available.
