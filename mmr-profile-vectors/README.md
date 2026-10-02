# Draft-exact vectors for draft-bryce-cose-receipts-mmr-profile-03

Known-answer vectors for the MMR receipt profile, derived **from the -03 text
alone**. They are the draft's values, not this repository's: checkpointed-local-log
(CLL) uses a different leaf hash and a different proof format, so CLL's own vectors
(`../mmr-conformance-vectors/`) do not test the draft, and these do not test CLL.

| | |
|---|---|
| Draft | `draft-bryce-cose-receipts-mmr-profile-03` (R. Bryce, J. Geater, 19 September 2026) |
| Text | <https://www.ietf.org/archive/id/draft-bryce-cose-receipts-mmr-profile-03.txt> |
| sha256 of that text | `fba4838118dad19733ab6c6dbdcb92f799ccfa35db38ae3a6c1e17b84b8b56d7` |

## How they were made

`draft03.py` transcribes the -03 pseudocode (Sections 4.1, 5.2, 6.1, 7.1.1, 8.1,
8.2.1, 9.1, 9.2 and Appendix A). As printed, the pseudocode does not run:
`all_ones` is false for every input, so `index_height` never returns. The
transcription therefore applies **only the repairs the -03 prose itself states**,
and names each one. Every repaired line is marked `REPAIR R<n>` in `draft03.py`,
and each vector lists the repairs it depends on in `repairs_applied`.

| id | repair | where the -03 text states it |
|---|---|---|
| R1 | `all_ones`: `mask = (most_sig_bit(pos) << 1) - 1` | A.4 prose: "b0111 would be true" |
| R2 | `append` returns the node count after the append (the index the next node takes) | 8.1 listing comments (`i - 2^(g+1)`, `i - 1`, `H(i + 1 \|\| ...)`) and Section 2 `pos = i + 1` |
| R3 | right-peaks: discard as many tree-size-2 peaks as `consistent_roots` returns, not `len(proofs)` | 7.1 step 7 (6.1 as printed disagrees) |
| R4 | the consistent accumulator is the roots followed by the **values** in `right-peaks` | Section 6 CDDL comment on `right-peaks` |
| R5 | `accumulatorfrom` is a trusted verifier input (the proof does not carry it) | 7.1.1 "Given" list |
| R6 | both cardinality checks in `consistent_roots` are executed and raise | 7.1.1 prose MUST and `# ... -> ERROR` comment |
| R7 | a size n is complete iff `index_height(n) == 0`; incomplete sizes are rejected | 9.2 names the test, not the value; 0 is the only value for which it holds |
| R8 | the inclusion input is `SHA-256(entry)` | 8.1 "f the leaf value resulting from H(x)" |

Not repaired, because the -03 prose does not state it: leaf/interior domain
separation, a leaf-only check on a proof's index, de-duplication by position in
`consistent_roots`, a byte encoding for the consistency accumulator, the 64-bit
bound on `2 << g`. The `hazard-*` vectors show what -03 accepts as a result.

No COSE_Sign1 receipts are included. -03 does not define the detached payload
bytes of a receipt of consistency, so the set stops at the proof layer: node
values, proof paths, the deterministic CBOR of each proof per the -03 CDDL, and
the accumulator a verifier must reach.

## Layout

Same shape as the RFC 9162 vectors in
[ietf-wg-scitt/examples `test-vectors/scitt-cose/`](https://github.com/ietf-wg-scitt/examples/tree/main/test-vectors/scitt-cose):

```
manifest.json          index: provenance (draft + sha256), the named repairs, every vector with its expectations inline
SHA256SUMS             digest of every v1/ file
v1/<vector-id>/expected.json
draft03.py             the transcription (Code Components under the IETF Revised BSD terms)
generate.py            deterministic generator; --check verifies the committed bytes
STATUS-03.md           each SCITT-list review finding marked fixed or still open in -03
```

Conventions: SHA-256; interior node `SHA-256(be64(pos) || left || right)` with
`pos = index + 1`; leaf node `SHA-256(entry)`. **`tree_size`, `tree_size_1` and
`tree_size_2` are MMR node counts, not leaf counts** (MMR(39) holds 21 leaves).
The fixture appends 21 entries, `"draft-bryce-cose-receipts-mmr-profile-03 vector
entry {k}"` for k = 0..20 (UTF-8), giving MMR(39), the size the draft's reference
implementation also uses for its known-answer test.

## The vectors

| id | result | what it pins |
|---|---|---|
| `prim-all-ones` | VALID | A.4 as printed vs R1, pos 1..16 |
| `prim-index-height-mmr39` | VALID | heights of all 39 nodes |
| `prim-peaks-complete-sizes` | VALID | peaks of every complete size up to 39, with leaf counts |
| `prim-add-leaf-hash-4` | VALID | 4 leaves give 7 nodes under R2 (5 under the other reading) |
| `fixture-mmr39` | VALID | every node value of MMR(39) |
| `inc-leaf0-size3`, `inc-leaf0-size39`, `inc-leaf3-size8`, `inc-leaf17-size39` | VALID | inclusion paths to a peak |
| `inc-leaf2-size4`, `inc-leaf4-size8`, `inc-leaf20-size39` | VALID | a leaf that is itself a peak: empty path (which -03's `[ + bstr ]` CDDL rejects) |
| `inc-interior2-size7` | VALID | -03 lets an index name an interior node |
| `fail-inc-tampered-path` | INVALID `TAMPERED_INCLUSION_PATH` | one bit flipped in a path node |
| `fail-inc-wrong-index` | INVALID `WRONG_INDEX` | honest path under the wrong index |
| `fail-inc-wrong-entry` | INVALID `WRONG_ENTRY` | honest path, other entry |
| `hazard-interior-alias` | VALID under -03 | 72 bytes never appended verify as an "entry" at interior index 2 |
| `hazard-empty-path-index-rebind` | VALID under -03 | an empty-path receipt verifies under any index |
| `con-4-to-8-merge` | VALID | **the merge case**: MMR(4) peaks [2, 3] both reach peak 6; right-peaks must be [7]; 6.1 as printed gives [] |
| `con-3-to-7`, `con-7-to-8`, `con-8-to-15-merge`, `con-10-to-39`, `con-1-to-39`, `con-39-to-39` | VALID | growth, unchanged peaks, a second merge, multi-peak, same size |
| `fail-con-right-peaks-6-1-as-printed` | INVALID `RIGHT_PEAKS_COUNT` | the merge case with 6.1's right-peaks |
| `fail-con-tampered-path` | INVALID `TAMPERED_CONSISTENCY_PATH` | one bit flipped in a consistency path |
| `fail-con-wrong-accumulator-from` | INVALID `ACCUMULATOR_MISMATCH` | wrong trusted origin accumulator |
| `fail-con-cardinality` | INVALID `CARDINALITY_MISMATCH` | one origin peak value where MMR(4) has two |
| `fail-con-incomplete-size-2` | INVALID `INCOMPLETE_TREE_SIZE` | tree-size-2 = 9 is not a complete size |

## Reproduce

```bash
python3 mmr-profile-vectors/generate.py --check     # committed bytes == generator output
python3 -m pytest tests/checkpoint/test_mmr_profile_vectors.py
cd mmr-profile-vectors && shasum -a 256 -c SHA256SUMS
```

The test also checks the transcription against an independently built
post-order tree, and every inclusion and consistency pair of complete sizes up
to MMR(39).

## Status and next step

These vectors are pinned to the -03 text. The draft is changing (the editors'
repository has merged and open fixes for several of the points above since -03
was posted), so they will be **regenerated against -04** once it is posted and the
fixes settle, and then offered to
[ietf-wg-scitt/examples](https://github.com/ietf-wg-scitt/examples). Until then
they live here. A disagreement with your implementation is a useful report:
open an issue with the vector id.

## Relation to CLL

CLL implements an MMR with the leaf/interior domain separation reviewers asked
for: its leaf is `SHA-256(0x00 || body_digest)`, a 33-byte preimage that can
never equal a 72-byte interior preimage. Its interior hash has the same form as
the draft's. So CLL's node array equals the -03 tree whose application
leaf preimage is `0x00 || body_digest` (the test checks this), but CLL's roots,
proof formats and accumulator encoding differ from -03, and CLL's vectors are
not the draft's.
