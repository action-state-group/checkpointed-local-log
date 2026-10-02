# Review findings against draft-bryce-cose-receipts-mmr-profile-03

Status of each finding from the from-the-text reviews on the SCITT list, checked
against the **published -03** (19 September 2026, sha256
`fba4838118dad19733ab6c6dbdcb92f799ccfa35db38ae3a6c1e17b84b8b56d7`). "txt" line
numbers are lines of that .txt file. The last column is informative only: what
the editors' repository (robinbryce/draft-bryce-cose-receipts-mmr-profile) shows
on 1 October 2026, after -03 was posted.

-03 is the text the reviews were written against (the `-03` tag, 54b1b33, is
9232f58 plus an address change), so every review finding is still open in -03.
The three -02 items Michael Msebenzi listed as already fixed on main are fixed in -03.

Reviews: Michael Msebenzi, 4 Aug and 25 Aug 2026; Henri Sirkkavaara, 28 Aug 2026;
Anton Sokolov, 28 Aug 2026 (section numbers below are his); Konrad Gruszka, 30 Sep
2026 (adoption thread).

| # | Finding | Raised by | -03 location | In -03 | Since -03 (editors' repo, 1 Oct) |
|---|---|---|---|---|---|
| 1 | `all_ones` is never true; `index_height` never terminates | Msebenzi, Sirkkavaara, Sokolov 1.1, Gruszka | A.4 (txt 1076), 9.1 | STILL OPEN | PR #56 open (issue #15) |
| 2 | `add_leaf_hash` is one node behind: the `append` return convention is unstated | Sirkkavaara, Sokolov 1.1 | 8.1 (txt 736, 756) | STILL OPEN | PR #55 open (issue #16) |
| 3 | Leaf/interior aliasing: no domain separation, no leaf-only check on the proof index | Msebenzi, Sirkkavaara, Sokolov 1.3 | 2 (txt 183), 8.1, 8.2, 5.2 | STILL OPEN | issue #13 open; PR #54 open (partial) |
| 4 | `accumulatorfrom` is not carried by the wire format and is not defined as a trusted input | Msebenzi, Sokolov 2.1 | 7.1 step 2 (txt 626) | STILL OPEN | issue #22 closed |
| 5 | The cumulative consistency loop never advances; chaining between proofs is undefined | Msebenzi, Sokolov 2.1 | 7.1 steps 1, 9 (txt 624, 645) | STILL OPEN | issue #23 closed |
| 6 | Right-peaks discards `len(proofs)`; MMR(4) to MMR(8) loses peak 7 | Sokolov 1.2 | 6.1 (txt 537) vs 7.1 step 7 (txt 639) | STILL OPEN | PR #44 merged (issue #17) |
| 7 | The verifier never reads the `right-peaks` field; `peaks()` returns indices | Sokolov 2.1 | 7.1 steps 6, 8 (txt 636, 642) | STILL OPEN | issue #24 closed |
| 8 | `consistent_roots` de-duplicates by value, not position | Sokolov 1.4 | 7.1.1 (txt 702) | STILL OPEN | issue #18 closed |
| 9 | Cardinality: prose MUST and code comment check different lengths; neither runs | Msebenzi, Sokolov 1.6 | 7.1.1 (txt 662, 695) | STILL OPEN | issue #19 closed |
| 10 | Detached payload bytes of the consistency accumulator are undefined | Sokolov 2.1 | 7.1 step 9 (txt 645) | STILL OPEN | PR #45 merged: concatenation, descending height (issue #29) |
| 11 | Consistency paths are not required to end at a peak of tree-size-2 | Sokolov 2.1 | 7.1.1 | STILL OPEN | issue #25 closed |
| 12 | `inclusion-path: [ + bstr ]` rejects the empty path the prose allows | Sokolov 1.5, Gruszka | 4 (txt 235) | STILL OPEN | issue #28 open; PR #57 open |
| 13 | With an empty path, the index is not authenticated | Sokolov 1.5 | 5.2 | STILL OPEN | issue #14 open |
| 14 | Inclusion input is ambiguous between entry bytes and node hash | Sokolov 2.2 | 5.1 (txt 379) | STILL OPEN | issue #26 open |
| 15 | Several inclusion proofs under one signature have no defined meaning | Sokolov 2.2 | 5 (txt 355) | STILL OPEN | issue #30 open |
| 16 | Path-length SHOULD needs a tree size the inclusion proof does not carry | Msebenzi, Sokolov 2.2 | 5.1 (txt 403) | STILL OPEN | issue #27 closed (PR #48) |
| 17 | IANA: no paired "COSE Verifiable Data Structure Proofs" entries; no Change Controller | Msebenzi, Sokolov 2.3 | 12 (txt 928-950) | STILL OPEN | issue #33 open |
| 18 | Normative references: cites the I-D (-18), not RFC 9942; omits RFC 9052 and RFC 9162 | Msebenzi, Sokolov 2.4 | 13.1 (txt 971-979) | STILL OPEN | issue #34 open |
| 19 | `TBD_1` is an undefined name inside the CDDL | Sokolov 2.4 | 5, 7 (txt 343, 580) | STILL OPEN | issue #35 open |
| 20 | Inline "Hash algorithm agility is tbd" contradicts the editor's note | Msebenzi | 8.2.1 (txt 822) vs 12 (txt 957) | STILL OPEN | issue #36 open; PR #57 open |
| 21 | No 32-byte size rule for proof nodes and peaks | Sokolov 2.4 | 4, 6 CDDL | STILL OPEN | issue #31 open |
| 22 | tree-size-1 = 0 gives ifrom = -1 | Sokolov 2.4 | 7.1 step 3 (txt 629) | STILL OPEN | PR #50 merged (issue #32) |
| 23 | `2 << g` overflows 64 bits at the stated maximum height | Sokolov 2.4 | 2 (txt 194) | STILL OPEN | PR #56 open (issue #21) |
| 24 | The completeness test's value and the rejection are unstated | Sokolov 2.4 | 9.2 (txt 864) | STILL OPEN | PR #56 open (issue #20) |
| 25 | Editorial: consistency sections labelled "inclusion", `consistency_proof_path(s)`, "tres-size-2" | Msebenzi (issue #6) | 6.1 (txt 555), 7 (txt 576), 7.1 (txt 639) | STILL OPEN | PR #53 merged; issue #37 open |
| 26 | -02: `&(vds: 395) => 3` hard-coded | Msebenzi (fixed on main) | 5, 7 (txt 343, 580) | FIXED | — |
| 27 | -02: `consistency-proof` (singular) as the map value | Msebenzi (fixed on main) | 7 (txt 595) | FIXED | — |
| 28 | -02: "pos the size of the MMR" | Msebenzi (fixed on main) | 2 (txt 180) | FIXED | — |
| 29 | tree-size-1 / tree-size-2 are node counts, but the text never says so (RFC 9162 tree sizes count leaves) | new here | 6 CDDL (txt 516) | STILL OPEN | not raised as an issue |

The vectors in this directory apply only the repairs the -03 prose states for
rows 1, 2, 4-7, 9, 14 and 24 (R1-R8 in `README.md`). They do not repair rows 3,
8 or 13; the `hazard-*` vectors show the effect.
