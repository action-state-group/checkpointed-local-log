# CLL MMR conformance vectors

Shared, byte-pinned MMR roots plus inclusion, consistency, and range proofs for
Go and TypeScript implementations to consume. The Python `cll.checkpoint.core`
implementation is the reference that generated the expected values; the test
suite regenerates and verifies every vector against it.

The set includes both positive cases (`expect` absent or `true`: the proof must
regenerate byte-for-byte and verify) and interior-tamper negatives (`expect:
false`: a mutated leaf or witness that verification MUST reject). A consumer whose
`verify_inclusion`/`verify_consistency`/`verify_range` silently accepts a tampered
proof, or whose range check only binds the two endpoints, fails these negatives —
so the shared set now covers negative-path parity, not just positive byte-parity.

## Fixture and conventions

For each `seq` from 1 through 7, the body digest is
`sha256(UTF-8("asg-ledger-mmr-vector-leaf-{seq}"))`; the MMR receives
`leaf_hash(body_digest)`. Every case includes the exact fixture sequence range
it uses. `leaf_index` is the zero-based MMR leaf index: `leaf_index == seq -
1`. `size`, `size_a`, and `size_b` are flat MMR **node** counts, not leaf
counts.

All digest fields and proof elements are lower-case, 32-byte hexadecimal
strings. The proof shapes directly match `InclusionProof` and
`ConsistencyProof`; JSON arrays correspond to their tuple fields.

## Hashing and independent hand derivation

The vectors exercise the production domain separation:

```
leaf     = sha256(00 || body_digest)
parent  = sha256(be64(parent_position + 1) || left || right)
root    = fold peaks from the right with sha256(right || left)
```

Here is a standalone `hashlib.sha256` derivation, without calling a CLL hash
helper, for the 5-leaf root and its first-leaf inclusion chain. It also makes
the domain-separation bytes and position commitments reviewable.

```
body[1] = c0fce8ae20e1ec53ba801443d30ef6d262a81de1610736eefdef40764f1ec4fe
leaf[1] = H(00 || body[1]) = 184208f662bb7a6f5cc14a39988f74f2bb05bd3f934311da0aa3f65a950d8e01
leaf[2] = H(00 || body[2]) = be87c6b74ae0f1a5b9dcc48a8b8ea403e7183d11abbe3cd8f423d23974d6b31e
p[2]    = H(be64(3) || leaf[1] || leaf[2]) = f7b19d3f831d2cddfe91865465a8beb649e4bf16c3aa2fde7378e7ee2e215694
p[5]    = H(be64(6) || leaf[3] || leaf[4]) = 05c9493be026d8315757aa79d5bea709b5e51fb8ce61c011a55bb78a04ce20c1
p[6]    = H(be64(7) || p[2] || p[5]) = 44588de7a213cb67d681fd0822d22f57248a50b5cab4d5579c1d9162403b6755
leaf[5] = H(00 || body[5]) = 71235381e2cb35478270e72fab0bc96ac0ee43de2078f035c240687fbe9365bb
root[5] = H(leaf[5] || p[6]) = a19de527084fc32502d998b4dd0e73f942d3b4ddc55b2c093dfd907e95a93f1a
```

Thus `inclusion-5-leaves-leaf-0` has witness `[leaf[2], p[5]]`, right peak
`[leaf[5]]`, and reaches the same `root[5]`. A missing `00` leaf prefix, a
missing position prefix, or an incorrect parent position changes these pinned
bytes.

## Files and use

- `vectors.json` contains 26 cases: 7 root, 8 inclusion, 6 consistency, and 5
  range. Four are negatives (`expect: false`): a flipped witness sibling for each
  of inclusion, consistency, and range, plus one **interior-leaf** tamper
  (`neg-range-interior-leaf-altered`) — a replaced interior body digest that only
  the every-leaf range binding rejects (a two-endpoint check would miss it).
  `range` cases carry `from_seq`/`to_seq`, `from_index`/`to_index`, the ordered
  `body_digests`, and a flat CLL range `witness`; every leaf in the interval
  participates in rebuilding the root.
- `reference_verifier.py` regenerates the fixture and checks exact proof
  structures and verification results with Python CLL.

Run `python3 mmr-conformance-vectors/reference_verifier.py` in an installed
development environment. Go and TypeScript consumers should parse the JSON
and compare every listed hexadecimal value exactly.
