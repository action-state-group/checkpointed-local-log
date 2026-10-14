# Vectors for draft-mih-scitt-checkpointed-local-log-02

Known-answer vectors for the -02 checkpoint: the log, every accumulator, a
four-checkpoint chain, and one-change negative cases. They are generated from
the -02 text on top of the MMR profile's editors' copy, **without importing
any of this repository's implementations**, so the four implementations are
checked against them rather than producing them.

| | |
|---|---|
| CLL draft | `draft-mih-scitt-checkpointed-local-log-02` (`../spec/`) |
| MMR profile | `draft-bryce-cose-receipts-mmr-profile-03`; algorithms from editors' main [`f1320c0`](https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile/blob/f1320c0/draft-bryce-cose-receipts-mmr-profile.md) |

## Files

```
profile_main.py   the profile's pseudocode as printed on editors' main (no repairs needed)
cll02.py          the -02 encoder and reference verifier, written from the -02 text
generate.py       deterministic generator; --check verifies every committed byte
vectors.json      the vectors
SHA256SUMS        digest of vectors.json
```

`generate.py` also writes the pinned copies the Go and TypeScript tests read
(`go/mmr/testdata/cll02_vectors.json`, `ts/test/testdata/cll-02-vectors.json`),
and `--check` fails if either differs from `vectors.json` by a byte.

```
python3 cll-02-vectors/generate.py --check
```

needs `cryptography` (for Ed25519); nothing else.

## Conventions

- Entry k (k = 0..20) is `SHA-256(UTF-8 "cll-02 vector entry {k}")`; the leaf
  value is `SHA-256(0x00 || entry)`, appended with `add_leaf_hash`. 21
  entries make MMR(39).
- `log_size` is the MMR tree size (node count); `leaf_count` is the entry
  count. `sizes` lists both for every prefix of the log, with the peaks, the
  `commitment` (peaks concatenated tallest first), and `commitment_sha256`
  (the `as-transmitted` digest of the `cll-checkpoint` artifact type).
- `consistency_proof` is the profile's `consistency-proof`:
  `bstr .cbor [tree-size-1, tree-size-2, consistency-paths, right-peaks]`.
- Payloads are deterministic CBOR (RFC 8949 Section 4.2.1). Checkpoints are
  COSE_Sign1 with alg -19 (Ed25519, RFC 9864), `kid` = the raw public key,
  and CWT_Claims `{1: iss, 2: sub}` where `sub` is the log and never changes.
  The fixture seed is `0x07` repeated, as in `../checkpoint-conformance-vectors/`.
  Ed25519 is deterministic, so `cose_hex` is a byte-exact pin.

## Cases

`checkpoints` is one log's chain, registered in order at one Transparency
Service (`continuity` is what that service's Consistency Registration Policy
concludes):

| id | leaves | log_size | prev_size | proof | continuity |
|---|---|---|---|---|---|
| cp1 | 3 | 4 | 0 | none (first) | first-seen |
| cp2 | 7 | 11 | 4 | 2 paths, 2 right-peaks | continuous |
| cp3 | 7 | 11 | 11 | none (no growth) | continuous |
| cp4 | 21 | 39 | 11 | 3 paths, 2 right-peaks | continuous |

`negative` changes one thing in an honest checkpoint and names the -02 check
it breaks (`failure_code`); `registered` is the service state a
registration case is evaluated against. Every case is re-evaluated by
`generate.py` on every run, and the run fails if the reference verifier's
conclusion differs.

| id | breaks |
|---|---|
| fail-commitment-cbor-array | commitment length (-01 CBOR-array encoding) |
| fail-log-size-is-leaf-count | commitment length (entry count written as `log_size`) |
| fail-log-size-incomplete | complete-size rule |
| fail-leaf-count-mismatch | `leaf_count` rule |
| fail-proof-missing | proof required when the log grew |
| fail-proof-legacy-map | proof must be the profile's `consistency-proof` |
| fail-proof-tampered-path | consistency |
| fail-proof-paths-disagree | every path to one peak must agree |
| fail-proof-right-peaks-count | consistency |
| fail-proof-sizes | proof sizes must equal `prev_size`/`log_size` |
| fail-proof-on-first | no proof on a first checkpoint |
| fail-no-growth-commitment-changed | equal sizes need equal commitments |
| fail-commitment-not-extension | consistency |
| fail-registration-not-continuous | registration continuity (skips a registered checkpoint) |
| sub-per-checkpoint-is-first-seen | not a failure: a per-checkpoint `sub` makes continuity silently unchecked |

## Implementations

Each implementation runs these vectors in two layers:

- **Log layer, must pass:** node values, `log_size` as the node count, every
  accumulator, and the implementation's own consistency proof mapped onto the
  profile's (its per-peak witnesses are the consistency-paths; the right-peaks
  are the new peaks no path reaches).
- **Wire layer, pinned gap:** the implementations still emit the -01 wire
  form. These tests assert the difference, so they fail the day an
  implementation emits -02, and must then become equality tests.

| | log layer | wire layer |
|---|---|---|
| Python | `python/tests/checkpoint/test_cll02_vectors.py` | strict xfail |
| Go | `go/mmr/cll02_vectors_test.go` | `go/checkpoint/cll02_wire_test.go` |
| TypeScript | `ts/test/cll02-vectors.test.ts` (Node and browser paths) | same file |
| Rust | `rust/checkpointed-local-log/tests/cll02_vectors.rs` | same file |

The Python test also checks that `profile_main.py` reproduces the -03 vectors
in `../mmr-profile-vectors/`, so the two transcriptions of the profile agree
where the texts do.
