# CLL checkpoint conformance vectors

Byte-pinned `CheckpointRecord` signing bodies, digests, and Ed25519
signatures for Go, TypeScript, Rust, and any other CLL implementation to
consume. The Python `cll.checkpoint.emit.CheckpointRecord` implementation is
the reference that generated the expected values; the test suite
regenerates and verifies every vector against it.

This is the checkpoint-layer sibling of `mmr-conformance-vectors/` (which
pins the MMR roots and proofs these checkpoints commit to) and
`commitment-conformance-vectors/` (which pins the MMRIVER-conformant
peak-list encoding). Together the three sets pin every byte a cross-language
CLL implementation must reproduce: leaves and roots, the external commitment
encoding, and the signed checkpoint record that wraps a root.

## Fixture and conventions

- `signing_key_seed_hex` is a deterministic 32-byte Ed25519 fixture seed
  (`0x07` repeated) -- not a real credential. Ed25519 signing is fully
  deterministic (RFC 8032): the same seed and message always produce the
  same signature bytes in any conformant implementation, so `signature`
  below is a genuine cross-language pin, not merely a self-consistency
  check.
- `key_id` is the raw 32-byte Ed25519 public key derived from that seed,
  hex-encoded -- the same value `CheckpointRecord.key_id` and
  `verify_checkpoint_signature_offline`/`verify_signature_offline` expect.
- `root`/`prev_root` and the chained case's `consistency_proof` are reused
  verbatim from `mmr-conformance-vectors/vectors.json`'s `root-2-leaves`,
  `root-7-leaves`, and `consistency-2-to-7-leaves` cases (leaf identity seed
  `asg-ledger-mmr-vector-leaf-{seq}`, `seq` 1..7) -- the same 7-leaf MMR
  fixture the MMR vectors already pin, so a consumer that has those roots
  right needs nothing new to reproduce these checkpoints.
- `digest_hex` = `sha256(signing_body_utf8).hexdigest()` where
  `signing_body` is the canonical JSON (`sort_keys=True,
  separators=(",", ":")`) of `{v, kind, log_id, mmr_size, root, prev_size,
  prev_root, key_id, timestamp}` -- this is the value a Transparency Service
  registers and the value `signature` is computed over (its ASCII bytes).
- `entry_digest_hex` = `sha256(canonical_json(to_dict())).hexdigest()` --
  the digest of the FULL persisted record (adds `signature`, omits nothing),
  what a checkpoint's own ledger stamp commits to.
- `signature` is the hex Ed25519 signature over `digest_hex`'s ASCII bytes.

## Files and use

- `cose-vectors.json` pins the COSE_Sign1 wire form of both cases below,
  signed with the same seed. `claims_hex` is the signed claims payload, a CBOR
  map in RFC 8949 section 4.2.1 deterministic order: every producer MUST emit
  exactly these bytes. `cose_hex` is the Python reference's whole statement:
  every verifier MUST accept it. The protected header is not pinned across
  producers (its map order is each COSE library's own), so a producer's own
  statement is checked by verifying it and comparing its payload with
  `claims_hex`. `reference_verifier.py` regenerates both byte-for-byte;
  `rust/checkpointed-local-log/tests/checkpoint_cose_vectors.rs` checks the Rust crate.

- `vectors.json` contains 2 cases: `checkpoint-first-2-leaves` (a log's
  first checkpoint, `prev_size=0`, no consistency proof) and
  `checkpoint-chained-2-to-7-leaves` (a second checkpoint chained from the
  first via the MMR consistency proof bridging `size_a=3` to `size_b=11`).
- `ed25519-vectors.json` pins how a verifier decides Ed25519 signatures on
  checkpoints and receipts, including inputs that platform libraries
  accept but a verifier must refuse because they need no private key.
  `ed25519_cases` are raw `(public_key, message, signature)` triples and
  `cose_cases` are whole checkpoint statements whose `kid` is the key. A
  verifier refuses A or R that is not a canonical encoding (y >= p, or x = 0
  with the sign bit set) or is of small order, and S >= L, and checks the
  cofactorless equation `[S]B = R + [k]A`. The `mixed-order A` cases (a key
  `aB + T` with a small-order `T`, signed by the holder of `a` with a
  challenge `k` that is a multiple of 8) must verify. For other `k`,
  `[k]T` is not the identity and the cofactorless check fails, so such a key
  is not usable in general.
  `generate_ed25519.py` writes the file with plain RFC 8032 arithmetic, so
  it depends on none of the verifiers it tests; `--check` fails when the
  file is out of date.
- `receipt-vectors.json` pins which witness receipts a receipt verifier
  accepts: COSE Receipts over the entry hash of `checkpoint-first-2-leaves`,
  signed by a fixture authority key, each with the `tree_size` and
  `leaf_index` a holder stores. Every CLL receipt verifier (Go
  `witness.ReceiptVerifier`, Python `ReceiptVerifier`, TypeScript
  `ReceiptVerifier`) decides each case as `accept` says, which is how
  agent-action-capsule's `VerifyCOSEReceipt` decides it since
  agent-action-capsule#523: a tag-18 COSE_Sign1 whose message, protected
  header and each inclusion-proof blob are one CBOR item under the receipt
  encoding rule of the AAC interop profile v1 §6.2.2 (definite lengths,
  shortest arguments, no repeated key, integer or text keys, valid UTF-8,
  integers from -2^63, no float, no simple value but false, true and null,
  no tag but the outer 18, at most 16 levels; map order is not checked),
  with a detached (null) payload, protected `vds` 1 and `alg` EdDSA, `crit`
  naming only present, understood labels, and 1 to 16 inclusion proofs that
  all decode and fit their tree, one of which rebuilds the root the
  signature covers. A holder also refuses a receipt whose stored position is
  not that proof's. Python checks the encoding rule and `crit` before
  `cll.ed25519.verify_receipt`, which is scitt-cose's `verify_receipt`: that
  alone decodes a proof blob leniently and admits tags, floats and simple
  values elsewhere in the receipt.
  `generate_receipts.py` assembles the receipts byte by byte, so it depends
  on none of the verifiers it tests; `--check` fails when the file is out of
  date. `go/witness/testdata/receipt-vectors.json` is a pinned copy.
- `reference_verifier.py` regenerates every case from `CheckpointRecord`
  plus the pinned seed and checks exact digest/signature match, and also
  checks the witness-receipt boundary: each case's `digest_hex` round-trips
  through scitt-cose's own `cll`-agnostic COSE Receipt build/verify path
  (`check_scitt_cose_receipt_interop`).

Run `python3 checkpoint-conformance-vectors/reference_verifier.py` in an
installed development environment. Rust, Go, and TypeScript consumers
should parse the JSON, reconstruct the record fields, and reproduce
`digest_hex`/`entry_digest_hex`/`signature` exactly -- see `rust/checkpointed-local-log/
tests/checkpoint_conformance_vectors.rs` for this crate's own pass over the same
file, including offline COSE-wire verification of the chained case, and
`rust/checkpointed-local-log/tests/scitt_cose_receipt_interop.rs` (`cargo test --features
python-interop-tests`) for the witness-receipt boundary check -- no Rust
scitt-cose verifier exists yet, so it drives that check by invoking this
same `reference_verifier.py` as a subprocess.
