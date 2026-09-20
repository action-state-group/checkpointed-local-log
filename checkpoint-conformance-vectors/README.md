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

- `vectors.json` contains 2 cases: `checkpoint-first-2-leaves` (a log's
  first checkpoint, `prev_size=0`, no consistency proof) and
  `checkpoint-chained-2-to-7-leaves` (a second checkpoint chained from the
  first via the MMR consistency proof bridging `size_a=3` to `size_b=11`).
- `reference_verifier.py` regenerates every case from `CheckpointRecord`
  plus the pinned seed and checks exact digest/signature match.

Run `python3 checkpoint-conformance-vectors/reference_verifier.py` in an
installed development environment. Rust, Go, and TypeScript consumers
should parse the JSON, reconstruct the record fields, and reproduce
`digest_hex`/`entry_digest_hex`/`signature` exactly -- see `rust/cll/tests/
checkpoint_conformance_vectors.rs` for this crate's own pass over the same
file, including offline COSE-wire verification of the chained case.
