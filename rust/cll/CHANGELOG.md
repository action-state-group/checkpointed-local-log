# Changelog: checkpointed-local-log (Rust)

## Unreleased

- **BREAKING: no default witness.** `impl Default for WitnessClient` and
  `witness::DEFAULT_TS_URL` are removed: build a client with
  `WitnessClient::new(url)` and the URL you choose.

## 0.2.1

- **Fixed: COSE checkpoint claims are now deterministic CBOR.**
  `checkpoint_to_cose` (via `encode_checkpoint_claims`) wrote the claims
  map in insertion order (`kind, log_size, commitment, prev_size,
  prev_commitment, issued_at`), not the RFC 8949 §4.2.1 deterministic order
  the Python reference emits. It now sorts every map, at every depth
  (including a `consistency_proof`), by its keys' encoded bytes. The
  claims payload is byte-identical to the Python reference's.
- **Checkpoints signed before this fix stay valid for Python but need
  re-signing for TypeScript.** The Python verifier accepts either order. The
  TypeScript verifier (`cll-ts`) requires deterministic encoding and rejects
  statements this crate signed at 0.2.0 or earlier. Re-sign any that a
  TypeScript consumer must check. Nothing else about the statement changed.
- New cross-language vector `checkpoint-conformance-vectors/cose-vectors.json`:
  the signed claims bytes every producer must emit, and a reference statement
  every verifier must accept. Checked here (`tests/checkpoint_cose_vectors.rs`)
  and by the Python reference verifier.

## 0.2.0

- First release on crates.io, as `checkpointed-local-log` (library name `cll`).
- A signer interface for checkpoints, so a checkpoint can be signed by a key
  the crate never holds.
- A durable, file-backed MMR node store.
- The same content as the `rust-cll-v0.2.0` git tag. That tag's manifest
  still reads 0.1.0; the tag is not moved.

## 0.1.0 (git tag `rust-cll-v0.1.0`, not published)

- The MMR, checkpoints, range proofs, the store and witness registration,
  matching the Python reference through the shared conformance vectors.
