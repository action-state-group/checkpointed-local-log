# Changelog: checkpointed-local-log (Rust)

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
