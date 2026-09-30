# Changelog: evidencebook (Rust)

## Unreleased

- `CllSubstrate::reprove_cose(checkpoint, from_size, from_root, signer)`:
  re-sign a checkpoint so it chains from a witness's last-accepted
  `(from_size, from_root)`, with a consistency proof from there, in the COSE
  wire form. For a witness that refused the checkpoint (HTTP 409) because it
  never saw the checkpoint's own prev (a push-time cut, or a restart). Nothing
  is persisted. Refuses a `from_size` not below the checkpoint's size
  (`SubstrateError::ReproveNotBehind`) and a witness root this log does not
  hold (`SubstrateError::ReproveRootMismatch`).

## 0.0.1

- First release on crates.io. Depends on `checkpointed-local-log` 0.2.0.
- Content as in the `rust-evidencebook-v0.1.0` git tag. That tag is not a
  crates.io version and is not moved.
