# Changelog: evidencebook (Rust)

## 0.0.3

- Depends on `checkpointed-local-log` 0.3.1 (which has no default witness
  client, and adds `cll::log`). Nothing in this crate used the removed
  default. Version 0.0.2 was never published: the manifest carried it before
  the merged-bump release workflow existed, so this release takes 0.0.3.

## 0.0.1

- First release on crates.io. Depends on `checkpointed-local-log` 0.2.0.
- Content as in the `rust-evidencebook-v0.1.0` git tag. That tag is not a
  crates.io version and is not moved.
