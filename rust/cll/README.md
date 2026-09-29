# checkpointed-local-log (Rust)

A Rust implementation of the Checkpointed Local Log (CLL): an append-only log
committed by a Merkle Mountain Range (MMR), with signed COSE checkpoints,
per-record inclusion and range proofs, and witness registration. It follows
the checkpointed-local-log Python reference and is tested against the same
conformance vectors.

The crate is published as `checkpointed-local-log`; the library is named
`cll`:

```toml
[dependencies]
checkpointed-local-log = "0.2"
```

```rust
use cll::mmr::{add_leaf, MemoryNodeStore};
```

## Modules

- `mmr`: the Merkle Mountain Range: leaves, peaks, roots, and inclusion and
  consistency proofs.
- `checkpoint`: signed COSE checkpoints and their verification, over a
  pluggable signer.
- `range_proof`: per-record inclusion proofs and range proofs.
- `store`, `node_store`: the log store and a durable, file-backed MMR node
  store.
- `witness`: witness registration of checkpoints.

## Tests

The tests read the conformance vectors at the root of the
[repository](https://github.com/action-state-group/checkpointed-local-log),
so they run from a checkout, not from the published package:

```
cargo test
```

## Changes

See [CHANGELOG.md](CHANGELOG.md).
