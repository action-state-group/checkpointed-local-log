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
checkpointed-local-log = "0.3"
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
- `witness`: witness registration of checkpoint digests (`/v1/digest`).
- `runner`: the checkpoint runner: indexes a `log` store's entries into its
  MMR and signs a COSE checkpoint on an entry-count or age cadence.
- `witness_delivery`: delivers queued checkpoints to witnesses'
  `/checkpoints` route with bounded exponential retry; the host supplies the
  receipt verifier.
- `log`: the storage interfaces shared with the Go, TypeScript and Python
  implementations (entry log, checkpoint state, witness state), with
  `memory` and `jsonl` backends, `sqlite` and `mysql` backends behind Cargo
  features of the same names, and a conformance runner for any backend.

```toml
checkpointed-local-log = { version = "0.3", features = ["sqlite"] }
```

```rust
use cll::log::{memory::MemoryStore, AppendInput, EntryStore, Timestamp};

let log = MemoryStore::new();
let result = log
    .append(&AppendInput { value: vec![7; 32], appended_at: Timestamp::now() })
    .unwrap();
assert_eq!(result.entry.seq, 1);
```

## Tests

The tests read the conformance vectors at the root of the
[repository](https://github.com/action-state-group/checkpointed-local-log),
so they run from a checkout, not from the published package:

```
cargo test
CLL_MYSQL_URL=mysql://user:pass@127.0.0.1:3306/cll cargo test --all-features
```

The MySQL tests skip when `CLL_MYSQL_URL` is unset, and fail instead when `CI`
is set.

## Changes

See [CHANGELOG.md](CHANGELOG.md).
