# Changelog

All notable changes to `checkpointed-local-log` (the `cll` Python package)
are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## 0.1.0

### Added — the `cll` package: spec + reference library + vectors

Initial release of the `cll` Python package, extracted from `capsule-emit`
(`capsule_emit.checkpoint`) and `capsule-ledger`'s surviving ledger core per
the W3 one-neutral-library-per-spec decision. `cll` ships:

- **Append-only log store + hash chains** (`cll.ledger`) — JSONL segments
  plus a derived SQLite index, the three-state admission contract, and
  chain-gap detection (`chain.parent_capsule_id` hash-chain integrity).
- **Merkle Mountain Range (MMR)** (`cll.checkpoint.core`/`.index`/`.store`) —
  the pure MMR position math, domain-separated hashing, and
  inclusion/consistency proofs this spec's checkpoints commit to.
- **Signed COSE checkpoints** (`cll.checkpoint.emit`/`.cose_wire`) —
  building, signing, and registering checkpoints with a Transparency Service
  over the COSE_Sign1 wire form, plus Transparency Service witness-stamp
  verification (three-state: WITNESSED / UNVERIFIED / INVALID).
- **Disclosure bundles** (`cll.checkpoint.bundle`) — the record/range-level,
  offline-verifiable evidence package (inclusion proof + covering checkpoint
  + witness stamp + consistency proof) for handing one log record to a
  stranger; content-agnostic (parameterized leaf-id/kind fields, no
  hardcoded capsule vocabulary).

See [`docs/module-map.md`](docs/module-map.md) for the section-by-section map
from `draft-mih-scitt-checkpointed-local-log-00` to the package's modules,
including two known gaps flagged (not yet fixed): the -00 draft's checkpoint
claim names don't yet byte-match the shipping field names, and RFC9338 stub
countersignatures aren't wired yet.

`cll` installs standalone (`pip install checkpointed-local-log`); its own
test suite is green (167 passed, 1 skipped — the opt-in live-TS network
test). `capsule-emit` (0.7.0+) and `capsule-ledger` depend on it rather than
each forking their own MMR/checkpoint/ledger-store implementation.
