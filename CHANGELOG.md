# Changelog

All notable changes to `checkpointed-local-log` (the `cll` Python package)
are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## Unreleased

### Changed — range proofs bind every leaf, not just the two boundaries

`cll.checkpoint.core`/`cll.checkpoint.index`'s `RangeProof`/`range_proof`/
`verify_range` no longer compose a pair of `InclusionProof`s for
`from_seq`/`to_seq` only. That shape proved the two boundary leaves were
genuine and the MMR structurally complete at `size`, but never touched any
leaf strictly between them — a deleted or replaced interior record still
verified. The proof now carries a leaf-independent sibling set
(`from_index`/`to_index`/`witness`): the caller supplies every leaf's own
body digest in the range, and `verify_range` rebuilds every peak the range
touches from those digests plus the witness hashes, so a deleted or
replaced interior leaf changes the peak it falls under and is caught.
`cll.ledger.segments.verify_segment` now passes every record's body digest
through, not just the first/last. **Breaking, wire-incompatible with the
old proof shape.**

Vectors: round-trip, single-leaf, first-leaf (index 0), three-leaf,
cross-peak, tampered-boundary, replaced-interior, deleted-interior, sparse
selection, mismatched checkpoint, and stability-across-appends
(`tests/checkpoint/test_mmr_index.py`) — including an explicit red→green
demonstration (reverting `verify_range` to the old endpoint-only rebuild
and confirming the deleted-/replaced-interior mutants pass it) that pins
down the exact bug class this change closes.

Ported byte-identically into `scitt-cose`'s `scitt_cose.cll` and the hosted
bundle viewer's `MMR_JS`/`BUNDLE_JS` (a separate repo/PR): the viewer's
"Completeness" ritual stage is renamed "Range membership", and its pass
copy now reads "records *from*–*to* are present, unaltered, and bound to
checkpoint *C* — this does not show that no other records exist" in place
of the old "N of N claimed records" phrasing.

## 0.3.0 — 2026-09-08

### Changed — `agent-action-capsule` floor raised to `>=0.3.0`

`LedgerStore.verify()` delegates Capsule validation to
`agent_action_capsule.verify` wholesale, so raising the floor to 0.3.0 (the
release carrying draft-04 `references[]` structural checks) guarantees those
checks run for every store without any code change here. No MMR/checkpoint
algorithm change. New append→fetch→verify integration tests cover a valid
reference, a reference duplicating `chain.parent_capsule_id`, a malformed
(non-hex64) reference digest, and a reference digest edited directly in a
stored JSONL segment (bypassing `append()`).

### Added — segment rotation at checkpoint boundaries

`cll.ledger.store.LedgerStore` gains opt-in (`rotate_at_checkpoint=False` by
default) byte-size-triggered segment rotation, closed on a checkpoint
boundary rather than a calendar: crossing `max_segment_bytes` (default 256
MiB) forces a checkpoint through an attached `cll.ledger.segments
.Checkpointer` (the out-of-the-box `MmrCheckpointer` wraps an `MmrLedger` +
any `cll.checkpoint.emit.Signer`), closes the segment exactly at that
checkpoint's boundary, and writes `segments/<log_id>-<mmr_size>
.manifest.json` — generic fields only (seq range, timestamps, byte/record
counts, a content digest, and a range proof over the segment's own boundary
leaves), so an archived segment is offline-verifiable from its own bytes
plus manifest alone (`cll.ledger.segments.verify_segment`). New
`unmount_segment`/`mount_segment`/`list_segments`/`verify_segment_standalone`
methods on `LedgerStore`; a read that reaches an unmounted segment raises
`SegmentUnmounted(checkpoint_root, mmr_size)` instead of reporting "not
found". New `cll segments list|mount|unmount|verify` CLI
(`pip install`'s `cll` console script). Existing stores/callers are
unaffected until they opt in.

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
- **Time-fenced key revocation + a local signer** (`cll.revocation`,
  `cll.signing`) — `LedgerStore.verify()` rebuilds the key-rotation timeline
  from the ledger's own `key_rotation` events and flags a record signed by an
  already-revoked key as a DEFAULT finding, zero caller configuration
  required; `extra_findings` remains available for a caller's own additional
  checks layered on top.

See [`docs/module-map.md`](docs/module-map.md) for the section-by-section map
from `draft-mih-scitt-checkpointed-local-log-00` to the package's modules,
including two known gaps flagged (not yet fixed): the -00 draft's checkpoint
claim names don't yet byte-match the shipping field names, and RFC9338 stub
countersignatures aren't wired yet.

`cll` installs standalone (`pip install checkpointed-local-log`); its own
test suite is green (180 passed, 1 skipped — the opt-in live-TS network
test). `capsule-emit` (0.7.0+) and `capsule-ledger` depend on it rather than
each forking their own MMR/checkpoint/ledger-store implementation.
