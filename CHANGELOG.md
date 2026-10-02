# Changelog

All notable changes to `checkpointed-local-log` (the `cll` Python package)
are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/) once it reaches 1.0.

## Unreleased

### Changed — requires agent-action-capsule 0.6.0

The `agent-action-capsule` floor is now `>=0.6.0`, the release the format-4 tests are written
against (the reference verifier refuses format-2 capsules from 0.4 on). `uv.lock` is refreshed for
it (it still pinned 0.2.0, below the previous floor).

### Fixed — `LedgerStore.scan` compares time bounds as instants, not strings

`ScanQuery.since`/`until` were compared as SQL strings (`timestamp >= ?`/`<= ?`). Record times come
in more than one spelling (whole seconds `…:59Z`, microseconds `…:59.999999Z`, other offsets), and
string order is wrong across them: `…23:59:59Z` sorts after `…23:59:59.999999Z`, so a record stamped
in a period's last second fell outside an inclusive upper bound. Bounds and record times are now
compared as parsed instants (any fraction length, `Z` or an offset). A date alone means midnight UTC,
and a time with no offset means UTC. SQL narrows by date first, a day wider on each side, so scans
stay indexed. `limit` applies after the time filter. A record whose time does not parse is left out
of a bounded scan, and an unreadable bound raises `ValueError`.

### Changed — the Python tests run in CI, and pass against current agent-action-capsule

No workflow ran the Python tests, and 59 of them in `tests/ledger/` had been failing against
`agent-action-capsule` 0.4 and later. Their hand-built fixture capsules carried no
`format_version` (or the retired `"2"`), and the reference verifier now requires `"4"`. The fixtures
now build current-format capsules. `test_verify_passthrough_ok` checks a freshly sealed format-4
record; the format-2 sample ledger stays for the chain checks that use it. A new `python` workflow
runs ruff and pytest on Python 3.9 and 3.12 on every push and pull request.

### Added — draft-exact vectors for the MMR receipt profile (-03)

`mmr-profile-vectors/` holds known-answer vectors derived from the text of
draft-bryce-cose-receipts-mmr-profile-03 alone (sha256 `fba48381…8b56d7`):
the pseudocode transcribed with only the repairs its own prose states, each
named (R1–R8), including the MMR(4) → MMR(8) merge case and negatives. They are
the draft's values, not CLL's. `generate.py --check` runs in CI, and
`tests/checkpoint/test_mmr_profile_vectors.py` checks the transcription against
an independently built tree. They will be regenerated against -04.

### Added — the merge-case consistency vector

`mmr-conformance-vectors/` gains `consistency-3-to-5-leaves` (size 4 to 8),
where both old peaks fold into one new peak. The set had no case of that shape.

### Fixed — the default checkpoint time is whole seconds with no fraction

`emit_checkpoint` (both `cll.checkpoint.emit` and `cll.ledger.checkpoint`)
defaulted to `isoformat()`, with microseconds. A checkpoint's time is its COSE
statement's `issued_at`, and the TypeScript verifier holds RFC 3339 times to
one normalized form (no trailing-zero fraction), so it refused about one
default-timed checkpoint in ten (any whose microseconds end in 0). The default
is now whole-second UTC with no fraction (`2026-10-01T23:04:00Z`). An explicit
`timestamp` is used as given. Tests hold the default to that verifier's rule,
including through `checkpoint_to_cose`.

### Added — a witness's continuity refusal is a typed error

A witness refuses (409) a checkpoint whose `prev_size`/`prev_root` is not the
checkpoint it last accepted for the `log_id`, one whose `consistency_proof`
does not verify, and (when it requires proofs) one after the first that
carries no proof. `register_checkpoint` now raises `WitnessContinuityRefused`
(a `CheckpointError` subclass, so existing handlers still catch it) for that
409, with the witness's own `last_accepted_mmr_size`/`last_accepted_root` and
`code` (`"consistency_proof_required"` for a proof-less checkpoint, else
`None`). A producer holding a local checkpoint at that size can catch the
witness up by submitting its later checkpoints in order; one without it must
start a new `log_id`. Any other error is unchanged.

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

### Docs — dev↔I-D field-mapping doc reconciled

`docs/module-map.md`'s checkpoint row and `cll.checkpoint.cose_wire`'s
module docstring disagreed on whether the dev (`CheckpointRecord`)
vs. wire (CBOR claim) field-name split was a resolved, deliberate dialect
or an open reconciliation gap — it's the former (Decision 1: ship the
mapping table, never rename `CheckpointRecord`). Corrected the stale
row, confirmed `issued_at`'s CDDL type (`tstr`, was previously flagged
unconfirmed), and documented a known `iss`/`sub` semantics deviation from
the I-D's stated producer/log identity split. No code or wire-format
change.

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
