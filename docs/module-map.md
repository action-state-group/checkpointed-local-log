# Spec section ↔ module map

Companion to `spec/draft-mih-scitt-checkpointed-local-log-00.md`. Written as
part of the W3.1 extraction (2026-09-01, held branch `w3-1-cll-extraction`) —
see the acceptance criteria in `[w3-cll-lib-extraction]` (ledger lane).

## Scope note (read first)

The spec is scoped to the **checkpoint discipline**: the log-append
discipline, the checkpoint's COSE_Sign1/CBOR shape, the required constraints
once a producer publishes checkpoints, witnessing (SCITT registration or
direct countersignature), stub countersignatures, and what a checkpoint
does/does not establish. It is **not** normative about a specific storage
binding, an admission/authenticity contract for entries, or a query API —
those are reference-implementation choices `cll.ledger` makes, one level
below the spec, not requirements the spec imposes. The table below reflects
that: `cll.checkpoint` is the spec-normative core; `cll.ledger` is a
reference binding.

## `cll.checkpoint` — spec-normative

| Spec section | Module | Notes |
|---|---|---|
| §The Log Discipline (append-only, one-log-one-signing-identity) | `cll.checkpoint.index` (`MmrLedger`, `LogSource`) | `LogSource` is the structural append-only-log protocol the discipline describes; concrete bindings (e.g. `cll.ledger.store.LedgerStore`) implement it. |
| §The Checkpoint (COSE_Sign1 claims table) | `cll.checkpoint.emit` (`CheckpointRecord`), `cll.checkpoint.cose_wire` (`checkpoint_to_cose`, `encode_checkpoint_claims`) | **Known field-name gap (flagging, not fixing, in this pass):** the spec's claim names are `log_size`/`commitment`/`prev_size`/`prev_commitment`/`issued_at`/`cadence`; the shipping reference implementation (ported forward unchanged from `capsule_emit.checkpoint`/Amendment E) uses `mmr_size`/`root`/`prev_size`/`prev_root`/`timestamp`. The two are the same shape under different names, not a semantic divergence — but they are not yet byte/field-identical to the -00 draft table. Reconciling the names is a real, separate, wire-affecting task (touches `CheckpointRecord`, `cose_wire`, every consumer's fixtures) and is explicitly OUT of scope for W3.1 (extraction, not a spec-conformance rewrite). Filed here so it isn't lost. |
| §The Checkpoint > cryptographic agility (opaque `commitment`, algorithm in COSE header) | `cll.checkpoint.core` (`root_from_peaks`, `commitment_object`), `cll.checkpoint.cose_wire` | `commitment_object`/`root_from_peaks` are the MMRIVER-profile accumulator; see `commitment-conformance-vectors/README.md` for the bespoke-vs-MMRIVER-profile distinction already called out there. |
| §Required constraints (declared cadence, continuity, named witnesses, no-claims-beyond-last-witnessed) | `cll.checkpoint.emit` (`CheckpointConfig.cadence_entries`/`cadence_seconds`/`max_lag_entries`, `due_for_checkpoint`, `lag_exceeded`), `cll.checkpoint.bundle` (`verify_bundle_log_integrity` consistency check, honest first-checkpoint labeling) | |
| §Witnessing (SCITT registration, direct countersignature, checkpoint-aware vs plain witness) | `cll.checkpoint.emit` (`register_checkpoint`, `WitnessRecord`, `Grade`, `StampVerdict`, `verify_witness_stamp_tristate`) | |
| §Stub Countersignatures | *(not yet implemented)* | `STUB_MARKER`/`STUB_TS_URL` exist in `cll.checkpoint.emit` for local dev/test registration, but the RFC9338 `cll-stub` protected-header/`crit` shape from the -00 draft is not yet wired. Flagged, not fixed, in this pass. |
| §Verification (inclusion, consistency, range completeness) | `cll.checkpoint.core` (`verify_inclusion`, `verify_consistency`), `cll.checkpoint.index` (`RangeProof`, `verify_range`), `cll.checkpoint.bundle` (`Bundle`, `bundle()`, `verify_bundle_log_integrity()` — the record/range-level disclosure-bundle primitive that assembles inclusion + checkpoint + consistency into one offline-verifiable object) | |
| §What a CLL Does and Does Not Establish / §Security Considerations | `cll.checkpoint.bundle.verify_bundle_log_integrity` docstring (honest anti-REWRITE-not-anti-FORK labeling), `cll.checkpoint.emit` witness tri-state (WITNESSED/UNVERIFIED/INVALID — never silently treats an unpinned TS as forged) | The three-state honesty pattern (never collapse "unknown" into "false") recurs across this module; see also `cll.ledger`'s three-state admission contract below, same discipline one layer up. |

## `cll.ledger` — reference binding (not spec-normative)

| Capability (W3.1 scope item) | Module | Notes |
|---|---|---|
| store | `cll.ledger.store` (`LedgerStore`) | Append-only JSONL segments + derived SQLite index; the only module allowed to touch `sqlite3`. **Honest scope note:** this binding is capsule-shaped today (SQL schema columns, `verify()` calling `agent_action_capsule.verify`) — a content-agnostic log store (so a non-capsule consumer like a TRACE registry could reuse it directly) is a plausible future direction this extraction does not attempt; see `cll/__init__.py`. |
| chains (chain-gap detection) | `cll.ledger.store.LedgerStore.find_gaps`, `cll.ledger.records.ChainGap` | Locates `chain.parent_capsule_id` references missing from the ledger; each gap is a browsable window (`edge_before`/`edge_after`), never a silent null. |
| refusals + the three-state ask surface | `cll.ledger.admission` (`AdmissionRequest`, `AdmissionRejected`, `resolve_admission`, the `UNSIGNED`/`SIGNED` declared-mode contract) | Dispatches solely on the caller's DECLARED admission mode, never inferred from envelope presence — the anti-silent-downgrade invariant. |
| read/verify seam | `cll.ledger.api` (`LedgerAPI`, `ScanQuery`), `cll.ledger.store.LedgerStore.verify`/`.scan`/`.fetch`, `cll.revocation` (`build_key_timeline`, `check_time_fenced_revocation`), `cll.signing` (`Signer`, `LocalSigner`) | **Reclassified 2026-09-02 ([cll-revocation-default-finding]):** the W3.1 extraction originally left the time-fenced key-revocation check out of `verify()` on the theory it was guard/policy-layer product code (`guards/revocation.py`, `guards/signing.py`); the 2026-09-01 dependency-trace ruling reclassified it as a verify-primitive belonging in this package (a counterparty verifying a log needs a complete verify out of the box). `build_key_timeline`/`check_time_fenced_revocation` now live in `cll.revocation`, `Signer`/`LocalSigner` in `cll.signing`, and `verify()` runs the revocation check as a DEFAULT finding — zero caller configuration. `extra_findings` (the `LedgerStore` constructor parameter) remains the seam for a caller's OWN additional store-level checks layered on top; it is no longer how revocation itself is delivered. |
| checkpoints (the ledger-side registration/storage wrapper) | `cll.ledger.checkpoint` | **Distinct from, not a duplicate of, `cll.checkpoint.emit`** — a different signing scheme (HMAC vs Ed25519/COSE) and a different, legacy TS registration protocol (`/v1/digest` generic-digest-anchoring vs the checkpoint-aware `/checkpoints` COSE route). Reuses the shared MMR math (`cll.checkpoint.core`) rather than reimplementing it; its own contribution is the on-disk checkpoint storage layout (`<root>/checkpoints/config.json` + `<mmr_size>.json`). See the module's own docstring for the full disambiguation — this is the answer to the "no second MMR/checkpoint/store implementation" acceptance gate for this module. |
| record/range-level disclosure bundles | `cll.checkpoint.bundle` (see the spec-normative table above) | Genericized during this extraction from `capsule_emit.bundle` (was hardcoded to a `capsule_id`-named field and a direct `capsule_emit.ledger` file read); now parameterized (`id_field`, `kind_field`, `non_leaf_kinds`, `stamp_kind`) and takes pre-read `entries` rather than reading a log itself. `capsule_emit.bundle` becomes a thin wrapper supplying its own field names and its own capsule-content-authenticity check (`verify_bundle`, composed from this module's `verify_bundle_log_integrity` — see that function's docstring for why content-authenticity is split out). |

## Grep gate: no second MMR/checkpoint/store implementation

- MMR core (`core.py`/`index.py`/`store.py`): singular, in `cll.checkpoint`. `cll.ledger.checkpoint` imports it (`from ..checkpoint import core`); does not reimplement it.
- Checkpoint *registration protocol*: two, by design, not by oversight — `cll.checkpoint.emit` (Ed25519/COSE, `/checkpoints`) and `cll.ledger.checkpoint` (HMAC, legacy `/v1/digest`). See that module's disambiguating docstring. A future pass could retire the legacy protocol once every consumer speaks the COSE one; out of scope here.
- Ledger store: singular, in `cll.ledger.store`. `capsule-ledger`'s own copy becomes a thin re-export/subclass (see the companion held branch in that repo).
