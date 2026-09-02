# CLL commitment-object conformance vectors

`[cll-commitment-interop]` — the interoperable encoding of a CLL checkpoint's
MMR accumulator, pinned so a second implementation (e.g. Go) produces
byte-identical commitments.

## Why this exists

`capsule_emit.checkpoint.core.root_from_peaks` folds an MMR's peak hashes
into a single bagged digest. That fold is this codebase's own bespoke,
internal-only convention (right-to-left `sha256(right || left)`, no domain
separator) — useful for a fast local scalar comparison, but nowhere specified
by, and not reproducible from,
[`draft-bryce-cose-receipts-mmr-profile-00`](https://www.ietf.org/archive/id/draft-bryce-cose-receipts-mmr-profile-00.txt)
(Robin Bryce, Datatrails — the MMRIVER draft's own author). That profile
never folds the peaks into one hash: §6/§7 sign the **accumulator itself —
the ordered list of peak hashes** — as a COSE Receipt's detached payload.

The tree math underneath (`interior_hash`/`hash_pospair64`, `peaks()`,
position commitment) is already MMRIVER-aligned and separately KAT-tested
against `datatrails/go-datatrails-merklelog` in
`tests/checkpoint/test_mmr_kat39.py`. This is not a tree rebuild — it is the
missing **commitment-object encoding** layered on top: given the same
(already-conformant) peak hashes, what exact bytes does an MMRIVER/profile-
conformant tool need to check inclusion and consistency from?

## The encoding

`commitment_object(peak_hashes)` = a canonical/deterministic CBOR array of
the accumulator's peak hashes, ordered tallest-to-smallest (this module's own
`peaks()` order — the same "descending height ordered list" the profile's
`consistent_roots` produces, §7.1.1):

```
commitment = [ *bstr ]     ; RFC 8949 §4.2 definite-length encoding
                            ; one 32-byte string per peak, tallest first
```

This shape (one array, fixed-length byte-string elements, no floats, no
maps) has exactly one valid RFC 8949 deterministic encoding, so every
conformant CBOR encoder in any language produces identical bytes — verified
here against a real library (`cbor2.dumps(peaks, canonical=True)`) in
`tests/checkpoint/test_commitment_object.py`. It's implemented by hand in
`capsule_emit/checkpoint/core.py` (`commitment_object`, ~15 lines) rather
than pulled in as a library dependency, precisely so it stays this trivial
to reproduce in any language — see `reference_verifier.py` for a from-scratch
Python reimplementation that never imports `capsule_emit` or a CBOR library.

This is the encoding of the commitment **object** only. It does not change
`root_from_peaks`, `verify_inclusion`, or `verify_consistency` — those stay
on the bagged hash for this codebase's own internal proof checks. It also
does not touch `CheckpointRecord`'s frozen dev-facing field names or
signing body; wiring `commitment_object` bytes into the checkpoint's CBOR
wire form (the `commitment` claim key) is `[cll-checkpoint-cose-wire]`'s
scope, a sibling item that consumes this encoding.

## Files

- `vectors.json` — `format_version`, `spec`, `encoding`, and `cases`: a list
  of `{name, kind, description, peak_hashes, commitment_hex[, reason]}`.
  `kind: "positive"` cases assert the verifier's computed commitment matches
  `commitment_hex`. `kind: "must-fail"` cases assert it does **not** —
  each pins a specific way a claimed commitment can diverge from the true
  one (wrong peak order, dropped/duplicated/bit-flipped peak, or a
  structurally-equivalent but non-canonical CBOR encoding).
- `reference_verifier.py` — standalone (no `capsule_emit`, no CBOR library)
  verifier; `python3 reference_verifier.py` checks every vector.

## Provenance of the positive peak sets

The `kat39-*` positive vectors reuse peak-hash sets from
`tests/checkpoint/test_mmr_kat39.py`'s KAT39 fixture — itself copied
verbatim from `datatrails/go-datatrails-merklelog`'s
`mmr/draft_kat39_test.go` (MIT licensed) — so the *inputs* to this encoding
are independently cross-checked MMRIVER tree state, not just an internally
self-consistent fixture.
