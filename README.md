# checkpointed-local-log

**The Checkpointed Local Log (CLL)** — an IETF Internet-Draft specifying a
producer-operated, append-only local log with periodic signed checkpoints.
Entries are appended locally and never published; only a small checkpoint —
a signed commitment to the log's entire history — ever leaves the producer.
Checkpoints may be registered with one or more independent SCITT Transparency
Services or witnesses, turning a set of individually signed records into a
stream with provable order, contemporaneity, and completeness.

A "witness" in this repository is a SCITT Transparency Service registering
checkpoint statements under a consistency Registration Policy
([RFC 9943](https://www.rfc-editor.org/rfc/rfc9943)).

The log itself is a **Merkle Mountain Range (MMR)**, whose COSE proof formats
are specified in `I-D.bryce-cose-receipts-mmr-profile`. This document
specifies the log discipline and the checkpoint structure on top of that
MMR — it defines no new proof formats, no transparency service behavior, and
no payload semantics. The append-only MMR log is implemented in this repo's
`cll` Python package (below); `capsule-emit` and `capsule-ledger` consume it
rather than each forking their own copy.

> **Status.** This is an **individual** IETF Internet-Draft, not a Working
> Group document, and not an RFC.

## The `cll` package

`cll` is the reference implementation of this spec: a Python package
shipping the pieces a CLL producer or verifier needs.

```sh
pip install checkpointed-local-log
```

What it ships:

- **Append-only log store** (`cll.ledger`) — JSONL segments plus a derived
  SQLite index, the three-state admission contract, and hash-chain /
  chain-gap detection.
- **Merkle Mountain Range (MMR)** (`cll.checkpoint.core`/`.index`/`.store`) —
  the pure position math, domain-separated hashing, and inclusion/consistency
  proofs this spec's checkpoints commit to.
- **Signed COSE checkpoints** (`cll.checkpoint.emit`/`.cose_wire`) —
  building, signing, and registering checkpoints with a Transparency Service
  over the COSE_Sign1 wire form this spec defines.
- **Disclosure bundles** (`cll.checkpoint.bundle`) — the record/range-level,
  offline-verifiable evidence package (inclusion proof + covering checkpoint
  + witness stamp + consistency proof) for handing one log record to a
  stranger.

See [`docs/module-map.md`](docs/module-map.md) for the section-by-section map
from this spec to the package's modules.

### The `cll` Rust crate

`rust/cll/` (crates.io: [`checkpointed-local-log`](https://crates.io/crates/checkpointed-local-log);
the name `cll` there belongs to an unrelated crate, but the library is imported
as `cll`) is a Rust sibling of the Python package, covering the same substrate
scope as the Go and TypeScript implementations (see the next section): the
Merkle Mountain Range (leaf/interior hashing, peaks, root, inclusion and
consistency proofs), the MMRIVER-conformant peak-list commitment, per-record
range-membership proofs, signed COSE_Sign1 checkpoints (byte-for-byte port
of `cll.checkpoint.emit`/`.cose_wire`), a `checkpoints.jsonl` reader/writer
matching the on-disk shape a Python checkpointer already writes, and a
witness-registration client. Rust and Python are two implementations of one
spec; the vectors in `mmr-conformance-vectors/`, `commitment-conformance-
vectors/`, and `checkpoint-conformance-vectors/` are the contract — both
languages regenerate and verify the same pinned bytes (roots, proofs,
checkpoint digests, and Ed25519 signatures, which are deterministic per
RFC 8032), so a change only one side's tests catch is a real divergence, not
a passing build.

```sh
cd rust/cll && cargo test
```

See [`checkpoint-conformance-vectors/README.md`](checkpoint-conformance-vectors/README.md)
for how the checkpoint-record vectors pin cross-language digest/signature
parity, and `rust/cll/tests/` for this crate's own pass over all three
vector sets. The witness-receipt boundary -- a checkpoint `digest_hex`
round-tripping through scitt-cose's own `cll`-agnostic COSE Receipt
build/verify path -- is verified in both languages: `rust/cll/tests/
scitt_cose_receipt_interop.rs` (opt in with `cargo test --features
python-interop-tests`; no Rust scitt-cose verifier exists yet, so it
drives the check by invoking the Python reference's `reference_verifier.py`
as a subprocess) alongside that same script's own direct check.

### Cross-language scope: the ledger layer is Python-only, by decision

The Go (`cll-go`), TypeScript (`@action-state-group/cll`), and Rust (`cll`,
above) implementations are the **checkpoint + MMR + storage substrate
only**: the append-only log, the Merkle Mountain Range with
inclusion/consistency proofs, signed COSE checkpoints, witness delivery, and
the storage backends. They are deliberately application-neutral and do not
interpret record bodies.

The **ledger layer** — `cll.ledger` (three-state admission control, segment
closing and manifests, the rebuildable lookup index, the append-only capsule
store) and `cll.revocation` (the key-validity timeline) — is **not ported to Go
or TypeScript, and this is a decision rather than a gap.** That layer is the
business logic of *who may write and how records are admitted, archived,
queried, and key-checked*; it was folded into this Python package by the
"one neutral library per spec" extraction of `capsule-ledger`
(2026-09-01), and nothing downstream in the AAC ecosystem requires it in Go or
TypeScript. Cross-language byte-parity is therefore required for the substrate
(MMR proofs, checkpoints) and is explicitly **not** claimed for the ledger
layer. Should a Go or TS consumer ever need admission or revocation semantics,
adding them is a new, separately-scoped decision, not a matter of "catching up"
to the reference.

## The `evidencebook` Rust crate

`rust/evidencebook/` (crates.io: [`evidencebook`](https://crates.io/crates/evidencebook),
0.0.1) implements the store-level semantics of the Evidence Layer
Internet-Draft, [`draft-mih-agent-evidence-layer-00`](https://github.com/action-state-group/agent-action-capsule/blob/main/spec/draft-mih-agent-evidence-layer-00.md)
(kept in `agent-action-capsule`, not here). It is a second layer on top of
this repository's log: evidencebook owns records, their epistemic types and
links, retention, disclosure, index classes, request answers, and reconcile
and close; the embedded `cll` crate owns append order, the MMR, checkpoints,
inclusion and consistency. `cll` is embedded, never exposed:
`tests/public_api.rs` fails if a public item names a `cll` type. Each public
item names the I-D section it implements, and the I-D is
implementation-independent: a store conforms by meeting its requirements, not
by using this crate.

| Module | I-D section | What it does |
|---|---|---|
| `record` | Record header, Epistemic Type, Typed Links | The record header and its validation, the eight epistemic types (read from the vendored schema shared with the Go and Python implementations), the six link types. |
| `retention` | Record/Payload Separation; Retention States | Folds lifecycle records into a retention state per record and payload; a move to `DELETED` is a tombstone. |
| `disclosure` | Disclosure Records | The store's own statement of what it revealed, with each withheld field listed under its committed digest. |
| `index` | Index Classes | Operational, authenticated and discovery index traits; a discovery result cannot be used as proof input (a `compile_fail` doctest pins this). |
| `substrate` | The Commitment-Substrate Interface | The `Substrate` and `Signer` traits and `CllSubstrate`, the reference implementation: a file-backed MMR plus `checkpoints.jsonl`. |
| `request` | Answering a Request; Three Kinds of "No" | Request subjects, outcomes, the kinds of "no", the registered refusal reasons, and verification of a signed refusal (tokens from the companion `draft-mih-agent-evidence-request-00`). |
| `reconcile` | Reconcile and Close | Pairs halves from two independently held accounts into one of six states, under the profile's join policy and comparator; one unavailable half is not counted as disagreement. |
| `padding` | Privacy Considerations (what a checkpoint reveals) | Padding records with a fresh store nonce, so the leaf count reaches a bucket boundary before a checkpoint. |
| `canonical` | Record identity | RFC 8785 JCS and `JSON-DIGEST`; a record's `record_id` is its capsule's `capsule_id`. |

`tests/refusal_interop.rs` verifies a refusal signed by the Python
implementation (the same vector the Go implementation checks). Its own CI,
`.github/workflows/evidencebook.yml`, runs on changes under
`rust/evidencebook/` or `rust/cll/`: a vocabulary gate, `cargo fmt`,
`cargo clippy -D warnings`, `cargo test --all-features`, and `cargo doc` with
warnings denied.

```sh
cd rust/evidencebook && cargo test && ./scripts/check-vocabulary.sh
```

See [`rust/evidencebook/README.md`](rust/evidencebook/README.md).

## Conformance vectors

| Directory | What it pins | Checked by |
|---|---|---|
| `mmr-conformance-vectors/` | MMR roots and inclusion, consistency and range proofs, byte for byte (the Python package is the reference). | `rust/cll/tests/`, the Python tests |
| `checkpoint-conformance-vectors/` | `CheckpointRecord` signing bodies, digests and Ed25519 signatures, and COSE checkpoint vectors. | `rust/cll/tests/`, the Python tests |
| `commitment-conformance-vectors/` | The byte encoding of a checkpoint's MMR accumulator: a deterministic CBOR array of 32-byte peaks, tallest first. 7 positive and 5 must-fail cases, with a standalone `reference_verifier.py`. | `rust/cll/tests/mmr_conformance_vectors.rs`, `tests/checkpoint/test_commitment_object.py`, CI (`rust.yml`) |
| `mmr-profile-vectors/` | 30 known-answer vectors for `draft-bryce-cose-receipts-mmr-profile-03`, derived from that draft's text alone. They are the draft's values, not this repository's: CLL uses a different leaf hash and proof format, so they do **not** test CLL; one test checks that CLL's node array equals the draft's tree when the leaf preimage is `0x00 || body_digest`. `STATUS-03.md` records which review findings -03 fixed. | `tests/checkpoint/test_mmr_profile_vectors.py`, CI (`generate.py --check` in `rust.yml`) |

```sh
python3 commitment-conformance-vectors/reference_verifier.py
python3 mmr-profile-vectors/generate.py --check
python3 -m pytest tests/checkpoint
```

## Building the draft

The build toolchain is [`kramdown-rfc`](https://github.com/cabo/kramdown-rfc)
(Markdown → RFCXML v2) and [`xml2rfc`](https://pypi.org/project/xml2rfc/)
(v2 → v3 → text):

```sh
cd spec
make DRAFT=draft-mih-scitt-checkpointed-local-log-00 \
     KDRFC=kramdown-rfc2629 \
     XML2RFC=xml2rfc \
     draft-mih-scitt-checkpointed-local-log-00.xml \
     draft-mih-scitt-checkpointed-local-log-00.txt
```

`spec/` holds `-00`, `-01` and `-02`; set `DRAFT` to the one you want.
`spec/.refcache/` is committed so the build never depends on `bib.ietf.org`
being reachable. See comments in `spec/Makefile` for `rebuild` and
`refresh-refs` targets.

## License

- **Code** (the Python package `cll/`, the Rust crates under `rust/`, tests and
  tooling unless a file's SPDX header says otherwise) is licensed under the
  Apache License 2.0: see [LICENSE-APACHE](LICENSE-APACHE). The crates publish
  to crates.io as `Apache-2.0`.
- **The specification text** under `spec/` is under the Revised BSD License:
  see [LICENSE](LICENSE). As an Internet-Draft it is also governed by
  [BCP 78](https://www.rfc-editor.org/info/bcp78) and the IETF Trust's Legal
  Provisions.
