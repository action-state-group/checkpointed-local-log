# checkpointed-local-log

**The Checkpointed Local Log (CLL)** — an IETF Internet-Draft specifying a
producer-operated, append-only local log with periodic signed checkpoints.
Entries are appended locally and never published; only a small checkpoint —
a signed commitment to the log's entire history — ever leaves the producer.
Checkpoints may be registered with one or more independent SCITT Transparency
Services or witnesses, turning a set of individually signed records into a
stream with provable order, contemporaneity, and completeness.

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

`spec/.refcache/` is committed so the build never depends on `bib.ietf.org`
being reachable. See comments in `spec/Makefile` for `rebuild` and
`refresh-refs` targets.

## License

See [LICENSE](LICENSE): the specification text is governed by
[BCP 78](https://www.rfc-editor.org/info/bcp78) and the IETF Trust's Legal
Provisions; code and reference material are under the Revised BSD License.
