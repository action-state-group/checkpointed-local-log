# checkpointed-local-log

**The Checkpointed Local Log (CLL)** — an IETF Internet-Draft specifying a
producer-operated, append-only local log with periodic signed checkpoints.
Entries are appended locally and never published; only a small checkpoint —
a signed commitment to the log's entire history — ever leaves the producer.
Checkpoints may be registered with one or more independent SCITT Transparency
Services or witnesses, turning a set of individually signed records into a
stream with provable order, contemporaneity, and completeness.

The log itself is a Merkle Mountain Range (MMR), whose COSE proof formats are
specified in `I-D.bryce-cose-receipts-mmr-profile`. This document specifies
the log discipline and the checkpoint structure on top of that MMR — it
defines no new proof formats, no transparency service behavior, and no
payload semantics. The append-only MMR log itself is implemented in
[`capsule-ledger`](https://github.com/action-state-group/capsule-ledger); a
CLL is the checkpoint discipline that rides on top of it.

> **Status.** This is an **individual** IETF Internet-Draft, not a Working
> Group document, and not an RFC.

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
