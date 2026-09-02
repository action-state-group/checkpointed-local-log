# SPDX-License-Identifier: Apache-2.0
"""``cll`` -- Checkpointed Local Log: the reference library for
``draft-mih-scitt-checkpointed-local-log`` (see ``../spec/``).

Two subpackages, imported explicitly (this top level stays empty so a bare
``import cll`` never pays for either):

- ``cll.checkpoint`` -- the MMR/checkpoint/COSE core: pure position math,
  domain-separated hashing, inclusion/consistency proofs, COSE_Sign1
  checkpoint wire format, Transparency Service registration, and the
  record/range-level disclosure-bundle primitive. Content-agnostic — knows
  nothing about capsules or any other record shape.
- ``cll.ledger`` -- an append-only log store (JSONL segments + SQLite
  index), its read/query API, the three-state admission contract, and
  chain-gap detection. This binding is capsule-shaped today (it verifies
  Agent Action Capsules specifically) — a content-agnostic log store is a
  possible future direction, not a claim this package makes yet.

Neither subpackage names a product, a company, or a capsule format in its
own vocabulary — the log layer is deliberately not capsule-specific (the
same layering law as ``scitt-cose``: capsule semantics never enter it).
Downstream capsule-shaped consumers (``capsule-emit``, ``capsule-ledger``)
depend on this package rather than each forking their own copy.
"""
