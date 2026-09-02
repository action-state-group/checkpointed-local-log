# SPDX-License-Identifier: Apache-2.0
"""``cll.ledger`` -- the append-only log store, its read/query API, the
three-state admission contract, and chain-gap detection.

``LedgerAPI`` (api.py) is the transport-agnostic interface; ``LedgerStore``
(store.py) is its v0 in-process binding. Everything else in the package must
go through ``LedgerStore`` — it is the only module allowed to touch sqlite3.

``cll.ledger.checkpoint`` (not re-exported here — import it explicitly) is
capsule-ledger's own checkpoint/registration protocol, layered on top of the
shared MMR core (``cll.checkpoint.core``); see that module's docstring for
how and why it differs from ``cll.checkpoint``'s own checkpoint/emit path.

**Ported from ``capsule-ledger/capsule_ledger/ledger/*.py`` per the W3.1 CLL
extraction (2026-09-01).** ``capsule-ledger`` now depends on this package
and re-exports these symbols as thin compatibility wrappers (its own
``LedgerStore`` subclass layers the guard-layer key-revocation check this
package deliberately does not carry — see ``store.py``'s module docstring).
"""
from .admission import (
    AUTHENTICITY_SIGNED,
    AUTHENTICITY_UNSIGNED,
    SIGNED,
    UNSIGNED,
    AdmissionRejected,
    AdmissionRequest,
    ProducerEnvelope,
)
from .api import LedgerAPI, ScanQuery
from .records import ChainGap, LedgerRecord
from .store import LedgerStore

__all__ = [
    "LedgerAPI",
    "ScanQuery",
    "LedgerRecord",
    "ChainGap",
    "LedgerStore",
    "AdmissionRequest",
    "AdmissionRejected",
    "ProducerEnvelope",
    "UNSIGNED",
    "SIGNED",
    "AUTHENTICITY_UNSIGNED",
    "AUTHENTICITY_SIGNED",
]
