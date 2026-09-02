# SPDX-License-Identifier: Apache-2.0
"""Transport-agnostic ledger interface.

:class:`~capsule_ledger.ledger.store.LedgerStore` is the v0 *in-process* binding of
this interface. Every method here takes and returns only plain, serializable
shapes — dataclasses of primitives, dicts, and other dataclasses — never file
handles, cursors, or a raw ``sqlite3`` connection. That's deliberate: the
ephemeral-mode deployment (gating decisions doc §3 — a Lambda/Cloud Run/short-
lived container calling a nearby ledger service over a local network hop) needs
a binding that talks to a remote ledger service instead of a local directory.
Because every request/response here is already serializable, that binding can
implement this same ``LedgerAPI`` Protocol by putting these shapes on the wire
(e.g. as JSON) — no API change, no caller-visible difference between the two.

Nothing is built for that remote binding yet — this module only keeps the v0
API from being painted into an in-process-only corner.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from agent_action_capsule import VerificationResult

from .admission import AdmissionRequest
from .records import ChainGap, LedgerRecord

__all__ = ["ScanQuery", "LedgerAPI"]


@dataclass(frozen=True)
class ScanQuery:
    """A filtered-scan request. Every field is optional and independently serializable.

    ``agent`` matches the capsule's ``developer`` field; ``counterparty`` matches
    ``operator`` (the closest available mapping — the envelope has no literal
    ``counterparty`` field). ``since``/``until`` are inclusive ISO-8601 bounds on
    ``timestamp``; ``verdict`` matches ``disposition.verdict_class``.
    """

    agent: str | None = None
    since: str | None = None
    until: str | None = None
    counterparty: str | None = None
    verdict: str | None = None
    action_type: str | None = None
    limit: int | None = None


@runtime_checkable
class LedgerAPI(Protocol):
    """The read/append surface every ledger binding (in-process or remote) implements."""

    def append(
        self,
        capsule: dict,
        *,
        consequential: bool = True,
        admission: AdmissionRequest | None = None,
    ) -> LedgerRecord:
        """Append under the three-state admission contract (see
        :mod:`capsule_ledger.ledger.admission`). ``admission`` carries the
        EXPLICIT declared mode admission dispatches on; omitting it is
        equivalent to declared-unsigned. A declared-signed submission whose
        producer envelope is missing or does not verify against the recomputed
        ``capsule_id`` raises ``AdmissionRejected`` and is never persisted."""
        ...

    def scan(self, query: ScanQuery | None = None) -> Iterator[LedgerRecord]: ...

    def fetch(self, capsule_id: str) -> LedgerRecord | None: ...

    def verify(self, capsule_id: str) -> VerificationResult | None: ...

    def find_gaps(self) -> list[ChainGap]: ...
