# SPDX-License-Identifier: Apache-2.0
"""``cll.log`` -- the CLL entry log, checkpoint state and witness state.

The interfaces, values, error codes and limits here implement the CLL backend
contract, ``docs/backend-contract.md`` in the repository, which is the single
source of truth for every language. Names follow the contract's Python
column: snake_case operations with the contract's argument order, and
synchronous calls.

Backends live in submodules so that importing ``cll.log`` loads no database
driver:

- ``cll.log.memory`` -- in-process ``MemoryStore``
- ``cll.log.jsonl`` -- the shared JSONL v4 journal
- ``cll.log.sqlite`` -- the shared SQLite schema (stdlib ``sqlite3``)
- ``cll.log.mysql`` -- the shared MySQL 8 schema (PyMySQL, extra ``mysql``)
- ``cll.log.ledger`` -- adapters from ``LedgerStore`` and any ``LogSource``
- ``cll.log.conformance`` -- the shared conformance vectors, for any backend

Times are timezone-aware UTC ``datetime`` values with millisecond precision.
Python's ``datetime`` holds only years 1..9999, a subset of the contract's
ECMAScript ``Date`` range: a caller time outside it cannot be constructed,
an encoded one is ``invalid``, and a stored one is ``corrupt``. Python
backends therefore lack the conformance capability ``extended-years``; the
contract records this as an intentional difference.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, Sequence, runtime_checkable

__all__ = [
    "ENTRY_BYTES",
    "MAX_WITNESSES",
    "MAX_CHECKPOINT_BYTES",
    "MAX_JOURNAL_EVENT_BYTES",
    "MAX_WITNESS_RESPONSE_BYTES",
    "MAX_IDENTIFIER_BYTES",
    "MAX_REASON_BYTES",
    "DEFAULT_SCAN_LIMIT",
    "MAX_SCAN_LIMIT",
    "MAX_PORTABLE_INTEGER",
    "MIN_PORTABLE_UNIX_MILLIS",
    "MAX_PORTABLE_UNIX_MILLIS",
    "MAX_ATTEMPTS",
    "INSERTED",
    "IDEMPOTENT",
    "Entry",
    "AppendInput",
    "AppendResult",
    "CheckpointState",
    "WitnessReceipt",
    "WitnessState",
    "CllState",
    "CllError",
    "NotFoundError",
    "InvalidError",
    "CorruptError",
    "ClosedError",
    "ContentionError",
    "RejectedError",
    "UnsupportedError",
    "EntrySource",
    "EntryStore",
    "CheckpointStateStore",
    "WitnessStateStore",
    "CheckpointStore",
    "Backend",
    "validate_identifier",
]

# -- limits (docs/backend-contract.md, "Limits") ------------------------------

ENTRY_BYTES = 32
MAX_WITNESSES = 32
MAX_CHECKPOINT_BYTES = 65536
MAX_JOURNAL_EVENT_BYTES = 4194304
MAX_WITNESS_RESPONSE_BYTES = 2097152
MAX_IDENTIFIER_BYTES = 191
MAX_REASON_BYTES = 4096
DEFAULT_SCAN_LIMIT = 100
MAX_SCAN_LIMIT = 1000
MAX_PORTABLE_INTEGER = 9007199254740991
MIN_PORTABLE_UNIX_MILLIS = -8640000000000000
MAX_PORTABLE_UNIX_MILLIS = 8640000000000000
#: ``attempts`` is an unsigned 32-bit counter in every language.
MAX_ATTEMPTS = 4294967295

#: ``AppendResult.outcome`` values.
INSERTED = "inserted"
IDEMPOTENT = "idempotent"

_IDENTIFIER = re.compile(r"[A-Za-z0-9._:/-]+")


def validate_identifier(value: object) -> bool:
    """True when ``value`` is a portable log or witness identifier: 1..191
    UTF-8 bytes matching ``^[A-Za-z0-9._:/-]+$``. The pattern admits only
    ASCII, so a string with an unpaired surrogate is simply not one."""
    return (
        isinstance(value, str)
        and _IDENTIFIER.fullmatch(value) is not None
        and len(value) <= MAX_IDENTIFIER_BYTES
    )


# -- errors (docs/backend-contract.md, "Error codes") -------------------------


class CllError(Exception):
    """Base of every CLL storage failure. ``code`` is the contract code."""

    code = "unclassified"


class NotFoundError(CllError):
    """A direct lookup found nothing."""

    code = "not_found"


class InvalidError(CllError):
    """A caller-supplied value or transition breaks the contract."""

    code = "invalid"


class CorruptError(CllError):
    """Durable bytes, rows or events are malformed or inconsistent."""

    code = "corrupt"


class ClosedError(CllError):
    """The backend was closed."""

    code = "closed"


class ContentionError(CllError):
    """A compare-and-set failed, or another writer holds the log."""

    code = "contention"


class RejectedError(CllError):
    """A witness or offline verification permanently rejected a response.
    Storage operations never raise it."""

    code = "rejected"


class UnsupportedError(CllError):
    """The store does not offer this operation (see the contract's
    capabilities)."""

    code = "unsupported"


# -- values (docs/backend-contract.md, "Values") -------------------------------
#
# Frozen dataclasses holding ``bytes`` and tuples: a returned value can never
# alias stored state, which is the contract's copy rule.


@dataclass(frozen=True)
class Entry:
    """One dense, 1-based log entry holding an opaque 32-byte identity."""

    seq: int
    value: bytes
    appended_at: datetime


@dataclass(frozen=True)
class AppendInput:
    """The application-supplied identity and observation time."""

    value: bytes
    appended_at: datetime


@dataclass(frozen=True)
class AppendResult:
    """The durable entry and whether ``append`` inserted it (``INSERTED``) or
    found it already present (``IDEMPOTENT``)."""

    entry: Entry
    outcome: str


@dataclass(frozen=True)
class CheckpointState:
    """The latest checkpoint tuple; all present or the whole value absent."""

    bytes: bytes
    size: int
    indexed_seq: int
    peaks: tuple = ()


@dataclass(frozen=True)
class WitnessReceipt:
    """A verified witness receipt and its optional metadata."""

    bytes: bytes
    entry_hash: str | None = None
    entry_hash_scheme: str | None = None
    leaf_index: int | None = None
    tree_size: int | None = None


@dataclass(frozen=True)
class WitnessState:
    """Durable delivery state for one witness and checkpoint, keyed by
    (``witness_id``, ``checkpoint_size``)."""

    witness_id: str
    checkpoint_size: int
    checkpoint: bytes
    attempts: int
    next_attempt_at: datetime
    receipt: WitnessReceipt | None = None
    permanent: bool = False
    last_error: str | None = None


@dataclass(frozen=True)
class CllState:
    """CLL checkpoint state: MMR nodes, indexed sequence, the optional latest
    checkpoint and every witness row."""

    size: int = 0
    nodes: tuple = ()
    indexed_seq: int = 0
    first_pending_at: datetime | None = None
    checkpoint: CheckpointState | None = None
    witnesses: tuple = ()


# -- interfaces (docs/backend-contract.md, "Interfaces and names") -------------


@runtime_checkable
class EntrySource(Protocol):
    """Reads the entry log in sequence order."""

    def scan_entries(self, after_seq: int, limit: int) -> Sequence[Entry]: ...


@runtime_checkable
class EntryStore(EntrySource, Protocol):
    """The entry log: an entry source that appends and looks up identities."""

    def append(self, input: AppendInput) -> AppendResult: ...

    def get_entry(self, value: bytes) -> Entry: ...


@runtime_checkable
class CheckpointStateStore(Protocol):
    """Compare-and-set CLL checkpoint state."""

    def load_cll(self) -> CllState: ...

    def commit_cll(self, expected_size: int, expected_checkpoint: bytes | None, next: CllState) -> None: ...


@runtime_checkable
class WitnessStateStore(Protocol):
    """Witness delivery state. ``get_witness`` returns ``None`` when the key is
    absent (the contract's Python not-found idiom)."""

    def pending_witnesses(self, now: datetime, limit: int) -> Sequence[WitnessState]: ...

    def get_witness(self, witness_id: str, checkpoint_size: int) -> WitnessState | None: ...

    def commit_witness(self, expected_attempts: int, next: WitnessState) -> None: ...


@runtime_checkable
class CheckpointStore(EntrySource, CheckpointStateStore, WitnessStateStore, Protocol):
    """Everything a checkpoint runner needs."""


@runtime_checkable
class Backend(EntryStore, CheckpointStateStore, WitnessStateStore, Protocol):
    """A full CLL backend: entry log, checkpoint state, witness state and
    ``close``."""

    def close(self) -> None: ...
