# SPDX-License-Identifier: Apache-2.0
"""Adapters from the Python-specific log bindings to the entry-log interface
of docs/backend-contract.md.

``LedgerStore`` (JSONL segments plus a SQLite index) keeps its own format and
is not part of cross-language interop, but it sits behind the same
interface: ``LedgerEntryStore`` implements ``EntryStore`` over it, and
``LogSourceEntries`` implements a read-only ``EntrySource`` over any
``cll.checkpoint.index.LogSource``. ``LedgerAPI``, ``Checkpointer`` and both
registration protocols stay above these, unchanged.

Mapping, for both adapters:

- ``Entry.seq`` is the record's ``seq`` (gapless, 1-based append order, the
  same ``seq`` ``MmrLedger`` uses as ``leaf_index + 1``).
- ``Entry.value`` is the record's ``capsule_id`` decoded from hex: the 32-byte
  body digest whose ``leaf_hash`` the MMR commits to. A ``capsule_id`` that is
  not 64 hex digits is ``corrupt``.
- ``Entry.appended_at`` is derived, because neither binding stores an append
  time: it is the record's capsule ``timestamp`` (the producer's observation
  time), read as an instant (an offset-less value is UTC, as
  ``LedgerStore.scan`` reads it), converted to UTC and truncated to whole
  milliseconds. A record without a parseable timestamp is ``corrupt``; pass
  ``appended_at=`` to derive it differently.

A ledger record is a full signed or unsigned capsule, so the ledger cannot
store a bare identity: ``LedgerEntryStore`` lacks the ``digest-append``
capability. ``append`` validates its input, returns the existing entry as
``idempotent`` when the ledger already holds that digest, and raises
``unsupported`` otherwise; append capsules through ``LedgerStore.append``.

This module imports neither ``cll.ledger`` nor any database driver: both
adapters take the binding object structurally.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Callable

from . import (
    ENTRY_BYTES,
    IDEMPOTENT,
    AppendInput,
    AppendResult,
    ClosedError,
    CorruptError,
    Entry,
    NotFoundError,
    UnsupportedError,
)
from .engine import check_append, check_scan, check_value
from .wire import normalize_time

__all__ = ["capsule_timestamp", "record_entry", "LogSourceEntries", "LedgerEntryStore"]


def capsule_timestamp(record: Any) -> datetime:
    """The default ``appended_at`` of a ledger record: its capsule
    ``timestamp`` as a UTC millisecond instant."""
    capsule = getattr(record, "capsule", None)
    value = capsule.get("timestamp") if isinstance(capsule, dict) else None
    if not isinstance(value, str) or not value:
        raise CorruptError(f"record seq={getattr(record, 'seq', '?')} has no capsule timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError as exc:
        raise CorruptError(f"record seq={getattr(record, 'seq', '?')} has an unparseable timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return normalize_time(parsed, CorruptError)


def record_entry(record: Any, appended_at: Callable[[Any], datetime] = capsule_timestamp) -> Entry:
    """The ``Entry`` a ledger record maps to (see the module docstring)."""
    seq = getattr(record, "seq", None)
    capsule_id = getattr(record, "capsule_id", None)
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise CorruptError("record seq is not a positive integer")
    try:
        value = bytes.fromhex(capsule_id) if isinstance(capsule_id, str) else b""
    except ValueError:
        value = b""
    if len(value) != ENTRY_BYTES or capsule_id != value.hex():
        raise CorruptError(f"record seq={seq} capsule_id is not a 32-byte lowercase hex digest")
    return Entry(seq, value, normalize_time(appended_at(record), CorruptError))


class LogSourceEntries:
    """A read-only ``EntrySource`` over any ``LogSource``.

    ``LogSource.scan()`` has no sequence filter, so each call walks the source
    from the start and stops after ``limit`` entries past ``after_seq``. A
    record out of dense sequence order is ``corrupt``.
    """

    def __init__(self, source: Any, *, appended_at: Callable[[Any], datetime] = capsule_timestamp) -> None:
        self._source = source
        self._appended_at = appended_at

    def scan_entries(self, after_seq: int, limit: int) -> list:
        check_scan(after_seq, limit)
        out = []
        for expected, record in enumerate(self._source.scan(), start=1):
            if getattr(record, "seq", None) != expected:
                raise CorruptError(f"log source record seq={getattr(record, 'seq', '?')} is out of order")
            if expected <= after_seq:
                continue
            out.append(record_entry(record, self._appended_at))
            if len(out) == limit:
                break
        return out


class LedgerEntryStore:
    """``EntryStore`` over a ``cll.ledger.store.LedgerStore``, without the
    ``digest-append`` capability.

    Lookups use the ledger's own indexes (``by_seq_range``, ``by_digest``),
    which fall back to a full scan when its lookup index is absent. ``close``
    stops this adapter and, with ``owns_store=True``, closes the ledger.
    """

    def __init__(
        self,
        store: Any,
        *,
        appended_at: Callable[[Any], datetime] = capsule_timestamp,
        owns_store: bool = False,
    ) -> None:
        self._store = store
        self._appended_at = appended_at
        self._owns_store = owns_store
        self._closed = False
        self._lock = threading.Lock()

    def _require_open(self) -> None:
        if self._closed:
            raise ClosedError("backend is closed")

    def scan_entries(self, after_seq: int, limit: int) -> list:
        self._require_open()
        check_scan(after_seq, limit)
        records = self._store.by_seq_range(after_seq + 1, after_seq + limit)
        entries = [record_entry(record, self._appended_at) for record in records]
        for offset, entry in enumerate(entries):
            if entry.seq != after_seq + 1 + offset:
                raise CorruptError("ledger sequences are not dense")
        return entries

    def get_entry(self, value: bytes) -> Entry:
        self._require_open()
        value = check_value(value)
        record = self._store.by_digest(value.hex())
        if record is None:
            raise NotFoundError("entry not found")
        return record_entry(record, self._appended_at)

    def append(self, input: AppendInput) -> AppendResult:
        self._require_open()
        value, _ = check_append(input)
        record = self._store.by_digest(value.hex())
        if record is None:
            raise UnsupportedError(
                "LedgerStore cannot append a bare identity; append the capsule through LedgerStore.append"
            )
        return AppendResult(record_entry(record, self._appended_at), IDEMPOTENT)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._owns_store:
                self._store.close()
