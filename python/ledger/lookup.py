# SPDX-License-Identifier: Apache-2.0
"""Generic, derived, rebuildable lookup index over a ledger's segments.

``<store root>/index.sqlite`` -- distinct from :mod:`cll.ledger.store`'s own
capsule-schema ``index.sqlite3`` -- maps time / content-digest / caller-
declared correlation ids to a record's ``(seq, segment, byte_offset)``, so a
UI finder or an evidence responder can answer time-range / id / digest
queries across a rotated store without a linear JSONL scan.

This module carries no capsule/mesh vocabulary of its own: which fields
count as correlation ids is supplied by the caller (``correlation_fields``,
e.g. capsule-emit passes ``exchange_id``, ``capsule_id``) at open time, not
hardcoded here. **Never evidence** -- like :mod:`cll.ledger.segments`'s
``StoreManifest``, this index is local bookkeeping the store rebuilds from
the JSONL segments (the source of truth) if it is ever lost or corrupted;
see :meth:`~cll.ledger.store.LedgerStore.rebuild_lookup_index` and the
``cll index rebuild`` CLI. :class:`LedgerStore` is what actually resolves a
hit to a record (honoring mount state) and falls back to a full scan if this
index is absent or corrupt -- see that module for the fallback wiring.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path

__all__ = ["LookupIndex", "extract_correlation_ids"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    seq INTEGER PRIMARY KEY,
    ts TEXT,
    record_digest TEXT NOT NULL,
    segment TEXT NOT NULL,
    byte_offset INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lookup_ts ON records(ts);
CREATE INDEX IF NOT EXISTS idx_lookup_digest ON records(record_digest);

-- One row per (correlation_id, seq), not a column on records itself: a
-- record may carry more than one declared correlation field, and the same
-- correlation id legitimately recurs across records (e.g. both sides of an
-- exchange carry the same exchange_id).
CREATE TABLE IF NOT EXISTS correlations (
    correlation_id TEXT NOT NULL,
    seq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lookup_correlation ON correlations(correlation_id);
CREATE INDEX IF NOT EXISTS idx_lookup_correlation_seq ON correlations(seq);
"""


def extract_correlation_ids(record: dict, correlation_fields: Iterable[str]) -> list[str]:
    """Pull opaque correlation-id strings out of ``record`` for each declared
    field name in ``correlation_fields``. A field name may be a bare
    top-level key or a dotted path (``"chain.parent_capsule_id"``); its
    value may be a single string or a list of strings. Anything else
    (absent, wrong type) is silently skipped -- this is a caller-declared
    convenience index, not a schema validator.
    """
    ids: list[str] = []
    for field_name in correlation_fields:
        value: object = record
        for part in field_name.split("."):
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        if isinstance(value, str):
            ids.append(value)
        elif isinstance(value, list):
            ids.extend(v for v in value if isinstance(v, str))
    return ids


class LookupIndex:
    """Owns ``<store root>/index.sqlite``. Pure key -> ``(seq, segment,
    byte_offset)`` lookups; resolving a hit into an actual
    :class:`~cll.ledger.records.LedgerRecord` is
    :class:`~cll.ledger.store.LedgerStore`'s job -- it alone knows how to
    read a segment file and honor mount state.
    """

    def __init__(self, root: Path, *, correlation_fields: tuple[str, ...] = ()):
        self._path = Path(root) / "index.sqlite"
        self._correlation_fields = tuple(correlation_fields)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def record(self, *, seq: int, ts: str | None, record_digest: str, segment: str, byte_offset: int, capsule: dict) -> None:
        """Incremental update for one newly-appended record."""
        self._conn.execute(
            "INSERT OR REPLACE INTO records (seq, ts, record_digest, segment, byte_offset) "
            "VALUES (?, ?, ?, ?, ?)",
            (seq, ts, record_digest, segment, byte_offset),
        )
        self._conn.execute("DELETE FROM correlations WHERE seq = ?", (seq,))
        for cid in extract_correlation_ids(capsule, self._correlation_fields):
            self._conn.execute("INSERT INTO correlations (correlation_id, seq) VALUES (?, ?)", (cid, seq))
        self._conn.commit()

    def rebuild(self, rows: Iterable[tuple[int, str | None, str, str, int, dict]]) -> None:
        """Wipe and reinsert from ``rows`` -- ``(seq, ts, record_digest,
        segment, byte_offset, capsule)`` in seq order. The caller (see
        :meth:`~cll.ledger.store.LedgerStore.rebuild_lookup_index`) is what
        actually reads the segments; this just repopulates from what it's
        given, so an incremental :meth:`record` and a full :meth:`rebuild`
        share the exact same insert logic below.
        """
        self._conn.execute("DELETE FROM records")
        self._conn.execute("DELETE FROM correlations")
        for seq, ts, record_digest, segment, byte_offset, capsule in rows:
            self._conn.execute(
                "INSERT INTO records (seq, ts, record_digest, segment, byte_offset) "
                "VALUES (?, ?, ?, ?, ?)",
                (seq, ts, record_digest, segment, byte_offset),
            )
            for cid in extract_correlation_ids(capsule, self._correlation_fields):
                self._conn.execute("INSERT INTO correlations (correlation_id, seq) VALUES (?, ?)", (cid, seq))
        self._conn.commit()

    # -- queries: each returns (seq, segment, byte_offset) hits ------------

    def by_time(self, start: str | None, end: str | None) -> list[tuple[int, str, int]]:
        clauses: list[str] = []
        params: list[str] = []
        if start is not None:
            clauses.append("ts >= ?")
            params.append(start)
        if end is not None:
            clauses.append("ts <= ?")
            params.append(end)
        sql = "SELECT seq, segment, byte_offset FROM records"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq"
        return [tuple(row) for row in self._conn.execute(sql, params)]

    def by_digest(self, record_digest: str) -> tuple[int, str, int] | None:
        row = self._conn.execute(
            "SELECT seq, segment, byte_offset FROM records WHERE record_digest = ?",
            (record_digest,),
        ).fetchone()
        return tuple(row) if row is not None else None

    def by_correlation(self, correlation_id: str) -> list[tuple[int, str, int]]:
        rows = self._conn.execute(
            "SELECT r.seq, r.segment, r.byte_offset FROM records r "
            "JOIN correlations c ON c.seq = r.seq WHERE c.correlation_id = ? ORDER BY r.seq",
            (correlation_id,),
        )
        return [tuple(row) for row in rows]

    def by_seq_range(self, first: int, last: int) -> list[tuple[int, str, int]]:
        rows = self._conn.execute(
            "SELECT seq, segment, byte_offset FROM records WHERE seq BETWEEN ? AND ? ORDER BY seq",
            (first, last),
        )
        return [tuple(row) for row in rows]
