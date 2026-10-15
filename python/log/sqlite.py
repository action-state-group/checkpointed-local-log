# SPDX-License-Identifier: Apache-2.0
"""SQLite CLL backend implementing ``cll.log.Backend`` with the stdlib
``sqlite3`` module.

The tables are docs/backend-contract.md ("Relational schema"), byte for byte
the DDL Go and TypeScript run, so one database file opens in every language.
Several logs share a database, keyed by ``log_id``. Writers serialize per
database with ``BEGIN IMMEDIATE`` and a bounded busy wait; contention left
after the wait is ``contention``.

``init(path, log_id)`` provisions the file (WAL mode), the tables and the
log's metadata, preserving existing data. ``open(path, log_id)`` requires all
of them and never writes. This is the only module of ``cll.log`` that imports
``sqlite3``.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Iterator
from urllib.parse import quote

from . import (
    AppendInput,
    AppendResult,
    ClosedError,
    CllState,
    ContentionError,
    Entry,
    InvalidError,
    WitnessState,
    validate_identifier,
)
from . import sql

__all__ = ["SCHEMA", "SqliteStore", "init", "open"]

SCHEMA = """CREATE TABLE IF NOT EXISTS cll_meta (
  log_id TEXT PRIMARY KEY,
  state BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS cll_entries (
  log_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  value BLOB NOT NULL,
  appended_at TEXT NOT NULL,
  PRIMARY KEY(log_id, seq),
  UNIQUE(log_id, value)
);
CREATE TABLE IF NOT EXISTS cll_nodes (
  log_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  node BLOB NOT NULL,
  PRIMARY KEY(log_id, position)
);
CREATE TABLE IF NOT EXISTS cll_witnesses (
  log_id TEXT NOT NULL,
  witness_id TEXT NOT NULL,
  checkpoint_size TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  witness BLOB NOT NULL,
  PRIMARY KEY(log_id, witness_id, checkpoint_size)
);"""

#: Seconds a writer waits for another writer before ``contention``.
BUSY_TIMEOUT = 5.0


def init(path: str | os.PathLike, log_id: str) -> None:
    """Provision the database file, tables and the log's metadata. Existing
    entries are preserved; retrying after a partial failure is safe."""
    SqliteStore._open(path, log_id, initialize=True).close()


def open(path: str | os.PathLike, log_id: str) -> SqliteStore:
    """Open and validate an existing log without schema or data writes."""
    return SqliteStore._open(path, log_id, initialize=False)


def _contention(exc: sqlite3.Error) -> bool:
    message = str(exc).lower()
    return isinstance(exc, sqlite3.OperationalError) and ("locked" in message or "busy" in message)


class SqliteStore:
    """A SQLite ``Backend`` for one log. Use ``open`` or ``init``."""

    def __init__(self, connection: sqlite3.Connection, log_id: str) -> None:
        self._connection = connection
        self._log_id = log_id
        self._lock = threading.RLock()
        self._closed = False

    @classmethod
    def _open(cls, path: str | os.PathLike, log_id: str, initialize: bool) -> SqliteStore:
        if not os.fspath(path) or not validate_identifier(log_id):
            raise InvalidError("database path and log ID are required")
        mode = "rwc" if initialize else "rw"
        uri = f"file:{quote(os.path.abspath(os.fspath(path)))}?mode={mode}"
        connection = sqlite3.connect(
            uri, uri=True, timeout=BUSY_TIMEOUT, isolation_level=None, check_same_thread=False
        )
        store = cls(connection, log_id)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute(f"PRAGMA busy_timeout={int(BUSY_TIMEOUT * 1000)}")
            if initialize:
                with store._classified():
                    connection.execute("PRAGMA journal_mode=WAL")
                    connection.executescript(SCHEMA)
                    connection.execute(
                        "INSERT OR IGNORE INTO cll_meta(log_id,state) VALUES(?,?)",
                        (log_id, sql.metadata(CllState())),
                    )
            with store._transaction("BEGIN") as cursor:
                sql.validate_entries(cursor, log_id, "length")
                sql.load_state(cursor, log_id)
        except BaseException:
            connection.close()
            raise
        return store

    @contextmanager
    def _classified(self) -> Iterator[None]:
        try:
            yield
        except sqlite3.Error as exc:
            if _contention(exc):
                raise ContentionError(f"SQLite database is busy: {exc}") from exc
            raise

    @contextmanager
    def _transaction(self, begin: str) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            if self._closed:
                raise ClosedError("backend is closed")
            with self._classified():
                cursor = self._connection.cursor()
                cursor.execute(begin)
                try:
                    yield cursor
                except BaseException:
                    cursor.execute("ROLLBACK")
                    raise
                cursor.execute("COMMIT")

    def _read(self):
        return self._transaction("BEGIN")

    def _write(self):
        return self._transaction("BEGIN IMMEDIATE")

    def append(self, input: AppendInput) -> AppendResult:
        with self._write() as cursor:
            return sql.append(cursor, self._log_id, input)

    def get_entry(self, value: bytes) -> Entry:
        with self._read() as cursor:
            return sql.get_entry(cursor, self._log_id, value)

    def scan_entries(self, after_seq: int, limit: int) -> list:
        with self._read() as cursor:
            return sql.scan_entries(cursor, self._log_id, after_seq, limit)

    def load_cll(self) -> CllState:
        with self._read() as cursor:
            return sql.load_state(cursor, self._log_id)

    def commit_cll(self, expected_size: int, expected_checkpoint: bytes | None, next: CllState) -> None:
        with self._write() as cursor:
            sql.commit_cll(cursor, self._log_id, expected_size, expected_checkpoint, next, for_update=False)

    def pending_witnesses(self, now: datetime, limit: int) -> list:
        with self._read() as cursor:
            return sql.pending_witnesses(cursor, self._log_id, now, limit)

    def get_witness(self, witness_id: str, checkpoint_size: int) -> WitnessState | None:
        with self._read() as cursor:
            return sql.get_witness(cursor, self._log_id, witness_id, checkpoint_size)

    def commit_witness(self, expected_attempts: int, next: WitnessState) -> None:
        with self._write() as cursor:
            sql.commit_witness(cursor, self._log_id, expected_attempts, next)

    def close(self) -> None:
        """Close the connection. Repeating it is harmless."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._connection.close()
