# SPDX-License-Identifier: Apache-2.0
"""MySQL 8 CLL backend implementing ``cll.log.Backend`` with PyMySQL.

Install the ``mysql`` extra (``pip install 'checkpointed-local-log[mysql]'``).
The tables are docs/backend-contract.md ("Relational schema"), byte for byte
the DDL Go and TypeScript run, so one database serves every language. Several
logs share a database, keyed by ``log_id``. Writers serialize per log by
locking its ``cll_meta`` row with ``SELECT ... FOR UPDATE``; ``commit_witness``
relies on its ``attempts`` compare-and-set instead. Duplicate keys, lock wait
timeouts and deadlocks are ``contention``.

``init(url, log_id)`` provisions the tables and the log's metadata, preserving
existing data. ``open(url, log_id)`` requires both and never writes. ``url`` is
``mysql://user:password@host:port/database`` (user and password
percent-encoded). This is the only module of ``cll.log`` that imports
``pymysql``.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterator
from urllib.parse import unquote, urlsplit

import pymysql
from pymysql.constants import CLIENT

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

__all__ = ["SCHEMA_STATEMENTS", "MysqlStore", "init", "open", "connect_args"]

SCHEMA_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS cll_meta (
  log_id VARCHAR(191) PRIMARY KEY,
  state LONGBLOB NOT NULL
) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS cll_entries (
  log_id VARCHAR(191) NOT NULL,
  seq BIGINT UNSIGNED NOT NULL,
  value BINARY(32) NOT NULL,
  appended_at VARCHAR(32) NOT NULL,
  PRIMARY KEY(log_id, seq),
  UNIQUE KEY uq_cll_entry(log_id, value)
) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS cll_nodes (
  log_id VARCHAR(191) NOT NULL,
  position BIGINT UNSIGNED NOT NULL,
  node BINARY(32) NOT NULL,
  PRIMARY KEY(log_id, position)
) ENGINE=InnoDB""",
    """CREATE TABLE IF NOT EXISTS cll_witnesses (
  log_id VARCHAR(191) NOT NULL,
  witness_id VARCHAR(191) NOT NULL,
  checkpoint_size VARCHAR(32) NOT NULL,
  attempts INT UNSIGNED NOT NULL,
  witness LONGBLOB NOT NULL,
  PRIMARY KEY(log_id, witness_id, checkpoint_size)
) ENGINE=InnoDB""",
)

#: MySQL error numbers reported as ``contention``: duplicate key, lock wait
#: timeout, deadlock.
_CONTENTION = {1062, 1205, 1213}


def connect_args(url: str) -> dict:
    """PyMySQL connection arguments for a ``mysql://`` URL."""
    if not isinstance(url, str):
        raise InvalidError("MySQL URL must be a string")
    parts = urlsplit(url)
    database = unquote(parts.path.lstrip("/"))
    if parts.scheme != "mysql" or not parts.hostname or not database or "/" in database or parts.query:
        raise InvalidError("MySQL URL must be mysql://user:password@host:port/database")
    return {
        "host": parts.hostname,
        "port": parts.port or 3306,
        "user": unquote(parts.username or ""),
        "password": unquote(parts.password or ""),
        "database": database,
    }


def init(url: str, log_id: str) -> None:
    """Provision the tables and the log's metadata. MySQL DDL is not
    transactional, so retrying after a partial failure is supported."""
    MysqlStore._open(url, log_id, initialize=True).close()


def open(url: str, log_id: str) -> MysqlStore:
    """Open and validate an existing log without DDL or data writes."""
    return MysqlStore._open(url, log_id, initialize=False)


class _Cursor:
    """Runs the shared ``?``-placeholder SQL on a PyMySQL cursor."""

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def execute(self, query: str, params: tuple = ()) -> None:
        self._cursor.execute(query.replace("?", "%s"), params)

    def fetchone(self) -> Any:
        return self._cursor.fetchone()

    def fetchall(self) -> Any:
        return self._cursor.fetchall()

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount


class MysqlStore:
    """A MySQL ``Backend`` for one log. Use ``open`` or ``init``."""

    def __init__(self, connection: Any, log_id: str) -> None:
        self._connection = connection
        self._log_id = log_id
        self._lock = threading.RLock()
        self._closed = False

    @classmethod
    def _open(cls, url: str, log_id: str, initialize: bool) -> MysqlStore:
        if not validate_identifier(log_id):
            raise InvalidError("log ID is required")
        connection = pymysql.connect(
            **connect_args(url),
            charset="utf8mb4",
            autocommit=True,
            binary_prefix=True,
            # UPDATE reports matched rows, so committing an unchanged witness
            # row still satisfies the compare-and-set.
            client_flag=CLIENT.FOUND_ROWS,
        )
        store = cls(connection, log_id)
        try:
            if initialize:
                with store._classified():
                    with connection.cursor() as cursor:
                        for statement in SCHEMA_STATEMENTS:
                            cursor.execute(statement)
                        cursor.execute(
                            "INSERT IGNORE INTO cll_meta(log_id,state) VALUES(%s,%s)",
                            (log_id, sql.metadata(CllState())),
                        )
            with store._transaction("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY") as cursor:
                sql.validate_entries(cursor, log_id, "OCTET_LENGTH")
                sql.load_state(cursor, log_id)
        except BaseException:
            connection.close()
            raise
        return store

    @contextmanager
    def _classified(self) -> Iterator[None]:
        try:
            yield
        except pymysql.MySQLError as exc:
            if exc.args and exc.args[0] in _CONTENTION:
                raise ContentionError(f"MySQL contention: {exc}") from exc
            raise

    @contextmanager
    def _transaction(self, begin: str | None) -> Iterator[_Cursor]:
        """``begin`` opens a transaction; ``None`` runs autocommit reads."""
        with self._lock:
            if self._closed:
                raise ClosedError("backend is closed")
            with self._classified(), self._connection.cursor() as raw:
                cursor = _Cursor(raw)
                if begin is None:
                    yield cursor
                    return
                raw.execute(begin)
                try:
                    yield cursor
                except BaseException:
                    self._connection.rollback()
                    raise
                self._connection.commit()

    def _write(self):
        return self._transaction("START TRANSACTION")

    def append(self, input: AppendInput) -> AppendResult:
        with self._write() as cursor:
            return sql.append(cursor, self._log_id, input, lock=True)

    def get_entry(self, value: bytes) -> Entry:
        with self._transaction(None) as cursor:
            return sql.get_entry(cursor, self._log_id, value)

    def scan_entries(self, after_seq: int, limit: int) -> list:
        with self._transaction(None) as cursor:
            return sql.scan_entries(cursor, self._log_id, after_seq, limit)

    def load_cll(self) -> CllState:
        with self._transaction("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY") as cursor:
            return sql.load_state(cursor, self._log_id)

    def commit_cll(self, expected_size: int, expected_checkpoint: bytes | None, next: CllState) -> None:
        with self._write() as cursor:
            sql.commit_cll(cursor, self._log_id, expected_size, expected_checkpoint, next, for_update=True)

    def pending_witnesses(self, now: datetime, limit: int) -> list:
        with self._transaction(None) as cursor:
            return sql.pending_witnesses(cursor, self._log_id, now, limit)

    def get_witness(self, witness_id: str, checkpoint_size: int) -> WitnessState | None:
        with self._transaction(None) as cursor:
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
