# SPDX-License-Identifier: Apache-2.0
"""JSONL v4 CLL backend implementing ``cll.log.Backend``.

The journal format is docs/backend-contract.md ("JSONL v4"), shared byte for
byte with the Go and TypeScript backends: one compact JSON event per line,
``cll.init`` first, delta ``cll.commit`` events, a non-blocking exclusive
``flock`` on the journal descriptor itself (never a sidecar file), fsync per
event and truncation of a failed write back to the last durable offset.

``init(path)`` creates the journal or validates an existing one and repairs
only an incomplete final line. ``open(path)`` requires an initialized
journal, never creates one and rejects a torn tail as ``corrupt`` without
changing the file. Both take the writer lock, so a second writer in any
language fails with ``contention``. POSIX only (``fcntl.flock``).
"""
from __future__ import annotations

import errno
import fcntl
import json
import os
import threading
from datetime import datetime

from . import (
    MAX_JOURNAL_EVENT_BYTES,
    AppendInput,
    AppendResult,
    ClosedError,
    CllError,
    CllState,
    ContentionError,
    CorruptError,
    Entry,
    InvalidError,
    WitnessState,
)
from .engine import Engine, check_expected_attempts
from .wire import (
    decode_bytes,
    dumps,
    encode_bytes,
    entry_from_wire,
    entry_to_wire,
    parse_decimal,
    state_from_wire,
    state_to_wire,
    witness_from_wire,
    witness_to_wire,
)

__all__ = ["JsonlStore", "init", "open"]

SCHEMA_VERSION = 4


def init(path: str | os.PathLike) -> None:
    """Create the journal, or validate an existing one and truncate an
    incomplete final line. Complete corrupt lines are never removed.
    Repeating it is harmless."""
    JsonlStore._open(path, initialize=True).close()


def open(path: str | os.PathLike) -> JsonlStore:
    """Open an initialized journal under the writer lock."""
    return JsonlStore._open(path, initialize=False)


class JsonlStore:
    """A single-writer JSONL v4 ``Backend``. Use ``open`` or ``init``."""

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._engine = Engine()
        self._lock = threading.RLock()
        self._closed = False

    @classmethod
    def _open(cls, path: str | os.PathLike, initialize: bool) -> JsonlStore:
        if not os.fspath(path):
            raise InvalidError("journal path is required")
        flags = os.O_RDWR | (os.O_CREAT if initialize else 0)
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = os.open(path, flags, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                raise ContentionError("JSONL backend already has a writer") from exc
            raise
        store = cls(fd)
        try:
            store._replay(repair=initialize)
            if os.fstat(fd).st_size == 0:
                if not initialize:
                    raise CorruptError("missing JSONL initialization; call init")
                store._append_event({"version": SCHEMA_VERSION, "type": "cll.init"})
        except BaseException:
            store._close_file()
            raise
        return store

    # -- journal -----------------------------------------------------------------

    def _replay(self, repair: bool) -> None:
        os.lseek(self._fd, 0, os.SEEK_SET)
        chunks = []
        while True:
            chunk = os.read(self._fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        valid_end = 0
        initialized = False
        start = 0
        while start < len(data):
            end = data.find(b"\n", start)
            if end < 0:
                break
            if end - start > MAX_JOURNAL_EVENT_BYTES:
                raise CorruptError("JSONL event exceeds size limit")
            try:
                item = json.loads(data[start:end].decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise CorruptError(f"corrupt complete JSONL line at byte {start}") from exc
            if not isinstance(item, dict):
                raise CorruptError(f"JSONL line at byte {start} is not an object")
            version = item.get("version")
            if type(version) is not int or version != SCHEMA_VERSION:
                if version == 3 or item.get("v") == 3:
                    raise CorruptError("legacy JSONL schema version 3 is unsupported")
                raise CorruptError("unsupported JSONL schema version")
            if not initialized and item.get("type") != "cll.init":
                raise CorruptError("JSONL journal does not begin with cll.init")
            try:
                self._apply_event(item)
            except CllError as exc:
                raise CorruptError(f"event at byte {start}: {exc}") from exc
            initialized = True
            start = valid_end = end + 1
        if valid_end != len(data):
            if not repair:
                raise CorruptError("incomplete JSONL tail; call init to recover")
            os.ftruncate(self._fd, valid_end)
            os.fsync(self._fd)

    def _apply_event(self, item: dict) -> None:
        kind = item.get("type")
        if kind == "cll.init":
            if self._engine.entries or self._engine.state.size != 0:
                raise CorruptError("duplicate CLL initialization after state")
            if any(key in item for key in ("entry", "state", "witness")):
                raise CorruptError("invalid CLL initialization")
        elif kind == "entry.append":
            if "entry" not in item:
                raise CorruptError("missing entry")
            self._engine.replay_entry(entry_from_wire(item["entry"]))
        elif kind == "cll.commit":
            if "state" not in item:
                raise CorruptError("missing CLL state")
            expected_size = parse_decimal(item.get("expected_size"))
            expected = item.get("expected_checkpoint")
            checkpoint = None if expected is None else decode_bytes(expected)
            self._engine.commit_cll_delta(expected_size, checkpoint, state_from_wire(item["state"]))
        elif kind == "witness.commit":
            attempts = item.get("expected_attempts")
            if "witness" not in item or type(attempts) is not int:
                raise CorruptError("missing witness commit fields")
            try:
                check_expected_attempts(attempts)
            except InvalidError as exc:
                raise CorruptError(str(exc)) from exc
            self._engine.commit_witness(attempts, witness_from_wire(item["witness"]))
        else:
            raise CorruptError(f"unknown event type {kind!r}")

    def _append_event(self, item: dict) -> None:
        encoded = dumps(item) + b"\n"
        if len(encoded) > MAX_JOURNAL_EVENT_BYTES:
            raise InvalidError("JSONL event exceeds size limit")
        start = os.lseek(self._fd, 0, os.SEEK_END)
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(self._fd, view)
                if written <= 0:
                    raise OSError(errno.EIO, "short JSONL write")
                view = view[written:]
            os.fsync(self._fd)
        except BaseException as cause:
            self._rollback(start, cause)
            raise

    def _rollback(self, offset: int, cause: BaseException) -> None:
        try:
            os.ftruncate(self._fd, offset)
            os.fsync(self._fd)
        except OSError as exc:
            self._closed = True
            self._close_file()
            raise CorruptError("JSONL rollback failed") from exc

    def _mutate(self, operation, event) -> object:
        """Apply ``operation`` to the engine and persist ``event(result,
        snapshot)``; restore the engine when the write fails."""
        with self._lock:
            if self._closed:
                raise ClosedError("backend is closed")
            snapshot = self._engine.snapshot()
            result = operation()
            item = event(result, snapshot)
            if item is None:
                return result
            try:
                self._append_event(item)
            except BaseException:
                self._engine.restore(snapshot)
                raise
            return result

    def _read(self):
        if self._closed:
            raise ClosedError("backend is closed")
        return self._engine

    # -- Backend ---------------------------------------------------------------

    def append(self, input: AppendInput) -> AppendResult:
        def event(result: AppendResult, snapshot: tuple) -> dict | None:
            if result.outcome != "inserted":
                return None
            return {"version": SCHEMA_VERSION, "type": "entry.append", "entry": entry_to_wire(result.entry)}

        return self._mutate(lambda: self._engine.append(input), event)

    def get_entry(self, value: bytes) -> Entry:
        with self._lock:
            return self._read().get_entry(value)

    def entry_count(self) -> int:
        with self._lock:
            # The engine's snapshot starts with its entry count, read in O(1).
            return self._read().snapshot()[0]

    def scan_entries(self, after_seq: int, limit: int) -> list:
        with self._lock:
            return self._read().scan_entries(after_seq, limit)

    def load_cll(self) -> CllState:
        with self._lock:
            return self._read().state

    def commit_cll(self, expected_size: int, expected_checkpoint: bytes | None, next: CllState) -> None:
        def event(_: None, snapshot: tuple) -> dict:
            item = {"version": SCHEMA_VERSION, "type": "cll.commit", "expected_size": str(expected_size)}
            if expected_checkpoint is not None:
                item["expected_checkpoint"] = encode_bytes(bytes(expected_checkpoint))
            item["state"] = state_to_wire(self._engine.delta_since(snapshot))
            return item

        self._mutate(lambda: self._engine.commit_cll(expected_size, expected_checkpoint, next), event)

    def pending_witnesses(self, now: datetime, limit: int) -> list:
        with self._lock:
            return self._read().pending_witnesses(now, limit)

    def get_witness(self, witness_id: str, checkpoint_size: int) -> WitnessState | None:
        with self._lock:
            return self._read().get_witness(witness_id, checkpoint_size)

    def commit_witness(self, expected_attempts: int, next: WitnessState) -> None:
        def event(_: None, snapshot: tuple) -> dict:
            stored = self._engine.get_witness(next.witness_id, next.checkpoint_size)
            return {
                "version": SCHEMA_VERSION,
                "type": "witness.commit",
                "expected_attempts": expected_attempts,
                "witness": witness_to_wire(stored),
            }

        self._mutate(lambda: self._engine.commit_witness(expected_attempts, next), event)

    def close(self) -> None:
        """Unlock and close the journal. Repeating it is harmless."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._close_file()

    def _close_file(self) -> None:
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
