# SPDX-License-Identifier: Apache-2.0
"""In-memory CLL backend implementing ``cll.log.Backend``.

Implements docs/backend-contract.md with the shared engine. It has no durable
state, so it has only a constructor (no ``init``/``open``) and runs every
conformance case except those that reopen.
"""
from __future__ import annotations

import threading
from datetime import datetime

from . import AppendInput, AppendResult, ClosedError, CllState, Entry, WitnessState
from .engine import Engine

__all__ = ["MemoryStore"]


class MemoryStore:
    """A thread-safe in-process ``Backend``."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._engine = Engine()
        self._closed = False

    def _open(self) -> Engine:
        if self._closed:
            raise ClosedError("backend is closed")
        return self._engine

    def entry_count(self) -> int:
        with self._lock:
            # The engine's snapshot starts with its entry count, read in O(1).
            return self._open().snapshot()[0]

    def scan_entries(self, after_seq: int, limit: int) -> list:
        with self._lock:
            return self._open().scan_entries(after_seq, limit)

    def append(self, input: AppendInput) -> AppendResult:
        with self._lock:
            return self._open().append(input)

    def get_entry(self, value: bytes) -> Entry:
        with self._lock:
            return self._open().get_entry(value)

    def load_cll(self) -> CllState:
        with self._lock:
            return self._open().state

    def commit_cll(self, expected_size: int, expected_checkpoint: bytes | None, next: CllState) -> None:
        with self._lock:
            self._open().commit_cll(expected_size, expected_checkpoint, next)

    def pending_witnesses(self, now: datetime, limit: int) -> list:
        with self._lock:
            return self._open().pending_witnesses(now, limit)

    def get_witness(self, witness_id: str, checkpoint_size: int) -> WitnessState | None:
        with self._lock:
            return self._open().get_witness(witness_id, checkpoint_size)

    def commit_witness(self, expected_attempts: int, next: WitnessState) -> None:
        with self._lock:
            self._open().commit_witness(expected_attempts, next)

    def close(self) -> None:
        with self._lock:
            self._closed = True
