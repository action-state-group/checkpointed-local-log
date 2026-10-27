# SPDX-License-Identifier: Apache-2.0
"""``EntryCounter`` beside the entry log protocols. The shared vectors
(``count/*``) cover each backend's results."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cll.log import AppendInput, CorruptError, EntryStore
from cll.log import sqlite
from cll.log.counter import EntryCounter
from cll.log.jsonl import JsonlStore
from cll.log.memory import MemoryStore
from cll.log.sqlite import SqliteStore

T0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def test_builtin_backends_are_entry_counters():
    for backend in (MemoryStore, JsonlStore, SqliteStore):
        assert callable(getattr(backend, "entry_count", None))
    assert isinstance(MemoryStore(), EntryCounter)


def test_entry_log_protocols_do_not_require_a_count():
    class EntryOnly:
        def scan_entries(self, after_seq, limit):
            return []

        def append(self, input):
            raise NotImplementedError

        def get_entry(self, value):
            raise NotImplementedError

    store = EntryOnly()
    assert isinstance(store, EntryStore)
    assert not isinstance(store, EntryCounter)


def test_memory_count_follows_appends():
    store = MemoryStore()
    for byte in range(1, 6):
        store.append(AppendInput(bytes([byte]) * 32, T0))
    assert store.entry_count() == 5


def test_sql_count_rejects_an_out_of_range_sequence(tmp_path):
    path = tmp_path / "cll.sqlite"
    sqlite.init(path, "log")
    store = sqlite.open(path, "log")
    store.append(AppendInput(bytes([1]) * 32, T0))
    store._connection.execute("UPDATE cll_entries SET seq=? WHERE log_id='log'", (2**53,))
    store._connection.commit()
    with pytest.raises(CorruptError):
        store.entry_count()
    store.close()
