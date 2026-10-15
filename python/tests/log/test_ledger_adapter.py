# SPDX-License-Identifier: Apache-2.0
"""``LedgerStore`` and ``LogSource`` behind the entry-log interface."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cll.checkpoint import core
from cll.checkpoint.index import MmrLedger
from cll.checkpoint.store import MemoryNodeStore
from cll.ledger import LedgerStore
from cll.log import (
    AppendInput,
    ClosedError,
    CorruptError,
    EntrySource,
    EntryStore,
    InvalidError,
    NotFoundError,
    UnsupportedError,
)
from cll.log.ledger import LedgerEntryStore, LogSourceEntries, capsule_timestamp, record_entry

FIXTURE = Path(__file__).resolve().parents[1] / "ledger" / "fixtures" / "amaury_sample_ledger.jsonl"
T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)


@pytest.fixture
def ledger(tmp_path):
    store = LedgerStore(tmp_path)
    store.import_jsonl(FIXTURE)
    yield store
    store.close()


def capsules() -> list:
    return [json.loads(line) for line in FIXTURE.read_text().splitlines() if line.strip()]


def test_ledger_entries_map_seq_digest_and_capsule_timestamp(ledger):
    adapter = LedgerEntryStore(ledger)
    assert isinstance(adapter, EntryStore)
    entries = adapter.scan_entries(0, 1000)
    assert [entry.seq for entry in entries] == list(range(1, len(capsules()) + 1))
    for entry, capsule in zip(entries, capsules()):
        assert entry.value == bytes.fromhex(capsule["capsule_id"])
        stamp = datetime.fromisoformat(capsule["timestamp"].replace("Z", "+00:00"))
        assert entry.appended_at == stamp.replace(microsecond=stamp.microsecond // 1000 * 1000)
        assert adapter.get_entry(entry.value) == entry
    assert adapter.scan_entries(1, 1) == entries[1:2]
    assert adapter.scan_entries(len(entries), 10) == []


def test_ledger_append_is_idempotent_or_unsupported(ledger):
    adapter = LedgerEntryStore(ledger)
    first = adapter.scan_entries(0, 1)[0]
    result = adapter.append(AppendInput(first.value, T0))
    assert result.outcome == "idempotent" and result.entry == first
    with pytest.raises(InvalidError):
        adapter.append(AppendInput(b"short", T0))
    with pytest.raises(UnsupportedError):
        adapter.append(AppendInput(bytes(32), T0))
    with pytest.raises(NotFoundError):
        adapter.get_entry(bytes(32))
    with pytest.raises(InvalidError):
        adapter.scan_entries(0, 0)
    adapter.close()
    adapter.close()
    with pytest.raises(ClosedError):
        adapter.scan_entries(0, 1)
    assert list(ledger.scan())  # the adapter does not own the ledger


def test_log_source_adapter_matches_the_ledger_adapter_and_mmr_root(ledger):
    source = LogSourceEntries(ledger)
    assert isinstance(source, EntrySource)
    entries = source.scan_entries(0, 1000)
    assert entries == LedgerEntryStore(ledger).scan_entries(0, 1000)
    assert source.scan_entries(2, 1) == entries[2:3]
    nodes = MemoryNodeStore()
    for entry in entries:
        core.add_leaf(nodes, core.leaf_hash(entry.value))
    index = MmrLedger(ledger)
    index.sync()
    assert core.root_from_peaks([nodes.node(p) for p in core.peaks(nodes.size())]) == index.root()


@dataclass
class Record:
    seq: int
    capsule_id: str
    capsule: dict


def test_record_mapping_rejects_malformed_records():
    good = Record(1, "ab" * 32, {"timestamp": "2026-09-01T12:00:00.123456"})
    assert record_entry(good).appended_at == datetime(2026, 9, 1, 12, 0, 0, 123000, tzinfo=timezone.utc)
    assert capsule_timestamp(Record(1, "", {"timestamp": "2026-09-01T14:00:00+02:00"})) == datetime(
        2026, 9, 1, 12, tzinfo=timezone.utc
    )
    for bad in (
        Record(0, "ab" * 32, good.capsule),
        Record(1, "AB" * 32, good.capsule),
        Record(1, "ab" * 31, good.capsule),
        Record(1, "zz" * 32, good.capsule),
        Record(1, "ab" * 32, {}),
        Record(1, "ab" * 32, {"timestamp": "yesterday"}),
    ):
        with pytest.raises(CorruptError):
            record_entry(bad)
    assert record_entry(good, appended_at=lambda record: T0).appended_at == T0


def test_log_source_adapter_rejects_gaps():
    class Gappy:
        def scan(self, query=None):
            yield Record(1, "ab" * 32, {"timestamp": "2026-09-01T12:00:00Z"})
            yield Record(3, "cd" * 32, {"timestamp": "2026-09-01T12:00:00Z"})

    with pytest.raises(CorruptError):
        LogSourceEntries(Gappy()).scan_entries(0, 10)


@pytest.mark.parametrize(
    "stamp,micros",
    [
        ("2026-09-01T12:00:00.1Z", 100000),
        ("2026-09-01T12:00:00.1234Z", 123000),
        ("2026-09-01T12:00:00.1234567+00:00", 123000),
        ("2026-09-01 12:00:00.12", 120000),
    ],
)
def test_capsule_timestamp_accepts_any_fraction_length(stamp, micros):
    """As LedgerStore.scan reads it, on Python 3.9 too (where fromisoformat
    takes only 3 or 6 fraction digits)."""
    parsed = capsule_timestamp(Record(1, "ab" * 32, {"timestamp": stamp}))
    assert parsed == datetime(2026, 9, 1, 12, 0, 0, micros, tzinfo=timezone.utc)
