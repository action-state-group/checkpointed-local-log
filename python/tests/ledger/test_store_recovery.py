# SPDX-License-Identifier: Apache-2.0
"""``LedgerStore`` crash safety: the duplicate check before any write,
``recover()`` reconciling the active segment with both indexes, atomic
manifest writes, and unmanaged instances over a managed store."""
from __future__ import annotations

import itertools
import json
import sqlite3

import pytest
from cll.ledger import DuplicateRecord, LedgerCorrupt, LedgerStore, SegmentRotationError
from cll.ledger import store as store_module

_counter = itertools.count()


def _capsule(**extra) -> dict:
    i = next(_counter)
    return {
        "spec_version": "draft-mih-scitt-agent-action-capsule-04",
        "format_version": "4",
        "canonicalization_id": "jcs",
        "action_type": "fyi",
        "operator": "test-op",
        "developer": "test-dev",
        "timestamp": f"2026-01-01T00:00:{i % 60:02d}Z",
        "event": f"recovery_{i}",
        **extra,
    }


def _managed(root) -> LedgerStore:
    return LedgerStore(root, rotate_at_checkpoint=True)


def _segment(root):
    manifest = json.loads((root / "manifest.json").read_text())
    return root / "segments" / manifest["active_segment"]


def _seqs(store) -> list[int]:
    return [r.seq for r in store.scan()]


def test_duplicate_append_writes_nothing(tmp_path):
    store = _managed(tmp_path)
    first = store.append(_capsule())
    seg = _segment(tmp_path)
    before = seg.read_bytes()

    with pytest.raises(DuplicateRecord) as info:
        store.append(dict(first.capsule))

    assert isinstance(info.value, sqlite3.IntegrityError)
    assert info.value.capsule_id == first.capsule_id
    assert info.value.record.seq == first.seq
    assert seg.read_bytes() == before
    store.close()


def test_recover_truncates_torn_tail_and_next_append_offset_reads_back(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    store.close()
    seg = _segment(tmp_path)
    with open(seg, "ab") as fh:
        fh.write(b'{"capsule_id":"torn')

    store = _managed(tmp_path)
    report = store.recover()
    assert report.truncated_bytes == len(b'{"capsule_id":"torn')
    assert seg.read_bytes().endswith(b"\n")

    added = store.append(_capsule())
    fetched = store.fetch(added.capsule_id)
    assert fetched is not None and fetched.capsule == added.capsule
    assert store.recover().changed is False
    store.close()


def test_recover_indexes_unindexed_line_and_skips_orphan_duplicate(tmp_path):
    store = _managed(tmp_path)
    kept = store.append(_capsule())
    store.close()
    seg = _segment(tmp_path)
    unindexed = _capsule(capsule_id="ab" * 32)
    with open(seg, "ab") as fh:
        fh.write((json.dumps(kept.capsule, separators=(",", ":")) + "\n").encode())
        fh.write((json.dumps(unindexed, separators=(",", ":")) + "\n").encode())

    store = _managed(tmp_path)
    report = store.recover()
    assert report.skipped_offsets and report.indexed_seqs == (2,)
    assert store.fetch("ab" * 32).capsule == unindexed
    assert _seqs(store) == [1, 2]
    assert store.recover().changed is False
    store.close()


def test_recover_crash_between_segment_write_and_index(tmp_path, monkeypatch):
    store = _managed(tmp_path)

    def crash(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(store, "_index_line", crash)
    capsule = _capsule()
    with pytest.raises(KeyboardInterrupt):
        store.append(capsule)
    store.close()
    monkeypatch.undo()

    store = _managed(tmp_path)
    report = store.recover()
    assert report.indexed_seqs == (1,)
    assert store.scan().__next__().capsule["event"] == capsule["event"]
    store.close()


def test_recover_catches_up_lookup_index(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    second = store.append(_capsule())
    store.close()
    with sqlite3.connect(tmp_path / "index.sqlite") as conn:
        conn.execute("DELETE FROM records WHERE seq = ?", (second.seq,))

    store = _managed(tmp_path)
    assert [hit[0] for hit in store._lookup.by_seq_range(1, 10)] == [1]
    report = store.recover()
    assert report.lookup_seqs == (second.seq,)
    assert [r.seq for r in store.by_seq_range(1, 10)] == [1, 2]
    store.close()


def test_recover_refuses_a_line_that_is_not_json(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    store.close()
    with open(_segment(tmp_path), "ab") as fh:
        fh.write(b"not json\n")

    store = _managed(tmp_path)
    with pytest.raises(LedgerCorrupt, match="not JSON"):
        store.recover()
    store.close()


def test_recover_refuses_a_line_that_is_not_a_record(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    store.close()
    with open(_segment(tmp_path), "ab") as fh:
        fh.write(b"[1, 2]\n")

    store = _managed(tmp_path)
    with pytest.raises(LedgerCorrupt, match="not a record"):
        store.recover()
    store.close()


def test_recover_refuses_an_index_past_the_segment_end(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    store.append(_capsule())
    store.close()
    seg = _segment(tmp_path)
    first_line = seg.read_bytes().split(b"\n")[0] + b"\n"
    seg.write_bytes(first_line)

    store = _managed(tmp_path)
    with pytest.raises(LedgerCorrupt, match="does not reach"):
        store.recover()
    store.close()


def test_recover_needs_a_managed_store(tmp_path):
    store = LedgerStore(tmp_path)
    with pytest.raises(ValueError, match="managed"):
        store.recover()
    store.close()


def test_manifest_write_is_atomic(tmp_path, monkeypatch):
    store = _managed(tmp_path)
    store.append(_capsule())
    before = (tmp_path / "manifest.json").read_text()

    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(store_module.os, "replace", fail)
    store._manifest.active_segment = "seg-999999.jsonl"
    with pytest.raises(OSError):
        store._save_store_manifest()
    monkeypatch.undo()

    assert (tmp_path / "manifest.json").read_text() == before
    store.close()


def test_atomic_write_leaves_no_temp_file(tmp_path):
    target = tmp_path / "m.json"
    store_module._atomic_write_text(target, "{}")
    store_module._atomic_write_text(target, '{"a":1}')
    assert json.loads(target.read_text()) == {"a": 1}
    assert [p.name for p in tmp_path.iterdir()] == ["m.json"]


def test_unmanaged_instance_over_managed_store_reads_and_never_writes(tmp_path):
    store = _managed(tmp_path)
    kept = store.append(_capsule())
    store.close()
    before = sorted(p.name for p in (tmp_path / "segments").iterdir())

    reader = LedgerStore(tmp_path, segment_max_records=1)
    assert reader.fetch(kept.capsule_id).capsule == kept.capsule
    with pytest.raises(SegmentRotationError, match="managed store"):
        reader.append(_capsule())
    reader.close()

    assert sorted(p.name for p in (tmp_path / "segments").iterdir()) == before
