# SPDX-License-Identifier: Apache-2.0
"""``LedgerStore`` crash safety: the duplicate check before any write,
``recover()`` reconciling the active segment with both indexes, atomic
manifest writes, and unmanaged instances over a managed store."""
from __future__ import annotations

import itertools
import json
import sqlite3

import pytest
from cll.checkpoint import MmrLedger
from cll.ledger import DuplicateRecord, LedgerCorrupt, LedgerStore, MmrCheckpointer, SegmentRotationError
from cll.ledger import store as store_module
from cll.signing import LocalSigner

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

    monkeypatch.setattr(store, "_insert_record", crash)
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
    with pytest.raises(LedgerCorrupt, match="does not hold in full"):
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
    assert not list(tmp_path.glob(".*.tmp"))
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


def _with_orphan(root) -> tuple[dict, dict]:
    """A store whose segment holds A, a pre-fix orphan copy of A, then B."""
    store = _managed(root)
    a = store.append(_capsule())
    store.close()
    with open(_segment(root), "ab") as fh:
        fh.write((json.dumps(a.capsule, separators=(",", ":")) + "\n").encode())
    store = _managed(root)
    store.recover()
    b = store.append(_capsule())
    store.close()
    return a.capsule, b.capsule


def test_reindex_keeps_the_first_line_per_capsule_id(tmp_path):
    a, b = _with_orphan(tmp_path)
    store = _managed(tmp_path)
    store.reindex()
    assert [(r.seq, r.capsule["event"]) for r in store.scan()] == [(1, a["event"]), (2, b["event"])]
    store.close()


def test_rebuild_lookup_index_agrees_with_the_records_index(tmp_path):
    a, b = _with_orphan(tmp_path)
    store = _managed(tmp_path)
    b_id = next(r.capsule_id for r in store.scan() if r.capsule["event"] == b["event"])
    store.rebuild_lookup_index()
    assert [r.capsule["event"] for r in store.by_seq_range(2, 2)] == [b["event"]]
    assert store.by_digest(b_id).seq == 2
    store.close()


def test_reindex_failure_leaves_the_index_intact(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    store.close()
    with open(_segment(tmp_path), "ab") as fh:
        fh.write(b"not json\n")
    store = _managed(tmp_path)
    with pytest.raises(ValueError):
        store.reindex()
    assert _seqs(store) == [1]
    store.close()


def test_recover_never_truncates_an_indexed_line(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    store.append(_capsule())
    store.close()
    seg = _segment(tmp_path)
    data = seg.read_bytes()
    seg.write_bytes(data[:-5])
    before = seg.read_bytes()

    store = _managed(tmp_path)
    with pytest.raises(LedgerCorrupt, match="does not hold in full"):
        store.recover()
    assert seg.read_bytes() == before
    store.close()


def test_recover_refuses_a_record_whose_id_cannot_be_derived(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    store.close()
    with open(_segment(tmp_path), "ab") as fh:
        fh.write(b'{"not":"a capsule"}\n')
    store = _managed(tmp_path)
    with pytest.raises(LedgerCorrupt, match="no capsule_id"):
        store.recover()
    store.close()


def test_recover_fills_a_lookup_gap_and_an_unindexed_line_together(tmp_path):
    store = _managed(tmp_path)
    a = store.append(_capsule())
    store.append(_capsule())
    store.close()
    with sqlite3.connect(tmp_path / "index.sqlite") as conn:
        conn.execute("DELETE FROM records WHERE seq = ?", (a.seq,))
    with open(_segment(tmp_path), "ab") as fh:
        fh.write((json.dumps(_capsule(capsule_id="cd" * 32), separators=(",", ":")) + "\n").encode())

    store = _managed(tmp_path)
    report = store.recover()
    assert report.lookup_seqs == (a.seq,) and report.indexed_seqs == (3,)
    assert [r.seq for r in store.by_seq_range(1, 10)] == [1, 2, 3]
    store.close()


def test_recover_reports_only_lookup_rows_it_wrote(tmp_path, monkeypatch):
    store = _managed(tmp_path)
    a = store.append(_capsule())
    store.close()
    with sqlite3.connect(tmp_path / "index.sqlite") as conn:
        conn.execute("DELETE FROM records WHERE seq = ?", (a.seq,))

    store = _managed(tmp_path)

    def fail(**kwargs):
        raise sqlite3.DatabaseError("disk I/O error")

    monkeypatch.setattr(store._lookup, "record", fail)
    assert store.recover().lookup_seqs == ()
    assert store._lookup is None
    store.close()


def test_recover_survives_an_unreadable_lookup_index(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    store.close()
    (tmp_path / "index.sqlite").write_bytes(b"not a database" * 100)
    store = _managed(tmp_path)
    assert store.recover().changed is False
    store.close()


def test_unmanaged_instance_refuses_reindex_and_lookup_rebuild(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    store.close()
    reader = LedgerStore(tmp_path)
    with pytest.raises(SegmentRotationError, match="reindex"):
        reader.reindex()
    with pytest.raises(SegmentRotationError, match="lookup index"):
        reader.rebuild_lookup_index()
    reader.close()


def _rotating(root):
    store = LedgerStore(root, rotate_at_checkpoint=True, max_segment_bytes=300)
    signer = LocalSigner(key_id="test-key", secret=b"secret-bytes-for-hmac-signing-01")
    store.set_checkpointer(MmrCheckpointer(mmr=MmrLedger(store), signer=signer))
    return store


def test_recover_after_rotation_is_a_no_op_and_manifests_leave_no_temp_files(tmp_path):
    store = _rotating(tmp_path)
    while len(store.list_segments()) < 2:
        store.append(_capsule(detail="x" * 50))
    assert store.recover().changed is False
    assert not list(tmp_path.rglob(".*.tmp"))
    store.close()


def test_duplicate_of_a_record_in_an_archived_segment(tmp_path):
    store = _rotating(tmp_path)
    first = store.append(_capsule(detail="x" * 50))
    while len(store.list_segments()) < 2:
        store.append(_capsule(detail="x" * 50))
    store.unmount_segment(store.list_segments()[0].name)
    with pytest.raises(DuplicateRecord) as info:
        store.append(dict(first.capsule))
    assert info.value.record is None
    store.close()


def test_failed_index_write_takes_the_line_back(tmp_path, monkeypatch):
    store = _managed(tmp_path)
    store.append(_capsule(event="e0"))
    real = store._insert_record
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise sqlite3.OperationalError("database is locked")
        return real(*args, **kwargs)

    monkeypatch.setattr(store, "_insert_record", flaky)
    retry = _capsule(event="e1")
    with pytest.raises(sqlite3.OperationalError):
        store.append(dict(retry))
    store.append(_capsule(event="e2"))
    store.append(dict(retry))
    monkeypatch.undo()
    before = [(r.seq, r.capsule["event"]) for r in store.scan()]
    assert before == [(1, "e0"), (2, "e2"), (3, "e1")]

    store.reindex()
    store.rebuild_lookup_index()
    assert [(r.seq, r.capsule["event"]) for r in store.scan()] == before
    assert [(r.seq, r.capsule["event"]) for r in store.by_seq_range(1, 10)] == before
    store.close()


def test_recover_reports_corruption_when_a_lookup_gap_names_a_missing_line(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    second = store.append(_capsule())
    store.close()
    seg = _segment(tmp_path)
    seg.write_bytes(seg.read_bytes().split(b"\n")[0] + b"\n")
    with sqlite3.connect(tmp_path / "index.sqlite") as conn:
        conn.execute("DELETE FROM records WHERE seq = ?", (second.seq,))

    store = _managed(tmp_path)
    with pytest.raises(LedgerCorrupt):
        store.recover()
    store.close()


class _CommitFails:
    """A connection whose commit fails once, delegating everything else."""

    def __init__(self, conn):
        object.__setattr__(self, "_conn", conn)
        object.__setattr__(self, "armed", True)

    def commit(self):
        if self.armed:
            object.__setattr__(self, "armed", False)
            raise sqlite3.OperationalError("disk I/O error")
        return self._conn.commit()

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __setattr__(self, name, value):
        setattr(self._conn, name, value)


def test_reindex_rolls_back_a_failed_commit(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule(event="kept"))
    store.close()
    with open(_segment(tmp_path), "ab") as fh:
        fh.write((json.dumps(_capsule(event="new"), separators=(",", ":")) + "\n").encode())

    store = _managed(tmp_path)
    store._conn = _CommitFails(store._conn)
    with pytest.raises(sqlite3.OperationalError):
        store.reindex()
    assert [r.capsule["event"] for r in store.scan()] == ["kept"]
    store.close()


def test_a_non_sqlite_failure_before_commit_takes_the_line_back(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    seg = _segment(tmp_path)
    before = seg.read_bytes()
    with pytest.raises(OverflowError):
        store.append(_capsule(capsule_id="9a" * 32, timestamp=10**30))
    assert seg.read_bytes() == before
    store.append(_capsule())
    assert _seqs(store) == [1, 2]
    store.close()


def test_a_failure_after_commit_keeps_the_line(tmp_path, monkeypatch):
    store = _managed(tmp_path)

    def boom(**kwargs):
        raise RuntimeError("after the commit")

    monkeypatch.setattr(store._lookup, "record", boom)
    capsule = _capsule()
    with pytest.raises(RuntimeError):
        store.append(capsule)
    monkeypatch.undo()
    assert [r.capsule["event"] for r in store.scan()] == [capsule["event"]]
    assert _segment(tmp_path).read_bytes().count(b"\n") == 1
    store.close()


def test_recover_reports_a_tail_line_it_cannot_index_and_rolls_back(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    store.close()
    with open(_segment(tmp_path), "ab") as fh:
        fh.write((json.dumps(_capsule(capsule_id="9b" * 32, timestamp=10**30), separators=(",", ":")) + "\n").encode())

    store = _managed(tmp_path)
    with pytest.raises(LedgerCorrupt, match="cannot be indexed"):
        store.recover()
    assert not store._conn.in_transaction
    assert _seqs(store) == [1]
    store.close()


def test_recover_reports_a_lookup_gap_whose_line_is_not_a_record(tmp_path):
    store = _managed(tmp_path)
    store.append(_capsule())
    second = store.append(_capsule())
    store.close()
    seg = _segment(tmp_path)
    first_line = seg.read_bytes().split(b"\n")[0] + b"\n"
    replacement = b"[1]" + b" " * (len(seg.read_bytes()) - len(first_line) - 4) + b"\n"
    seg.write_bytes(first_line + replacement)
    with sqlite3.connect(tmp_path / "index.sqlite") as conn:
        conn.execute("DELETE FROM records WHERE seq = ?", (second.seq,))

    store = _managed(tmp_path)
    with pytest.raises(LedgerCorrupt, match="not a record"):
        store.recover()
    store.close()
