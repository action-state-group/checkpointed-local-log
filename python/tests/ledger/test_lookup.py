# SPDX-License-Identifier: Apache-2.0
"""Tests for the generic lookup index (``cll.ledger.lookup``,
``index.sqlite``): incremental writes, ``cll index rebuild`` identity,
lookups across a rotated store, and the never-fail-a-read corruption
fallback.
"""
from __future__ import annotations

import itertools
import logging

import pytest

from cll.checkpoint import MmrLedger
from cll.cli import main
from cll.ledger.segments import MmrCheckpointer, SegmentUnmounted
from cll.ledger.store import LedgerStore
from cll.signing import LocalSigner

_capsule_counter = itertools.count()


def _synthetic_capsule(*, exchange_id: str | None = None, i: int | None = None) -> dict:
    if i is None:
        i = next(_capsule_counter)
    capsule = {
        "canonicalization_id": "jcs",
        "action_type": "fyi",
        "operator": "test-op",
        "developer": "test-dev",
        "timestamp": f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z",
        "event": f"test_event_{i}",
        "detail": {"i": i, "padding": "x" * 20},
    }
    if exchange_id is not None:
        capsule["exchange_id"] = exchange_id
    return capsule


def _dump(store: LedgerStore) -> tuple[list, list]:
    conn = store._lookup._conn
    records = conn.execute("SELECT * FROM records ORDER BY seq").fetchall()
    correlations = conn.execute(
        "SELECT * FROM correlations ORDER BY correlation_id, seq"
    ).fetchall()
    return records, correlations


def test_incremental_lookups(tmp_path):
    store = LedgerStore(tmp_path, correlation_fields=("exchange_id",))
    records = [store.append(_synthetic_capsule(exchange_id="ex-a"), consequential=False) for _ in range(3)]
    records += [store.append(_synthetic_capsule(exchange_id="ex-b"), consequential=False) for _ in range(2)]

    by_a = store.by_correlation("ex-a")
    assert {r.seq for r in by_a} == {r.seq for r in records[:3]}

    by_b = store.by_correlation("ex-b")
    assert {r.seq for r in by_b} == {r.seq for r in records[3:]}

    hit = store.by_digest(records[0].capsule_id)
    assert hit is not None
    assert hit.capsule_id == records[0].capsule_id

    assert store.by_digest("no-such-digest") is None

    seq_range = store.by_seq_range(records[1].seq, records[3].seq)
    assert [r.seq for r in seq_range] == [records[1].seq, records[2].seq, records[3].seq]

    times = store.by_time(records[0].capsule["timestamp"], records[0].capsule["timestamp"])
    assert [r.seq for r in times] == [records[0].seq]

    store.close()


def test_rebuild_identity(tmp_path):
    store = LedgerStore(tmp_path, correlation_fields=("exchange_id", "capsule_id"))
    for i in range(12):
        store.append(_synthetic_capsule(exchange_id=f"ex-{i % 4}"), consequential=False)

    before = _dump(store)
    assert before[0], "sanity: something was indexed"

    store.rebuild_lookup_index()
    after = _dump(store)

    assert before == after
    store.close()


def _managed_store(tmp_path, *, correlation_fields=(), max_segment_bytes: int = 300):
    store = LedgerStore(
        tmp_path,
        rotate_at_checkpoint=True,
        max_segment_bytes=max_segment_bytes,
        correlation_fields=correlation_fields,
    )
    mmr = MmrLedger(store)
    signer = LocalSigner(key_id="test-key", secret=b"secret-bytes-for-hmac-signing-01")
    checkpointer = MmrCheckpointer(mmr=mmr, signer=signer)
    store.set_checkpointer(checkpointer)
    return store


def test_lookups_span_a_rotated_store(tmp_path):
    store = _managed_store(tmp_path, correlation_fields=("exchange_id",))
    appended = [store.append(_synthetic_capsule(exchange_id="ex-shared"), consequential=False) for _ in range(30)]

    segments_used = {r.segment for r in appended}
    assert len(segments_used) > 1, "30 small records at a 300-byte threshold should span segments"

    spanning = store.by_seq_range(appended[0].seq, appended[-1].seq)
    assert [r.seq for r in spanning] == [r.seq for r in appended]
    assert {r.segment for r in spanning} == segments_used

    by_corr = store.by_correlation("ex-shared")
    assert {r.seq for r in by_corr} == {r.seq for r in appended}

    store.close()


def test_lookup_on_unmounted_segment_raises_typed_error(tmp_path):
    store = _managed_store(tmp_path, correlation_fields=("exchange_id",))
    appended = [store.append(_synthetic_capsule(exchange_id="ex-a"), consequential=False) for _ in range(30)]

    closed = [s for s in store.list_segments() if s.manifest is not None]
    target = closed[0]
    first_in_target = next(r for r in appended if r.segment == target.name)

    store.unmount_segment(target.name)

    with pytest.raises(SegmentUnmounted) as excinfo:
        store.by_digest(first_in_target.capsule_id)
    assert excinfo.value.checkpoint_root == target.checkpoint_root

    with pytest.raises(SegmentUnmounted):
        store.by_seq_range(first_in_target.seq, first_in_target.seq)

    store.close()


def test_rebuild_identity_across_rotation(tmp_path):
    store = _managed_store(tmp_path, correlation_fields=("exchange_id",))
    for i in range(30):
        store.append(_synthetic_capsule(exchange_id=f"ex-{i % 5}"), consequential=False)

    before = _dump(store)
    store.rebuild_lookup_index()
    after = _dump(store)
    assert before == after
    store.close()


def test_corrupt_index_at_open_falls_back_to_scan(tmp_path, caplog):
    store = LedgerStore(tmp_path, correlation_fields=("exchange_id",))
    appended = [store.append(_synthetic_capsule(exchange_id="ex-a"), consequential=False) for _ in range(3)]
    store.close()

    (tmp_path / "index.sqlite").write_bytes(b"not a real sqlite database" * 4)

    with caplog.at_level(logging.WARNING):
        store2 = LedgerStore(tmp_path, correlation_fields=("exchange_id",))
    assert store2._lookup is None
    assert any("corrupt" in r.message for r in caplog.records)

    hit = store2.by_digest(appended[0].capsule_id)
    assert hit is not None
    assert hit.capsule_id == appended[0].capsule_id

    by_corr = store2.by_correlation("ex-a")
    assert {r.seq for r in by_corr} == {r.seq for r in appended}

    store2.close()


def test_corrupt_index_mid_session_falls_back_to_scan(tmp_path, caplog):
    store = LedgerStore(tmp_path, correlation_fields=("exchange_id",))
    appended = [store.append(_synthetic_capsule(exchange_id="ex-a"), consequential=False) for _ in range(3)]

    # simulate the index becoming unusable mid-session without touching the
    # segments (the source of truth) at all.
    store._lookup.close()

    with caplog.at_level(logging.WARNING):
        hit = store.by_digest(appended[0].capsule_id)
    assert hit is not None
    assert store._lookup is None
    assert any("corrupt" in r.message for r in caplog.records)

    store.close()


def test_rebuild_recovers_from_corruption(tmp_path):
    store = LedgerStore(tmp_path, correlation_fields=("exchange_id",))
    appended = [store.append(_synthetic_capsule(exchange_id="ex-a"), consequential=False) for _ in range(3)]
    store.close()

    (tmp_path / "index.sqlite").write_bytes(b"not a real sqlite database" * 4)

    store2 = LedgerStore(tmp_path, correlation_fields=("exchange_id",))
    assert store2._lookup is None

    store2.rebuild_lookup_index()
    assert store2._lookup is not None

    by_corr = store2.by_correlation("ex-a")
    assert {r.seq for r in by_corr} == {r.seq for r in appended}
    store2.close()


def test_cli_index_rebuild(tmp_path):
    store = LedgerStore(tmp_path, correlation_fields=("exchange_id",))
    appended = [store.append(_synthetic_capsule(exchange_id="ex-a"), consequential=False) for _ in range(3)]
    before = _dump(store)
    store.close()

    rc = main(["index", "rebuild", str(tmp_path)])
    assert rc == 0

    store2 = LedgerStore(tmp_path, correlation_fields=("exchange_id",))
    after = _dump(store2)
    assert before == after
    by_corr = store2.by_correlation("ex-a")
    assert {r.seq for r in by_corr} == {r.seq for r in appended}
    store2.close()


def test_correlation_fields_persist_without_re_declaring(tmp_path):
    store = LedgerStore(tmp_path, correlation_fields=("exchange_id",))
    appended = store.append(_synthetic_capsule(exchange_id="ex-persisted"), consequential=False)
    store.close()

    # reopen with no correlation_fields argument -- must read lookup_config.json
    reopened = LedgerStore(tmp_path)
    assert reopened._correlation_fields == ("exchange_id",)
    hits = reopened.by_correlation("ex-persisted")
    assert [r.seq for r in hits] == [appended.seq]
    reopened.close()
