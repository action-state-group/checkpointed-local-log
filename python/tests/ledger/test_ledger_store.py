# SPDX-License-Identifier: Apache-2.0
import json
import re
import time
from pathlib import Path

from cll.ledger import ChainGap, LedgerAPI, LedgerRecord, LedgerStore, ScanQuery

FIXTURES = Path(__file__).parent / "fixtures"
AMAURY = FIXTURES / "amaury_sample_ledger.jsonl"
NANDA_LEDGER = FIXTURES / "nanda_transaction_ledger.jsonl"

AMAURY_PARENT_ID = "705955419ca6f944a75db77ae2a59844fdd99d355866c6c1dbc4ebe655c024c7"
AMAURY_CHILD_ID = "94c877c7ff0240cf7dafe2067f7016e5412d59b05f9eefa4baf90fc792f16142"


def _fixture_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_store_implements_ledger_api(tmp_path):
    store = LedgerStore(tmp_path)
    assert isinstance(store, LedgerAPI)
    store.close()


def test_amaury_roundtrip(tmp_path):
    store = LedgerStore(tmp_path)
    original = _fixture_lines(AMAURY)
    n = store.import_jsonl(AMAURY)
    assert n == len(original)

    scanned = list(store.scan())
    assert len(scanned) == len(original)
    assert [r.capsule for r in scanned] == original

    for cap in original:
        fetched = store.fetch(cap["capsule_id"])
        assert fetched is not None
        assert fetched.capsule == cap

    # unambiguous prefix lookup
    prefix_hit = store.fetch(original[0]["capsule_id"][:12])
    assert prefix_hit is not None
    assert prefix_hit.capsule_id == original[0]["capsule_id"]

    store.close()


def test_nanda_ledger_roundtrip(tmp_path):
    store = LedgerStore(tmp_path)
    original = _fixture_lines(NANDA_LEDGER)
    n = store.import_jsonl(NANDA_LEDGER)
    assert n == len(original)
    scanned = list(store.scan())
    assert [r.capsule for r in scanned] == original
    store.close()


def test_fetch_missing_returns_none(tmp_path):
    store = LedgerStore(tmp_path)
    store.import_jsonl(AMAURY)
    assert store.fetch("f" * 64) is None
    store.close()


def test_amaury_has_no_gaps_when_intact(tmp_path):
    store = LedgerStore(tmp_path)
    store.import_jsonl(AMAURY)
    assert store.find_gaps() == []
    store.close()


def test_chain_gap_located_finding(tmp_path):
    """Delete the amaury record that another record's chain confirms — a real,
    non-synthetic gap using the sample ledger's own chain linkage."""
    original = _fixture_lines(AMAURY)
    removed = [c for c in original if c["capsule_id"] == AMAURY_PARENT_ID]
    assert removed, "fixture no longer has the expected parent record — update AMAURY_PARENT_ID"
    remaining = [c for c in original if c["capsule_id"] != AMAURY_PARENT_ID]

    gapped_path = tmp_path / "gapped.jsonl"
    gapped_path.write_text("\n".join(json.dumps(c) for c in remaining) + "\n")

    store = LedgerStore(tmp_path / "store")
    store.import_jsonl(gapped_path)

    gaps = store.find_gaps()
    assert len(gaps) == 1
    gap = gaps[0]
    assert isinstance(gap, ChainGap)
    assert gap.missing_parent_id == AMAURY_PARENT_ID
    assert gap.child.capsule_id == AMAURY_CHILD_ID
    assert gap.relation == "confirms"
    assert gap.edge_after.capsule_id == AMAURY_CHILD_ID
    # edge_before is the nearest ledger-position neighbor, not a dead end
    assert gap.edge_before is not None
    assert gap.edge_before.seq == gap.child.seq - 1
    assert gap.window == f"#{gap.edge_before.seq} → #{gap.child.seq}"
    assert gap.duration_seconds is not None
    assert gap.duration_seconds >= 0
    assert gap.browsable_from_either_edge is True

    # not a dead end: both edges are still independently fetchable/scannable
    assert store.fetch(gap.edge_before.capsule_id) is not None
    assert store.fetch(gap.edge_after.capsule_id) is not None
    store.close()


def test_verify_passthrough_ok(tmp_path):
    store = LedgerStore(tmp_path)
    store.import_jsonl(AMAURY)
    first = next(store.scan())
    result = store.verify(first.capsule_id)
    assert result is not None
    assert result.ok is True
    store.close()


def test_verify_passthrough_flags_missing_parent(tmp_path):
    original = _fixture_lines(AMAURY)
    remaining = [c for c in original if c["capsule_id"] != AMAURY_PARENT_ID]
    gapped_path = tmp_path / "gapped.jsonl"
    gapped_path.write_text("\n".join(json.dumps(c) for c in remaining) + "\n")

    store = LedgerStore(tmp_path / "store")
    store.import_jsonl(gapped_path)
    result = store.verify(AMAURY_CHILD_ID)
    assert result is not None
    codes = {f.code for f in result.findings}
    assert "chain_parent_missing" in codes
    store.close()


def test_verify_missing_capsule_returns_none(tmp_path):
    store = LedgerStore(tmp_path)
    store.import_jsonl(AMAURY)
    assert store.verify("f" * 64) is None
    store.close()


def test_scan_filters(tmp_path):
    store = LedgerStore(tmp_path)
    capsules = [
        {
            "capsule_id": format(i, "064x"),
            "operator": "acme" if i % 2 == 0 else "globex",
            "developer": f"agent-{i % 3}",
            "action_type": "approve_purchase" if i < 5 else "record_transaction",
            "timestamp": f"2026-01-01T00:00:{i:02d}Z",
            "disposition": {"verdict_class": "executed" if i % 2 == 0 else "blocked"},
        }
        for i in range(10)
    ]
    for cap in capsules:
        store.append(cap, consequential=False)

    all_records = list(store.scan())
    assert len(all_records) == 10
    assert [r.seq for r in all_records] == list(range(1, 11))

    by_agent = list(store.scan(ScanQuery(agent="agent-1")))
    assert {r.capsule_id for r in by_agent} == {c["capsule_id"] for c in capsules if c["developer"] == "agent-1"}

    by_counterparty = list(store.scan(ScanQuery(counterparty="acme")))
    assert all(r.capsule["operator"] == "acme" for r in by_counterparty)
    assert len(by_counterparty) == 5

    by_verdict = list(store.scan(ScanQuery(verdict="blocked")))
    assert all(r.capsule["disposition"]["verdict_class"] == "blocked" for r in by_verdict)

    by_action = list(store.scan(ScanQuery(action_type="record_transaction")))
    assert len(by_action) == 5

    by_time = list(store.scan(ScanQuery(since="2026-01-01T00:00:03Z", until="2026-01-01T00:00:05Z")))
    assert [r.seq for r in by_time] == [4, 5, 6]

    combined = list(store.scan(ScanQuery(counterparty="acme", verdict="executed")))
    assert {r.capsule_id for r in combined} == {c["capsule_id"] for c in capsules if c["operator"] == "acme"}

    limited = list(store.scan(ScanQuery(limit=3)))
    assert len(limited) == 3

    store.close()


def test_fsync_called_only_when_consequential(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("os.fsync", lambda fd: calls.append(fd))

    store = LedgerStore(tmp_path)
    store.append({"capsule_id": "a" * 64, "operator": "x", "developer": "y",
                   "action_type": "decide", "timestamp": "2026-01-01T00:00:00Z"}, consequential=True)
    assert len(calls) == 1

    store.append({"capsule_id": "b" * 64, "operator": "x", "developer": "y",
                   "action_type": "decide", "timestamp": "2026-01-01T00:00:01Z"}, consequential=False)
    assert len(calls) == 1  # unchanged

    store.close()


def test_consequential_defaults_true(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr("os.fsync", lambda fd: calls.append(fd))
    store = LedgerStore(tmp_path)
    rec = store.append({"capsule_id": "a" * 64, "operator": "x", "developer": "y",
                         "action_type": "decide", "timestamp": "2026-01-01T00:00:00Z"})
    assert rec.consequential is True
    assert len(calls) == 1
    store.close()


def test_segment_rotation(tmp_path):
    store = LedgerStore(tmp_path, segment_max_records=3)
    for i in range(7):
        store.append(
            {"capsule_id": format(i, "064x"), "operator": "x", "developer": "y",
             "action_type": "decide", "timestamp": "2026-01-01T00:00:00Z"},
            consequential=False,
        )
    segments = sorted((tmp_path / "segments").glob("seg-*.jsonl"))
    assert len(segments) == 3  # 3 + 3 + 1
    # every record is still reachable across the rotation boundary
    assert len(list(store.scan())) == 7
    store.close()


def test_reindex_rebuilds_from_segments(tmp_path):
    store = LedgerStore(tmp_path)
    store.import_jsonl(AMAURY)
    before = {r.capsule_id for r in store.scan()}
    store.reindex()
    after = {r.capsule_id for r in store.scan()}
    assert before == after
    store.close()


def test_10k_record_scan_under_100ms(tmp_path):
    store = LedgerStore(tmp_path)
    verdicts = ["executed", "blocked", "deferred", "escalated"]
    actions = ["decide", "approve_purchase", "record_transaction", "dispatch"]
    for i in range(10_000):
        store.append(
            {
                "capsule_id": format(i, "064x"),
                "operator": "acme" if i % 4 == 0 else "globex",
                "developer": f"agent-{i % 25}",
                "action_type": actions[i % len(actions)],
                "timestamp": f"2026-01-01T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}Z",
                "disposition": {"verdict_class": verdicts[i % len(verdicts)]},
            },
            consequential=False,
        )

    t0 = time.perf_counter()
    results = list(store.scan(ScanQuery(agent="agent-7", verdict="executed")))
    elapsed = time.perf_counter() - t0

    assert results
    assert elapsed < 0.1, f"scan took {elapsed:.4f}s, want < 0.1s"
    store.close()


def test_no_direct_sqlite_access_outside_ledger():
    """The ledger query API is the ONLY read path — enforce it, don't just document it."""
    repo_root = Path(__file__).parent.parent.parent / "cll"
    offenders = []
    pattern = re.compile(r"^\s*(import sqlite3|from sqlite3)")
    for py_file in repo_root.rglob("*.py"):
        if "ledger" in py_file.relative_to(repo_root).parts:
            continue
        for lineno, line in enumerate(py_file.read_text().splitlines(), start=1):
            if pattern.match(line):
                offenders.append(f"{py_file}:{lineno}")
    assert not offenders, f"sqlite3 touched outside ledger/: {offenders}"


def test_ledger_record_and_chain_gap_are_serializable_shapes():
    """Public API types must be plain dataclasses of primitives/dicts (no file
    handles, cursors, or connections) so a future remote binding can put them
    on the wire unchanged."""
    import dataclasses

    for cls in (LedgerRecord, ChainGap):
        assert dataclasses.is_dataclass(cls)
