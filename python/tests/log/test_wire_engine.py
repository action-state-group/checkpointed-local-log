# SPDX-License-Identifier: Apache-2.0
"""Portable encodings and engine rules not reached through the vectors."""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from cll.log import (
    CorruptError,
    CllState,
    InvalidError,
    WitnessState,
    validate_identifier,
)
from cll.log.engine import Engine, mmr_leaf_count, validate_state, validate_witness
from cll.log.wire import (
    decode_bytes,
    format_time,
    parse_decimal,
    parse_time,
    state_from_wire,
    state_to_wire,
    witness_from_wire,
    witness_to_wire,
)

UTC = timezone.utc


@pytest.mark.parametrize(
    "value,text",
    [
        (datetime(2026, 9, 1, 12, 0, 0, 123456, tzinfo=UTC), "2026-09-01T12:00:00.123Z"),
        (datetime(1, 1, 1, tzinfo=UTC), "0001-01-01T00:00:00.000Z"),
        (datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC), "9999-12-31T23:59:59.999Z"),
        (datetime(2026, 9, 1, 14, 0, tzinfo=timezone(timedelta(hours=2))), "2026-09-01T12:00:00.000Z"),
    ],
)
def test_format_time_matches_to_iso_string(value, text):
    assert format_time(value) == text


@pytest.mark.parametrize(
    "text",
    [
        "2026-09-01T12:00:00Z",
        "2026-09-01T12:00:00.000+00:00",
        "2026-02-30T00:00:00.000Z",
        "0000-01-01T00:00:00.000Z",  # valid portable time Python cannot hold
        "+010000-01-01T00:00:00.000Z",
        "-000001-01-01T00:00:00.000Z",
        "2026-09-01t12:00:00.000Z",
        7,
    ],
)
def test_parse_time_rejects(text):
    with pytest.raises(CorruptError):
        parse_time(text)
    with pytest.raises(InvalidError):
        parse_time(text, InvalidError)


def test_naive_and_overflowing_times_are_invalid():
    with pytest.raises(InvalidError):
        format_time(datetime(2026, 1, 1))
    with pytest.raises(InvalidError):
        format_time(datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1))))


@pytest.mark.parametrize("text", ["", "01", "-1", "1.0", " 1", str(1 << 64), 1])
def test_parse_decimal_rejects(text):
    with pytest.raises(CorruptError):
        parse_decimal(text)


def test_decode_bytes_is_strict():
    assert decode_bytes("YQ==") == b"a"
    for text in ("YQ", "YR==", "Y Q==", "YQ==\n", "-_8=", None):
        with pytest.raises(CorruptError):
            decode_bytes(text)


def test_identifier_rules():
    assert validate_identifier("a" * 191)
    assert validate_identifier("primary.witness:1/x-y_z")
    for bad in ("", "a" * 192, "bad id", "é", None):
        assert not validate_identifier(bad)


def test_mmr_leaf_count():
    assert [mmr_leaf_count(size) for size in range(12)] == [0, 1, None, 2, 3, None, None, 4, 5, None, 6, 7]


def test_witness_wire_round_trip_and_metadata_rule():
    row = {
        "witnessId": "w",
        "checkpointSize": "3",
        "checkpoint": "YQ==",
        "attempts": 2,
        "nextAttemptAt": "2026-09-01T12:00:00.000Z",
        "receipt": "Yg==",
        "entryHash": "ab" * 32,
        "entryHashScheme": "legacy",
        "leafIndex": 0,
        "treeSize": 3,
        "permanent": False,
        "lastError": "x",
        "futureField": True,  # additive fields are accepted
    }
    witness = witness_from_wire(row)
    expected = dict(row)
    del expected["futureField"]
    assert witness_to_wire(witness) == expected
    with pytest.raises(CorruptError):
        witness_from_wire({**{k: v for k, v in row.items() if k != "receipt"}})
    with pytest.raises(CorruptError):
        witness_from_wire({**row, "permanent": None})
    with pytest.raises(CorruptError):
        witness_from_wire({**row, "attempts": True})
    with pytest.raises(CorruptError):
        witness_from_wire({**row, "attempts": 1 << 32})
    with pytest.raises(CorruptError):
        witness_from_wire({k: v for k, v in row.items() if k != "witnessId"})


def test_state_wire_requires_a_complete_checkpoint_tuple():
    wire = {"size": "1", "indexedSeq": "1", "nodes": ["A" * 43 + "="], "witnesses": [], "checkpoint": "YQ=="}
    with pytest.raises(CorruptError):
        state_from_wire(wire)
    with pytest.raises(CorruptError):
        state_from_wire([])
    with pytest.raises(CorruptError):
        state_from_wire({"size": "0", "indexedSeq": "0", "nodes": {}, "witnesses": []})
    assert state_to_wire(state_from_wire({"size": "0", "indexedSeq": "0", "nodes": [], "witnesses": []})) == {
        "size": "0",
        "indexedSeq": "0",
        "nodes": [],
        "witnesses": [],
    }


def test_engine_rejects_wrong_types():
    engine = Engine()
    with pytest.raises(InvalidError):
        engine.commit_cll(0, None, "state")  # type: ignore[arg-type]
    with pytest.raises(InvalidError):
        engine.commit_cll(0, "cp", CllState())  # type: ignore[arg-type]
    with pytest.raises(InvalidError):
        engine.commit_witness(-1, WitnessState("w", 1, b"a", 0, datetime(2026, 1, 1, tzinfo=UTC)))
    with pytest.raises(InvalidError):
        engine.pending_witnesses(datetime(2026, 1, 1), 1)
    with pytest.raises(InvalidError):
        validate_witness(WitnessState("w", 1, b"a", 0, datetime(2026, 1, 1, tzinfo=UTC), last_error="é" * 2049))
    with pytest.raises(CorruptError):
        validate_state(CllState(size=1), CorruptError)


def test_importing_cll_log_loads_no_database_driver():
    code = (
        "import sys, cll, cll.log, cll.log.engine, cll.log.wire, cll.log.memory, cll.log.jsonl, "
        "cll.log.conformance, cll.log.ledger\n"
        "loaded = sorted(name for name in ('sqlite3', '_sqlite3', 'pymysql') if name in sys.modules)\n"
        "assert not loaded, loaded\n"
        "assert 'cll.ledger' not in sys.modules\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)
