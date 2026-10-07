# SPDX-License-Identifier: Apache-2.0
"""``ScanQuery.since``/``until`` compare instants, not strings. Record times
come in more than one spelling (whole seconds ``...:59Z``, microseconds
``...:59.999999Z``, offsets); compared as strings, ``...23:59:59Z`` sorts
after ``...23:59:59.999999Z`` and drops out of a bound that ends at the
period's last microsecond."""
from __future__ import annotations

import pytest
from agent_action_capsule import AssuranceBlock, Capsule

from cll.ledger.api import ScanQuery
from cll.ledger.store import LedgerStore


def _capsule(timestamp: str) -> dict:
    return Capsule(
        spec_version="draft-mih-scitt-agent-action-capsule-04",
        format_version="4",
        canonicalization_id="jcs",
        action_id=f"scan-bounds/{timestamp}",
        action_type="fyi",
        operator="ACME-CO",
        developer="agent@v1",
        timestamp=timestamp,
        assurance=AssuranceBlock(
            attestation_mode="self_attested", effect_mode="not_applicable", ledger_mode="standalone"
        ),
    ).seal()


TIMES = [
    "2026-07-31T23:59:59.999999Z",  # last instant before the period
    "2026-08-01T00:00:00Z",  # first second, whole
    "2026-08-01T00:00:00.000001Z",  # first second, fraction
    "2026-08-31T19:59:59-04:00",  # last second, another offset
    "2026-08-31T23:59:59.5Z",  # last second, short fraction
    "2026-08-31T23:59:59Z",  # last second, whole: string-sorts after the bound
    "2026-09-01T00:00:00Z",  # first instant after the period
]


@pytest.fixture
def store(tmp_path):
    store = LedgerStore(tmp_path)
    for t in TIMES:
        store.append(_capsule(t), consequential=False)
    yield store
    store.close()


def _times(store: LedgerStore, query: ScanQuery) -> list[str]:
    return [r.capsule["timestamp"] for r in store.scan(query)]


def test_a_period_includes_every_spelling_of_its_last_second(store):
    got = _times(store, ScanQuery(since="2026-08-01T00:00:00.000000Z", until="2026-08-31T23:59:59.999999Z"))
    assert got == TIMES[1:6]


def test_whole_second_bounds_compare_as_instants(store):
    got = _times(store, ScanQuery(since="2026-08-01T00:00:00Z", until="2026-08-31T23:59:59Z"))
    # The fractional time in the last second is after the whole-second bound.
    assert got == ["2026-08-01T00:00:00Z", "2026-08-01T00:00:00.000001Z", "2026-08-31T19:59:59-04:00", "2026-08-31T23:59:59Z"]


def test_a_date_bound_is_midnight_utc(store):
    assert _times(store, ScanQuery(since="2026-09-01")) == ["2026-09-01T00:00:00Z"]
    assert _times(store, ScanQuery(until="2026-08-01")) == TIMES[:2]


def test_limit_applies_after_the_time_filter(store):
    got = _times(store, ScanQuery(since="2026-08-31T00:00:00Z", limit=2))
    assert got == ["2026-08-31T19:59:59-04:00", "2026-08-31T23:59:59.5Z"]


def test_an_unreadable_bound_is_refused(store):
    with pytest.raises(ValueError):
        list(store.scan(ScanQuery(until="last tuesday")))
