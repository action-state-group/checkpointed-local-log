# SPDX-License-Identifier: Apache-2.0
"""The shared backend conformance vectors against every Python backend.

Test IDs are ``<backend>/<case>``, so ``pytest -k jsonl/`` runs one backend.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from cll.log import InvalidError, conformance, jsonl, sqlite
from cll.log.memory import MemoryStore
from tests.log.conftest import mysql_url, unique_log_id

ROOT = Path(__file__).resolve().parents[3]


class EntryOnly:
    """A user-style store implementing only ``EntryStore``."""

    def __init__(self) -> None:
        self._inner = MemoryStore()

    def append(self, input):
        return self._inner.append(input)

    def get_entry(self, value):
        return self._inner.get_entry(value)

    def scan_entries(self, after_seq, limit):
        return self._inner.scan_entries(after_seq, limit)


class Durable:
    """``open``/``reopen`` for a persistent backend module."""

    def __init__(self, module, target) -> None:
        self.module = module
        self.target = target
        self.args = {}

    def open(self):
        args = self.target()
        self.module.init(*args)
        store = self.module.open(*args)
        self.args[id(store)] = args
        return store

    def reopen(self, current):
        args = self.args.pop(id(current))
        current.close()
        store = self.module.open(*args)
        self.args[id(store)] = args
        return store


def _ledger_store(tmp_path_factory):
    from cll.ledger.store import LedgerStore
    from cll.log.ledger import LedgerEntryStore

    return LedgerEntryStore(LedgerStore(tmp_path_factory.mktemp("ledger")), owns_store=True)


def _configs(tmp_path_factory):
    def jsonl_target():
        return (str(tmp_path_factory.mktemp("jsonl") / "log.jsonl"),)

    def sqlite_target():
        return (str(tmp_path_factory.mktemp("sqlite") / "cll.sqlite"), unique_log_id())

    def mysql_target():
        return (mysql_url(), unique_log_id("conformance"))

    durable = {"jsonl": Durable(jsonl, jsonl_target), "sqlite": Durable(sqlite, sqlite_target)}

    def mysql_durable():
        from cll.log import mysql

        return Durable(mysql, mysql_target)

    return {
        "memory": lambda: conformance.cases(MemoryStore),
        "jsonl": lambda: conformance.cases(durable["jsonl"].open, durable["jsonl"].reopen),
        "sqlite": lambda: conformance.cases(durable["sqlite"].open, durable["sqlite"].reopen),
        "mysql": lambda: (lambda d: conformance.cases(d.open, d.reopen))(mysql_durable()),
        "entry-only": lambda: conformance.cases(EntryOnly, interfaces=("entries",)),
        "ledger": lambda: conformance.cases(
            lambda: _ledger_store(tmp_path_factory), digest_append=False, interfaces=("entries",)
        ),
    }


_NAMES = [case.name for case in conformance.cases(MemoryStore)]
_BACKENDS = ["memory", "jsonl", "sqlite", "mysql", "entry-only", "ledger"]


@pytest.mark.parametrize(
    "backend,name",
    [(backend, name) for backend in _BACKENDS for name in _NAMES],
    ids=[f"{backend}/{name}" for backend in _BACKENDS for name in _NAMES],
)
def test_conformance_vector(backend, name, tmp_path_factory):
    if backend == "mysql":
        mysql_url()
    case = next(case for case in _configs(tmp_path_factory)[backend]() if case.name == name)
    if case.skip:
        pytest.skip(case.skip)
    case.run()


def test_expected_skips_are_exactly_the_documented_differences():
    """Python lacks only ``extended-years``; the memory backend lacks only
    ``reopen``; a store without digest append runs the unsupported case."""
    skipped = {case.name: case.skip for case in conformance.cases(MemoryStore) if case.skip}
    assert skipped == {
        "entries/extended-years": "backend lacks capability extended-years",
        "entries/digest-append-unsupported": "case applies only without capability digest-append",
        "lifecycle/reopen": "backend lacks capability reopen",
    }
    ledger = {case.name for case in conformance.cases(MemoryStore, digest_append=False, interfaces=("entries",))
              if not case.skip}
    assert ledger == {"entries/empty-log", "entries/invalid-values", "entries/digest-append-unsupported"}


def test_runner_reports_a_wrong_result():
    class Broken(MemoryStore):
        def get_entry(self, value):
            raise InvalidError("wrong code")

    case = next(case for case in conformance.cases(Broken) if case.name == "entries/empty-log")
    with pytest.raises(AssertionError, match="expected"):
        case.run()


def test_runner_reports_a_missing_operation():
    case = next(case for case in conformance.cases(object, interfaces=("entries",)) if case.name == "entries/empty-log")
    with pytest.raises(AssertionError, match="does not implement"):
        case.run()


def test_pinned_vectors_equal_the_repository_vectors():
    root = ROOT / "backend-conformance-vectors" / "vectors.json"
    if not root.exists():
        pytest.skip("not running from a repository checkout")
    pinned = Path(conformance.__file__).with_name("vectors.json")
    assert pinned.read_bytes() == root.read_bytes()
    assert os.path.getsize(pinned) > 0
