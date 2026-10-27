# SPDX-License-Identifier: Apache-2.0
"""Runs the language-neutral CLL backend conformance vectors against any
backend, built-in or user-supplied.

The vectors (``backend-conformance-vectors/`` in the repository, pinned here
as package data ``vectors.json``) implement docs/backend-contract.md. The
runner depends on no test framework; map each case onto one test::

    import pytest
    from cll.log import conformance
    from cll.log.memory import MemoryStore

    CASES = conformance.cases(MemoryStore)

    @pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
    def test_conformance(case):
        if case.skip:
            pytest.skip(case.skip)
        case.run()

``open`` returns a fresh, empty backend for one case. ``reopen(current)``
closes ``current`` and opens the same durable state again; leave it ``None``
for a backend without durable state. ``digest_append=False`` declares a store
whose ``append`` refuses identities it does not already hold. ``interfaces``
names what the backend implements (``entries``, ``checkpoint``, ``witness``,
``count``, ``close``); cases needing more are skipped. The default is a full
``Backend``; add ``count`` for a backend that also implements
``cll.log.counter.EntryCounter``.

Python backends lack the ``extended-years`` capability: ``datetime`` holds
only years 1..9999 (an intentional difference recorded in the contract).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Any, Callable, Iterable

from . import AppendInput, CllError, InvalidError
from .wire import (
    decode_bytes,
    entry_to_wire,
    parse_decimal,
    parse_time,
    state_from_wire,
    state_to_wire,
    witness_from_wire,
    witness_to_wire,
)

__all__ = ["Case", "cases", "load_vectors", "INTERFACES", "BACKEND_INTERFACES"]

#: Interface names the vectors use, and the operations each requires.
INTERFACES = {
    "entries": ("append", "get_entry", "scan_entries"),
    "checkpoint": ("load_cll", "commit_cll"),
    "witness": ("pending_witnesses", "get_witness", "commit_witness"),
    "count": ("entry_count",),
    "close": ("close",),
}

#: The interfaces of a full ``Backend``, the default for ``cases``.
BACKEND_INTERFACES = ("entries", "checkpoint", "witness", "close")


@dataclass(frozen=True)
class Case:
    """One vector. ``skip`` is set when the case does not apply."""

    name: str
    description: str
    skip: str | None
    run: Callable[[], None]


def load_vectors() -> dict:
    """The pinned vectors document."""
    text = resources.files(__package__).joinpath("vectors.json").read_text(encoding="utf-8")
    document = json.loads(text)
    if document.get("version") != 1:
        raise ValueError("unsupported conformance vectors version")
    return document


def cases(
    open: Callable[[], Any],
    reopen: Callable[[Any], Any] | None = None,
    digest_append: bool = True,
    interfaces: Iterable[str] = BACKEND_INTERFACES,
) -> list:
    """One runnable ``Case`` per vector, skipped where it does not apply."""
    implemented = set(interfaces)
    capabilities = set()
    if digest_append:
        capabilities.add("digest-append")
    if reopen is not None:
        capabilities.add("reopen")
    out = []
    for item in load_vectors()["cases"]:
        skip = None
        missing = [name for name in item["interfaces"] if name not in implemented]
        lacking = [name for name in item.get("requires", ()) if name not in capabilities]
        excluded = [name for name in item.get("unless", ()) if name in capabilities]
        if missing:
            skip = f"backend does not implement {missing[0]}"
        elif lacking:
            skip = f"backend lacks capability {lacking[0]}"
        elif excluded:
            skip = f"case applies only without capability {excluded[0]}"
        out.append(Case(item["name"], item.get("description", ""), skip, _runner(item, open, reopen)))
    return out


def _runner(item: dict, open: Callable[[], Any], reopen: Callable[[Any], Any] | None) -> Callable[[], None]:
    return lambda: _run(item, open, reopen)


def _run(item: dict, open: Callable[[], Any], reopen: Callable[[Any], Any] | None) -> None:
    subject = open()
    try:
        for name in item["interfaces"]:
            for operation in INTERFACES[name]:
                if not callable(getattr(subject, operation, None)):
                    raise AssertionError(f"{item['name']}: backend does not implement {operation}")
        for index, step in enumerate(item["steps"]):
            label = f"{item['name']} step {index} ({step['op']})"
            if step["op"] == "reopen":
                if reopen is None:
                    raise AssertionError(f"{label}: no reopen configured")
                subject = reopen(subject)
                continue
            expect = step["expect"]
            try:
                result = _execute(subject, step)
            except CllError as error:
                if expect.get("error") != error.code:
                    raise AssertionError(f"{label}: expected {expect}, got {error.code}: {error}") from error
                continue
            if "error" in expect:
                raise AssertionError(f"{label}: expected error {expect['error']}, got {result!r}")
            want = _normalize(step["op"], expect.get("result"))
            got = _normalize(step["op"], result)
            if want != got:
                raise AssertionError(f"{label}: expected {want}, got {got}")
    finally:
        close = getattr(subject, "close", None)
        if callable(close):
            close()


def _execute(subject: Any, step: dict) -> Any:
    op = step["op"]
    if op == "append":
        argument = step["input"]
        value = decode_bytes(argument["value"], InvalidError)
        appended_at = parse_time(argument["appendedAt"], InvalidError)
        result = subject.append(AppendInput(value, appended_at))
        return {"entry": entry_to_wire(result.entry), "outcome": result.outcome}
    if op == "getEntry":
        return entry_to_wire(subject.get_entry(decode_bytes(step["value"], InvalidError)))
    if op == "scanEntries":
        after_seq = parse_decimal(step["afterSeq"], InvalidError)
        return [entry_to_wire(entry) for entry in subject.scan_entries(after_seq, step["limit"])]
    if op == "entryCount":
        return str(subject.entry_count())
    if op == "loadCll":
        return state_to_wire(subject.load_cll())
    if op == "commitCll":
        expected_size = parse_decimal(step["expectedSize"], InvalidError)
        expected = step.get("expectedCheckpoint")
        expected_checkpoint = None if expected is None else decode_bytes(expected, InvalidError)
        subject.commit_cll(expected_size, expected_checkpoint, state_from_wire(step["next"], InvalidError))
        return None
    if op == "pendingWitnesses":
        now = parse_time(step["now"], InvalidError)
        return [witness_to_wire(row) for row in subject.pending_witnesses(now, step["limit"])]
    if op == "getWitness":
        size = parse_decimal(step["checkpointSize"], InvalidError)
        row = subject.get_witness(step["witnessId"], size)
        if row is None:
            raise _NotFound()
        return witness_to_wire(row)
    if op == "commitWitness":
        subject.commit_witness(step["expectedAttempts"], witness_from_wire(step["next"], InvalidError))
        return None
    if op == "close":
        subject.close()
        return None
    raise AssertionError(f"unknown conformance op {op!r}")


class _NotFound(CllError):
    """``get_witness`` returned ``None``: the vectors spell it ``not_found``."""

    code = "not_found"

    def __init__(self) -> None:
        super().__init__("get_witness returned None")


def _normalize(op: str, value: Any) -> str:
    if op == "loadCll" and isinstance(value, dict) and isinstance(value.get("witnesses"), list):
        value = dict(value)
        value["witnesses"] = sorted(
            value["witnesses"], key=lambda row: (int(row["checkpointSize"]), row["witnessId"].encode("utf-8"))
        )
    return json.dumps(value, sort_keys=True)
