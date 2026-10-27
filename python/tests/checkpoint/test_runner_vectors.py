# SPDX-License-Identifier: Apache-2.0
"""The shared runner vectors (``runner-conformance-vectors/``) against the
Python checkpoint and witness delivery runners.

The Go runners produced the vectors; replaying them here proves the Python
runners leave the same durable state, with byte-identical checkpoint
statements, on the same steps. Python has every capability the vectors name,
so no case is skipped.
"""
from __future__ import annotations

import base64
import json
import threading
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cll.checkpoint.runner import CheckpointRunner, Ed25519CheckpointSigner
from cll.checkpoint.witness import WitnessDeliveryRunner
from cll.log import AppendInput, ContentionError, RejectedError, WitnessReceipt
from cll.log.memory import MemoryStore
from cll.log.wire import parse_time, state_to_wire

ROOT = Path(__file__).parents[3]
VECTORS = json.loads((ROOT / "runner-conformance-vectors" / "vectors.json").read_text())
CAPABILITIES = {"bounded-run", "stop-after-retryable"}


class _Script:
    """Each witness's scripted submit outcomes and verify answers, in order.
    The runner calls witnesses from worker threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.submit: dict = {}
        self.verify: dict = {}

    def load(self, step: dict) -> None:
        with self._lock:
            self.submit = {key: list(value) for key, value in (step.get("submit") or {}).items()}
            self.verify = {key: list(value) for key, value in (step.get("verify") or {}).items()}

    def pop(self, table: dict, witness_id: str):
        with self._lock:
            items = table.get(witness_id) or []
            assert items, f"witness {witness_id} called more than scripted"
            return items.pop(0)

    def assert_exhausted(self) -> None:
        assert not any(self.submit.values()) and not any(self.verify.values()), "scripted answers left unused"


class _Submitter:
    def __init__(self, script: _Script, witness_id: str) -> None:
        self._script, self._id = script, witness_id

    def submit(self, checkpoint: bytes) -> WitnessReceipt:
        outcome = self._script.pop(self._script.submit, self._id)
        if outcome.get("error") == "retryable":
            raise ContentionError("scripted retryable failure")
        if outcome.get("error") == "permanent":
            raise RejectedError("scripted permanent failure")
        receipt = outcome["receipt"]
        return WitnessReceipt(
            base64.b64decode(receipt["bytes"]),
            receipt["entryHash"],
            receipt["entryHashScheme"],
            receipt["leafIndex"],
            receipt["treeSize"],
        )


class _Verifier:
    def __init__(self, script: _Script, witness_id: str) -> None:
        self._script, self._id = script, witness_id

    def verify(self, checkpoint: bytes, receipt: WitnessReceipt) -> None:
        if not self._script.pop(self._script.verify, self._id):
            raise RejectedError("scripted receipt rejection")


def _normalize(state) -> dict:
    wire = state_to_wire(state)
    wire["witnesses"].sort(key=lambda row: (int(row["checkpointSize"]), row["witnessId"]))
    for row in wire["witnesses"]:
        if "lastError" in row:
            row["lastError"] = "<set>"
    return wire


def _replay(case: dict) -> None:
    signer = Ed25519CheckpointSigner(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTORS["signingKeySeed"])))
    config = case["config"]
    store = MemoryStore()
    runner = CheckpointRunner(
        store,
        signer,
        VECTORS["logId"],
        witness_ids=config.get("witnessIds") or (),
        cadence_entries=config["cadenceEntries"],
        cadence_age=timedelta(milliseconds=config["cadenceAgeMs"]),
        scan_limit=config["scanLimit"],
    )
    script = _Script()
    witnesses = config.get("witnessIds") or ()
    delivery = None
    if witnesses:
        delivery = WitnessDeliveryRunner(
            store,
            {witness_id: _Submitter(script, witness_id) for witness_id in witnesses},
            {witness_id: _Verifier(script, witness_id) for witness_id in witnesses},
            base_backoff=timedelta(milliseconds=config["baseBackoffMs"]),
            max_backoff=timedelta(milliseconds=config["maxBackoffMs"]),
            jitter=False,
        )
    for index, step in enumerate(case["steps"]):
        label = f"{case['name']} step {index} ({step['op']})"
        op = step["op"]
        if op == "append":
            store.append(AppendInput(base64.b64decode(step["value"]), parse_time(step["appendedAt"])))
        elif op == "runCheckpoint":
            runner.run_once(parse_time(step["now"]))
        elif op == "deliverWitnesses":
            script.load(step)
            completed = delivery.run_once(parse_time(step["now"]), step["limit"])
            script.assert_exhausted()
            assert completed == step["expect"]["result"], label
        elif op == "loadCll":
            assert _normalize(store.load_cll()) == step["expect"]["result"], label
        else:
            raise AssertionError(f"{label}: unknown op")


def test_every_case_applies():
    assert VECTORS["version"] == 1
    assert set(VECTORS["capabilities"]) == CAPABILITIES
    assert VECTORS["cases"]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[case["name"] for case in VECTORS["cases"]])
def test_runner_vector(case):
    assert set(case.get("requires", ())) <= CAPABILITIES
    _replay(case)


def test_a_wrong_expectation_fails():
    case = json.loads(json.dumps(VECTORS["cases"][1]))
    case["steps"][-1]["expect"]["result"]["indexedSeq"] = "0"
    with pytest.raises(AssertionError):
        _replay(case)


