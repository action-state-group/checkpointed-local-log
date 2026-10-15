# SPDX-License-Identifier: Apache-2.0
"""Deterministic generator for the CLL backend conformance vectors.

    python3 backend-conformance-vectors/generate.py          # rewrite vectors.json and the pinned copies
    python3 backend-conformance-vectors/generate.py --check  # exit 1 if any committed copy differs

Every case is written from ../docs/backend-contract.md. No implementation code
is imported, so the four implementations are checked against these vectors
rather than producing them.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
VECTORS = HERE / "vectors.json"
# Each implementation reads its own copy because packages cannot reach the
# repository root. --check keeps them byte-identical to vectors.json.
PINNED_COPIES = (
    "go/cll/conformance/vectors.json",
    "ts/src/conformance/vectors.json",
    "rust/checkpointed-local-log/src/log/conformance/vectors.json",
)

MAX_PORTABLE = 9007199254740991
T0 = "2026-09-01T12:00:00.000Z"
T1 = "2026-09-01T12:00:01.000Z"
T2 = "2026-09-01T12:00:02.000Z"
LATER = "2026-09-01T13:00:00.000Z"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def v(byte: int, width: int = 32) -> str:
    """A 32-byte (by default) value of one repeated byte, base64."""
    return b64(bytes([byte]) * width)


def text(value: str) -> str:
    return b64(value.encode())


def entry(seq: int, byte: int, at: str) -> dict:
    return {"seq": str(seq), "value": v(byte), "appendedAt": at}


def append(byte: int, at: str, result: dict | None = None, error: str | None = None, width: int = 32) -> dict:
    return step("append", {"input": {"value": v(byte, width), "appendedAt": at}}, result, error)


def step(op: str, args: dict, result=None, error: str | None = None) -> dict:
    out = {"op": op, **args}
    out["expect"] = {"error": error} if error is not None else {"result": result}
    return out


def ok(op: str, **args) -> dict:
    return step(op, args, None)


def fail(op: str, error: str, **args) -> dict:
    return step(op, args, error=error)


def witness(witness_id: str, size: int, checkpoint: str, attempts: int = 0, at: str = T0, **extra) -> dict:
    out = {
        "witnessId": witness_id,
        "checkpointSize": str(size),
        "checkpoint": checkpoint,
        "attempts": attempts,
        "nextAttemptAt": at,
        "permanent": False,
    }
    out.update(extra)
    return out


def state(nodes: list[str], indexed: int, checkpoint: dict | None = None, witnesses: list[dict] | None = None, **extra) -> dict:
    out = {"size": str(len(nodes)), "indexedSeq": str(indexed), "nodes": nodes}
    if checkpoint is not None:
        out.update(
            checkpoint=checkpoint["bytes"],
            checkpointSize=str(checkpoint["size"]),
            checkpointIndexedSeq=str(checkpoint["indexedSeq"]),
            checkpointPeaks=checkpoint["peaks"],
        )
    out["witnesses"] = witnesses or []
    out.update(extra)
    return out


def checkpoint(data: str, size: int, indexed: int, peaks: list[str]) -> dict:
    return {"bytes": data, "size": size, "indexedSeq": indexed, "peaks": peaks}


def commit(expected_size: int, expected_checkpoint: str | None, next_state: dict, error: str | None = None) -> dict:
    args = {"expectedSize": str(expected_size), "next": next_state}
    if expected_checkpoint is not None:
        args["expectedCheckpoint"] = expected_checkpoint
    return step("commitCll", args, error=error)


EMPTY = {"size": "0", "indexedSeq": "0", "nodes": [], "witnesses": []}
CP1 = text("checkpoint-1")
CP2 = text("checkpoint-2")
N = [v(0x30 + i) for i in range(8)]  # node values; the backend never rehashes them
# MMR sizes and leaf counts: 1 -> 1, 3 -> 2, 4 -> 3, 7 -> 4.
STATE1 = state(N[:1], 1, checkpoint(CP1, 1, 1, N[:1]))
STATE3 = state(N[:3], 2, checkpoint(CP2, 3, 2, [N[2]]))


def entry_cases() -> list[dict]:
    e1, e2, e3 = entry(1, 1, T0), entry(2, 2, T1), entry(3, 3, T2)
    return [
        {
            "name": "entries/empty-log",
            "description": "A new log has no entries; lookups of any 32-byte value are not found.",
            "interfaces": ["entries"],
            "steps": [
                step("scanEntries", {"afterSeq": "0", "limit": 10}, []),
                fail("getEntry", "not_found", value=v(1)),
            ],
        },
        {
            "name": "entries/append-and-idempotent",
            "description": "New values get dense 1-based sequences; a repeated value returns its original entry and time.",
            "interfaces": ["entries"],
            "requires": ["digest-append"],
            "steps": [
                append(1, T0, {"entry": e1, "outcome": "inserted"}),
                append(2, T1, {"entry": e2, "outcome": "inserted"}),
                append(1, LATER, {"entry": e1, "outcome": "idempotent"}),
                append(2, T0, {"entry": e2, "outcome": "idempotent"}),
                step("scanEntries", {"afterSeq": "0", "limit": 10}, [e1, e2]),
                step("getEntry", {"value": v(2)}, e2),
                step("getEntry", {"value": v(1)}, e1),
                fail("getEntry", "not_found", value=v(9)),
            ],
        },
        {
            "name": "entries/scan-bounds",
            "description": "Scans return entries after afterSeq in order, at most limit, and reject out-of-range arguments.",
            "interfaces": ["entries"],
            "requires": ["digest-append"],
            "steps": [
                append(1, T0, {"entry": e1, "outcome": "inserted"}),
                append(2, T1, {"entry": e2, "outcome": "inserted"}),
                append(3, T2, {"entry": e3, "outcome": "inserted"}),
                step("scanEntries", {"afterSeq": "0", "limit": 2}, [e1, e2]),
                step("scanEntries", {"afterSeq": "2", "limit": 2}, [e3]),
                step("scanEntries", {"afterSeq": "1", "limit": 1000}, [e2, e3]),
                step("scanEntries", {"afterSeq": "3", "limit": 1}, []),
                step("scanEntries", {"afterSeq": "100", "limit": 1}, []),
                step("scanEntries", {"afterSeq": str(MAX_PORTABLE), "limit": 1}, []),
                fail("scanEntries", "invalid", afterSeq=str(MAX_PORTABLE + 1), limit=1),
                fail("scanEntries", "invalid", afterSeq="0", limit=0),
                fail("scanEntries", "invalid", afterSeq="0", limit=1001),
            ],
        },
        {
            "name": "entries/invalid-values",
            "description": "Values that are not 32 bytes are invalid for append and lookup, and nothing is stored.",
            "interfaces": ["entries"],
            "steps": [
                append(1, T0, error="invalid", width=31),
                append(1, T0, error="invalid", width=33),
                append(1, T0, error="invalid", width=0),
                fail("getEntry", "invalid", value=v(1, 31)),
                fail("getEntry", "invalid", value=v(1, 0)),
                fail("scanEntries", "invalid", afterSeq="0", limit=0),
                step("scanEntries", {"afterSeq": "0", "limit": 10}, []),
            ],
        },
        {
            "name": "entries/time-range",
            "description": "Append keeps millisecond times exactly and rejects times outside the ECMAScript Date range.",
            "interfaces": ["entries"],
            "requires": ["digest-append"],
            "steps": [
                append(1, "1969-12-31T23:59:59.999Z", {"entry": entry(1, 1, "1969-12-31T23:59:59.999Z"), "outcome": "inserted"}),
                append(2, "0001-01-01T00:00:00.000Z", {"entry": entry(2, 2, "0001-01-01T00:00:00.000Z"), "outcome": "inserted"}),
                append(3, "9999-12-31T23:59:59.999Z", {"entry": entry(3, 3, "9999-12-31T23:59:59.999Z"), "outcome": "inserted"}),
                append(4, "+275760-09-13T00:00:00.001Z", error="invalid"),
                append(4, "-271821-04-19T23:59:59.999Z", error="invalid"),
            ],
        },
        {
            "name": "entries/extended-years",
            "description": "Times outside years 0001..9999 within the ECMAScript Date range use the six-digit year form.",
            "interfaces": ["entries"],
            "requires": ["digest-append", "extended-years"],
            "steps": [
                append(1, "-271821-04-20T00:00:00.000Z", {"entry": entry(1, 1, "-271821-04-20T00:00:00.000Z"), "outcome": "inserted"}),
                append(2, "+275760-09-13T00:00:00.000Z", {"entry": entry(2, 2, "+275760-09-13T00:00:00.000Z"), "outcome": "inserted"}),
                append(3, "0000-01-01T00:00:00.000Z", {"entry": entry(3, 3, "0000-01-01T00:00:00.000Z"), "outcome": "inserted"}),
                step("scanEntries", {"afterSeq": "0", "limit": 10}, [
                    entry(1, 1, "-271821-04-20T00:00:00.000Z"),
                    entry(2, 2, "+275760-09-13T00:00:00.000Z"),
                    entry(3, 3, "0000-01-01T00:00:00.000Z"),
                ]),
            ],
        },
        {
            "name": "entries/digest-append-unsupported",
            "description": "A store without digest-append validates the value, then refuses a new identity as unsupported.",
            "interfaces": ["entries"],
            "unless": ["digest-append"],
            "steps": [
                append(1, T0, error="invalid", width=31),
                append(1, T0, error="unsupported"),
                fail("getEntry", "not_found", value=v(1)),
            ],
        },
    ]


def checkpoint_cases() -> list[dict]:
    w1 = witness("primary", 1, CP1)
    return [
        {
            "name": "checkpoint/initial-state",
            "description": "A new backend has empty CLL state.",
            "interfaces": ["checkpoint"],
            "steps": [step("loadCll", {}, EMPTY)],
        },
        {
            "name": "checkpoint/first-commit",
            "description": "The first commit expects size 0 and no checkpoint, and is returned by loadCll.",
            "interfaces": ["checkpoint"],
            "steps": [
                commit(0, None, state(N[:1], 1, checkpoint(CP1, 1, 1, N[:1]), [w1])),
                step("loadCll", {}, state(N[:1], 1, checkpoint(CP1, 1, 1, N[:1]), [w1])),
                commit(1, CP1, state(N[:1], 1, checkpoint(CP1, 1, 1, N[:1]), [w1])),
                step("loadCll", {}, state(N[:1], 1, checkpoint(CP1, 1, 1, N[:1]), [w1])),
            ],
        },
        {
            "name": "checkpoint/state-without-checkpoint",
            "description": "Nodes and indexedSeq may advance without a checkpoint, and firstPendingAt round-trips.",
            "interfaces": ["checkpoint"],
            "steps": [
                commit(0, None, state(N[:3], 2, firstPendingAt=T1)),
                step("loadCll", {}, state(N[:3], 2, firstPendingAt=T1)),
                commit(3, None, state(N[:4], 3)),
                step("loadCll", {}, state(N[:4], 3)),
            ],
        },
        {
            "name": "checkpoint/compare-and-set",
            "description": "A stale expected size or checkpoint is contention, before any validation of next.",
            "interfaces": ["checkpoint"],
            "steps": [
                commit(1, None, STATE1, error="contention"),
                commit(0, CP1, STATE1, error="contention"),
                commit(1, None, state(N[:2], 1), error="contention"),
                commit(0, None, STATE1),
                commit(0, None, STATE3, error="contention"),
                commit(1, None, STATE3, error="contention"),
                commit(1, CP2, STATE3, error="contention"),
                commit(3, CP1, STATE3, error="contention"),
                commit(1, CP1, STATE3),
                step("loadCll", {}, STATE3),
            ],
        },
        {
            "name": "checkpoint/invalid-structure",
            "description": "A next state whose nodes, size or checkpoint tuple break the structural rules is invalid.",
            "interfaces": ["checkpoint"],
            "steps": [
                commit(0, None, {**state(N[:1], 1), "size": "2"}, error="invalid"),
                commit(0, None, state(N[:2], 1), error="invalid"),
                commit(0, None, state(N[:2], 2), error="invalid"),
                commit(0, None, state(N[:3], 3), error="invalid"),
                commit(0, None, state(N[:3], 1), error="invalid"),
                commit(0, None, state([v(1, 31)], 1), error="invalid"),
                commit(0, None, state([v(1, 33)], 1), error="invalid"),
                commit(0, None, {k: val for k, val in STATE1.items() if k != "checkpointPeaks"}, error="invalid"),
                commit(0, None, {k: val for k, val in STATE1.items() if k != "checkpoint"}, error="invalid"),
                commit(0, None, {k: val for k, val in STATE1.items() if k != "checkpointSize"}, error="invalid"),
                commit(0, None, state(N[:1], 1, checkpoint("", 1, 1, N[:1])), error="invalid"),
                commit(0, None, state(N[:1], 1, checkpoint(CP1, 0, 0, [])), error="invalid"),
                commit(0, None, state(N[:1], 1, checkpoint(CP1, 3, 1, N[:1])), error="invalid"),
                commit(0, None, state(N[:1], 1, checkpoint(CP1, 1, 2, N[:1])), error="invalid"),
                commit(0, None, state(N[:1], 1, checkpoint(CP1, 1, 1, [v(1, 31)])), error="invalid"),
                step("loadCll", {}, EMPTY),
                commit(0, None, STATE1),
            ],
        },
        {
            "name": "checkpoint/invalid-witness-rows",
            "description": "Witness rows inside a commit follow the witness rules, and a key may appear once.",
            "interfaces": ["checkpoint"],
            "steps": [
                commit(0, None, state(N[:1], 1, witnesses=[w1, w1]), error="invalid"),
                commit(0, None, state(N[:1], 1, witnesses=[witness("", 1, CP1)]), error="invalid"),
                commit(0, None, state(N[:1], 1, witnesses=[witness("bad id", 1, CP1)]), error="invalid"),
                commit(0, None, state(N[:1], 1, witnesses=[witness("primary", 0, CP1)]), error="invalid"),
                commit(0, None, state(N[:1], 1, witnesses=[witness("primary", 1, "")]), error="invalid"),
                commit(0, None, state(N[:1], 1, witnesses=[witness("primary", 1, CP1, lastError="x" * 4097)]), error="invalid"),
                step("loadCll", {}, EMPTY),
                commit(0, None, state(N[:1], 1, witnesses=[witness("a" * 191, 1, CP1, lastError="x" * 4096)])),
            ],
        },
        {
            "name": "checkpoint/append-only",
            "description": "Existing nodes cannot change and size cannot shrink.",
            "interfaces": ["checkpoint"],
            "steps": [
                commit(0, None, state(N[:3], 2)),
                commit(3, None, state([v(0x7F)] + N[1:3], 2), error="invalid"),
                commit(3, None, state(N[:1], 1), error="invalid"),
                commit(3, None, state([v(0x7F)] + N[1:4], 3), error="invalid"),
                commit(3, None, state(N[:4], 3)),
                step("loadCll", {}, state(N[:4], 3)),
            ],
        },
        {
            "name": "checkpoint/checkpoint-transitions",
            "description": "A checkpoint cannot be removed, move backward, or change at the size it already holds.",
            "interfaces": ["checkpoint"],
            "steps": [
                commit(0, None, STATE1),
                commit(1, CP1, state(N[:3], 2), error="contention"),
                commit(1, CP1, state(N[:3], 2, checkpoint(text("changed"), 1, 1, N[:1])), error="contention"),
                commit(1, CP1, state(N[:3], 2, checkpoint(CP1, 1, 1, [N[2]])), error="contention"),
                commit(1, CP1, state(N[:3], 2, checkpoint(CP1, 1, 0, N[:1])), error="contention"),
                commit(1, CP1, STATE3),
                commit(3, CP2, state(N[:4], 3, checkpoint(CP1, 1, 1, N[:1])), error="contention"),
                commit(3, CP2, state(N[:4], 3, checkpoint(text("checkpoint-3"), 3, 1, [N[2]])), error="contention"),
                commit(3, CP2, state(N[:4], 3, checkpoint(text("checkpoint-3"), 4, 3, [N[2], N[3]]))),
                step("loadCll", {}, state(N[:4], 3, checkpoint(text("checkpoint-3"), 4, 3, [N[2], N[3]]))),
            ],
        },
    ]


def witness_cases() -> list[dict]:
    w1 = witness("primary", 1, CP1)
    w1_tried = witness("primary", 1, CP1, attempts=1, at=LATER, lastError="timeout")
    w2 = witness("secondary", 1, CP1)
    receipt = witness(
        "primary", 1, CP1, attempts=2, at=LATER,
        receipt=text("receipt"), entryHash="ab" * 32, entryHashScheme="legacy", leafIndex=0, treeSize=1,
    )
    base = state(N[:1], 1, checkpoint(CP1, 1, 1, N[:1]))
    return [
        {
            "name": "witness/get",
            "description": "getWitness validates the key, then returns the row or not found.",
            "interfaces": ["checkpoint", "witness"],
            "steps": [
                fail("getWitness", "not_found", witnessId="primary", checkpointSize="1"),
                commit(0, None, {**base, "witnesses": [w1]}),
                step("getWitness", {"witnessId": "primary", "checkpointSize": "1"}, w1),
                fail("getWitness", "not_found", witnessId="primary", checkpointSize="3"),
                fail("getWitness", "not_found", witnessId="other", checkpointSize="1"),
                fail("getWitness", "invalid", witnessId="", checkpointSize="1"),
                fail("getWitness", "invalid", witnessId="bad id", checkpointSize="1"),
                fail("getWitness", "invalid", witnessId="a" * 192, checkpointSize="1"),
                fail("getWitness", "invalid", witnessId="primary", checkpointSize="0"),
            ],
        },
        {
            "name": "witness/commit-cas",
            "description": "commitWitness validates next, then compares attempts and checkpoint bytes with the stored row.",
            "interfaces": ["checkpoint", "witness"],
            "steps": [
                commit(0, None, {**base, "witnesses": [w1]}),
                fail("commitWitness", "contention", expectedAttempts=0, next=witness("missing", 1, CP1, attempts=1)),
                fail("commitWitness", "contention", expectedAttempts=1, next=w1_tried),
                fail("commitWitness", "contention", expectedAttempts=0, next=witness("primary", 1, CP2, attempts=1)),
                fail("commitWitness", "invalid", expectedAttempts=0, next=witness("missing", 1, CP1, lastError="x" * 4097)),
                ok("commitWitness", expectedAttempts=0, next=w1_tried),
                step("getWitness", {"witnessId": "primary", "checkpointSize": "1"}, w1_tried),
                fail("commitWitness", "contention", expectedAttempts=0, next=receipt),
                ok("commitWitness", expectedAttempts=1, next=receipt),
                step("getWitness", {"witnessId": "primary", "checkpointSize": "1"}, receipt),
                step("pendingWitnesses", {"now": LATER, "limit": 32}, []),
            ],
        },
        {
            "name": "witness/invalid-rows",
            "description": "commitWitness rejects rows that break the witness rules as invalid.",
            "interfaces": ["checkpoint", "witness"],
            "steps": [
                commit(0, None, {**base, "witnesses": [w1]}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "lastError": "x" * 4097}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "witnessId": "bad id"}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "checkpointSize": "0"}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "checkpoint": ""}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "receipt": ""}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "receipt": text("r"), "entryHash": "AB" * 32}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "receipt": text("r"), "entryHash": "ab" * 31}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "receipt": text("r"), "entryHashScheme": "other"}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "receipt": text("r"), "leafIndex": -1}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "receipt": text("r"), "treeSize": MAX_PORTABLE + 1}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "entryHash": "ab" * 32}),
                fail("commitWitness", "invalid", expectedAttempts=0, next={**w1_tried, "leafIndex": 0}),
                step("getWitness", {"witnessId": "primary", "checkpointSize": "1"}, w1),
                ok("commitWitness", expectedAttempts=0, next={**w1_tried, "receipt": text("r"), "leafIndex": MAX_PORTABLE, "treeSize": 0}),
            ],
        },
        {
            "name": "witness/commit-cll-merge",
            "description": "commitCll inserts new witness keys, keeps existing rows as stored, never deletes rows, and rejects rebinding a key.",
            "interfaces": ["checkpoint", "witness"],
            "steps": [
                commit(0, None, {**base, "witnesses": [w1]}),
                ok("commitWitness", expectedAttempts=0, next=w1_tried),
                commit(1, CP1, {**base, "witnesses": [w1, w2]}),
                step("getWitness", {"witnessId": "primary", "checkpointSize": "1"}, w1_tried),
                step("getWitness", {"witnessId": "secondary", "checkpointSize": "1"}, w2),
                commit(1, CP1, {**base, "witnesses": []}),
                step("loadCll", {}, {**base, "witnesses": [w1_tried, w2]}),
                commit(1, CP1, {**base, "witnesses": [witness("secondary", 1, CP2)]}, error="contention"),
                step("getWitness", {"witnessId": "secondary", "checkpointSize": "1"}, w2),
            ],
        },
        {
            "name": "witness/pending-order",
            "description": "pendingWitnesses returns due rows without receipt or permanent failure, by numeric size then witness ID.",
            "interfaces": ["checkpoint", "witness"],
            "steps": [
                commit(0, None, state(N[:1], 1, witnesses=[
                    witness("zeta", 10, CP1),
                    witness("beta", 9, CP1),
                    witness("alpha", 9, CP1),
                    witness("later", 2, CP1, at=LATER),
                    witness("done", 2, CP1, receipt=text("receipt")),
                    witness("failed", 2, CP1, permanent=True),
                    witness("mid", 3, CP1, at=T0),
                ])),
                step("pendingWitnesses", {"now": T0, "limit": 32}, [
                    witness("mid", 3, CP1),
                    witness("alpha", 9, CP1),
                    witness("beta", 9, CP1),
                    witness("zeta", 10, CP1),
                ]),
                step("pendingWitnesses", {"now": T0, "limit": 2}, [witness("mid", 3, CP1), witness("alpha", 9, CP1)]),
                step("pendingWitnesses", {"now": "2026-09-01T11:59:59.999Z", "limit": 32}, []),
                step("pendingWitnesses", {"now": LATER, "limit": 1}, [witness("later", 2, CP1, at=LATER)]),
                fail("pendingWitnesses", "invalid", now=T0, limit=0),
                fail("pendingWitnesses", "invalid", now=T0, limit=33),
            ],
        },
    ]


def lifecycle_cases() -> list[dict]:
    closed_steps = [
        fail("append", "closed", input={"value": v(8), "appendedAt": T0}),
        fail("append", "closed", input={"value": v(8, 1), "appendedAt": T0}),
        fail("getEntry", "closed", value=v(1)),
        fail("getEntry", "closed", value=v(1, 1)),
        fail("scanEntries", "closed", afterSeq="0", limit=1),
        fail("scanEntries", "closed", afterSeq=str(MAX_PORTABLE + 1), limit=0),
        fail("loadCll", "closed"),
        fail("commitCll", "closed", expectedSize="0", next={**EMPTY, "size": "2"}),
        fail("pendingWitnesses", "closed", now=T0, limit=0),
        fail("getWitness", "closed", witnessId="", checkpointSize="0"),
        fail("commitWitness", "closed", expectedAttempts=0, next=witness("", 0, "")),
    ]
    return [
        {
            "name": "lifecycle/close",
            "description": "close is repeatable, and every other operation then fails closed before validating arguments.",
            "interfaces": ["entries", "checkpoint", "witness", "close"],
            "steps": [ok("close"), ok("close"), *closed_steps, ok("close")],
        },
        {
            "name": "lifecycle/reopen",
            "description": "A persistent backend reopens with the same entries, CLL state and witness rows.",
            "interfaces": ["entries", "checkpoint", "witness", "close"],
            "requires": ["digest-append", "reopen"],
            "steps": [
                append(1, T0, {"entry": entry(1, 1, T0), "outcome": "inserted"}),
                append(2, T1, {"entry": entry(2, 2, T1), "outcome": "inserted"}),
                commit(0, None, {**STATE3, "witnesses": [witness("primary", 3, CP2)], "firstPendingAt": T2}),
                ok("commitWitness", expectedAttempts=0, next=witness("primary", 3, CP2, attempts=1, at=LATER)),
                ok("reopen"),
                step("scanEntries", {"afterSeq": "0", "limit": 10}, [entry(1, 1, T0), entry(2, 2, T1)]),
                step("loadCll", {}, {**STATE3, "witnesses": [witness("primary", 3, CP2, attempts=1, at=LATER)], "firstPendingAt": T2}),
                append(1, LATER, {"entry": entry(1, 1, T0), "outcome": "idempotent"}),
                append(3, T2, {"entry": entry(3, 3, T2), "outcome": "inserted"}),
                ok("reopen"),
                step("getEntry", {"value": v(3)}, entry(3, 3, T2)),
                step("getWitness", {"witnessId": "primary", "checkpointSize": "3"}, witness("primary", 3, CP2, attempts=1, at=LATER)),
            ],
        },
    ]


def build() -> dict:
    return {
        "version": 1,
        "contract": "docs/backend-contract.md",
        "description": (
            "Language-neutral CLL backend conformance cases. Each case runs its steps in order against a fresh, "
            "empty backend. Arguments and results use the contract's portable encodings. A case runs only when the "
            "backend implements every listed interface, has every capability in requires and none in unless."
        ),
        "interfaces": {
            "entries": "EntryStore: append, getEntry, scanEntries",
            "checkpoint": "CheckpointStateStore: loadCll, commitCll",
            "witness": "WitnessStateStore: pendingWitnesses, getWitness, commitWitness",
            "close": "close",
        },
        "capabilities": {
            "digest-append": "append stores a bare 32-byte identity (absent: append of a new identity is unsupported)",
            "reopen": "the runner can close the backend and open the same durable state again (the reopen step)",
            "extended-years": "times outside years 0001..9999 are representable",
        },
        "cases": entry_cases() + checkpoint_cases() + witness_cases() + lifecycle_cases(),
    }


def render() -> bytes:
    return (json.dumps(build(), indent=1, ensure_ascii=False) + "\n").encode()


def main(argv: list[str]) -> int:
    data = render()
    targets = [VECTORS] + [ROOT / path for path in PINNED_COPIES]
    if argv[1:] == ["--check"]:
        stale = [str(t.relative_to(ROOT)) for t in targets if not t.exists() or t.read_bytes() != data]
        if stale:
            print("stale backend conformance vectors: " + ", ".join(stale), file=sys.stderr)
            return 1
        return 0
    if argv[1:]:
        print(__doc__, file=sys.stderr)
        return 2
    for target in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
