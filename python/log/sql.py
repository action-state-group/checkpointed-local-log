# SPDX-License-Identifier: Apache-2.0
"""Shared relational logic for the SQLite and MySQL backends.

docs/backend-contract.md ("Relational schema") fixes the tables, the JSON
each column holds and the access pattern; this module holds what the two
dialects share. It imports no database driver: each backend passes a cursor
whose ``execute`` takes ``?`` placeholders (MySQL's adapter rewrites them).
"""
from __future__ import annotations

import json
from typing import Any

from . import (
    ENTRY_BYTES,
    IDEMPOTENT,
    INSERTED,
    MAX_PORTABLE_INTEGER,
    AppendInput,
    AppendResult,
    CllState,
    ContentionError,
    CorruptError,
    Entry,
    InvalidError,
    NotFoundError,
    WitnessState,
)
from .engine import (
    apply_cll,
    apply_witness,
    binary,
    check_append,
    check_expected_attempts,
    check_pending,
    check_scan,
    check_value,
    check_witness_key,
    pending,
    validate_state,
    validate_witness,
    witness_key,
)
from .wire import (
    dumps,
    encode_bytes,
    format_time,
    parse_time,
    state_from_wire,
    state_to_wire,
    witness_from_wire,
    witness_to_wire,
)

def metadata(state: CllState) -> bytes:
    """``cll_meta.state``: the state JSON with empty nodes and witnesses."""
    wire = state_to_wire(CllState(
        size=state.size,
        indexed_seq=state.indexed_seq,
        first_pending_at=state.first_pending_at,
        checkpoint=state.checkpoint,
    ))
    return dumps(wire)


def _json(raw: Any, what: str) -> Any:
    try:
        if isinstance(raw, (bytes, bytearray, memoryview)):
            raw = bytes(raw).decode("utf-8")
        return json.loads(raw)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise CorruptError(f"decode {what}") from exc


def entry_from_row(seq: Any, value: Any, appended_at: Any) -> Entry:
    if not isinstance(seq, int) or not 0 < seq <= MAX_PORTABLE_INTEGER:
        raise CorruptError("stored entry is invalid")
    value = binary(value)
    if value is None or len(value) != ENTRY_BYTES:
        raise CorruptError("stored entry is invalid")
    return Entry(seq, value, parse_time(appended_at))


def witness_from_row(witness_id: Any, checkpoint_size: Any, attempts: Any, encoded: Any) -> WitnessState:
    """A witness row whose JSON must agree with its indexed columns."""
    wire = _json(encoded, "witness row")
    if (
        not isinstance(wire, dict)
        or wire.get("witnessId") != witness_id
        or wire.get("checkpointSize") != checkpoint_size
        or wire.get("attempts") != attempts
    ):
        raise CorruptError("witness index disagrees with JSON")
    return validate_witness(witness_from_wire(wire), CorruptError)


def validate_entries(cursor: Any, log_id: str, width_function: str) -> None:
    """Dense entries from 1 with valid widths and times."""
    cursor.execute(
        f"SELECT seq,{width_function}(value),appended_at FROM cll_entries WHERE log_id=? ORDER BY seq",
        (log_id,),
    )
    expected = 1
    for seq, width, appended_at in cursor.fetchall():
        if seq != expected or seq > MAX_PORTABLE_INTEGER or width != ENTRY_BYTES:
            raise CorruptError("stored entries are not dense and valid")
        parse_time(appended_at)
        expected += 1


def load_witnesses(cursor: Any, log_id: str) -> tuple:
    cursor.execute(
        "SELECT witness_id,checkpoint_size,attempts,witness FROM cll_witnesses WHERE log_id=? "
        "ORDER BY checkpoint_size,witness_id",
        (log_id,),
    )
    rows = tuple(witness_from_row(*row) for row in cursor.fetchall())
    keys = {witness_key(row.witness_id, row.checkpoint_size) for row in rows}
    if len(keys) != len(rows):
        raise CorruptError("duplicate witness key")
    return rows


def load_state(cursor: Any, log_id: str, for_update: bool = False) -> CllState:
    cursor.execute("SELECT state FROM cll_meta WHERE log_id=?" + (" FOR UPDATE" if for_update else ""), (log_id,))
    row = cursor.fetchone()
    if row is None:
        raise CorruptError("missing CLL metadata")
    wire = _json(row[0], "CLL metadata")
    if not isinstance(wire, dict):
        raise CorruptError("CLL metadata is not an object")
    cursor.execute("SELECT position,node FROM cll_nodes WHERE log_id=? ORDER BY position", (log_id,))
    nodes = []
    for position, node in cursor.fetchall():
        if position != len(nodes):
            raise CorruptError("stored node positions are not dense")
        # bytes(5) would be five zero bytes: require a real 32-byte buffer.
        node = binary(node)
        if node is None or len(node) != ENTRY_BYTES:
            raise CorruptError("stored node is not 32 bytes")
        nodes.append(encode_bytes(node))
    wire = dict(wire)
    wire["nodes"] = nodes
    wire["witnesses"] = []
    state = state_from_wire(wire)
    state = CllState(
        size=state.size,
        nodes=state.nodes,
        indexed_seq=state.indexed_seq,
        first_pending_at=state.first_pending_at,
        checkpoint=state.checkpoint,
        witnesses=load_witnesses(cursor, log_id),
    )
    return validate_state(state, CorruptError)


def append(cursor: Any, log_id: str, input: AppendInput, lock: bool = False) -> AppendResult:
    """Append under the caller's write transaction. ``lock`` first takes the
    log's ``cll_meta`` row lock (MySQL), after validating ``input``."""
    value, appended_at = check_append(input)
    if lock:
        cursor.execute("SELECT state FROM cll_meta WHERE log_id=? FOR UPDATE", (log_id,))
        if cursor.fetchone() is None:
            raise CorruptError("missing CLL metadata")
    found = _find_entry(cursor, log_id, value)
    if found is not None:
        return AppendResult(found, IDEMPOTENT)
    cursor.execute("SELECT MAX(seq) FROM cll_entries WHERE log_id=?", (log_id,))
    maximum = cursor.fetchone()[0]
    seq = 1 if maximum is None else int(maximum) + 1
    if seq > MAX_PORTABLE_INTEGER:
        raise InvalidError("entry sequence exceeds the portable range")
    cursor.execute(
        "INSERT INTO cll_entries(log_id,seq,value,appended_at) VALUES(?,?,?,?)",
        (log_id, seq, value, format_time(appended_at)),
    )
    return AppendResult(Entry(seq, value, appended_at), INSERTED)


def _find_entry(cursor: Any, log_id: str, value: bytes) -> Entry | None:
    cursor.execute("SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND value=?", (log_id, value))
    row = cursor.fetchone()
    return None if row is None else entry_from_row(*row)


def get_entry(cursor: Any, log_id: str, value: bytes) -> Entry:
    found = _find_entry(cursor, log_id, check_value(value))
    if found is None:
        raise NotFoundError("entry not found")
    return found


def entry_count(cursor: Any, log_id: str) -> int:
    """Sequences are dense, so the last one is the count, and the primary key
    answers it without a scan."""
    cursor.execute("SELECT MAX(seq) FROM cll_entries WHERE log_id=?", (log_id,))
    maximum = cursor.fetchone()[0]
    if maximum is None:
        return 0
    count = int(maximum)
    if count < 1 or count > MAX_PORTABLE_INTEGER:
        raise CorruptError("stored entry sequence is outside the portable range")
    return count


def scan_entries(cursor: Any, log_id: str, after_seq: int, limit: int) -> list:
    check_scan(after_seq, limit)
    cursor.execute(
        "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND seq>? ORDER BY seq LIMIT ?",
        (log_id, after_seq, limit),
    )
    return [entry_from_row(*row) for row in cursor.fetchall()]


def commit_cll(cursor: Any, log_id: str, expected_size: int, expected_checkpoint: bytes | None, next: CllState,
               for_update: bool) -> None:
    """Compare-and-set under the caller's write transaction. Inserts only new
    nodes and new witness rows."""
    current = load_state(cursor, log_id, for_update)
    updated = apply_cll(current, expected_size, expected_checkpoint, next)
    cursor.execute("UPDATE cll_meta SET state=? WHERE log_id=?", (metadata(updated), log_id))
    for position in range(len(current.nodes), len(updated.nodes)):
        cursor.execute(
            "INSERT INTO cll_nodes(log_id,position,node) VALUES(?,?,?)", (log_id, position, updated.nodes[position])
        )
    for row in updated.witnesses[len(current.witnesses):]:
        cursor.execute(
            "INSERT INTO cll_witnesses(log_id,witness_id,checkpoint_size,attempts,witness) VALUES(?,?,?,?,?)",
            (log_id, row.witness_id, str(row.checkpoint_size), row.attempts, dumps(witness_to_wire(row))),
        )


def pending_witnesses(cursor: Any, log_id: str, now: Any, limit: int) -> list:
    now = check_pending(now, limit)
    return pending(load_witnesses(cursor, log_id), now, limit)


def get_witness(cursor: Any, log_id: str, witness_id: str, checkpoint_size: int) -> WitnessState | None:
    check_witness_key(witness_id, checkpoint_size)
    cursor.execute(
        "SELECT witness_id,checkpoint_size,attempts,witness FROM cll_witnesses "
        "WHERE log_id=? AND witness_id=? AND checkpoint_size=?",
        (log_id, witness_id, str(checkpoint_size)),
    )
    row = cursor.fetchone()
    return None if row is None else witness_from_row(*row)


def commit_witness(cursor: Any, log_id: str, expected_attempts: int, next: WitnessState) -> None:
    """Witness compare-and-set: the ``attempts`` predicate on the UPDATE is the
    lock, so it needs no ``cll_meta`` row lock."""
    next = validate_witness(next)
    check_expected_attempts(expected_attempts)
    current = get_witness(cursor, log_id, next.witness_id, next.checkpoint_size)
    if current is None:
        raise ContentionError("witness state changed")
    _, updated = apply_witness([current], expected_attempts, next)
    cursor.execute(
        "UPDATE cll_witnesses SET attempts=?,witness=? "
        "WHERE log_id=? AND witness_id=? AND checkpoint_size=? AND attempts=?",
        (updated.attempts, dumps(witness_to_wire(updated)), log_id, updated.witness_id,
         str(updated.checkpoint_size), expected_attempts),
    )
    if cursor.rowcount != 1:
        raise ContentionError("witness compare-and-set failed")
