# SPDX-License-Identifier: Apache-2.0
"""The shared CLL transition engine: validation, check order, idempotent
append, compare-and-set rules, witness merge and pending order.

Every Python backend applies these functions, so they all report the codes
docs/backend-contract.md ("Operations") assigns, in its check order. This is a
port of Go's ``go/internal/backend/engine.go``. Durable backends call the same
rules with ``CorruptError`` while replaying or opening stored state.

``Engine`` is the in-memory representation the memory and JSONL backends hold;
the SQL backends call the module-level functions on rows they read.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Sequence

from . import (
    ENTRY_BYTES,
    IDEMPOTENT,
    INSERTED,
    MAX_ATTEMPTS,
    MAX_CHECKPOINT_BYTES,
    MAX_PORTABLE_INTEGER,
    MAX_REASON_BYTES,
    MAX_SCAN_LIMIT,
    MAX_WITNESS_RESPONSE_BYTES,
    MAX_WITNESSES,
    AppendInput,
    AppendResult,
    CheckpointState,
    CllError,
    CllState,
    ContentionError,
    CorruptError,
    Entry,
    InvalidError,
    NotFoundError,
    WitnessReceipt,
    WitnessState,
    validate_identifier,
)
from .wire import normalize_time

__all__ = [
    "Engine",
    "binary",
    "check_expected_attempts",
    "mmr_leaf_count",
    "witness_key",
    "check_append",
    "check_value",
    "check_scan",
    "check_witness_key",
    "check_pending",
    "validate_entries",
    "validate_state",
    "validate_witness",
    "apply_cll",
    "apply_witness",
    "pending",
    "added_witnesses",
]

_ENTRY_HASH = re.compile(r"[0-9a-f]{64}")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def binary(value: object) -> bytes | None:
    """``value``'s raw bytes when it is a binary buffer, else ``None``.

    Conversion comes before any length check: ``len`` of a typed
    ``memoryview`` counts items, not bytes (``memoryview(bytes(128)).cast("I")``
    has length 32)."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return None


def _width(value: object, minimum: int, maximum: int) -> bytes | None:
    """``value`` as bytes when it is a buffer of ``minimum..maximum`` bytes."""
    data = binary(value)
    if data is None or not minimum <= len(data) <= maximum:
        return None
    return data


def _utf8_length(value: str) -> int | None:
    """UTF-8 byte length, or ``None`` for a string with an unpaired
    surrogate, which has no UTF-8 encoding."""
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def mmr_leaf_count(size: int) -> int | None:
    """Leaf count of a complete MMR of ``size`` nodes, or ``None`` when
    ``size`` is not a complete MMR size."""
    leaves = 0
    remaining = size
    previous = None
    while remaining > 0:
        height = (remaining + 1).bit_length() - 2  # largest mountain 2^(h+1)-1 <= remaining
        if previous is not None and height >= previous:
            return None
        remaining -= (1 << (height + 1)) - 1
        leaves += 1 << height
        previous = height
    return leaves


def witness_key(witness_id: str, checkpoint_size: int) -> tuple:
    return (witness_id, checkpoint_size)


# -- argument checks (always before stored state is consulted) -----------------


def check_value(value: object) -> bytes:
    data = _width(value, ENTRY_BYTES, ENTRY_BYTES)
    if data is None:
        raise InvalidError("entry value must be exactly 32 bytes")
    return data


def check_append(input: object) -> tuple:
    """Validated ``(value, appended_at)`` of an ``AppendInput``."""
    if not isinstance(input, AppendInput):
        raise InvalidError("append input must be an AppendInput")
    return check_value(input.value), normalize_time(input.appended_at)


def check_scan(after_seq: object, limit: object) -> None:
    if not _is_int(after_seq) or not 0 <= after_seq <= MAX_PORTABLE_INTEGER:
        raise InvalidError("after_seq is outside 0..MaxPortableInteger")
    if not _is_int(limit) or not 1 <= limit <= MAX_SCAN_LIMIT:
        raise InvalidError("limit is outside 1..MaxScanLimit")


def check_witness_key(witness_id: object, checkpoint_size: object) -> None:
    if not validate_identifier(witness_id) or not _is_int(checkpoint_size) or not 0 < checkpoint_size < 1 << 64:
        raise InvalidError("invalid witness key")


def check_pending(now: object, limit: object) -> datetime:
    if not _is_int(limit) or not 1 <= limit <= MAX_WITNESSES:
        raise InvalidError("limit is outside 1..MaxWitnesses")
    return normalize_time(now)


def check_expected_attempts(expected_attempts: object) -> None:
    if not _is_int(expected_attempts) or not 0 <= expected_attempts <= MAX_ATTEMPTS:
        raise InvalidError("expected_attempts is outside 0..4294967295")


# -- value rules -----------------------------------------------------------------


def validate_entries(entries: Sequence[Entry], error: type[CllError] = CorruptError) -> None:
    """Stored entries are dense from 1, 32 bytes wide and distinct."""
    seen = set()
    for index, entry in enumerate(entries):
        if (
            entry.seq != index + 1
            or entry.seq > MAX_PORTABLE_INTEGER
            or _width(entry.value, ENTRY_BYTES, ENTRY_BYTES) is None
        ):
            raise error("stored CLL entries are not contiguous and valid")
        normalize_time(entry.appended_at, error)
        if entry.value in seen:
            raise error("stored CLL entries contain duplicates")
        seen.add(entry.value)


def validate_witness(value: object, error: type[CllError] = InvalidError) -> WitnessState:
    """The contract's witness rules. Returns the row with ``bytes`` values
    and a UTC millisecond ``next_attempt_at``."""
    if not isinstance(value, WitnessState):
        raise error("witness state must be a WitnessState")
    checkpoint = _width(value.checkpoint, 1, MAX_CHECKPOINT_BYTES)
    if (
        not validate_identifier(value.witness_id)
        or not _is_int(value.checkpoint_size)
        or not 0 < value.checkpoint_size < 1 << 64
        or checkpoint is None
        or not _is_int(value.attempts)
        or not 0 <= value.attempts <= MAX_ATTEMPTS
        or not isinstance(value.permanent, bool)
    ):
        raise error("witness state is invalid")
    if value.last_error is not None:
        length = _utf8_length(value.last_error) if isinstance(value.last_error, str) else None
        if length is None or length > MAX_REASON_BYTES:
            raise error("witness last_error is invalid")
    next_attempt_at = normalize_time(value.next_attempt_at, error)
    receipt = value.receipt
    if receipt is not None:
        receipt_bytes = _width(receipt.bytes, 1, MAX_WITNESS_RESPONSE_BYTES) if isinstance(receipt, WitnessReceipt) else None
        if receipt_bytes is None:
            raise error("witness receipt is invalid")
        if receipt.entry_hash is not None and (
            not isinstance(receipt.entry_hash, str) or _ENTRY_HASH.fullmatch(receipt.entry_hash) is None
        ):
            raise error("witness entry hash is invalid")
        if receipt.entry_hash_scheme is not None and receipt.entry_hash_scheme != "legacy":
            raise error("witness entry hash scheme is invalid")
        for position in (receipt.leaf_index, receipt.tree_size):
            if position is not None and (not _is_int(position) or not 0 <= position <= MAX_PORTABLE_INTEGER):
                raise error("witness receipt position is invalid")
        receipt = WitnessReceipt(
            bytes=receipt_bytes,
            entry_hash=receipt.entry_hash,
            entry_hash_scheme=receipt.entry_hash_scheme,
            leaf_index=receipt.leaf_index,
            tree_size=receipt.tree_size,
        )
    return WitnessState(
        witness_id=value.witness_id,
        checkpoint_size=value.checkpoint_size,
        checkpoint=checkpoint,
        attempts=value.attempts,
        next_attempt_at=next_attempt_at,
        receipt=receipt,
        permanent=value.permanent,
        last_error=value.last_error,
    )


def _validate_metadata(value: CllState, node_count: int, error: type[CllError]) -> tuple:
    """Header rules shared by full states and JSONL deltas. Returns the
    normalized ``(first_pending_at, checkpoint, witnesses)``."""
    if not _is_int(value.size) or value.size != node_count:
        raise error("CLL size does not match nodes")
    if not _is_int(value.indexed_seq) or mmr_leaf_count(value.size) != value.indexed_seq:
        raise error("CLL nodes do not form the indexed MMR")
    first_pending_at = None
    if value.first_pending_at is not None:
        first_pending_at = normalize_time(value.first_pending_at, error)
    checkpoint = value.checkpoint
    if checkpoint is not None:
        data = _width(checkpoint.bytes, 1, MAX_CHECKPOINT_BYTES) if isinstance(checkpoint, CheckpointState) else None
        if (
            data is None
            or not _is_int(checkpoint.size)
            or not 0 < checkpoint.size <= value.size
            or not _is_int(checkpoint.indexed_seq)
            or not 0 <= checkpoint.indexed_seq <= value.indexed_seq
            or not isinstance(checkpoint.peaks, (tuple, list))
        ):
            raise error("checkpoint state is invalid")
        peaks = tuple(_width(peak, ENTRY_BYTES, ENTRY_BYTES) for peak in checkpoint.peaks)
        if None in peaks:
            raise error("checkpoint peak has wrong width")
        checkpoint = CheckpointState(
            bytes=data,
            size=checkpoint.size,
            indexed_seq=checkpoint.indexed_seq,
            peaks=peaks,
        )
    if not isinstance(value.witnesses, (tuple, list)):
        raise error("witnesses must be a sequence")
    witnesses = []
    seen = set()
    for row in value.witnesses:
        row = validate_witness(row, error)
        key = witness_key(row.witness_id, row.checkpoint_size)
        if key in seen:
            raise error("duplicate witness key")
        seen.add(key)
        witnesses.append(row)
    return first_pending_at, checkpoint, tuple(witnesses)


def _nodes(value: object, error: type[CllError]) -> tuple:
    if not isinstance(value, (tuple, list)):
        raise error("nodes must be a sequence")
    nodes = tuple(_width(node, ENTRY_BYTES, ENTRY_BYTES) for node in value)
    if None in nodes:
        raise error("node has wrong width")
    return nodes


def validate_state(value: object, error: type[CllError] = InvalidError) -> CllState:
    """Structural rules for a complete state. Returns it normalized."""
    if not isinstance(value, CllState):
        raise error("CLL state must be a CllState")
    if not isinstance(value.nodes, (tuple, list)):
        raise error("nodes must be a sequence")
    first_pending_at, checkpoint, witnesses = _validate_metadata(value, len(value.nodes), error)
    return CllState(
        size=value.size,
        nodes=_nodes(value.nodes, error),
        indexed_seq=value.indexed_seq,
        first_pending_at=first_pending_at,
        checkpoint=checkpoint,
        witnesses=witnesses,
    )


def _same_expected(checkpoint: CheckpointState | None, expected: bytes | None) -> bool:
    if checkpoint is None:
        return expected is None
    return expected is not None and checkpoint.bytes == expected


def _check_expected(current: CllState, expected_size: object, expected_checkpoint: object) -> None:
    if expected_checkpoint is not None:
        expected_checkpoint = binary(expected_checkpoint)
        if expected_checkpoint is None:
            raise InvalidError("expected checkpoint must be bytes or None")
    if not _is_int(expected_size):
        raise InvalidError("expected size must be an integer")
    if current.size != expected_size or not _same_expected(current.checkpoint, expected_checkpoint):
        raise ContentionError("CLL state changed")


def added_witnesses(current: CllState, next: CllState) -> tuple:
    """Checkpoint and witness transition rules. Returns the witness rows
    ``next`` adds; repeated keys keep the stored row."""
    if next.indexed_seq < current.indexed_seq:
        raise InvalidError("CLL state is not append-only")
    old, new = current.checkpoint, next.checkpoint
    if old is not None and new is None:
        raise ContentionError("checkpoint cannot be removed")
    if old is not None and new is not None:
        if new.size < old.size or new.indexed_seq < old.indexed_seq:
            raise ContentionError("checkpoint moved backward")
        if new.size == old.size and (
            new.bytes != old.bytes or new.indexed_seq != old.indexed_seq or tuple(new.peaks) != tuple(old.peaks)
        ):
            raise ContentionError("checkpoint changed at an existing size")
    existing = {witness_key(row.witness_id, row.checkpoint_size): row for row in current.witnesses}
    added = []
    for row in next.witnesses:
        stored = existing.get(witness_key(row.witness_id, row.checkpoint_size))
        if stored is not None:
            if stored.checkpoint != row.checkpoint:
                raise ContentionError("witness checkpoint changed")
            continue
        added.append(row)
    return tuple(added)


def apply_cll(current: CllState, expected_size: object, expected_checkpoint: object, next: object) -> CllState:
    """``commit_cll`` on ``current``: compare, validate, then transition."""
    _check_expected(current, expected_size, expected_checkpoint)
    next = validate_state(next)
    if (
        next.size < current.size
        or next.indexed_seq < current.indexed_seq
        or next.nodes[: len(current.nodes)] != current.nodes
    ):
        raise InvalidError("CLL state is not append-only")
    added = added_witnesses(current, next)
    return CllState(
        size=next.size,
        nodes=next.nodes,
        indexed_seq=next.indexed_seq,
        first_pending_at=next.first_pending_at,
        checkpoint=next.checkpoint,
        witnesses=tuple(current.witnesses) + added,
    )


def apply_cll_delta(current: CllState, expected_size: int, expected_checkpoint: bytes | None, delta: CllState) -> CllState:
    """A JSONL ``cll.commit`` whose ``nodes`` and ``witnesses`` hold only the
    rows that commit adds."""
    _check_expected(current, expected_size, expected_checkpoint)
    nodes = _nodes(delta.nodes, InvalidError)
    if delta.size != current.size + len(nodes):
        raise InvalidError("CLL node delta does not match size")
    first_pending_at, checkpoint, witnesses = _validate_metadata(delta, delta.size, InvalidError)
    normalized = CllState(
        size=delta.size,
        nodes=nodes,
        indexed_seq=delta.indexed_seq,
        first_pending_at=first_pending_at,
        checkpoint=checkpoint,
        witnesses=witnesses,
    )
    added = added_witnesses(current, normalized)
    return CllState(
        size=delta.size,
        nodes=tuple(current.nodes) + nodes,
        indexed_seq=delta.indexed_seq,
        first_pending_at=first_pending_at,
        checkpoint=checkpoint,
        witnesses=tuple(current.witnesses) + added,
    )


def apply_witness(rows: Sequence[WitnessState], expected_attempts: object, next: object) -> tuple:
    """``commit_witness`` on ``rows``: validate ``next``, then compare
    attempts and checkpoint bytes. Returns ``(index, row)`` to store."""
    next = validate_witness(next)
    check_expected_attempts(expected_attempts)
    key = witness_key(next.witness_id, next.checkpoint_size)
    for index, row in enumerate(rows):
        if witness_key(row.witness_id, row.checkpoint_size) != key:
            continue
        if row.attempts != expected_attempts:
            raise ContentionError("witness state changed")
        if row.checkpoint != next.checkpoint:
            raise ContentionError("witness checkpoint changed")
        return index, next
    raise ContentionError("witness state changed")


def pending(rows: Sequence[WitnessState], now: datetime, limit: int) -> list:
    """Due rows without receipt or permanent failure, by numeric
    ``checkpoint_size`` then ``witness_id`` byte order, at most ``limit``."""
    due = [row for row in rows if row.receipt is None and not row.permanent and row.next_attempt_at <= now]
    due.sort(key=lambda row: (row.checkpoint_size, row.witness_id.encode("utf-8")))
    return due[:limit]


class Engine:
    """In-memory entries and CLL state with the contract's transition rules.
    Callers serialize access."""

    def __init__(self) -> None:
        self._entries: list = []
        self._by_value: dict = {}
        self._state = CllState()

    @property
    def entries(self) -> tuple:
        return tuple(self._entries)

    @property
    def state(self) -> CllState:
        return self._state

    def snapshot(self) -> tuple:
        return len(self._entries), self._state

    def restore(self, snapshot: tuple) -> None:
        count, state = snapshot
        for entry in self._entries[count:]:
            del self._by_value[entry.value]
        del self._entries[count:]
        self._state = state

    def append(self, input: AppendInput) -> AppendResult:
        value, appended_at = check_append(input)
        index = self._by_value.get(value)
        if index is not None:
            return AppendResult(self._entries[index], IDEMPOTENT)
        seq = len(self._entries) + 1
        if seq > MAX_PORTABLE_INTEGER:
            raise InvalidError("entry sequence exceeds the portable range")
        entry = Entry(seq, value, appended_at)
        self._entries.append(entry)
        self._by_value[value] = seq - 1
        return AppendResult(entry, INSERTED)

    def replay_entry(self, entry: Entry) -> None:
        """Apply a stored entry; anything but the next dense insert is
        corrupt."""
        try:
            result = self.append(AppendInput(entry.value, entry.appended_at))
        except CllError as exc:
            raise CorruptError(f"invalid stored entry: {exc}") from exc
        if result.outcome != INSERTED or result.entry.seq != entry.seq or result.entry.appended_at != entry.appended_at:
            raise CorruptError("invalid stored entry")

    def get_entry(self, value: bytes) -> Entry:
        index = self._by_value.get(check_value(value))
        if index is None:
            raise NotFoundError("entry not found")
        return self._entries[index]

    def scan_entries(self, after_seq: int, limit: int) -> list:
        check_scan(after_seq, limit)
        return self._entries[after_seq : after_seq + limit]

    def commit_cll(self, expected_size: int, expected_checkpoint: bytes | None, next: CllState) -> None:
        self._state = apply_cll(self._state, expected_size, expected_checkpoint, next)

    def commit_cll_delta(self, expected_size: int, expected_checkpoint: bytes | None, delta: CllState) -> None:
        self._state = apply_cll_delta(self._state, expected_size, expected_checkpoint, delta)

    def delta_since(self, snapshot: tuple) -> CllState:
        """The JSONL ``cll.commit`` delta of the mutation after ``snapshot``."""
        before = snapshot[1]
        current = self._state
        existing = {witness_key(row.witness_id, row.checkpoint_size) for row in before.witnesses}
        return CllState(
            size=current.size,
            nodes=current.nodes[len(before.nodes) :],
            indexed_seq=current.indexed_seq,
            first_pending_at=current.first_pending_at,
            checkpoint=current.checkpoint,
            witnesses=tuple(
                row for row in current.witnesses if witness_key(row.witness_id, row.checkpoint_size) not in existing
            ),
        )

    def pending_witnesses(self, now: datetime, limit: int) -> list:
        now = check_pending(now, limit)
        return pending(self._state.witnesses, now, limit)

    def get_witness(self, witness_id: str, checkpoint_size: int) -> WitnessState | None:
        check_witness_key(witness_id, checkpoint_size)
        for row in self._state.witnesses:
            if row.witness_id == witness_id and row.checkpoint_size == checkpoint_size:
                return row
        return None

    def commit_witness(self, expected_attempts: int, next: WitnessState) -> None:
        rows = list(self._state.witnesses)
        index, row = apply_witness(rows, expected_attempts, next)
        rows[index] = row
        state = self._state
        self._state = CllState(
            size=state.size,
            nodes=state.nodes,
            indexed_seq=state.indexed_seq,
            first_pending_at=state.first_pending_at,
            checkpoint=state.checkpoint,
            witnesses=tuple(rows),
        )
