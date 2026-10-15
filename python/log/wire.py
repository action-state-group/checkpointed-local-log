# SPDX-License-Identifier: Apache-2.0
"""Portable encodings of docs/backend-contract.md ("Portable encodings").

Counters are base-10 strings without leading zeros, bytes are RFC 4648
standard base64 with padding, times are ``Date.prototype.toISOString()``
strings with three fraction digits, and absent optional values are absent
fields, never ``null``. Every JSONL event and relational JSON column uses
these, so Python reads what Go and TypeScript write and the reverse.

Decoders take an ``error`` class: ``InvalidError`` for caller input (the
conformance runner) and ``CorruptError`` for durable data.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from typing import Any

from . import (
    MAX_ATTEMPTS,
    CheckpointState,
    CllError,
    CllState,
    CorruptError,
    Entry,
    InvalidError,
    WitnessReceipt,
    WitnessState,
)

__all__ = [
    "normalize_time",
    "format_time",
    "parse_time",
    "format_decimal",
    "parse_decimal",
    "encode_bytes",
    "decode_bytes",
    "entry_to_wire",
    "entry_from_wire",
    "witness_to_wire",
    "witness_from_wire",
    "state_to_wire",
    "state_from_wire",
    "dumps",
]

_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z")
_DECIMAL = re.compile(r"0|[1-9][0-9]*")


def normalize_time(value: object, error: type[CllError] = InvalidError) -> datetime:
    """``value`` in UTC, truncated to whole milliseconds. Naive datetimes and
    non-datetimes raise ``error``: the contract's times are instants."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise error("time must be a timezone-aware datetime")
    try:
        value = value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise error("time is outside the representable range") from exc
    return value.replace(microsecond=value.microsecond // 1000 * 1000)


def format_time(value: datetime) -> str:
    """``Date.prototype.toISOString()`` of ``value``. Python years are always
    0001..9999, so the signed six-digit year form never occurs."""
    value = normalize_time(value)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond // 1000,
    )


def parse_time(text: object, error: type[CllError] = CorruptError) -> datetime:
    """Parse exactly the ``toISOString()`` form. A valid portable time whose
    year Python cannot hold (0000 or the signed six-digit form) also raises
    ``error``."""
    match = _TIME.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        raise error(f"invalid portable time: {text!r}")
    year, month, day, hour, minute, second, millis = (int(part) for part in match.groups())
    try:
        parsed = datetime(year, month, day, hour, minute, second, millis * 1000, tzinfo=timezone.utc)
    except ValueError as exc:
        raise error(f"invalid portable time: {text!r}") from exc
    return parsed


def format_decimal(value: int) -> str:
    return str(value)


def parse_decimal(text: object, error: type[CllError] = CorruptError) -> int:
    """A canonical unsigned 64-bit base-10 string."""
    if not isinstance(text, str) or _DECIMAL.fullmatch(text) is None:
        raise error(f"invalid decimal: {text!r}")
    value = int(text)
    if value >= 1 << 64:
        raise error(f"decimal exceeds 64 bits: {text!r}")
    return value


def encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode_bytes(text: object, error: type[CllError] = CorruptError) -> bytes:
    """Strict standard base64 with padding."""
    if not isinstance(text, str):
        raise error("base64 value must be a string")
    try:
        decoded = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise error(f"invalid base64: {text!r}") from exc
    if base64.b64encode(decoded).decode("ascii") != text:
        raise error(f"non-canonical base64: {text!r}")
    return decoded


def dumps(value: Any) -> bytes:
    """Compact UTF-8 JSON without insignificant whitespace."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# -- values --------------------------------------------------------------------


def _object(value: object, what: str, error: type[CllError]) -> dict:
    if not isinstance(value, dict):
        raise error(f"{what} must be a JSON object")
    return value


def _required(wire: dict, key: str, error: type[CllError]) -> Any:
    if key not in wire:
        raise error(f"missing field {key}")
    return wire[key]


def _string(value: object, what: str, error: type[CllError]) -> str:
    if not isinstance(value, str):
        raise error(f"{what} must be a string")
    return value


def _integer(value: object, what: str, error: type[CllError]) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise error(f"{what} must be an integer")
    return value


def entry_to_wire(entry: Entry) -> dict:
    return {
        "seq": format_decimal(entry.seq),
        "value": encode_bytes(entry.value),
        "appendedAt": format_time(entry.appended_at),
    }


def entry_from_wire(wire: object, error: type[CllError] = CorruptError) -> Entry:
    """Decode an entry. Width and range checks belong to the engine."""
    wire = _object(wire, "entry", error)
    return Entry(
        seq=parse_decimal(_required(wire, "seq", error), error),
        value=decode_bytes(_required(wire, "value", error), error),
        appended_at=parse_time(_required(wire, "appendedAt", error), error),
    )


def witness_to_wire(value: WitnessState) -> dict:
    wire: dict = {
        "witnessId": value.witness_id,
        "checkpointSize": format_decimal(value.checkpoint_size),
        "checkpoint": encode_bytes(value.checkpoint),
        "attempts": value.attempts,
        "nextAttemptAt": format_time(value.next_attempt_at),
    }
    receipt = value.receipt
    if receipt is not None:
        wire["receipt"] = encode_bytes(receipt.bytes)
        if receipt.entry_hash is not None:
            wire["entryHash"] = receipt.entry_hash
        if receipt.entry_hash_scheme is not None:
            wire["entryHashScheme"] = receipt.entry_hash_scheme
        if receipt.leaf_index is not None:
            wire["leafIndex"] = receipt.leaf_index
        if receipt.tree_size is not None:
            wire["treeSize"] = receipt.tree_size
    wire["permanent"] = value.permanent
    if value.last_error is not None:
        wire["lastError"] = value.last_error
    return wire


def witness_from_wire(wire: object, error: type[CllError] = CorruptError) -> WitnessState:
    """Decode a witness row. Receipt metadata without receipt bytes is not
    representable and raises ``error``; the witness rules belong to the
    engine."""
    wire = _object(wire, "witness", error)
    attempts = _integer(_required(wire, "attempts", error), "attempts", error)
    if not 0 <= attempts <= MAX_ATTEMPTS:
        raise error("attempts is outside 0..4294967295")
    permanent = _required(wire, "permanent", error)
    if not isinstance(permanent, bool):
        raise error("permanent must be a boolean")
    last_error = wire.get("lastError")
    if last_error is not None:
        last_error = _string(last_error, "lastError", error)
    metadata = {
        "entry_hash": wire.get("entryHash"),
        "entry_hash_scheme": wire.get("entryHashScheme"),
        "leaf_index": wire.get("leafIndex"),
        "tree_size": wire.get("treeSize"),
    }
    receipt = None
    if wire.get("receipt") is not None:
        for key in ("entry_hash", "entry_hash_scheme"):
            if metadata[key] is not None:
                _string(metadata[key], key, error)
        for key in ("leaf_index", "tree_size"):
            if metadata[key] is not None:
                _integer(metadata[key], key, error)
        receipt = WitnessReceipt(bytes=decode_bytes(wire["receipt"], error), **metadata)
    elif any(item is not None for item in metadata.values()):
        raise error("witness receipt metadata without receipt bytes")
    return WitnessState(
        witness_id=_string(_required(wire, "witnessId", error), "witnessId", error),
        checkpoint_size=parse_decimal(_required(wire, "checkpointSize", error), error),
        checkpoint=decode_bytes(_required(wire, "checkpoint", error), error),
        attempts=attempts,
        next_attempt_at=parse_time(_required(wire, "nextAttemptAt", error), error),
        receipt=receipt,
        permanent=permanent,
        last_error=last_error,
    )


def state_to_wire(value: CllState) -> dict:
    wire: dict = {
        "size": format_decimal(value.size),
        "indexedSeq": format_decimal(value.indexed_seq),
        "nodes": [encode_bytes(node) for node in value.nodes],
    }
    if value.first_pending_at is not None:
        wire["firstPendingAt"] = format_time(value.first_pending_at)
    if value.checkpoint is not None:
        wire["checkpoint"] = encode_bytes(value.checkpoint.bytes)
        wire["checkpointSize"] = format_decimal(value.checkpoint.size)
        wire["checkpointIndexedSeq"] = format_decimal(value.checkpoint.indexed_seq)
        wire["checkpointPeaks"] = [encode_bytes(peak) for peak in value.checkpoint.peaks]
    wire["witnesses"] = [witness_to_wire(row) for row in value.witnesses]
    return wire


_CHECKPOINT_FIELDS = ("checkpoint", "checkpointSize", "checkpointIndexedSeq", "checkpointPeaks")


def state_from_wire(wire: object, error: type[CllError] = CorruptError) -> CllState:
    """Decode a state. An incomplete checkpoint tuple raises ``error``; the
    structural rules belong to the engine."""
    wire = _object(wire, "state", error)
    nodes = _required(wire, "nodes", error)
    witnesses = _required(wire, "witnesses", error)
    if not isinstance(nodes, list) or not isinstance(witnesses, list):
        raise error("nodes and witnesses must be arrays")
    first_pending_at = wire.get("firstPendingAt")
    present = [wire.get(key) is not None for key in _CHECKPOINT_FIELDS]
    checkpoint = None
    if all(present):
        peaks = wire["checkpointPeaks"]
        if not isinstance(peaks, list):
            raise error("checkpointPeaks must be an array")
        checkpoint = CheckpointState(
            bytes=decode_bytes(wire["checkpoint"], error),
            size=parse_decimal(wire["checkpointSize"], error),
            indexed_seq=parse_decimal(wire["checkpointIndexedSeq"], error),
            peaks=tuple(decode_bytes(peak, error) for peak in peaks),
        )
    elif any(present):
        raise error("checkpoint tuple is incomplete")
    return CllState(
        size=parse_decimal(_required(wire, "size", error), error),
        indexed_seq=parse_decimal(_required(wire, "indexedSeq", error), error),
        nodes=tuple(decode_bytes(node, error) for node in nodes),
        first_pending_at=None if first_pending_at is None else parse_time(first_pending_at, error),
        checkpoint=checkpoint,
        witnesses=tuple(witness_from_wire(row, error) for row in witnesses),
    )
