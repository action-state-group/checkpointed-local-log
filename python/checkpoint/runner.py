# SPDX-License-Identifier: Apache-2.0
"""``cll.checkpoint.runner`` -- the checkpoint runner over a CLL backend.

A port of Go's ``checkpoint.Runner`` (``go/checkpoint/runner.go``). The
runner indexes the entry log into the MMR state a ``cll.log.CheckpointStore``
keeps, signs a checkpoint when the cadence is due, and queues one witness
row per configured witness. Every commit is ``commit_cll``'s compare-and-set,
so runners in any language can take turns on one durable log; the shared
``runner-conformance-vectors/`` pin the state and the checkpoint bytes.

Each ``run_once`` scans at most one batch of ``scan_limit`` entries, so its
cost is bounded however far behind the index is. ``run`` repeats it until
the log is caught up, then waits for ``notify`` or the poll interval.

Checkpoints use the COSE wire form of ``cll.checkpoint.cose_wire``.
``Ed25519CheckpointSigner`` signs them with a deterministic protected
header, so a statement is byte-identical to the one Go or TypeScript signs
with the same key, log and time.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Protocol

import cbor2

from ..log import (
    DEFAULT_SCAN_LIMIT,
    MAX_SCAN_LIMIT,
    MAX_WITNESSES,
    CheckpointState,
    CllState,
    ContentionError,
    CorruptError,
    InvalidError,
    WitnessState,
    validate_identifier,
)
from ..log.wire import normalize_time
from . import core
from .cose_wire import checkpoint_to_cose, verify_checkpoint_cose_offline
from .emit import CheckpointRecord
from .store import MemoryNodeStore

__all__ = ["CheckpointSigner", "CheckpointRunner", "Ed25519CheckpointSigner", "checkpoint_timestamp"]

_COSE_ALG_EDDSA = -8


class CheckpointSigner(Protocol):
    """What the runner needs from a signer: the raw Ed25519 public key as
    lowercase hex, and the ``sign_cose_statement`` shape that
    ``cose_wire.checkpoint_to_cose`` calls."""

    key_id: str

    def sign_cose_statement(self, payload: bytes, *, content_type: str, issuer: str, subject: str) -> bytes: ...


class Ed25519CheckpointSigner:
    """Signs checkpoint statements with an in-memory Ed25519 key.

    The protected header is encoded as deterministic CBOR (RFC 8949 Section
    4.2.1), which is the order Go's and TypeScript's signers produce, and the
    ``kid`` is the raw public key.
    """

    def __init__(self, private_key) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("an Ed25519PrivateKey is required")
        self._private_key = private_key
        self._public = private_key.public_key().public_bytes_raw()
        self.key_id = self._public.hex()

    def sign_cose_statement(self, payload: bytes, *, content_type: str, issuer: str, subject: str) -> bytes:
        protected = cbor2.dumps(
            {1: _COSE_ALG_EDDSA, 3: content_type, 4: self._public, 15: {1: issuer, 2: subject}},
            canonical=True,
        )
        to_sign = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
        signature = self._private_key.sign(to_sign)
        return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]), canonical=True)


def checkpoint_timestamp(value: datetime) -> str:
    """The checkpoint ``issued_at`` text Go's and TypeScript's runners write
    for a millisecond UTC time: RFC 3339 with the fraction's trailing zeros,
    and an all-zero fraction, omitted."""
    value = value.astimezone(timezone.utc)
    # Built field by field, as cll.log.wire.format_time is: strftime's %Y
    # zero-padding for years below 1000 depends on the C library.
    text = (
        f"{value.year:04d}-{value.month:02d}-{value.day:02d}"
        f"T{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
    )
    fraction = f"{value.microsecond // 1000:03d}".rstrip("0")
    return f"{text}.{fraction}Z" if fraction else f"{text}Z"


def _peaks(nodes: MemoryNodeStore, size: int) -> list:
    return [nodes.node(position) for position in core.peaks(size)]


class _Loaded:
    """The durable state of one pass and the MMR rebuilt from its nodes."""

    def __init__(self, state: CllState, nodes: MemoryNodeStore) -> None:
        self.state = state
        self.nodes = nodes


class CheckpointRunner:
    """Advances durable CLL checkpoint state when its host runs it.

    ``store`` is a ``cll.log.CheckpointStore`` and ``signer`` a
    ``CheckpointSigner``. A checkpoint is due when entries are uncheckpointed
    and either ``cadence_entries`` of them are, or the oldest has waited
    ``cadence_age``. ``witness_ids`` get one delivery row per checkpoint,
    for a ``WitnessDeliveryRunner`` to deliver.
    """

    def __init__(
        self,
        store,
        signer: CheckpointSigner,
        log_id: str,
        *,
        witness_ids=(),
        cadence_entries: int = 100,
        cadence_age: timedelta = timedelta(minutes=15),
        scan_limit: int = DEFAULT_SCAN_LIMIT,
        poll_interval: timedelta = timedelta(minutes=1),
    ) -> None:
        witness_ids = tuple(witness_ids)
        if (
            store is None
            or signer is None
            or not validate_identifier(log_id)
            or not isinstance(scan_limit, int)
            or isinstance(scan_limit, bool)
            or not 1 <= scan_limit <= MAX_SCAN_LIMIT
            or not isinstance(cadence_entries, int)
            or isinstance(cadence_entries, bool)
            or cadence_entries < 1
            or not isinstance(cadence_age, timedelta)
            or cadence_age <= timedelta(0)
            or not isinstance(poll_interval, timedelta)
            or poll_interval <= timedelta(0)
        ):
            raise InvalidError("invalid runner configuration")
        if len(witness_ids) > MAX_WITNESSES:
            raise InvalidError("too many witnesses")
        if not all(validate_identifier(item) for item in witness_ids):
            raise InvalidError("invalid witness ID")
        if len(set(witness_ids)) != len(witness_ids):
            raise InvalidError("duplicate witness ID")
        self._store = store
        self._signer = signer
        self._log_id = log_id
        self._witness_ids = witness_ids
        self._cadence_entries = cadence_entries
        self._cadence_age = cadence_age
        self._scan_limit = scan_limit
        self._poll_interval = poll_interval.total_seconds()
        self._lock = threading.Lock()
        self._wake = threading.Event()

    def notify(self) -> None:
        """Wake a running ``run`` loop without blocking the caller."""
        self._wake.set()

    def run(self, stop: threading.Event) -> None:
        """Catch up until ``stop`` is set, then wait for ``notify`` or the
        poll interval. Contention is retried on the next wakeup."""
        while not stop.is_set():
            try:
                self._catch_up(datetime.now(timezone.utc), stop)
            except ContentionError:
                pass
            self._wake.wait(self._poll_interval)
            self._wake.clear()

    def run_once(self, now: datetime | None = None) -> bool:
        """Advance durable state by at most one entry scan batch. True when
        it commits nodes, a checkpoint, or both."""
        with self._lock:
            now = normalize_time(datetime.now(timezone.utc) if now is None else now)
            return self._advance(now, self._load())

    def _catch_up(self, now: datetime, stop: threading.Event | None = None) -> None:
        with self._lock:
            # One time for the whole pass, so every checkpoint it signs
            # shares one evaluation time.
            now = normalize_time(now)
            loaded = self._load()
            reloaded = False
            while True:
                try:
                    changed = self._advance(now, loaded)
                except ContentionError:
                    if reloaded:
                        raise
                    loaded = self._load()
                    reloaded = True
                    continue
                # A log that grows faster than it is indexed must not keep
                # the loop from stopping, so stop is checked between batches.
                if not changed or stop is not None and stop.is_set():
                    return
                reloaded = False

    def _load(self) -> _Loaded:
        state = self._store.load_cll()
        nodes = MemoryNodeStore()
        nodes.append_nodes(list(state.nodes))
        try:
            leaves = core.leaf_count(state.size)
        except ValueError as exc:
            raise CorruptError("MMR size is not a complete MMR") from exc
        if leaves != state.indexed_seq or state.size != len(state.nodes):
            raise CorruptError("MMR size does not match indexed sequence")
        self._verify_checkpoint(state, nodes)
        return _Loaded(state, nodes)

    def _verify_checkpoint(self, state: CllState, nodes: MemoryNodeStore) -> None:
        checkpoint = state.checkpoint
        if checkpoint is None:
            return
        try:
            leaves = core.leaf_count(checkpoint.size)
        except ValueError as exc:
            raise CorruptError("invalid stored checkpoint position") from exc
        if checkpoint.size > state.size or leaves != checkpoint.indexed_seq or checkpoint.indexed_seq > state.indexed_seq:
            raise CorruptError("invalid stored checkpoint position")
        if _peaks(nodes, checkpoint.size) != list(checkpoint.peaks):
            raise CorruptError("stored checkpoint peaks mismatch")
        verified = verify_checkpoint_cose_offline(checkpoint.bytes)
        decoded = verified.decoded
        if not verified.ok or decoded is None:
            raise CorruptError("stored checkpoint signature mismatch")
        if (
            decoded.log_id != self._log_id
            or decoded.key_id != self._signer.key_id
            or decoded.mmr_size != checkpoint.size
            or list(decoded.new_peak_hashes) != list(checkpoint.peaks)
            or decoded.root != core.root_from_peaks(list(checkpoint.peaks)).hex()
        ):
            raise CorruptError("stored checkpoint metadata mismatch")

    def _advance(self, now: datetime, loaded: _Loaded) -> bool:
        state = loaded.state
        nodes = loaded.nodes
        entries = self._store.scan_entries(state.indexed_seq, self._scan_limit)
        first_pending = state.first_pending_at
        indexed = state.indexed_seq
        for entry in entries:
            if entry.seq != indexed + 1:
                raise CorruptError("CLL entry sequence is not contiguous")
            try:
                core.add_leaf(nodes, core.leaf_hash(entry.value))
            except ValueError as exc:
                raise CorruptError("CLL entry value is invalid") from exc
            indexed = entry.seq
            if first_pending is None:
                first_pending = normalize_time(entry.appended_at, CorruptError)
        last_checkpointed = state.checkpoint.indexed_seq if state.checkpoint is not None else 0
        uncheckpointed = indexed - last_checkpointed
        due = first_pending is not None and uncheckpointed > 0 and (
            uncheckpointed >= self._cadence_entries or now - first_pending >= self._cadence_age
        )
        size = nodes.size()
        checkpoint = state.checkpoint
        witnesses = state.witnesses
        if due:
            peaks = _peaks(nodes, size)
            record = CheckpointRecord(
                v=1,
                kind="mmr_checkpoint",
                log_id=self._log_id,
                mmr_size=size,
                root=core.root_from_peaks(peaks).hex(),
                prev_size=0 if checkpoint is None else checkpoint.size,
                prev_root="" if checkpoint is None else core.root_from_peaks(list(checkpoint.peaks)).hex(),
                key_id=self._signer.key_id,
                timestamp=checkpoint_timestamp(now),
                signature="",
            )
            statement = checkpoint_to_cose(
                record,
                self._signer,
                peaks,
                prev_peak_hashes=None if checkpoint is None else list(checkpoint.peaks),
                consistency_proof=None if checkpoint is None else core.consistency_proof(nodes, checkpoint.size, size),
            )
            checkpoint = CheckpointState(statement, size, indexed, tuple(peaks))
            first_pending = None
            witnesses = witnesses + tuple(
                WitnessState(witness_id, size, statement, 0, now) for witness_id in self._witness_ids
            )
        if not entries and not due:
            return False
        next_state = CllState(
            size=size,
            nodes=tuple(nodes.node(position) for position in range(size)),
            indexed_seq=indexed,
            first_pending_at=first_pending,
            checkpoint=checkpoint,
            witnesses=witnesses,
        )
        expected = state.checkpoint.bytes if state.checkpoint is not None else None
        self._store.commit_cll(state.size, expected, next_state)
        loaded.state = next_state
        return True
