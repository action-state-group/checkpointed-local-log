# SPDX-License-Identifier: Apache-2.0
"""Python storage interop driver for go/scripts/check-storage-interop.sh.

    storage.py <advance|verify|summary|hold|expect-contention> <jsonl|sqlite|mysql> <target> <log-id> [argument...]

Reproduces the deterministic fixture of storage.mjs and the Go driver exactly
(identities, times, checkpoints, witness receipts), so a log any language
writes continues and verifies here with identical roots. MMR nodes and peaks
come from ``cll.checkpoint.core``. The MySQL target is a ``mysql://`` URL.
Needs the ``cll`` package installed (``pip install './python[mysql]'``).
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cll.checkpoint import core
from cll.checkpoint.store import MemoryNodeStore
from cll.log import (
    AppendInput,
    CheckpointState,
    CllState,
    ContentionError,
    WitnessReceipt,
    WitnessState,
)
from cll.log.wire import entry_to_wire, state_to_wire

BASE_TIME = datetime(2026, 9, 3, 12, 0, 0, 123000, tzinfo=timezone.utc)
WITNESS_ID = "interop-witness"


def backend_module(name: str):
    if name == "jsonl":
        from cll.log import jsonl

        return jsonl
    if name == "sqlite":
        from cll.log import sqlite

        return sqlite
    if name == "mysql":
        from cll.log import mysql

        return mysql
    raise SystemExit(f"unsupported backend {name}")


def identity_for(sequence: int) -> bytes:
    return bytes([sequence]) * 32


def checkpoint_for(sequence: int) -> bytes:
    return bytes([0xC0, sequence])


def receipt_for(sequence: int) -> bytes:
    return bytes([0xD0, sequence])


def time_for(sequence: int) -> datetime:
    return BASE_TIME + timedelta(seconds=sequence)


def tree(nodes) -> MemoryNodeStore:
    store = MemoryNodeStore()
    store.append_nodes(list(nodes))
    return store


def peak_hashes(nodes: MemoryNodeStore) -> tuple:
    return tuple(nodes.node(position) for position in core.peaks(nodes.size()))


def advance(store) -> None:
    entries = store.scan_entries(0, 1000)
    verify(store, len(entries))
    sequence = len(entries) + 1
    if sequence > 255:
        raise SystemExit("interop sequence exceeds fixture range")
    identity = identity_for(sequence)
    result = store.append(AppendInput(identity, time_for(sequence)))
    if result.outcome != "inserted" or result.entry.seq != sequence:
        raise SystemExit("unexpected append result")

    state = store.load_cll()
    nodes = tree(state.nodes)
    core.add_leaf(nodes, core.leaf_hash(identity))
    all_nodes = tuple(nodes.node(position) for position in range(nodes.size()))
    checkpoint = checkpoint_for(sequence)
    previous_size = None if state.checkpoint is None else state.checkpoint.size
    witness = WitnessState(
        witness_id=WITNESS_ID,
        checkpoint_size=nodes.size(),
        checkpoint=checkpoint,
        attempts=0,
        next_attempt_at=time_for(sequence),
        permanent=False,
    )
    following = CllState(
        size=nodes.size(),
        nodes=all_nodes,
        indexed_seq=sequence,
        first_pending_at=state.first_pending_at,
        checkpoint=CheckpointState(checkpoint, nodes.size(), sequence, peak_hashes(nodes)),
        witnesses=tuple(state.witnesses) + (witness,),
    )
    store.commit_cll(state.size, None if state.checkpoint is None else state.checkpoint.bytes, following)
    if previous_size is not None:
        complete_witness(store, previous_size, sequence - 1, sequence)
    verify(store, sequence)


def complete_witness(store, checkpoint_size: int, checkpoint_sequence: int, current_sequence: int) -> None:
    current = store.get_witness(WITNESS_ID, checkpoint_size)
    if current is None:
        raise SystemExit("previous witness is missing")
    digest = hashlib.sha256(current.checkpoint).hexdigest()
    store.commit_witness(
        current.attempts,
        WitnessState(
            witness_id=current.witness_id,
            checkpoint_size=current.checkpoint_size,
            checkpoint=current.checkpoint,
            attempts=current.attempts + 1,
            next_attempt_at=time_for(current_sequence),
            receipt=WitnessReceipt(
                bytes=receipt_for(checkpoint_sequence),
                entry_hash=digest,
                entry_hash_scheme="legacy",
                leaf_index=checkpoint_sequence - 1,
                tree_size=current_sequence,
            ),
            permanent=False,
            last_error=current.last_error,
        ),
    )


def verify(store, expected: int) -> None:
    entries = store.scan_entries(0, 1000)
    if len(entries) != expected:
        raise SystemExit(f"got {len(entries)} entries, want {expected}")
    nodes = MemoryNodeStore()
    sizes = []
    for index, entry in enumerate(entries):
        sequence = index + 1
        if (
            entry.seq != sequence
            or entry.value != identity_for(sequence)
            or entry.appended_at != time_for(sequence)
        ):
            raise SystemExit(f"entry {sequence} disagrees with portable fixture")
        core.add_leaf(nodes, core.leaf_hash(entry.value))
        sizes.append(nodes.size())

    state = store.load_cll()
    if (
        state.size != nodes.size()
        or state.indexed_seq != expected
        or tuple(state.nodes) != tuple(nodes.node(p) for p in range(nodes.size()))
        or len(state.witnesses) != expected
        or state.first_pending_at is not None
    ):
        raise SystemExit("CLL state disagrees with portable fixture")
    if expected == 0:
        if state.checkpoint is not None:
            raise SystemExit("empty fixture has a checkpoint")
        return
    checkpoint = state.checkpoint
    if (
        checkpoint is None
        or checkpoint.size != nodes.size()
        or checkpoint.indexed_seq != expected
        or checkpoint.bytes != checkpoint_for(expected)
        or tuple(checkpoint.peaks) != peak_hashes(nodes)
    ):
        raise SystemExit("latest checkpoint disagrees with portable fixture")

    for index, size in enumerate(sizes):
        sequence = index + 1
        item = store.get_witness(WITNESS_ID, size)
        if item is None or item.checkpoint != checkpoint_for(sequence):
            raise SystemExit(f"witness {sequence} checkpoint mismatch")
        if sequence == expected:
            if item.attempts != 0 or item.receipt is not None:
                raise SystemExit("latest witness is not pending")
        else:
            verify_receipt(item, sequence)
    pending = store.pending_witnesses(BASE_TIME + timedelta(days=1), 32)
    if len(pending) != 1 or pending[0].checkpoint_size != sizes[-1]:
        raise SystemExit("pending witness projection mismatch")


def verify_receipt(item: WitnessState, sequence: int) -> None:
    digest = hashlib.sha256(checkpoint_for(sequence)).hexdigest()
    receipt = item.receipt
    if (
        item.attempts != 1
        or receipt is None
        or receipt.bytes != receipt_for(sequence)
        or receipt.entry_hash != digest
        or receipt.entry_hash_scheme != "legacy"
        or receipt.leaf_index != sequence - 1
        or receipt.tree_size != sequence + 1
    ):
        raise SystemExit(f"witness {sequence} receipt mismatch")


def summary(store) -> None:
    """Entries, CLL state with witness rows by numeric checkpointSize then
    witnessId, and the root bagged from the checkpoint peaks."""
    state = store.load_cll()
    wire = state_to_wire(state)
    wire["witnesses"] = [
        row
        for _, row in sorted(
            zip(state.witnesses, wire["witnesses"]),
            key=lambda pair: (pair[0].checkpoint_size, pair[0].witness_id.encode("utf-8")),
        )
    ]
    peaks = [] if state.checkpoint is None else list(state.checkpoint.peaks)
    root = core.root_from_peaks(peaks).hex() if peaks else ""
    document = {"entries": [entry_to_wire(entry) for entry in store.scan_entries(0, 1000)], "state": wire, "root": root}
    sys.stdout.write(json.dumps(document, separators=(",", ":")) + "\n")


def hold(ready_path: str, stop_path: str) -> None:
    Path(ready_path).write_text("ready\n")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if Path(stop_path).exists():
            return
        time.sleep(0.01)
    raise SystemExit("timed out waiting for stop file")


def main(argv: list) -> int:
    if len(argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    mode, backend_name, target, log_id, *arguments = argv
    module = backend_module(backend_name)
    target_args = (target,) if backend_name == "jsonl" else (target, log_id)
    if mode in ("advance", "hold"):
        module.init(*target_args)
    if mode == "expect-contention":
        try:
            store = module.open(*target_args)
        except ContentionError:
            return 0
        store.close()
        raise SystemExit("second writer unexpectedly opened")
    store = module.open(*target_args)
    try:
        if mode == "advance":
            advance(store)
        elif mode == "verify":
            if not arguments or not arguments[0].isdigit():
                raise SystemExit("verify requires expected entry count")
            verify(store, int(arguments[0]))
        elif mode == "summary":
            summary(store)
        elif mode == "hold":
            if len(arguments) < 2:
                raise SystemExit("hold requires ready and stop paths")
            hold(arguments[0], arguments[1])
        else:
            raise SystemExit(f"unsupported mode {mode}")
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
