# SPDX-License-Identifier: Apache-2.0
"""Wires an append-only capsule log to an MMR-backed inclusion/range-proof index.

``MmrLedger`` is a decorator over any object satisfying the ``LogSource``
Protocol below -- structurally, not by inheritance, so any log binding that
already exposes ``append``/``scan``/``fetch``/``find_gaps``/``verify`` (e.g.
capsule-ledger's own ``LedgerStore``) works here unmodified. This module never
reaches around that surface into raw storage, and never imports a concrete log
implementation -- that is what keeps this an opt-in, dependency-free
subpackage of the base emission library.

Two wiring styles are supported rather than picking one:

- **Automatic**: every capsule appended *through* this wrapper's own
  ``append()`` is folded into the MMR immediately, in-line.
- **Explicit catch-up**: ``sync()`` scans the wrapped log and folds in any
  records this index hasn't seen yet. This covers a log populated some other
  way (a bulk import, a pre-existing store opened fresh, or another
  process's writer) without this module reaching into the wrapped log's
  internals or requiring any change to its own ``append()``.

Leaf ordering: MMR ``leaf_index == record.seq - 1``. ``seq`` is expected to be
a gapless, 1-indexed append order (matching capsule-ledger's
``LedgerRecord.seq``) -- every leaf this index has ever seen is addressed by
the same ``seq`` a caller already gets back from ``append()``/``scan()``, no
separate id scheme.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from . import core
from .store import MemoryNodeStore

__all__ = ["LogSource", "MmrLedger", "RangeProof", "verify_range"]


@runtime_checkable
class LogSource(Protocol):
    """The structural surface any log binding must satisfy to be MMR-indexed.

    Matches capsule-ledger's ``LedgerAPI`` by shape -- deliberately not by
    import, so this subpackage carries no dependency on any concrete ledger
    implementation. Every record returned by ``append``/``scan``/``fetch``
    need only expose ``.seq`` (gapless, 1-indexed) and ``.capsule_id`` (the
    hex body digest) for this module's purposes.
    """

    def append(self, capsule: dict, *, consequential: bool = True) -> Any: ...

    def scan(self, query: Any = None) -> Iterator[Any]: ...

    def fetch(self, capsule_id: str) -> Any | None: ...

    def verify(self, capsule_id: str) -> Any | None: ...

    def find_gaps(self) -> list[Any]: ...


@dataclass(frozen=True)
class RangeProof:
    """Proves a contiguous leaf range ``[from_seq, to_seq]`` (inclusive,
    1-indexed log seq) belongs to the MMR of the given ``size``.

    Composed from inclusion proofs of the two range boundaries rather than one
    proof per leaf in the range: a valid MMR size is only ever a *complete*
    accounting of exactly ``leaf_count(size)`` leaves (``core.peaks`` rejects
    any size that would represent a partial/sparse tree), so proving both
    boundary leaves are genuinely bound to their claimed digests under one
    common, peaks()-validated root also certifies every leaf strictly between
    them is structurally present -- there is no MMR-valid way for a size to
    "skip" an interior leaf position. ``size`` is fixed to
    ``node_count(to_seq)``, i.e. the MMR exactly as it stood right after
    ``to_seq`` was appended, so the range proof is meaningful even when the
    log has since grown further (see ``MmrLedger.consistency_proof`` for
    bridging an older range forward to a newer root).
    """

    from_seq: int
    to_seq: int
    size: int
    inclusion_from: core.InclusionProof
    inclusion_to: core.InclusionProof


def verify_range(
    root: bytes,
    from_seq: int,
    to_seq: int,
    from_digest: bytes,
    to_digest: bytes,
    proof: RangeProof,
) -> bool:
    """Pure range verification. No reader, never raises."""
    try:
        if proof is None or proof.from_seq != from_seq or proof.to_seq != to_seq:
            return False
        if from_seq < 1 or to_seq < from_seq:
            return False
        if core.leaf_count(proof.size) != to_seq:
            return False
        if not core.verify_inclusion(root, proof.size, from_seq - 1, from_digest, proof.inclusion_from):
            return False
        if not core.verify_inclusion(root, proof.size, to_seq - 1, to_digest, proof.inclusion_to):
            return False
        return True
    except Exception:
        return False


class MmrLedger:
    """MMR-backed inclusion/range-proof index over any ``LogSource`` binding."""

    def __init__(self, ledger: LogSource, *, node_store: core.NodeAppender | None = None) -> None:
        self._ledger = ledger
        self._nodes: core.NodeAppender = node_store if node_store is not None else MemoryNodeStore()
        self._body_digests: list[bytes] = []  # index i = leaf_index i's body_digest (== capsule_id bytes)

    # -- LogSource passthrough (never reaches around it) ---------------------

    def append(self, capsule: dict, *, consequential: bool = True) -> Any:
        record = self._ledger.append(capsule, consequential=consequential)
        self._index_record(record)
        return record

    def scan(self, query: Any = None) -> Iterator[Any]:
        return self._ledger.scan(query)

    def fetch(self, capsule_id: str) -> Any | None:
        return self._ledger.fetch(capsule_id)

    def verify(self, capsule_id: str) -> Any | None:
        return self._ledger.verify(capsule_id)

    def find_gaps(self) -> list[Any]:
        return self._ledger.find_gaps()

    # -- MMR sync -------------------------------------------------------------

    def sync(self) -> int:
        """Fold any log records not yet indexed into the MMR.

        Returns the number of leaves newly added. Idempotent -- safe to call
        repeatedly, including with nothing new to add.
        """
        added = 0
        for record in self._ledger.scan():
            if record.seq <= len(self._body_digests):
                continue
            self._index_record(record)
            added += 1
        return added

    def _index_record(self, record: Any) -> None:
        expected_seq = len(self._body_digests) + 1
        if record.seq != expected_seq:
            raise core.IntegrityError(
                f"cannot index record seq={record.seq} out of order "
                f"(expected seq={expected_seq}) -- MMR indexing requires a "
                "gapless, seq-ordered log"
            )
        body_digest = bytes.fromhex(record.capsule_id)
        core.add_leaf(self._nodes, core.leaf_hash(body_digest))
        self._body_digests.append(body_digest)

    # -- read surface -----------------------------------------------------

    def size(self) -> int:
        """Current MMR node count."""
        return self._nodes.size()

    def leaf_count(self) -> int:
        """Current number of indexed leaves."""
        return len(self._body_digests)

    def root(self) -> bytes:
        return self.root_at(self._nodes.size())

    def root_at(self, size: int) -> bytes:
        """Root of the MMR as it stood at `size` nodes -- any prior size the
        node store has already grown past, not just the current one. Nodes
        are write-once, so a historical size's peaks are still readable."""
        return core.root_from_peaks(self.peak_hashes_at(size))

    def commitment_at(self, size: int) -> bytes:
        """Conformant commitment object (``core.commitment_object`` --
        [cll-commitment-interop]) of the MMR as it stood at `size` nodes:
        what an external MMRIVER/profile-conformant tool needs, as opposed
        to `root_at`'s internal-only bagged hash."""
        return core.commitment_object(self.peak_hashes_at(size))

    def peak_hashes_at(self, size: int) -> list[bytes]:
        """Peak hashes (left to right) of the MMR as it stood at `size`
        nodes. Public so callers (e.g. checkpoint emission) never need to
        reach into this object's node store directly."""
        pks = core.peaks(size)
        return [self._nodes.node(p) for p in pks]

    def body_digest(self, seq: int) -> bytes:
        if seq < 1 or seq > len(self._body_digests):
            raise core.IntegrityError(f"no indexed leaf for seq {seq}")
        return self._body_digests[seq - 1]

    def inclusion_proof(self, seq: int, *, size: int | None = None) -> core.InclusionProof:
        """Inclusion proof for log record `seq`, against the MMR at `size`
        (defaults to the current size)."""
        target_size = size if size is not None else self._nodes.size()
        return core.inclusion_proof(self._nodes, seq - 1, target_size)

    def range_proof(self, from_seq: int, to_seq: int) -> RangeProof:
        """Range proof for the contiguous log records [from_seq, to_seq],
        against the MMR exactly as it stood when `to_seq` was appended."""
        if from_seq < 1 or to_seq < from_seq:
            raise core.InvalidArgumentError(f"invalid range [{from_seq}, {to_seq}]")
        size = core.node_count(to_seq)
        inclusion_from = core.inclusion_proof(self._nodes, from_seq - 1, size)
        inclusion_to = core.inclusion_proof(self._nodes, to_seq - 1, size)
        return RangeProof(from_seq, to_seq, size, inclusion_from, inclusion_to)

    def consistency_proof(self, size_a: int, size_b: int | None = None) -> core.ConsistencyProof:
        """Proof that the MMR at `size_b` (defaults to current size) extends
        the MMR at `size_a` -- the update path for a proof/root pinned at an
        earlier size, without recomputing anything about its leaves."""
        target_size_b = size_b if size_b is not None else self._nodes.size()
        return core.consistency_proof(self._nodes, size_a, target_size_b)
