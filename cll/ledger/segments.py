# SPDX-License-Identifier: Apache-2.0
"""Segment closing, manifests, and mount/unmount state for :class:`~cll.ledger.store.LedgerStore`.

Generic log mechanics only -- no capsule/mesh vocabulary. A segment closes on
a checkpoint boundary (never a calendar), and a closed segment's manifest
uses only content-neutral fields (seq, timestamp, byte counts, digests) so
this module has no notion of what a stored record *is*.

**Never evidence.** :class:`StoreManifest` (which segments exist, mounted or
not) is local bookkeeping the store rebuilds if lost; the thing a stranger
can actually trust is a :class:`SegmentManifest` plus its ``range_proof`` --
see :func:`verify_segment`, which needs nothing but a segment's own bytes and
its own manifest, not the rest of the store.

``checkpoints`` (wherever a caller's checkpoint layer stores them -- e.g.
``cll.ledger.checkpoint``'s ``<root>/checkpoints/<mmr_size>.json``) never
rotates: this module only ever closes ``segments/``, never that directory.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from ..checkpoint.core import InclusionProof
from ..checkpoint.index import RangeProof, verify_range

__all__ = [
    "DEFAULT_MAX_SEGMENT_BYTES",
    "Checkpointer",
    "MmrCheckpointer",
    "SegmentRotationError",
    "SegmentUnmounted",
    "SegmentManifest",
    "SegmentEntry",
    "StoreManifest",
    "verify_segment",
    "manifest_filename",
]

DEFAULT_MAX_SEGMENT_BYTES = 256 * 1024 * 1024  # 256 MiB


class SegmentRotationError(RuntimeError):
    """A segment could not be closed at its checkpoint boundary -- a
    misconfigured/missing checkpointer, or the checkpoint produced does not
    close exactly at this segment's last record."""


class SegmentUnmounted(Exception):
    """Raised by a read that touches a segment which has been archived
    (unmounted). Carries the closing checkpoint's ``root``/``mmr_size`` so a
    caller (e.g. an evidence responder) maps this to a signed refusal
    (``retention_expired``) instead of treating it as ``no_such_subject`` --
    the chain proves the record existed, it just isn't mounted here."""

    def __init__(self, checkpoint_root: str | None, mmr_size: int | None, *, segment: str = ""):
        self.checkpoint_root = checkpoint_root
        self.mmr_size = mmr_size
        self.segment = segment
        super().__init__(
            f"segment {segment!r} is unmounted -- closed under checkpoint "
            f"mmr_size={mmr_size} root={checkpoint_root}"
        )


@runtime_checkable
class Checkpointer(Protocol):
    """What a store needs in order to force a checkpoint at a segment
    boundary. ``checkpoint()`` returns any object with ``.root: str`` (hex)
    and ``.mmr_size: int`` -- e.g. ``cll.checkpoint.emit.CheckpointRecord``.
    ``range_proof(from_seq, to_seq)`` returns a
    ``cll.checkpoint.index.RangeProof`` anchored at that same checkpoint's
    ``mmr_size``, which is what lets a closed segment be verified later
    without replaying the rest of the log (see :func:`verify_segment`)."""

    def checkpoint(self) -> Any: ...

    def range_proof(self, from_seq: int, to_seq: int) -> RangeProof: ...


@dataclass
class MmrCheckpointer:
    """The out-of-the-box :class:`Checkpointer`: an ``MmrLedger`` synced from
    the same store it backs, signed with any ``cll.checkpoint.emit.Signer``
    -shaped key.

    ``mmr`` must wrap the SAME store this checkpointer is attached to via
    :meth:`~cll.ledger.store.LedgerStore.set_checkpointer` -- rotation calls
    :meth:`checkpoint` immediately after the record that crossed the byte
    threshold, while the store's own lock is held, so ``sync()`` here always
    folds that record in first and nothing else can be appended concurrently.
    """

    mmr: Any  # cll.checkpoint.index.MmrLedger
    signer: Any  # cll.checkpoint.emit.Signer
    log_id: str = ""
    _prev: Any = field(default=None, init=False, repr=False)

    def checkpoint(self) -> Any:
        from ..checkpoint.emit import emit_checkpoint

        self.mmr.sync()
        cp = emit_checkpoint(self.mmr, self.signer, log_id=self.log_id, prev=self._prev)
        self._prev = cp
        return cp

    def range_proof(self, from_seq: int, to_seq: int) -> RangeProof:
        return self.mmr.range_proof(from_seq, to_seq)


def manifest_filename(log_id: str, mmr_size: int) -> str:
    return f"{log_id}-{mmr_size}.manifest.json"


def _inclusion_to_dict(p: InclusionProof) -> dict:
    return {
        "v": p.v,
        "kind": p.kind,
        "size": p.size,
        "leaf_index": p.leaf_index,
        "witness": list(p.witness),
        "peaks_left": list(p.peaks_left),
        "peaks_right": list(p.peaks_right),
    }


def _inclusion_from_dict(d: dict) -> InclusionProof:
    return InclusionProof(
        v=int(d["v"]),
        kind=d["kind"],
        size=int(d["size"]),
        leaf_index=int(d["leaf_index"]),
        witness=tuple(d["witness"]),
        peaks_left=tuple(d["peaks_left"]),
        peaks_right=tuple(d["peaks_right"]),
    )


def _range_proof_to_dict(p: RangeProof) -> dict:
    return {
        "from_seq": p.from_seq,
        "to_seq": p.to_seq,
        "size": p.size,
        "inclusion_from": _inclusion_to_dict(p.inclusion_from),
        "inclusion_to": _inclusion_to_dict(p.inclusion_to),
    }


def _range_proof_from_dict(d: dict) -> RangeProof:
    return RangeProof(
        from_seq=int(d["from_seq"]),
        to_seq=int(d["to_seq"]),
        size=int(d["size"]),
        inclusion_from=_inclusion_from_dict(d["inclusion_from"]),
        inclusion_to=_inclusion_from_dict(d["inclusion_to"]),
    )


@dataclass
class SegmentManifest:
    """The closing record for one rotated segment -- written once, at
    rotation time, alongside the checkpoint that forced the close. Never
    mutated afterward. Together with the segment's own raw bytes, this is a
    self-contained, offline-verifiable artifact (see :func:`verify_segment`)
    -- an archived segment needs nothing else from the store it came from."""

    log_id: str
    first_seq: int
    last_seq: int
    first_ts: str | None
    last_ts: str | None
    checkpoint_root: str
    mmr_size: int
    bytes: int
    record_count: int
    sha256_of_segment: str
    range_proof: RangeProof

    def to_dict(self) -> dict:
        return {
            "log_id": self.log_id,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "checkpoint_root": self.checkpoint_root,
            "mmr_size": self.mmr_size,
            "bytes": self.bytes,
            "record_count": self.record_count,
            "sha256_of_segment": self.sha256_of_segment,
            "range_proof": _range_proof_to_dict(self.range_proof),
        }

    @classmethod
    def from_dict(cls, d: dict) -> SegmentManifest:
        return cls(
            log_id=d.get("log_id", ""),
            first_seq=int(d["first_seq"]),
            last_seq=int(d["last_seq"]),
            first_ts=d.get("first_ts"),
            last_ts=d.get("last_ts"),
            checkpoint_root=d["checkpoint_root"],
            mmr_size=int(d["mmr_size"]),
            bytes=int(d["bytes"]),
            record_count=int(d["record_count"]),
            sha256_of_segment=d["sha256_of_segment"],
            range_proof=_range_proof_from_dict(d["range_proof"]),
        )


@dataclass
class SegmentEntry:
    """One segment's entry in the store manifest: its mounted state and,
    once closed, where its own :class:`SegmentManifest` lives."""

    name: str
    mounted: bool = True
    manifest: str | None = None  # path (relative to store root) to the SegmentManifest, once closed
    checkpoint_root: str | None = None
    mmr_size: int | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "mounted": self.mounted,
            "manifest": self.manifest,
            "checkpoint_root": self.checkpoint_root,
            "mmr_size": self.mmr_size,
        }

    @classmethod
    def from_dict(cls, d: dict) -> SegmentEntry:
        return cls(
            name=d["name"],
            mounted=bool(d.get("mounted", True)),
            manifest=d.get("manifest"),
            checkpoint_root=d.get("checkpoint_root"),
            mmr_size=d.get("mmr_size"),
        )


@dataclass
class StoreManifest:
    """Lists every segment this store has ever written, its mounted state,
    and (once closed) where its :class:`SegmentManifest` lives. Never
    evidence on its own -- a caller trusts the individual segment
    manifests' checkpoint linkage, not this index; this file is local
    bookkeeping the store could in principle rebuild from ``segments/``."""

    log_id: str = ""
    active_segment: str | None = None
    segments: list[SegmentEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "log_id": self.log_id,
            "active_segment": self.active_segment,
            "segments": [s.to_dict() for s in self.segments],
        }

    @classmethod
    def from_dict(cls, d: dict) -> StoreManifest:
        return cls(
            log_id=d.get("log_id", ""),
            active_segment=d.get("active_segment"),
            segments=[SegmentEntry.from_dict(s) for s in d.get("segments", [])],
        )

    def entry(self, name: str) -> SegmentEntry | None:
        return next((s for s in self.segments if s.name == name), None)


def verify_segment(
    segment_bytes: bytes,
    manifest: SegmentManifest,
    *,
    id_field: str = "capsule_id",
) -> tuple[bool, list[str]]:
    """Pure, offline, standalone verification of one closed segment: no
    store, no sqlite index, no rest of the log -- just the segment's raw
    bytes and its own :class:`SegmentManifest`. Never raises.

    Checks, in order: (1) the segment's bytes are exactly what the manifest
    sealed (``sha256_of_segment``); (2) it holds exactly ``record_count``
    records spanning ``[first_seq, last_seq]``; (3) the boundary records are
    genuinely leaves of the checkpoint's MMR at ``mmr_size``, under
    ``checkpoint_root`` (``range_proof`` -- see
    ``cll.checkpoint.index.RangeProof``'s docstring for exactly what a range
    proof does and does not establish about interior leaves: MMR structural
    completeness rules out a *missing* interior leaf, it does not
    independently re-verify every interior leaf's content). This does NOT
    re-verify the checkpoint's own signature or witness stamps -- that is a
    separate, already-existing check
    (``cll.checkpoint.emit.verify_checkpoint_signature_offline``) a caller
    layers on top once it also holds the checkpoint record itself.
    """
    from agent_action_capsule import compute_capsule_id

    errors: list[str] = []
    try:
        digest = hashlib.sha256(segment_bytes).hexdigest()
        if digest != manifest.sha256_of_segment:
            errors.append(
                f"segment digest {digest} does not match manifest sha256_of_segment "
                f"{manifest.sha256_of_segment} -- segment bytes have changed"
            )
            return False, errors

        lines = [line for line in segment_bytes.decode("utf-8").splitlines() if line.strip()]
        if len(lines) != manifest.record_count:
            errors.append(
                f"segment holds {len(lines)} records, manifest declares "
                f"record_count={manifest.record_count}"
            )
            return False, errors
        if manifest.last_seq - manifest.first_seq + 1 != manifest.record_count:
            errors.append(
                f"manifest seq range [{manifest.first_seq}, {manifest.last_seq}] is not "
                f"{manifest.record_count} records wide"
            )
            return False, errors

        records = [json.loads(line) for line in lines]
        first_record, last_record = records[0], records[-1]
        first_digest = first_record.get(id_field) or compute_capsule_id(first_record)
        last_digest = last_record.get(id_field) or compute_capsule_id(last_record)

        root = bytes.fromhex(manifest.checkpoint_root)
        ok = verify_range(
            root,
            manifest.first_seq,
            manifest.last_seq,
            bytes.fromhex(first_digest),
            bytes.fromhex(last_digest),
            manifest.range_proof,
        )
        if not ok:
            errors.append(
                "range proof does not verify the segment's boundary records against "
                f"checkpoint_root={manifest.checkpoint_root} at mmr_size={manifest.mmr_size}"
            )
            return False, errors
        return True, errors
    except Exception as exc:  # noqa: BLE001 -- pure verifier, never raises
        errors.append(f"unexpected error verifying segment: {exc}")
        return False, errors
