# SPDX-License-Identifier: Apache-2.0
"""Tests for segment rotation-at-checkpoint, closing manifests, mount/unmount,
and standalone segment verification (``cll.ledger.segments`` +
``LedgerStore``'s ``rotate_at_checkpoint`` path).
"""
from __future__ import annotations

import itertools
import json

import pytest
from cll.checkpoint import MmrLedger
from cll.ledger.segments import (
    MmrCheckpointer,
    SegmentManifest,
    SegmentRotationError,
    SegmentUnmounted,
    verify_segment,
)
from cll.ledger.store import LedgerStore
from cll.signing import LocalSigner

_capsule_counter = itertools.count()


def _synthetic_capsule(*, i: int | None = None) -> dict:
    """A minimal, valid, content-unique capsule dict -- enough to be an MMR
    leaf and round-trip through :class:`LedgerStore`. Same shape as
    ``test_checkpoint.py``'s helper, kept local so this file has no
    cross-test-module import."""
    if i is None:
        i = next(_capsule_counter)
    return {
        "canonicalization_id": "jcs",
        "action_type": "fyi",
        "operator": "test-op",
        "developer": "test-dev",
        "timestamp": f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z",
        "event": f"test_event_{i}",
        "detail": {"i": i, "padding": "x" * 20},
    }


def _managed_store(tmp_path, *, max_segment_bytes: int = 300, log_id: str = ""):
    store = LedgerStore(
        tmp_path,
        log_id=log_id,
        rotate_at_checkpoint=True,
        max_segment_bytes=max_segment_bytes,
    )
    mmr = MmrLedger(store)
    signer = LocalSigner(key_id="test-key", secret=b"secret-bytes-for-hmac-signing-01")
    checkpointer = MmrCheckpointer(mmr=mmr, signer=signer, log_id=log_id)
    store.set_checkpointer(checkpointer)
    return store, mmr, checkpointer


def _append_n(store, n: int) -> list:
    return [store.append(_synthetic_capsule(), consequential=False) for _ in range(n)]


def test_rotate_on_threshold(tmp_path):
    store, mmr, _ = _managed_store(tmp_path)
    _append_n(store, 30)

    segments = store.list_segments()
    assert len(segments) >= 3, "30 small records at a 300-byte threshold should rotate more than once"

    closed = [s for s in segments if s.manifest is not None]
    assert closed, "at least one segment should have been closed"
    for entry in closed:
        assert entry.checkpoint_root is not None
        assert entry.mmr_size is not None
        manifest_path = store.root / entry.manifest
        assert manifest_path.exists()

    # the active segment (last in the list) is never closed
    assert segments[-1].manifest is None
    store.close()


def test_rotate_forces_checkpoint(tmp_path):
    store, mmr, _ = _managed_store(tmp_path)
    records = _append_n(store, 30)

    closed = [s for s in store.list_segments() if s.manifest is not None]
    assert closed

    first = closed[0]
    seg_manifest = SegmentManifest.from_dict(json.loads((store.root / first.manifest).read_text()))
    assert seg_manifest.checkpoint_root == first.checkpoint_root
    assert seg_manifest.mmr_size == first.mmr_size
    # the checkpoint that closed this segment covers exactly its last record
    assert seg_manifest.last_seq <= len(records)
    assert seg_manifest.record_count == seg_manifest.last_seq - seg_manifest.first_seq + 1
    store.close()


def test_rotate_requires_checkpointer(tmp_path):
    store = LedgerStore(tmp_path, rotate_at_checkpoint=True, max_segment_bytes=200)
    with pytest.raises(SegmentRotationError):
        _append_n(store, 20)
    store.close()


def test_set_checkpointer_requires_rotate_at_checkpoint(tmp_path):
    store = LedgerStore(tmp_path)
    with pytest.raises(ValueError):
        store.set_checkpointer(object())
    store.close()


def test_rotate_at_checkpoint_default_off_is_unaffected(tmp_path):
    """capsule-emit consumers: default construction must behave exactly as
    before -- no manifest.json, no segment-archival surface, and the
    existing record-count-based rotation still governs segment naming."""
    store = LedgerStore(tmp_path)
    _append_n(store, 5)
    assert not (tmp_path / "manifest.json").exists()
    with pytest.raises(ValueError):
        store.list_segments()
    store.close()


def test_managed_store_requires_a_fresh_root(tmp_path):
    store = LedgerStore(tmp_path)
    store.append(_synthetic_capsule(), consequential=False)
    store.close()

    with pytest.raises(SegmentRotationError):
        LedgerStore(tmp_path, rotate_at_checkpoint=True)


def test_cross_segment_inclusion_proof(tmp_path):
    from cll.checkpoint import core

    store, mmr, _ = _managed_store(tmp_path)
    _append_n(store, 30)
    mmr.sync()

    closed = [s for s in store.list_segments() if s.manifest is not None]
    assert closed
    first_segment_manifest = SegmentManifest.from_dict(
        json.loads((store.root / closed[0].manifest).read_text())
    )
    target_seq = first_segment_manifest.first_seq  # a leaf in the first, now-closed segment

    root = mmr.root()
    size = mmr.size()
    digest = mmr.body_digest(target_seq)
    proof = mmr.inclusion_proof(target_seq, size=size)
    assert core.verify_inclusion(root, size, target_seq - 1, digest, proof)
    store.close()


def test_unmounted_segment_raises_typed_error_on_read(tmp_path):
    store, mmr, _ = _managed_store(tmp_path)
    _append_n(store, 30)

    closed = [s for s in store.list_segments() if s.manifest is not None]
    target = closed[0]
    seg_manifest = SegmentManifest.from_dict(json.loads((store.root / target.manifest).read_text()))

    store.unmount_segment(target.name)

    with pytest.raises(SegmentUnmounted) as excinfo:
        list(store.scan())
    assert excinfo.value.checkpoint_root == seg_manifest.checkpoint_root
    assert excinfo.value.mmr_size == seg_manifest.mmr_size
    store.close()


def test_mount_reverses_unmount(tmp_path):
    store, mmr, _ = _managed_store(tmp_path)
    _append_n(store, 30)
    closed = [s for s in store.list_segments() if s.manifest is not None]
    target = closed[0].name

    store.unmount_segment(target)
    with pytest.raises(SegmentUnmounted):
        list(store.scan())

    store.mount_segment(target)
    records = list(store.scan())  # no longer raises
    assert len(records) == 30
    store.close()


def test_unmount_refuses_active_segment(tmp_path):
    store, mmr, _ = _managed_store(tmp_path)
    _append_n(store, 5)
    active = store.list_segments()[-1].name
    with pytest.raises(ValueError):
        store.unmount_segment(active)
    store.close()


def test_standalone_segment_verify(tmp_path):
    store, mmr, _ = _managed_store(tmp_path)
    _append_n(store, 30)
    closed = [s for s in store.list_segments() if s.manifest is not None]
    target = closed[0].name

    ok, errors = store.verify_segment_standalone(target)
    assert ok, errors

    store.unmount_segment(target)
    ok, errors = store.verify_segment_standalone(target)
    assert ok, errors

    # fully standalone: verify_segment() needs nothing from the store at all
    seg_manifest = SegmentManifest.from_dict(
        json.loads((store.root / closed[0].manifest).read_text())
    )
    segment_bytes = (store.root / "segments" / ".archived" / target).read_bytes()
    ok, errors = verify_segment(segment_bytes, seg_manifest)
    assert ok, errors
    store.close()


def test_standalone_segment_verify_mutant_tampered_bytes(tmp_path):
    """Mutant: flip a byte in the archived segment's content after closing.
    verify_segment must fail, not silently pass."""
    store, mmr, _ = _managed_store(tmp_path)
    _append_n(store, 30)
    closed = [s for s in store.list_segments() if s.manifest is not None]
    target = closed[0].name
    seg_manifest = SegmentManifest.from_dict(
        json.loads((store.root / closed[0].manifest).read_text())
    )

    store.unmount_segment(target)
    segment_path = store.root / "segments" / ".archived" / target
    tampered = bytearray(segment_path.read_bytes())
    # flip a byte in the middle of the file, inside JSON content
    mid = len(tampered) // 2
    tampered[mid] ^= 0xFF
    segment_path.write_bytes(bytes(tampered))

    ok, errors = store.verify_segment_standalone(target)
    assert not ok
    assert errors

    ok2, errors2 = verify_segment(bytes(tampered), seg_manifest)
    assert not ok2
    assert errors2
    store.close()


def test_standalone_segment_verify_mutant_wrong_checkpoint_root(tmp_path):
    """Mutant: a manifest claiming a checkpoint_root the segment's own
    records don't actually range-proof against must fail, not pass."""
    store, mmr, _ = _managed_store(tmp_path)
    _append_n(store, 30)
    closed = [s for s in store.list_segments() if s.manifest is not None]
    target = closed[0].name
    seg_manifest = SegmentManifest.from_dict(
        json.loads((store.root / closed[0].manifest).read_text())
    )
    segment_bytes = (store.root / "segments" / target).read_bytes()

    forged = SegmentManifest(
        log_id=seg_manifest.log_id,
        first_seq=seg_manifest.first_seq,
        last_seq=seg_manifest.last_seq,
        first_ts=seg_manifest.first_ts,
        last_ts=seg_manifest.last_ts,
        checkpoint_root="ff" * 32,
        mmr_size=seg_manifest.mmr_size,
        bytes=seg_manifest.bytes,
        record_count=seg_manifest.record_count,
        sha256_of_segment=seg_manifest.sha256_of_segment,
        range_proof=seg_manifest.range_proof,
    )
    ok, errors = verify_segment(segment_bytes, forged)
    assert not ok
    assert errors
    store.close()


def test_verify_segment_standalone_unknown_segment(tmp_path):
    store, mmr, _ = _managed_store(tmp_path)
    _append_n(store, 5)
    ok, errors = store.verify_segment_standalone("seg-999999.jsonl")
    assert not ok
    assert errors
    store.close()
