# SPDX-License-Identifier: Apache-2.0
"""The -02 vectors (cll-02-vectors/) against this package.

Two layers. The log layer (node values, sizes, peaks, the consistency proof's
paths and right-peaks) must match today: -02 changes no tree arithmetic. The
wire layer (the -02 claims bytes and the CWT sub) is ahead of this package,
so those tests are strict xfails: they turn into failures, and must be
flipped to plain tests, the day the package emits the -02 wire form.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from cll.checkpoint import core
from cll.checkpoint.emit import CheckpointRecord
from cll.checkpoint.store import MemoryNodeStore

ROOT = Path(__file__).parents[3]
VECTORS = json.loads((ROOT / "cll-02-vectors" / "vectors.json").read_text())
PROFILE_03 = json.loads((ROOT / "mmr-profile-vectors" / "manifest.json").read_text())
WIRE_PENDING = "CLL 0.2 wire release pending: the package still emits the -01 wire form"


def _store() -> MemoryNodeStore:
    store = MemoryNodeStore()
    for entry in VECTORS["entries"]:
        core.add_leaf(store, core.leaf_hash(bytes.fromhex(entry)))
    return store


def _checkpoints():
    return [cp for cp in VECTORS["checkpoints"] if cp["consistency_proof"]]


def test_log_nodes_and_sizes_match():
    store = MemoryNodeStore()
    sizes = [0]
    for entry in VECTORS["entries"]:
        core.add_leaf(store, core.leaf_hash(bytes.fromhex(entry)))
        sizes.append(store.size())
    assert [store.node(i).hex() for i in range(store.size())] == VECTORS["nodes"]
    assert sizes == [s["log_size"] for s in VECTORS["sizes"]]


def test_log_size_is_node_count_and_peaks_match():
    store = _store()
    for row in VECTORS["sizes"]:
        size = row["log_size"]
        peaks = [] if size == 0 else [store.node(p) for p in core.peaks(size)]
        assert [p.hex() for p in peaks] == row["peaks"]
        assert (core.leaf_count(size) if size else 0) == row["leaf_count"]
        assert b"".join(peaks).hex() == row["commitment"]


@pytest.mark.parametrize("cp", _checkpoints(), ids=lambda cp: cp["id"])
def test_consistency_proof_maps_onto_profile_proof(cp):
    """The package's own proof carries the profile's proof losslessly: its
    per-old-peak witnesses are the consistency-paths, and the right-peaks are
    the new peaks no path reaches."""
    want = cp["consistency_proof"]
    store = _store()
    proof = core.consistency_proof(store, want["tree_size_1"], want["tree_size_2"])
    assert [list(w) for w in proof.witness] == want["consistency_paths"]
    right = want["right_peaks"]
    assert list(proof.new_peaks[len(proof.new_peaks) - len(right):]) == right
    assert core.verify_consistency(
        core.root_from_peaks([bytes.fromhex(h) for h in proof.old_peaks]), proof.size_a,
        core.root_from_peaks([bytes.fromhex(h) for h in proof.new_peaks]), proof.size_b, proof,
    )


def test_profile_transcription_reproduces_03_vectors():
    """profile_main (editors' main) and draft03 (the -03 text, repaired) agree
    on the -03 fixture's nodes and on every VALID -03 consistency vector."""
    sys.path.insert(0, str(ROOT / "cll-02-vectors"))
    import hashlib

    import profile_main as pm

    db = pm.ListDB()
    for k in range(21):
        entry = f"draft-bryce-cose-receipts-mmr-profile-03 vector entry {k}".encode()
        pm.add_leaf_hash(db, hashlib.sha256(entry).digest())
    fixture = next(v for v in PROFILE_03["vectors"] if v["id"] == "fixture-mmr39")
    assert [n.hex() for n in db.nodes] == fixture["expected"]["nodes"]
    checked = 0
    for v in PROFILE_03["vectors"]:
        e = v["expected"]
        if v["kind"] != "consistency" or v["expected_result"] != "VALID":
            continue
        s1, s2 = e["tree_size_1"], e["tree_size_2"]
        if s1 == s2:
            continue
        paths = [[db.nodes[i] for i in p] for p in pm.consistency_proof_paths(s1 - 1, s2 - 1)]
        assert [[x.hex() for x in p] for p in paths] == e["consistency_paths"]
        roots, nright = pm.consistent_roots(
            s1, s2, [bytes.fromhex(h) for h in e["accumulator_from"]], paths)
        assert [r.hex() for r in roots] + e["right_peaks"] == e["consistent_accumulator"]
        assert nright == len(e["right_peaks"])
        checked += 1
    assert checked >= 5


def _record(claims: dict, store: MemoryNodeStore):
    size, prev = claims["log_size"], claims["prev_size"]
    peaks = [store.node(p) for p in core.peaks(size)]
    prev_peaks = [store.node(p) for p in core.peaks(prev)] if prev else None
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id=VECTORS["conventions"]["log_identity"]["sub"],
        mmr_size=size, root=core.root_from_peaks(peaks).hex(), prev_size=prev,
        prev_root=core.root_from_peaks(prev_peaks).hex() if prev_peaks else "",
        key_id=VECTORS["kid"], timestamp=claims["issued_at"], signature="",
    )
    proof = core.consistency_proof(store, prev, size) if 0 < prev < size else None
    return cp, peaks, prev_peaks, proof


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=WIRE_PENDING)
@pytest.mark.parametrize("cp", VECTORS["checkpoints"], ids=lambda cp: cp["id"])
def test_wire_claims_match_02(cp):
    import cbor2

    from cll.checkpoint.cose_wire import encode_checkpoint_claims

    store = _store()
    record, peaks, prev_peaks, proof = _record(cp["claims"], store)
    claims = encode_checkpoint_claims(
        record, peaks, prev_peak_hashes=prev_peaks, consistency_proof=proof,
        cadence_seconds=cp["claims"]["cadence"])
    if "leaf_count" in cp["claims"]:
        claims["leaf_count"] = cp["claims"]["leaf_count"]
    assert cbor2.dumps(claims, canonical=True).hex() == cp["claims_hex"]


class _SubjectCapture:
    """A signer stub: records the CWT issuer and subject it is asked to sign."""

    key_id = VECTORS["kid"]

    def sign_cose_statement(self, payload, *, content_type, issuer, subject, **_):
        self.issuer, self.subject = issuer, subject
        return b""


@pytest.mark.xfail(strict=True, raises=AssertionError, reason=WIRE_PENDING)
def test_wire_sub_is_the_log():
    from cll.checkpoint.cose_wire import checkpoint_to_cose

    store = _store()
    record, peaks, _, _ = _record(VECTORS["checkpoints"][0]["claims"], store)
    signer = _SubjectCapture()
    checkpoint_to_cose(record, signer, peaks)
    assert signer.subject == VECTORS["conventions"]["log_identity"]["sub"]
