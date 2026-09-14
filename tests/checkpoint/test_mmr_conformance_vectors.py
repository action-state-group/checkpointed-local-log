# SPDX-License-Identifier: Apache-2.0
"""Shared MMR root and proof vectors must remain exact Python-reference output."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cll.checkpoint import core
from cll.checkpoint.store import MemoryNodeStore


VECTORS = Path(__file__).parents[2] / "mmr-conformance-vectors" / "vectors.json"


def _fixture(vectors: dict) -> MemoryNodeStore:
    store = MemoryNodeStore()
    template = vectors["leaf_identity"]["template"]
    for seq in range(1, 8):
        body = hashlib.sha256(template.format(seq=seq).encode("utf-8")).digest()
        core.add_leaf(store, core.leaf_hash(body))
    return store


def _root(store: MemoryNodeStore, size: int) -> bytes:
    return core.root_from_peaks([store.node(pos) for pos in core.peaks(size)])


def _inclusion_proof(data: dict) -> core.InclusionProof:
    data = dict(data)
    for field in ("witness", "peaks_left", "peaks_right"):
        data[field] = tuple(data[field])
    return core.InclusionProof(**data)


def _consistency_proof(data: dict) -> core.ConsistencyProof:
    data = dict(data)
    for field in ("old_peaks", "new_peaks"):
        data[field] = tuple(data[field])
    data["witness"] = tuple(tuple(w) for w in data["witness"])
    return core.ConsistencyProof(**data)


def test_mmr_conformance_vectors_match_reference_and_verify():
    vectors = json.loads(VECTORS.read_text())
    store = _fixture(vectors)
    assert vectors["count"] == len(vectors["cases"])

    for case in vectors["cases"]:
        if case["kind"] == "root":
            assert case["leaf_identity_inputs"]["seq_range"] == [1, case["leaf_count"]]
            assert _root(store, case["size"]).hex() == case["root_hex"], case["name"]
        elif case["kind"] == "inclusion":
            assert case["leaf_identity_inputs"]["seq_range"] == [1, case["leaf_count"]]
            body = hashlib.sha256(
                vectors["leaf_identity"]["template"].format(seq=case["leaf_index"] + 1).encode("utf-8")
            ).digest()
            assert body.hex() == case["body_digest_hex"], case["name"]
            proof = _inclusion_proof(case["proof"])
            assert core.inclusion_proof(store, case["leaf_index"], case["size"]) == proof, case["name"]
            assert core.verify_inclusion(
                bytes.fromhex(case["root_hex"]), case["size"], case["leaf_index"],
                bytes.fromhex(case["body_digest_hex"]), proof,
            ), case["name"]
        elif case["kind"] == "consistency":
            assert case["leaf_identity_inputs"]["seq_range"] == [1, case["leaf_count_b"]]
            proof = _consistency_proof(case["proof"])
            assert core.consistency_proof(store, case["size_a"], case["size_b"]) == proof, case["name"]
            assert core.verify_consistency(
                bytes.fromhex(case["root_a_hex"]), case["size_a"],
                bytes.fromhex(case["root_b_hex"]), case["size_b"], proof,
            ), case["name"]
        else:
            raise AssertionError(f"{case['name']}: unknown kind {case['kind']!r}")
