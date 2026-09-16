# SPDX-License-Identifier: Apache-2.0
"""Verify ``vectors.json`` against the CLL Python reference.

Run from this directory or the repository root with ``python3
mmr-conformance-vectors/reference_verifier.py``.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cll.checkpoint import core
from cll.checkpoint.store import MemoryNodeStore


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


def _range_proof(data: dict) -> core.RangeProof:
    data = dict(data)
    data["witness"] = tuple(data["witness"])
    return core.RangeProof(**data)


def main() -> int:
    vectors = json.loads((Path(__file__).parent / "vectors.json").read_text())
    store = _fixture(vectors)
    failures = []
    for case in vectors["cases"]:
        kind = case["kind"]
        # A case is a positive by default; expect==false is a tamper case that
        # MUST be rejected. A positive is also required to regenerate exactly.
        expect = case.get("expect", True)
        if kind == "root":
            verified = _root(store, case["size"]).hex() == case["root_hex"]
            ok = verified == expect
        elif kind == "inclusion":
            proof = _inclusion_proof(case["proof"])
            verified = core.verify_inclusion(
                bytes.fromhex(case["root_hex"]), case["size"], case["leaf_index"],
                bytes.fromhex(case["body_digest_hex"]), proof,
            )
            ok = verified == expect
            if expect:
                ok = ok and core.inclusion_proof(store, case["leaf_index"], case["size"]) == proof
        elif kind == "consistency":
            proof = _consistency_proof(case["proof"])
            verified = core.verify_consistency(
                bytes.fromhex(case["root_a_hex"]), case["size_a"],
                bytes.fromhex(case["root_b_hex"]), case["size_b"], proof,
            )
            ok = verified == expect
            if expect:
                ok = ok and core.consistency_proof(store, case["size_a"], case["size_b"]) == proof
        elif kind == "range":
            proof = _range_proof(case["proof"])
            body_digests = [bytes.fromhex(digest) for digest in case["body_digests"]]
            verified = core.verify_range(
                bytes.fromhex(case["root_hex"]), case["size"],
                case["from_index"], case["to_index"], body_digests, proof,
            )
            ok = verified == expect
            if expect:
                ok = ok and core.range_proof(store, case["from_index"], case["to_index"], case["size"]) == proof
        else:
            failures.append(f"{case['name']}: unknown kind {kind!r}")
            continue
        if not ok:
            failures.append(f"{case['name']}: verify={verified!r}, expected verify=={expect!r}")
    if failures:
        print("FAIL:\n" + "\n".join(failures))
        return 1
    print(f"OK: {len(vectors['cases'])} MMR conformance vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
