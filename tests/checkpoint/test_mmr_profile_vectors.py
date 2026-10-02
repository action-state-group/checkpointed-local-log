# SPDX-License-Identifier: Apache-2.0
"""The draft-exact MMR profile vectors (mmr-profile-vectors/) regenerate byte for byte,
and the -03 transcription agrees with an independent post-order construction.

These vectors are the -03 draft's values, not CLL's. The last test records the one
relation that does hold: CLL's node values equal the draft's tree when the draft's
caller-defined leaf preimage is 0x00 || body_digest. CLL's roots and proofs are not
the draft's.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from cll.checkpoint import core
from cll.checkpoint.store import MemoryNodeStore

DIR = Path(__file__).parents[2] / "mmr-profile-vectors"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"_mmrprofile_{name}", DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _load("generate")
d = gen.d


def test_committed_vectors_regenerate_byte_for_byte():
    files = gen.render(DIR)
    for rel, text in files.items():
        assert (DIR / rel).read_text() == text, rel
    committed = {p.relative_to(DIR).as_posix() for p in (DIR / "v1").rglob("*") if p.is_file()}
    assert committed == {p for p in files if p.startswith("v1/")}


def test_sha256sums_cover_every_vector_file():
    lines = (DIR / "SHA256SUMS").read_text().splitlines()
    assert lines
    for line in lines:
        digest, rel = line.split("  ", 1)
        assert hashlib.sha256((DIR / rel).read_bytes()).hexdigest() == digest, rel


def test_manifest_pins_the_03_text_and_names_every_repair():
    m = json.loads((DIR / "manifest.json").read_text())
    assert m["provenance"]["draft_sha256"] == d.DRAFT_SHA256
    assert set(m["repairs"]) == {f"R{n}" for n in range(1, 9)}
    for case in m["vectors"]:
        assert set(case["expected"]["repairs_applied"]) <= set(m["repairs"]), case["id"]


def test_printed_all_ones_never_terminates_and_repair_matches_figure():
    assert d.index_height_as_printed(0, 100000) is None
    # Section 1 figure, MMR(8): heights of nodes 0..7
    assert [d.index_height(i) for i in range(8)] == [0, 0, 1, 0, 0, 1, 2, 0]


def _independent_postorder(leaves):
    """Post-order MMR built without any -03 algorithm: append, then merge equal-height peaks."""
    nodes, stack = [], []  # stack of (height, index)
    for leaf in leaves:
        nodes.append(leaf)
        stack.append((0, len(nodes) - 1))
        while len(stack) >= 2 and stack[-1][0] == stack[-2][0]:
            (h, right), (_, left) = stack.pop(), stack.pop()
            pos = len(nodes) + 1
            nodes.append(hashlib.sha256(pos.to_bytes(8, "big") + nodes[left] + nodes[right]).digest())
            stack.append((h + 1, len(nodes) - 1))
    return nodes, [i for _, i in stack]


def test_transcription_matches_independent_construction():
    entries, _, nodes = gen.fixture()
    ref, ref_peaks = _independent_postorder([hashlib.sha256(e).digest() for e in entries])
    assert nodes == ref
    assert d.peaks(len(nodes) - 1) == ref_peaks


def test_every_inclusion_and_consistency_pair_up_to_mmr39():
    _, _, nodes = gen.fixture()
    sizes = [s for s in range(1, len(nodes) + 1) if d.is_complete(s)]
    for s in sizes:
        peak_values = [nodes[p] for p in d.peaks(s - 1)]
        for i in range(s):
            path = [nodes[x] for x in d.inclusion_proof_path(i, s - 1)]
            assert d.included_root(i, nodes[i], path) in peak_values
    for a in sizes:
        for b in (x for x in sizes if x >= a):
            acc = [nodes[p] for p in d.peaks(a - 1)]
            paths = [[nodes[x] for x in p] for p in d.consistency_proof_paths(a - 1, b - 1)]
            right = d.right_peaks(nodes, a, b, acc)
            assert d.consistent_accumulator(a, b, acc, paths, right) == [
                nodes[p] for p in d.peaks(b - 1)
            ]


def test_cll_nodes_equal_draft_tree_with_prefixed_leaf_preimage():
    """CLL leaf = H(0x00 || body_digest); its parents use the draft's H(be64(i+1) || l || r).
    So CLL's node array is the -03 tree over x = 0x00 || body_digest. Roots, proofs and the
    accumulator encoding still differ; this is a relation, not a claim that CLL's vectors are
    the draft's."""
    store, db = MemoryNodeStore(), d.ListDB()
    for k in range(21):
        body = hashlib.sha256(f"cll-relation-{k}".encode()).digest()
        core.add_leaf(store, core.leaf_hash(body))
        d.add_leaf_hash(db, hashlib.sha256(b"\x00" + body).digest())
    assert [store.node(i) for i in range(store.size())] == db.nodes
