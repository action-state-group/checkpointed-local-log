# SPDX-License-Identifier: Apache-2.0
"""Deterministic generator for the draft-exact MMR profile vectors.

    python3 mmr-profile-vectors/generate.py            # rewrite manifest.json, v1/, SHA256SUMS
    python3 mmr-profile-vectors/generate.py --check    # exit 1 if the committed bytes differ

Inputs are fixed strings; there are no keys, clocks or randomness. The
algorithms come from ``draft03.py`` (the -03 text with its named repairs). No
CLL code is imported here: these are the draft's values, not CLL's.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import draft03 as d  # noqa: E402

VERSION = "v1"
LEAF_COUNT = 21  # MMR(39), the size the draft's reference KAT also uses
ENTRY_TEMPLATE = "draft-bryce-cose-receipts-mmr-profile-03 vector entry {k}"


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hx(b: bytes) -> str:
    return b.hex()


# -- deterministic CBOR (RFC 8949 4.2.1) for the -03 proof CDDL ----------------

def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([(major << 5) | ai]) + n.to_bytes(width, "big")
    raise ValueError(n)


def cbor(v) -> bytes:
    if isinstance(v, int):
        return _head(0, v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor(x) for x in v)
    raise TypeError(type(v))


# -- fixture ---------------------------------------------------------------------

def fixture():
    entries = [ENTRY_TEMPLATE.format(k=k).encode("utf-8") for k in range(LEAF_COUNT)]
    db = d.ListDB()
    leaf_index_of = []
    for e in entries:
        leaf_index_of.append(len(db.nodes))
        d.add_leaf_hash(db, H(e))  # R8: the leaf value is H(entry)
    return entries, leaf_index_of, db.nodes


def flip(b: bytes) -> bytes:
    return bytes([b[0] ^ 0x01]) + b[1:]


def main_cases():
    entries, leaf_index_of, nodes = fixture()
    size = len(nodes)
    cases = []

    def add(id_, description, result, expected, repairs, failure_code=None, kind=None):
        c = {"id": id_, "dir": f"{VERSION}/{id_}", "kind": kind, "description": description,
             "expected_result": result}
        if failure_code:
            c["failure_code"] = failure_code
        exp = {"description": description, **expected, "repairs_applied": repairs,
               "result": result}
        if failure_code:
            exp["failure_code"] = failure_code
        c["expected"] = exp
        cases.append(c)

    # -- primitives --------------------------------------------------------------
    add("prim-all-ones", "A.4 all_ones as printed vs repaired (R1), pos 1..16.", "VALID", {
        "pos": list(range(1, 17)),
        "all_ones_as_printed": [d.all_ones_as_printed(p) for p in range(1, 17)],
        "all_ones_repaired": [d.all_ones(p) for p in range(1, 17)],
        "index_height_0_as_printed_returns_within_100000_steps":
            d.index_height_as_printed(0, 100000) is not None,
    }, ["R1"], kind="primitive")

    add("prim-index-height-mmr39", "9.1 index_height for every node of MMR(39).", "VALID", {
        "tree_size": size,
        "index_height": [d.index_height(i) for i in range(size)],
    }, ["R1"], kind="primitive")

    complete = [s for s in range(0, size + 1) if d.is_complete(s)]
    add("prim-peaks-complete-sizes", "9.2 peaks(tree_size - 1) for every complete size up to 39; "
        "sizes are node counts.", "VALID", {
        "complete_sizes": complete,
        "leaf_counts": [sum(1 for i in range(s) if d.index_height(i) == 0) for s in complete],
        "peaks": {str(s): d.peaks(s - 1) for s in complete},
    }, ["R1", "R7"], kind="primitive")

    db_alt_nodes = []

    class IndexDB(d.ListDB):  # the other reading of 8.1: append returns the index just stored
        def append(self, entry):
            self.nodes.append(entry)
            return len(self.nodes) - 1

    alt = IndexDB()
    for e in entries[:4]:
        d.add_leaf_hash(alt, H(e))
    db_alt_nodes = alt.nodes
    good = d.ListDB()
    for e in entries[:4]:
        d.add_leaf_hash(good, H(e))
    add("prim-add-leaf-hash-4", "8.1 add_leaf_hash over 4 leaves: R2 gives the 7-node post-order "
        "layout; reading append() as 'index just stored' gives 5 nodes.", "VALID", {
        "leaf_entries": [hx(e) for e in entries[:4]],
        "nodes_r2": [hx(n) for n in good.nodes],
        "node_count_r2": len(good.nodes),
        "node_count_if_append_returns_stored_index": len(db_alt_nodes),
    }, ["R1", "R2", "R8"], kind="primitive")

    add("fixture-mmr39", "The fixture: 21 entries appended with add_leaf_hash; every node value of "
        "MMR(39).", "VALID", {
        "entry_template": ENTRY_TEMPLATE,
        "leaf_entries": [hx(e) for e in entries],
        "leaf_node_index": leaf_index_of,
        "nodes": [hx(n) for n in nodes],
        "peaks": d.peaks(size - 1),
        "accumulator": [hx(nodes[p]) for p in d.peaks(size - 1)],
    }, ["R1", "R2", "R7", "R8"], kind="fixture")

    # -- inclusion ---------------------------------------------------------------
    def inclusion(id_, desc, index, tree_size, entry=None, nodehash=None, path=None,
                  claimed_index=None, result="VALID", code=None, extra=None):
        if path is None:
            path = [nodes[s] for s in d.inclusion_proof_path(index, tree_size - 1)]
        if nodehash is None:
            nodehash = H(entry)
        ci = index if claimed_index is None else claimed_index
        signed_peak = [nodes[p] for p in d.peaks(tree_size - 1)
                       if p >= index and p - (2 << d.index_height(p)) + 2 <= index][0]
        got = d.included_root(ci, nodehash, path)
        ok = got == signed_peak
        assert ok == (result == "VALID"), id_
        exp = {
            "leaf_entry": hx(entry) if entry is not None else None,
            "node_hash": hx(nodehash),
            "index": ci,
            "tree_size": tree_size,
            "inclusion_path": [hx(p) for p in path],
            "inclusion_proof_cbor": hx(cbor([ci, path])),
            "receipt_payload": hx(signed_peak),
            "reconstructed_root": hx(got) if ok else None,
        }
        if extra:
            exp.update(extra)
        add(id_, desc, result, exp, ["R1", "R7", "R8"], code, kind="inclusion")

    L = leaf_index_of
    inclusion("inc-leaf0-size3", "Leaf 0 in MMR(3): one-step path to peak 2.", L[0], 3, entries[0])
    inclusion("inc-leaf0-size39", "Leaf 0 in MMR(39): four-step path to peak 30.", L[0], 39, entries[0])
    inclusion("inc-leaf2-size4", "Leaf 2 (index 3) in MMR(4): it is itself a peak, so the path is "
              "empty. Note: -03's CDDL 'inclusion-path: [ + bstr ]' rejects this encoding.",
              L[2], 4, entries[2])
    inclusion("inc-leaf4-size8", "Leaf 4 (index 7) in MMR(8): single-leaf peak, empty path.",
              L[4], 8, entries[4])
    inclusion("inc-leaf3-size8", "Leaf 3 (index 4) in MMR(8): right sibling first, path to peak 6.",
              L[3], 8, entries[3])
    inclusion("inc-leaf17-size39", "Leaf 17 (index 32) in MMR(39): path to peak 37.",
              L[17], 39, entries[17])
    inclusion("inc-leaf20-size39", "Last leaf (index 38) in MMR(39): single-leaf peak, empty path.",
              L[20], 39, entries[20])
    inclusion("inc-interior2-size7", "Interior node 2 in MMR(7), node value given directly (-03 "
              "lets index name any node).", 2, 7, nodehash=nodes[2])

    good_path = [nodes[s] for s in d.inclusion_proof_path(L[0], 38)]
    inclusion("fail-inc-tampered-path", "Leaf 0 in MMR(39) with one bit flipped in the first path "
              "node. The computed peak no longer matches the signed peak.", L[0], 39, entries[0],
              path=[flip(good_path[0])] + good_path[1:], result="INVALID",
              code="TAMPERED_INCLUSION_PATH")
    inclusion("fail-inc-wrong-index", "Leaf 1's honest proof presented under leaf 0's index: "
              "the position commitment changes every parent hash.", L[1], 39, entries[1],
              claimed_index=L[0], result="INVALID", code="WRONG_INDEX")
    inclusion("fail-inc-wrong-entry", "Leaf 0's honest proof with the entry bytes of leaf 1.",
              L[0], 39, entries[1], path=good_path, result="INVALID", code="WRONG_ENTRY")

    # hazards: accepted by -03 as written (nothing in -03 rejects them)
    alias_entry = (3).to_bytes(8, "big") + nodes[0] + nodes[1]
    assert H(alias_entry) == nodes[2]
    inclusion("hazard-interior-alias", "Accepted by -03 as written. The 72 bytes be64(3) || "
              "node0 || node1 were never appended, yet H(them) equals interior node 2, so the "
              "proof index=2, path=[node5] reaches the signed peak 6 of MMR(7). A verifier that "
              "requires index_height(index) == 0 for an entry (not in -03) rejects it.",
              2, 7, alias_entry, extra={"rejected_if_leaf_only_check": True})
    inclusion("hazard-empty-path-index-rebind", "Accepted by -03 as written. The honest receipt "
              "for leaf 4 (index 7, a peak of MMR(8), empty path) relabelled index 0: with an "
              "empty path included_root returns the node hash and never reads the index.",
              L[4], 8, entries[4], claimed_index=0,
              extra={"rejected_if_leaf_only_check": False})

    # -- consistency -------------------------------------------------------------
    def consistency(id_, desc, s1, s2, acc_from=None, paths=None, right=None,
                    result="VALID", code=None, extra=None):
        honest_acc = [nodes[p] for p in d.peaks(s1 - 1)] if d.is_complete(s1) else None
        if acc_from is None:
            acc_from = honest_acc
        if paths is None:
            paths = [[nodes[x] for x in p] for p in d.consistency_proof_paths(s1 - 1, s2 - 1)]
        if right is None:
            right = d.right_peaks(nodes, s1, s2, honest_acc)
        signed = [nodes[p] for p in d.peaks(s2 - 1)] if d.is_complete(s2) else None
        try:
            got = d.consistent_accumulator(s1, s2, acc_from, paths, right)
            ok = got == signed
        except (d.IncompleteSize, d.CardinalityError):
            got, ok = None, False
        assert ok == (result == "VALID"), id_
        exp = {
            "tree_size_1": s1,
            "tree_size_2": s2,
            "accumulator_from": [hx(a) for a in acc_from],
            "consistency_paths": [[hx(x) for x in p] for p in paths],
            "right_peaks": [hx(x) for x in right],
            "consistency_proof_cbor": hx(cbor([s1, s2, paths, list(right)])),
            "signed_accumulator": [hx(x) for x in signed] if signed else None,
            "consistent_accumulator": [hx(x) for x in got] if ok else None,
        }
        if extra:
            exp.update(extra)
        add(id_, desc, result, exp, ["R1", "R3", "R4", "R5", "R6", "R7"], code, kind="consistency")

    merge_paths = d.consistency_proof_paths(3, 7)
    consistency("con-4-to-8-merge", "MERGE CASE. MMR(4) (3 leaves, peaks [2, 3]) to MMR(8) (5 "
                "leaves, peaks [6, 7]). Both origin peaks reach peak 6, so consistent_roots "
                "returns one root and right-peaks must be [node 7]. Section 6.1 as printed "
                "(discard len(proofs) = 2) gives right-peaks = [] and loses peak 7.", 4, 8,
                extra={"path_node_indices": merge_paths,
                       "right_peaks_section_6_1_as_printed":
                           [hx(x) for x in d.right_peaks_as_printed(nodes, 8, merge_paths)]})
    consistency("con-3-to-7", "MMR(3) to MMR(7): peak 2 grows into peak 6.", 3, 7)
    consistency("con-7-to-8", "MMR(7) to MMR(8): peak 6 unchanged (empty path), right-peaks [7].",
                7, 8)
    consistency("con-8-to-15-merge", "MMR(8) to MMR(15): peaks [6, 7] both reach peak 14.", 8, 15)
    consistency("con-10-to-39", "MMR(10) (6 leaves) to MMR(39) (21 leaves): peaks [6, 9] both "
                "reach peak 30; right-peaks [37, 38].", 10, 39)
    consistency("con-1-to-39", "MMR(1) to MMR(39): a single leaf carried to peak 30.", 1, 39)
    consistency("con-39-to-39", "Same size: every path empty, no right-peaks.", 39, 39)

    consistency("fail-con-right-peaks-6-1-as-printed", "The merge case with right-peaks built by "
                "Section 6.1 as printed ([]): the accumulator has one peak where MMR(8) has two.",
                4, 8, right=d.right_peaks_as_printed(nodes, 8, merge_paths), result="INVALID",
                code="RIGHT_PEAKS_COUNT")
    honest = [[nodes[x] for x in p] for p in merge_paths]
    consistency("fail-con-tampered-path", "The merge case with one bit flipped in the second "
                "origin peak's path: its root no longer equals the first, so two roots plus one "
                "right peak exceed MMR(8)'s two peaks.", 4, 8,
                paths=[honest[0], [flip(honest[1][0])] + honest[1][1:]], result="INVALID",
                code="TAMPERED_CONSISTENCY_PATH")
    consistency("fail-con-wrong-accumulator-from", "con-10-to-39 with a wrong trusted origin "
                "accumulator (first peak bit-flipped): the computed accumulator differs from the "
                "signed one.", 10, 39,
                acc_from=[flip(nodes[6]), nodes[9]], result="INVALID",
                code="ACCUMULATOR_MISMATCH")
    consistency("fail-con-cardinality", "The merge case with only one origin peak value supplied "
                "for MMR(4), which has two (R6).", 4, 8, acc_from=[nodes[2]], result="INVALID",
                code="CARDINALITY_MISMATCH")
    consistency("fail-con-incomplete-size-2", "tree-size-2 = 9 is not a complete MMR size "
                "(index_height(9) != 0) and must be rejected (R7). Without R7, peaks(8) returns "
                "[6, 7, 8].", 8, 9, paths=[[], []], right=[nodes[7]],
                result="INVALID", code="INCOMPLETE_TREE_SIZE",
                extra={"peaks_as_printed_for_size_9": d.peaks_as_printed(8)})
    return cases


def render(out: Path):
    cases = main_cases()
    files = {}
    for c in cases:
        files[f"{c['dir']}/expected.json"] = json.dumps(c["expected"], indent=2) + "\n"
    manifest = {
        "version": VERSION,
        "stability": "draft-exact; regenerated, not appended, when the draft changes",
        "provenance": {
            "draft": d.DRAFT,
            "draft_url": d.DRAFT_URL,
            "draft_sha256": d.DRAFT_SHA256,
            "generator": "mmr-profile-vectors/generate.py",
            "note": "Derived from the -03 text alone: pseudocode transcribed in draft03.py with "
                    "only the repairs the -03 prose states, each named in `repairs`. These are "
                    "the draft's values, not checkpointed-local-log's (CLL domain-separates "
                    "leaves; see README).",
        },
        "repairs": d.REPAIRS,
        "hash": "SHA-256; interior node = SHA-256(be64(pos) || left || right), pos = index + 1",
        "leaf_entry_definition": "leaf node value = SHA-256(entry bytes) (Section 8.1, R8)",
        "tree_construction": f"{LEAF_COUNT} entries '{ENTRY_TEMPLATE}' (k = 0..{LEAF_COUNT - 1}, "
                             "UTF-8) appended with add_leaf_hash; MMR(39)",
        "sizes": "tree_size, tree_size_1 and tree_size_2 are MMR node counts, not leaf counts",
        "vectors": cases,
    }
    files["manifest.json"] = json.dumps(manifest, indent=2) + "\n"
    sums = "".join(f"{hashlib.sha256(files[p].encode()).hexdigest()}  {p}\n"
                   for p in sorted(files) if p.startswith(f"{VERSION}/"))
    files["SHA256SUMS"] = sums
    return files


def main(argv):
    files = render(HERE)
    if "--check" in argv:
        bad = [p for p, s in files.items()
               if not (HERE / p).is_file() or (HERE / p).read_text() != s]
        if bad:
            print("STALE:\n" + "\n".join(bad))
            return 1
        print(f"OK: {len(files)} files match the generator")
        return 0
    for p, s in files.items():
        (HERE / p).parent.mkdir(parents=True, exist_ok=True)
        (HERE / p).write_text(s)
    print(f"wrote {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
