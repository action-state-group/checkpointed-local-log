# SPDX-License-Identifier: Apache-2.0
"""Deterministic generator for the draft-mih-scitt-checkpointed-local-log-02 vectors.

    python3 cll-02-vectors/generate.py            # rewrite vectors.json and SHA256SUMS
    python3 cll-02-vectors/generate.py --check    # exit 1 if the committed bytes differ

Inputs are fixed strings and a fixed Ed25519 seed; Ed25519 signing is
deterministic (RFC 8032), so every byte reproduces. Values come from
``cll02`` (the -02 text) over ``profile_main`` (the MMR profile's editors'
main). No checkpointed-local-log implementation code is imported.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cll02 as c  # noqa: E402
import profile_main as pm  # noqa: E402

LEAVES = 21  # MMR(39), the size the profile's own examples use
ENTRY_TEMPLATE = "cll-02 vector entry {k}"
SEED = bytes([0x07] * 32)  # same fixture seed as ../checkpoint-conformance-vectors
ISS = "https://producer.example"
SUB = "https://producer.example/logs/1"
CADENCE = 3600
PINNED_COPIES = ("go/mmr/testdata/cll02_vectors.json", "ts/test/testdata/cll-02-vectors.json")

# (leaves, issued_at, carry leaf_count)
CHAIN = [
    (3, "2026-10-13T00:00:00Z", False),
    (7, "2026-10-13T01:00:00Z", True),
    (7, "2026-10-13T02:00:00Z", False),  # no growth: no proof, same commitment
    (21, "2026-10-13T03:00:00Z", True),
]


def hx(b: bytes) -> str:
    return b.hex()


def entries():
    return [hashlib.sha256(ENTRY_TEMPLATE.format(k=k).encode("utf-8")).digest()
            for k in range(LEAVES)]


def proof_json(content):
    s1, s2, paths, right = content
    return {"tree_size_1": s1, "tree_size_2": s2,
            "consistency_paths": [[hx(x) for x in p] for p in paths],
            "right_peaks": [hx(x) for x in right]}


def build():
    ents = entries()
    nodes, sizes = c.build_log(ents)
    key = c.signing_key(SEED)
    kid = c.raw_public(key)

    size_table = []
    for n, size in enumerate(sizes):
        acc = c.accumulator(nodes, size)
        com = c.commitment(acc)
        size_table.append({
            "leaf_count": n, "log_size": size,
            "peaks": [hx(p) for p in acc],
            "commitment": hx(com),
            "commitment_sha256": hashlib.sha256(com).hexdigest(),
        })

    checkpoints = []
    prev_size, prev_com = 0, b""
    for i, (leaves, issued_at, with_lc) in enumerate(CHAIN, 1):
        size = sizes[leaves]
        com = c.commitment(c.accumulator(nodes, size))
        content = (c.consistency_proof_content(nodes, prev_size, size)
                   if 0 < prev_size < size else None)
        claims = c.claims_map(log_size=size, commit=com, prev_size=prev_size,
                              prev_commit=prev_com, issued_at=issued_at, cadence=CADENCE,
                              leaf_count=leaves if with_lc else None, proof_content=content)
        payload = c.cbor(claims)
        protected = c.protected_header(kid, ISS, SUB)
        cose = c.sign1(key, protected, payload)
        checkpoints.append({
            "id": f"cp{i}", "leaves": leaves, "claims": claims,
            "claims_hex": hx(payload), "protected_hex": hx(protected), "cose_hex": hx(cose),
            "consistency_proof": proof_json(content) if content else None,
            "consistency_proof_hex": hx(c.cbor(content)) if content else None,
        })
        prev_size, prev_com = size, com
    return ents, nodes, sizes, key, kid, size_table, checkpoints


def flip(b: bytes) -> bytes:
    return bytes([b[0] ^ 0x01]) + b[1:]


def negatives(nodes, sizes, key, kid, cps):
    """Each mutant changes one thing in an honest checkpoint and names the
    -02 MUST it breaks. ``registered`` is the Transparency Service state the
    case is evaluated against (None: the single-checkpoint checks only)."""
    cp1, cp2, cp3, cp4 = (x["claims"] for x in cps)
    out = []

    def add(id_, base, mutate, code, description, sub=SUB, registered=None, expect="FAIL"):
        m = copy.deepcopy(base)
        mutate(m)
        payload = c.cbor(m)
        cose = c.sign1(key, c.protected_header(kid, ISS, sub), payload)
        out.append({"id": id_, "description": description, "expected_result": expect,
                    "failure_code": code if expect == "FAIL" else None,
                    "registered": registered, "sub": sub,
                    "claims_hex": hx(payload), "cose_hex": hx(cose)})

    def set_(k, v):
        return lambda m: m.__setitem__(k, v)

    def drop(k):
        return lambda m: m.pop(k)

    old_proof_cbor = c.decode(cp2["consistency_proof"])

    def legacy_array(m):
        m["commitment"] = c.cbor(c.split_commitment(m["commitment"]))

    add("fail-commitment-cbor-array", cp2, legacy_array, "commitment-length",
        "commitment carried as the -01 CBOR array [*bstr] instead of the concatenation.")
    add("fail-log-size-is-leaf-count", cp2, set_("log_size", 7), "commitment-length",
        "log_size carries the leaf count (7). 7 is a complete size with 1 peak, so the "
        "3-peak commitment no longer fits.")
    add("fail-log-size-incomplete", cp2, set_("log_size", 9), "size-incomplete",
        "log_size 9 is not a complete MMR size.")
    add("fail-leaf-count-mismatch", cp2, set_("leaf_count", 11), "leaf-count-mismatch",
        "leaf_count carries the node count instead of the leaf count.")
    add("fail-proof-missing", cp2, drop("consistency_proof"), "proof-missing",
        "prev_size > 0 and the log grew, but no consistency_proof.")

    def legacy_proof(m):
        m["consistency_proof"] = {"size_a": 4, "size_b": 11, "old_peaks": [], "witness": [],
                                  "new_peaks": []}

    add("fail-proof-legacy-map", cp2, legacy_proof, "proof-not-profile-encoding",
        "consistency_proof as the pre-02 implementation map (size_a/size_b/old_peaks/"
        "witness/new_peaks), not the profile's consistency-proof.")

    def tamper_path(m):
        p = copy.deepcopy(old_proof_cbor)
        p[2][0][0] = flip(p[2][0][0])
        m["consistency_proof"] = c.cbor(p)

    add("fail-proof-tampered-path", cp2, tamper_path, "proof-invalid",
        "first node of the first consistency path altered.")

    def tamper_later_path(m):
        p = copy.deepcopy(c.decode(cp4["consistency_proof"]))
        p[2][1][-1] = flip(p[2][1][-1])
        m["consistency_proof"] = c.cbor(p)

    add("fail-proof-paths-disagree", cp4, tamper_later_path, "proof-invalid",
        "11 -> 39: all three origin peaks lead to the same height-4 peak; the second "
        "path's last node is altered. Only the check that every path to one peak "
        "agrees catches this: the first path alone still reaches the commitment.")

    def drop_right(m):
        p = copy.deepcopy(old_proof_cbor)
        p[3] = p[3][:-1]
        m["consistency_proof"] = c.cbor(p)

    add("fail-proof-right-peaks-count", cp2, drop_right, "proof-invalid",
        "one right-peak removed.")

    def wrong_sizes(m):
        p = copy.deepcopy(old_proof_cbor)
        p[0] = 3
        m["consistency_proof"] = c.cbor(p)

    add("fail-proof-sizes", cp2, wrong_sizes, "proof-sizes",
        "consistency_proof tree-size-1 (3) differs from prev_size (4).")
    add("fail-proof-on-first", cp1, set_("consistency_proof", cp2["consistency_proof"]),
        "proof-unexpected", "a first checkpoint (prev_size 0) carrying a consistency_proof.")
    add("fail-no-growth-commitment-changed", cp3,
        set_("commitment", flip(cp3["commitment"])), "commitment-changed-without-growth",
        "log_size == prev_size but the commitment differs from prev_commitment.")

    def rewrite_peak(m):
        m["commitment"] = flip(m["commitment"])

    add("fail-commitment-not-extension", cp2, rewrite_peak, "proof-invalid",
        "commitment altered: the honest proof from prev_commitment no longer reaches it.")

    # Registration continuity (Section 5.2): internally valid, refused by state.
    cp1_state = {"log_size": cp1["log_size"], "commitment": hx(cp1["commitment"])}
    cp2_state = {"log_size": cp2["log_size"], "commitment": hx(cp2["commitment"])}
    skip = c.claims_map(log_size=cp4["log_size"], commit=cp4["commitment"],
                        prev_size=cp1["log_size"], prev_commit=cp1["commitment"],
                        issued_at="2026-10-13T03:00:00Z", cadence=CADENCE,
                        proof_content=c.consistency_proof_content(
                            nodes, cp1["log_size"], cp4["log_size"]))
    add("fail-registration-not-continuous", skip, lambda m: None, "not-continuous",
        "internally valid (a correct proof 4 -> 39), but the Transparency Service last "
        "registered size 11 for this log identity; prev_* must equal that.",
        registered=cp2_state)
    add("sub-per-checkpoint-is-first-seen", cp2, lambda m: None, None,
        "honest cp2 claims, but sub = '<log>#11' (the pre-02 implementations' form). The "
        "Transparency Service holds state for '<log>' only, so it sees a new log identity: "
        "continuity is never checked. Expected outcome 'first-seen', where the same claims "
        "under the log's own sub give 'continuous'.",
        sub=f"{SUB}#{cp2['log_size']}", registered=cp1_state, expect="first-seen")
    return out


def evaluate(case, kid, sub=SUB):
    """What the reference verifier concludes; used by --check and the tests."""
    identity, m = c.parse_and_verify_signature(bytes.fromhex(case["cose_hex"]), kid)
    c.check_claims(m)
    reg = case.get("registered")
    if reg is None:
        return "VALID"
    state = {(ISS, sub): (reg["log_size"], bytes.fromhex(reg["commitment"]))}
    return c.registration_continuity(identity, m, state)


def jsonable(v):
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, dict):
        return {k: jsonable(x) for k, x in v.items()}
    if isinstance(v, list):
        return [jsonable(x) for x in v]
    return v


def manifest():
    ents, nodes, sizes, key, kid, size_table, cps = build()
    negs = negatives(nodes, sizes, key, kid, cps)
    for case in negs:
        try:
            got = evaluate(case, kid)
        except c.CheckpointError as exc:
            got = f"FAIL:{exc.code}"
        want = (f"FAIL:{case['failure_code']}" if case["expected_result"] == "FAIL"
                else case["expected_result"])
        if got != want:
            raise SystemExit(f"{case['id']}: reference verifier says {got}, expected {want}")
    registered = {}
    for cp in cps:
        identity, m = c.parse_and_verify_signature(bytes.fromhex(cp["cose_hex"]), kid)
        c.check_claims(m)
        cp["continuity"] = c.registration_continuity(identity, m, registered)
        registered[identity] = (m["log_size"], m["commitment"])
    return {
        "version": "v1",
        "draft": "draft-mih-scitt-checkpointed-local-log-02",
        "profile": {"draft": "draft-bryce-cose-receipts-mmr-profile-03",
                    "editors_main": f"{pm.PROFILE_REPO} @ {pm.PROFILE_COMMIT}",
                    "algorithms": "profile_main.py (editors' main, as printed)"},
        "conventions": {
            "entry": f"SHA-256(UTF-8 '{ENTRY_TEMPLATE}'), k = 0..{LEAVES - 1}",
            "leaf_value": "SHA-256(0x00 || entry), appended with add_leaf_hash",
            "interior_node": "SHA-256(be64(pos) || left || right), pos = index + 1",
            "log_size": "MMR node count (the profile's tree-size), a complete MMR size",
            "commitment": "accumulator node values concatenated, tallest first",
            "consistency_proof": "bstr .cbor [tree-size-1, tree-size-2, consistency-paths, right-peaks]",
            "cbor": "RFC 8949 Section 4.2.1 deterministic encoding",
            "signing": "COSE_Sign1, alg -19 (Ed25519), kid = raw public key, "
                       "CWT_Claims {iss, sub}; seed 0x07 x 32",
            "log_identity": {"iss": ISS, "sub": SUB},
        },
        "kid": hx(kid),
        "entries": [hx(e) for e in ents],
        "nodes": [hx(n) for n in nodes],
        "sizes": size_table,
        "checkpoints": [jsonable(cp) for cp in cps],
        "negative": negs,
    }


def write(check: bool) -> int:
    data = (json.dumps(manifest(), indent=2, sort_keys=False) + "\n").encode("utf-8")
    sums = f"{hashlib.sha256(data).hexdigest()}  vectors.json\n".encode("ascii")
    targets = {HERE / "vectors.json": data, HERE / "SHA256SUMS": sums}
    # Go and TypeScript read pinned copies from inside their own package trees.
    for pinned in PINNED_COPIES:
        targets[HERE.parent / pinned] = data
    if check:
        stale = [p.name for p, b in targets.items() if not p.exists() or p.read_bytes() != b]
        if stale:
            print("stale:", ", ".join(stale))
            return 1
        print("cll-02-vectors: up to date")
        return 0
    for p, b in targets.items():
        p.write_bytes(b)
    print("wrote", ", ".join(p.name for p in targets))
    return 0


if __name__ == "__main__":
    sys.exit(write("--check" in sys.argv[1:]))
