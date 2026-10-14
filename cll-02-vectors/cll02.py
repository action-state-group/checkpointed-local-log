# SPDX-License-Identifier: Apache-2.0
"""Reference encoder and verifier for draft-mih-scitt-checkpointed-local-log-02.

Written from the -02 text (spec/draft-mih-scitt-checkpointed-local-log-02.md),
on top of ``profile_main`` (the MMR profile's editors' main, transcribed). It
imports no checkpointed-local-log code, so the vectors it produces are an
independent check on the four implementations, not a copy of one of them.

Section references below are to the -02 text.
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import profile_main as pm

KIND = "cll-checkpoint"
HASH_LEN = 32
ALG_ED25519 = -19  # RFC 9864 fully-specified Ed25519
HDR_ALG, HDR_KID, HDR_CWT_CLAIMS = 1, 4, 15
CWT_ISS, CWT_SUB = 1, 2


class CheckpointError(ValueError):
    """A checkpoint fails a MUST of -02. ``code`` names which one."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


# -- deterministic CBOR (RFC 8949 Section 4.2.1), the subset -02 needs ------------

def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([(major << 5) | ai]) + n.to_bytes(width, "big")
    raise ValueError(n)


def cbor(v) -> bytes:
    if isinstance(v, bool) or v is None:
        raise TypeError("not used by -02")
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        items = sorted((cbor(k), cbor(x)) for k, x in v.items())
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise TypeError(type(v))


def decode(b: bytes):
    """Strict decoder: definite lengths, shortest-form heads, sorted unique map
    keys, no trailing bytes. Anything else is not deterministic CBOR."""
    v, end = _dec(b, 0)
    if end != len(b):
        raise CheckpointError("cbor-not-deterministic", "trailing bytes")
    return v


def _dec(b: bytes, i: int):
    if i >= len(b):
        raise CheckpointError("cbor-not-deterministic", "truncated")
    ib = b[i]
    major, ai = ib >> 5, ib & 0x1F
    i += 1
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        w = 1 << (ai - 24)
        if i + w > len(b):
            raise CheckpointError("cbor-not-deterministic", "truncated")
        n = int.from_bytes(b[i:i + w], "big")
        i += w
        if _head(major, n) != bytes([ib]) + n.to_bytes(w, "big"):
            raise CheckpointError("cbor-not-deterministic", "non-shortest head")
    else:
        raise CheckpointError("cbor-not-deterministic", "indefinite or reserved")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(b):
            raise CheckpointError("cbor-not-deterministic", "truncated")
        s = b[i:i + n]
        return (bytes(s) if major == 2 else s.decode("utf-8")), i + n
    if major == 4:
        out = []
        for _ in range(n):
            x, i = _dec(b, i)
            out.append(x)
        return out, i
    if major == 5:
        out, prev = {}, None
        for _ in range(n):
            ks = i
            k, i = _dec(b, i)
            kb = b[ks:i]
            if prev is not None and kb <= prev:
                raise CheckpointError("cbor-not-deterministic", "map keys unsorted or duplicated")
            prev = kb
            x, i = _dec(b, i)
            out[k] = x
        return out, i
    raise CheckpointError("cbor-not-deterministic", f"major type {major}")


# -- the log (Section 3 and "Entries and Leaves") ---------------------------------

def leaf_value(entry: bytes) -> bytes:
    """-02: the leaf value appended with add_leaf_hash is H(0x00 || entry)."""
    if len(entry) != HASH_LEN:
        raise ValueError("a CLL entry is a 32-byte digest")
    return hashlib.sha256(b"\x00" + entry).digest()


def build_log(entries: list[bytes]):
    db = pm.ListDB()
    sizes = [0]
    for e in entries:
        sizes.append(pm.add_leaf_hash(db, leaf_value(e)))
    return db.nodes, sizes


def accumulator(nodes, size: int) -> list[bytes]:
    return [] if size == 0 else [nodes[p] for p in pm.peaks(size - 1)]


def peak_count(size: int) -> int:
    return 0 if size == 0 else pm.ones_count(pm.leaf_count(size - 1))


def commitment(peaks: list[bytes]) -> bytes:
    """-02 Section 4.2: the accumulator's node values concatenated, tallest
    first -- the bytes a receipt of consistency's detached payload is."""
    return b"".join(peaks)


def split_commitment(c: bytes) -> list[bytes]:
    return [c[i:i + HASH_LEN] for i in range(0, len(c), HASH_LEN)]


def consistency_proof_content(nodes, size1: int, size2: int) -> list:
    """Producer side: [tree-size-1, tree-size-2, consistency-paths, right-peaks]."""
    paths = [[nodes[s] for s in p] for p in
             (pm.consistency_proof_paths(size1 - 1, size2 - 1) if size1 else [])]
    roots, nright = pm.consistent_roots(size1, size2, accumulator(nodes, size1), paths)
    acc2 = accumulator(nodes, size2)
    right = acc2[len(acc2) - nright:] if nright else []
    return [size1, size2, paths, right]


# -- claims (Section 4) --------------------------------------------------------------

def claims_map(*, log_size, commit, prev_size, prev_commit, issued_at,
               cadence=None, leaf_count=None, proof_content=None) -> dict:
    m = {
        "kind": KIND,
        "log_size": log_size,
        "commitment": commit,
        "prev_size": prev_size,
        "prev_commitment": prev_commit,
        "issued_at": issued_at,
    }
    if cadence is not None:
        m["cadence"] = cadence
    if leaf_count is not None:
        m["leaf_count"] = leaf_count
    if proof_content is not None:
        m["consistency_proof"] = cbor(proof_content)
    return m


# -- COSE_Sign1 (RFC 9052) -----------------------------------------------------------

def signing_key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def protected_header(kid: bytes, iss: str, sub: str) -> bytes:
    return cbor({HDR_ALG: ALG_ED25519, HDR_KID: kid,
                 HDR_CWT_CLAIMS: {CWT_ISS: iss, CWT_SUB: sub}})


def sign1(key: Ed25519PrivateKey, protected: bytes, payload: bytes) -> bytes:
    tbs = cbor(["Signature1", protected, b"", payload])
    sig = key.sign(tbs)
    return b"\xd2" + cbor([protected, {}, payload, sig])


# -- verification (Sections 4.3, 5 and 6) --------------------------------------------

def parse_and_verify_signature(cose: bytes, trusted_kid: bytes):
    """Returns (log identity, claims). The key is the caller's trust input."""
    if not cose.startswith(b"\xd2"):
        raise CheckpointError("cose-malformed", "not tag 18")
    arr = decode(cose[1:])
    if not (isinstance(arr, list) and len(arr) == 4):
        raise CheckpointError("cose-malformed")
    protected, _unprotected, payload, sig = arr
    hdr = decode(protected)
    if hdr.get(HDR_ALG) != ALG_ED25519 or hdr.get(HDR_KID) != trusted_kid:
        raise CheckpointError("cose-malformed", "alg or kid")
    try:
        Ed25519PublicKey.from_public_bytes(trusted_kid).verify(
            sig, cbor(["Signature1", protected, b"", payload]))
    except Exception as exc:
        raise CheckpointError("signature-invalid") from exc
    cwt = hdr.get(HDR_CWT_CLAIMS)
    if not isinstance(cwt, dict) or not isinstance(cwt.get(CWT_ISS), str) \
            or not isinstance(cwt.get(CWT_SUB), str):
        raise CheckpointError("log-identity-missing")
    return (cwt[CWT_ISS], cwt[CWT_SUB]), decode(payload)


def _uint(m, k):
    v = m.get(k)
    if not isinstance(v, int) or v < 0:
        raise CheckpointError("claim-type", k)
    return v


def _bstr(m, k):
    v = m.get(k)
    if not isinstance(v, bytes):
        raise CheckpointError("claim-type", k)
    return v


def check_claims(m: dict) -> None:
    """Section 4.3: every check a verifier makes on one checkpoint alone."""
    if m.get("kind") != KIND:
        raise CheckpointError("kind")
    log_size, prev_size = _uint(m, "log_size"), _uint(m, "prev_size")
    c, pc = _bstr(m, "commitment"), _bstr(m, "prev_commitment")
    if not isinstance(m.get("issued_at"), str):
        raise CheckpointError("claim-type", "issued_at")
    for name, size in (("log_size", log_size), ("prev_size", prev_size)):
        if not pm.is_complete(size):
            raise CheckpointError("size-incomplete", name)
    if prev_size > log_size:
        raise CheckpointError("size-decreased")
    if len(c) != HASH_LEN * peak_count(log_size):
        raise CheckpointError("commitment-length")
    if len(pc) != HASH_LEN * peak_count(prev_size):
        raise CheckpointError("prev-commitment-length")
    if "leaf_count" in m:
        lc = _uint(m, "leaf_count")
        if lc != (pm.leaf_count(log_size - 1) if log_size else 0):
            raise CheckpointError("leaf-count-mismatch")
    has_proof = "consistency_proof" in m
    if prev_size == 0 or prev_size == log_size:
        if has_proof:
            raise CheckpointError("proof-unexpected")
        if prev_size == log_size and c != pc:
            raise CheckpointError("commitment-changed-without-growth")
        return
    if not has_proof:
        raise CheckpointError("proof-missing")
    raw = m["consistency_proof"]
    if not isinstance(raw, bytes):
        raise CheckpointError("proof-not-profile-encoding", "not a bstr")
    content = decode(raw)
    if not (isinstance(content, list) and len(content) == 4
            and isinstance(content[0], int) and isinstance(content[1], int)
            and isinstance(content[2], list) and isinstance(content[3], list)):
        raise CheckpointError("proof-not-profile-encoding", "shape")
    if content[0] != prev_size or content[1] != log_size:
        raise CheckpointError("proof-sizes")
    try:
        acc = pm.verify_consistency_accumulator(prev_size, split_commitment(pc), content)
    except pm.ProofError as exc:
        raise CheckpointError("proof-invalid", str(exc)) from exc
    if commitment(acc) != c:
        raise CheckpointError("proof-invalid", "accumulator != commitment")


def registration_continuity(identity, m: dict, registered: dict) -> str:
    """Section 5.2: a Transparency Service's consistency Registration Policy.

    ``registered`` maps a log identity (iss, sub) to the (log_size,
    commitment) it last registered. Returns "continuous" or "first-seen";
    raises on a checkpoint the policy refuses."""
    last = registered.get(identity)
    if last is None:
        return "first-seen"
    if (m["prev_size"], m["prev_commitment"]) != last:
        raise CheckpointError("not-continuous")
    return "continuous"
