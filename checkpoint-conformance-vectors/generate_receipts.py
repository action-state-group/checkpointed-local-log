# SPDX-License-Identifier: Apache-2.0
"""Generate ``receipt-vectors.json``: witness receipts over one checkpoint that
every CLL receipt verifier must decide the same way as agent-action-capsule's
``VerifyCOSEReceipt``, which since agent-action-capsule#523 (``go/v0.19.0``; ``go/v0.18.0``
accepts an undefined payload) decodes the
receipt, its protected header and each inclusion-proof blob under the receipt
encoding rule of the AAC interop profile v1 section 6.2.2.

Each case is a COSE Receipt (RFC 9942 shape, RFC 9162 SHA-256 inclusion
proof) over the entry hash of the ``checkpoint-first-2-leaves`` statement in
``cose-vectors.json``, signed by a fixture authority key. The receipts are
assembled byte by byte, so the file depends on none of the verifiers it
tests; Ed25519 signing is deterministic, so every byte is reproducible.

Run: ``python3 generate_receipts.py`` (needs ``cbor2`` and ``cryptography``)
to rewrite the file, or ``python3 generate_receipts.py --check`` to fail if it
is out of date.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import sys

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "receipt-vectors.json"
# A fixture seed, not a credential.
AUTHORITY_SEED = bytes([0x0B]) * 32
OTHER_SEED = bytes([0x0C]) * 32


def _head(major: int, value: int, width: int | None = None) -> bytes:
    """A CBOR head; ``width`` forces a non-shortest argument."""
    if width is None:
        if value < 24:
            return bytes([major << 5 | value])
        width = 1 if value < 1 << 8 else 2 if value < 1 << 16 else 4 if value < 1 << 32 else 8
    add = {1: 24, 2: 25, 4: 26, 8: 27}[width]
    return bytes([major << 5 | add]) + value.to_bytes(width, "big")


def _int(value: int, width: int | None = None) -> bytes:
    return _head(0, value, width) if value >= 0 else _head(1, -1 - value, width)


def _bstr(value: bytes) -> bytes:
    return _head(2, len(value)) + value


def _array(*items: bytes) -> bytes:
    return _head(4, len(items)) + b"".join(items)


def _map(*pairs: tuple[bytes, bytes]) -> bytes:
    return _head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def _leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _sign(seed: bytes, protected: bytes, root: bytes) -> bytes:
    to_be_signed = _array(cbor2.dumps("Signature1"), _bstr(protected), _bstr(b""), _bstr(root))
    return Ed25519PrivateKey.from_private_bytes(seed).sign(to_be_signed)


def _public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


ALG_EDDSA = (_int(1), _int(-8))
VDS_1 = (_int(395), _int(1))


def _protected(*pairs: tuple[bytes, bytes]) -> bytes:
    return _map(*(pairs or (ALG_EDDSA, VDS_1)))


def _proof(size: int, index: int, path: list[bytes]) -> bytes:
    return _array(_int(size), _int(index), _array(*(_bstr(node) for node in path)))


def _unprotected(*proofs: bytes) -> bytes:
    return _map((_int(396), _map((_int(-1), _array(*(_bstr(p) for p in proofs))))))


def _receipt(protected: bytes, unprotected: bytes, payload: bytes, signature: bytes, tag: bytes = b"\xd2") -> bytes:
    return tag + _array(_bstr(protected), unprotected, payload, _bstr(signature))


NULL = b"\xf6"


def _cases(entry: bytes) -> list[dict]:
    leaf = _leaf_hash(entry)
    # The entry is leaf 2 of a 3-leaf RFC 9162 tree: root = H(H(l0, l1), leaf).
    left = _node(_leaf_hash(b"left-0"), _leaf_hash(b"left-1"))
    root3 = _node(left, leaf)
    proof1 = _proof(1, 0, [])
    proof3 = _proof(3, 2, [left])
    wrong3 = _proof(3, 2, [bytes(32)])
    std = _protected()

    def signed(protected: bytes = std, root: bytes = leaf, seed: bytes = AUTHORITY_SEED) -> bytes:
        return _sign(seed, protected, root)

    def receipt(protected: bytes = std, unprotected: bytes | None = None, payload: bytes = NULL, root: bytes = leaf, **kw) -> bytes:
        unprotected = _unprotected(proof1) if unprotected is None else unprotected
        return _receipt(protected, unprotected, payload, signed(protected, root, **kw))

    cases: list[tuple[str, bool, int, int, str, bytes]] = []

    def case(name: str, accept: bool, why: str, raw: bytes, size: int = 1, index: int = 0) -> None:
        cases.append((name, accept, size, index, why, raw))

    case("pos-single-proof", True, "a detached payload and one proof whose rebuilt root the signature covers", receipt())
    case("pos-three-leaf-tree", True, "leaf 2 of a 3-leaf tree with a one-node audit path",
         receipt(unprotected=_unprotected(proof3), root=root3), 3, 2)
    case("pos-two-proofs-first-verifies", True, "several proofs are allowed when every one decodes and one verifies",
         receipt(unprotected=_unprotected(proof1, proof1)))
    case("pos-two-proofs-second-verifies", True, "the proof that verifies need not be the first",
         receipt(unprotected=_unprotected(wrong3, proof3), root=root3), 3, 2)
    case("pos-crit-understood", True, "crit may list vds, a label the verifier processes",
         receipt(protected=_protected(ALG_EDDSA, (_int(2), _array(_int(395))), VDS_1)))
    case("pos-cwt-claims", True, "a protected CWT claims map (label 15) with iat",
         receipt(protected=_protected(ALG_EDDSA, (_int(15), _map((_int(6), _int(1767225600)))), VDS_1)))
    case("pos-protected-key-order", True, "protected map keys out of canonical order are still shortest-form CBOR",
         receipt(protected=_protected(VDS_1, ALG_EDDSA)))
    case("pos-unknown-unprotected-label", True, "an unprotected label the verifier does not process is ignored",
         receipt(unprotected=_map((_int(396), _map((_int(-1), _array(_bstr(proof1))))), (_int(77), _bstr(b"x")))))
    def extra(value: bytes) -> bytes:
        return _map((_int(396), _map((_int(-1), _array(_bstr(proof1))))), (_int(77), value))

    # The receipt encoding rule (profile v1 section 6.2.2, as
    # agent-action-capsule#523 applies it to every COSE Receipt) covers the
    # whole message, each inclusion-proof blob included: no tag but the outer
    # 18, no float, no bignum, no simple value but false, true and null,
    # definite lengths, shortest arguments, integer or text keys, at most 16
    # levels. Label 77 sits three levels deep (tag, array, map).
    case("neg-unprotected-tagged-value", False, "a tagged value, even under an unprotected label the verifier ignores",
         receipt(unprotected=extra(_head(6, 1000) + _int(0))))
    case("neg-unprotected-half-float", False, "a float, even in its shortest (half-precision) form",
         receipt(unprotected=extra(b"\xf9\x3c\x00")))
    case("neg-proof-non-shortest-integer", False, "the inclusion-proof blob is decoded under the same rule as the message",
         receipt(unprotected=_unprotected(_array(_int(1, 2), _int(0), _array()))))
    case("neg-proof-bignum-tree-size", False, "a proof's tree_size is an unsigned integer, not a bignum (tag 2)",
         receipt(unprotected=_unprotected(_array(b"\xc2" + _bstr(b"\x01"), _int(0), _array()))))
    case("neg-proof-indefinite-path", False, "an indefinite-length audit path inside the proof blob",
         receipt(unprotected=_unprotected(_array(_int(3), _int(2), b"\x9f" + _bstr(left) + b"\xff")), root=root3), 3, 2)
    case("neg-proof-indefinite-blob", False, "a proof blob that is an indefinite-length array",
         receipt(unprotected=_unprotected(b"\x9f" + _int(1) + _int(0) + _array() + b"\xff")))

    def proof_with(size: bytes, index: bytes, path: bytes) -> bytes:
        return _unprotected(_array(size, index, path))

    case("neg-proof-self-described-blob", False, "the self-described CBOR tag (55799) around the proof blob",
         receipt(unprotected=_unprotected(_head(6, 55799) + proof1)))
    case("neg-proof-self-described-size", False, "the self-described tag around a proof's tree_size",
         receipt(unprotected=proof_with(_head(6, 55799) + _int(1), _int(0), _array())))
    case("neg-proof-self-described-node", False, "the self-described tag around an audit-path node",
         receipt(unprotected=proof_with(_int(3), _int(2), _array(_head(6, 55799) + _bstr(left))), root=root3), 3, 2)
    case("neg-unprotected-bignum", False, "a bignum, even one that needs more than 64 bits",
         receipt(unprotected=extra(b"\xc2" + _bstr(b"\x01" + bytes(8)))))
    case("neg-unprotected-integer-below-int64", False, "the integer -2^64, below -2^63",
         receipt(unprotected=extra(b"\x3b" + b"\xff" * 8)))
    case("neg-unprotected-undefined", False, "undefined, even under an ignored label", receipt(unprotected=extra(b"\xf7")))
    case("neg-unprotected-simple-value", False, "simple value 32", receipt(unprotected=extra(b"\xf8\x20")))
    case("neg-unprotected-simple-value-0", False, "the unassigned simple value 0", receipt(unprotected=extra(b"\xe0")))
    case("neg-unprotected-indefinite-array", False, "an indefinite-length array under an ignored label",
         receipt(unprotected=extra(b"\x9f\x01\xff")))
    case("neg-unprotected-array-key", False, "a map keyed by an array",
         receipt(unprotected=extra(_map((_array(_int(1)), _int(1))))))
    case("neg-unprotected-bytes-key", False, "a map keyed by a byte string",
         receipt(unprotected=extra(_map((_bstr(b"k"), _int(1))))))
    case("neg-unprotected-nan-keys", False, "a map keyed twice by NaN",
         receipt(unprotected=extra(_map((b"\xf9\x7e\x00", _int(1)), (b"\xf9\x7e\x00", _int(2))))))
    case("neg-unprotected-nested-repeated-key", False, "a map under an ignored label that repeats a key",
         receipt(unprotected=extra(_map((_int(1), _int(1)), (_int(1), _int(2))))))
    case("neg-unprotected-depth-17", False, "14 nested arrays under label 77, so an item 17 levels deep",
         receipt(unprotected=extra(b"\x81" * 14 + _int(0))))
    case("neg-unprotected-nested-29", False, "29 nested arrays under an ignored label",
         receipt(unprotected=extra(b"\x81" * 29 + b"\x80")))
    case("pos-unprotected-depth-16", True, "13 nested arrays under label 77, so an item 16 levels deep, the most allowed",
         receipt(unprotected=extra(b"\x81" * 13 + _int(0))))
    case("pos-unprotected-keys-out-of-order", True, "a map under an ignored label whose text keys are not in canonical order",
         receipt(unprotected=extra(_map((cbor2.dumps("b"), _int(1)), (cbor2.dumps("a"), _int(2))))))
    case("pos-unprotected-kid-integer", True, "an unprotected kid (4) that is an integer, a label the verifier does not read",
         receipt(unprotected=_map((_int(4), _int(1)), (_int(396), _map((_int(-1), _array(_bstr(proof1))))))))
    case("pos-protected-content-type", True, "a protected content type (3) \"abc\", a label the verifier does not read",
         receipt(protected=_protected(ALG_EDDSA, (_int(3), cbor2.dumps("abc")), VDS_1)))
    case("pos-crit-cwt-claims", True, "crit [15] with an empty protected CWT claims map, a label the verifier processes",
         receipt(protected=_protected(ALG_EDDSA, (_int(2), _array(_int(15))), (_int(15), _map()), VDS_1)))
    case("neg-protected-tag-unread-label", False, "an epoch time (tag 1) under protected label -65538, which no check reads",
         receipt(protected=_protected(ALG_EDDSA, VDS_1, (_int(-65538), b"\xc1" + _int(1)))))
    case("neg-protected-float-iat", False, "a protected CWT iat that is a float",
         receipt(protected=_protected(ALG_EDDSA, (_int(15), _map((_int(6), cbor2.dumps(1767225600.5)))), VDS_1)))
    case("neg-protected-float-claim-key", False, "protected CWT claims keyed by the float 6.0",
         receipt(protected=_protected(ALG_EDDSA, (_int(15), _map((b"\xf9\x46\x00", _int(1767225600)))), VDS_1)))
    case("neg-crit-not-an-array", False, "crit must be an array, not an integer",
         receipt(protected=_protected(ALG_EDDSA, (_int(2), _int(1)), VDS_1)))
    case("neg-crit-boolean", False, "crit [true] lists a label that is not an integer or text",
         receipt(protected=_protected(ALG_EDDSA, (_int(2), _array(b"\xf5")), VDS_1)))
    case("neg-crit-kid", False, "crit [4] over a protected kid, a label the verifier does not process",
         receipt(protected=_protected(ALG_EDDSA, (_int(2), _array(_int(4))), (_int(4), _bstr(b"k")), VDS_1)))

    case("neg-attached-payload-root", False, "an attached payload binds nothing, even when it is the rebuilt root",
         receipt(payload=_bstr(leaf)))
    case("neg-attached-payload-other", False, "an attached payload is refused whatever it holds",
         receipt(payload=_bstr(b"not the root")))
    case("neg-attached-payload-empty", False, "an empty byte string is an attached payload, not a detached one",
         receipt(payload=_bstr(b"")))
    case("neg-crit-unknown-label", False, "crit marks a header the verifier does not understand (RFC 9052 section 3.1)",
         receipt(protected=_protected(ALG_EDDSA, (_int(2), _array(_int(99))), VDS_1, (_int(99), _int(1)))))
    case("neg-crit-absent-label", False, "crit lists a header absent from the protected header",
         receipt(protected=_protected(ALG_EDDSA, (_int(2), _array(_int(77))), VDS_1)))
    case("neg-crit-empty", False, "crit must be a non-empty array",
         receipt(protected=_protected(ALG_EDDSA, (_int(2), _array()), VDS_1)))
    case("neg-protected-non-shortest", False, "a protected header argument that is not in its shortest form",
         receipt(protected=_map(ALG_EDDSA, (_int(395, 4), _int(1)))))
    case("neg-protected-duplicate-key", False, "a protected header that repeats a label",
         receipt(protected=_map(ALG_EDDSA, VDS_1, ALG_EDDSA)))
    case("neg-protected-indefinite-map", False, "an indefinite-length protected header",
         receipt(protected=b"\xbf" + b"".join(k + v for k, v in (ALG_EDDSA, VDS_1)) + b"\xff"))
    case("neg-alg-es256-under-ed25519-key", False, "the alg fixes the key type: ES256 never verifies under an Ed25519 key",
         receipt(protected=_protected((_int(1), _int(-7)), VDS_1)))
    case("neg-alg-text", False, "alg must be an integer", receipt(protected=_protected((_int(1), cbor2.dumps("EdDSA")), VDS_1)))
    case("neg-vds-2", False, "only vds 1 (RFC9162_SHA256)", receipt(protected=_protected(ALG_EDDSA, (_int(395), _int(2)))))
    case("neg-vds-true", False, "vds must be the integer 1, not true",
         receipt(protected=_protected(ALG_EDDSA, (_int(395), b"\xf5"))))
    case("neg-vds-text", False, "vds must be an integer", receipt(protected=_protected(ALG_EDDSA, (_int(395), cbor2.dumps("1")))))

    good = receipt()
    case("neg-untagged", False, "a receipt is a tag-18 COSE_Sign1", good[1:])
    case("neg-wrong-tag", False, "tag 17 (COSE_Mac0) is not a COSE_Sign1", b"\xd1" + good[1:])
    case("neg-trailing-byte", False, "bytes after the COSE_Sign1 message", good + b"\x00")
    case("neg-envelope-non-shortest-length", False, "the COSE_Sign1 array length is not in its shortest form",
         b"\xd2\x98\x04" + good[2:])
    case("neg-envelope-indefinite-array", False, "an indefinite-length COSE_Sign1 array", b"\xd2\x9f" + good[2:] + b"\xff")
    case("neg-unprotected-duplicate-key", False, "an unprotected header that repeats a label",
         _receipt(std, _map((_int(396), _map((_int(-1), _array(_bstr(proof1))))), (_int(396), _map())), NULL, signed()))
    case("neg-unprotected-non-shortest", False, "the whole message is decoded strictly, the unprotected header included",
         _receipt(std, _map((_int(396, 4), _map((_int(-1), _array(_bstr(proof1)))))), NULL, signed()))

    case("neg-unprotected-non-shortest-float", False, "1.0 as a double is not its shortest form, even under an ignored label",
         receipt(unprotected=extra(b"\xfb\x3f\xf0" + bytes(6))))
    case("neg-payload-undefined", False, "a detached payload is CBOR null; undefined is not null",
         receipt(payload=b"\xf7"))
    case("neg-unprotected-epoch-time", False, "an epoch time (tag 1) does not survive the strict decoders' re-encoding",
         receipt(unprotected=extra(b"\xc1" + _int(0))))
    case("neg-unprotected-small-bignum", False, "a bignum that fits in 64 bits is not its shortest form",
         receipt(unprotected=extra(b"\xc2" + _bstr(b"\x01"))))
    case("neg-unprotected-bignum-leading-zero", False, "nor is one with a leading zero byte",
         receipt(unprotected=extra(b"\xc2" + _bstr(b"\x00\x01"))))
    case("neg-unprotected-negative-bignum", False, "the same holds for a negative bignum (tag 3)",
         receipt(unprotected=extra(b"\xc3" + _bstr(b"\x00"))))
    case("neg-unprotected-self-described", False, "the self-described tag (55799) inside the strictly decoded message",
         receipt(unprotected=extra(_head(6, 55799) + _int(0))))
    case("neg-envelope-self-described", False, "the self-described tag around the COSE_Sign1", _head(6, 55799) + good)
    case("neg-protected-self-described", False, "the self-described tag inside the protected header",
         receipt(protected=_protected(ALG_EDDSA, (_int(15), _head(6, 55799) + _map((_int(6), _int(5)))), VDS_1)))
    case("neg-protected-epoch-time-iat", False, "an iat written as an epoch time (tag 1)",
         receipt(protected=_protected(ALG_EDDSA, (_int(15), _map((_int(6), b"\xc1" + _int(5)))), VDS_1)))
    case("neg-no-vdp", False, "no vdp (label 396) in the unprotected header", receipt(unprotected=_map()))
    case("neg-no-proofs", False, "the vdp proof array is empty", receipt(unprotected=_map((_int(396), _map((_int(-1), _array()))))))
    case("neg-proof-not-bytes", False, "an inclusion proof that is not a byte string",
         receipt(unprotected=_map((_int(396), _map((_int(-1), _array(proof1)))))))
    case("neg-second-proof-malformed", False, "every proof must decode, even after one that verifies",
         receipt(unprotected=_unprotected(proof1, b"\xff")))
    case("neg-second-proof-wrong-path-length", False,
         "a later proof that decodes but cannot fit its tree refuses the receipt, even after one that verifies",
         receipt(unprotected=_unprotected(proof1, _proof(4, 1, [left]))))
    case("neg-second-proof-index-out-of-range", False, "the same for a later proof whose leaf_index is not below tree_size",
         receipt(unprotected=_unprotected(proof1, _proof(1, 1, []))))
    case("neg-proof-float-tree-size", False, "tree_size must be an integer, not the float 1.0",
         receipt(unprotected=_unprotected(_array(b"\xf9\x3c\x00", _int(0), _array()))))
    case("neg-proof-null-index", False, "leaf_index null", receipt(unprotected=proof_with(_int(1), NULL, _array())))
    case("neg-proof-undefined-index", False, "leaf_index undefined", receipt(unprotected=proof_with(_int(1), b"\xf7", _array())))
    case("neg-proof-simple-index", False, "leaf_index simple value 0", receipt(unprotected=proof_with(_int(1), b"\xe0", _array())))
    case("neg-proof-null-path", False, "audit path null", receipt(unprotected=proof_with(_int(1), _int(0), NULL)))
    case("neg-proof-tagged-size", False, "tree_size under an unregistered tag",
         receipt(unprotected=proof_with(_head(6, 1000) + _int(1), _int(0), _array())))
    case("neg-proof-epoch-time-size", False, "tree_size as an epoch time (tag 1)",
         receipt(unprotected=proof_with(b"\xc1" + _int(1), _int(0), _array())))
    case("neg-proof-bignum-node", False, "an audit-path node must be a byte string, not a bignum",
         receipt(unprotected=proof_with(_int(3), _int(2), _array(b"\xc2" + _bstr(left))), root=root3), 3, 2)
    case("neg-too-many-proofs", False, "at most 16 inclusion proofs", receipt(unprotected=_unprotected(*([proof1] * 17))))
    case("neg-proof-path-length", False, "an audit path longer than the tree needs",
         receipt(unprotected=_unprotected(_proof(1, 0, [left]))))
    case("neg-proof-index-out-of-range", False, "leaf_index must be below tree_size",
         receipt(unprotected=_unprotected(_proof(1, 1, []))), 1, 1)
    case("neg-wrong-key", False, "signed by a key other than the pinned one", receipt(seed=OTHER_SEED))
    case("neg-other-entry", False, "a signature over another entry's root", receipt(root=_leaf_hash(b"another entry")))

    return [
        {"name": name, "accept": accept, "tree_size": size, "leaf_index": index, "why": why,
         "receipt_b64": base64.b64encode(raw).decode()}
        for name, accept, size, index, why, raw in cases
    ]


def build() -> dict:
    name = "checkpoint-first-2-leaves"
    cose = json.loads((HERE / "cose-vectors.json").read_text())
    statement = bytes.fromhex(next(c for c in cose["cases"] if c["name"] == name)["cose_hex"])
    # The checkpoint-digest entry hash: SHA-256 of the checkpoint digest's bytes.
    record = json.loads((HERE / "vectors.json").read_text())
    entry = hashlib.sha256(bytes.fromhex(next(c for c in record["cases"] if c["name"] == name)["digest_hex"])).digest()
    return {
        "format_version": 1,
        "note": (
            "Witness receipts over one checkpoint statement. A receipt verifier pinned to authority_public_key_hex, "
            "given checkpoint_cose_b64 and a receipt with entry_hash_hex, tree_size and leaf_index, accepts exactly "
            "the cases whose accept is true, as agent-action-capsule's VerifyCOSEReceipt does under the receipt "
            "encoding rule of its interop profile v1 section 6.2.2 (agent-action-capsule#523). "
            "Generated by generate_receipts.py."
        ),
        "checkpoint_cose_b64": base64.b64encode(statement).decode(),
        "entry_hash_hex": entry.hex(),
        "authority_public_key_hex": _public(AUTHORITY_SEED).hex(),
        "cases": _cases(entry),
    }


def main() -> int:
    text = json.dumps(build(), indent=2) + "\n"
    if "--check" in sys.argv[1:]:
        if OUT.read_text() != text:
            print(f"{OUT.name} is out of date; run generate_receipts.py", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
