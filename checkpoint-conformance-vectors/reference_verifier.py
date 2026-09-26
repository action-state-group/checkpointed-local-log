# SPDX-License-Identifier: Apache-2.0
"""Standalone reference verifier for vectors.json.

Regenerates every case's `signing_body`/`digest`/`entry_digest`/`signature`
from scratch using `cll.checkpoint.emit.CheckpointRecord` and the pinned
Ed25519 fixture seed, and demands byte-identical output against the pinned
values -- the same "regenerate and verify" convention as
`mmr-conformance-vectors/reference_verifier.py`. A non-Python implementation
(this crate's `rust/cll`, or any future port) reproduces the SAME pinned
values from nothing but this file's field list and RFC 8032 Ed25519 --
Ed25519 signing is fully deterministic, so `signature_hex` is not just a
self-consistency check, it is a genuine cross-language pin.

Also checks the witness-receipt boundary (`checkpoint produced by any CLL
implementation verifies with scitt-cose unchanged`): `scitt_cose.receipt
.build_receipt`/`verify_receipt` never import or special-case `cll` -- a
witness mints a receipt over whatever hex digest string it is handed via
`POST /v1/digest`, regardless of which language computed it. Since this
file's cross-language pin already proves `digest_hex` is byte-identical
between the Python and Rust checkpoint implementations, round-tripping that
SAME digest through scitt-cose's real (non-cll) receipt build/verify path
demonstrates a Rust-anchored checkpoint's digest receipts exactly as a
Python-anchored one would, with no scitt-cose change required.

Run: ``python3 reference_verifier.py``.
"""
from __future__ import annotations

import json
import pathlib
import sys
from typing import TypedDict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cll.checkpoint.emit import CheckpointRecord, verify_checkpoint_signature_offline


class CheckpointCase(TypedDict):
    name: str
    v: int
    kind: str
    log_id: str
    mmr_size: int
    root: str
    prev_size: int
    prev_root: str
    key_id: str
    timestamp: str
    signature: str
    digest_hex: str
    entry_digest_hex: str


class VectorsDoc(TypedDict):
    signing_key_seed_hex: str
    key_id: str
    count: int
    cases: list[CheckpointCase]


def check_checkpoint_vectors(doc: VectorsDoc, sk: Ed25519PrivateKey, failures: list[str]) -> None:
    pub_raw = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if pub_raw.hex() != doc["key_id"]:
        failures.append(f"key_id mismatch: derived {pub_raw.hex()} != pinned {doc['key_id']}")

    for case in doc["cases"]:
        name = case["name"]
        cp = CheckpointRecord(
            v=case["v"],
            kind=case["kind"],
            log_id=case["log_id"],
            mmr_size=case["mmr_size"],
            root=case["root"],
            prev_size=case["prev_size"],
            prev_root=case["prev_root"],
            key_id=case["key_id"],
            timestamp=case["timestamp"],
            signature="",
        )

        digest = cp.digest()
        if digest != case["digest_hex"]:
            failures.append(f"{name}: digest mismatch: {digest} != {case['digest_hex']}")

        signature = sk.sign(digest.encode("ascii")).hex()
        if signature != case["signature"]:
            failures.append(f"{name}: signature mismatch: {signature} != {case['signature']}")

        cp.signature = case["signature"]
        if not verify_checkpoint_signature_offline(cp):
            failures.append(f"{name}: verify_checkpoint_signature_offline rejected the pinned signature")

        entry_digest = cp.entry_digest()
        if entry_digest != case["entry_digest_hex"]:
            failures.append(f"{name}: entry_digest mismatch: {entry_digest} != {case['entry_digest_hex']}")


def check_scitt_cose_receipt_interop(doc: VectorsDoc, failures: list[str]) -> None:
    """Every case's `digest_hex` receipts cleanly through scitt-cose's own
    (cll-agnostic) RFC 9162 receipt build/verify path -- see module
    docstring for why this establishes the witness-receipt boundary."""
    from cryptography.hazmat.primitives.asymmetric import ed25519 as cose_ed25519

    from scitt_cose.receipt import build_receipt, verify_receipt

    log_key = cose_ed25519.Ed25519PrivateKey.generate()
    log_priv_pem = log_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    log_pub_pem = log_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    digests = [case["digest_hex"] for case in doc["cases"]]
    for i, (case, digest) in enumerate(zip(doc["cases"], digests)):
        name = case["name"]
        receipt = build_receipt(
            leaf_entry_hex=digest,
            leaf_index=i,
            tree_entries_hex=digests,
            alg="EdDSA",
            log_private_key_pem=log_priv_pem,
        )
        result = verify_receipt(receipt, leaf_entry_hex=digest, log_public_key_pem=log_pub_pem)
        if not result.ok:
            failures.append(f"{name}: scitt-cose receipt round-trip failed: {result.errors}")


def main() -> int:
    doc: VectorsDoc = json.loads((pathlib.Path(__file__).parent / "vectors.json").read_text())
    seed = bytes.fromhex(doc["signing_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)

    failures: list[str] = []
    check_checkpoint_vectors(doc, sk, failures)
    check_scitt_cose_receipt_interop(doc, failures)

    if failures:
        print(f"FAIL ({len(failures)} issue(s)):")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(
        f"OK: all {len(doc['cases'])} checkpoint conformance cases verified "
        "(digest/signature parity + scitt-cose receipt interop)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
