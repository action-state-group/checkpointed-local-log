# SPDX-License-Identifier: Apache-2.0
"""``checkpoint-conformance-vectors/ed25519-vectors.json``, shared by every
implementation, through ``cll.ed25519`` and each verifier that uses it: the
checkpoint statement, the JSON checkpoint record, and the receipt paths.

OpenSSL accepts the small-order cases on some builds (the one in the
``cryptography`` wheel among them), so each forgery here is refused only by
the checks in ``cll.ed25519``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from cll.checkpoint.cose_wire import verify_checkpoint_cose_offline
from cll.checkpoint.emit import (
    CheckpointRecord,
    StampVerdict,
    WitnessRecord,
    verify_checkpoint_signature_offline,
    verify_receipt_offline,
    verify_witness_stamp_tristate,
)
from cll.checkpoint.witness import ReceiptVerifier, RejectedError, WitnessReceipt
from cll.ed25519 import acceptable_signature, verify
from cll.ledger.checkpoint import verify_receipt_offline as ledger_verify_receipt_offline

VECTORS_DIR = pathlib.Path(__file__).resolve().parents[3] / "checkpoint-conformance-vectors"
VECTORS = json.loads((VECTORS_DIR / "ed25519-vectors.json").read_text())
IDENTITY = bytes([1]) + bytes(31)


def _identity_forgery() -> bytes:
    """R = rB, S = r: under the identity key, [k]A is the identity for every
    challenge k, so this signs any message without a private key."""
    case = next(c for c in VECTORS["ed25519_cases"] if c["name"] == "small-order A identity")
    return bytes.fromhex(case["signature_hex"])


@pytest.mark.parametrize("case", VECTORS["ed25519_cases"], ids=lambda c: c["name"])
def test_verify_decides_every_raw_case(case):
    public_key = bytes.fromhex(case["public_key_hex"])
    signature = bytes.fromhex(case["signature_hex"])
    assert verify(public_key, bytes.fromhex(case["message_hex"]), signature) is case["valid"]


@pytest.mark.parametrize("case", VECTORS["cose_cases"], ids=lambda c: c["name"])
def test_checkpoint_statement_verifier_decides_every_case(case):
    result = verify_checkpoint_cose_offline(bytes.fromhex(case["cose_hex"]))
    assert result.ok is case["valid"], result.errors


def test_acceptable_signature_refuses_wrong_types_and_lengths():
    honest = VECTORS["ed25519_cases"][0]
    assert honest["name"] == "honest"
    public_key, signature = bytes.fromhex(honest["public_key_hex"]), bytes.fromhex(honest["signature_hex"])
    assert acceptable_signature(public_key, signature)
    assert not acceptable_signature(public_key[1:], signature)
    assert not acceptable_signature(public_key, signature[1:])
    assert not acceptable_signature(public_key, None)
    assert not verify(public_key[1:], bytes.fromhex(honest["message_hex"]), signature)


def test_checkpoint_record_forged_for_identity_key_is_refused():
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id="forged-log", mmr_size=1, root="42" * 32,
        prev_size=0, prev_root="", key_id=IDENTITY.hex(), timestamp="2026-10-27T00:00:00Z",
        signature=_identity_forgery().hex(),
    )
    assert not verify_checkpoint_signature_offline(cp)


def test_checkpoint_record_signed_honestly_still_verifies():
    key = Ed25519PrivateKey.generate()
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id="honest-log", mmr_size=1, root="42" * 32,
        prev_size=0, prev_root="",
        key_id=key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        timestamp="2026-10-27T00:00:00Z", signature="",
    )
    cp.signature = key.sign(cp.digest().encode("ascii")).hex()
    assert verify_checkpoint_signature_offline(cp)


def _forged_receipt(entry: str) -> bytes:
    """A well-formed receipt for ``entry`` whose signature is the identity
    key forgery."""
    from scitt_cose import build_receipt

    pem = Ed25519PrivateKey.generate().private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    receipt = build_receipt(
        leaf_entry_hex=entry, leaf_index=0, tree_entries_hex=[entry], alg="EdDSA", log_private_key_pem=pem
    )
    tag = cbor2.loads(receipt)
    return cbor2.dumps(cbor2.CBORTag(tag.tag, [*tag.value[:3], _identity_forgery()]))


def test_receipts_forged_for_identity_key_are_refused_on_every_path():
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id="log", mmr_size=1, root="42" * 32, prev_size=0,
        prev_root="", key_id="00" * 32, timestamp="2026-10-27T00:00:00Z", signature="",
    )
    entry = hashlib.sha256(bytes.fromhex(cp.digest())).hexdigest()
    forged = _forged_receipt(entry)
    identity_pem = Ed25519PublicKey.from_public_bytes(IDENTITY).public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    witness = WitnessRecord(
        ts_url="https://witness.example", entry_hash=entry,
        receipt_b64=base64.b64encode(forged).decode(), leaf_index=0, tree_size=1,
    )

    ok, errors = verify_receipt_offline(witness, ts_pubkey_pem=identity_pem)
    assert not ok and any("small order" in e for e in errors)
    ok, _ = ledger_verify_receipt_offline(witness, ts_pubkey_pem=identity_pem)
    assert not ok
    verdict, _ = verify_witness_stamp_tristate(cp, witness, ts_pubkey_pem=identity_pem)
    assert verdict is StampVerdict.INVALID


def test_receipt_verifier_refuses_forgery_for_identity_pinned_key():
    statement = bytes.fromhex(VECTORS["cose_cases"][0]["cose_hex"])
    decoded = verify_checkpoint_cose_offline(statement).decoded
    entry = hashlib.sha256(bytes.fromhex(decoded.to_checkpoint_record().digest())).hexdigest()
    receipt = WitnessReceipt(_forged_receipt(entry), entry, "legacy", 0, 1)
    with pytest.raises(RejectedError):
        ReceiptVerifier(IDENTITY).verify(statement, receipt)


def test_honest_receipt_still_verifies():
    entry = "ab" * 32
    key = Ed25519PrivateKey.generate()
    from scitt_cose import build_receipt

    receipt = build_receipt(
        leaf_entry_hex=entry, leaf_index=0, tree_entries_hex=[entry], alg="EdDSA",
        log_private_key_pem=key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
    )
    witness = WitnessRecord(
        ts_url="https://witness.example", entry_hash=entry,
        receipt_b64=base64.b64encode(receipt).decode(), leaf_index=0, tree_size=1,
    )
    pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    assert verify_receipt_offline(witness, ts_pubkey_pem=pem) == (True, [])


def test_receipt_under_a_non_ed25519_key_is_left_to_scitt_cose():
    """An ES384 receipt (a CCF log's key type) passes through unchanged:
    honest verifies, under another key it does not."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from scitt_cose import build_receipt

    from cll.ed25519 import verify_receipt

    entry = "ab" * 32
    key = ec.generate_private_key(ec.SECP384R1())
    receipt = build_receipt(
        leaf_entry_hex=entry, leaf_index=0, tree_entries_hex=[entry], alg="ES384",
        log_private_key_pem=key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
    )
    pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    other = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    assert verify_receipt(receipt, leaf_entry_hex=entry, log_public_key_pem=pem).ok
    assert not verify_receipt(receipt, leaf_entry_hex=entry, log_public_key_pem=other).ok
    witness = WitnessRecord(
        ts_url="https://witness.example", entry_hash=entry,
        receipt_b64=base64.b64encode(receipt).decode(), leaf_index=0, tree_size=1,
    )
    assert verify_receipt_offline(witness, ts_pubkey_pem=pem) == (True, [])
    assert ledger_verify_receipt_offline(witness, ts_pubkey_pem=pem)[0]


def test_receipt_is_refused_when_the_key_cannot_be_read(monkeypatch):
    """If scitt-cose accepted but the key cannot be read back, fail closed."""
    import cll.ed25519 as strict

    entry = "ab" * 32
    key = Ed25519PrivateKey.generate()
    from scitt_cose import build_receipt

    receipt = build_receipt(
        leaf_entry_hex=entry, leaf_index=0, tree_entries_hex=[entry], alg="EdDSA",
        log_private_key_pem=key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
    )
    pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    assert strict.verify_receipt(receipt, leaf_entry_hex=entry, log_public_key_pem=pem).ok

    def unreadable(_pem):
        raise ValueError("unreadable key")

    monkeypatch.setattr(strict, "_raw_ed25519_key", unreadable)
    result = strict.verify_receipt(receipt, leaf_entry_hex=entry, log_public_key_pem=pem)
    assert not result.ok and result.failed_at == "signature"
