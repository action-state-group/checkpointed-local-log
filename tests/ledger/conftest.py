# SPDX-License-Identifier: Apache-2.0
"""Minimal, self-contained producer-envelope signing for ``cll.ledger``'s
admission-contract tests.

Deliberately independent of ``capsule_emit.signing`` (that would be a
cll -> downstream-consumer dependency, the wrong direction). Implements just
the frozen AAC producer-envelope profile -- a COSE_Sign1 over the raw
32-byte ``capsule_id`` digest -- using ``agent_action_capsule`` and
``scitt_cose`` directly, the same primitives
``capsule_emit.signing.LocalKeypairSigner.sign_envelope`` itself calls.
"""
from __future__ import annotations

import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from cll.ledger import LedgerStore


@pytest.fixture
def store(tmp_path):
    s = LedgerStore(tmp_path)
    yield s
    s.close()


class Ed25519EnvelopeSigner:
    """In-memory Ed25519 signer producing frozen AAC producer envelopes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._private_key = Ed25519PrivateKey.generate()
        self.key_id = self._private_key.public_key().public_bytes_raw().hex()

    def sign_envelope(self, payload: bytes) -> tuple[str, str]:
        from agent_action_capsule.media_types import CAPSULE_ID_MEDIA_TYPE
        from scitt_cose.cose_sign1 import sign_sign1

        with self._lock:
            key = self._private_key
            key_id = self.key_id
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        protected = {3: CAPSULE_ID_MEDIA_TYPE, 4: bytes.fromhex(key_id)}
        envelope = sign_sign1(payload, alg="EdDSA", private_key_pem=pem, protected=protected, unprotected={})
        return envelope.hex(), key_id


def sign_producer_envelope(signer: Ed25519EnvelopeSigner, capsule_id: str) -> tuple[str, str]:
    """Sign ``capsule_id`` (lowercase hex) and return ``(envelope_hex, key_id)``
    -- the frozen AAC producer-envelope profile."""
    return signer.sign_envelope(bytes.fromhex(capsule_id))


@pytest.fixture
def envelope_signer() -> Ed25519EnvelopeSigner:
    return Ed25519EnvelopeSigner()
