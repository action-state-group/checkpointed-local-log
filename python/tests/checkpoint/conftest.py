# SPDX-License-Identifier: Apache-2.0
"""A minimal, dependency-free ``LogSource`` fake for testing ``MmrLedger``.

``cll`` carries no dependency on any particular log binding (that would
defeat the point of the package -- see the ``checkpoint`` package
docstring). This fake satisfies the same structural shape
(``append``/``scan``/``fetch``/``find_gaps``/``verify``, records exposing
``.seq``/``.capsule_id``) so ``MmrLedger`` is exercised exactly as it will be
by any real log binding, ``cll.ledger``'s included.

Also provides ``Ed25519TestSigner`` -- a minimal, self-contained COSE signer
for the checkpoint-wire tests. Deliberately independent of
``capsule_emit.signing.LocalKeypairSigner`` (that would be a cll -> a
downstream-consumer dependency, the wrong direction): same
``sign_cose_statement`` shape (``cll.checkpoint.cose_wire``'s only
requirement of a signer), backed by an in-memory Ed25519 key and
``scitt_cose.statement.build_signed_statement`` directly -- the same
primitive ``LocalKeypairSigner`` itself calls.
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat


@dataclass
class FakeRecord:
    seq: int
    capsule_id: str
    capsule: dict


@dataclass
class FakeLogSource:
    """In-memory, gapless-seq log satisfying the ``LogSource`` shape."""

    records: list[FakeRecord] = field(default_factory=list)

    def append(self, capsule: dict, *, consequential: bool = True) -> FakeRecord:
        seq = len(self.records) + 1
        capsule_id = capsule.get("capsule_id") or hashlib.sha256(
            json.dumps(capsule, sort_keys=True, default=str).encode()
        ).hexdigest()
        rec = FakeRecord(seq=seq, capsule_id=capsule_id, capsule=dict(capsule))
        self.records.append(rec)
        return rec

    def scan(self, query=None):
        return iter(self.records)

    def fetch(self, capsule_id: str) -> FakeRecord | None:
        for r in self.records:
            if r.capsule_id == capsule_id:
                return r
        return None

    def verify(self, capsule_id: str) -> None:
        return None

    def find_gaps(self) -> list:
        return []


def synthetic_capsule(i: int) -> dict:
    return {
        "operator": "acme",
        "developer": "agent-x",
        "action_type": "decide",
        "timestamp": f"2026-01-01T00:00:{i:02d}Z",
        "disposition": {"verdict_class": "executed"},
        "seq_marker": i,
    }


@pytest.fixture
def log_source() -> FakeLogSource:
    return FakeLogSource()


class Ed25519TestSigner:
    """Minimal in-memory Ed25519 signer implementing just ``key_id`` +
    ``sign_cose_statement`` -- everything ``cll.checkpoint.cose_wire.
    checkpoint_to_cose`` needs from a signer, and nothing else."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._private_key = Ed25519PrivateKey.generate()
        raw = self._private_key.public_key().public_bytes_raw()
        self.key_id = raw.hex()

    def sign_cose_statement(
        self,
        payload: bytes,
        *,
        content_type: str,
        issuer: str,
        subject: str,
        extra_cwt_claims: dict | None = None,
    ) -> bytes:
        from scitt_cose.statement import build_signed_statement

        with self._lock:
            key = self._private_key
            key_id = self.key_id
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        return build_signed_statement(
            payload,
            alg="EdDSA",
            private_key_pem=pem,
            issuer=issuer,
            subject=subject,
            content_type=content_type,
            extra_cwt_claims=extra_cwt_claims,
            kid=bytes.fromhex(key_id),
        )


@pytest.fixture
def cose_signer() -> Ed25519TestSigner:
    return Ed25519TestSigner()
