# SPDX-License-Identifier: Apache-2.0
"""A minimal signing-key abstraction for local, application-attested records.

**Ported from ``capsule-ledger``'s ``guards/signing.py`` per the W3
CLL-revocation reconciliation (2026-09-02).** Content-neutral: nothing here
names a product, a company, or a capsule format. It exists to give
:mod:`cll.revocation`'s time-fenced key-revocation check a real,
checkable notion of "which key signed this" without pulling in a
cryptography dependency this module doesn't itself need -- a local
HMAC-SHA256 "signature" is enough to make key material a real precondition
and the signature field tamper-evident once committed into a capsule's
``capsule_id``.

This is deliberately NOT the producer-envelope signer :mod:`cll.ledger`'s
admission contract verifies (a COSE_Sign1 envelope over the raw
``capsule_id`` digest, see ``tests/ledger/conftest.py``'s
``Ed25519EnvelopeSigner``) -- that proves who produced a *specific* capsule.
This signer is for an application-level, application-namespaced signature
extension a caller layers onto a capsule's payload (e.g. a
``key_rotation`` event), independent of and orthogonal to the admission
contract's own envelope.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = ["LocalSigner", "Signer", "SigningKeyUnavailable", "key_fingerprint"]


class SigningKeyUnavailable(Exception):
    """No signing key is available right now.

    Raised by whatever supplies a ``Signer`` to a caller (e.g. a key
    provider callable) -- never by ``Signer.sign()`` itself. A caller that
    cannot produce a ``Signer`` must not attempt to build a capsule at all;
    that fail-closed gate lives one layer up, in the caller.
    """


@runtime_checkable
class Signer(Protocol):
    key_id: str
    algorithm: str

    def sign(self, digest: str) -> str: ...


@dataclass(frozen=True)
class LocalSigner:
    """An in-process HMAC-SHA256 signer over a node-local secret."""

    key_id: str
    secret: bytes
    algorithm: str = "hmac-sha256"

    def sign(self, digest: str) -> str:
        return hmac.new(self.secret, digest.encode("ascii"), hashlib.sha256).hexdigest()


def key_fingerprint(key_id: str, secret: bytes) -> str:
    """A stable, secret-revealing-nothing identifier for one key's material.

    Binds ``key_id`` into the hash (not just ``secret``) so a fresh key that
    happens to reuse another key's secret bytes still fingerprints
    differently -- a rotation event records this, never the raw secret.
    """
    return hashlib.sha256(key_id.encode("utf-8") + b":" + secret).hexdigest()
