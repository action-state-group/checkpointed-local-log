# SPDX-License-Identifier: Apache-2.0
"""Ed25519 checks for checkpoints and receipts, the same in every CLL
implementation (``checkpoint-conformance-vectors/ed25519-vectors.json``).

OpenSSL, which ``cryptography`` and ``scitt_cose`` verify with, accepts a
signature by a small-order public key on some builds, including the OpenSSL 4.0.3
in the ``cryptography`` 50.0.2 wheel for macOS. Anyone can make such a signature without a
private key: when ``[k]A`` is the identity, ``R = rB`` and ``S = r`` satisfy
``[S]B = R + [k]A``. It also accepts an identity ``R``.

So before OpenSSL checks the cofactorless equation (comparing ``R``'s bytes,
which also refuses a mixed-order ``R``), these refuse ``A`` or ``R`` whose
``y`` is not below ``p`` or is one of the five small-order ``y`` values, and
``S >= L``.
"""
from __future__ import annotations

from typing import Any

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_ORDER_8_Y = 0x05FC536D880238B13933C6D305ACDFD5F098EFF289F4C345B027B2C28F95E826
# The y coordinates of the eight small-order points: 0 (order 4), 1 (the
# identity), p - 1 (order 2) and the order-8 pair. A canonical encoding with
# one of these is of small order whatever its sign bit.
_SMALL_ORDER_Y = frozenset({0, 1, _P - 1, _ORDER_8_Y, _P - _ORDER_8_Y})

__all__ = ["acceptable_signature", "verify", "verify_receipt"]


def _acceptable_point(encoded: bytes) -> bool:
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    return y < _P and y not in _SMALL_ORDER_Y


def acceptable_signature(public_key: bytes, signature: bytes) -> bool:
    """Whether ``public_key`` and ``signature`` pass the checks OpenSSL
    leaves out: canonical, not small-order ``A`` and ``R``, and ``S < L``.
    The signature still has to verify."""
    return (
        isinstance(public_key, (bytes, bytearray))
        and isinstance(signature, (bytes, bytearray))
        and len(public_key) == 32
        and len(signature) == 64
        and _acceptable_point(bytes(public_key))
        and _acceptable_point(bytes(signature[:32]))
        and int.from_bytes(signature[32:], "little") < _L
    )


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Whether ``signature`` is a valid Ed25519 signature of ``message`` by
    ``public_key`` under the checks above. Never raises."""
    if not acceptable_signature(public_key, signature):
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(bytes(signature), message)
        return True
    except Exception:
        return False


def cose_sign1_signature(cose_bytes: bytes) -> bytes | None:
    """The signature of a COSE_Sign1 message, tagged or not, or None."""
    from .cbor import loads

    try:
        item: Any = loads(cose_bytes)
    except Exception:
        return None
    if getattr(item, "tag", None) == 18:
        item = item.value
    if isinstance(item, (list, tuple)) and len(item) == 4 and isinstance(item[3], bytes):
        return item[3]
    return None


def _raw_ed25519_key(pem: bytes | str) -> bytes | None:
    """The raw key of an Ed25519 PEM public key, or None for any other key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

    key = load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)
    if not isinstance(key, Ed25519PublicKey):
        return None
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def verify_receipt(receipt: bytes, *, leaf_entry_hex: str, log_public_key_pem: bytes | str):
    """``scitt_cose.verify_receipt``, refusing an Ed25519 receipt whose key
    or signature fails :func:`acceptable_signature`. A receipt under another
    key type (a CCF ES384 log) is left to ``scitt_cose``."""
    from scitt_cose import verify_receipt as scitt_verify_receipt

    result = scitt_verify_receipt(
        receipt, leaf_entry_hex=leaf_entry_hex, log_public_key_pem=log_public_key_pem
    )
    if not result.ok:
        return result
    try:
        public_key = _raw_ed25519_key(log_public_key_pem)
    except Exception:
        public_key = b""
    if public_key is not None and not acceptable_signature(public_key, cose_sign1_signature(receipt)):
        result.ok = False
        result.failed_at = "signature"
        result.errors.append(
            "receipt signature is refused: the key or R is not canonical or is of small order, or S >= L"
        )
    return result
