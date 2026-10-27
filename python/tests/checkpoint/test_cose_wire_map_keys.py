# SPDX-License-Identifier: Apache-2.0
"""checkpointed-local-log#104: a COSE checkpoint whose maps hold keys that are
distinct in CBOR but equal in Python (1 and true, 0 and false) is refused by
:func:`verify_checkpoint_cose_offline`, never silently rewritten.

Each statement here is built byte by byte and signed with the test key, so
the CBOR reaching the verifier is exactly what the test wrote (cbor2's
encoder could not write these maps).
"""
from __future__ import annotations

import hashlib

import cbor2
import pytest

from cll.checkpoint import core as mmr_core
from cll.checkpoint.cose_wire import (
    CLL_CHECKPOINT_CONTENT_TYPE,
    encode_checkpoint_claims,
    verify_checkpoint_cose_offline,
)
from cll.checkpoint.emit import CheckpointRecord
from cll.checkpoint.store import MemoryNodeStore
from tests.checkpoint.conftest import Ed25519TestSigner

LOG_ID = "log-a"
COLLIDING = "equal as a Python value"

# Two entries whose keys collide in Python: (1, true) and (0, false).
PAIRS = {
    "1-true": [(b"\x01", cbor2.dumps("a")), (b"\xf5", cbor2.dumps("b"))],
    "0-false": [(b"\x00", cbor2.dumps("a")), (b"\xf4", cbor2.dumps("b"))],
}


def _map(entries: list[tuple[bytes, bytes]]) -> bytes:
    """A definite-length CBOR map from already-encoded keys and values, in
    the order given (fewer than 24 entries)."""
    assert len(entries) < 24
    return bytes([0xA0 + len(entries)]) + b"".join(k + v for k, v in entries)


def _enc(*items: object) -> list[bytes]:
    return [cbor2.dumps(i) for i in items]


def _protected_entries(signer: Ed25519TestSigner, mmr_size: int) -> list[tuple[bytes, bytes]]:
    cwt = _map([tuple(_enc(1, LOG_ID)), tuple(_enc(2, f"{LOG_ID}#{mmr_size}"))])
    return [
        tuple(_enc(1, -8)),  # alg: EdDSA
        tuple(_enc(3, CLL_CHECKPOINT_CONTENT_TYPE)),
        tuple(_enc(4, bytes.fromhex(signer.key_id))),
        (cbor2.dumps(15), cwt),  # CWT_Claims
    ]


def _claims_entries() -> tuple[int, list[tuple[bytes, bytes]]]:
    store = MemoryNodeStore()
    for i in range(3):
        mmr_core.add_leaf(store, mmr_core.leaf_hash(hashlib.sha256(f"e{i}".encode()).digest()))
    size = store.size()
    peaks = [store.node(p) for p in mmr_core.peaks(size)]
    cp = CheckpointRecord(
        v=1, kind="mmr_checkpoint", log_id=LOG_ID, mmr_size=size,
        root=mmr_core.root_from_peaks(peaks).hex(), prev_size=0, prev_root="",
        key_id="", timestamp="2026-10-27T00:00:00Z", signature="",
    )
    claims = encode_checkpoint_claims(cp, peaks)
    return size, [(cbor2.dumps(k), cbor2.dumps(v, canonical=True)) for k, v in sorted(claims.items())]


def _sign1(
    signer: Ed25519TestSigner,
    *,
    protected: bytes,
    payload: bytes,
    unprotected: bytes = b"\xa0",
) -> bytes:
    to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
    signature = signer._private_key.sign(to_sign)
    return b"\xd2\x84" + cbor2.dumps(protected) + unprotected + cbor2.dumps(payload) + cbor2.dumps(signature)


def _statement(
    signer: Ed25519TestSigner,
    *,
    extra_protected: list[tuple[bytes, bytes]] = (),
    extra_claims: list[tuple[bytes, bytes]] = (),
    unprotected: bytes = b"\xa0",
) -> bytes:
    size, claims = _claims_entries()
    return _sign1(
        signer,
        protected=_map(_protected_entries(signer, size) + list(extra_protected)),
        payload=_map(claims + list(extra_claims)),
        unprotected=unprotected,
    )


@pytest.fixture
def signer() -> Ed25519TestSigner:
    return Ed25519TestSigner()


def test_baseline_statement_verifies(signer: Ed25519TestSigner) -> None:
    result = verify_checkpoint_cose_offline(_statement(signer))
    assert result.ok, result.errors


@pytest.mark.parametrize("pair", PAIRS)
def test_protected_header_keys_that_collide_are_refused(signer: Ed25519TestSigner, pair: str) -> None:
    # Labels 1/true and 0/false next to the real alg/content type/kid/CWT.
    result = verify_checkpoint_cose_offline(_statement(signer, extra_protected=[(b"\x18\x63", b"\x00")] + PAIRS[pair]))
    assert not result.ok
    assert result.errors


def test_protected_header_collision_scitt_cose_misses_is_refused(signer: Ed25519TestSigner) -> None:
    # alg = "x"*18, then true: -8 replaces it, and an epoch time (tag 1) that
    # cbor2 re-encodes 20 bytes longer makes up the lost bytes, so a check
    # on re-encoded length alone (scitt-cose's strict_decode) passes it.
    size, claims = _claims_entries()
    entries = _protected_entries(signer, size)
    protected = _map(
        [(b"\x01", cbor2.dumps("x" * 18)), (b"\xf5", b"\x27")] + entries[1:] + [(b"\x18\x63", b"\xc1\x00")]
    )
    result = verify_checkpoint_cose_offline(_sign1(signer, protected=protected, payload=_map(claims)))
    assert not result.ok
    assert any(COLLIDING in e for e in result.errors), result.errors


@pytest.mark.parametrize("pair", PAIRS)
def test_unprotected_header_keys_that_collide_are_refused(signer: Ed25519TestSigner, pair: str) -> None:
    result = verify_checkpoint_cose_offline(_statement(signer, unprotected=_map(PAIRS[pair])))
    assert not result.ok
    assert result.errors


def test_unprotected_header_collision_scitt_cose_misses_is_refused(signer: Ed25519TestSigner) -> None:
    unprotected = _map([(b"\x01", cbor2.dumps("x" * 18)), (b"\xf5", b"\x27"), (b"\x18\x63", b"\xc1\x00")])
    result = verify_checkpoint_cose_offline(_statement(signer, unprotected=unprotected))
    assert not result.ok
    assert any(COLLIDING in e for e in result.errors), result.errors


@pytest.mark.parametrize("pair", PAIRS)
def test_claims_map_keys_that_collide_are_refused(signer: Ed25519TestSigner, pair: str) -> None:
    result = verify_checkpoint_cose_offline(_statement(signer, extra_claims=PAIRS[pair]))
    assert not result.ok
    assert any(COLLIDING in e for e in result.errors), result.errors


@pytest.mark.parametrize("pair", PAIRS)
def test_collision_nested_in_an_ignored_claim_is_refused(signer: Ed25519TestSigner, pair: str) -> None:
    # -01 says verifiers ignore claims they do not understand; this one is
    # still refused, since its map cannot be read back faithfully (#104).
    nested = _map([(cbor2.dumps("k"), _map(PAIRS[pair]))])
    result = verify_checkpoint_cose_offline(_statement(signer, extra_claims=[(cbor2.dumps("x-ext"), nested)]))
    assert not result.ok
    assert any(COLLIDING in e for e in result.errors), result.errors


def test_ignored_claim_without_collision_is_accepted(signer: Ed25519TestSigner) -> None:
    # true next to 2 collides with nothing, and claims have no label rule.
    nested = _map([(b"\x02", cbor2.dumps("a")), (b"\xf5", cbor2.dumps("b"))])
    result = verify_checkpoint_cose_offline(_statement(signer, extra_claims=[(cbor2.dumps("x-ext"), nested)]))
    assert result.ok, result.errors


@pytest.mark.parametrize(
    "where",
    ["protected", "unprotected", "cwt"],
)
def test_true_label_alone_is_refused(signer: Ed25519TestSigner, where: str) -> None:
    # A lone `true` label collides with nothing, but a lookup of label 1
    # would find it; RFC 9052 and RFC 8392 allow only int and tstr labels.
    size, claims = _claims_entries()
    entries = _protected_entries(signer, size)
    unprotected = b"\xa0"
    if where == "protected":
        entries[0] = (b"\xf5", b"\x27")  # true: EdDSA in place of alg
    elif where == "unprotected":
        unprotected = _map([(b"\xf5", b"\x27")])
    else:
        entries[3] = (b"\x0f", _map([(b"\xf5", cbor2.dumps(LOG_ID)), tuple(_enc(2, f"{LOG_ID}#{size}"))]))
    result = verify_checkpoint_cose_offline(
        _sign1(signer, protected=_map(entries), payload=_map(claims), unprotected=unprotected)
    )
    assert not result.ok
    assert any("not an integer or a text string" in e for e in result.errors), result.errors
