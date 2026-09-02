# SPDX-License-Identifier: Apache-2.0
"""Acceptance tests for the three-state admission contract on ``append()``.

These are written to mirror, shape-for-shape, what the Go ``capsule-ledger-go``
side will assert, so the two implementations of the same contract stay honest
against each other:

  1. declared-unsigned admits, and records an explicit unsigned-authenticity
     state on the entry;
  2. declared-signed + no envelope → REJECT;
  3. declared-signed + an envelope that does NOT verify against the recomputed
     ``capsule_id`` → REJECT;
  4. declared-signed + ≥1 valid envelope → ADMIT, persisted bundled with the
     envelope, and re-verify-from-storage is clean;
  5. stripping the envelope off a declared-signed submission does NOT silently
     downgrade to unsigned — the declared mode is authoritative, so it REJECTS.

The signing side reuses a minimal test-only producer-signing helper
(``conftest.sign_producer_envelope`` — the frozen AAC producer-envelope
profile, same primitives ``capsule_emit.signing`` itself calls) — the tests
never hand-roll a COSE envelope, exactly as the store never hand-rolls the
verify.
"""
from __future__ import annotations

import pytest
from agent_action_capsule import compute_capsule_id
from tests.ledger.conftest import Ed25519EnvelopeSigner, sign_producer_envelope

from cll.ledger import LedgerStore
from cll.ledger.admission import (
    AUTHENTICITY_SIGNED,
    AUTHENTICITY_UNSIGNED,
    SIGNED,
    UNSIGNED,
    AdmissionRejected,
    AdmissionRequest,
    ProducerEnvelope,
)


def _capsule(**overrides) -> dict:
    cap = {
        "canonicalization_id": "jcs",
        "action_type": "record_transaction",
        "operator": "acme",
        "developer": "agent-alpha",
        "timestamp": "2026-08-25T00:00:00Z",
    }
    cap.update(overrides)
    return cap


@pytest.fixture
def signer():
    return Ed25519EnvelopeSigner()


def _envelope_for(signer, capsule: dict) -> ProducerEnvelope:
    """A real, verifying Producer Envelope over the capsule's recomputed id."""
    capsule_id = compute_capsule_id(capsule)
    envelope_hex, key_id = sign_producer_envelope(signer, capsule_id)
    return ProducerEnvelope(envelope=envelope_hex, key_id=key_id)


# 1 -----------------------------------------------------------------------
def test_declared_unsigned_admits_and_records_unsigned_state(store):
    cap = _capsule()
    record = store.append(cap, admission=AdmissionRequest(mode=UNSIGNED))

    # admitted
    assert store.fetch(record.capsule_id) is not None
    # explicit unsigned-authenticity state recorded ON the entry, not inferred
    fetched = store.fetch(record.capsule_id)
    assert fetched.authenticity == AUTHENTICITY_UNSIGNED


# 2 -----------------------------------------------------------------------
def test_declared_signed_no_envelope_rejects(store):
    cap = _capsule()
    with pytest.raises(AdmissionRejected) as exc:
        store.append(cap, admission=AdmissionRequest(mode=SIGNED))
    assert exc.value.code == "envelope_missing"
    # nothing was persisted
    assert store.fetch(compute_capsule_id(cap)) is None


# 3 -----------------------------------------------------------------------
def test_declared_signed_envelope_not_verifying_rejects(store, signer):
    cap = _capsule()
    # An envelope minted over a DIFFERENT capsule's id — well-formed COSE, real
    # signature, but it does not verify against THIS capsule's recomputed id.
    other = _capsule(action_type="approve_purchase", timestamp="2026-08-25T01:00:00Z")
    wrong_envelope = _envelope_for(signer, other)
    assert compute_capsule_id(other) != compute_capsule_id(cap)

    with pytest.raises(AdmissionRejected) as exc:
        store.append(cap, admission=AdmissionRequest(mode=SIGNED, envelopes=(wrong_envelope,)))
    assert exc.value.code == "envelope_invalid"
    assert store.fetch(compute_capsule_id(cap)) is None


# 4 -----------------------------------------------------------------------
def test_declared_signed_valid_envelope_admits_persists_bundled_and_reverifies(store, signer):
    cap = _capsule()
    envelope = _envelope_for(signer, cap)

    record = store.append(cap, admission=AdmissionRequest(mode=SIGNED, envelopes=(envelope,)))

    fetched = store.fetch(record.capsule_id)
    assert fetched is not None
    # signed-authenticity state recorded
    assert fetched.authenticity == AUTHENTICITY_SIGNED
    # persisted BUNDLED: the verifying envelope travels with the stored capsule
    assert fetched.envelopes
    assert fetched.envelopes[0].key_id == envelope.key_id
    assert fetched.envelopes[0].envelope == envelope.envelope

    # re-verify-from-storage is clean: rehydrate from a fresh store over the same
    # segments and confirm the persisted bundle still verifies against the
    # recomputed capsule_id.
    reopened = LedgerStore(store.root)
    try:
        again = reopened.fetch(record.capsule_id)
        assert again is not None
        assert again.authenticity == AUTHENTICITY_SIGNED
        capsule_id = compute_capsule_id(again.capsule)
        from agent_action_capsule.producer_envelope import verify_producer_envelope

        env = again.envelopes[0]
        result = verify_producer_envelope(capsule_id, bytes.fromhex(env.envelope))
        assert result.ok
        assert result.public_key == bytes.fromhex(env.key_id)
    finally:
        reopened.close()


# 5 -----------------------------------------------------------------------
def test_stripping_envelope_from_signed_submission_does_not_silently_downgrade(store, signer):
    """The anti-downgrade invariant: a submission DECLARED signed, whose envelope
    is then stripped, must REJECT — never quietly admit as unsigned. The declared
    mode is authoritative; admission never infers signedness from envelope
    presence."""
    cap = _capsule()
    # caller intended signed, but the envelope is gone by the time we append
    stripped = AdmissionRequest(mode=SIGNED)  # no envelopes, mode still SIGNED

    with pytest.raises(AdmissionRejected):
        store.append(cap, admission=stripped)

    # and it is NOT sitting in the ledger as a silently-unsigned entry
    assert store.fetch(compute_capsule_id(cap)) is None
