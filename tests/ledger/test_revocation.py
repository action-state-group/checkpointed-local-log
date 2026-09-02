# SPDX-License-Identifier: Apache-2.0
"""Key rotation as a recorded ledger event, plus time-fenced revocation:
a revoked key's signature is trusted for records dated at-or-before its
revocation timestamp, and rejected for anything claiming to postdate it.

**Ported from ``capsule-ledger``'s ``tests/test_key_rotation.py`` per the W3
CLL-revocation reconciliation (2026-09-02).** The CLI-facing tests (``capsule
key rotate``/``status``) stayed behind -- cll ships no CLI. The capsule
builder below is a minimal, self-contained stand-in for
``capsule_ledger.guards.capsule.build_event_capsule`` (guard/policy-layer
product code, the wrong dependency direction for a cll test) -- same pattern
``tests/ledger/test_checkpoint.py`` already uses for its own synthetic
capsules.

The integration tests below are the acceptance check for
[cll-revocation-default-finding]: :meth:`LedgerStore.verify` must flag a
time-fenced revocation violation with ZERO caller configuration -- no
``extra_findings`` supplied at construction. (Mutant-tested manually: with
the ``build_key_timeline``/``check_time_fenced_revocation`` call removed
from ``LedgerStore.verify``, ``test_store_verify_default_rejects_post_revocation_record``
fails red, confirming the test actually exercises the wiring rather than
some other path.)
"""
from __future__ import annotations

import itertools

from agent_action_capsule import (
    AssuranceBlock,
    Capsule,
    compute_capsule_id,
    json_digest,
)

from cll.ledger import LedgerStore
from cll.revocation import (
    ROTATION_EVENT,
    build_key_timeline,
    check_time_fenced_revocation,
)
from cll.signing import LocalSigner, key_fingerprint

OLD_KEY_ID = "key-2026-q1"
OLD_SECRET = b"old-secret-material"
NEW_KEY_ID = "key-2026-q2"
NEW_SECRET = b"new-secret-material"
ROTATED_AT = "2026-04-01T00:00:00Z"

_capsule_counter = itertools.count()


def _build_capsule(*, operator: str, developer: str, event: str, detail: dict, signer, timestamp: str) -> dict:
    """A minimal, valid, content-unique Agent Action Capsule carrying an
    ``asg_payload``/``asg_signature`` extension -- the same namespaced,
    non-spec payload-extension shape :mod:`cll.revocation` reads. Mirrors
    ``capsule_ledger.guards.capsule.build_event_capsule`` closely enough to
    be a faithful stand-in without depending on guard/policy-layer code.
    """
    i = next(_capsule_counter)
    capsule_obj = Capsule(
        spec_version="draft-mih-scitt-agent-action-capsule-02",
        format_version="2",
        action_id=f"rotation-test-{i}",
        action_type="fyi",
        operator=operator,
        developer=developer,
        timestamp=timestamp,
        assurance=AssuranceBlock(
            attestation_mode="self_attested", effect_mode="not_applicable", ledger_mode="standalone"
        ),
    )
    body = capsule_obj.to_dict()
    body["asg_payload"] = {"event": event, "detail": detail}

    presig_digest = json_digest(body)
    body["asg_signature"] = {
        "key_id": signer.key_id,
        "alg": signer.algorithm,
        "sig": signer.sign(presig_digest),
    }
    body["capsule_id"] = compute_capsule_id(body)
    return body


def _rotation_detail(*, rotated_at: str = ROTATED_AT) -> dict:
    return {
        "old_key_id": OLD_KEY_ID,
        "old_key_fingerprint": key_fingerprint(OLD_KEY_ID, OLD_SECRET),
        "new_key_id": NEW_KEY_ID,
        "new_key_fingerprint": key_fingerprint(NEW_KEY_ID, NEW_SECRET),
        "rotated_at": rotated_at,
    }


def _rotation_capsule() -> dict:
    old_signer = LocalSigner(key_id=OLD_KEY_ID, secret=OLD_SECRET)
    return _build_capsule(
        operator="acme", developer="key-admin", event=ROTATION_EVENT,
        detail=_rotation_detail(), signer=old_signer, timestamp=ROTATED_AT,
    )


def _append_rotation_event(store: LedgerStore, *, rotated_at: str = ROTATED_AT) -> dict:
    old_signer = LocalSigner(key_id=OLD_KEY_ID, secret=OLD_SECRET)
    capsule = _build_capsule(
        operator="acme", developer="key-admin", event=ROTATION_EVENT,
        detail=_rotation_detail(rotated_at=rotated_at), signer=old_signer, timestamp=rotated_at,
    )
    store.append(capsule, consequential=True)
    return capsule


def _signed_record(*, key_id: str, secret: bytes, timestamp: str, event: str = "note") -> dict:
    signer = LocalSigner(key_id=key_id, secret=secret)
    return _build_capsule(
        operator="acme", developer="agent@v1", event=event, detail={}, signer=signer, timestamp=timestamp
    )


# -- unit: fingerprints + timeline reconstruction -----------------------------


def test_key_fingerprint_is_stable_and_key_id_bound():
    fp1 = key_fingerprint("k1", b"secret")
    fp2 = key_fingerprint("k1", b"secret")
    fp3 = key_fingerprint("k2", b"secret")
    assert fp1 == fp2
    assert fp1 != fp3  # same secret, different key_id -> different fingerprint
    assert len(fp1) == 64  # sha256 hex


def test_build_key_timeline_reconstructs_from_ledger_alone(store):
    _append_rotation_event(store)
    timeline = build_key_timeline(store)

    assert timeline[OLD_KEY_ID].revoked_at == ROTATED_AT
    assert timeline[NEW_KEY_ID].activated_at == ROTATED_AT
    assert timeline[NEW_KEY_ID].revoked_at is None  # still live


def test_build_key_timeline_chains_across_multiple_rotations(store):
    _append_rotation_event(store, rotated_at="2026-01-01T00:00:00Z")
    third_signer_detail = {
        "old_key_id": NEW_KEY_ID,
        "old_key_fingerprint": key_fingerprint(NEW_KEY_ID, NEW_SECRET),
        "new_key_id": "key-2026-q3",
        "new_key_fingerprint": key_fingerprint("key-2026-q3", b"third-secret"),
        "rotated_at": "2026-07-01T00:00:00Z",
    }
    signer = LocalSigner(key_id=NEW_KEY_ID, secret=NEW_SECRET)
    capsule = _build_capsule(
        operator="acme", developer="key-admin", event=ROTATION_EVENT,
        detail=third_signer_detail, signer=signer, timestamp="2026-07-01T00:00:00Z",
    )
    store.append(capsule, consequential=True)

    timeline = build_key_timeline(store)
    assert timeline[OLD_KEY_ID].revoked_at == "2026-01-01T00:00:00Z"
    assert timeline[NEW_KEY_ID].activated_at == "2026-01-01T00:00:00Z"
    assert timeline[NEW_KEY_ID].revoked_at == "2026-07-01T00:00:00Z"
    assert timeline["key-2026-q3"].activated_at == "2026-07-01T00:00:00Z"
    assert timeline["key-2026-q3"].revoked_at is None


# -- the core time-fenced revocation property ---------------------------------


def test_time_fenced_revocation_accepts_record_dated_before_rotation():
    timeline = build_key_timeline_from_capsules([_rotation_capsule()])
    before = _signed_record(key_id=OLD_KEY_ID, secret=OLD_SECRET, timestamp="2026-03-01T00:00:00Z")
    finding = check_time_fenced_revocation(before, timeline)
    assert finding.ok is True


def test_time_fenced_revocation_rejects_record_dated_after_rotation():
    timeline = build_key_timeline_from_capsules([_rotation_capsule()])
    after = _signed_record(key_id=OLD_KEY_ID, secret=OLD_SECRET, timestamp="2026-05-01T00:00:00Z")
    finding = check_time_fenced_revocation(after, timeline)
    assert finding.ok is False
    assert "revoked" in finding.reason
    assert OLD_KEY_ID in finding.reason


def test_time_fenced_revocation_accepts_rotation_event_at_the_boundary_instant():
    """The rotation event itself, signed by the outgoing key at exactly its
    own revocation timestamp, must stay valid -- otherwise the rotation
    record could never verify, contradicting the "real, verifiable record"
    requirement."""
    rotation_capsule = _rotation_capsule()
    timeline = build_key_timeline_from_capsules([rotation_capsule])
    finding = check_time_fenced_revocation(rotation_capsule, timeline)
    assert finding.ok is True


def test_time_fenced_revocation_new_key_unaffected_by_old_keys_fence():
    timeline = build_key_timeline_from_capsules([_rotation_capsule()])
    new_key_record = _signed_record(key_id=NEW_KEY_ID, secret=NEW_SECRET, timestamp="2026-12-01T00:00:00Z")
    finding = check_time_fenced_revocation(new_key_record, timeline)
    assert finding.ok is True


def test_time_fenced_revocation_ignores_key_with_no_rotation_history():
    finding = check_time_fenced_revocation(
        _signed_record(key_id="never-rotated", secret=b"x", timestamp="2026-01-01T00:00:00Z"), {}
    )
    assert finding.ok is True


class _FakeLedger:
    """A minimal LedgerAPI-shaped stand-in exposing only ``scan()`` --
    ``build_key_timeline`` never needs more than that."""

    def __init__(self, capsules: list[dict]):
        self._capsules = capsules

    def scan(self, query=None):
        from cll.ledger.records import LedgerRecord

        for i, capsule in enumerate(self._capsules, start=1):
            yield LedgerRecord(seq=i, capsule_id=capsule["capsule_id"], capsule=capsule, segment="mem", consequential=True)


def build_key_timeline_from_capsules(capsules: list[dict]) -> dict:
    return build_key_timeline(_FakeLedger(capsules))


# -- acceptance: LedgerStore.verify() enforces the fence BY DEFAULT -----------
# (zero caller configuration -- no extra_findings supplied anywhere below)


def test_store_verify_default_accepts_pre_revocation_record(store):
    _append_rotation_event(store)
    before = _signed_record(key_id=OLD_KEY_ID, secret=OLD_SECRET, timestamp="2026-03-01T00:00:00Z")
    record = store.append(before, consequential=True)

    result = store.verify(record.capsule_id)
    assert result.ok is True


def test_store_verify_default_rejects_post_revocation_record(store):
    """THE acceptance check: a store constructed with NO extra_findings still
    catches a revoked-key-across-rotation violation."""
    _append_rotation_event(store)
    after = _signed_record(key_id=OLD_KEY_ID, secret=OLD_SECRET, timestamp="2026-05-01T00:00:00Z")
    record = store.append(after, consequential=True)

    result = store.verify(record.capsule_id)
    assert result.ok is False
    assert any(f.code == "key_revoked_at_timestamp" for f in result.findings)


def test_store_verify_default_accepts_post_revocation_record_signed_by_new_key(store):
    _append_rotation_event(store)
    after = _signed_record(key_id=NEW_KEY_ID, secret=NEW_SECRET, timestamp="2026-05-01T00:00:00Z")
    record = store.append(after, consequential=True)

    result = store.verify(record.capsule_id)
    assert result.ok is True


def test_store_verify_default_accepts_record_when_no_rotation_ever_happened(store):
    """A ledger with no key_rotation events at all -- the common case --
    must not be affected by wiring a check that always runs: no timeline
    entries means the check is a no-op, same as before this change."""
    record = store.append(
        _signed_record(key_id="never-rotated", secret=b"x", timestamp="2026-01-01T00:00:00Z"),
        consequential=True,
    )
    result = store.verify(record.capsule_id)
    assert result.ok is True
    assert not any(f.code == "key_revoked_at_timestamp" for f in result.findings)


def test_extra_findings_still_composes_alongside_the_default(tmp_path):
    """``extra_findings`` remains a live extension point -- a caller's own
    additional check still runs, alongside (not instead of) the default
    revocation finding."""
    from agent_action_capsule import Finding

    calls = []

    def _custom_check(s, record):
        calls.append(record.capsule_id)
        return Finding("custom_check_flag", "always flags", severity="error")

    custom_store = LedgerStore(tmp_path / "custom", extra_findings=(_custom_check,))
    try:
        record = custom_store.append(
            _signed_record(key_id="never-rotated", secret=b"x", timestamp="2026-01-01T00:00:00Z"),
            consequential=True,
        )
        result = custom_store.verify(record.capsule_id)
        assert result.ok is False
        assert any(f.code == "custom_check_flag" for f in result.findings)
        assert calls == [record.capsule_id]
    finally:
        custom_store.close()
