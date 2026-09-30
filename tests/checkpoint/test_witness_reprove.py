# SPDX-License-Identifier: Apache-2.0
"""Re-proving a checkpoint from a witness's last-accepted state.

A witness that already accepted a checkpoint for a ``log_id`` refuses (409)
a later one whose ``prev_size``/``prev_root`` is not what it last accepted,
or one that carries no ``consistency_proof``. The 409 body carries the
witness's own ``(last_accepted_mmr_size, last_accepted_root)``.
``register_checkpoint`` surfaces that as ``WitnessContinuityRefused``, and
``reprove_checkpoint`` / ``reprove_checkpoint_cose`` re-sign the same
checkpoint so that it chains from the witness's view, with a consistency
proof from there.
"""
from __future__ import annotations

import io
import json
import urllib.error

import pytest
from tests.checkpoint.conftest import Ed25519TestSigner, FakeLogSource, synthetic_capsule

from cll.checkpoint import (
    CheckpointError,
    MmrLedger,
    RollbackError,
    WitnessContinuityRefused,
    core,
    emit_checkpoint,
    reprove_checkpoint,
    reprove_checkpoint_cose,
    verify_checkpoint_cose_offline,
    verify_checkpoint_signature_offline,
)
from cll.checkpoint import emit as emit_mod


class _Signer(Ed25519TestSigner):
    """Signs both the JSON checkpoint digest and the COSE envelope."""

    def sign(self, digest_hex: str) -> str:
        return self._private_key.sign(digest_hex.encode("ascii")).hex()


def _grow(mmr: MmrLedger, start: int, n: int) -> None:
    for i in range(start, start + n):
        mmr.append(synthetic_capsule(i), consequential=False)


def _three_checkpoints():
    """cp1 <- cp2 <- cp3 on one log. The witness is taken to have accepted
    cp1 only (cp2 was never sent, e.g. a cut between clock ticks)."""
    signer = _Signer()
    mmr = MmrLedger(FakeLogSource())
    _grow(mmr, 0, 3)
    cp1 = emit_checkpoint(mmr, signer, log_id="log-r", timestamp="2026-09-30T00:00:00Z")
    _grow(mmr, 3, 2)
    cp2 = emit_checkpoint(mmr, signer, log_id="log-r", prev=cp1, timestamp="2026-09-30T00:01:00Z")
    _grow(mmr, 5, 3)
    cp3 = emit_checkpoint(mmr, signer, log_id="log-r", prev=cp2, timestamp="2026-09-30T00:02:00Z")
    return signer, mmr, cp1, cp2, cp3


def test_reprove_rechains_from_the_witness_view():
    signer, mmr, cp1, _cp2, cp3 = _three_checkpoints()
    reproved = reprove_checkpoint(cp3, mmr, signer, from_size=cp1.mmr_size, from_root=cp1.root)

    assert (reproved.log_id, reproved.mmr_size, reproved.root, reproved.timestamp) == (
        cp3.log_id, cp3.mmr_size, cp3.root, cp3.timestamp,
    )
    assert (reproved.prev_size, reproved.prev_root) == (cp1.mmr_size, cp1.root)
    assert reproved.signature != cp3.signature
    assert verify_checkpoint_signature_offline(reproved)


def test_reprove_cose_carries_a_proof_from_the_witness_view():
    signer, mmr, cp1, _cp2, cp3 = _three_checkpoints()
    reproved, cose = reprove_checkpoint_cose(
        cp3, mmr, signer, from_size=cp1.mmr_size, from_root=cp1.root
    )

    result = verify_checkpoint_cose_offline(cose)
    assert result.ok, result.errors
    proof = result.decoded.consistency_proof
    assert proof is not None
    assert (proof.size_a, proof.size_b) == (cp1.mmr_size, cp3.mmr_size)
    assert core.verify_consistency(
        bytes.fromhex(cp1.root), cp1.mmr_size, bytes.fromhex(reproved.root), reproved.mmr_size, proof
    )


def test_reprove_refuses_a_witness_root_this_log_does_not_hold():
    """The witness accepted a different history at that size (a fork, or a
    log restarted under a reused log_id): re-signing must not paper over it."""
    signer, mmr, cp1, _cp2, cp3 = _three_checkpoints()
    with pytest.raises(RollbackError, match="does not extend what the witness holds"):
        reprove_checkpoint(cp3, mmr, signer, from_size=cp1.mmr_size, from_root="ab" * 32)


def test_reprove_refuses_when_the_witness_is_already_past_the_checkpoint():
    signer, mmr, _cp1, cp2, _cp3 = _three_checkpoints()
    with pytest.raises(CheckpointError, match="already at or past"):
        reprove_checkpoint(cp2, mmr, signer, from_size=cp2.mmr_size, from_root=cp2.root)


# --- register_checkpoint surfaces the witness's 409 -----------------------------


def _raise_http(code: int, body: bytes):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, code, "refused", {}, io.BytesIO(body))

    return fake_urlopen


def test_register_checkpoint_409_with_last_accepted_raises_continuity_refused(monkeypatch):
    body = json.dumps(
        {
            "detail": {
                "error": "checkpoint for log_id='log-r' carries no consistency_proof ...",
                "last_accepted_mmr_size": 4,
                "last_accepted_root": "cd" * 32,
                "code": "consistency_proof_required",
            }
        }
    ).encode()
    monkeypatch.setattr(emit_mod.urllib.request, "urlopen", _raise_http(409, body))

    with pytest.raises(WitnessContinuityRefused) as info:
        emit_mod.register_checkpoint(b"\xd2", "https://witness.example")
    exc = info.value
    assert isinstance(exc, CheckpointError)
    assert exc.last_accepted_mmr_size == 4
    assert exc.last_accepted_root == "cd" * 32
    assert exc.code == "consistency_proof_required"
    assert "HTTP 409" in str(exc)


def test_register_checkpoint_409_fork_refusal_has_no_code(monkeypatch):
    body = json.dumps(
        {"detail": {"error": "fork", "last_accepted_mmr_size": 7, "last_accepted_root": "ef" * 32}}
    ).encode()
    monkeypatch.setattr(emit_mod.urllib.request, "urlopen", _raise_http(409, body))

    with pytest.raises(WitnessContinuityRefused) as info:
        emit_mod.register_checkpoint(b"\xd2", "https://witness.example")
    assert info.value.code is None
    assert info.value.last_accepted_mmr_size == 7


@pytest.mark.parametrize(
    ("code", "body"),
    [
        (409, b"not json"),
        (409, json.dumps({"detail": "a plain string"}).encode()),
        (400, json.dumps({"detail": {"last_accepted_mmr_size": 1, "last_accepted_root": "00"}}).encode()),
    ],
)
def test_register_checkpoint_other_errors_stay_plain_checkpoint_errors(monkeypatch, code, body):
    monkeypatch.setattr(emit_mod.urllib.request, "urlopen", _raise_http(code, body))
    with pytest.raises(CheckpointError) as info:
        emit_mod.register_checkpoint(b"\xd2", "https://witness.example")
    assert not isinstance(info.value, WitnessContinuityRefused)
