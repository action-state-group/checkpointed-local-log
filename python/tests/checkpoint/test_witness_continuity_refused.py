# SPDX-License-Identifier: Apache-2.0
"""A witness's continuity refusal surfaces as ``WitnessContinuityRefused``.

A witness that already accepted a checkpoint for a ``log_id`` refuses (409)
a later one whose ``prev_size``/``prev_root`` is not what it last accepted,
or one that carries no ``consistency_proof``. The 409 body carries the
witness's own ``(last_accepted_mmr_size, last_accepted_root)``, which
``register_checkpoint`` exposes so a producer can catch the witness up.
"""
from __future__ import annotations

import io
import json
import urllib.error

import pytest

from cll.checkpoint import CheckpointError, WitnessContinuityRefused
from cll.checkpoint import emit as emit_mod


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
