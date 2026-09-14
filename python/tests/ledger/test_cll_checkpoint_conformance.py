# SPDX-License-Identifier: Apache-2.0
"""Cross-language conformance guard: ``cll.ledger.checkpoint`` vs scitt-cose.

The signing body ``cll.ledger.checkpoint``'s emit path produces must be
byte-identical to the canonical CLL shape scitt-cose's ``cll.Checkpoint``
parses and verifies -- both are ports of the same original
``CheckpointRecord.signing_body`` (Amendment E). They diverged once: this
module's ``CheckpointRecord`` shipped an 8-field body with no ``log_id``
while the canonical shape (capsule-emit 0.4.0, scitt-cose 0.2.2) is 9 fields
with ``log_id`` (empty string for single-node). This test is the guard that
stops that recurring: it runs a checkpoint this module actually emitted
through scitt-cose's own parser and digest function and demands both a
clean parse and a byte-identical digest.

**Ported from capsule-ledger per the W3.1 CLL extraction (2026-09-01).**
``scitt-cose`` is not optional here the way it is for
``TestVerifyReceiptOffline`` in ``test_checkpoint.py``: this package's own
``dependencies`` require ``scitt-cose>=0.2.0`` directly -- so any environment
that can import ``cll.ledger.checkpoint`` at all already has a real
scitt-cose installed. ``importorskip`` is kept anyway (matching the existing
convention in this test suite) purely as a defensive guard against an
unusual environment, not because the dependency is expected to be absent.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

pytest.importorskip("scitt_cose")

from scitt_cose.cll import Checkpoint  # noqa: E402


@dataclass(frozen=True)
class _LocalSigner:
    """Minimal in-process HMAC-SHA256 ``Signer`` -- see ``test_checkpoint.py``."""

    key_id: str
    secret: bytes

    def sign(self, digest: str) -> str:
        return hmac.new(self.secret, digest.encode("ascii"), hashlib.sha256).hexdigest()


def _emit_cll_checkpoint():
    """Emit a real checkpoint via ``cll.ledger.checkpoint``'s own emit path.

    Returns the ``CheckpointRecord`` before it's serialised to JSON.
    """
    from cll.checkpoint import MmrLedger
    from cll.ledger.checkpoint import emit_checkpoint
    from cll.ledger.store import LedgerStore

    tmp = Path(tempfile.mkdtemp())
    store = LedgerStore(tmp)
    mmr = MmrLedger(store)
    signer = _LocalSigner(key_id="conformance-test-key", secret=secrets.token_bytes(32))

    for i in range(3):
        capsule = {
            "canonicalization_id": "jcs",
            "action_type": "fyi",
            "operator": "test-op",
            "developer": "test-dev",
            "timestamp": f"2026-01-01T00:00:{i:02d}Z",
            "event": f"conformance_event_{i}",
            "detail": {"i": i},
        }
        mmr.append(capsule, consequential=False)

    cp = emit_checkpoint(mmr, signer, timestamp="2026-08-22T00:00:00Z")
    store.close()
    return cp


def test_legacy_eight_field_checkpoint_fails_scitt_cose():
    """RED: the pre-fix shape (no ``log_id``) is rejected by scitt-cose.

    Reproduces exactly what this module emitted before this fix -- the real
    ``to_dict()`` output with the ``log_id`` key stripped back out -- and
    demands scitt-cose's parser refuse it. If this assertion ever starts
    failing, ``Checkpoint.from_dict`` stopped requiring ``log_id`` and this
    guard has lost its ability to catch the regression it exists for.
    """
    legacy_dict = _emit_cll_checkpoint().to_dict()
    del legacy_dict["log_id"]

    with pytest.raises(KeyError, match="log_id"):
        Checkpoint.from_dict(legacy_dict)


def test_cll_checkpoint_verifies_green():
    """GREEN: today's cll checkpoint parses AND digest-matches.

    A clean parse alone would not be enough -- a parser that silently
    defaulted ``log_id`` would also "pass" while producing a different
    digest, breaking every downstream TS registration. This demands the
    digest scitt-cose independently recomputes from the canonical JSON is
    byte-identical to the one this module signed.
    """
    ledger_cp = _emit_cll_checkpoint()

    scitt_cp = Checkpoint.from_dict(ledger_cp.to_dict())

    assert scitt_cp.digest() == ledger_cp.digest(), (
        f"digest mismatch: cll computed {ledger_cp.digest()!r}, "
        f"scitt-cose independently recomputed {scitt_cp.digest()!r} -- "
        "the signing-body canonicalization has diverged again"
    )
