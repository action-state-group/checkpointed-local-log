# SPDX-License-Identifier: Apache-2.0
"""Tests for the MMR peaks-checkpoint emit path.

Covers:
  - emit_checkpoint: produces a correctly signed checkpoint record
  - verify_checkpoint_signature: passes for valid, fails for tampered
  - verify_checkpoint_consistency: passes when MMR extends prev, FAILS on rollback
  - register_checkpoint: correct request/response wiring (mocked TS)
  - verify_receipt_offline: correct wiring to scitt-cose (mocked)
  - list/save/load_checkpoint: round-trips storage layer
  - Mutant test: verifying a rolled-back log returns RollbackError / fails consistency

Live network tests (off by default; opt-in via CAPSULE_TEST_LIVE_TS=1).

**Ported from capsule-ledger per the W3.1 CLL extraction (2026-09-01).**
``LocalSigner`` and the synthetic-capsule builder below are minimal,
self-contained test helpers -- deliberately independent of
``capsule_ledger.guards.*`` (guard/policy-layer product code, the wrong
dependency direction for a cll test). The CLI smoke-test class was dropped
(cll ships no CLI); see the note near where it used to be.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import itertools
import json
import os
import secrets
import tempfile
import unittest.mock as mock
from dataclasses import dataclass
from pathlib import Path

import pytest
from cll.checkpoint import MemoryNodeStore, MmrLedger

from cll.ledger.checkpoint import (
    DEFAULT_TS_URL,
    CheckpointConfig,
    CheckpointError,
    CheckpointRecord,
    RollbackError,
    WitnessRecord,
    emit_checkpoint,
    list_checkpoints,
    load_checkpoint,
    load_latest_checkpoint,
    register_checkpoint,
    save_checkpoint,
    save_config,
    verify_checkpoint_consistency,
    verify_checkpoint_signature,
    verify_receipt_offline,
)
from cll.ledger.store import LedgerStore

_LIVE_TS = os.environ.get("CAPSULE_TEST_LIVE_TS") == "1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LocalSigner:
    """A minimal in-process HMAC-SHA256 ``Signer`` -- key_id + sign(digest_hex)."""

    key_id: str
    secret: bytes

    def sign(self, digest: str) -> str:
        return hmac.new(self.secret, digest.encode("ascii"), hashlib.sha256).hexdigest()


def _make_signer(key_id: str = "test-key") -> LocalSigner:
    return LocalSigner(key_id=key_id, secret=secrets.token_bytes(32))


_capsule_counter = itertools.count()


def _synthetic_capsule(*, operator: str, developer: str, event: str, detail: dict, **_ignored) -> dict:
    """A minimal, valid, content-unique capsule dict -- enough to be an MMR
    leaf and round-trip through :class:`LedgerStore`. Deliberately does not
    reproduce ``capsule_ledger.guards.capsule.build_event_capsule``'s
    self-attested guard signature; these tests never check it."""
    i = next(_capsule_counter)
    return {
        "canonicalization_id": "jcs",
        "action_type": "fyi",
        "operator": operator,
        "developer": developer,
        "timestamp": f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z",
        "event": event,
        "detail": detail,
    }


def _make_mmr_with_leaves(n: int) -> tuple[MmrLedger, LedgerStore, Path]:
    """Create a temp ledger with n entries and return (mmr, store, root_dir)."""
    tmp = Path(tempfile.mkdtemp())
    store = LedgerStore(tmp)
    mmr = MmrLedger(store)

    signer = _make_signer()
    for i in range(n):
        capsule = _synthetic_capsule(
            operator="test-op",
            developer="test-dev",
            signer=signer,
            event=f"test_event_{i}",
            detail={"i": i},
        )
        mmr.append(capsule, consequential=False)

    return mmr, store, tmp


# ---------------------------------------------------------------------------
# emit_checkpoint
# ---------------------------------------------------------------------------


class TestEmitCheckpoint:
    def test_produces_signed_record(self):
        mmr, store, tmp = _make_mmr_with_leaves(5)
        signer = _make_signer()
        cp = emit_checkpoint(mmr, signer, timestamp="2026-08-18T00:00:00Z")
        store.close()

        assert cp.v == 1
        assert cp.kind == "mmr_checkpoint"
        assert cp.mmr_size == mmr.size()
        assert cp.key_id == signer.key_id
        assert cp.timestamp == "2026-08-18T00:00:00Z"
        assert len(cp.root) == 64
        assert cp.prev_size == 0
        assert cp.prev_root == ""
        assert len(cp.signature) == 64

    def test_empty_mmr_raises(self):
        store = LedgerStore(Path(tempfile.mkdtemp()))
        mmr = MmrLedger(store)
        signer = _make_signer()
        with pytest.raises(CheckpointError):
            emit_checkpoint(mmr, signer)
        store.close()

    def test_second_checkpoint_chains_prev(self):
        mmr, store, tmp = _make_mmr_with_leaves(4)
        signer = _make_signer()
        cp1 = emit_checkpoint(mmr, signer, timestamp="2026-08-18T00:00:00Z")

        # Append more leaves then checkpoint again.
        for i in range(3):
            capsule = _synthetic_capsule(
                operator="test-op", developer="test-dev", signer=signer,
                event="test_event_more", detail={"i": i},
            )
            mmr.append(capsule, consequential=False)

        cp2 = emit_checkpoint(mmr, signer, prev=cp1, timestamp="2026-08-18T01:00:00Z")
        store.close()

        assert cp2.prev_size == cp1.mmr_size
        assert cp2.prev_root == cp1.root
        assert cp2.mmr_size > cp1.mmr_size

    def test_monotonicity_violation_raises(self):
        mmr, store, tmp = _make_mmr_with_leaves(5)
        signer = _make_signer()
        emit_checkpoint(mmr, signer)  # needed to advance the MMR before faking prev

        # Fake a prev checkpoint with a LARGER size to trigger the violation.
        fake_prev = CheckpointRecord(
            v=1, kind="mmr_checkpoint",
            mmr_size=mmr.size() + 10,
            root="a" * 64,
            prev_size=0, prev_root="",
            key_id=signer.key_id, timestamp="2026-08-18T00:00:00Z",
            signature="c" * 64,
        )
        with pytest.raises(RollbackError):
            emit_checkpoint(mmr, signer, prev=fake_prev)
        store.close()


# ---------------------------------------------------------------------------
# verify_checkpoint_signature
# ---------------------------------------------------------------------------


class TestVerifyCheckpointSignature:
    def test_valid_signature(self):
        mmr, store, tmp = _make_mmr_with_leaves(3)
        signer = _make_signer()
        cp = emit_checkpoint(mmr, signer)
        store.close()
        assert verify_checkpoint_signature(cp, signer)

    def test_tampered_signature_fails(self):
        mmr, store, tmp = _make_mmr_with_leaves(3)
        signer = _make_signer()
        cp = emit_checkpoint(mmr, signer)
        store.close()
        # Tamper the signature.
        cp2 = CheckpointRecord(**{**cp.__dict__, "signature": "aa" * 32})
        assert not verify_checkpoint_signature(cp2, signer)

    def test_wrong_key_fails(self):
        mmr, store, tmp = _make_mmr_with_leaves(3)
        signer = _make_signer("key-a")
        cp = emit_checkpoint(mmr, signer)
        store.close()
        other_signer = _make_signer("key-b")
        assert not verify_checkpoint_signature(cp, other_signer)


# ---------------------------------------------------------------------------
# verify_checkpoint_consistency (rollback detection)
# ---------------------------------------------------------------------------


class TestVerifyCheckpointConsistency:
    def test_consistent_chain_passes(self):
        mmr, store, tmp = _make_mmr_with_leaves(3)
        signer = _make_signer()
        cp1 = emit_checkpoint(mmr, signer)

        for i in range(2):
            capsule = _synthetic_capsule(
                operator="op", developer="dev", signer=signer,
                event="more", detail={"i": i},
            )
            mmr.append(capsule, consequential=False)

        cp2 = emit_checkpoint(mmr, signer, prev=cp1)
        store.close()

        assert verify_checkpoint_consistency(cp1, cp2, mmr)

    def test_rollback_detected(self):
        """Mutate a peak hash in a MemoryNodeStore → consistency check fails."""
        mmr, store, tmp = _make_mmr_with_leaves(5)
        signer = _make_signer()
        cp1 = emit_checkpoint(mmr, signer, timestamp="2026-08-18T00:00:00Z")

        # Build a second checkpoint referencing a WRONG prev_root
        # (simulating that someone tried to claim a different prev state).
        tampered_cp2 = CheckpointRecord(
            v=1, kind="mmr_checkpoint",
            mmr_size=cp1.mmr_size + 1,
            root="a" * 64,
            prev_size=cp1.mmr_size,
            prev_root="dead" * 16,  # wrong root
            key_id=signer.key_id,
            timestamp="2026-08-18T01:00:00Z",
            signature="c" * 64,
        )
        assert not verify_checkpoint_consistency(cp1, tampered_cp2, mmr)

    def test_mmr_rollback_simulation(self):
        """A rolled-back log rebuilds with different peak hashes → consistency fails.

        The MemoryNodeStore is write-once: interior hashes are computed and stored
        at append time. To simulate a genuine rollback we build a SECOND ledger with
        mutated leaf bodies, sync its MMR from scratch, then verify that the old
        checkpoint's root no longer matches the root at the same size in the mutated
        store.
        """

        mmr, store, tmpd = _make_mmr_with_leaves(5)
        signer = _make_signer()
        cp1 = emit_checkpoint(mmr, signer, timestamp="2026-08-18T00:00:00Z")

        # Append more leaves and produce cp2 that back-references cp1.
        for i in range(2):
            capsule = _synthetic_capsule(
                operator="op", developer="dev", signer=signer,
                event="ext", detail={"i": i},
            )
            mmr.append(capsule, consequential=False)

        cp2 = emit_checkpoint(mmr, signer, prev=cp1)

        # Simulate rollback: build a fresh MmrLedger by appending DIFFERENT leaf
        # hashes for the same size. The recomputed root at cp1.mmr_size will differ.
        from cll.checkpoint import core as mmr_core

        mutant_store = MemoryNodeStore()
        mutant_mmr = MmrLedger.__new__(MmrLedger)
        mutant_mmr._ledger = None
        mutant_mmr._nodes = mutant_store
        mutant_mmr._body_digests = []

        # Rebuild the full MMR with garbage leaf hashes (same count as original).
        total_leaves = mmr.leaf_count()
        for i in range(total_leaves):
            garbage = hashlib.sha256(f"mutant-{i}".encode()).digest()
            mmr_core.add_leaf(mutant_store, mmr_core.leaf_hash(garbage))
            mutant_mmr._body_digests.append(garbage)

        # The mutant's root at cp1.mmr_size != cp1.root → consistency FAILS.
        assert not verify_checkpoint_consistency(cp1, cp2, mutant_mmr)

        # And also: the same mutant applied directly to cp1.root check.
        from cll.ledger.checkpoint import _root_hex
        mutant_root_at_cp1 = _root_hex(mutant_mmr, cp1.mmr_size)
        assert mutant_root_at_cp1 != cp1.root

        store.close()


# ---------------------------------------------------------------------------
# register_checkpoint (mocked TS)
# ---------------------------------------------------------------------------


class TestRegisterCheckpoint:
    def _fake_receipt_b64(self) -> str:
        # A minimal COSE_Sign1 (CBOR tag 18) stub — not a real receipt, just
        # enough bytes to be non-empty base64 for round-trip tests.
        return base64.b64encode(b"FAKE_RECEIPT").decode()

    def test_posts_checkpoint_digest_to_ts(self):
        mmr, store, tmp = _make_mmr_with_leaves(3)
        signer = _make_signer()
        cp = emit_checkpoint(mmr, signer)
        store.close()

        expected_digest = cp.digest()
        expected_entry_hash = hashlib.sha256(bytes.fromhex(expected_digest)).hexdigest()

        fake_body = json.dumps({
            "receipt_b64": self._fake_receipt_b64(),
            "entry_hash": expected_entry_hash,
            "leaf_index": 0,
            "tree_size": 1,
        }).encode()

        with mock.patch("urllib.request.urlopen") as m_open:
            m_resp = mock.MagicMock()
            m_resp.__enter__ = lambda s: s
            m_resp.__exit__ = mock.MagicMock(return_value=False)
            m_resp.read.return_value = fake_body
            m_open.return_value = m_resp

            witness = register_checkpoint(cp, DEFAULT_TS_URL)

        # Verify the POST payload contained the correct digest.
        call_args = m_open.call_args
        req_obj = call_args[0][0]
        posted = json.loads(req_obj.data)
        assert posted["capsule_id"] == expected_digest

        assert witness.ts_url == DEFAULT_TS_URL
        assert witness.entry_hash == expected_entry_hash
        assert witness.leaf_index == 0
        assert witness.tree_size == 1

    def test_http_error_raises_checkpoint_error(self):
        mmr, store, tmp = _make_mmr_with_leaves(2)
        signer = _make_signer()
        cp = emit_checkpoint(mmr, signer)
        store.close()

        import urllib.error

        with mock.patch("urllib.request.urlopen") as m_open:
            m_open.side_effect = urllib.error.HTTPError(
                url="http://x", code=400, msg="bad", hdrs=None, fp=mock.MagicMock(read=lambda: b"bad input")
            )
            with pytest.raises(CheckpointError):
                register_checkpoint(cp, DEFAULT_TS_URL)


# ---------------------------------------------------------------------------
# verify_receipt_offline (mocked scitt-cose)
# ---------------------------------------------------------------------------


class TestVerifyReceiptOffline:
    def setup_method(self):
        # scitt-cose is the `checkpoint` extra, not `dev` — mock.patch("scitt_cose....")
        # needs the module importable even though checkpoint.py's own import is a soft
        # try/except. Skip loudly (not silently) rather than ModuleNotFoundError in CI's
        # base `dev`-only job.
        pytest.importorskip("scitt_cose")

    def _make_witness(self) -> WitnessRecord:
        return WitnessRecord(
            ts_url=DEFAULT_TS_URL,
            entry_hash="a" * 64,
            receipt_b64=base64.b64encode(b"COSE_BYTES").decode(),
            leaf_index=0,
            tree_size=1,
        )

    def test_returns_true_when_scitt_cose_ok(self):
        w = self._make_witness()
        fake_result = mock.MagicMock()
        fake_result.ok = True
        fake_result.errors = []

        # Patch the scitt_cose module import inside checkpoint to return a success.
        with mock.patch("scitt_cose.verify_receipt", return_value=fake_result):
            ok, errors = verify_receipt_offline(w, ts_pubkey_pem=b"FAKE_PEM")

        assert ok
        assert errors == []

    def test_returns_false_errors_on_bad_receipt(self):
        w = self._make_witness()
        # Patch scitt_cose.verify_receipt to return a failure result.
        fake_result = mock.MagicMock()
        fake_result.ok = False
        fake_result.errors = ["invalid alg"]

        with mock.patch("scitt_cose.verify_receipt", return_value=fake_result):
            ok, errors = verify_receipt_offline(w, ts_pubkey_pem=b"FAKE_PEM")

        assert not ok
        assert "invalid alg" in errors


# ---------------------------------------------------------------------------
# Storage round-trip
# ---------------------------------------------------------------------------


class TestStorage:
    def test_save_and_load_checkpoint(self, tmp_path):
        mmr, store, tmp = _make_mmr_with_leaves(3)
        signer = _make_signer()
        cp = emit_checkpoint(mmr, signer, timestamp="2026-08-18T00:00:00Z")
        store.close()

        # Add a fake witness to test round-trip.
        cp.witnesses.append(
            WitnessRecord(
                ts_url=DEFAULT_TS_URL,
                entry_hash="b" * 64,
                receipt_b64="RECEIPT_B64",
                leaf_index=0,
                tree_size=1,
            )
        )

        p = save_checkpoint(tmp_path, cp)
        assert p.exists()

        loaded = load_checkpoint(tmp_path, cp.mmr_size)
        assert loaded is not None
        assert loaded.mmr_size == cp.mmr_size
        assert loaded.root == cp.root
        assert loaded.signature == cp.signature
        assert len(loaded.witnesses) == 1
        assert loaded.witnesses[0].ts_url == DEFAULT_TS_URL

    def test_load_latest_returns_largest(self, tmp_path):
        mmr, store, tmp = _make_mmr_with_leaves(5)
        signer = _make_signer()
        cp1 = emit_checkpoint(mmr, signer, timestamp="2026-08-18T00:00:00Z")

        for _i in range(2):
            capsule = _synthetic_capsule(
                operator="op", developer="dev", signer=signer, event="e", detail={}
            )
            mmr.append(capsule, consequential=False)

        cp2 = emit_checkpoint(mmr, signer, prev=cp1, timestamp="2026-08-18T01:00:00Z")
        store.close()

        save_checkpoint(tmp_path, cp1)
        save_checkpoint(tmp_path, cp2)

        latest = load_latest_checkpoint(tmp_path)
        assert latest is not None
        assert latest.mmr_size == cp2.mmr_size

    def test_list_checkpoints_sorted(self, tmp_path):
        mmr, store, tmp = _make_mmr_with_leaves(5)
        signer = _make_signer()
        cp1 = emit_checkpoint(mmr, signer, timestamp="2026-08-18T00:00:00Z")

        for _i in range(2):
            capsule = _synthetic_capsule(
                operator="op", developer="dev", signer=signer, event="e", detail={}
            )
            mmr.append(capsule, consequential=False)

        cp2 = emit_checkpoint(mmr, signer, prev=cp1, timestamp="2026-08-18T01:00:00Z")
        store.close()

        save_checkpoint(tmp_path, cp1)
        save_checkpoint(tmp_path, cp2)

        sizes = list_checkpoints(tmp_path)
        assert sizes == sorted(sizes)
        assert cp1.mmr_size in sizes
        assert cp2.mmr_size in sizes

    def test_config_round_trip(self, tmp_path):
        cfg = CheckpointConfig(
            ts_urls=[DEFAULT_TS_URL, "https://other.ts.example"],
            cadence_entries=50,
            max_lag_entries=150,
        )
        save_config(tmp_path, cfg)
        from cll.ledger.checkpoint import load_config
        loaded = load_config(tmp_path)
        assert loaded is not None
        assert loaded.ts_urls == cfg.ts_urls
        assert loaded.cadence_entries == 50
        assert loaded.max_lag_entries == 150


# ---------------------------------------------------------------------------
# NOTE: capsule-ledger's own CLI smoke tests (checkpoint emit/status/verify)
# are NOT ported here -- cll ships no CLI. capsule-ledger's own test suite
# keeps that coverage, exercising its CLI against this package post-extraction.
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# Live network tests (skipped unless CAPSULE_TEST_LIVE_TS=1)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _LIVE_TS, reason="set CAPSULE_TEST_LIVE_TS=1 to run live TS tests")
class TestLiveTS:
    def test_end_to_end_emit_register_verify(self, tmp_path):
        """Full flow: emit → register at public anchor → verify receipt offline."""
        from cll.ledger.checkpoint import cache_ts_pubkey

        mmr, store, tmpd = _make_mmr_with_leaves(5)
        signer_obj = _make_signer("live-test-key")

        cp = emit_checkpoint(mmr, signer_obj, timestamp="2026-08-18T00:00:00Z")
        witness = register_checkpoint(cp, DEFAULT_TS_URL, timeout=30.0)
        cp.witnesses.append(witness)
        save_checkpoint(tmpd, cp)

        # Cache the TS authority public key.
        pem = cache_ts_pubkey(tmpd, DEFAULT_TS_URL)
        assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")

        # Verify receipt offline (no network needed after key is cached).
        ok, errors = verify_receipt_offline(witness, ts_pubkey_pem=pem)
        assert ok, f"offline verify failed: {errors}"

        store.close()
