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
  - End to end against a local anchor on 127.0.0.1: register, cache the
    authority key, verify a real COSE receipt (no network)

**Ported from capsule-ledger in the CLL extraction (2026-09-01).**
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
import secrets
import tempfile
import threading
import unittest.mock as mock
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
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
    cache_ts_pubkey,
    emit_checkpoint,
    list_checkpoints,
    load_checkpoint,
    load_latest_checkpoint,
    load_ts_pubkey,
    register_checkpoint,
    save_checkpoint,
    save_config,
    verify_checkpoint_consistency,
    verify_checkpoint_signature,
    verify_receipt_offline,
)
from cll.ledger.store import LedgerStore


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
        "spec_version": "draft-mih-scitt-agent-action-capsule-04",
        "format_version": "4",
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

    def test_default_timestamp_is_whole_seconds_with_no_fraction(self):
        import re

        from tests.checkpoint.conftest import FakeLogSource, synthetic_capsule

        mmr = MmrLedger(FakeLogSource())
        for i in range(1, 4):
            mmr.append(synthetic_capsule(i), consequential=False)
        cp = emit_checkpoint(mmr, _make_signer())
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", cp.timestamp), cp.timestamp

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

        # Patch the receipt check (scitt_cose plus cll.ed25519) to return a success.
        with mock.patch("cll.ed25519.verify_receipt", return_value=fake_result):
            ok, errors = verify_receipt_offline(w, ts_pubkey_pem=b"FAKE_PEM")

        assert ok
        assert errors == []

    def test_returns_false_errors_on_bad_receipt(self):
        w = self._make_witness()
        # Patch scitt_cose.verify_receipt to return a failure result.
        fake_result = mock.MagicMock()
        fake_result.ok = False
        fake_result.errors = ["invalid alg"]

        with mock.patch("cll.ed25519.verify_receipt", return_value=fake_result):
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
# End to end against a local anchor (no network)
# ---------------------------------------------------------------------------


class _LocalAnchor:
    """A capsule-anchor stand-in on 127.0.0.1 serving the two routes this
    module calls: ``GET /anchor/authority-pubkey`` and ``POST /v1/digest``.
    Each POST appends ``sha256(digest)`` to its log and answers with a real
    COSE receipt over it, signed by a fresh Ed25519 authority key."""

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        key = Ed25519PrivateKey.generate()
        self.private_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        self.public_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        self.pubkey_hex = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self.entries: list[str] = []
        self.requests: list[tuple[str, str]] = []
        anchor = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                anchor.requests.append(("GET", self.path))
                if self.path != "/anchor/authority-pubkey":
                    self._reply(404, {"error": "not found"})
                    return
                self._reply(200, {"pubkey_hex": anchor.pubkey_hex, "key_id": anchor.pubkey_hex[:16]})

            def do_POST(self):
                anchor.requests.append(("POST", self.path))
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path != "/v1/digest":
                    self._reply(404, {"error": "not found"})
                    return
                self._reply(200, anchor.register(body["capsule_id"]))

            def _reply(self, status: int, obj: dict) -> None:
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def register(self, digest_hex: str) -> dict:
        from scitt_cose import build_receipt

        entry = hashlib.sha256(bytes.fromhex(digest_hex)).hexdigest()
        self.entries.append(entry)
        receipt = build_receipt(
            leaf_entry_hex=entry,
            leaf_index=len(self.entries) - 1,
            tree_entries_hex=list(self.entries),
            alg="EdDSA",
            log_private_key_pem=self.private_pem,
        )
        return {
            "entry_hash": entry,
            "receipt_b64": base64.b64encode(receipt).decode(),
            "leaf_index": len(self.entries) - 1,
            "tree_size": len(self.entries),
        }

    def close(self) -> None:
        if not self.thread.is_alive():
            return
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.fixture
def local_anchor(monkeypatch):
    # urllib sends even loopback requests through a proxy named in the
    # environment unless no_proxy exempts the host.
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.setenv(name, "127.0.0.1")
    anchor = _LocalAnchor()
    try:
        yield anchor
    finally:
        anchor.close()


class TestEndToEndLocalAnchor:
    def test_emit_register_cache_and_verify(self, local_anchor):
        """Emit, register, cache the authority key, reload it, verify the receipt."""
        mmr, store, root = _make_mmr_with_leaves(5)
        try:
            first = emit_checkpoint(mmr, _make_signer(), timestamp="2026-08-18T00:00:00Z")
            register_checkpoint(first, local_anchor.url)
            cp = emit_checkpoint(mmr, _make_signer(), timestamp="2026-08-18T00:00:01Z")
            witness = register_checkpoint(cp, local_anchor.url, timeout=5.0)
            cp.witnesses.append(witness)
            save_checkpoint(root, cp)

            assert witness.ts_url == local_anchor.url
            assert witness.entry_hash == hashlib.sha256(bytes.fromhex(cp.digest())).hexdigest()
            assert (witness.leaf_index, witness.tree_size) == (1, 2)
            assert load_checkpoint(root, cp.mmr_size).witnesses[0].entry_hash == witness.entry_hash

            assert load_ts_pubkey(root, local_anchor.url) is None
            pem = cache_ts_pubkey(root, local_anchor.url, timeout=5.0)
            assert pem == local_anchor.public_pem
            assert load_ts_pubkey(root, local_anchor.url) == pem
            assert load_ts_pubkey(root, "https://other.example") is None

            assert verify_receipt_offline(witness, ts_pubkey_pem=pem) == (True, [])
            # With no cached key it fetches the key from the witness's own URL.
            assert verify_receipt_offline(witness) == (True, [])
            assert local_anchor.requests == [
                ("POST", "/v1/digest"),
                ("POST", "/v1/digest"),
                ("GET", "/anchor/authority-pubkey"),
                ("GET", "/anchor/authority-pubkey"),
            ]
        finally:
            store.close()

    def test_receipt_fails_under_another_key_or_for_another_entry(self, local_anchor):
        mmr, store, _root = _make_mmr_with_leaves(3)
        try:
            cp = emit_checkpoint(mmr, _make_signer(), timestamp="2026-08-18T00:00:00Z")
            witness = register_checkpoint(cp, local_anchor.url)
        finally:
            store.close()

        other = _LocalAnchor()
        try:
            ok, errors = verify_receipt_offline(witness, ts_pubkey_pem=other.public_pem)
            assert not ok and errors
            # Fetching the key from another anchor fails the same way.
            ok, errors = verify_receipt_offline(witness, ts_base_url=other.url)
            assert not ok and errors
        finally:
            other.close()

        witness.entry_hash = "00" * 32
        ok, errors = verify_receipt_offline(witness, ts_pubkey_pem=local_anchor.public_pem)
        assert not ok and errors

    def test_unreachable_anchor_fails_closed(self, local_anchor, tmp_path):
        url = local_anchor.url
        local_anchor.close()
        witness = WitnessRecord(ts_url=url, entry_hash="ab" * 32, receipt_b64="", leaf_index=0, tree_size=1)
        ok, errors = verify_receipt_offline(witness, timeout=2.0)
        assert not ok and errors
        with pytest.raises(OSError):
            cache_ts_pubkey(tmp_path, url, timeout=2.0)
