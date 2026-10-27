# SPDX-License-Identifier: Apache-2.0
"""``cll.checkpoint.runner`` and ``cll.checkpoint.witness`` beyond the shared
vectors: configuration, corrupt state, contention, the run loops, the HTTP
client and the receipt verifier."""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from cll.checkpoint.cose_wire import verify_checkpoint_cose_offline
from cll.checkpoint.runner import CheckpointRunner, Ed25519CheckpointSigner, checkpoint_timestamp
from cll.checkpoint.witness import HttpWitnessClient, ReceiptVerifier, WitnessDeliveryRunner
from cll.log import (
    MAX_REASON_BYTES,
    AppendInput,
    ContentionError,
    CorruptError,
    InvalidError,
    RejectedError,
    WitnessReceipt,
)
from cll.log.memory import MemoryStore

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _wait_for(condition, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not reached"
        time.sleep(0.01)


def _signer(seed: int = 7) -> Ed25519CheckpointSigner:
    return Ed25519CheckpointSigner(Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32))


def _store(count: int) -> MemoryStore:
    store = MemoryStore()
    for byte in range(1, count + 1):
        store.append(AppendInput(bytes([byte]) * 32, T0))
    return store


def _checkpointed(count: int = 2, witness_ids=("w-a",)) -> tuple:
    store = _store(count)
    signer = _signer()
    runner = CheckpointRunner(store, signer, "log", witness_ids=witness_ids, cadence_entries=count)
    assert runner.run_once(T0)
    return store, signer, runner


# -- checkpoint runner -----------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"log_id": "bad id"},
        {"scan_limit": 0},
        {"scan_limit": 1001},
        {"cadence_entries": 0},
        {"cadence_age": timedelta(0)},
        {"poll_interval": timedelta(0)},
        {"witness_ids": ("w", "w")},
        {"witness_ids": ("bad id",)},
        {"witness_ids": tuple(f"w{index}" for index in range(33))},
    ],
)
def test_runner_rejects_invalid_configuration(kwargs):
    arguments = {"log_id": "log", **kwargs}
    log_id = arguments.pop("log_id")
    with pytest.raises(InvalidError):
        CheckpointRunner(MemoryStore(), _signer(), log_id, **arguments)


def test_signed_checkpoint_verifies_and_names_the_log():
    store, signer, _ = _checkpointed()
    state = store.load_cll()
    verified = verify_checkpoint_cose_offline(state.checkpoint.bytes)
    assert verified.ok, verified.errors
    assert verified.decoded.log_id == "log"
    assert verified.decoded.key_id == signer.key_id
    assert [row.witness_id for row in state.witnesses] == ["w-a"]


def test_naive_time_is_invalid():
    runner = CheckpointRunner(_store(1), _signer(), "log")
    with pytest.raises(InvalidError):
        runner.run_once(datetime(2026, 10, 1))


def test_checkpoint_timestamp_drops_zero_fraction_digits():
    assert checkpoint_timestamp(T0) == "2026-10-01T12:00:00Z"
    assert checkpoint_timestamp(T0 + timedelta(milliseconds=500)) == "2026-10-01T12:00:00.5Z"
    assert checkpoint_timestamp(T0 + timedelta(milliseconds=12)) == "2026-10-01T12:00:00.012Z"
    assert checkpoint_timestamp(datetime(5, 1, 2, tzinfo=timezone.utc)) == "0005-01-02T00:00:00Z"


def test_a_checkpoint_from_another_key_or_log_is_corrupt():
    store, _, _ = _checkpointed()
    with pytest.raises(CorruptError):
        CheckpointRunner(store, _signer(9), "log").run_once(T0)
    with pytest.raises(CorruptError):
        CheckpointRunner(store, _signer(), "other-log").run_once(T0)


def test_tampered_checkpoint_bytes_are_corrupt():
    store, signer, _ = _checkpointed()
    state = store.load_cll()
    tampered = bytearray(state.checkpoint.bytes)
    tampered[-1] ^= 1

    class Tampered(MemoryStore):
        def load_cll(self):
            current = store.load_cll()
            return replace(current, checkpoint=replace(current.checkpoint, bytes=bytes(tampered)))

        def scan_entries(self, after_seq, limit):
            return store.scan_entries(after_seq, limit)

    with pytest.raises(CorruptError):
        CheckpointRunner(Tampered(), signer, "log").run_once(T0)


def test_catch_up_stops_between_batches_once_asked():
    store = _store(5)
    stop = threading.Event()
    stop.set()
    CheckpointRunner(store, _signer(), "log", scan_limit=2)._catch_up(T0, stop)
    assert store.load_cll().indexed_seq == 2


def test_a_malformed_entry_value_is_corrupt():
    store = _store(1)

    class Short(MemoryStore):
        def load_cll(self):
            return store.load_cll()

        def scan_entries(self, after_seq, limit):
            return [replace(entry, value=b"short") for entry in store.scan_entries(after_seq, limit)]

    with pytest.raises(CorruptError):
        CheckpointRunner(Short(), _signer(), "log").run_once(T0)


def test_a_later_naive_entry_time_is_corrupt():
    store = _store(2)

    class Naive(MemoryStore):
        def load_cll(self):
            return store.load_cll()

        def scan_entries(self, after_seq, limit):
            first, second = store.scan_entries(after_seq, limit)
            return [first, replace(second, appended_at=second.appended_at.replace(tzinfo=None))]

    with pytest.raises(CorruptError):
        CheckpointRunner(Naive(), _signer(), "log").run_once(T0)


def test_inconsistent_index_is_corrupt():
    store = _store(1)

    class Broken(MemoryStore):
        def load_cll(self):
            return replace(store.load_cll(), indexed_seq=1)

    with pytest.raises(CorruptError):
        CheckpointRunner(Broken(), _signer(), "log").run_once(T0)


def test_non_contiguous_entries_are_corrupt():
    store = _store(2)

    class Gap(MemoryStore):
        def load_cll(self):
            return store.load_cll()

        def scan_entries(self, after_seq, limit):
            return store.scan_entries(after_seq, limit)[1:]

    with pytest.raises(CorruptError):
        CheckpointRunner(Gap(), _signer(), "log").run_once(T0)


def test_catch_up_reloads_once_after_contention():
    store = _store(3)
    other = CheckpointRunner(store, _signer(), "log", scan_limit=1)

    class Racing(MemoryStore):
        raced = False

        def load_cll(self):
            return store.load_cll()

        def scan_entries(self, after_seq, limit):
            return store.scan_entries(after_seq, limit)

        def commit_cll(self, expected_size, expected_checkpoint, next):
            if not Racing.raced:
                Racing.raced = True
                other.run_once(T0)  # another runner commits first
            store.commit_cll(expected_size, expected_checkpoint, next)

    CheckpointRunner(Racing(), _signer(), "log", scan_limit=1)._catch_up(T0)
    assert Racing.raced
    assert store.load_cll().indexed_seq == 3


def test_run_stops_and_wakes_on_notify():
    store = _store(2)
    runner = CheckpointRunner(store, _signer(), "log", cadence_entries=2, poll_interval=timedelta(hours=1))
    stop = threading.Event()
    thread = threading.Thread(target=runner.run, args=(stop,))
    thread.start()
    _wait_for(lambda: store.load_cll().checkpoint is not None)
    store.append(AppendInput(bytes([9]) * 32, T0))
    runner.notify()
    _wait_for(lambda: store.load_cll().indexed_seq == 3)
    stop.set()
    runner.notify()
    thread.join(timeout=5)
    assert not thread.is_alive()


# -- delivery runner -------------------------------------------------------------


class _Fixed:
    def __init__(self, outcome) -> None:
        self.outcome = outcome
        self.calls = 0

    def submit(self, checkpoint: bytes) -> WitnessReceipt:
        self.calls += 1
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome

    def verify(self, checkpoint: bytes, receipt: WitnessReceipt) -> None:
        if isinstance(self.outcome, BaseException):
            raise self.outcome


RECEIPT = WitnessReceipt(b"r", "ab" * 32, "legacy", 0, 1)


def _delivery(store, client, verifier=None, **kwargs) -> WitnessDeliveryRunner:
    return WitnessDeliveryRunner(store, {"w-a": client}, {"w-a": verifier or _Fixed(None)}, jitter=False, **kwargs)


@pytest.mark.parametrize(
    "clients,verifiers,kwargs",
    [
        ({}, {}, {}),
        ({"w-a": _Fixed(RECEIPT)}, {}, {}),
        ({"bad id": _Fixed(RECEIPT)}, {"bad id": _Fixed(None)}, {}),
        ({"w-a": _Fixed(RECEIPT)}, {"w-a": _Fixed(None)}, {"base_backoff": timedelta(0)}),
        ({"w-a": _Fixed(RECEIPT)}, {"w-a": _Fixed(None)}, {"max_backoff": timedelta(milliseconds=1)}),
    ],
)
def test_delivery_rejects_invalid_configuration(clients, verifiers, kwargs):
    with pytest.raises(InvalidError):
        WitnessDeliveryRunner(MemoryStore(), clients, verifiers, **kwargs)


@pytest.mark.parametrize(
    "error,permanent",
    [(ContentionError("busy"), False), (OSError("reset"), False), (RejectedError("no"), True), (ValueError("x"), True)],
)
def test_submit_failures_are_classified(error, permanent):
    store, _, _ = _checkpointed()
    assert _delivery(store, _Fixed(error)).run_once(T0) == 0
    row = store.load_cll().witnesses[0]
    assert (row.attempts, row.permanent, row.receipt) == (1, permanent, None)
    assert row.next_attempt_at == T0 + timedelta(seconds=1)


def test_a_stored_checkpoint_that_fails_verification_is_permanent_without_submitting():
    store, _, _ = _checkpointed()
    row = store.load_cll().witnesses[0]
    client = _Fixed(RECEIPT)

    class Bad(MemoryStore):
        def pending_witnesses(self, now, limit):
            return [replace(row, checkpoint=b"\x00")]

        def commit_witness(self, expected_attempts, next):
            store.commit_witness(expected_attempts, replace(next, checkpoint=row.checkpoint))

    assert _delivery(Bad(), client).run_once(T0) == 0
    assert client.calls == 0
    assert store.load_cll().witnesses[0].permanent


def test_last_error_is_bounded_valid_utf8():
    store, _, _ = _checkpointed()
    _delivery(store, _Fixed(ContentionError("é" * MAX_REASON_BYTES + "\ud800"))).run_once(T0)
    text = store.load_cll().witnesses[0].last_error
    assert len(text.encode("utf-8")) <= MAX_REASON_BYTES
    text.encode("utf-8")


def test_jitter_stays_below_the_backoff():
    store, _, _ = _checkpointed()
    runner = WitnessDeliveryRunner(store, {"w-a": _Fixed(ContentionError("busy"))}, {"w-a": _Fixed(None)})
    runner.run_once(T0)
    assert T0 <= store.load_cll().witnesses[0].next_attempt_at < T0 + timedelta(seconds=1)


def test_delivery_run_stops():
    store, _, _ = _checkpointed()
    runner = _delivery(store, _Fixed(RECEIPT), poll_interval=timedelta(hours=1))
    stop = threading.Event()
    thread = threading.Thread(target=runner.run, args=(stop,))
    thread.start()
    _wait_for(lambda: store.load_cll().witnesses[0].receipt == RECEIPT)
    stop.set()
    runner.notify()
    thread.join(timeout=5)
    assert not thread.is_alive()


# -- HTTP client -----------------------------------------------------------------


def _serve(status: int, body: bytes, headers: dict | None = None):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append((self.path, self.headers["Content-Type"], self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(status)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, requests


def _response(**overrides) -> bytes:
    body = {
        "receipt_b64": base64.b64encode(b"receipt").decode(),
        "entry_hash": "ab" * 32,
        "entry_hash_scheme": "legacy",
        "leaf_index": 0,
        "tree_size": 1,
        **overrides,
    }
    return json.dumps(body).encode()


def _statement() -> bytes:
    store, _, _ = _checkpointed()
    return store.load_cll().checkpoint.bytes


def test_client_posts_and_parses_a_receipt():
    statement = _statement()
    server, requests = _serve(200, _response())
    try:
        receipt = HttpWitnessClient(f"http://127.0.0.1:{server.server_port}/base/").submit(statement)
    finally:
        server.shutdown()
    assert receipt == WitnessReceipt(b"receipt", "ab" * 32, "legacy", 0, 1)
    assert requests == [("/base/checkpoints", "application/cll-checkpoint+cbor", statement)]


@pytest.mark.parametrize(
    "status,body,headers,error,reason",
    [
        (503, b"busy", None, ContentionError, "HTTP 503"),
        (429, b"", None, ContentionError, "HTTP 429"),
        (400, b"bad", None, RejectedError, "HTTP 400"),
        (302, b"", {"Location": "http://example.invalid/"}, RejectedError, "HTTP 302"),
        (200, b"not json", None, RejectedError, "invalid witness JSON"),
        (200, b"[]", None, RejectedError, "invalid witness response"),
        (200, _response(entry_hash_scheme="other"), None, RejectedError, "entry hash scheme"),
        (200, _response(entry_hash="AB" * 32), None, RejectedError, "invalid entry hash"),
        (200, _response(leaf_index=1, tree_size=1), None, RejectedError, "transparency position"),
        (200, _response(tree_size=True), None, RejectedError, "transparency position"),
        (200, _response(receipt_b64="!!"), None, RejectedError, "receipt base64"),
        (200, _response(receipt_b64=""), None, RejectedError, "receipt base64"),
    ],
)
def test_client_classifies_responses(status, body, headers, error, reason):
    statement = _statement()
    server, _ = _serve(status, body, headers)
    try:
        with pytest.raises(error, match=reason):
            HttpWitnessClient(f"http://127.0.0.1:{server.server_port}").submit(statement)
    finally:
        server.shutdown()


def test_client_bounds_the_response():
    statement = _statement()
    server, _ = _serve(200, _response())
    try:
        with pytest.raises(RejectedError, match="exceeds 64 bytes"):
            HttpWitnessClient(f"http://127.0.0.1:{server.server_port}", max_response_bytes=64).submit(statement)
    finally:
        server.shutdown()


@pytest.mark.parametrize("status", [200, 400])
def test_a_response_cut_off_mid_body_is_retryable(status):
    statement = _statement()

    class Truncating(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(status)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b'{"partial":')
            self.close_connection = True

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Truncating)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with pytest.raises(ContentionError):
            HttpWitnessClient(f"http://127.0.0.1:{server.server_port}").submit(statement)
    finally:
        server.shutdown()


def test_client_refuses_an_unverifiable_checkpoint_and_an_unreachable_witness():
    with pytest.raises(RejectedError):
        HttpWitnessClient("http://127.0.0.1:1").submit(b"\x00")
    with pytest.raises(ContentionError):
        HttpWitnessClient("http://127.0.0.1:1", timeout=2).submit(_statement())


@pytest.mark.parametrize("url", ["ftp://host", "http://", "http://user@host", "http://host?q", "http://host#f"])
def test_client_rejects_invalid_base_urls(url):
    with pytest.raises(InvalidError):
        HttpWitnessClient(url)


# -- receipt verifier ------------------------------------------------------------


def _authority():
    key = Ed25519PrivateKey.from_private_bytes(bytes([3]) * 32)
    return key, key.public_key().public_bytes_raw()


def _receipt_for(statement: bytes, key) -> WitnessReceipt:
    from scitt_cose import build_receipt

    decoded = verify_checkpoint_cose_offline(statement).decoded
    entry = hashlib.sha256(bytes.fromhex(decoded.to_checkpoint_record().digest())).hexdigest()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    raw = build_receipt(leaf_entry_hex=entry, leaf_index=0, tree_entries_hex=[entry], alg="EdDSA", log_private_key_pem=pem)
    return WitnessReceipt(raw, entry, "legacy", 0, 1)


def test_receipt_verifier_accepts_a_receipt_bound_to_the_checkpoint():
    key, public = _authority()
    statement = _statement()
    ReceiptVerifier(public).verify(statement, _receipt_for(statement, key))


def test_receipt_verifier_rejects_wrong_binding_scheme_and_key():
    key, public = _authority()
    statement = _statement()
    receipt = _receipt_for(statement, key)
    with pytest.raises(RejectedError):
        ReceiptVerifier(public).verify(statement, replace(receipt, entry_hash="cd" * 32))
    with pytest.raises(RejectedError):
        ReceiptVerifier(public).verify(statement, replace(receipt, entry_hash_scheme=None))
    with pytest.raises(RejectedError):
        ReceiptVerifier(bytes([1]) * 32).verify(statement, receipt)
    with pytest.raises(RejectedError, match="position"):
        ReceiptVerifier(public).verify(statement, replace(receipt, leaf_index=1, tree_size=2))
    with pytest.raises(InvalidError):
        ReceiptVerifier(b"short")
