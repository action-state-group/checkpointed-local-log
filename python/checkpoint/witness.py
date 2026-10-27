# SPDX-License-Identifier: Apache-2.0
"""``cll.checkpoint.witness`` -- witness delivery over a CLL backend.

A port of Go's ``witness`` package (``go/witness``): ``WitnessDeliveryRunner``
delivers the witness rows a ``CheckpointRunner`` queues, ``HttpWitnessClient``
posts a checkpoint statement to a witness's ``/checkpoints`` route, and
``ReceiptVerifier`` checks the returned receipt offline under a pinned
authority key.

A client raises ``cll.log.ContentionError`` for a failure worth retrying (a
timeout, a network error, HTTP 408, 429 or 5xx) and ``cll.log.RejectedError``
for a permanent one. The runner also retries ``OSError``, which is how
``urllib`` reports network failures, and treats any other exception, and
every verifier failure, as permanent. A retryable failure ends that
witness's pass; a later row for it waits for the next pass.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import random
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Mapping, Protocol

from ..log import (
    MAX_PORTABLE_INTEGER,
    MAX_REASON_BYTES,
    MAX_WITNESS_RESPONSE_BYTES,
    MAX_WITNESSES,
    ContentionError,
    InvalidError,
    RejectedError,
    WitnessReceipt,
    WitnessState,
    validate_identifier,
)
from ..log.wire import normalize_time
from .cose_wire import CLL_CHECKPOINT_CONTENT_TYPE, verify_checkpoint_cose_offline

__all__ = [
    "ENTRY_HASH_SCHEME_CHECKPOINT_DIGEST",
    "HttpWitnessClient",
    "ReceiptVerifier",
    "Submitter",
    "Verifier",
    "WitnessDeliveryRunner",
]

#: The witness protocol's label for a checkpoint digest registered as raw
#: bytes with the transparency log.
ENTRY_HASH_SCHEME_CHECKPOINT_DIGEST = "legacy"

_ENTRY_HASH = re.compile(r"[0-9a-f]{64}")


class Submitter(Protocol):
    """Sends a signed checkpoint statement to one witness."""

    def submit(self, checkpoint: bytes) -> WitnessReceipt: ...


class Verifier(Protocol):
    """Checks a receipt without trusting the witness that returned it;
    raises on failure."""

    def verify(self, checkpoint: bytes, receipt: WitnessReceipt) -> None: ...


def _checkpoint_entry_hash(checkpoint: bytes) -> str:
    """The witness log's entry hash for a verified checkpoint statement:
    SHA-256 of the checkpoint digest's bytes. Raises ``RejectedError`` if
    the statement does not verify."""
    verified = verify_checkpoint_cose_offline(checkpoint)
    if not verified.ok or verified.decoded is None:
        raise RejectedError(f"signed checkpoint failed verification: {verified.errors}")
    digest = verified.decoded.to_checkpoint_record().digest()
    return hashlib.sha256(bytes.fromhex(digest)).hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpWitnessClient:
    """Posts checkpoints to ``base_url + "/checkpoints"``. Redirects are not
    followed, the response is bounded by ``max_response_bytes``, and every
    receipt field the runner stores is validated."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        max_response_bytes: int = MAX_WITNESS_RESPONSE_BYTES,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise InvalidError("base URL must be an HTTP(S) origin or path")
        if not timeout > 0 or not 1 <= max_response_bytes <= MAX_WITNESS_RESPONSE_BYTES:
            raise InvalidError("witness timeout and response limit must be positive")
        self._endpoint = base_url.rstrip("/") + "/checkpoints"
        self._timeout = timeout
        self._max_bytes = max_response_bytes
        self._opener = urllib.request.build_opener(_NoRedirect)

    def submit(self, checkpoint: bytes) -> WitnessReceipt:
        _checkpoint_entry_hash(checkpoint)
        request = urllib.request.Request(
            self._endpoint,
            data=checkpoint,
            method="POST",
            headers={"Content-Type": CLL_CHECKPOINT_CONTENT_TYPE, "Accept": "application/json"},
        )
        try:
            try:
                with self._opener.open(request, timeout=self._timeout) as response:
                    status, raw = response.status, response.read(self._max_bytes + 1)
                    # A bounded read returns short, without raising, when the
                    # connection closes before the declared Content-Length.
                    if len(raw) <= self._max_bytes and (getattr(response, "length", None) or 0) > 0:
                        raise http.client.IncompleteRead(raw, response.length)
            except urllib.error.HTTPError as exc:
                status, raw = exc.code, exc.read(self._max_bytes + 1)
        except (OSError, http.client.HTTPException) as exc:
            # A refused or reset connection, a timeout, or a response cut off
            # mid-body: worth retrying.
            raise ContentionError(f"witness request failed: {exc}") from exc
        if len(raw) > self._max_bytes:
            raise RejectedError(f"witness response exceeds {self._max_bytes} bytes")
        if not 200 <= status < 300:
            message = f"witness returned HTTP {status}: {raw.decode('utf-8', 'replace').strip()}"
            if status in (408, 429) or status >= 500:
                raise ContentionError(message)
            raise RejectedError(message)
        return _parse_receipt(raw)


def _parse_receipt(raw: bytes) -> WitnessReceipt:
    try:
        wire = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RejectedError("invalid witness JSON response") from exc
    if not isinstance(wire, dict):
        raise RejectedError("invalid witness response")
    scheme = wire.get("entry_hash_scheme")
    if scheme != ENTRY_HASH_SCHEME_CHECKPOINT_DIGEST:
        raise RejectedError(f"unsupported entry hash scheme {scheme!r}")
    entry_hash = wire.get("entry_hash")
    if not isinstance(entry_hash, str) or _ENTRY_HASH.fullmatch(entry_hash) is None:
        raise RejectedError("invalid entry hash")
    leaf_index, tree_size = wire.get("leaf_index"), wire.get("tree_size")
    if (
        not all(isinstance(value, int) and not isinstance(value, bool) for value in (leaf_index, tree_size))
        or not 0 <= leaf_index < tree_size <= MAX_PORTABLE_INTEGER
    ):
        raise RejectedError("invalid transparency position")
    encoded = wire.get("receipt_b64")
    try:
        receipt = base64.b64decode(encoded, validate=True) if isinstance(encoded, str) else b""
    except binascii.Error:
        receipt = b""
    if not receipt:
        raise RejectedError("invalid receipt base64")
    return WitnessReceipt(receipt, entry_hash, scheme, leaf_index, tree_size)


class ReceiptVerifier:
    """Verifies RFC 9162 COSE receipts under a pinned Ed25519 authority key
    (the raw 32-byte public key), with ``scitt_cose.verify_receipt``."""

    def __init__(self, public_key: bytes) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
            raise InvalidError("pinned Ed25519 authority key is required")
        key = Ed25519PublicKey.from_public_bytes(bytes(public_key))
        self._pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    def verify(self, checkpoint: bytes, receipt: WitnessReceipt) -> None:
        from scitt_cose import verify_receipt

        if not 1 <= len(receipt.bytes) <= MAX_WITNESS_RESPONSE_BYTES:
            raise RejectedError("receipt size is invalid")
        if receipt.entry_hash_scheme != ENTRY_HASH_SCHEME_CHECKPOINT_DIGEST:
            raise RejectedError(f"unsupported receipt entry hash scheme {receipt.entry_hash_scheme!r}")
        entry_hash = _checkpoint_entry_hash(checkpoint)
        if receipt.entry_hash != entry_hash:
            raise RejectedError("entry hash does not bind signed checkpoint")
        result = verify_receipt(receipt.bytes, leaf_entry_hex=entry_hash, log_public_key_pem=self._pem)
        if not result.ok:
            raise RejectedError(f"receipt failed verification: {result.errors}")
        # The runner stores the response's position, so it must be the one the
        # signed proof carries.
        if result.tree_size != receipt.tree_size or result.leaf_index != receipt.leaf_index:
            raise RejectedError("receipt position mismatch")


def _bounded_text(value: str) -> str:
    """Error text that stays valid UTF-8 and within ``MAX_REASON_BYTES``
    once stored."""
    encoded = value.encode("utf-8", "replace")[:MAX_REASON_BYTES]
    return encoded.decode("utf-8", "ignore")


class WitnessDeliveryRunner:
    """Delivers pending witness rows from a ``cll.log.WitnessStateStore``.

    ``clients`` and ``verifiers`` map each witness ID to its ``Submitter``
    and ``Verifier``. Each pass handles witnesses concurrently and one
    witness's rows in order. A failed delivery is retried after
    ``base_backoff`` doubled per earlier attempt, capped at ``max_backoff``,
    and drawn uniformly below that when ``jitter`` is set.
    """

    def __init__(
        self,
        store,
        clients: Mapping[str, Submitter],
        verifiers: Mapping[str, Verifier],
        *,
        poll_interval: timedelta = timedelta(minutes=1),
        base_backoff: timedelta = timedelta(seconds=1),
        max_backoff: timedelta = timedelta(hours=1),
        jitter: bool = True,
    ) -> None:
        if (
            store is None
            or not isinstance(poll_interval, timedelta)
            or poll_interval <= timedelta(0)
            or not isinstance(base_backoff, timedelta)
            or base_backoff <= timedelta(0)
            or not isinstance(max_backoff, timedelta)
            or max_backoff < base_backoff
            or not 1 <= len(clients) <= MAX_WITNESSES
            or set(clients) != set(verifiers)
        ):
            raise InvalidError("invalid witness delivery configuration")
        for witness_id in clients:
            if not validate_identifier(witness_id) or clients[witness_id] is None or verifiers[witness_id] is None:
                raise InvalidError(f"invalid witness dependency for {witness_id!r}")
        self._store = store
        self._clients = dict(clients)
        self._verifiers = dict(verifiers)
        self._poll_interval = poll_interval.total_seconds()
        self._base_backoff = base_backoff
        self._max_backoff = max_backoff
        self._jitter = jitter
        self._lock = threading.Lock()
        self._wake = threading.Event()

    def notify(self) -> None:
        """Wake a running ``run`` loop without blocking the caller."""
        self._wake.set()

    def run(self, stop: threading.Event) -> None:
        """Deliver until ``stop`` is set. Contention is retried on the next
        wakeup."""
        while not stop.is_set():
            try:
                self.run_once()
            except ContentionError:
                pass
            self._wake.wait(self._poll_interval)
            self._wake.clear()

    def run_once(self, now: datetime | None = None, limit: int = MAX_WITNESSES) -> int:
        """Deliver the rows due at ``now``, at most ``limit``. Returns the
        number that received a verified receipt."""
        with self._lock:
            now = normalize_time(datetime.now(timezone.utc) if now is None else now)
            groups: dict = {}
            for item in self._store.pending_witnesses(now, limit):
                groups.setdefault(item.witness_id, []).append(item)
            if not groups:
                return 0
            with ThreadPoolExecutor(max_workers=len(groups)) as pool:
                futures = [pool.submit(self._deliver_all, now, items) for items in groups.values()]
                outcomes = [future.exception() or future.result() for future in futures]
            for outcome in outcomes:
                if isinstance(outcome, BaseException):
                    raise outcome
            return sum(outcomes)

    def _deliver_all(self, now: datetime, items: list) -> int:
        completed = 0
        for item in items:
            success, retryable = self._deliver(now, item)
            completed += success
            if retryable:
                break
        return completed

    def _deliver(self, now: datetime, item: WitnessState) -> tuple:
        client = self._clients.get(item.witness_id)
        verifier = self._verifiers.get(item.witness_id)
        if client is None or verifier is None:
            raise InvalidError(f"no configured client and verifier for witness {item.witness_id!r}")
        try:
            _checkpoint_entry_hash(item.checkpoint)
        except RejectedError:
            self._fail(now, item, True, "stored checkpoint failed verification")
            return False, False
        try:
            receipt = client.submit(item.checkpoint)
        except Exception as exc:  # noqa: BLE001 -- every failure is recorded on the row
            retryable = isinstance(exc, (ContentionError, OSError))
            self._fail(now, item, not retryable, str(exc))
            return False, retryable
        try:
            verifier.verify(item.checkpoint, receipt)
        except Exception as exc:  # noqa: BLE001 -- a verifier failure is permanent
            self._fail(now, item, True, str(exc))
            return False, False
        next_row = replace(
            item,
            attempts=item.attempts + 1,
            next_attempt_at=now,
            receipt=receipt,
            permanent=False,
            last_error=None,
        )
        self._store.commit_witness(item.attempts, next_row)
        return True, False

    def _fail(self, now: datetime, item: WitnessState, permanent: bool, reason: str) -> None:
        next_row = replace(
            item,
            attempts=item.attempts + 1,
            permanent=permanent,
            last_error=_bounded_text(reason),
            next_attempt_at=normalize_time(now + self._backoff(item.attempts)),
        )
        self._store.commit_witness(item.attempts, next_row)

    def _backoff(self, attempts: int) -> timedelta:
        delay = self._base_backoff
        for _ in range(attempts):
            if delay >= self._max_backoff:
                break
            delay = min(delay * 2, self._max_backoff)
        if self._jitter:
            delay = delay * random.random()
        return delay
