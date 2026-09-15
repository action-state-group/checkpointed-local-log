# SPDX-License-Identifier: Apache-2.0
"""MMR peaks checkpoint: sign, register with a Transparency Service, verify.

**Distinct from, not a duplicate of, ``cll.checkpoint`` (``emit.py``).** This
module is capsule-ledger's own checkpoint/registration protocol, ported
alongside the ledger core it was written for: **HMAC-SHA256** operator
signing (via any ``Signer``-shaped object, not the Ed25519/COSE signer
``cll.checkpoint.emit`` uses) and registration against the **legacy**
capsule-anchor ``/v1/digest`` generic-digest-anchoring endpoint (not the
checkpoint-aware ``/checkpoints`` COSE route ``cll.checkpoint.emit.
register_checkpoint`` posts to — see the ``[witness-aac-deploy]`` two-stage
witness rollout). The two are wire-COMPATIBLE in field shape (both are the
Amendment E CLL checkpoint shape) but not the same object, the same
signature scheme, or the same registration protocol — so their same-named
classes (``CheckpointRecord`` etc.) intentionally live at a different module
path (``cll.ledger.checkpoint.*`` vs ``cll.checkpoint.*``) rather than being
merged. This module's genuinely non-duplicated contribution is the reusable
MMR math (imported from ``cll.checkpoint.core`` — see below, not
reimplemented) plus the on-disk checkpoint storage layout described below.

A *checkpoint* is a signed, tamper-evident snapshot of the MMR's current peak
set: ``{v, kind, log_id, mmr_size, root, prev_size, prev_root, key_id,
timestamp}`` — the CLL shape ratified in Amendment E, wire-identical to
``cll.checkpoint.CheckpointRecord`` and scitt-cose's
``cll.Checkpoint``. ``log_id`` identifies which log a checkpoint belongs to
in a multi-log/multi-peer deployment; single-node ``capsule-ledger`` always
emits ``log_id=""``. Registering the digest with a SCITT Transparency
Service (TS) yields a COSE Receipt that provides third-party freshness
evidence up to that checkpoint.

Verification chain (all links must hold):
  1. MMR inclusion-to-peak: any leaf under ``mmr_size`` is genuinely in the log
     (``MmrLedger.inclusion_proof`` + ``core.verify_inclusion``).
  2. Checkpoint signature: the peak set committed at ``mmr_size`` is operator-
     signed (``verify_checkpoint_signature``).
  3. TS receipt: the checkpoint digest appears in the TS's append-only log
     (``verify_receipt_offline`` via scitt-cose).
  4. Rollback detection: the current MMR's root at the *previous* checkpoint's
     size matches the previous checkpoint's stored root
     (``verify_checkpoint_consistency``).

External checkpointing is OPTIONAL. Once enabled: cadence + max-lag are
declared; sizes are monotonic; peak-consistency with the previous checkpoint is
enforced before each new checkpoint is accepted. The operator supplies their
own key and their own cron — timing-jitter or scheduling as a service is the
Cloud tier, not here.

Storage layout under ``<ledger_root>/checkpoints/``:
  config.json               — cadence + max-lag + TS URLs (written by ``init``)
  <mmr_size:020d>.json      — checkpoint record (JSON, includes witness list)

The checkpoint ``signature`` covers all fields except itself (deterministic
JSON, sort_keys=True); the digest registered with the TS is
``sha256(signing_body_utf8).hexdigest()`` — exactly 64 hex chars, matching the
capsule-anchor ``/v1/digest`` endpoint.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..checkpoint import core

if TYPE_CHECKING:
    from ..checkpoint import MmrLedger

__all__ = [
    "CheckpointConfig",
    "WitnessRecord",
    "CheckpointRecord",
    "CheckpointError",
    "RollbackError",
    "emit_checkpoint",
    "load_latest_checkpoint",
    "load_checkpoint",
    "list_checkpoints",
    "verify_checkpoint_signature",
    "verify_checkpoint_consistency",
    "verify_receipt_offline",
    "DEFAULT_TS_URL",
]

DEFAULT_TS_URL = "https://anchor.agentactioncapsule.org"
_CHECKPOINT_DIR_NAME = "checkpoints"
_CONFIG_FILE = "config.json"


class CheckpointError(RuntimeError):
    """A checkpoint operation failed for a non-integrity reason (config, I/O)."""


class RollbackError(RuntimeError):
    """The current MMR is inconsistent with a prior checkpoint (rollback detected)."""


@dataclass
class CheckpointConfig:
    """Operator-declared checkpointing policy (persisted as checkpoints/config.json)."""

    ts_urls: list[str] = field(default_factory=lambda: [DEFAULT_TS_URL])
    cadence_entries: int = 100
    max_lag_entries: int = 200

    def to_dict(self) -> dict:
        return {
            "ts_urls": self.ts_urls,
            "cadence_entries": self.cadence_entries,
            "max_lag_entries": self.max_lag_entries,
        }

    @classmethod
    def from_dict(cls, d: dict) -> CheckpointConfig:
        return cls(
            ts_urls=d.get("ts_urls", [DEFAULT_TS_URL]),
            cadence_entries=int(d.get("cadence_entries", 100)),
            max_lag_entries=int(d.get("max_lag_entries", 200)),
        )


@dataclass
class WitnessRecord:
    """Evidence that a checkpoint's digest was seen by one Transparency Service."""

    ts_url: str
    entry_hash: str  # sha256(bytes.fromhex(checkpoint_digest)).hex() — TS-derived
    receipt_b64: str  # base64-encoded COSE Receipt (COSE_Sign1, CBOR tag 18)
    leaf_index: int
    tree_size: int

    def to_dict(self) -> dict:
        return {
            "ts_url": self.ts_url,
            "entry_hash": self.entry_hash,
            "receipt_b64": self.receipt_b64,
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
        }

    @classmethod
    def from_dict(cls, d: dict) -> WitnessRecord:
        return cls(
            ts_url=d["ts_url"],
            entry_hash=d["entry_hash"],
            receipt_b64=d["receipt_b64"],
            leaf_index=int(d["leaf_index"]),
            tree_size=int(d["tree_size"]),
        )


@dataclass
class CheckpointRecord:
    """A signed snapshot of the MMR's peak set at ``mmr_size``.

    ``signature`` covers the signing body (all fields except ``signature`` and
    ``witnesses``, serialised as deterministic JSON). ``witnesses`` is populated
    after registration with one or more Transparency Services.

    Wire-identical to ``cll.checkpoint.CheckpointRecord`` and
    scitt-cose's ``cll.Checkpoint`` (Amendment E CLL shape). ``log_id``
    defaults to ``""``: single-node ``capsule-ledger`` never multiplexes
    logs, so every checkpoint it emits carries the empty log id.
    """

    v: int
    kind: str
    mmr_size: int
    root: str           # hex: root_from_peaks at mmr_size
    prev_size: int      # 0 for the first checkpoint
    prev_root: str      # hex root at prev_size; empty string for the first checkpoint
    key_id: str
    timestamp: str      # ISO 8601 UTC
    signature: str      # hex HMAC-SHA256 over signing_body
    log_id: str = ""     # "" for single-node; identifies the log in a multi-log deployment
    witnesses: list[WitnessRecord] = field(default_factory=list)

    def signing_body(self) -> str:
        """Canonical JSON over the fields covered by the signature."""
        body = {
            "v": self.v,
            "kind": self.kind,
            "log_id": self.log_id,
            "mmr_size": self.mmr_size,
            "root": self.root,
            "prev_size": self.prev_size,
            "prev_root": self.prev_root,
            "key_id": self.key_id,
            "timestamp": self.timestamp,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """64-char lowercase hex: sha256 of the signing body (UTF-8 encoded).

        This is what gets registered with the Transparency Service.
        """
        return hashlib.sha256(self.signing_body().encode()).hexdigest()

    def to_dict(self) -> dict:
        d = {
            "v": self.v,
            "kind": self.kind,
            "log_id": self.log_id,
            "mmr_size": self.mmr_size,
            "root": self.root,
            "prev_size": self.prev_size,
            "prev_root": self.prev_root,
            "key_id": self.key_id,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }
        if self.witnesses:
            d["witnesses"] = [w.to_dict() for w in self.witnesses]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> CheckpointRecord:
        witnesses = [WitnessRecord.from_dict(w) for w in d.get("witnesses", [])]
        return cls(
            v=int(d["v"]),
            kind=d["kind"],
            log_id=d.get("log_id", ""),
            mmr_size=int(d["mmr_size"]),
            root=d["root"],
            prev_size=int(d["prev_size"]),
            prev_root=d.get("prev_root", ""),
            key_id=d["key_id"],
            timestamp=d["timestamp"],
            signature=d["signature"],
            witnesses=witnesses,
        )


# -- signing / verification --------------------------------------------------


def _root_hex(mmr: MmrLedger, size: int) -> str:
    peak_positions = core.peaks(size)
    hashes = [mmr._nodes.node(p) for p in peak_positions]
    return core.root_from_peaks(hashes).hex()


def emit_checkpoint(
    mmr: MmrLedger,
    signer,
    *,
    prev: CheckpointRecord | None = None,
    timestamp: str | None = None,
    log_id: str = "",
) -> CheckpointRecord:
    """Build and sign a checkpoint from ``mmr``'s current state.

    ``signer`` is any object with ``key_id: str`` and ``sign(digest_hex: str) -> str``.
    ``prev`` is the previous checkpoint (for monotonicity + rollback detection).
    ``timestamp`` overrides the current UTC time (for deterministic tests).
    ``log_id`` defaults to ``""`` — single-node deployments never need to set it.

    Raises ``RollbackError`` if the MMR is inconsistent with ``prev``.
    """
    if timestamp is None:
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    current_size = mmr.size()
    if current_size == 0:
        raise CheckpointError("cannot checkpoint an empty MMR (no leaves appended yet)")

    prev_size = 0
    prev_root = ""

    if prev is not None:
        if current_size <= prev.mmr_size:
            raise RollbackError(
                f"MMR size {current_size} is not greater than previous checkpoint size "
                f"{prev.mmr_size} — monotonicity violated"
            )
        # Rollback detection: the current MMR's root at prev_size must match.
        actual_prev_root = _root_hex(mmr, prev.mmr_size)
        if actual_prev_root != prev.root:
            raise RollbackError(
                f"MMR root at prev_size={prev.mmr_size} is {actual_prev_root!r} "
                f"but prior checkpoint recorded {prev.root!r} — log has been mutated"
            )
        prev_size = prev.mmr_size
        prev_root = prev.root

    root_hex = _root_hex(mmr, current_size)

    # Build unsigned record so we can compute the signing body.
    cp = CheckpointRecord(
        v=1,
        kind="mmr_checkpoint",
        mmr_size=current_size,
        root=root_hex,
        prev_size=prev_size,
        prev_root=prev_root,
        key_id=signer.key_id,
        timestamp=timestamp,
        signature="",
        log_id=log_id,
    )
    sig = signer.sign(cp.digest())
    cp.signature = sig
    return cp


def verify_checkpoint_signature(cp: CheckpointRecord, signer) -> bool:
    """Recompute and compare the checkpoint's HMAC signature. Never raises."""
    try:
        expected = signer.sign(cp.digest())
        return cp.signature == expected
    except Exception:
        return False


def verify_checkpoint_consistency(prev: CheckpointRecord, current: CheckpointRecord, mmr: MmrLedger) -> bool:
    """Check that ``current`` extends ``prev`` without rollback.

    Recomputes the MMR's root at ``prev.mmr_size`` from the live node store and
    compares it against ``current.prev_root``. A mutated or rolled-back log
    produces a different root.
    """
    try:
        if current.prev_size != prev.mmr_size:
            return False
        if current.mmr_size <= prev.mmr_size:
            return False
        actual = _root_hex(mmr, prev.mmr_size)
        return actual == current.prev_root
    except Exception:
        return False


# -- TS registration ---------------------------------------------------------


def _fetch_ts_authority_pubkey(ts_base_url: str, *, timeout: float = 15.0) -> bytes:
    """Fetch the raw 32-byte Ed25519 public key from the TS authority-pubkey endpoint."""
    url = ts_base_url.rstrip("/") + "/anchor/authority-pubkey"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read())
    hex_key = body["pubkey_hex"]
    return bytes.fromhex(hex_key)


def _raw_ed25519_to_pem(raw: bytes) -> bytes:
    """Convert a raw 32-byte Ed25519 public key to SubjectPublicKeyInfo PEM."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PublicKey.from_public_bytes(raw)
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def register_checkpoint(
    cp: CheckpointRecord,
    ts_url: str = DEFAULT_TS_URL,
    *,
    timeout: float = 30.0,
) -> WitnessRecord:
    """POST the checkpoint digest to ``ts_url/v1/digest`` and return a WitnessRecord.

    The TS returns a COSE Receipt over the checkpoint's digest. The receipt proves
    that this checkpoint was seen by the TS at some point in its log.
    """
    digest = cp.digest()
    url = ts_url.rstrip("/") + "/v1/digest"
    payload = json.dumps({"capsule_id": digest}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise CheckpointError(f"TS returned HTTP {exc.code}: {detail}") from exc

    return WitnessRecord(
        ts_url=ts_url,
        entry_hash=body["entry_hash"],
        receipt_b64=body["receipt_b64"],
        leaf_index=int(body["leaf_index"]),
        tree_size=int(body["tree_size"]),
    )


def verify_receipt_offline(
    witness: WitnessRecord,
    *,
    ts_pubkey_pem: bytes | str | None = None,
    ts_base_url: str | None = None,
    timeout: float = 15.0,
) -> tuple[bool, list[str]]:
    """Verify a COSE Receipt offline (no network unless pubkey must be fetched).

    Provide exactly one of ``ts_pubkey_pem`` (cached PEM bytes/str) or
    ``ts_base_url`` (fetches the key once; requires network). Returns
    ``(ok, errors)`` — never raises.
    """
    try:
        from scitt_cose import verify_receipt
    except ImportError:
        return False, ["scitt-cose is not installed; run: pip install 'checkpointed-local-log[checkpoint]'"]

    try:
        import base64

        if ts_pubkey_pem is None:
            if ts_base_url is None:
                ts_base_url = witness.ts_url
            raw = _fetch_ts_authority_pubkey(ts_base_url, timeout=timeout)
            ts_pubkey_pem = _raw_ed25519_to_pem(raw)

        receipt_bytes = base64.b64decode(witness.receipt_b64)
        result = verify_receipt(
            receipt_bytes,
            leaf_entry_hex=witness.entry_hash,
            log_public_key_pem=ts_pubkey_pem,
        )
        return result.ok, result.errors
    except Exception as exc:
        return False, [str(exc)]


# -- storage -----------------------------------------------------------------


def _checkpoint_dir(ledger_root: Path) -> Path:
    return ledger_root / _CHECKPOINT_DIR_NAME


def _checkpoint_path(ledger_root: Path, mmr_size: int) -> Path:
    return _checkpoint_dir(ledger_root) / f"{mmr_size:020d}.json"


def save_config(ledger_root: Path, cfg: CheckpointConfig) -> None:
    d = _checkpoint_dir(ledger_root)
    d.mkdir(parents=True, exist_ok=True)
    (d / _CONFIG_FILE).write_text(json.dumps(cfg.to_dict(), indent=2))


def load_config(ledger_root: Path) -> CheckpointConfig | None:
    cfg_path = _checkpoint_dir(ledger_root) / _CONFIG_FILE
    if not cfg_path.exists():
        return None
    return CheckpointConfig.from_dict(json.loads(cfg_path.read_text()))


def save_checkpoint(ledger_root: Path, cp: CheckpointRecord) -> Path:
    d = _checkpoint_dir(ledger_root)
    d.mkdir(parents=True, exist_ok=True)
    p = _checkpoint_path(ledger_root, cp.mmr_size)
    p.write_text(json.dumps(cp.to_dict(), indent=2))
    return p


def load_checkpoint(ledger_root: Path, mmr_size: int) -> CheckpointRecord | None:
    p = _checkpoint_path(ledger_root, mmr_size)
    if not p.exists():
        return None
    return CheckpointRecord.from_dict(json.loads(p.read_text()))


def list_checkpoints(ledger_root: Path) -> list[int]:
    """Return sorted list of MMR sizes for which checkpoints exist."""
    d = _checkpoint_dir(ledger_root)
    if not d.exists():
        return []
    sizes = []
    for p in sorted(d.glob("*.json")):
        if p.name == _CONFIG_FILE:
            continue
        try:
            sizes.append(int(p.stem))
        except ValueError:
            continue
    return sorted(sizes)


def load_latest_checkpoint(ledger_root: Path) -> CheckpointRecord | None:
    sizes = list_checkpoints(ledger_root)
    if not sizes:
        return None
    return load_checkpoint(ledger_root, sizes[-1])


def cache_ts_pubkey(ledger_root: Path, ts_url: str, *, timeout: float = 15.0) -> bytes:
    """Fetch and locally cache the TS authority public key as PEM.

    Returns the raw PEM bytes. Subsequent offline verifications can read the
    cached file instead of fetching again.
    """
    raw = _fetch_ts_authority_pubkey(ts_url, timeout=timeout)
    pem = _raw_ed25519_to_pem(raw)
    d = _checkpoint_dir(ledger_root)
    d.mkdir(parents=True, exist_ok=True)
    safe_name = ts_url.rstrip("/").replace("://", "_").replace("/", "_").replace(".", "_")
    p = d / f"ts_pubkey_{safe_name}.pem"
    p.write_bytes(pem)
    return pem


def load_ts_pubkey(ledger_root: Path, ts_url: str) -> bytes | None:
    """Load a cached TS authority public key (PEM), or None if not cached."""
    safe_name = ts_url.rstrip("/").replace("://", "_").replace("/", "_").replace(".", "_")
    p = _checkpoint_dir(ledger_root) / f"ts_pubkey_{safe_name}.pem"
    if not p.exists():
        return None
    return p.read_bytes()
