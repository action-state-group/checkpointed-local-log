# SPDX-License-Identifier: Apache-2.0
"""Signed peaks-checkpoint emission, TS registration, and offline verification.

A *checkpoint* is a signed, tamper-evident snapshot of one log's MMR peak set:
``{log_id, mmr_size, root, prev_size, prev_root, key_id, timestamp}``.
Registering its digest with a SCITT Transparency Service (TS)
yields a COSE Receipt that provides third-party freshness evidence up to that
checkpoint.

This is the CLL (Checkpointed Local Log) checkpoint shape ratified in
Amendment E: the ``capsule-ledger`` shape shipped in ``ldg-peaks-checkpoint-
emit`` (2026-08-18), plus ``log_id`` -- the field a multi-log or multi-peer
deployment (e.g. a mesh node checkpointing several independent streams) needs
to tell checkpoints apart. ``key_id`` doubles as a peer identifier in that
setting: it is whatever label the signer's own key is registered under, and a
per-peer signing key makes ``key_id`` and "which peer wrote this" the same
fact.

Verification chain (all links must hold):
  1. MMR inclusion-to-peak: any leaf under ``mmr_size`` is genuinely in the
     log (``MmrLedger.inclusion_proof`` + ``core.verify_inclusion``).
  2. Checkpoint signature: the peak set committed at ``mmr_size`` is
     operator-signed (``verify_checkpoint_signature`` for the producer's own
     round-trip check with a live ``Signer``; ``verify_checkpoint_signature_offline``
     for a stranger holding only the checkpoint bytes -- see below).
  3. TS receipt: the checkpoint digest appears in the TS's append-only log
     (``verify_receipt_offline`` via scitt-cose).
  4. Rollback detection: the current MMR's root at the *previous*
     checkpoint's size matches the previous checkpoint's stored root
     (``verify_checkpoint_consistency``).

These four links are still four separate, caller-composed primitives here --
this module never assembles them itself. ``capsule_emit.bundle.bundle()``
(O16 audit item 14) is what assembles all of them, plus the record's own
receipt and the prior checkpoint's consistency proof, into ONE
standalone-verifiable artifact for one record; ``capsule_emit.bundle
.verify_bundle()`` is the composed offline check. Reach for the primitives
directly only when you want something other than "verify one record's
bundle" (e.g. checking a checkpoint chain's rollback-freedom on its own).

These functions are OPTIONAL and OFF by default when used directly -- nothing
in this module makes a network call unless the caller invokes
``register_checkpoint`` or ``verify_receipt_offline(ts_base_url=...)``. Once
enabled: cadence and max-lag are declared via ``CheckpointConfig``; sizes are
monotonic; peak-consistency with the previous checkpoint is enforced before
each new checkpoint is accepted (``RollbackError``). The operator supplies
their own signing key and their own schedule (a cron, a timer, whatever the
deployment already has) -- timing-jitter or scheduling as an operated service
is explicitly out of scope here.

Since 0.5.0, ``capsule_emit.core.emit()``'s default path drives these same
functions automatically once a ledger forms a checkpoint-worthy stream --
see ``capsule_emit.witness``. That is a caller of this module, not a change
to it: everything above stays true for direct/manual use — nothing here
reaches for a signing key, a schedule, or the network on its own.

The free public-good witness tier lives at ``DEFAULT_TS_URL``
(``witness.agentactioncapsule.org`` -- semantically a witness, not the
anchor; see ``_PENDING_CNAME_TARGETS`` below for its current DNS status)
-- prefilled as the config default so a caller who wants it need not look it
up, but never contacted unless ``register_checkpoint``/``verify_receipt_offline``
is actually called, and freely substitutable with any conforming Transparency
Service. A generated config file should show it commented out (see
``EXAMPLE_CONFIG_TOML``), so opting in is an explicit uncomment, not a silent
default.

``register_checkpoint`` POSTs the checkpoint to the TS's ``/checkpoints``
route (single-host ruling, 2026-08-27) -- never ``/register``, the opt-in
per-record digest route; see :data:`_CHECKPOINT_ROUTE` below and
``capsule_emit.witness``'s no-egress guarantee. The checkpoint ``signature``
covers all fields except itself and ``witnesses`` (deterministic JSON,
``sort_keys=True``); the digest the TS's own receipt commits to is
``sha256(signing_body_utf8).hexdigest()`` -- exactly 64 hex chars.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from .index import MmrLedger

__all__ = [
    "CheckpointConfig",
    "Grade",
    "StampVerdict",
    "WitnessRecord",
    "CheckpointRecord",
    "Signer",
    "CheckpointError",
    "RollbackError",
    "emit_checkpoint",
    "verify_checkpoint_signature",
    "verify_checkpoint_consistency",
    "register_checkpoint",
    "register_checkpoint_stub",
    "verify_receipt_offline",
    "verify_checkpoint_signature_offline",
    "verify_witness_stamp_offline",
    "verify_witness_stamp_tristate",
    "due_for_checkpoint",
    "lag_exceeded",
    "DEFAULT_TS_URL",
    "DEFAULT_TS_PUBLIC_KEY_PEM",
    "DEFAULT_TS_PUBLIC_KEY_ID",
    "STUB_TS_URL",
    "STUB_MARKER",
    "EXAMPLE_CONFIG_TOML",
]

DEFAULT_TS_URL = "https://witness.agentactioncapsule.org"

#: The default free public-good witness's Ed25519 public key, PINNED so the
#: DEFAULT read path (``verify_witness_stamp_offline``/``grade()`` called
#: with no caller-supplied ``ts_pubkey_pem``) can tell "a stamp this exact
#: witness actually signed" apart from "a receipt shape that merely
#: reconstructs a root, from any key at all" -- closing the sophisticated
#: file-forger the naive [stamp-authenticity-on-read-not-presence] fix left
#: open (a forger with the *public* ``scitt_cose.build_receipt`` mints a
#: well-formed single-leaf receipt over the correct ``entry_hash``, signed
#: with a key of their own choosing; without a pin, structural root
#: reconstruction alone is key-independent and cannot tell that apart from
#: the real thing). Only ``WitnessRecord``s whose ``ts_url`` equals
#: ``DEFAULT_TS_URL`` exactly are matched against this pin -- an attacker
#: cannot make an unrelated stamp match it just by relabelling ``ts_url``,
#: since the pinned key itself is fixed here, not derived from the record.
#:
#: Fetched 2026-08-24 from the live ``GET /anchor/authority-pubkey`` endpoint
#: (``anchor.agentactioncapsule.org`` -- the host ``DEFAULT_TS_URL`` currently
#: dispatches to per ``_PENDING_CNAME_TARGETS``) over HTTPS, and cross-checked
#: against that same response's ``key_id`` (``sha256(pubkey)[:16]``, matching
#: capsule-anchor's own ``StaticKeyProvider.active_key_id()`` derivation --
#: see capsule-anchor's ``deploy/KEY-MANAGEMENT.md``) before being committed
#: here -- self-consistency the response could not fake without also holding
#: the private key.
#:
#: Rotates only on an operator-announced capsule-anchor key rotation
#: (KEY-MANAGEMENT.md's rotation procedure). A stale pin fails CLOSED: a
#: checkpoint witnessed under a rotated key demotes to "TS identity
#: unverified" (self-attested) rather than silently accepting the wrong key
#: -- update both constants below together when that happens.
DEFAULT_TS_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAObtlTJ3Ar+HA7e8N7/qmkJm4UYg2ybom4EkVNYQPlrU=
-----END PUBLIC KEY-----
"""

#: ``sha256(<raw 32-byte pubkey>)[:16]`` for :data:`DEFAULT_TS_PUBLIC_KEY_PEM`
#: -- matches the ``key_id`` capsule-anchor's own ``/anchor/authority-pubkey``
#: and ``/health`` endpoints publish for the current signing key. Not used
#: for verification itself (the PEM is); kept alongside it so a future
#: rotation editing one constant without the other is easy to catch by eye
#: or a test, rather than silently pinning a key whose recorded id lies.
DEFAULT_TS_PUBLIC_KEY_ID = "19a9ab3e02fad55c"

#: [currently anchor., domain mapping pending] ``witness.agentactioncapsule.org``
#: is the checkpoint-primary name for the SAME capsule-anchor service
#: ``anchor.agentactioncapsule.org`` already runs (single-host ruling,
#: 2026-08-27: one deployment, two routes -- ``/checkpoints`` default,
#: ``/register`` opt-in) -- but the ``witness.aac`` hostname itself has no DNS
#: record yet. Until Steven maps the domain, a request to the *default* URL is
#: dispatched to the anchor host directly (which already answers
#: ``/checkpoints`` -- same code, same deployment) so registration keeps
#: working today; an explicit non-default ``ts_url`` is never rewritten.
#: Remove this indirection once the ``witness.aac`` domain mapping is live.
_PENDING_CNAME_TARGETS = {DEFAULT_TS_URL: "https://anchor.agentactioncapsule.org"}

#: A generated-config snippet: the witness URL is prefilled with the free
#: public-good tier but shipped COMMENTED OUT, so registration stays opt-in
#: even when a caller copies this block verbatim. Any conforming TS may be
#: substituted for the URL.
EXAMPLE_CONFIG_TOML = f"""\
[checkpoint]
cadence_entries = 100
cadence_seconds = 900  # 15 minutes -- age leg; only fires with unwitnessed entries
max_lag_entries = 200
# ts_urls = ["{DEFAULT_TS_URL}"]
"""


class CheckpointError(RuntimeError):
    """A checkpoint operation failed for a non-integrity reason (config, network)."""


class RollbackError(RuntimeError):
    """The current MMR is inconsistent with a prior checkpoint (rollback detected)."""


class Signer(Protocol):
    """Any object with a stable ``key_id`` and a ``sign(digest_hex) -> str``
    method. Never imported concretely by this module -- bring your own key
    management."""

    key_id: str

    def sign(self, digest_hex: str) -> str: ...


@dataclass
class CheckpointConfig:
    """Operator-declared checkpointing policy: cadence, max lag, and which
    Transparency Service(s) to register with. ``ts_urls`` is empty by
    default -- registration is opt-in, never assumed."""

    ts_urls: list[str] = field(default_factory=list)
    cadence_entries: int = 100
    cadence_seconds: int = 900  # 15 minutes -- age leg, see due_for_checkpoint
    max_lag_entries: int = 200

    def to_dict(self) -> dict:
        return {
            "ts_urls": self.ts_urls,
            "cadence_entries": self.cadence_entries,
            "cadence_seconds": self.cadence_seconds,
            "max_lag_entries": self.max_lag_entries,
        }

    @classmethod
    def from_dict(cls, d: dict) -> CheckpointConfig:
        return cls(
            ts_urls=list(d.get("ts_urls", [])),
            cadence_entries=int(d.get("cadence_entries", 100)),
            cadence_seconds=int(d.get("cadence_seconds", 900)),
            max_lag_entries=int(d.get("max_lag_entries", 200)),
        )


def due_for_checkpoint(
    cfg: CheckpointConfig,
    entries_since_last: int,
    *,
    seconds_since_last: float | None = None,
) -> bool:
    """True once ``entries_since_last`` reaches the declared cadence, or
    ``seconds_since_last`` reaches ``cfg.cadence_seconds`` -- whichever comes
    first ("100 entries or 15 minutes", frozen surface §0, both configurable).

    The age leg only ever applies when there is at least one unwitnessed
    entry: with ``entries_since_last == 0`` this is always ``False``
    regardless of ``seconds_since_last`` -- an idle log is silent, never a
    heartbeat. Callers driving their own cron/timer should pass
    ``seconds_since_last`` as the time since the first unwitnessed entry
    (not since the last check) to get this behavior; omitting it falls back
    to the entry-count leg alone, matching the pre-existing signature.
    """
    if entries_since_last <= 0:
        return False
    if entries_since_last >= cfg.cadence_entries:
        return True
    return seconds_since_last is not None and seconds_since_last >= cfg.cadence_seconds


def lag_exceeded(cfg: CheckpointConfig, entries_since_last: int) -> bool:
    """True once ``entries_since_last`` exceeds the declared max lag -- the
    caller's signal that the checkpoint is now overdue, not just due."""
    return entries_since_last > cfg.max_lag_entries


class Grade(str, Enum):
    """A checkpoint's position on the ladder (frozen surface §4):
    ``self-attested`` until at least one REAL witness stamp lands, then
    ``witnessed`` -- an any-of transition (§2a.3): the first stamp flips the
    grade, additional stamps only ever compound independence, never gate it.
    A stub stamp (``WitnessRecord.is_stub``, see ``capsule_emit.witness``'s
    ``CAPSULE_WITNESS=stub`` mode) never counts toward this any-of -- frozen
    surface §1a.4: "stub stamps never reach rung 2, because a rung you can
    grant yourself isn't a rung." ``countersigned``, the ladder's third rung,
    is a distinct mechanism (a counterparty/operator receipt citing this one,
    not a witness stamp) and has no representation here."""

    SELF_ATTESTED = "self-attested"
    WITNESSED = "witnessed"


class StampVerdict(str, Enum):
    """Three-state per-stamp verdict [verify-threestate-trustanchor] --
    finer-grained than :func:`verify_witness_stamp_offline`'s ``bool``,
    which two-rung callers (``grade()``) still use unchanged. Callers that
    must tell "no trust anchor for this witness" apart from "this witness's
    signature is wrong" -- ``verify_bundle``/``verify_disclosure``, deciding
    whether an unverifiable stamp is fatal to the artifact -- read this
    instead. See :func:`verify_witness_stamp_tristate`.
    """

    WITNESSED = "witnessed"
    """Stamp verifies under a supplied or pinned trust-anchor key."""

    UNVERIFIED = "unverified"
    """Well-formed, checkpoint-bound stamp from a TS with no pin supplied --
    NOT evidence of forgery, just evidence we cannot check. A self-hosted/
    zero-egress TS a caller has not (yet) pinned lands here, never
    ``INVALID`` -- conflating the two false-accused exactly the deployments
    frozen §1a.2 promises zero-egress operation to."""

    INVALID = "invalid"
    """Either not even a well-formed, checkpoint-bound stamp (garbage bytes,
    wrong ``entry_hash``, undecodable COSE), or a stamp claiming a KNOWN/
    pinned TS whose signature fails to verify under that pin -- forgery."""


@dataclass
class WitnessRecord:
    """Evidence that a checkpoint's digest was seen by one Transparency Service.

    ``is_stub`` marks a record produced by the in-process stub witness
    (``CAPSULE_WITNESS=stub`` -- see ``capsule_emit.witness`` and frozen
    dev-surface §1a.4) rather than a real Transparency Service. It is a
    convenience flag for this codebase's own grade computation
    (:meth:`CheckpointRecord.grade`) and rendering -- **not** the normative
    stub marker itself. The normative marker's name and value (``cll-stub``
    / ``true``, see ``STUB_MARKER``) are now fixed by the CLL I-D
    (draft-mih-scitt-checkpointed-local-log-00, "Stub Countersignatures"),
    but the wire encoding is still pending separate COSE-wire work -- once
    that lands, a stub-produced ``receipt_b64``/``entry_hash`` carries the
    real COSE protected-header parameter directly, so a third-party verifier
    who has never read this codebase can still tell a stub record apart from
    a real one from the bytes alone. Until then, ``receipt_b64`` holds an
    interim JSON placeholder using that same marker name/value (see
    :func:`register_checkpoint_stub`) -- it cannot pass as a real COSE
    Receipt, so ``verify_receipt_offline`` fails closed on it rather than
    mistaking it for one.
    """

    ts_url: str
    entry_hash: str  # sha256(bytes.fromhex(checkpoint_digest)).hex() -- TS-derived
    receipt_b64: str  # base64-encoded COSE Receipt (COSE_Sign1, CBOR tag 18)
    leaf_index: int
    tree_size: int
    is_stub: bool = False

    def to_dict(self) -> dict:
        d = {
            "ts_url": self.ts_url,
            "entry_hash": self.entry_hash,
            "receipt_b64": self.receipt_b64,
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
        }
        if self.is_stub:
            d["is_stub"] = True
        return d

    @classmethod
    def from_dict(cls, d: dict) -> WitnessRecord:
        return cls(
            ts_url=d["ts_url"],
            entry_hash=d["entry_hash"],
            receipt_b64=d["receipt_b64"],
            leaf_index=int(d["leaf_index"]),
            tree_size=int(d["tree_size"]),
            is_stub=bool(d.get("is_stub", False)),
        )


@dataclass
class CheckpointRecord:
    """A signed snapshot of one log's MMR peak set at ``mmr_size``.

    ``signature`` covers the signing body (every field below except
    ``signature`` and ``witnesses``, serialised as deterministic JSON).
    ``witnesses`` is populated after registration with one or more
    Transparency Services.
    """

    v: int
    kind: str
    log_id: str
    mmr_size: int
    root: str  # hex: root_from_peaks at mmr_size (32B)
    prev_size: int  # 0 for the first checkpoint
    prev_root: str  # hex root at prev_size; empty string for the first checkpoint
    key_id: str  # signer's key id; doubles as peer id in a multi-peer deployment
    timestamp: str  # ISO 8601 UTC
    signature: str  # hex signature (Ed25519 by default, see checkpoint.emit.Signer) over signing_body
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

    def entry_digest(self) -> str:
        """64-char lowercase hex: sha256 of the FULL persisted entry --
        ``to_dict()`` (signing body, ``signature``, and ``witnesses`` alike),
        canonical JSON, ``sort_keys=True``.

        This -- not ``digest()`` -- is the value the checkpoint's own ledger
        stamp commits to the MMR as (see ``capsule_emit.witness
        ._persist_checkpoint_stamp``): the stamp's leaf must cover the entry
        AS PERSISTED, including ``witnesses``, so that flipping or deleting a
        byte in a persisted stamp's ``witnesses`` changes this leaf and
        breaks the covering checkpoint's root. ``digest()`` deliberately
        excludes ``signature``/``witnesses`` (it is the value the signature
        itself covers, and what is registered with the TS) and stays
        unchanged for that purpose.
        """
        body = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()

    def grade(self, *, ts_pubkey_pem: bytes | str | None = None) -> Grade:
        """This checkpoint's ladder position: ``WITNESSED`` once any-of
        ``witnesses`` holds at least one REAL (non-stub) stamp that ALSO
        verifies as an authentic, checkpoint-bound TS Receipt via
        :func:`verify_witness_stamp_offline` -- not merely present in the
        list, and not a stub. A file-level forger who hand-appends a
        fabricated ``WitnessRecord`` (no real Transparency Service ever
        contacted) grades ``SELF_ATTESTED``: presence in ``witnesses`` alone
        no longer counts as "valid stamp" (closes
        [stamp-authenticity-on-read-not-presence] -- presence-equals-success
        is a produce-side invariant that does not bind a file-level reader).
        Any-of semantics are unchanged (§2a.3): the first VALID, non-stub
        stamp flips the grade; additional stamps, valid or not, never gate
        it.

        Stub-sourced records (``is_stub=True``, ``CAPSULE_WITNESS=stub``)
        are excluded from this any-of explicitly, by design -- not merely
        as an incidental effect of their placeholder ``receipt_b64`` failing
        COSE-shape verification. The stub proves the mechanics work, never
        that a third party saw anything (frozen surface §1a.4); a future
        real COSE-wire stub encoding that happened to parse structurally
        must still never grade WITNESSED.

        Without ``ts_pubkey_pem``, a stamp from the pinned default witness
        (``DEFAULT_TS_URL``) is still signature-verified automatically; any
        other unpinned ``ts_url`` confirms structural + checkpoint-binding
        authenticity only, which is not enough to grade WITNESSED -- see
        :func:`verify_witness_stamp_offline` for exactly what each tier does
        and does not prove. Pass a caller-pinned/cached TS public key for the
        full identity-bound guarantee against a non-default witness.

        Two rungs here is correct, not a truncated ladder: the CLL ladder
        has three (self-attested / witnessed / countersigned), but
        ``countersigned`` is a receipt-level property produced by a
        counterparty/operator's countersign path over an already-issued
        receipt -- a fact about a receipt, not about a checkpoint -- so it
        has no representation on a `CheckpointRecord`'s own grade. A caller
        wanting the third rung reads it off the countersigned receipt
        directly, not off this method.
        """
        return (
            Grade.WITNESSED
            if any(
                not w.is_stub
                and verify_witness_stamp_offline(self, w, ts_pubkey_pem=ts_pubkey_pem)[0]
                for w in self.witnesses
            )
            else Grade.SELF_ATTESTED
        )

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
            log_id=d["log_id"],
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
    from . import core

    return core.root_from_peaks(mmr.peak_hashes_at(size)).hex()


def emit_checkpoint(
    mmr: MmrLedger,
    signer: Signer,
    *,
    log_id: str,
    prev: CheckpointRecord | None = None,
    timestamp: str | None = None,
) -> CheckpointRecord:
    """Build and sign a checkpoint from ``mmr``'s current state for ``log_id``.

    ``prev`` is the previous checkpoint for this same ``log_id`` (for
    monotonicity + rollback detection). ``timestamp`` overrides the current
    UTC time (for deterministic tests).

    Raises ``RollbackError`` if the MMR is inconsistent with ``prev``, or
    ``CheckpointError`` if ``prev`` belongs to a different log.
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
        if prev.log_id != log_id:
            raise CheckpointError(
                f"prev checkpoint belongs to log_id={prev.log_id!r}, not {log_id!r}"
            )
        if current_size <= prev.mmr_size:
            raise RollbackError(
                f"MMR size {current_size} is not greater than previous checkpoint size "
                f"{prev.mmr_size} -- monotonicity violated"
            )
        # Rollback detection: the current MMR's root at prev_size must match.
        actual_prev_root = _root_hex(mmr, prev.mmr_size)
        if actual_prev_root != prev.root:
            raise RollbackError(
                f"MMR root at prev_size={prev.mmr_size} is {actual_prev_root!r} "
                f"but prior checkpoint recorded {prev.root!r} -- log has been mutated"
            )
        prev_size = prev.mmr_size
        prev_root = prev.root

    root_hex = _root_hex(mmr, current_size)

    # Build unsigned record so we can compute the signing body.
    cp = CheckpointRecord(
        v=1,
        kind="mmr_checkpoint",
        log_id=log_id,
        mmr_size=current_size,
        root=root_hex,
        prev_size=prev_size,
        prev_root=prev_root,
        key_id=signer.key_id,
        timestamp=timestamp,
        signature="",
    )
    sig = signer.sign(cp.digest())
    cp.signature = sig
    return cp


def verify_checkpoint_signature(cp: CheckpointRecord, signer: Signer) -> bool:
    """Recompute and compare the checkpoint's signature. Never raises."""
    try:
        expected = signer.sign(cp.digest())
        return cp.signature == expected
    except Exception:
        return False


def verify_checkpoint_signature_offline(cp: CheckpointRecord) -> bool:
    """Verify ``cp.signature`` using ONLY ``cp`` itself -- no ``Signer``
    object, no private key, no network.

    ``verify_checkpoint_signature`` above needs a live ``Signer`` capable of
    reproducing the signature -- i.e. the producer's own private key (or the
    persisted key file). That is fine for the producer's own round-trip
    check, but useless to a stranger who holds only a built ``bundle()``
    (item 14): the whole reason the checkpoint signer moved to a persisted
    Ed25519 identity (`o16-14-precond-checkpoint-signer`) was so bundles
    handed to strangers could be verified. This function is that offline
    check: it reconstructs the Ed25519 public key straight from ``cp.key_id``
    (the raw public key, hex-encoded -- same convention as
    ``capsule_emit.signing.verify_capsule_signature`` for capsule content)
    and verifies ``cp.signature`` over ``cp.digest()``. It proves "the holder
    of this key signed this exact checkpoint"; it does NOT prove who that key
    belongs to -- same caveat as capsule-content signature verification.

    A checkpoint signed by a non-Ed25519 ``Signer`` (e.g. the retired
    in-process HMAC ``witness._AutoSigner``, whose ``key_id`` is an arbitrary
    label, not a public key) correctly fails here rather than false-passing.
    Never raises -- any malformed input is a verification failure.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(cp.key_id))
        public_key.verify(bytes.fromhex(cp.signature), cp.digest().encode("ascii"))
        return True
    except Exception:
        return False


def verify_checkpoint_consistency(
    prev: CheckpointRecord, current: CheckpointRecord, mmr: MmrLedger
) -> bool:
    """Check that ``current`` extends ``prev`` (same ``log_id``) without rollback.

    Recomputes the MMR's root at ``prev.mmr_size`` from the live node store
    and compares it against ``current.prev_root``. A mutated or rolled-back
    log produces a different root.
    """
    try:
        if current.log_id != prev.log_id:
            return False
        if current.prev_size != prev.mmr_size:
            return False
        if current.mmr_size <= prev.mmr_size:
            return False
        actual = _root_hex(mmr, prev.mmr_size)
        return actual == current.prev_root
    except Exception:
        return False


# -- TS registration -----------------------------------------------------


#: The witness-host's canonical checkpoint route (single-host ruling,
#: 2026-08-27): a TS that speaks the CLL checkpoint wire shape directly and
#: verifies the checkpoint's OWN signature server-side before counter-signing
#: -- strictly more verification than the plain-digest ``/register``
#: (``/v1/digest`` legacy alias) route, which treats the checkpoint's digest
#: as an opaque capsule_id. This is the ONLY route :func:`register_checkpoint`
#: ever calls -- see the module's default-emit no-egress guarantee
#: (``tests/test_witness_no_egress_to_register.py``): the default checkpoint
#: path must never touch ``/register``, mirroring the existing "default emit
#: never imports the checkpoint subpackage" layer-0 discipline.
_CHECKPOINT_ROUTE = "/checkpoints"


def register_checkpoint(
    checkpoint_cose: bytes,
    ts_url: str = DEFAULT_TS_URL,
    *,
    timeout: float = 30.0,
) -> WitnessRecord:
    """POST a COSE-wire checkpoint statement to ``ts_url/checkpoints`` and
    return a WitnessRecord.

    ``checkpoint_cose`` is the COSE_Sign1 (CBOR tag 18) bytes produced by
    ``capsule_emit.checkpoint.cose_wire.checkpoint_to_cose`` -- the ONLY
    shape this route accepts (single-host witness ruling, 2026-08-27,
    aligned to the [cll-checkpoint-cose-wire] wire form, superseding the
    earlier plain-JSON ``CheckpointRecord`` body). The witness-host route
    independently decodes and verifies this envelope (via scitt-cose) before
    ever counter-signing it -- never ``/register`` (the opt-in, plain-digest
    route; see ``_CHECKPOINT_ROUTE``). The TS returns a COSE Receipt over the
    checkpoint's digest, proving that this checkpoint was seen by the TS at
    some point in its log. This is called automatically once a checkpoint
    comes due on the default ``emit()`` path (see ``capsule_emit.witness``,
    which builds ``checkpoint_cose`` via ``checkpoint_to_cose`` while the
    live MMR and signer are both still in scope); a caller driving the
    checkpoint layer directly may also call it explicitly with its own
    ``checkpoint_to_cose()`` output.

    ``ts_url`` is what's recorded on the returned ``WitnessRecord`` (the
    semantic identity of the witness); the actual HTTP request may be
    dispatched elsewhere for the *default* URL only -- see
    ``_PENDING_CNAME_TARGETS``.
    """
    from .cose_wire import CLL_CHECKPOINT_CONTENT_TYPE

    dispatch_url = _PENDING_CNAME_TARGETS.get(ts_url, ts_url)
    url = dispatch_url.rstrip("/") + _CHECKPOINT_ROUTE
    req = urllib.request.Request(
        url,
        data=checkpoint_cose,
        method="POST",
        headers={"Content-Type": CLL_CHECKPOINT_CONTENT_TYPE, "Accept": "application/json"},
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


#: The (non-)URL recorded on a stub-produced ``WitnessRecord`` when the
#: caller supplies none -- never dialled, a plain label.
STUB_TS_URL = "stub://local"

#: The normative stub marker's name, now defined by the CLL I-D
#: (draft-mih-scitt-checkpointed-local-log-00, "Stub Countersignatures"):
#: a stub countersignature's COSE protected header MUST carry the parameter
#: ``cll-stub`` (label TBD1, pending IANA assignment) with value ``true``,
#: and MUST list that label in ``crit`` ({{Section 3.1 of RFC9052}}) -- a
#: verifier that recognizes it treats the countersignature as conferring no
#: witnessing; one that doesn't rejects it under ``crit`` processing. Either
#: way the result is unwitnessed, never witnessed, which is exactly
#: ``CheckpointRecord.grade()``'s stub exclusion below.
#:
#: capsule-emit does not yet speak real COSE for stub receipts -- that lands
#: with separate COSE-wire work -- so :func:`register_checkpoint_stub`'s
#: ``receipt_b64`` is still a JSON placeholder, not a COSE_Sign1
#: countersignature. It is built to be forward-compatible with the spec
#: now that the marker's name and value are fixed: the same key
#: (``STUB_MARKER`` == ``"cll-stub"``), the same value (``true``), and a
#: ``crit``-shaped list naming it -- so when the wire format lands, only the
#: encoding (JSON -> COSE protected header) changes, not the marker itself.
STUB_MARKER = "cll-stub"


def register_checkpoint_stub(cp: CheckpointRecord, ts_url: str | None = None) -> WitnessRecord:
    """Build a :class:`WitnessRecord` for ``cp`` via the in-process stub
    witness -- zero network, exercises the identical call shape a real
    ``register_checkpoint`` call would (same return type, same fields) so a
    caller (or test) driving the stub path runs the real code, not a mock.

    Never contacts ``ts_url`` -- it is recorded on the returned
    ``WitnessRecord`` purely as a label (``STUB_TS_URL`` when omitted), the
    same way a real TS URL is recorded, so ``status``/rendering code needs no
    special case to display it. ``is_stub=True`` is always set; grading
    (:meth:`CheckpointRecord.grade`) excludes stub records from the
    witnessed any-of, so a checkpoint registered only via this function stays
    ``Grade.SELF_ATTESTED`` -- frozen surface §1a.4: "the grade never leaves
    self-attested."
    """
    digest = cp.digest()
    entry_hash = hashlib.sha256(bytes.fromhex(digest)).hexdigest()
    stub_receipt = json.dumps(
        {
            STUB_MARKER: True,
            "crit": [STUB_MARKER],
            "note": "not a real COSE Receipt -- CAPSULE_WITNESS=stub was set; "
            "this checkpoint was never sent to a Transparency Service",
            "digest": digest,
        },
        sort_keys=True,
    ).encode()
    import base64

    return WitnessRecord(
        ts_url=ts_url or STUB_TS_URL,
        entry_hash=entry_hash,
        receipt_b64=base64.b64encode(stub_receipt).decode(),
        leaf_index=-1,
        tree_size=-1,
        is_stub=True,
    )


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


def verify_receipt_offline(
    witness: WitnessRecord,
    *,
    ts_pubkey_pem: bytes | str | None = None,
    ts_base_url: str | None = None,
    timeout: float = 15.0,
) -> tuple[bool, list[str]]:
    """Verify a COSE Receipt offline (no network unless the pubkey must be fetched).

    Provide exactly one of ``ts_pubkey_pem`` (cached PEM bytes/str) or
    ``ts_base_url`` (fetches the key once; requires network and the
    ``cryptography`` package). Returns ``(ok, errors)`` -- never raises.
    """
    try:
        from scitt_cose import verify_receipt
    except ImportError:
        return False, ["scitt-cose is not installed; run: pip install 'capsule-emit[checkpoint]'"]

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


_structural_probe_pubkey_pem_cache: bytes | None = None


def _structural_probe_pubkey_pem() -> bytes:
    """A syntactically valid Ed25519 public key PEM, generated once per
    process and cached -- NOT a trust anchor, never used to accept a
    signature as authentic. Used only to drive ``scitt_cose.verify_receipt``
    far enough to reconstruct the inclusion proof's root (a purely
    structural, key-independent step that happens before the signature
    check) so :func:`verify_witness_stamp_offline` can tell "this receipt is
    garbage" apart from "this receipt is a well-formed Receipt shape, just
    not checked against a trusted signer" without reimplementing COSE
    decoding here.
    """
    global _structural_probe_pubkey_pem_cache
    if _structural_probe_pubkey_pem_cache is None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        public_key = Ed25519PrivateKey.generate().public_key()
        _structural_probe_pubkey_pem_cache = public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
    return _structural_probe_pubkey_pem_cache


def verify_witness_stamp_tristate(
    cp: CheckpointRecord,
    witness: WitnessRecord,
    *,
    ts_pubkey_pem: bytes | str | None = None,
) -> tuple[StampVerdict, list[str]]:
    """Verify one witness stamp against ``cp``, returning the THREE-STATE
    verdict [verify-threestate-trustanchor] -- never raises. This is the
    finer-grained sibling of :func:`verify_witness_stamp_offline` (which
    collapses to a ``bool`` for ``grade()``'s two-rung ladder, correctly --
    see ``CheckpointRecord.grade``'s docstring). Callers that must decide
    whether an unverifiable stamp is FATAL to a hand-to-a-stranger artifact
    (``capsule_emit.bundle.verify_bundle``, ``capsule_emit.disclose
    .verify_disclosure``) need this distinction; ``grade()`` does not, since
    both non-WITNESSED states already mean SELF_ATTESTED to it.

    Always (no key needed): the stamp must be BOUND to this exact
    checkpoint -- ``witness.entry_hash`` must equal
    ``sha256(bytes.fromhex(cp.digest())).hexdigest()``, so a stamp copied or
    replayed from a different checkpoint is rejected -- and ``receipt_b64``
    must decode as a structurally valid COSE Receipt (RFC 9942 /
    draft-ietf-cose-merkle-tree-proofs) whose inclusion proof reconstructs a
    Merkle root for that entry_hash (via a key-independent probe -- see
    :func:`_structural_probe_pubkey_pem`). A hand-fabricated stamp (garbage
    ``receipt_b64``, wrong ``entry_hash`` -- exactly what a file-level
    forger who never talked to a real Transparency Service would write)
    fails here, returning :attr:`StampVerdict.INVALID` regardless of
    pinning -- these are hygiene failures, not identity-ambiguity ones.

    Structural validity alone is deliberately NOT enough to grade
    :attr:`StampVerdict.WITNESSED` -- root reconstruction is key-independent,
    so a *sophisticated* forger with the public ``scitt_cose.build_receipt``
    can mint a well-formed receipt over the correct ``entry_hash`` signed
    with a key of their own choosing (no producer or TS key needed), one
    level up from the garbage-bytes forger above. Three states resolve that,
    not two [verify-threestate-trustanchor] (supersedes the two-state
    collapse in [verify-batch-fastfollow] item D, which reported this same
    case as an unqualified failure -- fatal to a bundle when the ts_url
    happened to be unpinned, which false-accused every self-hosted/
    zero-egress TS deployment frozen §1a.2 promises, indistinguishable at
    the wire from this forger):

    With ``ts_pubkey_pem`` (a caller-pinned/cached TS public key) -- OR no
    ``ts_pubkey_pem`` but ``witness.ts_url == DEFAULT_TS_URL``, which
    auto-pins to :data:`DEFAULT_TS_PUBLIC_KEY_PEM`: the TS is KNOWN. The
    Receipt's COSE_Sign1 signature is checked under that specific key --
    verifies -> :attr:`StampVerdict.WITNESSED` (the full identity-bound
    guarantee); fails -> :attr:`StampVerdict.INVALID` (a KNOWN TS's
    signature not matching is forgery, not ambiguity).

    Without a pin, and any other ``ts_url``: the TS is UNKNOWN -- this
    function proves only that the stamp is a genuine, checkpoint-bound
    Receipt SHAPE, not a fabrication; it does NOT and cannot prove which
    Transparency Service produced it. That is :attr:`StampVerdict.UNVERIFIED`,
    not :attr:`StampVerdict.INVALID` -- a caller-supplied pin (or
    registering with the pinned default witness) upgrades it to the
    stronger guarantee; nothing about the shape being merely unverifiable
    justifies treating it as forged.
    """
    import base64

    try:
        expected_entry_hash = hashlib.sha256(bytes.fromhex(cp.digest())).hexdigest()
    except Exception as exc:
        return StampVerdict.INVALID, [f"checkpoint digest could not be computed: {exc}"]
    if witness.entry_hash != expected_entry_hash:
        return StampVerdict.INVALID, [
            "witness.entry_hash does not match this checkpoint's digest -- "
            "stamp is not bound to this checkpoint"
        ]

    try:
        receipt_bytes = base64.b64decode(witness.receipt_b64, validate=True)
    except Exception as exc:
        return StampVerdict.INVALID, [f"receipt_b64 is not valid base64: {exc}"]

    try:
        from scitt_cose import verify_receipt
    except ImportError:
        return StampVerdict.INVALID, [
            "scitt-cose is not installed; run: pip install 'capsule-emit[checkpoint]'"
        ]

    if ts_pubkey_pem is None and witness.ts_url == DEFAULT_TS_URL:
        ts_pubkey_pem = DEFAULT_TS_PUBLIC_KEY_PEM

    if ts_pubkey_pem is not None:
        try:
            result = verify_receipt(
                receipt_bytes, leaf_entry_hex=witness.entry_hash, log_public_key_pem=ts_pubkey_pem
            )
        except Exception as exc:
            return StampVerdict.INVALID, [f"receipt could not be evaluated: {exc}"]
        if result.ok:
            return StampVerdict.WITNESSED, []
        return StampVerdict.INVALID, (
            list(result.errors) or ["receipt signature does not verify under the pinned/supplied key"]
        )

    try:
        probe = verify_receipt(
            receipt_bytes,
            leaf_entry_hex=witness.entry_hash,
            log_public_key_pem=_structural_probe_pubkey_pem(),
        )
    except Exception as exc:
        return StampVerdict.INVALID, [f"receipt could not be evaluated: {exc}"]
    if probe.root is None:
        return StampVerdict.INVALID, [
            "receipt is not a structurally valid COSE Receipt bound to this checkpoint"
        ] + list(probe.errors)
    return StampVerdict.UNVERIFIED, [
        f"witnessed by {witness.ts_url}, pin not supplied — unverified stamp"
    ]


def verify_witness_stamp_offline(
    cp: CheckpointRecord,
    witness: WitnessRecord,
    *,
    ts_pubkey_pem: bytes | str | None = None,
) -> tuple[bool, list[str]]:
    """Verify one witness stamp is a cryptographically authentic TS Receipt
    bound to ``cp`` -- never raises. This is the read-side check
    [stamp-authenticity-on-read-not-presence] adds: ``grade()`` calls this
    (not :func:`verify_witness_stamp_tristate`) because its two-rung ladder
    treats :attr:`StampVerdict.UNVERIFIED` and :attr:`StampVerdict.INVALID`
    identically (both mean SELF_ATTESTED) -- see ``CheckpointRecord.grade``'s
    docstring for why two rungs is correct there. ``capsule_emit.bundle
    .verify_bundle`` and ``capsule_emit.disclose.verify_disclosure`` need
    the finer THREE-STATE distinction (an unpinned witness is not fatal
    evidence; a known witness's failed signature is) and call
    :func:`verify_witness_stamp_tristate` directly instead.

    A thin ``bool`` projection of :func:`verify_witness_stamp_tristate`:
    ``True`` iff :attr:`StampVerdict.WITNESSED`, ``False`` for either
    non-witnessed state. See that function for the full tier documentation.
    """
    verdict, errors = verify_witness_stamp_tristate(cp, witness, ts_pubkey_pem=ts_pubkey_pem)
    return verdict is StampVerdict.WITNESSED, errors
