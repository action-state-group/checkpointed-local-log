# SPDX-License-Identifier: Apache-2.0
"""The three-state admission contract for :meth:`LedgerStore.append`.

A signed checkpoint proves *inclusion* and *log integrity* — that a leaf sits
under a witnessed root and the history between checkpoints was not rewritten.
It does **not** prove *per-capsule authenticity*: that the party who produced a
capsule actually held the key it claims. That is a separate, per-entry property,
and this module is where the ledger decides whether to require it.

**Admission dispatches on an EXPLICIT declared mode carried by the append
request — never inferred from whether a producer envelope happens to be
present.** Inference would be a silent-downgrade hole: an attacker who strips the
envelope off a submission that was *meant* to be signed would have it quietly
admitted as unsigned, erasing the very authenticity requirement the submitter
asked for. The declared mode is authoritative; envelope presence only ever
decides whether a *declared-signed* request passes or is rejected.

Three states:

  1. :data:`UNSIGNED` — no producer envelope is required or consulted. The entry
     is ADMITTED, and an explicit :data:`AUTHENTICITY_UNSIGNED` state is recorded
     on it so a later reader sees "this was never claimed to be authenticated",
     not "authentication was checked and there was nothing to find".
  2. :data:`SIGNED` — at least one Producer Envelope MUST verify against the
     **recomputed** ``capsule_id`` (recomputed the canonical way, so a tampered
     carried id cannot pre-satisfy the check). Missing OR invalid → REJECT.
     On success the entry records :data:`AUTHENTICITY_SIGNED` and is persisted
     *bundled* with the verifying envelope so re-verify-from-storage is clean.
  3. Never infer signedness from envelope presence — see above.

Capsule and envelope stay separate objects (a Capsule ID is signer-independent —
the same content yields the same id for any signer), but they are *bundled* at
ingest and at persistence for signed entries, so the stored record carries its
own proof.

The cryptographic work is **entirely delegated to the published verifiers** —
this module hand-rolls no COSE or signature logic. ``capsule_id`` is recomputed
with :func:`agent_action_capsule.compute_capsule_id` (which already excludes the
local-only ``signature``/``key_id`` envelope fields from the preimage), and each
candidate envelope is checked with
:func:`agent_action_capsule.producer_envelope.verify_producer_envelope`, the same
primitive ``capsule_emit.signing.verify_capsule_signature`` reuses.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from agent_action_capsule import compute_capsule_id

__all__ = [
    "UNSIGNED",
    "SIGNED",
    "ADMISSION_MODES",
    "AUTHENTICITY_UNSIGNED",
    "AUTHENTICITY_SIGNED",
    "AdmissionRequest",
    "AdmissionRejected",
    "ProducerEnvelope",
    "resolve_admission",
]

#: Declared admission modes. These are the ONLY authoritative signal for which
#: of the three states an append takes; envelope presence is never consulted to
#: pick between them.
UNSIGNED = "unsigned"
SIGNED = "signed"
ADMISSION_MODES = (UNSIGNED, SIGNED)

AdmissionModeLiteral = Literal["unsigned", "signed"]

#: Per-entry authenticity states, recorded on the stored capsule so a reader
#: never has to re-derive intent from envelope presence.
AUTHENTICITY_UNSIGNED = "unsigned"
AUTHENTICITY_SIGNED = "signed"

#: The ledger-line key under which a signed entry's bundled proof is persisted.
BUNDLE_KEY = "admission"


class AdmissionRejected(Exception):
    """A declared-signed submission failed the per-capsule authenticity check.

    Raised for both failure modes the contract must reject: no envelope was
    supplied at all, and one or more envelopes were supplied but none verified
    against the recomputed ``capsule_id``. ``code`` distinguishes them for
    callers/tests; the message is human-readable and carries no secret material.
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProducerEnvelope:
    """One Producer Envelope offered for a declared-signed submission.

    ``envelope`` is a hex-encoded COSE_Sign1 producer envelope over the raw
    32-byte ``capsule_id`` digest (the frozen AAC producer-envelope profile);
    ``key_id`` is the raw Ed25519 public key, hex-encoded. This is exactly the
    ``(signature, key_id)`` pair ``capsule_emit.signing.sign_producer_envelope``
    returns, kept as a separate object from the capsule because a Capsule ID is
    signer-independent — the capsule does not need to know who will sign it.
    """

    envelope: str
    key_id: str

    def as_bundled(self) -> dict:
        return {"envelope": self.envelope, "key_id": self.key_id}


@dataclass(frozen=True)
class AdmissionRequest:
    """The declared admission decision carried alongside a capsule at append.

    ``mode`` is authoritative and REQUIRED — the append path dispatches on it and
    never on ``envelopes``. ``envelopes`` is only consulted when ``mode`` is
    :data:`SIGNED`; supplying envelopes with ``mode == UNSIGNED`` is rejected so a
    caller cannot half-declare a signed submission.
    """

    mode: AdmissionModeLiteral
    envelopes: tuple[ProducerEnvelope, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.mode not in ADMISSION_MODES:
            raise ValueError(
                f"admission mode must be one of {ADMISSION_MODES!r}, got {self.mode!r} — "
                "the mode is declared, never inferred"
            )
        if self.mode == UNSIGNED and self.envelopes:
            raise ValueError(
                "unsigned admission does not permit producer envelopes; declare "
                "mode='signed' to require authenticity"
            )


@dataclass(frozen=True)
class _Resolution:
    """Outcome of :func:`resolve_admission`: the authenticity state to record,
    the canonical recomputed ``capsule_id`` the decision was made against, and —
    for signed entries — the envelopes that actually verified (persisted bundled
    with the capsule). ``capsule_id`` is ``None`` for unsigned entries, where the
    contract does not recompute it (the store keeps its own id logic)."""

    authenticity: str
    verified_envelopes: tuple[ProducerEnvelope, ...]
    capsule_id: str | None = None


def _candidate_envelopes(capsule: dict, request: AdmissionRequest) -> list[ProducerEnvelope]:
    """Collect every envelope offered for a signed submission.

    Both delivery shapes are accepted, without ever *inferring* signedness from
    either: envelopes passed explicitly on the request, and — as a convenience
    for capsules already carrying an embedded ``signature``/``key_id`` pair (the
    shape ``capsule_emit.seal`` mints) — that embedded pair. The declared mode
    still gates whether these are consulted at all.
    """
    candidates = list(request.envelopes)
    embedded = capsule.get("signature")
    embedded_kid = capsule.get("key_id")
    if isinstance(embedded, str) and isinstance(embedded_kid, str):
        candidates.append(ProducerEnvelope(envelope=embedded, key_id=embedded_kid))
    return candidates


def _verifies(capsule_id: str, env: ProducerEnvelope) -> bool:
    """True iff ``env`` is a valid Producer Envelope over ``capsule_id`` signed
    by the key it names. Reuses the published aac verifier verbatim (no
    hand-rolled COSE) and applies the same key_id-binding check
    ``capsule_emit.signing.verify_capsule_signature`` applies. Never raises."""
    from agent_action_capsule.producer_envelope import verify_producer_envelope

    try:
        result = verify_producer_envelope(capsule_id, bytes.fromhex(env.envelope))
        return bool(result.ok) and result.public_key == bytes.fromhex(env.key_id)
    except (ValueError, TypeError):
        return False


def resolve_admission(capsule: dict, request: AdmissionRequest) -> _Resolution:
    """Apply the three-state contract; return the authenticity state to record.

    Dispatches SOLELY on ``request.mode``:

      * UNSIGNED → admit with :data:`AUTHENTICITY_UNSIGNED`; envelopes are never
        consulted (and were rejected at request construction if present).
      * SIGNED → require ≥1 envelope that verifies against the RECOMPUTED
        ``capsule_id``; raise :class:`AdmissionRejected` if none was supplied or
        none verifies. On success, return :data:`AUTHENTICITY_SIGNED` plus the
        verifying envelopes for bundled persistence.

    Because dispatch is on the declared mode, stripping the envelope off a
    declared-signed submission does NOT silently downgrade it to unsigned — it
    lands in the SIGNED branch with no candidate and is REJECTED.
    """
    if request.mode == UNSIGNED:
        return _Resolution(authenticity=AUTHENTICITY_UNSIGNED, verified_envelopes=())

    # request.mode == SIGNED
    capsule_id = compute_capsule_id(capsule)
    candidates = _candidate_envelopes(capsule, request)
    if not candidates:
        raise AdmissionRejected(
            "envelope_missing",
            "declared-signed submission carried no producer envelope; a signed "
            "entry requires at least one envelope verifying against the recomputed "
            "capsule_id",
        )
    verified = tuple(env for env in candidates if _verifies(capsule_id, env))
    if not verified:
        raise AdmissionRejected(
            "envelope_invalid",
            "declared-signed submission: no producer envelope verifies against the "
            "recomputed capsule_id",
        )
    return _Resolution(
        authenticity=AUTHENTICITY_SIGNED,
        verified_envelopes=verified,
        capsule_id=capsule_id,
    )
