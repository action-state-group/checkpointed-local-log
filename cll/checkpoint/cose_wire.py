# SPDX-License-Identifier: Apache-2.0
"""COSE_Sign1 + CBOR wire form for CLL checkpoints ([cll-checkpoint-cose-wire],
Decision 1, 2026-08-24).

Decision 1 scopes COSE to the WIRE boundary only, at the two stranger-facing
moments a checkpoint leaves the producer's own process: (a) registering a
checkpoint with a witness, (b) embedding a checkpoint in a ``bundle()``. The
internal dev API and dataclasses (``capsule_emit.checkpoint.emit
.CheckpointRecord`` and friends) are UNTOUCHED and keep their JSON
ergonomics -- this module is a pure translation layer at the wire boundary,
never imported by the internal signing/verification path itself. All
COSE/CBOR machinery is reused from ``scitt_cose`` (boundary rule: no
hand-rolled COSE, no capsule semantics leak into scitt-cose) -- specifically
``scitt_cose.statement`` (the generic SCITT Signed Statement: COSE_Sign1
with a CWT-Claims protected header, RFC 9597) and, transitively,
``scitt_cose.cose_sign1``.

**Field-mapping (resolves [cll-id-field-mapping-doc], Decision 1's mapping
ruling -- chosen option: ship this table, do NOT rename the internal
dataclass fields; ``CheckpointRecord`` stays exactly as it is).** CBOR claim
keys are the CLL I-D (draft-mih-scitt-checkpointed-local-log-00) §3 spec
names, plain UTF-8 text keys in the claims map:

============================  ================================================
dev / JSON (CheckpointRecord)  wire / CBOR (this module)
============================  ================================================
``kind`` (``"mmr_checkpoint"``)  ``kind`` -- fixed to ``"cll-checkpoint"`` at
                                translation, never copied from the dev value
``mmr_size``                   ``log_size``
``root`` (hex, bagged fold --   ``commitment`` -- NOT the bagged root: the
  internal fast-path only)       conformant peak-list accumulator
                                (``core.commitment_object`` -- [cll-
                                commitment-interop]), canonical CBOR
                                ``[ *bstr ]`` of the peak hashes at
                                ``log_size``, carried as a bstr claim value
``prev_size``                  ``prev_size``
``prev_root`` (hex, ``""`` for  ``prev_commitment`` -- same peak-list
  the first checkpoint)          encoding at ``prev_size``, empty bstr for
                                the first checkpoint
``timestamp`` (ISO 8601 str)   ``issued_at`` (ISO 8601 str, unchanged --
                                the I-D's exact CDDL type for this claim
                                could not be confirmed against the draft
                                text at implementation time; kept as the
                                lossless, round-trip-exact string form
                                rather than guess a numeric epoch encoding)
``log_id``                     CWT ``iss`` (claim 1) -- moves off a plaintext
                                field onto the SIGNED protected header
(``log_id``, ``mmr_size``)     CWT ``sub`` (claim 2) = ``"{log_id}#{mmr_size}"``
                                -- identifies this specific checkpoint
                                instance, also signed
``key_id`` (hex)                COSE ``kid`` (protected header label 4, raw
                                32 bytes) -- same convention as the #107
                                producer-envelope profile
``signature``                  N/A -- superseded by the COSE_Sign1 envelope's
                                own signature over the claims map; the JSON
                                Ed25519 signature is over a *different*
                                message (the JSON signing_body) and is never
                                carried inside the CBOR claims
``CheckpointConfig.cadence_seconds``  ``cadence`` (optional, integer seconds)
============================  ================================================

**Commitment shape reconciled with [cll-commitment-interop] (2026-08-27).**
``cp.root``/``cp.prev_root`` are this module's OWN internal fold
(``core.root_from_peaks``) -- convenient for a fast scalar comparison, but a
bespoke convention no external MMRIVER-family tool can reproduce (see
``core.commitment_object``'s docstring). The wire form's ``commitment``/
``prev_commitment`` claims therefore carry the CONFORMANT commitment object
instead -- the ordered peak-hash list itself, canonical-CBOR-encoded -- so a
stranger holding only the COSE bytes gets the same accumulator an
independent draft-bryce-cose-receipts-mmr-profile implementation signs.
``root_from_peaks`` is never removed from this module's OWN offline
verification: :func:`verify_checkpoint_cose_offline` recomputes it locally
from the decoded peak list to run ``core.verify_consistency`` -- the peak
list is the wire truth, the bagged root is a value derived FROM it, on both
the encode and decode sides. This means :func:`encode_checkpoint_claims`
now requires the caller to pass the checkpoint's own peak hashes at
``log_size`` (``new_peak_hashes``) and, when ``prev_size > 0``, at
``prev_size`` (``prev_peak_hashes``) -- there is no way to reconstruct
either peak list from ``cp.root``/``cp.prev_root`` alone, only verify a
candidate list against them. ``prev_peak_hashes`` is deliberately NOT
derived from ``consistency_proof.old_peaks`` even though an honest proof's
``old_peaks`` equal it exactly -- see :func:`encode_checkpoint_claims`'s
docstring for why sourcing it from the (possibly forged) proof itself would
make the decode-side consistency check tautological.

**Beyond Decision 1's literal claim-key list: ``consistency_proof``.** This
task's own directive requires the checkpoint's MMR consistency (extension)
proof to travel ON THE WIRE alongside the checkpoint, not just the
``prev_size``/``prev_commitment`` fields -- ruled for by
``[capsule-anchor-checkpoint-aware-witness]``'s two-check design: field
equality of ``prev_*`` ALONE accepts a rewritten tree with honest-looking
``prev_*`` fields (the signature covers the lie, since ``prev_root`` is just
a claimed string with nothing forcing it to relate to the actual tree
producing ``root``); a genuine, independently-checkable
:class:`~capsule_emit.checkpoint.core.ConsistencyProof` closes that gap.
This is flagged here explicitly as an ADDITION beyond the base ticket's
field list, not smoothed over as if it were always part of it. See
:func:`verify_checkpoint_cose_offline`'s docstring for exactly what a
passing consistency proof does and does not establish (anti-REWRITE, not
anti-FORK -- same honest caveat as ``capsule_emit.bundle.verify_bundle``
and ``scitt_cose.cll.verify_checkpoint_chain``).

**Signing.** Building the COSE envelope needs the SIGNER's private key
material (to construct a real, cross-verifiable COSE_Sign1 -- unlike the
internal JSON path's ``checkpoint.emit.Signer`` protocol, which only ever
sees a bare ``sign(digest_hex) -> str``). This module therefore takes the
richer ``capsule_emit.signing.Signer`` directly (the same persisted Ed25519
:class:`~capsule_emit.signing.LocalKeypairSigner` #84 already made the
checkpoint path's default, via ``witness._PersistedCheckpointSigner`` --
never HMAC), duck-typing its ``sign_cose_statement`` capability the same way
``capsule_emit.signing.sign_producer_envelope`` duck-types ``sign_envelope``
for the #107 profile.

**Verification is fully offline and self-contained**, same trust model as
``checkpoint.emit.verify_checkpoint_signature_offline``: the signing key is
read straight from the envelope's own ``kid``, so a stranger holding only
the COSE bytes (no registry, no live MMR reader) can check both the
signature and, if present, the consistency proof.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import cbor2

from .core import ConsistencyProof, commitment_object, root_from_peaks, verify_consistency
from .emit import CheckpointRecord

__all__ = [
    "CLL_CHECKPOINT_CONTENT_TYPE",
    "WIRE_KIND",
    "DecodedCheckpointCose",
    "CoseCheckpointVerification",
    "encode_checkpoint_claims",
    "checkpoint_to_cose",
    "verify_checkpoint_cose_offline",
]

#: Pending IANA media-type registration -- same "pinned now, exact value
#: confirmed against the registered type later" posture as the #107
#: producer-envelope profile's ``CAPSULE_ID_MEDIA_TYPE``.
CLL_CHECKPOINT_CONTENT_TYPE = "application/cll-checkpoint+cbor"

#: The CBOR claims map's ``kind`` value -- the CLL I-D §3 spec name, always
#: written on encode regardless of the internal ``CheckpointRecord.kind``
#: value (which stays ``"mmr_checkpoint"``, see the module docstring's
#: field-mapping table).
WIRE_KIND = "cll-checkpoint"

#: COSE protected-header label for `kid` (RFC 9052 §3.1) -- hardcoded here
#: rather than imported, matching the existing convention in
#: ``capsule_emit.signing.LocalKeypairSigner.sign_envelope``.
_HDR_KID = 4


def _consistency_proof_to_cbor(p: ConsistencyProof) -> dict:
    return {
        "size_a": p.size_a,
        "size_b": p.size_b,
        "old_peaks": [bytes.fromhex(h) for h in p.old_peaks],
        "witness": [[bytes.fromhex(h) for h in w] for w in p.witness],
        "new_peaks": [bytes.fromhex(h) for h in p.new_peaks],
    }


def _consistency_proof_from_cbor(d: dict) -> ConsistencyProof:
    if not isinstance(d, dict):
        raise ValueError("consistency_proof claim is not a map")
    try:
        old_peaks = tuple(bytes(h).hex() for h in d["old_peaks"])
        witness = tuple(tuple(bytes(x).hex() for x in w) for w in d["witness"])
        new_peaks = tuple(bytes(h).hex() for h in d["new_peaks"])
        return ConsistencyProof(
            v=1,
            kind="consistency",
            size_a=int(d["size_a"]),
            size_b=int(d["size_b"]),
            old_peaks=old_peaks,
            witness=witness,
            new_peaks=new_peaks,
        )
    except (KeyError, TypeError) as exc:
        raise ValueError(f"consistency_proof claim is malformed: {exc}") from exc


def encode_checkpoint_claims(
    cp: CheckpointRecord,
    new_peak_hashes: list,
    *,
    prev_peak_hashes: list | None = None,
    consistency_proof: ConsistencyProof | None = None,
    cadence_seconds: int | None = None,
) -> dict:
    """Build the CBOR claims map (I-D §3 field names) for ``cp`` -- the
    payload that :func:`checkpoint_to_cose` wraps in a COSE_Sign1 envelope.
    Pure translation, no signing. See the module docstring's field-mapping
    table for the exact dev-name -> wire-name correspondence.

    ``new_peak_hashes`` is the MMR's own peak-hash list at ``cp.mmr_size``
    (e.g. ``MmrLedger.peak_hashes_at(cp.mmr_size)``) -- the ``commitment``
    claim is ``core.commitment_object(new_peak_hashes)``, NOT ``cp.root``
    (see the module docstring's "Commitment shape reconciled with
    [cll-commitment-interop]" note). ``prev_peak_hashes`` is the same for
    ``cp.prev_size`` (required exactly when ``cp.prev_size > 0``) and backs
    the ``prev_commitment`` claim the SAME way.

    Both raise ``ValueError`` if they do not bag (``core.root_from_peaks``)
    to ``cp.root``/``cp.prev_root`` respectively -- passing any peak list
    other than the one that actually produced that field would silently
    mint a wire statement that lies about its own commitment.

    **Deliberately NOT derived from ``consistency_proof.old_peaks``, even
    though an honest proof's ``old_peaks`` equal ``prev_peak_hashes``
    exactly.** ``prev_commitment`` must be independently sourced from the
    checkpoint's OWN claimed prior state (anchored to ``cp.prev_root``) so
    that :func:`verify_checkpoint_cose_offline`'s later
    ``core.verify_consistency`` check is a REAL reconciliation between two
    independent claims, not a tautology against a proof that could itself
    be forged (see ``tests/checkpoint/test_cose_wire.py``'s RED-FIRST
    adversarial cases for exactly the attack this closes).

    Raises ``ValueError`` if ``consistency_proof`` is supplied but does not
    span exactly ``(cp.prev_size, cp.mmr_size)`` -- a proof for the wrong
    range would silently misrepresent what this checkpoint's continuity
    claim is backed by.
    """
    if consistency_proof is not None and (
        consistency_proof.size_a != cp.prev_size or consistency_proof.size_b != cp.mmr_size
    ):
        raise ValueError(
            f"consistency_proof spans ({consistency_proof.size_a}, {consistency_proof.size_b}) "
            f"but checkpoint is (prev_size={cp.prev_size}, mmr_size={cp.mmr_size})"
        )

    if root_from_peaks(new_peak_hashes) != bytes.fromhex(cp.root):
        raise ValueError(
            "new_peak_hashes do not bag (core.root_from_peaks) to cp.root "
            f"({cp.root!r}) -- pass the SAME peak set this checkpoint's own root was "
            "computed from, e.g. MmrLedger.peak_hashes_at(cp.mmr_size)"
        )

    if cp.prev_size > 0:
        if prev_peak_hashes is None:
            raise ValueError(
                f"checkpoint has prev_size={cp.prev_size} > 0 but no prev_peak_hashes was "
                "supplied -- pass MmrLedger.peak_hashes_at(cp.prev_size) from the SAME MMR"
            )
        if root_from_peaks(prev_peak_hashes) != bytes.fromhex(cp.prev_root):
            raise ValueError(
                "prev_peak_hashes do not bag (core.root_from_peaks) to cp.prev_root "
                f"({cp.prev_root!r}) -- pass the SAME peak set the prior checkpoint's own "
                "root was computed from, e.g. MmrLedger.peak_hashes_at(cp.prev_size)"
            )
        prev_commitment = commitment_object(prev_peak_hashes)
    else:
        prev_commitment = b""

    claims: dict = {
        "kind": WIRE_KIND,
        "log_size": cp.mmr_size,
        "commitment": commitment_object(new_peak_hashes),
        "prev_size": cp.prev_size,
        "prev_commitment": prev_commitment,
        "issued_at": cp.timestamp,
    }
    if cadence_seconds is not None:
        claims["cadence"] = cadence_seconds
    if consistency_proof is not None:
        claims["consistency_proof"] = _consistency_proof_to_cbor(consistency_proof)
    return claims


def checkpoint_to_cose(
    cp: CheckpointRecord,
    signer,
    new_peak_hashes: list,
    *,
    prev_peak_hashes: list | None = None,
    consistency_proof: ConsistencyProof | None = None,
    cadence_seconds: int | None = None,
) -> bytes:
    """Serialize ``cp`` as a COSE_Sign1 statement over the CBOR claims map
    (:func:`encode_checkpoint_claims`), signed by ``signer`` -- the wire
    form for the two stranger-facing moments (Decision 1).

    ``new_peak_hashes``/``prev_peak_hashes`` are threaded straight through
    to :func:`encode_checkpoint_claims` -- see its docstring.

    ``signer`` must be a ``capsule_emit.signing.Signer``-shaped object
    implementing ``sign_cose_statement`` (:class:`~capsule_emit.signing
    .LocalKeypairSigner` does) -- NOT ``checkpoint.emit.Signer``'s narrower
    ``sign(digest_hex) -> str`` adapter, which cannot build a real COSE
    envelope. Pass the SAME underlying signer identity used for ``cp``'s own
    JSON signature (e.g. what ``witness._PersistedCheckpointSigner`` wraps),
    so the wire form's ``kid`` matches ``cp.key_id``.

    Refuses (``ValueError``) to serialize a checkpoint that claims a prior
    (``cp.prev_size > 0``) without a ``consistency_proof`` -- continuity
    would otherwise be asserted only by the ``prev_size``/``prev_commitment``
    claim fields, which is exactly the field-equality gap this wire form
    exists to close (see the module docstring). Symmetrically refuses a
    ``consistency_proof`` on a first checkpoint (``prev_size == 0``), which
    has nothing to prove continuity with.
    """
    if cp.prev_size > 0 and consistency_proof is None:
        raise ValueError(
            f"checkpoint at mmr_size={cp.mmr_size} has prev_size={cp.prev_size} > 0 but no "
            "consistency_proof was supplied -- refusing to wire-serialize a continuity claim "
            "that field-equality alone cannot back; pass "
            "capsule_emit.checkpoint.core.consistency_proof(reader, cp.prev_size, cp.mmr_size) "
            "built from the same MMR that produced this checkpoint"
        )
    if consistency_proof is not None and cp.prev_size == 0:
        raise ValueError(
            "checkpoint has no prior (prev_size == 0) but a consistency_proof was supplied"
        )

    claims = encode_checkpoint_claims(
        cp,
        new_peak_hashes,
        prev_peak_hashes=prev_peak_hashes,
        consistency_proof=consistency_proof,
        cadence_seconds=cadence_seconds,
    )
    payload = cbor2.dumps(claims, canonical=True)

    sign_cose_statement = getattr(signer, "sign_cose_statement", None)
    if not callable(sign_cose_statement):
        raise TypeError(
            f"{type(signer).__name__} cannot sign a COSE checkpoint statement -- pass the "
            "underlying capsule_emit.signing.Signer (e.g. LocalKeypairSigner), which "
            "implements sign_cose_statement, not the narrower checkpoint.emit.Signer "
            "adapter used for the JSON signing_body path"
        )
    subject = f"{cp.log_id}#{cp.mmr_size}"
    return sign_cose_statement(
        payload,
        content_type=CLL_CHECKPOINT_CONTENT_TYPE,
        issuer=cp.log_id,
        subject=subject,
    )


@dataclass(frozen=True)
class DecodedCheckpointCose:
    """The JSON-shaped fields recovered from a verified COSE-wire checkpoint
    statement -- mirrors ``CheckpointRecord``'s verify-relevant fields (see
    the module docstring's field-mapping table), minus ``signature``
    (superseded by the COSE_Sign1 envelope's own signature, never carried
    inside the claims) and ``witnesses`` (a JSON-side, post-registration
    concept out of scope for this translation).

    ``root``/``prev_root`` are DERIVED here (``core.root_from_peaks`` over
    ``new_peak_hashes``/``prev_peak_hashes``), not carried directly -- the
    wire's own commitment is the peak list; the bagged root is this
    module's internal-only convenience value computed FROM it, same
    direction as the encode side. ``new_peak_hashes``/``prev_peak_hashes``
    are the actual [cll-commitment-interop] conformant commitment an
    external MMRIVER-profile verifier needs (``prev_peak_hashes`` is empty
    for the first checkpoint)."""

    log_id: str
    mmr_size: int
    root: str
    new_peak_hashes: tuple
    prev_size: int
    prev_root: str
    prev_peak_hashes: tuple
    timestamp: str
    key_id: str
    cadence_seconds: int | None
    consistency_proof: ConsistencyProof | None

    def to_checkpoint_record(self) -> CheckpointRecord:
        """Reconstruct a :class:`CheckpointRecord` from these fields --
        ``kind`` fixed back to the internal ``"mmr_checkpoint"`` convention,
        ``signature`` left empty (not recoverable here -- see the class
        docstring). Every OTHER field round-trips byte-for-byte against the
        JSON internal form a producer built this wire statement from."""
        return CheckpointRecord(
            v=1,
            kind="mmr_checkpoint",
            log_id=self.log_id,
            mmr_size=self.mmr_size,
            root=self.root,
            prev_size=self.prev_size,
            prev_root=self.prev_root,
            key_id=self.key_id,
            timestamp=self.timestamp,
            signature="",
        )


@dataclass
class CoseCheckpointVerification:
    """Outcome of :func:`verify_checkpoint_cose_offline`. Never raises --
    every failure is reported here, the same total-verifier convention as
    ``core.verify_consistency``/``bundle.verify_bundle``."""

    ok: bool = False
    decoded: DecodedCheckpointCose | None = None
    errors: list = field(default_factory=list)


def _extract_kid(cose_bytes: bytes) -> bytes | None:
    """Pull the raw ``kid`` bytes (protected header label 4) out of a
    COSE_Sign1 message WITHOUT verifying the signature -- needed to look up
    the public key to verify against in the first place (self-contained
    offline verify, same as ``checkpoint.emit.verify_checkpoint_signature
    _offline``'s ``key_id``-from-the-record-itself convention). Uses
    ``scitt_cose.cose_sign1.strict_decode`` for the outer structure (the
    same malleability-resistant decoder ``verify_sign1`` itself uses) --
    never a lenient/hand-rolled parse. Raises ``scitt_cose.CoseError`` on a
    malformed message; returns ``None`` if the message is well-formed but
    carries no ``kid``.
    """
    from scitt_cose.cose_sign1 import strict_decode

    outer = strict_decode(cose_bytes)
    value = outer.value
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        return None
    protected_bstr = value[0]
    if not protected_bstr:
        return None
    protected = cbor2.loads(bytes(protected_bstr))
    kid = protected.get(_HDR_KID) if hasattr(protected, "get") else None
    return bytes(kid) if isinstance(kid, (bytes, bytearray)) else None


def _ed25519_pubkey_pem(raw: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PublicKey.from_public_bytes(raw)
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def _decode_commitment(raw: bytes, *, what: str) -> tuple:
    """Decode a ``core.commitment_object``-encoded bstr claim back into its
    peak-hash list. ``commitment_object`` is exactly ``cbor2.dumps(peaks,
    canonical=True)`` (see its docstring/tests), so decoding is the inverse:
    ``cbor2.loads``, then the same shape checks ``commitment_object`` itself
    enforces on encode (a list of 32-byte strings)."""
    try:
        peaks = cbor2.loads(bytes(raw))
    except Exception as exc:  # noqa: BLE001 -- total verifier, never raises
        raise ValueError(f"{what} is not valid CBOR: {exc}") from exc
    if not isinstance(peaks, list) or not all(
        isinstance(p, (bytes, bytearray)) and len(p) == 32 for p in peaks
    ):
        raise ValueError(f"{what} is not a CBOR array of 32-byte peak hashes")
    return tuple(bytes(p) for p in peaks)


def _decode_claims(claims, *, issuer: str | None, subject: str | None, key_id: str) -> DecodedCheckpointCose:
    if not hasattr(claims, "get"):
        raise ValueError("claims payload is not a map")
    if claims.get("kind") != WIRE_KIND:
        raise ValueError(f"claims 'kind' is {claims.get('kind')!r}, expected {WIRE_KIND!r}")
    if not issuer:
        raise ValueError("statement carries no CWT issuer (log identity)")

    mmr_size = claims.get("log_size")
    prev_size = claims.get("prev_size")
    commitment = claims.get("commitment")
    prev_commitment = claims.get("prev_commitment", b"")
    issued_at = claims.get("issued_at")

    if not isinstance(mmr_size, int) or isinstance(mmr_size, bool) or mmr_size < 0:
        raise ValueError("log_size must be a non-negative integer")
    if not isinstance(prev_size, int) or isinstance(prev_size, bool) or prev_size < 0:
        raise ValueError("prev_size must be a non-negative integer")
    if not isinstance(commitment, (bytes, bytearray)):
        raise ValueError("commitment must be a CBOR byte string")
    new_peak_hashes = _decode_commitment(commitment, what="commitment")
    root = root_from_peaks(list(new_peak_hashes)).hex()
    if prev_commitment and not isinstance(prev_commitment, (bytes, bytearray)):
        raise ValueError("prev_commitment must be a CBOR byte string or empty")
    if prev_commitment:
        prev_peak_hashes = _decode_commitment(prev_commitment, what="prev_commitment")
        prev_root = root_from_peaks(list(prev_peak_hashes)).hex()
    else:
        prev_peak_hashes = ()
        prev_root = ""
    if not isinstance(issued_at, str):
        raise ValueError("issued_at must be a string (ISO 8601)")

    expected_subject = f"{issuer}#{mmr_size}"
    if subject != expected_subject:
        raise ValueError(f"CWT subject {subject!r} does not match expected {expected_subject!r}")

    cadence = claims.get("cadence")
    if cadence is not None and (not isinstance(cadence, int) or isinstance(cadence, bool)):
        raise ValueError("cadence must be an integer (seconds)")

    consistency_proof = None
    raw_proof = claims.get("consistency_proof")
    if raw_proof is not None:
        consistency_proof = _consistency_proof_from_cbor(raw_proof)
        if consistency_proof.size_a != prev_size or consistency_proof.size_b != mmr_size:
            raise ValueError(
                "consistency_proof does not span this checkpoint's own prev_size/log_size"
            )

    return DecodedCheckpointCose(
        log_id=issuer,
        mmr_size=mmr_size,
        root=root,
        new_peak_hashes=new_peak_hashes,
        prev_size=prev_size,
        prev_root=prev_root,
        prev_peak_hashes=prev_peak_hashes,
        timestamp=issued_at,
        key_id=key_id,
        cadence_seconds=cadence,
        consistency_proof=consistency_proof,
    )


def verify_checkpoint_cose_offline(cose_bytes: bytes) -> CoseCheckpointVerification:
    """Verify a COSE-wire checkpoint statement using ONLY the bytes
    themselves -- no registry, no network, no live MMR reader. Never raises.

    The signing key is read straight from the envelope's own protected-
    header ``kid`` (raw 32-byte Ed25519 public key) -- this proves "the
    holder of this key signed this exact claims map", not who that key
    belongs to (same caveat as every other self-contained-verify function in
    this codebase).

    **If the claims carry a ``consistency_proof`` (``decoded.prev_size >
    0``), it is independently re-verified here** via ``core
    .verify_consistency`` against the claims' OWN ``commitment``/
    ``prev_commitment`` -- a REAL extension proof, not field equality: a
    checkpoint whose claimed ``prev_commitment`` does not actually bag up
    from the checkpoint's ``commitment`` peaks (a rewritten/forged tail
    presented with an honest-looking, copied ``prev_commitment`` label) is
    REJECTED here even though the signature itself is perfectly valid --
    the signature only proves the signer's identity, never that the claimed
    continuity is real. A checkpoint claiming ``prev_size > 0`` with NO
    ``consistency_proof`` at all is likewise rejected -- continuity would be
    asserted, not proven, and this wire form exists specifically to close
    that gap (see the module docstring).

    **Honest scope, same as ``bundle.verify_bundle``/``scitt_cose.cll
    .verify_checkpoint_chain``:** a passing consistency proof rules out
    REWRITE (the presented history was not mutated/reordered/truncated
    between the two checkpoints) -- it does NOT rule out FORK/equivocation
    (a genuinely divergent second history extended from the same true
    prior, each side internally consistent). Detecting that requires an
    online witness that remembers per-log state across checkpoints
    (``[capsule-anchor-checkpoint-aware-witness]``, deferred stage 2) --
    out of scope for a single, self-contained COSE statement.
    """
    from scitt_cose.cose_sign1 import CoseError
    from scitt_cose.statement import parse_signed_statement

    result = CoseCheckpointVerification()

    try:
        kid = _extract_kid(cose_bytes)
    except CoseError as exc:
        result.errors.append(f"malformed COSE checkpoint statement: {exc}")
        return result
    except Exception as exc:  # noqa: BLE001 -- total verifier, never raises
        result.errors.append(f"could not read kid from COSE checkpoint statement: {exc}")
        return result

    if kid is None or len(kid) != 32:
        result.errors.append(
            "COSE checkpoint statement carries no 32-byte kid (label 4) -- cannot self-verify offline"
        )
        return result

    try:
        pubkey_pem = _ed25519_pubkey_pem(kid)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"kid is not a valid Ed25519 public key: {exc}")
        return result

    try:
        parsed = parse_signed_statement(cose_bytes, public_key_pem=pubkey_pem)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"statement could not be parsed: {exc}")
        return result

    if not parsed["signature_verified"]:
        result.errors.append("COSE checkpoint signature does not verify under its own kid")
        return result

    if parsed["content_type"] != CLL_CHECKPOINT_CONTENT_TYPE:
        result.errors.append(f"unexpected content_type {parsed['content_type']!r}")
        return result

    try:
        claims = cbor2.loads(parsed["payload"])
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"payload is not valid CBOR: {exc}")
        return result

    try:
        decoded = _decode_claims(
            claims, issuer=parsed["issuer"], subject=parsed["subject"], key_id=kid.hex()
        )
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"claims map is malformed: {exc}")
        return result

    if decoded.consistency_proof is not None:
        try:
            root_a = bytes.fromhex(decoded.prev_root)
            root_b = bytes.fromhex(decoded.root)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"commitment/prev_commitment is not valid hex: {exc}")
            return result
        if not verify_consistency(
            root_a, decoded.prev_size, root_b, decoded.mmr_size, decoded.consistency_proof
        ):
            result.errors.append(
                f"consistency proof does not bridge prev_size={decoded.prev_size} to "
                f"log_size={decoded.mmr_size} -- checkpoint claims continuity it cannot "
                "cryptographically back (rewritten, truncated, or forged tail)"
            )
            return result
    elif decoded.prev_size != 0:
        result.errors.append(
            f"checkpoint claims prev_size={decoded.prev_size} (not the log's first) but carries "
            "no consistency_proof -- continuity is asserted, not proven"
        )
        return result

    result.decoded = decoded
    result.ok = True
    return result
