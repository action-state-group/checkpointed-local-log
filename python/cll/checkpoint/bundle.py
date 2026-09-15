# SPDX-License-Identifier: Apache-2.0
"""``bundle()`` — the hand-to-anyone artifact for one log record.

The verification chain documented in ``cll.checkpoint.emit`` is four
separate, caller-composed primitives: MMR inclusion, checkpoint signature,
TS receipt, and rollback/consistency. This module is what assembles them
into ONE standalone object for one record:

    {receipt, inclusion proof, covering checkpoint (+ its witness stamp),
     prior checkpoint, consistency proof between the two}

Once built, a ``Bundle`` is offline-verifiable by a stranger — no account,
no further help from the producer, no network (see
:func:`verify_bundle_log_integrity`; witness-stamp re-confirmation is a
separate, explicitly optional step since it may need a network fetch of the
Transparency Service's public key). It gives the two-sided append bracket:
the record provably entered the log no later than the covering checkpoint's
stamp and no earlier than the prior checkpoint (it wasn't in that one yet)
— except for a record covered by the very first checkpoint a log ever had,
where there is no prior checkpoint to bound the lower side (``prior_checkpoint``
and ``consistency_proof`` are both ``None``; ``checkpoint.prev_size == 0``
says so honestly rather than gap-filling one).

A bundle is buildable at any later time for any record the log still
retains — this module never caches or persists one; every call re-derives
the MMR fresh from the caller-supplied ``entries`` (each raw log line is one
leaf, in append order).

**Content-agnostic by design (ported from ``capsule_emit.bundle`` per the
W3.1 CLL extraction, 2026-09).** This module knows nothing about capsules:
``entries`` is a plain list of dicts, the leaf-identifying field defaults to
``"capsule_id"`` (the historical name) but is a caller-supplied parameter
(``id_field``), and record filtering (skipping non-leaf bookkeeping entries
like checkpoint stamps) is driven by ``kind_field``/``non_leaf_kinds``
rather than a hardcoded notion of what a "capsule" is. A consumer with its
own record shape (e.g. TRACE records) supplies its own field names.

**Verification is deliberately split at its natural seam.**
:func:`verify_bundle_log_integrity` here checks everything the log itself
proves — MMR inclusion, checkpoint signature, consistency, witness stamps,
COSE wire — and nothing about the *content* of the leaf record. A consumer
whose leaf records carry their own content-authenticity property (e.g. a
capsule's producer signature) layers that check on top and merges the
result; see ``capsule_emit.bundle.verify_bundle`` for the reference
composition. This is the same layering law as ``scitt-cose`` (receipts) and
``agent-action-capsule`` (capsule semantics) — capsule vocabulary never
enters this module.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["Bundle", "BundleError", "bundle", "verify_bundle_log_integrity"]


class BundleError(RuntimeError):
    """A bundle cannot be built for the requested record — not found,
    ambiguous, or not yet covered by any checkpoint."""


@dataclass(frozen=True)
class Bundle:
    """A standalone-verifiable evidence package for one log record.

    ``prior_checkpoint``/``consistency_proof`` are ``None`` together, iff
    ``checkpoint.prev_size == 0`` (the covering checkpoint is the log's
    first) — never independently ``None``.
    """

    v: int
    capsule_id: str  # the leaf's content digest / id (field name kept for compat; see id_field)
    seq: int  # 1-indexed position in the raw log
    receipt: dict
    inclusion_proof: Any  # cll.checkpoint.core.InclusionProof
    checkpoint: Any  # cll.checkpoint.CheckpointRecord — covering, carries its stamp(s)
    prior_checkpoint: Any | None  # cll.checkpoint.CheckpointRecord | None
    consistency_proof: Any | None  # cll.checkpoint.core.ConsistencyProof | None
    checkpoint_cose: bytes | None = None
    """The covering checkpoint's COSE_Sign1 wire form -- ``None`` for a
    bundle built from a log whose checkpoint stamp predates this field, or
    whose COSE serialization failed at production time; never re-minted
    here, only ever carried through from what the operator's own process
    signed. A generic COSE/SCITT verifier can check this checkpoint's
    signature and CWT identity offline from this field alone, with no
    cll-specific code at all (see ``checkpoint.cose_wire
    .verify_checkpoint_cose_offline``)."""

    def to_dict(self) -> dict:
        return {
            "v": self.v,
            "capsule_id": self.capsule_id,
            "seq": self.seq,
            "receipt": self.receipt,
            "inclusion_proof": _inclusion_proof_to_dict(self.inclusion_proof),
            "checkpoint": self.checkpoint.to_dict(),
            "prior_checkpoint": self.prior_checkpoint.to_dict() if self.prior_checkpoint else None,
            "consistency_proof": (
                _consistency_proof_to_dict(self.consistency_proof)
                if self.consistency_proof is not None
                else None
            ),
            "checkpoint_cose": self.checkpoint_cose.hex() if self.checkpoint_cose is not None else None,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Bundle:
        from .emit import CheckpointRecord

        prior = d.get("prior_checkpoint")
        cproof = d.get("consistency_proof")
        cose_hex = d.get("checkpoint_cose")
        return cls(
            v=int(d["v"]),
            capsule_id=d["capsule_id"],
            seq=int(d["seq"]),
            receipt=d["receipt"],
            inclusion_proof=_inclusion_proof_from_dict(d["inclusion_proof"]),
            checkpoint=CheckpointRecord.from_dict(d["checkpoint"]),
            prior_checkpoint=CheckpointRecord.from_dict(prior) if prior else None,
            consistency_proof=_consistency_proof_from_dict(cproof) if cproof is not None else None,
            checkpoint_cose=bytes.fromhex(cose_hex) if cose_hex else None,
        )


def _inclusion_proof_to_dict(p: Any) -> dict:
    return {
        "v": p.v,
        "kind": p.kind,
        "size": p.size,
        "leaf_index": p.leaf_index,
        "witness": list(p.witness),
        "peaks_left": list(p.peaks_left),
        "peaks_right": list(p.peaks_right),
    }


def _inclusion_proof_from_dict(d: dict) -> Any:
    from .core import InclusionProof

    return InclusionProof(
        v=int(d["v"]),
        kind=d["kind"],
        size=int(d["size"]),
        leaf_index=int(d["leaf_index"]),
        witness=tuple(d["witness"]),
        peaks_left=tuple(d["peaks_left"]),
        peaks_right=tuple(d["peaks_right"]),
    )


def _consistency_proof_to_dict(p: Any) -> dict:
    return {
        "v": p.v,
        "kind": p.kind,
        "size_a": p.size_a,
        "size_b": p.size_b,
        "old_peaks": list(p.old_peaks),
        "witness": [list(w) for w in p.witness],
        "new_peaks": list(p.new_peaks),
    }


def _consistency_proof_from_dict(d: dict) -> Any:
    from .core import ConsistencyProof

    return ConsistencyProof(
        v=int(d["v"]),
        kind=d["kind"],
        size_a=int(d["size_a"]),
        size_b=int(d["size_b"]),
        old_peaks=tuple(d["old_peaks"]),
        witness=tuple(tuple(w) for w in d["witness"]),
        new_peaks=tuple(d["new_peaks"]),
    )


def _find_record(
    entries: list[dict], record_id: str, *, id_field: str, kind_field: str, non_leaf_kinds: frozenset
) -> int:
    """Resolve ``record_id`` (full, or an unambiguous >=8-char prefix) to
    its 0-based index in ``entries``. Entries whose ``kind_field`` value is
    in ``non_leaf_kinds`` are never a match — a bundle is for a content
    record, never for the log's own bookkeeping (checkpoint stamps etc.),
    even though both become MMR leaves too."""
    matches = [
        i
        for i, e in enumerate(entries)
        if e.get(kind_field) not in non_leaf_kinds
        and (
            e.get(id_field) == record_id
            or (len(record_id) >= 8 and str(e.get(id_field, "")).startswith(record_id))
        )
    ]
    if not matches:
        raise BundleError(f"no record matches {id_field}={record_id!r}")
    exact = [i for i in matches if entries[i][id_field] == record_id]
    if exact:
        return exact[0]
    if len(matches) > 1:
        raise BundleError(
            f"{id_field} prefix {record_id!r} matches {len(matches)} records — use more characters"
        )
    return matches[0]


def bundle(
    entries: list[dict],
    record_id: str,
    *,
    id_field: str = "capsule_id",
    kind_field: str = "kind",
    non_leaf_kinds: frozenset = frozenset(),
    stamp_kind: str = "checkpoint_stamp",
) -> Bundle:
    """Build a standalone-verifiable :class:`Bundle` for one record already
    present in ``entries`` — the caller's own raw, in-append-order log
    entries (this module never reads a log itself; see
    ``capsule_emit.bundle.bundle`` for the file-reading wrapper).

    Re-derives the MMR fresh from ``entries`` on every call — this never
    assumes an in-process ``MmrLedger`` is warm (a bundle can be built by a
    completely different process than the one that sealed the record).

    Raises :class:`BundleError` if ``record_id`` doesn't resolve to exactly
    one record, or if that record is not yet covered by any checkpoint (a
    record only becomes bundle-able once a checkpoint's ``mmr_size`` reaches
    it).
    """
    from . import core as mmr_core
    from .emit import CheckpointRecord
    from .store import MemoryNodeStore

    if not entries:
        raise BundleError("entries: empty log")

    target_idx = _find_record(
        entries, record_id, id_field=id_field, kind_field=kind_field, non_leaf_kinds=non_leaf_kinds
    )
    seq = target_idx + 1  # 1-indexed leaf position, matching production's raw-line numbering

    stamp_entries = [e for e in entries if e.get(kind_field) == stamp_kind]
    checkpoints: list[CheckpointRecord] = [
        CheckpointRecord.from_dict(e["checkpoint"]) for e in stamp_entries
    ]
    checkpoint_cose_by_size: dict[int, str] = {
        cp.mmr_size: e["checkpoint_cose"]
        for cp, e in zip(checkpoints, stamp_entries)
        if e.get("checkpoint_cose")
    }

    covering = next((cp for cp in checkpoints if mmr_core.leaf_count(cp.mmr_size) >= seq), None)
    if covering is None:
        raise BundleError(
            f"record {record_id!r} (seq={seq}) is not yet covered by any checkpoint — "
            "no bundle exists yet; it becomes buildable once the next checkpoint covers it"
        )

    prior = None
    if covering.prev_size > 0:
        prior = next((cp for cp in checkpoints if cp.mmr_size == covering.prev_size), None)
        if prior is None:
            raise BundleError(
                f"checkpoint at mmr_size={covering.mmr_size} names a prior checkpoint at "
                f"mmr_size={covering.prev_size} that is not present in entries — log is incomplete"
            )

    covered_leaves = mmr_core.leaf_count(covering.mmr_size)
    store = MemoryNodeStore()
    for entry in entries[:covered_leaves]:
        body_digest = bytes.fromhex(entry[id_field])
        mmr_core.add_leaf(store, mmr_core.leaf_hash(body_digest))
    if store.size() != covering.mmr_size:
        raise BundleError(
            f"reconstructed MMR size {store.size()} does not match checkpoint "
            f"mmr_size {covering.mmr_size} — log may be corrupt or truncated"
        )

    inclusion = mmr_core.inclusion_proof(store, seq - 1, covering.mmr_size)
    consistency = (
        mmr_core.consistency_proof(store, prior.mmr_size, covering.mmr_size) if prior is not None else None
    )
    cose_hex = checkpoint_cose_by_size.get(covering.mmr_size)

    return Bundle(
        v=1,
        capsule_id=entries[target_idx][id_field],
        seq=seq,
        receipt=entries[target_idx],
        inclusion_proof=inclusion,
        checkpoint=covering,
        prior_checkpoint=prior,
        consistency_proof=consistency,
        checkpoint_cose=bytes.fromhex(cose_hex) if cose_hex else None,
    )


def verify_bundle_log_integrity(
    b: Bundle, *, trust_anchor: dict[str, bytes | str] | None = None
) -> tuple[bool, list[str]]:
    """Pure, offline verification of everything the LOG itself proves about
    a standalone :class:`Bundle` — no reader, no network, never raises.
    Deliberately does NOT check the leaf record's own content authenticity
    (e.g. a capsule's producer signature) — that is the caller's concern
    (see the module docstring); a caller with such a property should check
    it itself and merge the result with this function's.

    ``trust_anchor`` is an optional caller-supplied mapping of
    ``ts_url -> pubkey_pem`` — one or several pins for Transparency Services
    the caller trusts beyond the built-in pinned default witness
    (``cll.checkpoint.DEFAULT_TS_URL`` / ``DEFAULT_TS_PUBLIC_KEY_PEM``,
    always consulted regardless of ``trust_anchor``). Confirms every link
    the two-sided append bracket depends on:

      1. inclusion — the receipt is genuinely a leaf under the covering
         checkpoint's root, at this bundle's ``seq``;
      2. the covering checkpoint's own signature, offline
         (``verify_checkpoint_signature_offline`` — Ed25519, via the
         checkpoint's own ``key_id``, no private key needed);
      3. if a prior checkpoint is present: its signature too, that the
         covering checkpoint's ``prev_size``/``prev_root`` genuinely name
         it, and the consistency proof (the ``bryce-cose-receipts-mmr-profile``
         relation, verified via ``core.verify_consistency``) bridging the
         two roots; if absent: that ``checkpoint.prev_size == 0`` — this is
         honestly the log's first checkpoint, not a silently dropped lower
         bound. **Label honestly:** a passing consistency check proves the
         history *within this bundle* was not rewritten/reordered/truncated
         between the two checkpoints (anti-REWRITE) — it does NOT prove no
         divergent history exists elsewhere (anti-FORK/anti-equivocation),
         since a forker can build two internally-consistent bundles and one
         offline verifier never sees both sides. The success notice reads
         exactly "history intact between checkpoints N and M" and never "no
         fork" / "not equivocated" — that guarantee is the witness's and
         multi-witness config's job, never this offline check's;
      4. witness stamp authenticity, if the covering checkpoint carries any
         (``verify_witness_stamp_tristate`` per ``WitnessRecord``). Each
         stamp resolves to one of three states, per ``ts_url`` matched
         against ``trust_anchor``/the pinned default witness:
           - WITNESSED (a supplied/pinned key verifies it) — the checkpoint
             genuinely is witnessed via this stamp;
           - UNVERIFIED (well-formed, checkpoint-bound, but its TS has no
             supplied pin) — reported as a non-fatal notice
             (``"witnessed by <url>, pin not supplied — unverified
             stamp"``), NEVER fatal on its own: a self-hosted/zero-egress
             TS a caller has not pinned is not evidence of forgery;
           - INVALID (not even a well-formed checkpoint-bound stamp, or a
             KNOWN/pinned TS's signature that fails) — a fatal notice,
             UNLESS at least one other stamp is WITNESSED (any-of), in
             which case it demotes to a non-fatal notice since the
             checkpoint genuinely IS witnessed via the valid one.
         The bundle is fatal on the witness dimension iff no stamp is
         WITNESSED **and** at least one is INVALID;
      5. if present, ``checkpoint_cose`` — the covering checkpoint's
         COSE_Sign1 wire form, independently re-verified via
         ``cose_wire.verify_checkpoint_cose_offline`` (signature under its
         own ``kid``, CWT identity, and — if it carries one — a REAL MMR
         consistency proof, not field equality) and then cross-checked
         field-for-field against ``b.checkpoint``. Fatal if present but
         invalid or mismatched; simply absent (older bundles, or a
         production-time COSE-serialization failure) is non-fatal — this
         field is additive, never required.

    Returns ``(ok, errors)`` — ``ok`` is false iff a FATAL problem was
    found; ``errors`` also carries non-fatal notices — so it is not empty
    on plenty of fully-passing bundles, not just the mixed-witness case.
    """
    from . import core as mmr_core
    from .cose_wire import verify_checkpoint_cose_offline
    from .emit import StampVerdict, verify_checkpoint_signature_offline, verify_witness_stamp_tristate

    errors: list[str] = []
    notices: list[str] = []
    try:
        body_digest = bytes.fromhex(b.capsule_id)
        root = bytes.fromhex(b.checkpoint.root)
        if not mmr_core.verify_inclusion(
            root, b.checkpoint.mmr_size, b.seq - 1, body_digest, b.inclusion_proof
        ):
            errors.append("inclusion proof does not verify against the covering checkpoint's root")

        if not verify_checkpoint_signature_offline(b.checkpoint):
            errors.append("covering checkpoint signature does not verify")

        if b.prior_checkpoint is not None:
            if not verify_checkpoint_signature_offline(b.prior_checkpoint):
                errors.append("prior checkpoint signature does not verify")
            if b.checkpoint.prev_size != b.prior_checkpoint.mmr_size:
                errors.append("checkpoint.prev_size does not match prior_checkpoint.mmr_size")
            if b.checkpoint.prev_root != b.prior_checkpoint.root:
                errors.append("checkpoint.prev_root does not match prior_checkpoint.root")
            if b.consistency_proof is None:
                errors.append("prior_checkpoint is present but consistency_proof is missing")
            else:
                root_a = bytes.fromhex(b.prior_checkpoint.root)
                if not mmr_core.verify_consistency(
                    root_a,
                    b.prior_checkpoint.mmr_size,
                    root,
                    b.checkpoint.mmr_size,
                    b.consistency_proof,
                ):
                    errors.append("consistency proof does not bridge prior_checkpoint to checkpoint")
                else:
                    notices.append(
                        "history intact between checkpoints "
                        f"{b.prior_checkpoint.mmr_size} and {b.checkpoint.mmr_size} "
                        "(consistency proof verified) -- rules out rewrite/reorder/"
                        "truncation between them; does not rule out a divergent fork, "
                        "which only a witness attests to"
                    )
        else:
            if b.checkpoint.prev_size != 0:
                errors.append("prior_checkpoint is missing but checkpoint.prev_size != 0")
            if b.consistency_proof is not None:
                errors.append("consistency_proof present without a prior_checkpoint")
            if b.checkpoint.prev_size == 0 and b.consistency_proof is None:
                notices.append(
                    f"no prior checkpoint -- checkpoint at mmr_size={b.checkpoint.mmr_size} "
                    "is this log's first; there is no earlier history to check continuity "
                    "against"
                )

        if b.checkpoint_cose is not None:
            cose_result = verify_checkpoint_cose_offline(b.checkpoint_cose)
            if not cose_result.ok:
                errors.append(
                    "checkpoint COSE-wire statement failed to verify: "
                    + "; ".join(cose_result.errors)
                )
            else:
                decoded = cose_result.decoded
                if (
                    decoded.log_id != b.checkpoint.log_id
                    or decoded.mmr_size != b.checkpoint.mmr_size
                    or decoded.root != b.checkpoint.root
                    or decoded.prev_size != b.checkpoint.prev_size
                    or decoded.prev_root != b.checkpoint.prev_root
                    or decoded.key_id != b.checkpoint.key_id
                ):
                    errors.append(
                        "checkpoint COSE-wire statement fields do not match the bundle's "
                        "JSON checkpoint"
                    )
                else:
                    notices.append(
                        "checkpoint COSE-wire statement independently verified (signature + "
                        "CWT identity + consistency proof, if any) -- checkable by a generic "
                        "COSE/SCITT verifier with no cll-specific code"
                    )

        if b.checkpoint.witnesses:
            stamp_checks = [
                (
                    w,
                    verify_witness_stamp_tristate(
                        b.checkpoint, w, ts_pubkey_pem=(trust_anchor or {}).get(w.ts_url)
                    ),
                )
                for w in b.checkpoint.witnesses
            ]
            any_witnessed = any(v is StampVerdict.WITNESSED for _, (v, _) in stamp_checks)
            any_invalid = any(v is StampVerdict.INVALID for _, (v, _) in stamp_checks)
            for w, (verdict, werrs) in stamp_checks:
                if verdict is StampVerdict.WITNESSED:
                    continue
                if verdict is StampVerdict.UNVERIFIED:
                    notices.extend(werrs)
                    continue
                detail = "; ".join(werrs) if werrs else "does not verify"
                msg = f"witness stamp ({w.ts_url}) INVALID: {detail}"
                (notices if any_witnessed else errors).append(msg)
            if not any_witnessed and any_invalid:
                errors.append(
                    f"checkpoint claims {len(b.checkpoint.witnesses)} witness stamp(s) but none "
                    "verify as authentic TS Receipts for this checkpoint"
                )
    except Exception as exc:  # noqa: BLE001 — pure verifier, never raises
        errors.append(f"unexpected error: {exc}")
        return False, errors + notices

    return not errors, errors + notices
