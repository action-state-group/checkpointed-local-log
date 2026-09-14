# SPDX-License-Identifier: Apache-2.0
"""Time-fenced key revocation, reconstructed from the ledger's own rotation
history.

**Ported from ``capsule-ledger``'s ``guards/revocation.py`` per the W3
CLL-revocation reconciliation (2026-09-02).** The W3.1 CLL extraction
originally left this check out of :class:`~cll.ledger.store.LedgerStore`
on the theory that it was guard/policy-layer product code; the 2026-09-01
dependency-trace ruling reclassified it as a verify-primitive that belongs
in the log-core namespace instead (a counterparty verifying a log needs
this to get a complete verify out of the box -- it does not need any
guard/policy layer to interoperate). ``LedgerStore.verify`` now wires this
in as a DEFAULT finding (see that module) -- this module stays usable
standalone (e.g. by a remote ``LedgerAPI`` binding, or a caller composing
its own store).

Design intent: rotating a signing key is itself a recorded event -- any
capsule a caller appends to the ledger through the normal write path,
naming the outgoing key's fingerprint, the incoming key's fingerprint, and
the timestamp the rotation took effect. Because that event sits in the
ledger like any other record, a verifier can walk the ledger alone -- no
secret key material required -- and rebuild the timeline of which
``key_id`` was live at which point in time.

Revocation is *time-fenced*, not retroactive: a record honestly signed by a
key at or before that key's rotation timestamp stays valid forever --
including the rotation event itself, which is the outgoing key's own last
legitimate act and is timestamped at exactly its own ``revoked_at`` (the
boundary is inclusive on that side deliberately, so the rotation record
always verifies). A record that claims a timestamp strictly *after* its
signing key's rotation timestamp is rejected -- that combination can only
arise from a clock lie or a replay attempting to trade on a compromised,
since-rotated key.
"""
from __future__ import annotations

from dataclasses import dataclass

from .ledger.api import LedgerAPI

__all__ = [
    "ROTATION_EVENT",
    "KeyWindow",
    "RevocationFinding",
    "build_key_timeline",
    "check_time_fenced_revocation",
]

ROTATION_EVENT = "key_rotation"


@dataclass(frozen=True)
class KeyWindow:
    """The ledger-visible lifetime of one signing key.

    ``revoked_at`` is ``None`` while the key is still the active signer.
    """

    key_id: str
    activated_at: str | None
    revoked_at: str | None


@dataclass(frozen=True)
class RevocationFinding:
    ok: bool
    reason: str | None = None


def build_key_timeline(ledger: LedgerAPI) -> dict[str, KeyWindow]:
    """Scan ``ledger`` for ``key_rotation`` event capsules and rebuild the
    key_id -> :class:`KeyWindow` map they imply. Reconstructable from the
    ledger alone, in ledger (append) order -- the earliest rotation touching
    a given key_id sets its ``activated_at``; the earliest rotation *away*
    from it sets its ``revoked_at``.
    """
    windows: dict[str, KeyWindow] = {}
    for record in ledger.scan():
        payload = record.capsule.get("asg_payload") or {}
        if payload.get("event") != ROTATION_EVENT:
            continue
        detail = payload.get("detail") or {}
        old_id = detail.get("old_key_id")
        new_id = detail.get("new_key_id")
        rotated_at = detail.get("rotated_at")

        if isinstance(old_id, str):
            existing = windows.get(old_id)
            activated = existing.activated_at if existing else None
            if existing is None or existing.revoked_at is None:
                windows[old_id] = KeyWindow(key_id=old_id, activated_at=activated, revoked_at=rotated_at)

        if isinstance(new_id, str):
            existing = windows.get(new_id)
            revoked = existing.revoked_at if existing else None
            windows[new_id] = KeyWindow(key_id=new_id, activated_at=rotated_at, revoked_at=revoked)

    return windows


def check_time_fenced_revocation(capsule: dict, timeline: dict[str, KeyWindow]) -> RevocationFinding:
    """Is ``capsule``'s claimed signing key + timestamp inside that key's
    live window per ``timeline``?

    A ``key_id`` absent from the timeline (never rotated) or a capsule
    missing the fields needed to check at all is not rejected here -- there
    is no recorded fence to enforce yet. That is a deliberate scope
    boundary: this is the time-fence check only, not general signature
    verification (this module has no COSE/asymmetric verification path;
    see ``cll.ledger.store``'s own producer-envelope admission contract for
    that, and ``signing.py``'s module docstring for how the two relate).
    """
    sig = capsule.get("asg_signature") or {}
    key_id = sig.get("key_id")
    timestamp = capsule.get("timestamp")
    if not isinstance(key_id, str) or not isinstance(timestamp, str):
        return RevocationFinding(ok=True)

    window = timeline.get(key_id)
    if window is None or window.revoked_at is None:
        return RevocationFinding(ok=True)

    if timestamp > window.revoked_at:
        return RevocationFinding(
            ok=False,
            reason=(
                f"capsule claims key_id={key_id!r} at timestamp {timestamp}, but that key "
                f"was revoked at {window.revoked_at} (time-fenced revocation: a revoked key's "
                "signature is only trusted for records dated at or before its revocation timestamp)"
            ),
        )
    return RevocationFinding(ok=True)
