# SPDX-License-Identifier: Apache-2.0
"""MmrLedger wired to a LogSource-shaped fake: append/sync, inclusion and
range proofs, and the MMR stability property across appends -- the whole
point of this data structure over a naive Merkle tree.

Ported from capsule-ledger's ``tests/test_mmr_index.py``, generalized from a
real ``LedgerStore`` to the ``FakeLogSource`` in ``conftest.py`` so this
package's own test suite carries no dependency on capsule-ledger. The
downstream smoke check (a real ``LedgerStore`` driven through
``cll.checkpoint.MmrLedger``) is reported separately -- see the
outbox entry for this task.
"""
from __future__ import annotations

import copy

from tests.checkpoint.conftest import FakeLogSource, synthetic_capsule

from cll.checkpoint import core
from cll.checkpoint.index import MmrLedger, verify_range

# -- append wiring + sync -----------------------------------------------


def test_append_through_wrapper_indexes_immediately(log_source):
    mmr = MmrLedger(log_source)
    for i in range(5):
        mmr.append(synthetic_capsule(i), consequential=False)
    assert mmr.leaf_count() == 5
    assert mmr.size() == core.node_count(5)
    assert mmr.root() != core.root_from_peaks([])


def test_sync_catches_up_a_log_populated_without_the_wrapper(log_source):
    for i in range(6):
        log_source.append(synthetic_capsule(i), consequential=False)

    mmr = MmrLedger(log_source)
    assert mmr.leaf_count() == 0  # nothing indexed yet -- append() was never used
    added = mmr.sync()
    assert added == 6
    assert mmr.leaf_count() == 6

    # idempotent: calling sync() again adds nothing
    assert mmr.sync() == 0
    assert mmr.leaf_count() == 6


def test_sync_and_append_produce_the_same_root_for_the_same_leaves():
    capsules = [synthetic_capsule(i) for i in range(9)]

    source_a = FakeLogSource()
    mmr_a = MmrLedger(source_a)
    for cap in capsules:
        mmr_a.append(copy.deepcopy(cap), consequential=False)
    root_a = mmr_a.root()

    source_b = FakeLogSource()
    for cap in capsules:
        source_b.append(copy.deepcopy(cap), consequential=False)
    mmr_b = MmrLedger(source_b)
    mmr_b.sync()
    root_b = mmr_b.root()

    assert root_a == root_b


def test_mmr_ledger_delegates_scan_fetch_find_gaps(log_source):
    mmr = MmrLedger(log_source)
    for i in range(4):
        log_source.append(synthetic_capsule(i), consequential=False)
    mmr.sync()
    assert mmr.leaf_count() == 4

    scanned = list(mmr.scan())
    assert len(scanned) == 4
    fetched = mmr.fetch(scanned[0].capsule_id)
    assert fetched is not None
    assert mmr.find_gaps() == []


# -- inclusion proofs -----------------------------------------------------


def test_inclusion_proof_round_trips(log_source):
    mmr = MmrLedger(log_source)
    n = 12
    for i in range(n):
        mmr.append(synthetic_capsule(i), consequential=False)

    root = mmr.root()
    size = mmr.size()
    for seq in range(1, n + 1):
        proof = mmr.inclusion_proof(seq)
        bd = mmr.body_digest(seq)
        assert core.verify_inclusion(root, size, seq - 1, bd, proof)


def test_inclusion_proof_rejects_tampered_body_digest(log_source):
    mmr = MmrLedger(log_source)
    for i in range(6):
        mmr.append(synthetic_capsule(i), consequential=False)

    root = mmr.root()
    size = mmr.size()
    seq = 3
    proof = mmr.inclusion_proof(seq)
    bd = bytearray(mmr.body_digest(seq))
    bd[0] ^= 0xFF
    assert not core.verify_inclusion(root, size, seq - 1, bytes(bd), proof)
    assert core.verify_inclusion(root, size, seq - 1, mmr.body_digest(seq), proof)


# -- range proofs -----------------------------------------------------------


def test_range_proof_round_trips(log_source):
    mmr = MmrLedger(log_source)
    n = 8
    for i in range(n):
        mmr.append(synthetic_capsule(i), consequential=False)

    # range_proof pins its size to node_count(to_seq) -- the MMR as it stood
    # right when to_seq was appended, not necessarily the log's current size
    # (the log has grown to n=8 here). Verify against that pinned size's own
    # root, per the RangeProof docstring.
    from_seq, to_seq = 2, 5
    proof = mmr.range_proof(from_seq, to_seq)
    root = mmr.root_at(proof.size)
    from_digest = mmr.body_digest(from_seq)
    to_digest = mmr.body_digest(to_seq)
    assert verify_range(root, from_seq, to_seq, from_digest, to_digest, proof)


def test_range_proof_rejects_tampered_boundary_digest(log_source):
    mmr = MmrLedger(log_source)
    n = 7
    for i in range(n):
        mmr.append(synthetic_capsule(i), consequential=False)

    from_seq, to_seq = 1, 4
    proof = mmr.range_proof(from_seq, to_seq)
    root = mmr.root_at(proof.size)
    from_digest = mmr.body_digest(from_seq)
    to_digest = mmr.body_digest(to_seq)
    assert verify_range(root, from_seq, to_seq, from_digest, to_digest, proof)

    tampered = bytearray(to_digest)
    tampered[0] ^= 0xFF
    assert not verify_range(root, from_seq, to_seq, from_digest, bytes(tampered), proof)


# -- stability across appends: the whole point of an MMR ---------------------


def test_inclusion_proof_stability_across_appends(log_source):
    """A proof taken while the log had 7 leaves must stay valid against its
    own frozen root forever, and a consistency proof must bridge it forward
    to a later root without recomputing anything about the original leaf."""
    mmr = MmrLedger(log_source)
    for i in range(7):
        mmr.append(synthetic_capsule(i), consequential=False)

    old_size = mmr.size()
    old_root = mmr.root()
    seq = 3
    old_proof = mmr.inclusion_proof(seq, size=old_size)
    old_body_digest = mmr.body_digest(seq)

    assert core.peaks(old_size) == [6, 9, 10]
    old_peak_bytes_before = mmr.peak_hashes_at(old_size)[0]  # peak at pos 6

    assert core.verify_inclusion(old_root, old_size, seq - 1, old_body_digest, old_proof)

    for i in range(7, 10):
        mmr.append(synthetic_capsule(i), consequential=False)

    new_size = mmr.size()
    new_root = mmr.root()
    assert new_size != old_size
    assert new_root != old_root

    # old peak's containing mountain has grown -- pos 6 is no longer a peak
    assert 6 not in core.peaks(new_size)

    # but the old peak's own hash bytes were never rewritten
    old_peak_bytes_after = mmr._nodes.node(6)  # noqa: SLF001 -- test-only introspection
    assert old_peak_bytes_after == old_peak_bytes_before

    # the ORIGINAL proof against the ORIGINAL root still verifies, untouched
    assert core.verify_inclusion(old_root, old_size, seq - 1, old_body_digest, old_proof)

    # trust bridges to the new root via a cheap consistency proof
    bridge = mmr.consistency_proof(old_size, new_size)
    assert core.verify_consistency(old_root, old_size, new_root, new_size, bridge)


def test_range_proof_stability_across_appends(log_source):
    mmr = MmrLedger(log_source)
    for i in range(7):
        mmr.append(synthetic_capsule(i), consequential=False)

    old_range = mmr.range_proof(2, 5)
    old_size = old_range.size
    from_digest = mmr.body_digest(2)
    to_digest = mmr.body_digest(5)
    root_at_old_size = core.root_from_peaks(mmr.peak_hashes_at(old_size))
    assert verify_range(root_at_old_size, 2, 5, from_digest, to_digest, old_range)

    for i in range(7, 10):
        mmr.append(synthetic_capsule(i), consequential=False)

    new_size = mmr.size()
    new_root = mmr.root()

    assert verify_range(root_at_old_size, 2, 5, from_digest, to_digest, old_range)

    bridge = mmr.consistency_proof(old_size, new_size)
    assert core.verify_consistency(root_at_old_size, old_size, new_root, new_size, bridge)


# -- LogSource duck-typing: no import of any concrete log implementation ----


def test_mmr_ledger_never_imports_a_concrete_log_binding():
    """MmrLedger accepts anything shaped like LogSource -- confirmed here by
    passing an object that is *not* an instance of any named base class."""

    class Anonymous:
        def __init__(self):
            self._recs = []

        def append(self, capsule, *, consequential=True):
            import hashlib

            from tests.checkpoint.conftest import FakeRecord

            capsule_id = hashlib.sha256(str(len(self._recs)).encode()).hexdigest()
            rec = FakeRecord(seq=len(self._recs) + 1, capsule_id=capsule_id, capsule=capsule)
            self._recs.append(rec)
            return rec

        def scan(self, query=None):
            return iter(self._recs)

        def fetch(self, capsule_id):
            return None

        def verify(self, capsule_id):
            return None

        def find_gaps(self):
            return []

    mmr = MmrLedger(Anonymous())
    mmr.append({"x": 1})
    assert mmr.leaf_count() == 1
