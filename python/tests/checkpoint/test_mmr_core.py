# SPDX-License-Identifier: Apache-2.0
"""Core MMR algorithm tests: identity/position-math properties, pinned KAT
append-sequence vectors, inclusion-proof matrices, and adversarial
tamper-rejection (I2 discipline -- pinned known-answer tests, not just unit
tests of the algorithm's own logic).
"""
from __future__ import annotations

import hashlib

import pytest

from cll.checkpoint import core
from cll.checkpoint.store import MemoryNodeStore


def _popcount(n: int) -> int:
    return bin(n).count("1")


def _body_digest(seed: int) -> bytes:
    return hashlib.sha256(f"asg-ledger-mmr-vector-leaf-{seed}".encode()).digest()


def _root_at(store: MemoryNodeStore, size: int) -> bytes:
    pks = core.peaks(size)
    return core.root_from_peaks([store.node(p) for p in pks])


def _flip_hex_byte(hex_str: str, byte_index: int) -> str:
    b = bytearray(bytes.fromhex(hex_str))
    b[byte_index] ^= 0xFF
    return bytes(b).hex()


def _build_mmr(n: int) -> tuple[MemoryNodeStore, list[bytes]]:
    store = MemoryNodeStore()
    digests = []
    for i in range(n):
        bd = _body_digest(i)
        digests.append(bd)
        core.add_leaf(store, core.leaf_hash(bd))
    return store, digests


# -- identity sweep (position math) ------------------------------------------


def test_node_count_and_peak_count_identity_sweep_1_to_2048():
    for f in range(1, 2049):
        expected_node_count = 2 * f - _popcount(f)
        assert core.node_count(f) == expected_node_count
        pks = core.peaks(core.node_count(f))
        assert len(pks) == _popcount(f)


def test_leaf_index_pos_roundtrip_exhaustive_to_512_sampled_beyond():
    for f in range(1, 513):
        for leaf_index in range(f):
            pos = core.leaf_index_to_pos(leaf_index)
            assert core.height_at(pos) == 0
            assert core.pos_to_leaf_index(pos) == leaf_index
    for f in range(513, 2049):
        samples = {i for i in (0, 1, f // 2, f - 2, f - 1) if 0 <= i < f}
        for leaf_index in samples:
            pos = core.leaf_index_to_pos(leaf_index)
            assert core.height_at(pos) == 0
            assert core.pos_to_leaf_index(pos) == leaf_index


def test_leaf_count_inverts_node_count():
    for f in range(0, 2049):
        assert core.leaf_count(core.node_count(f)) == f


def test_empty_mmr_root_is_32_zero_bytes():
    assert core.peaks(0) == []
    assert core.leaf_count(0) == 0
    root = core.root_from_peaks([])
    assert root == bytes(32)


def test_invalid_mmr_sizes_rejected():
    # size=2 is never a valid node_count(f): would require two adjacent
    # same-height peaks, which is structurally impossible.
    for bad_size in (2, 5, 6):
        with pytest.raises(core.InvalidArgumentError):
            core.peaks(bad_size)
        with pytest.raises(core.InvalidArgumentError):
            core.leaf_count(bad_size)


# -- determinism --------------------------------------------------------


def test_same_leaves_same_root_independent_of_process():
    n = 77
    digests = [_body_digest(i + 1000) for i in range(n)]

    store_a = MemoryNodeStore()
    for d in digests:
        core.add_leaf(store_a, core.leaf_hash(d))
    root_a = _root_at(store_a, store_a.size())

    store_b = MemoryNodeStore()
    for d in digests:
        core.add_leaf(store_b, core.leaf_hash(d))
    root_b = _root_at(store_b, store_b.size())

    assert root_a == root_b


def test_interleaving_unrelated_mmrs_does_not_perturb_a_stream_own_root():
    n = 40
    digests_a = [_body_digest(i + 2000) for i in range(n)]
    digests_c = [_body_digest(i + 5000) for i in range(n)]

    baseline = MemoryNodeStore()
    for d in digests_a:
        core.add_leaf(baseline, core.leaf_hash(d))
    root_baseline = _root_at(baseline, baseline.size())

    store_a = MemoryNodeStore()
    store_c = MemoryNodeStore()
    for i in range(n):
        core.add_leaf(store_a, core.leaf_hash(digests_a[i]))
        core.add_leaf(store_c, core.leaf_hash(digests_c[i]))
    root_interleaved = _root_at(store_a, store_a.size())

    assert root_interleaved == root_baseline


# -- pinned KAT: 7-leaf append sequence --------------------------------------
#
# Peak *positions* below are hand-derived from the flat-array MMR layout
# (independent of this module's own code): building leaves 0..6 one at a
# time yields positions 0,1,3,4,7,8,10 for leaves and 2,5,6,9 for interior
# nodes (2=parent(0,1), 5=parent(3,4), 6=parent(2,5), 9=parent(7,8)) --
# cross-checked against node_count(f) = 2f - popcount(f) and
# len(peaks) == popcount(f) above. Root *hashes* can't be hand-computed by a
# human; they are pinned from an actual run (frozen for regression), the
# same "generate once, pin the output, assert against it forever" discipline
# used by this repo's fold-engine KATs.

_EXPECTED_PEAKS_BY_LEAF_COUNT = {
    1: [0],
    2: [2],
    3: [2, 3],
    4: [6],
    5: [6, 7],
    6: [6, 9],
    7: [6, 9, 10],
}

_PINNED_ROOTS_BY_LEAF_COUNT = {
    1: "184208f662bb7a6f5cc14a39988f74f2bb05bd3f934311da0aa3f65a950d8e01",
    2: "f7b19d3f831d2cddfe91865465a8beb649e4bf16c3aa2fde7378e7ee2e215694",
    3: "e5280e43815bcb82f184d4dbe10741b65a28c34488a9a3029e0e08d1cbed9a17",
    4: "44588de7a213cb67d681fd0822d22f57248a50b5cab4d5579c1d9162403b6755",
    5: "a19de527084fc32502d998b4dd0e73f942d3b4ddc55b2c093dfd907e95a93f1a",
    6: "ade39981df4d01db5a3c3e5d1ff0a6f87ea3a63077820d37599c6a39fb904b01",
    7: "a0c0e8e7d78bf06dee4c988a228ff034dca8a25964a4af89a3d7d11670f31d10",
}


def test_kat_7_leaf_append_sequence_peak_structure_and_root():
    store = MemoryNodeStore()
    for n in range(1, 8):
        bd = _body_digest(n)
        core.add_leaf(store, core.leaf_hash(bd))
        size = store.size()
        pks = core.peaks(size)
        assert pks == _EXPECTED_PEAKS_BY_LEAF_COUNT[n], f"leaf count {n}: peak positions"
        root = _root_at(store, size)
        assert root.hex() == _PINNED_ROOTS_BY_LEAF_COUNT[n], f"leaf count {n}: root"


def test_kat_hashing_scheme_independent_cross_check_5_leaves():
    """Reconstructs the 5-leaf root via bare hashlib calls (not this module's
    own leaf_hash/interior_hash/root_from_peaks) to confirm the pinned root
    above isn't just self-consistent with a buggy implementation.

    Positions for the interior nodes (2, 5, 6) are hand-derived from the flat
    layout, same as the peak positions above, independent of this module's
    own code."""

    def ref_leaf(bd: bytes) -> bytes:
        return hashlib.sha256(b"\x00" + bd).digest()

    def ref_interior(left: bytes, right: bytes, position: int) -> bytes:
        pos_bytes = (position + 1).to_bytes(8, "big")
        return hashlib.sha256(pos_bytes + left + right).digest()

    def ref_bag(ps: list[bytes]) -> bytes:
        if not ps:
            return bytes(32)
        hashes = list(ps)
        while len(hashes) > 1:
            right = hashes.pop()
            left = hashes.pop()
            hashes.append(hashlib.sha256(right + left).digest())
        return hashes[0]

    digests = [_body_digest(n) for n in range(1, 6)]
    leaves = [ref_leaf(bd) for bd in digests]
    p2 = ref_interior(leaves[0], leaves[1], 2)
    p5 = ref_interior(leaves[2], leaves[3], 5)
    p6 = ref_interior(p2, p5, 6)
    expected_root = ref_bag([p6, leaves[4]])  # peaks: pos6 (height2), pos7 (leaf4, height0)

    assert expected_root.hex() == _PINNED_ROOTS_BY_LEAF_COUNT[5]

    store = MemoryNodeStore()
    for bd in digests:
        core.add_leaf(store, core.leaf_hash(bd))
    assert store.size() == 8  # node_count(5) = 10 - popcount(5)=2 -> 8
    assert core.peaks(8) == [6, 7]
    assert _root_at(store, 8) == expected_root


# -- inclusion proofs -----------------------------------------------------


def test_inclusion_proof_verifies_for_every_leaf_at_every_size_1_to_256():
    store = MemoryNodeStore()
    digests: list[bytes] = []
    for size in range(1, 257):
        bd = _body_digest(size + 100_000)
        digests.append(bd)
        core.add_leaf(store, core.leaf_hash(bd))
        mmr_size = store.size()
        root = _root_at(store, mmr_size)

        for leaf_index in range(size):
            proof = core.inclusion_proof(store, leaf_index, mmr_size)
            assert core.verify_inclusion(root, mmr_size, leaf_index, digests[leaf_index], proof)


def test_inclusion_proof_spot_checks_at_4096_leaves():
    n = 4096
    store = MemoryNodeStore()
    digests = []
    for i in range(n):
        bd = _body_digest(i + 200_000)
        digests.append(bd)
        core.add_leaf(store, core.leaf_hash(bd))
    mmr_size = store.size()
    root = _root_at(store, mmr_size)

    spot_indices = {0, 1, 2, n - 1, n - 2, n // 2, n // 2 - 1, n // 2 + 1, 1023, 1024, 1025, 2047, 2048, 3000}
    for leaf_index in spot_indices:
        proof = core.inclusion_proof(store, leaf_index, mmr_size)
        assert core.verify_inclusion(root, mmr_size, leaf_index, digests[leaf_index], proof)


def test_inclusion_adversarial_flipping_every_byte_causes_rejection():
    n = 250  # not a power of 2: multiple peaks, non-trivial witness+peaksLeft+peaksRight
    store, digests = _build_mmr(n)
    mmr_size = store.size()
    root = _root_at(store, mmr_size)

    leaf_index = 123
    proof = core.inclusion_proof(store, leaf_index, mmr_size)
    assert len(proof.witness) + len(proof.peaks_left) + len(proof.peaks_right) > 0
    assert core.verify_inclusion(root, mmr_size, leaf_index, digests[leaf_index], proof)

    for field in ("witness", "peaks_left", "peaks_right"):
        arr = getattr(proof, field)
        for entry_idx in range(len(arr)):
            for byte_idx in range(core.DIGEST_LEN):
                tampered_list = list(arr)
                tampered_list[entry_idx] = _flip_hex_byte(arr[entry_idx], byte_idx)
                tampered = _replace(proof, **{field: tuple(tampered_list)})
                assert not core.verify_inclusion(root, mmr_size, leaf_index, digests[leaf_index], tampered)


def _replace(proof, **kwargs):
    from dataclasses import replace

    return replace(proof, **kwargs)


def test_inclusion_adversarial_perturb_root_digest_leafindex_size():
    n = 17
    store, digests = _build_mmr(n)
    mmr_size = store.size()
    root = _root_at(store, mmr_size)
    leaf_index = 5
    proof = core.inclusion_proof(store, leaf_index, mmr_size)
    assert core.verify_inclusion(root, mmr_size, leaf_index, digests[leaf_index], proof)

    for i in range(core.DIGEST_LEN):
        bad_root = bytearray(root)
        bad_root[i] ^= 0xFF
        assert not core.verify_inclusion(bytes(bad_root), mmr_size, leaf_index, digests[leaf_index], proof)

    for i in range(core.DIGEST_LEN):
        bad_digest = bytearray(digests[leaf_index])
        bad_digest[i] ^= 0xFF
        assert not core.verify_inclusion(root, mmr_size, leaf_index, bytes(bad_digest), proof)

    assert not core.verify_inclusion(root, mmr_size, leaf_index + 1, digests[leaf_index], proof)
    assert not core.verify_inclusion(root, mmr_size, leaf_index - 1, digests[leaf_index], proof)
    assert not core.verify_inclusion(root, mmr_size + 1, leaf_index, digests[leaf_index], proof)
    assert not core.verify_inclusion(root, mmr_size - 1, leaf_index, digests[leaf_index], proof)

    assert not core.verify_inclusion(
        root, mmr_size, leaf_index, digests[leaf_index], _replace(proof, size=mmr_size + 1)
    )
    assert not core.verify_inclusion(
        root, mmr_size, leaf_index, digests[leaf_index], _replace(proof, leaf_index=leaf_index + 1)
    )


def test_inclusion_adversarial_rejects_wrong_length_witness_and_peaks():
    n = 250
    store, digests = _build_mmr(n)
    mmr_size = store.size()
    root = _root_at(store, mmr_size)

    leaf_index = None
    proof = None
    for i in range(n):
        p = core.inclusion_proof(store, i, mmr_size)
        if len(p.witness) > 0:
            leaf_index = i
            proof = p
            break
    assert proof is not None
    bd = digests[leaf_index]

    assert not core.verify_inclusion(root, mmr_size, leaf_index, bd, _replace(proof, witness=()))
    assert not core.verify_inclusion(
        root, mmr_size, leaf_index, bd, _replace(proof, witness=proof.witness[:-1])
    )
    assert not core.verify_inclusion(
        root, mmr_size, leaf_index, bd, _replace(proof, witness=proof.witness + (proof.witness[-1],))
    )
    assert not core.verify_inclusion(
        root, mmr_size, leaf_index, bd, _replace(proof, peaks_left=proof.peaks_left + ("00" * 32,))
    )
    if proof.peaks_right:
        assert not core.verify_inclusion(
            root, mmr_size, leaf_index, bd, _replace(proof, peaks_right=proof.peaks_right[:-1])
        )
    else:
        assert not core.verify_inclusion(
            root, mmr_size, leaf_index, bd, _replace(proof, peaks_right=("00" * 32,))
        )

    # Malformed hex must be rejected, never raise.
    bad_witness = ("not-hex",) + proof.witness[1:] if proof.witness else proof.witness
    assert core.verify_inclusion(root, mmr_size, leaf_index, bd, _replace(proof, witness=bad_witness)) is False

    assert core.verify_inclusion(root, mmr_size, leaf_index, bd, _replace(proof, kind="consistency")) is False
    assert core.verify_inclusion(root, mmr_size, leaf_index, bd, _replace(proof, v=2)) is False


def test_inclusion_empty_mmr_has_no_leaves_to_prove():
    zero_root = core.root_from_peaks([])
    fake_proof = core.InclusionProof(1, "inclusion", 0, 0, (), (), ())
    assert not core.verify_inclusion(zero_root, 0, 0, _body_digest(1), fake_proof)


# -- consistency proofs (the "range proof" mechanism) ------------------------


def test_consistency_proof_verifies_for_all_pairs_up_to_128_leaves():
    max_leaves = 128
    store, digests = _build_mmr(max_leaves)
    root_at_size = {0: core.root_from_peaks([])}
    running = MemoryNodeStore()
    for bd in digests:
        core.add_leaf(running, core.leaf_hash(bd))
        root_at_size[running.size()] = _root_at(running, running.size())

    for a in range(0, max_leaves + 1, 8):  # sampled: full 128x128 matrix is slow in pure Python
        size_a = core.node_count(a)
        root_a = root_at_size[size_a]
        for b in range(a, max_leaves + 1, 8):
            size_b = core.node_count(b)
            root_b = root_at_size[size_b]
            proof = core.consistency_proof(store, size_a, size_b)
            assert core.verify_consistency(root_a, size_a, root_b, size_b, proof)


def test_consistency_root_a_forged_fails():
    store, digests = _build_mmr(60)
    running = MemoryNodeStore()
    root_at_size = {0: core.root_from_peaks([])}
    for bd in digests:
        core.add_leaf(running, core.leaf_hash(bd))
        root_at_size[running.size()] = _root_at(running, running.size())

    for a, b in ((0, 60), (1, 60), (30, 60), (59, 60), (60, 60)):
        size_a = core.node_count(a)
        size_b = core.node_count(b)
        root_a = root_at_size[size_a]
        root_b = root_at_size[size_b]
        proof = core.consistency_proof(store, size_a, size_b)
        assert core.verify_consistency(root_a, size_a, root_b, size_b, proof)

        for i in range(core.DIGEST_LEN):
            forged = bytearray(root_a)
            forged[i] ^= 0xFF
            assert not core.verify_consistency(bytes(forged), size_a, root_b, size_b, proof)

        forged_b = bytearray(root_b)
        forged_b[0] ^= 0xFF
        assert not core.verify_consistency(root_a, size_a, bytes(forged_b), size_b, proof)


def test_consistency_verifies_old_roots_against_a_replayed_log():
    store, digests = _build_mmr(90)
    root_at_size = {0: core.root_from_peaks([])}
    running = MemoryNodeStore()
    for bd in digests:
        core.add_leaf(running, core.leaf_hash(bd))
        root_at_size[running.size()] = _root_at(running, running.size())

    for a in (0, 1, 2, 5, 33, 64, 89, 90):
        size_a = core.node_count(a)
        replay = MemoryNodeStore()
        for i in range(a):
            core.add_leaf(replay, core.leaf_hash(_body_digest(i)))
        replayed_root = _root_at(replay, replay.size())
        assert replayed_root == root_at_size[size_a]

        size_b = core.node_count(90)
        root_b = root_at_size[size_b]
        proof = core.consistency_proof(store, size_a, size_b)
        assert core.verify_consistency(replayed_root, size_a, root_b, size_b, proof)


def test_consistency_adversarial_byte_flips_cause_rejection():
    store, digests = _build_mmr(90)
    size_a = core.node_count(37)
    size_b = core.node_count(90)
    root_a = _root_at(store, size_a)
    root_b = _root_at(store, size_b)
    proof = core.consistency_proof(store, size_a, size_b)
    assert core.verify_consistency(root_a, size_a, root_b, size_b, proof)

    for field in ("old_peaks", "new_peaks"):
        arr = getattr(proof, field)
        for entry_idx in range(len(arr)):
            for byte_idx in range(core.DIGEST_LEN):
                tampered_list = list(arr)
                tampered_list[entry_idx] = _flip_hex_byte(arr[entry_idx], byte_idx)
                tampered = _replace(proof, **{field: tuple(tampered_list)})
                assert not core.verify_consistency(root_a, size_a, root_b, size_b, tampered)

    for i, w in enumerate(proof.witness):
        for j in range(len(w)):
            witness_list = [list(x) for x in proof.witness]
            witness_list[i][j] = _flip_hex_byte(w[j], 0)
            tampered = _replace(proof, witness=tuple(tuple(x) for x in witness_list))
            assert not core.verify_consistency(root_a, size_a, root_b, size_b, tampered)

    assert not core.verify_consistency(
        root_a, size_a, root_b, size_b, _replace(proof, witness=proof.witness[:-1])
    )
    assert not core.verify_consistency(
        root_a, size_a, root_b, size_b, _replace(proof, witness=proof.witness + ((),))
    )
    assert not core.verify_consistency(root_a, size_a + 1, root_b, size_b, proof)
    assert not core.verify_consistency(root_a, size_a, root_b, size_b + 1, proof)
    assert not core.verify_consistency(
        root_b, size_b, root_a, size_a, _replace(proof, size_a=size_b, size_b=size_a)
    )


def test_consistency_trivial_size_a_equals_size_b_empty_witnesses():
    store, digests = _build_mmr(23)
    size = core.node_count(23)
    root = _root_at(store, size)
    proof = core.consistency_proof(store, size, size)
    assert all(len(w) == 0 for w in proof.witness)
    assert core.verify_consistency(root, size, root, size, proof)


def test_consistency_empty_to_nonempty():
    store, digests = _build_mmr(10)
    size_b = core.node_count(10)
    root_a = core.root_from_peaks([])
    root_b = _root_at(store, size_b)
    proof = core.consistency_proof(store, 0, size_b)
    assert proof.old_peaks == ()
    assert core.verify_consistency(root_a, 0, root_b, size_b, proof)


# -- massifdb cross-check (internal only, NOT production) --------------------
#
# `_massifdb_interior_hash`/`_massifdb_root_from_peaks` reproduce this
# module's original massifdb-derived scheme and are kept solely as an
# internal cross-check against that original design source -- see the
# module docstring. These values were independently verified against a real
# massifdb TypeScript run; pin them here so any accidental change to the
# cross-check functions themselves is caught.


def test_massifdb_cross_check_matches_verified_typescript_output():
    aa = bytes([0xAA] * 32)
    bb = bytes([0xBB] * 32)
    cc = bytes([0xCC] * 32)

    l0 = core.leaf_hash(aa)
    l1 = core.leaf_hash(bb)
    l2 = core.leaf_hash(cc)
    assert l0.hex() == "e0bb82791bae3c50bd9c20fa4ccdcb8064a56e5c12bc69b07e6712ac9b4429e6"
    assert l1.hex() == "4f16119d36ccd0da91102f57692d73934fd0ad2494280df88449accedbbfb7ea"
    assert l2.hex() == "2e3aa189e1f666b2c3e864e21d978388020b89a6725e31ff2657bad5840a7f02"

    n2 = core._massifdb_interior_hash(l0, l1)  # noqa: SLF001 -- testing the internal cross-check directly
    assert n2.hex() == "03938e2c8f758e6cae443d499b41c899c373eb0c0198bae61796a069f2b05904"

    root = core._massifdb_root_from_peaks([n2, l2])  # noqa: SLF001
    assert root.hex() == "345abe89806802811606507081c9f710d0615012da316f5e3886afd7e701ec76"
