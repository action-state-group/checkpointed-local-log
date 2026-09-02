# SPDX-License-Identifier: Apache-2.0
"""[cll-commitment-interop]: the conformant commitment object.

``core.commitment_object`` -- NOT ``root_from_peaks`` -- is the value an
independent draft-bryce-cose-receipts-mmr-profile/MMRIVER-conformant tool
needs to re-derive inclusion + consistency from a checkpoint's committed
state alone: canonical-CBOR ``[ *bstr ]`` over the accumulator's peak
hashes, tallest-to-smallest. See ``commitment-conformance-vectors/README.md``
for the full rationale and ``vectors.json`` for the pinned cross-language
vectors this file replays against the real implementation.
"""
from __future__ import annotations

import json
import pathlib

import pytest
from tests.checkpoint.conftest import FakeLogSource, synthetic_capsule

from cll.checkpoint import MmrLedger, core

VECTORS_PATH = (
    pathlib.Path(__file__).resolve().parents[2] / "commitment-conformance-vectors" / "vectors.json"
)


def _load_vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text())


# -- shape ---------------------------------------------------------------


def test_empty_accumulator_is_the_empty_cbor_array():
    assert core.commitment_object([]) == bytes([0x80])


def test_single_peak_is_a_one_element_cbor_array_of_bstr():
    peak = bytes(range(32))
    # 0x81 = array(1); 0x58 0x20 = bstr header for a 32-byte string.
    assert core.commitment_object([peak]) == bytes([0x81, 0x58, 0x20]) + peak


def test_peak_order_is_preserved_not_resorted():
    a, b = bytes([1]) * 32, bytes([2]) * 32
    assert core.commitment_object([a, b]) != core.commitment_object([b, a])


def test_rejects_wrong_length_peak():
    with pytest.raises(core.InvalidArgumentError):
        core.commitment_object([b"too-short"])


def test_up_to_24_peaks_switches_cbor_array_length_form():
    # n=23 uses the 1-byte immediate array header (0x80|23); n=24 needs the
    # 1-byte-length-follows form (0x98, 24) -- exercise the boundary.
    peaks_23 = [bytes([i]) * 32 for i in range(23)]
    peaks_24 = [bytes([i]) * 32 for i in range(24)]
    assert core.commitment_object(peaks_23)[:1] == bytes([0x80 | 23])
    assert core.commitment_object(peaks_24)[:2] == bytes([0x98, 24])


# -- cross-check against a real CBOR library ------------------------------


def test_matches_cbor2_canonical_encoding():
    cbor2 = pytest.importorskip("cbor2")
    peaks = [bytes([i]) * 32 for i in range(5)]
    assert core.commitment_object(peaks) == cbor2.dumps(peaks, canonical=True)
    assert core.commitment_object([]) == cbor2.dumps([], canonical=True)


def test_matches_cbor2_decoding_round_trip():
    cbor2 = pytest.importorskip("cbor2")
    peaks = [bytes([i, i + 1]) * 16 for i in range(7)]
    encoded = core.commitment_object(peaks)
    assert cbor2.loads(encoded) == peaks


# -- pinned conformance vectors --------------------------------------------


def _vector_cases():
    return _load_vectors()["cases"]


@pytest.mark.parametrize("case", [c for c in _vector_cases() if c["kind"] == "positive"], ids=lambda c: c["name"])
def test_positive_vector_matches(case):
    peaks = [bytes.fromhex(h) for h in case["peak_hashes"]]
    assert core.commitment_object(peaks).hex() == case["commitment_hex"]


@pytest.mark.parametrize("case", [c for c in _vector_cases() if c["kind"] == "must-fail"], ids=lambda c: c["name"])
def test_must_fail_vector_does_not_match(case):
    peaks = [bytes.fromhex(h) for h in case["peak_hashes"]]
    assert core.commitment_object(peaks).hex() != case["commitment_hex"]


def test_vectors_file_has_both_kinds_represented():
    kinds = {c["kind"] for c in _vector_cases()}
    assert kinds == {"positive", "must-fail"}


# -- MmrLedger wiring -------------------------------------------------------


def test_mmr_ledger_commitment_at_matches_core_over_peak_hashes_at():
    mmr = MmrLedger(FakeLogSource())
    for i in range(10):
        mmr.append(synthetic_capsule(i), consequential=False)

    # Only node_count(k) for some leaf count k is a valid ("complete") MMR
    # size -- not every intermediate node count decomposes into peaks.
    for size in (0, core.node_count(5), mmr.size()):
        expected = core.commitment_object(mmr.peak_hashes_at(size))
        assert mmr.commitment_at(size) == expected


def test_mmr_ledger_commitment_at_differs_from_root_at():
    # Confirms this is genuinely a different value, not root_from_peaks by
    # another name -- a caller who mixes them up must see them diverge.
    mmr = MmrLedger(FakeLogSource())
    for i in range(5):
        mmr.append(synthetic_capsule(i), consequential=False)

    assert mmr.commitment_at(mmr.size()) != mmr.root_at(mmr.size())


def test_mmr_ledger_commitment_at_reproduces_root_from_peaks_via_decode():
    """Ties the two representations of the same accumulator together: the
    commitment object, decoded back into its peak list, must fold (via
    root_from_peaks) to exactly the same root the internal path computes --
    same underlying peaks, two different encodings of them."""
    cbor2 = pytest.importorskip("cbor2")
    mmr = MmrLedger(FakeLogSource())
    for i in range(9):
        mmr.append(synthetic_capsule(i), consequential=False)

    size = mmr.size()
    decoded_peaks = cbor2.loads(mmr.commitment_at(size))
    assert core.root_from_peaks(decoded_peaks) == mmr.root_at(size)
