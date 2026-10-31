# SPDX-License-Identifier: Apache-2.0
"""``checkpoint-conformance-vectors/receipt-vectors.json``, shared by every
implementation: the witness receipts agent-action-capsule's ``VerifyReceipts``
and scitt-cose's ``verify_receipt`` accept and refuse, through
``cll.ed25519.verify_receipt`` and the ``ReceiptVerifier`` that uses it.
"""
from __future__ import annotations

import base64
import dataclasses
import json
import pathlib

import pytest

from cll.checkpoint.witness import ReceiptVerifier, RejectedError, WitnessReceipt

VECTORS_DIR = pathlib.Path(__file__).resolve().parents[3] / "checkpoint-conformance-vectors"
VECTORS = json.loads((VECTORS_DIR / "receipt-vectors.json").read_text())
CHECKPOINT = base64.b64decode(VECTORS["checkpoint_cose_b64"])
VERIFIER = ReceiptVerifier(bytes.fromhex(VECTORS["authority_public_key_hex"]))
CASES = VECTORS["cases"]


def _receipt(case: dict) -> WitnessReceipt:
    return WitnessReceipt(
        base64.b64decode(case["receipt_b64"]),
        VECTORS["entry_hash_hex"],
        "legacy",
        case["leaf_index"],
        case["tree_size"],
    )


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_receipt_verifier_decides_every_case(case: dict) -> None:
    if case["accept"]:
        VERIFIER.verify(CHECKPOINT, _receipt(case))
    else:
        with pytest.raises(RejectedError):
            VERIFIER.verify(CHECKPOINT, _receipt(case))


@pytest.mark.parametrize("case", [c for c in CASES if c["accept"]], ids=[c["name"] for c in CASES if c["accept"]])
def test_receipt_verifier_refuses_another_stored_position(case: dict) -> None:
    receipt = dataclasses.replace(_receipt(case), tree_size=case["tree_size"] + 1)
    with pytest.raises(RejectedError, match="position mismatch"):
        VERIFIER.verify(CHECKPOINT, receipt)
