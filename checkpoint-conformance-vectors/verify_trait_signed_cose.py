# SPDX-License-Identifier: Apache-2.0
"""Cross-language check for `rust/cll`'s `checkpoint::CheckpointSigner` SPI
(2026-09-22): verifies a checkpoint COSE_Sign1 statement that
`rust/cll/examples/trait_signed_checkpoint.rs` produced through the new
signer trait (a `&dyn CheckpointSigner` call site, not a direct
`ed25519_dalek::SigningKey` one) -- proving the trait indirection changed
nothing about the wire bytes a stranger verifies. Uses the same
`verify_checkpoint_cose_offline` this repo's Rust->Python conformance
checks already rely on.

Run: ``cargo run --quiet --example trait_signed_checkpoint | python3
checkpoint-conformance-vectors/verify_trait_signed_cose.py``.
"""
from __future__ import annotations

import sys

from cll.checkpoint.cose_wire import verify_checkpoint_cose_offline

EXPECTED_LOG_ID = "trait-signed-cross-language-check"


def main() -> int:
    hex_bytes = sys.stdin.read().strip()
    if not hex_bytes:
        print("no COSE hex on stdin", file=sys.stderr)
        return 1
    cose_bytes = bytes.fromhex(hex_bytes)

    result = verify_checkpoint_cose_offline(cose_bytes)
    if not result.ok or result.decoded is None:
        print(f"FAIL: {result.errors}", file=sys.stderr)
        return 1
    if result.decoded.log_id != EXPECTED_LOG_ID:
        print(
            f"FAIL: unexpected log_id {result.decoded.log_id!r} "
            f"(expected {EXPECTED_LOG_ID!r})",
            file=sys.stderr,
        )
        return 1

    print(
        "OK: trait-signed checkpoint verifies under the Python reference "
        f"(log_id={result.decoded.log_id}, mmr_size={result.decoded.mmr_size}, "
        f"key_id={result.decoded.key_id})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
