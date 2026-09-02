# SPDX-License-Identifier: Apache-2.0
"""Standalone reference verifier for vectors.json.

Deliberately independent of ``capsule_emit`` and of any CBOR library --
proof that the commitment-object encoding needs nothing but this file's
``commitment_object`` function (15 lines) to reproduce in any language.
Run: ``python3 reference_verifier.py``.
"""
from __future__ import annotations

import json
import pathlib
import sys


def _header(major_type: int, n: int) -> bytes:
    prefix = major_type << 5
    if n < 24:
        return bytes([prefix | n])
    if n < 2**8:
        return bytes([prefix | 24, n])
    if n < 2**16:
        return bytes([prefix | 25]) + n.to_bytes(2, "big")
    if n < 2**32:
        return bytes([prefix | 26]) + n.to_bytes(4, "big")
    return bytes([prefix | 27]) + n.to_bytes(8, "big")


def commitment_object(peak_hashes: list[bytes]) -> bytes:
    out = bytearray(_header(4, len(peak_hashes)))  # CBOR array header
    for p in peak_hashes:
        out += _header(2, len(p))  # CBOR byte-string header
        out += p
    return bytes(out)


def main() -> int:
    vectors = json.loads((pathlib.Path(__file__).parent / "vectors.json").read_text())
    failures = []
    for case in vectors["cases"]:
        peaks = [bytes.fromhex(h) for h in case["peak_hashes"]]
        computed = commitment_object(peaks).hex()
        claimed = case["commitment_hex"]
        if case["kind"] == "positive":
            if computed != claimed:
                failures.append(f"{case['name']}: expected match, got {computed} != {claimed}")
        elif case["kind"] == "must-fail":
            if computed == claimed:
                failures.append(f"{case['name']}: expected mismatch, but commitment matched")
        else:
            failures.append(f"{case['name']}: unknown kind {case['kind']!r}")

    if failures:
        print(f"FAIL ({len(failures)}/{len(vectors['cases'])} cases):")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(f"OK: all {len(vectors['cases'])} cases verified "
          f"({sum(1 for c in vectors['cases'] if c['kind'] == 'positive')} positive, "
          f"{sum(1 for c in vectors['cases'] if c['kind'] == 'must-fail')} must-fail)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
