# SPDX-License-Identifier: Apache-2.0
"""Generate ``ed25519-vectors.json``: Ed25519 inputs a checkpoint verifier must
decide one way, including the ones platform Ed25519 libraries disagree on.

The curve arithmetic is plain RFC 8032 Python, so the file depends on none of
the verifiers it tests. Every case is deterministic.

Run: ``python3 generate_ed25519.py`` (needs ``cbor2``) to rewrite the file, or
``python3 generate_ed25519.py --check`` to fail if it is out of date.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import cbor2

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple  # extended coordinates (X, Y, Z, T)


def _add(a: Point, b: Point) -> Point:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % P
    bb = (y1 + x1) * (y2 + x2) % P
    cc = 2 * t1 * t2 * D % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s: int, point: Point) -> Point:
    result: Point = (0, 1, 1, 0)
    while s:
        if s & 1:
            result = _add(result, point)
        point = _add(point, point)
        s >>= 1
    return result


def _encode(point: Point) -> bytes:
    x, y, z, _ = point
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(encoded: bytes) -> Point:
    """RFC 8032 section 5.1.3, canonical encodings only."""
    value = int.from_bytes(encoded, "little")
    y, sign = value & ((1 << 255) - 1), value >> 255
    if y >= P:
        raise ValueError("non-canonical y")
    u, v = (y * y - 1) % P, (D * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    if v * x * x % P == P - u % P and u:
        x = x * SQRT_M1 % P
    if v * x * x % P != u % P:
        raise ValueError("not on the curve")
    if x == 0 and sign:
        raise ValueError("x = 0 with the sign bit set")
    if x & 1 != sign:
        x = P - x
    return (x, y, 1, x * y % P)


B = _decode((4 * pow(5, P - 2, P) % P).to_bytes(32, "little"))


def _scalar(value: int) -> bytes:
    return value.to_bytes(32, "little")


def _challenge(r: bytes, a: bytes, message: bytes) -> int:
    return int.from_bytes(hashlib.sha512(r + a + message).digest(), "little") % L


def _keypair(seed: bytes) -> tuple[int, bytes, bytes]:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, _encode(_mul(a, B)), h[32:]


def _sign(seed: bytes, message: bytes) -> bytes:
    a, public, prefix = _keypair(seed)
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    big_r = _encode(_mul(r, B))
    return big_r + _scalar((r + _challenge(big_r, public, message) * a) % L)


def _y(value: int, sign: int = 0) -> bytes:
    return (value | (sign << 255)).to_bytes(32, "little")


# The eight canonical encodings of the small-order points, then four
# non-canonical encodings of small-order points that lenient decoders accept:
# y = p (y = 0), y = p + 1 (the identity), and x = 0 with the sign bit set.
ORDER_8_Y = 0x05FC536D880238B13933C6D305ACDFD5F098EFF289F4C345B027B2C28F95E826
SMALL_ORDER = [
    ("identity", _y(1), True),
    ("y=-1 (order 2)", _y(P - 1), True),
    ("y=0 x even (order 4)", _y(0), True),
    ("y=0 x odd (order 4)", _y(0, 1), True),
    ("order 8 y=c x even", _y(ORDER_8_Y), True),
    ("order 8 y=c x odd", _y(ORDER_8_Y, 1), True),
    ("order 8 y=-c x even", _y(P - ORDER_8_Y), True),
    ("order 8 y=-c x odd", _y(P - ORDER_8_Y, 1), True),
    ("y=p, non-canonical y=0", _y(P), False),
    ("y=p+1, non-canonical identity", _y(P + 1), False),
    ("identity with sign bit", _y(1, 1), False),
    ("y=-1 with sign bit", _y(P - 1, 1), False),
]
for _name, _encoding, _canonical in SMALL_ORDER:
    if _canonical:
        assert _encode(_mul(8, _decode(_encoding))) == _y(1), _name

SEED = bytes(range(1, 33))
NONCE = 0x1234567
TORSION = _decode(SMALL_ORDER[4][1])


def _case(name: str, public: bytes, message: bytes, signature: bytes, valid: bool, why: str) -> dict:
    return {
        "name": name,
        "public_key_hex": public.hex(),
        "message_hex": message.hex(),
        "signature_hex": signature.hex(),
        "valid": valid,
        "why": why,
    }


def _message_with_challenge(prefix: str, r: bytes, a: bytes) -> bytes:
    """The first ``prefix N`` message whose challenge is a multiple of 8."""
    counter = 0
    while True:
        message = f"{prefix} {counter}".encode()
        if _challenge(r, a, message) % 8 == 0:
            return message
        counter += 1


def ed25519_cases() -> list[dict]:
    scalar, public, _ = _keypair(SEED)
    message = b"cll ed25519 edge cases"
    signature = _sign(SEED, message)
    s = int.from_bytes(signature[32:], "little")
    cases = [
        _case("honest", public, message, signature, True, "an honest RFC 8032 signature"),
        _case(
            "S + L", public, message, signature[:32] + _scalar(s + L), False,
            "S is not reduced below L (RFC 8032 section 5.1.7 step 1)",
        ),
    ]

    mixed_r = _encode(_add(_mul(NONCE, B), TORSION))
    mixed_s = (NONCE + _challenge(mixed_r, public, message) * scalar) % L
    cases.append(_case(
        "mixed-order R", public, message, mixed_r + _scalar(mixed_s), False,
        "R = rB + T for an order-8 T: the cofactored equation holds, the cofactorless one does not",
    ))

    for label, identity in (("identity R", _y(1)), ("non-canonical identity R y=p+1", _y(P + 1))):
        cases.append(_case(
            label, public, message,
            identity + _scalar(_challenge(identity, public, message) * scalar % L), False,
            "R is the identity and S = k*a, so [S]B = R + [k]A holds; R is of small order",
        ))

    mixed_a = _encode(_add(_mul(scalar, B), TORSION))
    big_r = _encode(_mul(NONCE, B))
    mixed_a_message = _message_with_challenge("mixed order", big_r, mixed_a)
    cases.append(_case(
        "mixed-order A", mixed_a, mixed_a_message,
        big_r + _scalar((NONCE + _challenge(big_r, mixed_a, mixed_a_message) * scalar) % L), True,
        "A = aB + T with k a multiple of 8, signed by the holder of a: the cofactorless equation "
        "holds and A is not of small order, so every verifier accepts it",
    ))

    for label, encoding, canonical in SMALL_ORDER:
        small_message = _message_with_challenge("small order", big_r, encoding)
        cases.append(_case(
            f"small-order A {label}", encoding, small_message, big_r + _scalar(NONCE), False,
            "A is of small order and k a multiple of 8, so [k]A is the identity and R = rB, S = r "
            "satisfies the equation with no private key"
            + ("" if canonical else "; A's encoding is also not canonical"),
        ))

    # y = 2 is below p but on no point of the curve.
    off_curve = _y(2)
    cases.append(_case("off-curve A y=2", off_curve, message, signature, False, "A is not a point on the curve"))
    cases.append(_case(
        "off-curve R y=2", public, message, off_curve + signature[32:], False, "R is not a point on the curve",
    ))

    for i in range(2, 19):
        encoding = _y(P + i)
        cases.append(_case(
            f"non-canonical A y=p+{i}", encoding, message, signature, False,
            "A's y is not below p",
        ))
        cases.append(_case(
            f"non-canonical R y=p+{i}", public, message, encoding + signature[32:], False,
            "R's y is not below p",
        ))
    return cases


def _cbor(value) -> bytes:
    return cbor2.dumps(value, canonical=True)


def _statement(kid: bytes, sign) -> bytes:
    """A well-formed one-leaf checkpoint statement for ``kid``, signed by
    ``sign(message)``, which returns None to ask for the next timestamp."""
    log_id = "forged-log"
    protected = _cbor({1: -8, 3: "application/cll-checkpoint+cbor", 4: kid, 15: {1: log_id, 2: f"{log_id}#1"}})
    for second in range(3600):
        payload = _cbor({
            "kind": "cll-checkpoint",
            "log_size": 1,
            "commitment": _cbor([bytes([0x42]) * 32]),
            "prev_size": 0,
            "prev_commitment": b"",
            "issued_at": f"2026-10-27T00:{second // 60:02d}:{second % 60:02d}Z",
        })
        signature = sign(_cbor(["Signature1", protected, b"", payload]))
        if signature is not None:
            return b"\xd2" + _cbor([protected, {}, payload, signature])
    raise AssertionError("no timestamp found")


def cose_cases() -> list[dict]:
    scalar, public, _ = _keypair(SEED)
    big_r = _encode(_mul(NONCE, B))
    cases = [{
        "name": "honest",
        "cose_hex": _statement(public, lambda m: _sign(SEED, m)).hex(),
        "valid": True,
    }]
    mixed_a = _encode(_add(_mul(scalar, B), TORSION))
    cases.append({
        "name": "mixed-order kid",
        "cose_hex": _statement(
            mixed_a,
            lambda m: big_r + _scalar((NONCE + _challenge(big_r, mixed_a, m) * scalar) % L)
            if _challenge(big_r, mixed_a, m) % 8 == 0 else None,
        ).hex(),
        "valid": True,
    })
    for label, encoding, _ in SMALL_ORDER:
        cases.append({
            "name": f"small-order kid {label}",
            "cose_hex": _statement(
                encoding,
                lambda m, a=encoding: big_r + _scalar(NONCE) if _challenge(big_r, a, m) % 8 == 0 else None,
            ).hex(),
            "valid": False,
        })
    return cases


def vectors() -> dict:
    ed = ed25519_cases()
    cose = cose_cases()
    return {
        "format_version": "1",
        "spec": "Ed25519 verification for CLL checkpoints and receipts (RFC 8032 section 5.1.7, strict)",
        "note": (
            "A verifier MUST accept a case whose valid is true and MUST refuse one whose valid is false. "
            "It refuses A or R that is not a canonical encoding (y >= p, or x = 0 with the sign bit set) "
            "or is of small order, and S >= L, and checks the cofactorless equation [S]B = R + [k]A. "
            "ed25519_cases are raw (public key, message, signature) triples; cose_cases are whole "
            "COSE_Sign1 checkpoint statements whose kid is the public key and whose only defect, if "
            "any, is the signing key. Generated by generate_ed25519.py."
        ),
        "signing_key_seed_hex": SEED.hex(),
        "ed25519_count": len(ed),
        "ed25519_cases": ed,
        "cose_count": len(cose),
        "cose_cases": cose,
    }


def main() -> int:
    path = pathlib.Path(__file__).with_name("ed25519-vectors.json")
    text = json.dumps(vectors(), indent=2) + "\n"
    if "--check" in sys.argv[1:]:
        if path.read_text() != text:
            print(f"{path.name} is out of date; run generate_ed25519.py", file=sys.stderr)
            return 1
        print(f"{path.name} is up to date")
        return 0
    path.write_text(text)
    print(f"wrote {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
