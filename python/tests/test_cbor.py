# SPDX-License-Identifier: Apache-2.0
"""``cll.cbor.loads``: maps whose keys collide as Python values are refused."""
from __future__ import annotations

import cbor2
import pytest

from cll.cbor import DuplicateMapKeyError, loads


@pytest.mark.parametrize(
    "hex_item",
    [
        "a2016161f56162",  # {1: "a", true: "b"}
        "a2006161f46162",  # {0: "a", false: "b"}
        "a2f56161016162",  # {true: "a", 1: "b"}
        "a2016161f93c006162",  # {1: "a", 1.0: "b"}
        "a2016161016162",  # {1: "a", 1: "b"}, a true duplicate
        "a201616118016162",  # {1: "a", 1 (non-minimal head): "b"}
        "a2c2490100000000000000006161c24901000000000000000061626162",  # one bignum twice
        "bf016161f56162ff",  # indefinite-length map
        "82a10102a2f501f501",  # [{1: 2}, {true: 1, true: 1}]: a map inside an array
        "a1a2016161f5616201",  # {{1: "a", true: "b"}: 1}: a map used as a key
        "a28101616181f56162",  # {[1]: "a", [true]: "b"}: keys collide element-wise
        "d9d9f7a2016161f56162",  # a map inside a tag
        "a1617882a0a2006161f46162",  # {"x": [{}, {0: "a", false: "b"}]}
        "a2f97e006161fb7ff80000000000006162",  # {NaN: "a", NaN (double): "b"}
    ],
)
def test_refuses_keys_equal_as_python_values(hex_item: str) -> None:
    data = bytes.fromhex(hex_item)
    with pytest.raises(DuplicateMapKeyError):
        loads(data)


@pytest.mark.parametrize(
    "hex_item",
    [
        "a3016161026162036163",  # {1: "a", 2: "b", 3: "c"}
        "a2016161616b6162",  # {1: "a", "k": "b"}: int and text keys never collide
        "a2f56161f46162",  # {true: "a", false: "b"}
        "a2c249010000000000000000616118ff6162",  # {2**64: "a", 255: "b"}
        "a28101616181026162",  # {[1]: "a", [2]: "b"}
        "bf6161a1016178ff",  # indefinite {"a": {1: "x"}}
        "5f4161ff",  # indefinite byte string
        "7f6161ff",  # indefinite text string
    ],
)
def test_accepts_distinct_keys_and_matches_cbor2(hex_item: str) -> None:
    data = bytes.fromhex(hex_item)
    assert loads(data) == cbor2.loads(data)


def test_error_is_a_value_error() -> None:
    # Existing callers catch ValueError (or Exception) around decoding.
    assert issubclass(DuplicateMapKeyError, ValueError)


def test_malformed_cbor_raises_as_cbor2_does() -> None:
    with pytest.raises(cbor2.CBORDecodeError):
        loads(b"\xa1\x01")  # a map missing its value


def test_key_that_cannot_be_decoded_alone_is_refused() -> None:
    # {"a": 28("x"), 29(0): 1}: the second key refers to a value shared
    # earlier in the item, so on its own it cannot be checked.
    data = bytes.fromhex("a26161d81c6178d81d0001")
    try:
        cbor2.loads(data)
    except Exception:  # noqa: BLE001 -- this cbor2 refuses the item itself
        pytest.skip("installed cbor2 does not decode value-sharing tags as map keys")
    with pytest.raises(DuplicateMapKeyError, match="cannot be decoded on its own"):
        loads(data)


def test_deep_nesting_is_refused_not_crashed(monkeypatch: pytest.MonkeyPatch) -> None:
    # cbor2 refuses this depth itself, so stand in for it to reach the walk.
    monkeypatch.setattr(cbor2, "loads", lambda data: None)
    with pytest.raises(DuplicateMapKeyError, match="nested too deeply"):
        loads(b"\x81" * 100_000 + b"\x00")
