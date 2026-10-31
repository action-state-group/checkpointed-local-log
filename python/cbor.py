# SPDX-License-Identifier: Apache-2.0
"""CBOR decoding for untrusted bytes whose maps must not lose keys.

In CBOR (RFC 8949) the integer ``1`` and ``true`` are distinct data items, so
a map may hold both as keys, and likewise ``0`` and ``false``, ``1`` and
``1.0``, or an integer and an equal bignum. In Python those values are equal
and hash alike, so ``cbor2.loads`` builds a dict in which the later entry
silently overwrites the earlier one (``{1: "a", true: "b"}`` decodes to
``{1: "b"}``). A verifier must not rewrite what it was handed, so
:func:`loads` refuses any map, at any depth, whose keys collide under Python
equality, true duplicates (two NaNs among them) included. RFC 8949 §5.6
names this approach: a decoder that does not accept maps with duplicate keys,
where the application "equates integers and floating-point values in map key
positions".

cbor2 6.1 can refuse such maps itself (``allow_duplicate_keys=False``), but
it needs Python 3.10, and this package supports 3.9 (cbor2 5.x). So the
check walks the encoded item and decodes each map key on its own.
"""
from __future__ import annotations

import cbor2

__all__ = ["DuplicateMapKeyError", "ReceiptEncodingError", "loads", "receipt_item"]


class DuplicateMapKeyError(ValueError):
    """A CBOR map holds two keys that are equal as Python values."""


def loads(data: bytes) -> object:
    """Decode one CBOR data item, as ``cbor2.loads`` does, but raise
    :class:`DuplicateMapKeyError` if any map in it, at any depth (keys and
    tag contents included), has two keys that decode to equal Python values.
    A key holding a tag whose value depends on the rest of the item (string
    references, tags 25 and 256; value sharing, tags 28 and 29) is refused
    the same way: decoded on its own it can resolve to a different value
    than in the whole item, so its collisions cannot be checked. Malformed
    CBOR raises whatever ``cbor2.loads`` raises.
    """
    data = bytes(data)
    value = cbor2.loads(data)
    try:
        _walk(data, 0)
    except RecursionError:
        raise DuplicateMapKeyError("CBOR item is nested too deeply to check its map keys") from None
    return value


def _head(data: bytes, i: int) -> tuple[int, int | None, int]:
    """The major type, argument (``None`` for indefinite length) and the
    offset after the head of the item at ``i``. Simple values and floats
    (major type 7) return their raw argument, which callers skip over."""
    initial = data[i]
    major, info = initial >> 5, initial & 0x1F
    if info < 24:
        return major, info, i + 1
    if info == 31:
        return major, None, i + 1
    if info > 27:
        raise ValueError(f"reserved additional information {info} at offset {i}")
    width = 1 << (info - 24)
    end = i + 1 + width
    if end > len(data):
        raise ValueError("CBOR item is truncated")
    return major, int.from_bytes(data[i + 1:end], "big"), end


#: Tags whose decoded value depends on other parts of the item: stringref
#: (25, 256) and value sharing (28, 29).
_CONTEXT_TAGS = frozenset({25, 28, 29, 256})


def _walk(data: bytes, i: int, in_key: bool = False) -> int:
    """Check every map in the item at ``i``; return the offset after it.
    ``in_key`` is true inside a map key, where context tags are refused.
    ``cbor2.loads`` has already accepted ``data``, so it is well formed."""
    major, arg, i = _head(data, i)
    if major in (0, 1, 7):
        return i
    if major in (2, 3):
        if arg is not None:
            return i + arg
        while data[i] != 0xFF:
            _, n, i = _head(data, i)
            i += n
        return i + 1
    if major == 6:
        if in_key and arg in _CONTEXT_TAGS:
            raise DuplicateMapKeyError(
                f"CBOR map key holds tag {arg}, whose value depends on the rest of the item, "
                "so its key cannot be checked on its own"
            )
        return _walk(data, i, in_key)
    if major == 4:
        count = 0
        while (arg is None and data[i] != 0xFF) or (arg is not None and count < arg):
            i = _walk(data, i, in_key)
            count += 1
        return i + 1 if arg is None else i
    # major == 5: a map
    keys, count = set(), 0
    while (arg is None and data[i] != 0xFF) or (arg is not None and count < arg):
        start = i
        i = _walk(data, i, True)
        raw = data[start:i]
        keys.add(_key(raw))
        count += 1
        if len(keys) < count:
            raise DuplicateMapKeyError(
                f"CBOR map key {raw[:16].hex()} is equal as a Python value to an earlier key in the "
                "same map (e.g. 1 and true, or a repeated key) -- refused rather than letting one "
                "entry replace the other"
            )
        i = _walk(data, i, in_key)
    return i + 1 if arg is None else i


#: Markers that keep a frozen map or tag apart from any decoded tuple, and
#: one NaN, so that two NaN keys (equal in CBOR, unequal in Python) collide.
_MAP, _TAG, _NAN = object(), object(), object()


def _key(raw: bytes) -> object:
    """A map key as the hashable value cbor2 compares it by."""
    try:
        return _frozen(cbor2.loads(raw))
    except Exception as exc:  # noqa: BLE001 -- any failure means the key can't be checked
        raise DuplicateMapKeyError(f"CBOR map key {raw[:16].hex()} cannot be decoded on its own: {exc}") from exc


def _frozen(value: object) -> object:
    # cbor2 decodes a key that is an array, map or set into a tuple, frozen
    # map or frozenset; standalone decoding may give the mutable forms, so
    # freeze them the same way. Equality is kept: [1] and [true] collide.
    if isinstance(value, (list, tuple)):
        return tuple(_frozen(v) for v in value)
    if hasattr(value, "items"):  # dict, or cbor2 6's frozendict
        return (_MAP, frozenset((_frozen(k), _frozen(v)) for k, v in value.items()))
    if isinstance(value, (set, frozenset)):
        return frozenset(_frozen(v) for v in value)
    if isinstance(value, cbor2.CBORTag):
        return (_TAG, value.tag, _frozen(value.value))
    if isinstance(value, float) and value != value:
        return _NAN
    return value


class ReceiptEncodingError(ValueError):
    """A CBOR item breaks the receipt encoding rule (:func:`receipt_item`)."""


#: The deepest nesting the receipt encoding rule allows.
_MAX_RECEIPT_DEPTH = 16


def receipt_item(data: bytes, top_tag: bool = False) -> object:
    """Decode one CBOR item under the receipt encoding rule of
    agent-action-capsule's interop profile v1 section 6.2.2, as its
    ``strictReceiptItem`` (agent-action-capsule#523) applies it to every COSE
    Receipt: no trailing bytes, definite lengths, the shortest form of every
    argument, no repeated map key, integers from -2^63, integer or text map
    keys, valid UTF-8, no float, no simple value but false, true and null, no
    tag but an outer 18 when ``top_tag``, and at most 16 levels. Map order is
    not checked. Raise :class:`ReceiptEncodingError` otherwise.

    The rule is checked on the encoded bytes, so an item that meets it means
    one thing to every decoder, and ``cbor2.loads`` then decodes it."""
    data = bytes(data)
    try:
        end = _receipt_walk(data, 0, 0, top_tag)
    except IndexError:
        raise ReceiptEncodingError("CBOR item is truncated") from None
    if end != len(data):
        raise ReceiptEncodingError("trailing bytes after the CBOR item")
    return cbor2.loads(data)


def _receipt_walk(data: bytes, i: int, depth: int, top_tag: bool) -> int:
    if depth > _MAX_RECEIPT_DEPTH:
        raise ReceiptEncodingError(f"CBOR nested more than {_MAX_RECEIPT_DEPTH} levels deep")
    initial = data[i]
    major, info = initial >> 5, initial & 0x1F
    if major == 7:
        if info in (20, 21, 22):  # false, true, null
            return i + 1
        raise ReceiptEncodingError("a float or a simple value other than false, true and null")
    if info > 27:
        raise ReceiptEncodingError("an indefinite or reserved CBOR length")
    if info < 24:
        arg, i = info, i + 1
    else:
        width = 1 << (info - 24)
        if i + 1 + width > len(data):
            raise ReceiptEncodingError("CBOR item is truncated")
        arg = int.from_bytes(data[i + 1:i + 1 + width], "big")
        if arg < (24, 1 << 8, 1 << 16, 1 << 32)[info - 24]:
            raise ReceiptEncodingError("a CBOR argument not in its shortest form")
        i += 1 + width
    if major == 0:
        return i
    if major == 1:
        if arg >= 1 << 63:
            raise ReceiptEncodingError("an integer below -2^63")
        return i
    if major in (2, 3):
        if i + arg > len(data):
            raise ReceiptEncodingError("CBOR item is truncated")
        if major == 3:
            try:
                data[i:i + arg].decode("utf-8")
            except UnicodeDecodeError:
                raise ReceiptEncodingError("a text string that is not valid UTF-8") from None
        return i + arg
    if major == 6:
        if not (depth == 0 and top_tag and arg == 18):
            raise ReceiptEncodingError(f"CBOR tag {arg} is not the outer tag 18")
        return _receipt_walk(data, i, depth + 1, False)
    # Every element takes at least one byte.
    if arg > len(data) - i:
        raise ReceiptEncodingError("CBOR item is truncated")
    if major == 4:
        for _ in range(arg):
            i = _receipt_walk(data, i, depth + 1, False)
        return i
    keys = set()
    for _ in range(arg):
        start = i
        if data[i] >> 5 not in (0, 1, 3):
            raise ReceiptEncodingError("a map key that is not an integer or text")
        i = _receipt_walk(data, i, depth + 1, False)
        # Keys are shortest-form integers or text, so equal keys have equal bytes.
        if data[start:i] in keys:
            raise ReceiptEncodingError("a repeated CBOR map key")
        keys.add(data[start:i])
        i = _receipt_walk(data, i, depth + 1, False)
    return i
