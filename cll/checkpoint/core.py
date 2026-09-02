# SPDX-License-Identifier: Apache-2.0
"""Merkle Mountain Range (MMR) core algorithm.

Classic flat-array MMR: 0-indexed node positions, grown strictly left to
right, interior nodes appear immediately after both of their children. This
is a published, implementation-independent accumulator design (originally
described by Peter Todd) that long predates and is independent of any single
implementation.

Production hashing scheme -- MMRIVER-draft-compatible, position-committed:
    leaf_hash     = sha256(0x00 || body_digest)
    interior_hash = sha256(be64(position + 1) || left || right)
                    where `position` is the 0-based flat-array index the new
                    interior node occupies
    root          = bagged peaks, right-to-left, NO domain-separator byte:
                    pop the two rightmost peak hashes, combine as
                    sha256(right || left), push the result back, repeat
                    until one hash remains
    root of an empty MMR = 32 zero bytes

The interior-hash construction matches the MMRIVER IETF draft as implemented
by datatrails/go-datatrails-merklelog (`mmr/add.go`, `mmr/hashwritevalue.go`
-- MIT licensed), verified against that repo's hardcoded 39-node KAT
(`mmr/draft_kat39_test.go`; see `tests/checkpoint/test_mmr_kat39.py`).
`leaf_hash` is unchanged from the original scheme this module was ported
from -- the reference's own
`AddHashedLeaf` takes an already-hashed leaf as an opaque input and applies
no transformation to it, so leaf-hash derivation from raw content is
caller-defined in this ecosystem, not prescribed by the draft. The root
peak-bagging formula is reference-source-verified (read directly from
`mmr/proofbagged.go`'s `hashPeaksRHS`) but, unlike the interior/leaf hashes,
has no literal hardcoded-root KAT to pin against upstream -- treat its
provenance accordingly (property/self-consistency tests, not a pinned root
value).

Position commitment is chosen deliberately over this module's original
massifdb-derived scheme (fixed 0x01/0x02 prefix bytes, no position) for three
reasons: (1) anti-equivocation -- a position-committed interior hash can only
ever be valid at the one array position it was computed for, so a party
holding a node hash cannot present it as valid evidence at a different
position or tree height, closing a residual equivocation attack the fixed-
prefix scheme does not; (2) it keeps this module aligned with the IETF MMRIVER
draft, in case that alignment matters for future tooling; (3) it keeps a path
open for completeness certificates produced here to be checkable by
independent MMRIVER-conformant tooling, without committing to that as a
current guarantee.

This remains implementational, never a normative or wire-interop claim. The
ecosystem's standards-interop surface is scitt-cose's RFC9162_SHA256 receipts
(a wholly different tree construction, byte-for-byte prescribed by RFC 9162);
this MMR exists solely to give a locally-appended log fast inclusion/
consistency proofs and is not claimed to interoperate with any external MMR
implementation on the wire.

The original massifdb-derived scheme (0x00/0x01/0x02 fixed-prefix, no
position commitment) that this module originally shipped with is kept as
`_massifdb_interior_hash`/`_massifdb_root_from_peaks` below, purely as an
internal cross-check against that original design source -- it is NOT used
by `add_leaf`, `inclusion_proof`, `consistency_proof`, or either verifier, and
must never be reintroduced onto the production path.

Verification functions (`verify_inclusion`/`verify_consistency`) are pure,
take no reader, and never raise -- any malformed input (wrong lengths, bad
hex, wrong type) is a verification *failure* (return False), not an
exception. That is deliberate: a verifier is a total function from (possibly
adversarial) bytes to a boolean, never a partial one.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

DIGEST_LEN = 32
MAX_MMR_SIZE = 2**50

__all__ = [
    "DIGEST_LEN",
    "MAX_MMR_SIZE",
    "InvalidArgumentError",
    "IntegrityError",
    "NodeReader",
    "NodeAppender",
    "InclusionProof",
    "ConsistencyProof",
    "leaf_hash",
    "interior_hash",
    "root_from_peaks",
    "commitment_object",
    "height_at",
    "node_count",
    "leaf_count",
    "leaf_index_to_pos",
    "pos_to_leaf_index",
    "peaks",
    "add_leaf",
    "inclusion_proof",
    "verify_inclusion",
    "consistency_proof",
    "verify_consistency",
]


class InvalidArgumentError(ValueError):
    """A caller-supplied argument (size, leaf_index, digest shape) is invalid."""


class IntegrityError(RuntimeError):
    """The node store cannot answer a request that should be structurally satisfiable."""


def _assert_digest(d: bytes, what: str = "digest") -> None:
    if not isinstance(d, (bytes, bytearray)) or len(d) != DIGEST_LEN:
        raise InvalidArgumentError(f"{what} must be {DIGEST_LEN} bytes")


def _require_nonneg_int(n: int, what: str) -> None:
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise InvalidArgumentError(f"{what} must be a non-negative integer: {n}")


# -- hashing -----------------------------------------------------------------


def leaf_hash(body_digest: bytes) -> bytes:
    """leaf_hash = sha256(0x00 || body_digest)."""
    _assert_digest(body_digest, "body_digest")
    return hashlib.sha256(b"\x00" + body_digest).digest()


def interior_hash(left: bytes, right: bytes, position: int) -> bytes:
    """interior_hash = sha256(be64(position+1) || left || right), per the
    MMRIVER draft (datatrails/go-datatrails-merklelog mmr/add.go,
    mmr/hashwritevalue.go -- MIT licensed). `position` is the 0-based
    array index this interior node occupies."""
    _assert_digest(left, "left")
    _assert_digest(right, "right")
    _require_nonneg_int(position, "position")
    pos_bytes = (position + 1).to_bytes(8, "big")
    return hashlib.sha256(pos_bytes + left + right).digest()


def root_from_peaks(peak_hashes: list[bytes]) -> bytes:
    """Root = binary-tree bagging of the peaks, right-to-left pairwise
    folding with NO domain-separator byte: pop the two rightmost hashes,
    combine as sha256(right || left), push the result back, repeat until
    one hash remains. Matches datatrails/go-datatrails-merklelog
    mmr/proofbagged.go's hashPeaksRHS (MIT licensed) -- reference-source-
    verified (the Go source was read directly, both for the fold order and
    for its own "hashes are highest to lowest" ordering comment, matching
    this module's peaks() left=tallest-to-right=smallest convention), but
    NOT independently KAT-pinned by a literal published root value the way
    interior/leaf hashes are (searched, found none -- the upstream repo's
    own root tests are self-consistency tests, not pinned-value tests).
    Treat this formula's provenance accordingly in downstream verification
    (property/self-consistency tests, not a hardcoded-root KAT).

    Root of an empty MMR is still 32 zero bytes (unchanged convention, not
    contradicted by anything in the reference).
    """
    if not peak_hashes:
        return bytes(DIGEST_LEN)
    for p in peak_hashes:
        _assert_digest(p, "peak")
    hashes = list(peak_hashes)
    while len(hashes) > 1:
        right = hashes.pop()
        left = hashes.pop()
        hashes.append(hashlib.sha256(right + left).digest())
    return hashes[0]


# -- conformant commitment object --------------------------------------------
#
# `root_from_peaks` above is this module's own internal fold: convenient for
# a fast scalar comparison, but a bespoke convention -- no external
# MMRIVER-family tool has any way to know its bagging order or that it omits
# a domain-separator byte. `[cll-commitment-interop]` requires the checkpoint
# to commit to the REAL commitment object instead: the one
# draft-bryce-cose-receipts-mmr-profile (Bryce, Datatrails -- the MMRIVER
# draft's own author; https://www.ietf.org/archive/id/draft-bryce-cose-
# receipts-mmr-profile-00.txt) actually signs. That draft (SS6/7) never
# folds the peaks into one hash: "the complete accumulator" IS the ordered
# list of peak hashes itself -- e.g. `right-peaks: [ *bstr ]` -- detached and
# signed as-is, so a verifier must recompute it from the SAME list, not from
# a collapsed digest a folding scheme would have thrown information away
# from.


def _cbor_uint_header(major_type: int, n: int) -> bytes:
    """RFC 8949 SS3 definite-length head, shortest-form length encoding
    (the only form a canonical/deterministic CBOR encoder ever produces)."""
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
    """The MMRIVER / draft-bryce-cose-receipts-mmr-profile conformant
    commitment object for an MMR accumulator: the ordered peak hashes
    (tallest-to-smallest -- this module's own ``peaks()`` order, matching
    the profile's own "descending height ordered list", SS7.1.1), encoded as
    a canonical/deterministic CBOR array of 32-byte strings: ``[ *bstr ]``.

    This shape (fixed-length byte-string elements, one array, no floats, no
    maps) has exactly one valid RFC 8949 SS4.2 deterministic encoding, so
    every conformant CBOR encoder in any language produces these identical
    bytes -- this is why it is hand-rolled here rather than built on a CBOR
    library dependency: reproducing it needs nothing but this function's
    docstring, in any language (see ``commitment-conformance-vectors/`` for
    pinned cross-language vectors, including MUST-FAIL mutations).

    NOT ``root_from_peaks`` -- that single bagged hash is this module's own
    internal-only fold, undocumented by and unreproducible from the profile.
    Never used to change ``verify_inclusion``/``verify_consistency`` (those
    stay on ``root_from_peaks`` for this module's own fast proof checks);
    this is purely the external, independently-conformant encoding of the
    SAME peak-hash list.
    """
    for p in peak_hashes:
        _assert_digest(p, "peak")
    body = bytearray(_cbor_uint_header(4, len(peak_hashes)))
    for p in peak_hashes:
        body += _cbor_uint_header(2, len(p))
        body += p
    return bytes(body)


# -- massifdb cross-check (internal only, NOT production) --------------------
#
# Reproduces this module's original massifdb-derived scheme (fixed
# 0x01/0x02-prefix interior/bagging, no position commitment). Kept solely as
# an internal cross-check against that original design source -- see the
# module docstring for why position-commitment replaced it in production.
# Never call these from add_leaf, inclusion_proof, consistency_proof, or
# either verifier.


def _massifdb_interior_hash(left: bytes, right: bytes) -> bytes:
    """massifdb-compatible interior_hash = sha256(0x01 || left || right).
    Internal cross-check only -- NOT the production hashing scheme."""
    _assert_digest(left, "left")
    _assert_digest(right, "right")
    return hashlib.sha256(b"\x01" + left + right).digest()


def _massifdb_root_from_peaks(peak_hashes: list[bytes]) -> bytes:
    """massifdb-compatible peak bagging: acc = peaks[-1], then fold
    sha256(0x02||peaks[i]||acc) right-to-left. Internal cross-check only --
    NOT the production scheme."""
    if not peak_hashes:
        return bytes(DIGEST_LEN)
    for p in peak_hashes:
        _assert_digest(p, "peak")
    acc = peak_hashes[-1]
    for i in range(len(peak_hashes) - 2, -1, -1):
        acc = hashlib.sha256(b"\x02" + peak_hashes[i] + acc).digest()
    return acc


# -- position math -------------------------------------------------------


def height_at(pos: int) -> int:
    """Height of the node at 0-indexed position `pos` (0 = leaf level).

    The flat MMR position->height mapping matches the post-order traversal
    sequence of an ever-doubling perfect binary tree: T(0) = [0],
    T(H) = T(H-1) ++ T(H-1) ++ [H]. Locate `pos` (1-indexed) within the
    smallest such tree that contains it and descend, halving height each step.
    """
    _require_nonneg_int(pos, "pos")
    pos1 = pos + 1
    h = 0
    while 2 ** (h + 1) - 1 < pos1:
        h += 1
    while h > 0:
        size = 2 ** (h + 1) - 1
        if pos1 == size:
            return h
        left_size = 2**h - 1
        if pos1 > left_size:
            pos1 -= left_size
        h -= 1
    return 0


def node_count(leaf_count_: int) -> int:
    """nodeCount(f) = 2f - popcount(f): total node count for `f` leaves."""
    _require_nonneg_int(leaf_count_, "leaf_count")
    return 2 * leaf_count_ - bin(leaf_count_).count("1")


def peaks(size: int) -> list[int]:
    """Peak positions (left to right) of an MMR with `size` nodes.

    A valid MMR size decomposes into a strictly-decreasing sequence of
    "mountain" sizes 2^(h+1)-1 (greedy, largest-fitting first) whose heights
    strictly decrease left to right -- mirroring the 1-bits of leaf_count in
    decreasing order of significance. Any size that does not decompose this
    way (e.g. an in-progress/incomplete parent) is not a valid MMR size.
    """
    if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size >= MAX_MMR_SIZE:
        raise InvalidArgumentError(f"invalid MMR size: {size}")
    result: list[int] = []
    remaining = size
    offset = 0
    prev_height = float("inf")
    while remaining > 0:
        h = 0
        while 2 ** (h + 2) - 1 <= remaining:
            h += 1
        if h >= prev_height:
            raise InvalidArgumentError(f"invalid MMR size (not a valid node count): {size}")
        m_size = 2 ** (h + 1) - 1
        offset += m_size
        result.append(offset - 1)
        remaining -= m_size
        prev_height = h
    return result


def leaf_count(size: int) -> int:
    """Number of leaves in an MMR of `size` nodes. Raises on an invalid size."""
    pks = peaks(size)
    return sum(2 ** height_at(p) for p in pks)


def leaf_index_to_pos(leaf_index: int) -> int:
    """Position of the nth (0-indexed) leaf: node_count(leaf_index)."""
    _require_nonneg_int(leaf_index, "leaf_index")
    pos = node_count(leaf_index)
    if pos >= MAX_MMR_SIZE:
        raise InvalidArgumentError(f"leaf_index too large: {leaf_index}")
    return pos


def pos_to_leaf_index(pos: int) -> int:
    """Inverse of leaf_index_to_pos. Raises if `pos` is not a leaf position."""
    if height_at(pos) != 0:
        raise InvalidArgumentError(f"position {pos} is not a leaf")
    return leaf_count(pos)


# -- node storage protocol + appending ---------------------------------------


class NodeReader(Protocol):
    def size(self) -> int: ...
    def node(self, pos: int) -> bytes: ...


class NodeAppender(NodeReader, Protocol):
    def append_nodes(self, hashes: list[bytes]) -> None: ...


def add_leaf(nodes: NodeAppender, leaf: bytes) -> tuple[int, list[bytes]]:
    """Append `leaf` to the MMR exposed by `nodes`.

    Writes the leaf and any newly-completed parent nodes. Returns the leaf's
    position and all nodes appended (leaf first, then parents), in append
    order. Existing node hashes are never re-read for any purpose other than
    combining them as an input to a *new* node -- no prior node's own bytes
    are ever recomputed or rewritten.
    """
    _assert_digest(leaf, "leaf_hash")
    size = nodes.size()
    leaf_pos = size
    new_nodes: list[bytes] = [leaf]

    existing_peaks = [] if size == 0 else peaks(size)
    peak_idx = len(existing_peaks) - 1

    height = 0
    cur_hash = leaf

    while peak_idx >= 0 and height_at(existing_peaks[peak_idx]) == height:
        left_pos = existing_peaks[peak_idx]
        left_hash = nodes.node(left_pos)
        parent_pos = leaf_pos + len(new_nodes)
        parent_hash = interior_hash(left_hash, cur_hash, parent_pos)
        new_nodes.append(parent_hash)
        cur_hash = parent_hash
        height += 1
        peak_idx -= 1

    nodes.append_nodes(new_nodes)
    return leaf_pos, new_nodes


# -- proof paths ---------------------------------------------------------


@dataclass(frozen=True)
class _PathStep:
    sibling_pos: int
    target_is_right: bool  # True if the node on the path-so-far is the RIGHT child here.
    parent_pos: int  # 0-based array position of the parent node produced by this fold step.


def _find_containing_peak(pos: int, peak_positions: list[int]) -> int:
    """Index of the peak whose mountain contains `pos`, or -1."""
    for i, peak_pos in enumerate(peak_positions):
        h = height_at(peak_pos)
        m_size = 2 ** (h + 1) - 1
        start = peak_pos - m_size + 1
        if start <= pos <= peak_pos:
            return i
    return -1


def _locate_path(root_pos: int, height: int, target_pos: int) -> list[_PathStep]:
    """Bottom-up sibling path from `target_pos` up to (but excluding) the
    mountain root at `root_pos` (height `height`).

    `target_pos` need not be a leaf: consistency_proof walks from an *old
    peak* (which may itself be an interior node of arbitrary height, and may
    even coincide with `root_pos` when the old peak is still a peak in the
    new tree) up to the containing new peak, so this stops as soon as the
    current subtree root reaches the target -- not only when height hits 0.
    """
    top_down: list[_PathStep] = []
    cur_root = root_pos
    cur_height = height
    while cur_height > 0 and cur_root != target_pos:
        parent_pos = cur_root
        left_size = 2**cur_height - 1
        left_child_root = cur_root - left_size - 1
        right_child_root = cur_root - 1
        if target_pos <= left_child_root:
            top_down.append(_PathStep(right_child_root, False, parent_pos))
            cur_root = left_child_root
        else:
            top_down.append(_PathStep(left_child_root, True, parent_pos))
            cur_root = right_child_root
        cur_height -= 1
    top_down.reverse()
    return top_down


def _parse_digest_hex(h: object) -> bytes:
    if not isinstance(h, str):
        raise InvalidArgumentError("proof element is not a hex string")
    b = bytes.fromhex(h)
    if len(b) != DIGEST_LEN:
        raise InvalidArgumentError(f"proof element has wrong digest length: {len(b)}")
    return b


# -- inclusion -------------------------------------------------------------


@dataclass(frozen=True)
class InclusionProof:
    """Sibling hashes up to the leaf's peak, then the *other peaks* needed to
    re-bag the root. Hex-encoded so the whole shape is JSON-serializable,
    matching every other public shape in this workspace."""

    v: int
    kind: str  # "inclusion"
    size: int
    leaf_index: int
    witness: tuple[str, ...]
    peaks_left: tuple[str, ...]
    peaks_right: tuple[str, ...]


def inclusion_proof(reader: NodeReader, leaf_index: int, size: int) -> InclusionProof:
    lc = leaf_count(size)
    if not isinstance(leaf_index, int) or leaf_index < 0 or leaf_index >= lc:
        raise InvalidArgumentError(f"leaf_index out of range: {leaf_index}")
    reader_size = reader.size()
    if reader_size < size:
        raise IntegrityError(f"reader size {reader_size} is smaller than requested size {size}")

    leaf_pos = leaf_index_to_pos(leaf_index)
    pks = peaks(size)
    peak_idx = _find_containing_peak(leaf_pos, pks)
    if peak_idx == -1:
        raise IntegrityError(f"leaf position {leaf_pos} not found under any peak")
    peak_pos = pks[peak_idx]
    peak_height = height_at(peak_pos)
    path = _locate_path(peak_pos, peak_height, leaf_pos)

    witness = tuple(reader.node(step.sibling_pos).hex() for step in path)
    peaks_left = tuple(reader.node(pks[i]).hex() for i in range(peak_idx))
    peaks_right = tuple(reader.node(pks[i]).hex() for i in range(peak_idx + 1, len(pks)))

    return InclusionProof(1, "inclusion", size, leaf_index, witness, peaks_left, peaks_right)


def verify_inclusion(
    root: bytes, size: int, leaf_index: int, body_digest: bytes, proof: InclusionProof
) -> bool:
    """Pure, total-order-stable inclusion verification. No reader, never raises."""
    try:
        _assert_digest(root, "root")
        _assert_digest(body_digest, "body_digest")
        if proof is None or proof.v != 1 or proof.kind != "inclusion":
            return False
        if proof.size != size or proof.leaf_index != leaf_index:
            return False
        if not isinstance(size, int) or size < 0 or size >= MAX_MMR_SIZE:
            return False
        if not isinstance(leaf_index, int) or leaf_index < 0:
            return False
        if (
            not isinstance(proof.witness, (list, tuple))
            or not isinstance(proof.peaks_left, (list, tuple))
            or not isinstance(proof.peaks_right, (list, tuple))
        ):
            return False

        lc = leaf_count(size)
        if leaf_index >= lc:
            return False

        leaf_pos = leaf_index_to_pos(leaf_index)
        pks = peaks(size)
        peak_idx = _find_containing_peak(leaf_pos, pks)
        if peak_idx == -1:
            return False

        peak_pos = pks[peak_idx]
        peak_height = height_at(peak_pos)
        path = _locate_path(peak_pos, peak_height, leaf_pos)

        # Strict shape validation: no accidental acceptance via wrong-length
        # or empty-path edge cases.
        if len(proof.witness) != len(path):
            return False
        if len(proof.peaks_left) != peak_idx:
            return False
        if len(proof.peaks_right) != len(pks) - peak_idx - 1:
            return False

        witness_bytes = [_parse_digest_hex(w) for w in proof.witness]
        peaks_left_bytes = [_parse_digest_hex(w) for w in proof.peaks_left]
        peaks_right_bytes = [_parse_digest_hex(w) for w in proof.peaks_right]

        # `zip(..., strict=True)` needs Python 3.10+; this package's floor is
        # 3.9. Lengths are already proven equal above (`len(proof.witness) !=
        # len(path)` returns False first), so a plain zip is equivalent here.
        acc = leaf_hash(body_digest)
        for step, sib in zip(path, witness_bytes):
            acc = (
                interior_hash(sib, acc, step.parent_pos)
                if step.target_is_right
                else interior_hash(acc, sib, step.parent_pos)
            )

        all_peaks = [*peaks_left_bytes, acc, *peaks_right_bytes]
        computed_root = root_from_peaks(all_peaks)
        return computed_root == root
    except Exception:
        return False


# -- consistency (range proof) ------------------------------------------------


@dataclass(frozen=True)
class ConsistencyProof:
    """Lets a verifier holding only (root_a, size_a) confirm that the MMR at
    size_b >= size_a extends it: each old peak is proven contained in the new
    MMR and re-bags to root_b. MMR nodes are write-once, so old-peak positions
    carry identical hashes in the new log -- this proof never needs to
    recompute anything about the leaves under `size_a`."""

    v: int
    kind: str  # "consistency"
    size_a: int
    size_b: int
    old_peaks: tuple[str, ...]
    witness: tuple[tuple[str, ...], ...]
    new_peaks: tuple[str, ...]


def consistency_proof(reader: NodeReader, size_a: int, size_b: int) -> ConsistencyProof:
    if not isinstance(size_a, int) or size_a < 0:
        raise InvalidArgumentError(f"invalid size_a: {size_a}")
    if not isinstance(size_b, int) or size_b < size_a:
        raise InvalidArgumentError(f"invalid size_b: {size_b} (must be >= size_a={size_a})")
    reader_size = reader.size()
    if reader_size < size_b:
        raise IntegrityError(f"reader size {reader_size} is smaller than requested size_b {size_b}")

    old_peak_positions = peaks(size_a)
    new_peak_positions = peaks(size_b)

    old_peaks: list[str] = []
    witness: list[tuple[str, ...]] = []

    for p in old_peak_positions:
        h = reader.node(p)
        old_peaks.append(h.hex())

        containing_idx = _find_containing_peak(p, new_peak_positions)
        if containing_idx == -1:
            raise IntegrityError(f"old peak at position {p} not found in new MMR of size {size_b}")
        new_peak_pos = new_peak_positions[containing_idx]
        new_peak_height = height_at(new_peak_pos)
        path = _locate_path(new_peak_pos, new_peak_height, p)

        w = tuple(reader.node(step.sibling_pos).hex() for step in path)
        witness.append(w)

    new_peaks = tuple(reader.node(p).hex() for p in new_peak_positions)

    return ConsistencyProof(1, "consistency", size_a, size_b, tuple(old_peaks), tuple(witness), new_peaks)


def verify_consistency(
    root_a: bytes, size_a: int, root_b: bytes, size_b: int, proof: ConsistencyProof
) -> bool:
    """Pure consistency verification. No reader, never raises."""
    try:
        _assert_digest(root_a, "root_a")
        _assert_digest(root_b, "root_b")
        if proof is None or proof.v != 1 or proof.kind != "consistency":
            return False
        if proof.size_a != size_a or proof.size_b != size_b:
            return False
        if not isinstance(size_a, int) or size_a < 0:
            return False
        if not isinstance(size_b, int) or size_b < size_a:
            return False
        if (
            not isinstance(proof.old_peaks, (list, tuple))
            or not isinstance(proof.new_peaks, (list, tuple))
            or not isinstance(proof.witness, (list, tuple))
        ):
            return False

        old_peak_positions = peaks(size_a)
        new_peak_positions = peaks(size_b)

        if len(proof.old_peaks) != len(old_peak_positions):
            return False
        if len(proof.new_peaks) != len(new_peak_positions):
            return False
        if len(proof.witness) != len(old_peak_positions):
            return False

        old_peaks_bytes = [_parse_digest_hex(w) for w in proof.old_peaks]
        new_peaks_bytes = [_parse_digest_hex(w) for w in proof.new_peaks]

        computed_root_a = root_from_peaks(old_peaks_bytes)
        if computed_root_a != root_a:
            return False
        computed_root_b = root_from_peaks(new_peaks_bytes)
        if computed_root_b != root_b:
            return False

        for i, p in enumerate(old_peak_positions):
            containing_idx = _find_containing_peak(p, new_peak_positions)
            if containing_idx == -1:
                return False

            new_peak_pos = new_peak_positions[containing_idx]
            new_peak_height = height_at(new_peak_pos)
            path = _locate_path(new_peak_pos, new_peak_height, p)

            w = proof.witness[i]
            if not isinstance(w, (list, tuple)) or len(w) != len(path):
                return False
            w_bytes = [_parse_digest_hex(x) for x in w]

            # See verify_inclusion above: lengths already proven equal by the
            # `len(w) != len(path)` check above, so plain zip is equivalent
            # to strict=True (unavailable before Python 3.10) here.
            acc = old_peaks_bytes[i]
            for step, sib in zip(path, w_bytes):
                acc = (
                    interior_hash(sib, acc, step.parent_pos)
                    if step.target_is_right
                    else interior_hash(acc, sib, step.parent_pos)
                )
            if acc != new_peaks_bytes[containing_idx]:
                return False

        return True
    except Exception:
        return False
