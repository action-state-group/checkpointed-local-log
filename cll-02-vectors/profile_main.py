# SPDX-License-Identifier: BSD-3-Clause
#
# Code Components transcribed from the editors' copy of
# draft-bryce-cose-receipts-mmr-profile (R. Bryce, J. Geater),
#   https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile
#   at commit f1320c0
#
# Copyright (c) 2026 IETF Trust and the persons identified as the document
# authors. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# - Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# - Neither the name of Internet Society, IETF or IETF Trust, nor the names of
#   specific contributors, may be used to endorse or promote products derived
#   from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
"""draft-bryce-cose-receipts-mmr-profile, editors' main, transcribed.

Source: https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile
at commit f1320c0 (draft-bryce-cose-receipts-mmr-profile.md). The functions
below are that text's pseudocode, copied as printed. Every ``# ... -> ERROR``
comment in the text is executed here as a raise; nothing else is changed.
Unlike -03 (see ../mmr-profile-vectors/draft03.py), editors' main runs as
printed, so no repairs are applied.

No checkpointed-local-log code is imported. This module is the independent
side of the CLL -02 vectors: the generator builds every value from it.
"""
from __future__ import annotations

import hashlib

PROFILE_COMMIT = "f1320c0"
PROFILE_REPO = "https://github.com/robinbryce/draft-bryce-cose-receipts-mmr-profile"


class ProofError(ValueError):
    """A ``# ... -> ERROR`` line of the profile text was reached."""


# -- Assumed bit primitives ----------------------------------------------------

def log2floor(x):
    return x.bit_length() - 1


def most_sig_bit(pos) -> int:
    return 1 << (pos.bit_length() - 1)


def bit_length(pos):
    return pos.bit_length()


def all_ones(pos) -> bool:
    mask = (most_sig_bit(pos) << 1) - 1
    return pos == mask


def ones_count(x):
    return bin(x).count("1")


# -- Essential supporting algorithms -------------------------------------------

def index_height(i) -> int:
    pos = i + 1
    while not all_ones(pos):
        pos = pos - most_sig_bit(pos) + 1
    return bit_length(pos) - 1


def peaks(i):
    peak = 0
    peaks_ = []
    s = i + 1
    while s != 0:
        highest_size = (1 << log2floor(s + 1)) - 1
        peak = peak + highest_size
        peaks_.append(peak - 1)
        s -= highest_size
    return peaks_


def leaf_count(i):
    s = i + 1
    peaksize = (1 << bit_length(s)) - 1
    peakmap = 0
    while peaksize > 0:
        peakmap <<= 1
        if s >= peaksize:
            s -= peaksize
            peakmap |= 1
        peaksize >>= 1
    return peakmap


def mmr_size_for_leaf_count(leaves):
    return 2 * leaves - ones_count(leaves)


def is_complete(size) -> bool:
    """Conventions: MMR(n) is complete iff index_height(n) is 0."""
    return size == 0 or index_height(size) == 0


# -- Node values ----------------------------------------------------------------

def hash_pospair64(pos, a, b):
    h = hashlib.sha256()
    h.update(pos.to_bytes(8, byteorder="big", signed=False))
    h.update(a)
    h.update(b)
    return h.digest()


class ListDB:
    """``append`` returns the node count after the append, as the text says."""

    def __init__(self):
        self.nodes = []

    def append(self, entry):
        self.nodes.append(entry)
        return len(self.nodes)

    def get(self, index):
        return self.nodes[index]


def add_leaf_hash(db, f: bytes):
    g = 0
    i = db.append(f)
    while index_height(i) > g:
        ileft = i - (2 << g)
        iright = i - 1
        i = db.append(hash_pospair64(i + 1, db.get(ileft), db.get(iright)))
        g += 1
    return i


# -- Inclusion ------------------------------------------------------------------

def inclusion_proof_path(i, c):
    path = []
    g = index_height(i)
    while True:
        siblingoffset = 2 << g
        if index_height(i + 1) > g:
            isibling = i - siblingoffset + 1
            i += 1
        else:
            isibling = i + siblingoffset - 1
            i += siblingoffset
        if isibling > c:
            return path
        path.append(isibling)
        g += 1


def included_root(i, nodehash, proof):
    root = nodehash
    g = index_height(i)
    for sibling in proof:
        if index_height(i + 1) > g:
            i = i + 1
            root = hash_pospair64(i + 1, sibling, root)
        else:
            i = i + (2 << g)
            root = hash_pospair64(i + 1, root, sibling)
        g = g + 1
    return root


# -- Consistency ----------------------------------------------------------------

def consistency_proof_paths(ifrom, ito):
    proof = []
    for i in peaks(ifrom):
        proof.append(inclusion_proof_path(i, ito))
    return proof


def consistent_roots(sizefrom, sizeto, accumulatorfrom, proofs):
    if sizeto <= sizefrom:
        raise ProofError("sizeto <= sizefrom")

    leavesto = leaf_count(sizeto - 1)
    if mmr_size_for_leaf_count(leavesto) != sizeto:
        raise ProofError("sizeto is not a complete MMR size")

    if sizefrom > 0:
        leavesfrom = leaf_count(sizefrom - 1)
    else:
        leavesfrom = 0

    n = ones_count(leavesfrom)
    if len(accumulatorfrom) != n:
        raise ProofError("length(accumulatorfrom) != n")
    if len(proofs) != n:
        raise ProofError("length(proofs) != n")

    nto = ones_count(leavesto)
    if n == 0:
        return [], nto

    split = bit_length(leavesfrom ^ leavesto) - 1

    roots = []
    offset = 0
    i = 0

    for h in range(bit_length(leavesfrom) - 1, split, -1):
        if not (leavesfrom >> h) & 1:
            continue
        if len(proofs[i]) != 0:
            raise ProofError("non-empty path for an origin peak above split")
        roots.append(accumulatorfrom[i])
        offset += (1 << (h + 1)) - 1
        i += 1

    above = len(roots)
    root = None
    for h in range(split - 1, -1, -1):
        if not (leavesfrom >> h) & 1:
            continue
        if len(proofs[i]) != split - h:
            raise ProofError("path length != split - h")
        subtree = (1 << (h + 1)) - 1
        proven = included_root(offset + subtree - 1, accumulatorfrom[i], proofs[i])
        if i == above:
            root = proven
        elif proven != root:
            raise ProofError("paths to the split peak disagree")
        offset += subtree
        i += 1

    if n > above:
        roots.append(root)

    return roots, nto - len(roots)


def verify_consistency_accumulator(tree_size_1, accumulatorfrom, proof_content):
    """Steps 3-5 of 'Verifying the Receipt of consistency' for one proof.

    ``proof_content`` is ``[tree-size-1, tree-size-2, consistency-paths,
    right-peaks]``. Returns the accumulator for tree-size-2 (the detached
    payload a receipt of consistency is signed over, as a peak list).
    """
    size1, size2, paths, right = proof_content
    if size1 != tree_size_1:
        raise ProofError("tree-size-1 != trusted tree size")
    for v in [x for p in paths for x in p] + list(right):
        if len(v) != 32:
            raise ProofError("node value is not 32 bytes")
    roots, nright = consistent_roots(size1, size2, accumulatorfrom, paths)
    if len(right) != nright:
        raise ProofError("length(right-peaks) != nright")
    return list(roots) + list(right)
