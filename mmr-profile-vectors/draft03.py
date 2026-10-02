# SPDX-License-Identifier: BSD-3-Clause
#
# Code Components transcribed from draft-bryce-cose-receipts-mmr-profile-03
# (R. Bryce, J. Geater, 19 September 2026),
#   https://www.ietf.org/archive/id/draft-bryce-cose-receipts-mmr-profile-03.txt
#   sha256 fba4838118dad19733ab6c6dbdcb92f799ccfa35db38ae3a6c1e17b84b8b56d7
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
"""The -03 pseudocode, transcribed, with only the repairs its own prose states.

This module is NOT checkpointed-local-log's MMR (that is ``cll.checkpoint.core``,
which domain-separates leaves and is not byte-identical to the draft). It is a
from-the-text reading of draft-bryce-cose-receipts-mmr-profile-03, used only to
generate the draft-exact vectors in this directory. It imports nothing from CLL.

Every departure from the printed code is marked ``REPAIR R<n>`` and listed in
``REPAIRS`` below with the -03 text that states it. Anything the -03 prose does
not state is NOT repaired here (leaf/interior domain separation, a leaf-only
check on the proof index, de-duplication by position, a byte encoding for the
consistency accumulator).
"""
from __future__ import annotations

import hashlib

DRAFT = "draft-bryce-cose-receipts-mmr-profile-03"
DRAFT_URL = "https://www.ietf.org/archive/id/draft-bryce-cose-receipts-mmr-profile-03.txt"
DRAFT_SHA256 = "fba4838118dad19733ab6c6dbdcb92f799ccfa35db38ae3a6c1e17b84b8b56d7"

REPAIRS = {
    "R1": {
        "name": "all_ones per its prose",
        "where": "Appendix A.4 (all_ones); used by Section 9.1 index_height",
        "printed": "mask = (1 << (msb + 1)) - 1, where msb = most_sig_bit(pos) is already a mask",
        "repair": "mask = (most_sig_bit(pos) << 1) - 1",
        "prose": "A.4: 'Tests if all bits, from the most significant that is set, are 1, "
                 "b0111 would be true, b0101 would be false.'",
        "why": "as printed all_ones is false for every pos, so index_height never terminates",
    },
    "R2": {
        "name": "append returns the node count (the index the next node will occupy)",
        "where": "Section 8.1 (add_leaf_hash)",
        "printed": "db 'append(entry) -> index', read as the index just stored, leaves the loop one node behind",
        "repair": "db.append returns the MMR size after the append; code otherwise unchanged",
        "prose": "8.1 listing comments: the left child of i 'is i - 2^(g+1)', the right child 'is i - 1', "
                 "'Set v to H(i + 1 || ...)', with Section 2 'pos = i + 1' for the node being stored",
        "why": "only this reading makes every comment in the listing true; four leaves give seven nodes",
    },
    "R3": {
        "name": "right-peaks count from consistent_roots, not len(proofs)",
        "where": "Section 6.1 vs Section 7.1 step 7",
        "printed": "6.1: right-peaks = peaks(tree-size-2 - 1) 'discarding length(proofs) from the left'",
        "repair": "discard the number of roots consistent_roots returns (7.1 step 7)",
        "prose": "7.1 step 7: 'discard from the left the number of roots returned by consistent_roots'",
        "why": "for MMR(4) -> MMR(8) both origin peaks reach peak 6; 6.1 as printed drops peak 7",
    },
    "R4": {
        "name": "right-peaks are node values, taken from the proof",
        "where": "Section 7.1 steps 6-8",
        "printed": "steps 6-8 call peaks(), which returns indices, and never read the right-peaks field",
        "repair": "the consistent accumulator is consistent_roots(...) followed by the right-peaks values",
        "prose": "Section 6 CDDL comment on right-peaks: 'the additional peaks that complete the "
                 "accumulator for tree-size-2, when appended to those produced by the consistency paths'",
        "why": "a verifier holds no node store; peaks() alone cannot produce values",
    },
    "R5": {
        "name": "accumulatorfrom is a trusted verifier input",
        "where": "Section 7.1 step 2, Section 7.1.1",
        "printed": "step 2: 'Initialize accumulatorfrom to the peaks of tree-size-1 in the current proof', "
                   "but the proof carries no such values",
        "repair": "accumulatorfrom is supplied by the verifier (the node values of peaks(tree-size-1 - 1))",
        "prose": "7.1.1 Given: 'accumulatorfrom the node values corresponding to the peaks of the "
                 "accumulator for tree-size-1'",
        "why": "consistent_roots needs values the wire format does not carry",
    },
    "R6": {
        "name": "cardinality checks raise",
        "where": "Section 7.1.1 (consistent_roots)",
        "printed": "prose MUST compares len(peaks(ifrom)) with len(accumulatorfrom); the code comment "
                   "compares len(frompeaks) with len(proofs); neither is executed",
        "repair": "both checks are executed and raise",
        "prose": "7.1.1: 'Implementations MUST require that the number of peaks returned by "
                 "Section 9.2(ifrom) equals the number of entries in accumulatorfrom' and the "
                 "'# if length(frompeaks) != length(proofs) -> ERROR' comment",
        "why": "otherwise extra or missing proof material is silently ignored or crashes",
    },
    "R7": {
        "name": "reject incomplete sizes: MMR(n) is complete iff index_height(n) == 0",
        "where": "Section 9.2 (peaks)",
        "printed": "'Assumes MMR(i+1) is complete, implementations can check for this condition by "
                   "testing the height of i+1' (the value tested for is not stated)",
        "repair": "peaks(i) raises unless index_height(i + 1) == 0",
        "prose": "9.2 names the test; 0 is the only height for which it holds (the next node would "
                 "be a leaf). The text names the test but not the value, so this one is a reading",
        "why": "peaks(4) returns [2, 3, 4] for the incomplete size 5, which is not an accumulator",
    },
    "R8": {
        "name": "the inclusion input is H(entry)",
        "where": "Section 5.1 vs Section 8.1",
        "printed": "5.1 applies the proof 'to a possible entry (set member) bytes'; included_root "
                   "takes a nodehash",
        "repair": "nodehash = SHA-256(entry bytes)",
        "prose": "8.1: 'f the leaf value resulting from H(x) for the caller defined leaf value x'",
        "why": "raw bytes and H(bytes) give different roots",
    },
}


# -- Appendix A: assumed bit primitives --------------------------------------

def log2floor(x):
    return x.bit_length() - 1


def most_sig_bit(pos) -> int:
    return 1 << (pos.bit_length() - 1)


def bit_length(pos):
    return pos.bit_length()


def all_ones_as_printed(pos) -> bool:
    """A.4 exactly as printed. Kept only to pin the defect; never used below."""
    msb = most_sig_bit(pos)
    mask = (1 << (msb + 1)) - 1
    return pos == mask


def all_ones(pos) -> bool:
    msb = most_sig_bit(pos)
    mask = (msb << 1) - 1  # REPAIR R1
    return pos == mask


# -- Section 9: essential supporting algorithms ------------------------------

def index_height(i) -> int:
    pos = i + 1
    while not all_ones(pos):
        pos = pos - most_sig_bit(pos) + 1
    return bit_length(pos) - 1


def index_height_as_printed(i, bound):
    """9.1 over the printed A.4; returns None if it has not returned after `bound` steps."""
    pos = i + 1
    for _ in range(bound):
        if all_ones_as_printed(pos):
            return bit_length(pos) - 1
        pos = pos - most_sig_bit(pos) + 1
    return None


class IncompleteSize(ValueError):
    pass


def is_complete(size) -> bool:
    return size == 0 or index_height(size) == 0  # REPAIR R7


def peaks(i):
    if not is_complete(i + 1):  # REPAIR R7
        raise IncompleteSize(f"MMR({i + 1}) is not complete")
    return peaks_as_printed(i)


def peaks_as_printed(i):
    peak = 0
    peaks = []
    s = i + 1
    while s != 0:
        # find the highest peak size in the current MMR(s)
        highest_size = (1 << log2floor(s + 1)) - 1
        peak = peak + highest_size
        peaks.append(peak - 1)
        s -= highest_size
    return peaks


# -- Section 8: appending a leaf ---------------------------------------------

def hash_pospair64(pos, a, b):
    # Note: Hash algorithm agility is tbd, this example uses SHA-256
    h = hashlib.sha256()
    # Take the big endian representation of pos
    h.update(pos.to_bytes(8, byteorder="big", signed=False))
    h.update(a)
    h.update(b)
    return h.digest()


class ListDB:
    """The 8.1 'db' interface under REPAIR R2: append returns the node count."""

    def __init__(self):
        self.nodes = []

    def append(self, entry):
        self.nodes.append(entry)
        return len(self.nodes)  # REPAIR R2

    def get(self, index):
        return self.nodes[index]


def add_leaf_hash(db, f: bytes):
    # Set g to 0, the height of the leaf item f
    g = 0
    # Set i to the result of invoking Append(f)
    i = db.append(f)
    # If index_height(i) is greater than g (#looptarget)
    while index_height(i) > g:
        ileft = i - (2 << g)
        iright = i - 1
        i = db.append(hash_pospair64(i + 1, db.get(ileft), db.get(iright)))
        g += 1
    return i


# -- Section 4.1 / 5.2: inclusion --------------------------------------------

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


# -- Section 6.1 / 7.1: consistency ------------------------------------------

def consistency_proof_paths(ifrom, ito):
    proof = []
    for i in peaks(ifrom):
        proof.append(inclusion_proof_path(i, ito))
    return proof


class CardinalityError(ValueError):
    pass


def consistent_roots(ifrom, accumulatorfrom, proofs):
    frompeaks = peaks(ifrom)
    if len(frompeaks) != len(accumulatorfrom):  # REPAIR R6 (prose MUST)
        raise CardinalityError("len(peaks(ifrom)) != len(accumulatorfrom)")
    if len(frompeaks) != len(proofs):  # REPAIR R6 (code comment)
        raise CardinalityError("len(frompeaks) != len(proofs)")
    roots = []
    for i in range(len(accumulatorfrom)):
        root = included_root(frompeaks[i], accumulatorfrom[i], proofs[i])
        if roots and roots[-1] == root:
            continue
        roots.append(root)
    return roots


def right_peaks_as_printed(nodes, tree_size_2, proofs):
    """6.1 as printed: peaks(tree-size-2 - 1), discard length(proofs) from the left."""
    return [nodes[p] for p in peaks(tree_size_2 - 1)[len(proofs):]]


def right_peaks(nodes, tree_size_1, tree_size_2, accumulatorfrom):
    """Producer side under REPAIR R3: discard as many as consistent_roots returns."""
    proofs = [[nodes[s] for s in path]
              for path in consistency_proof_paths(tree_size_1 - 1, tree_size_2 - 1)]
    nroots = len(consistent_roots(tree_size_1 - 1, accumulatorfrom, proofs))
    return [nodes[p] for p in peaks(tree_size_2 - 1)[nroots:]]


def consistent_accumulator(tree_size_1, tree_size_2, accumulatorfrom, proofs, right):
    """Verifier side, 7.1 steps 2-8 under R3, R4, R5, R6, R7."""
    peaks(tree_size_2 - 1)  # R7: tree-size-2 must be complete
    roots = consistent_roots(tree_size_1 - 1, accumulatorfrom, proofs)
    if len(roots) + len(right) != len(peaks(tree_size_2 - 1)):  # R3 / step 7
        raise CardinalityError("consistent roots + right-peaks != peaks of tree-size-2")
    return roots + list(right)  # R4 / step 8
