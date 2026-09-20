//! Merkle Mountain Range (MMR) core algorithm -- byte-for-byte port of the
//! Python reference's `cll.checkpoint.core` (see that module's docstring for
//! the full provenance/design rationale; this port carries only the wire
//! contract, not the essay).
//!
//! Classic flat-array MMR: 0-indexed node positions, grown strictly left to
//! right, interior nodes appear immediately after both of their children.
//!
//! Hashing scheme (MMRIVER-draft-compatible, position-committed):
//!   leaf_hash     = sha256(0x00 || body_digest)
//!   interior_hash = sha256(be64(position + 1) || left || right)
//!   root          = bagged peaks, right-to-left, no domain-separator byte:
//!                   pop the two rightmost peak hashes, combine as
//!                   sha256(right || left), push the result back, repeat
//!                   until one hash remains
//!   root of an empty MMR = 32 zero bytes

use sha2::{Digest, Sha256};
use std::fmt;

pub const DIGEST_LEN: usize = 32;
pub const MAX_MMR_SIZE: u64 = 1 << 50;

pub type Hash = [u8; DIGEST_LEN];

#[derive(Debug, thiserror::Error)]
pub enum MmrError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("integrity error: {0}")]
    Integrity(String),
}

pub(crate) fn invalid(msg: impl Into<String>) -> MmrError {
    MmrError::InvalidArgument(msg.into())
}

pub(crate) fn integrity(msg: impl Into<String>) -> MmrError {
    MmrError::Integrity(msg.into())
}

// -- hashing ------------------------------------------------------------

pub fn leaf_hash(body_digest: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00u8]);
    hasher.update(body_digest);
    hasher.finalize().into()
}

/// `position` is the 0-based array index the new interior node occupies.
pub fn interior_hash(left: &Hash, right: &Hash, position: u64) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update((position + 1).to_be_bytes());
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Root = binary-tree bagging of the peaks, right-to-left pairwise folding
/// with NO domain-separator byte. Root of an empty MMR is 32 zero bytes.
pub fn root_from_peaks(peak_hashes: &[Hash]) -> Hash {
    if peak_hashes.is_empty() {
        return [0u8; DIGEST_LEN];
    }
    let mut hashes: Vec<Hash> = peak_hashes.to_vec();
    while hashes.len() > 1 {
        let right = hashes.pop().unwrap();
        let left = hashes.pop().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(right);
        hasher.update(left);
        hashes.push(hasher.finalize().into());
    }
    hashes[0]
}

// -- conformant commitment object ----------------------------------------
//
// The MMRIVER / draft-bryce-cose-receipts-mmr-profile conformant commitment
// object for an MMR accumulator: canonical/deterministic CBOR array of
// 32-byte strings, `[ *bstr ]`, hand-rolled (RFC 8949 SS4.2 has exactly one
// valid encoding for this shape) rather than built on a CBOR library
// dependency -- see `commitment-conformance-vectors/` for pinned vectors.

fn cbor_uint_header(major_type: u8, n: u64) -> Vec<u8> {
    let prefix = major_type << 5;
    if n < 24 {
        vec![prefix | n as u8]
    } else if n < 1 << 8 {
        vec![prefix | 24, n as u8]
    } else if n < 1 << 16 {
        let mut v = vec![prefix | 25];
        v.extend_from_slice(&(n as u16).to_be_bytes());
        v
    } else if n < 1u64 << 32 {
        let mut v = vec![prefix | 26];
        v.extend_from_slice(&(n as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![prefix | 27];
        v.extend_from_slice(&n.to_be_bytes());
        v
    }
}

pub fn commitment_object(peak_hashes: &[Hash]) -> Vec<u8> {
    let mut body = cbor_uint_header(4, peak_hashes.len() as u64);
    for p in peak_hashes {
        body.extend(cbor_uint_header(2, p.len() as u64));
        body.extend_from_slice(p);
    }
    body
}

// -- position math ---------------------------------------------------------

/// Height of the node at 0-indexed position `pos` (0 = leaf level).
pub fn height_at(pos: u64) -> u32 {
    let mut pos1 = pos + 1;
    let mut h: u32 = 0;
    while (1u64 << (h + 1)) - 1 < pos1 {
        h += 1;
    }
    loop {
        if h == 0 {
            return 0;
        }
        let size = (1u64 << (h + 1)) - 1;
        if pos1 == size {
            return h;
        }
        let left_size = (1u64 << h) - 1;
        if pos1 > left_size {
            pos1 -= left_size;
        }
        h -= 1;
    }
}

/// nodeCount(f) = 2f - popcount(f): total node count for `f` leaves.
pub fn node_count(leaf_count_: u64) -> u64 {
    2 * leaf_count_ - leaf_count_.count_ones() as u64
}

/// Peak positions (left to right) of an MMR with `size` nodes.
pub fn peaks(size: u64) -> Result<Vec<u64>, MmrError> {
    if size >= MAX_MMR_SIZE {
        return Err(invalid(format!("invalid MMR size: {size}")));
    }
    let mut result = Vec::new();
    let mut remaining = size;
    let mut offset: u64 = 0;
    let mut prev_height: i64 = i64::MAX;
    while remaining > 0 {
        let mut h: u32 = 0;
        while (1u64 << (h + 2)) - 1 <= remaining {
            h += 1;
        }
        if h as i64 >= prev_height {
            return Err(invalid(format!("invalid MMR size (not a valid node count): {size}")));
        }
        let m_size = (1u64 << (h + 1)) - 1;
        offset += m_size;
        result.push(offset - 1);
        remaining -= m_size;
        prev_height = h as i64;
    }
    Ok(result)
}

/// Number of leaves in an MMR of `size` nodes.
pub fn leaf_count(size: u64) -> Result<u64, MmrError> {
    let pks = peaks(size)?;
    Ok(pks.iter().map(|&p| 1u64 << height_at(p)).sum())
}

/// Position of the nth (0-indexed) leaf.
pub fn leaf_index_to_pos(leaf_index: u64) -> Result<u64, MmrError> {
    let pos = node_count(leaf_index);
    if pos >= MAX_MMR_SIZE {
        return Err(invalid(format!("leaf_index too large: {leaf_index}")));
    }
    Ok(pos)
}

/// Inverse of `leaf_index_to_pos`. Errors if `pos` is not a leaf position.
pub fn pos_to_leaf_index(pos: u64) -> Result<u64, MmrError> {
    if height_at(pos) != 0 {
        return Err(invalid(format!("position {pos} is not a leaf")));
    }
    leaf_count(pos)
}

// -- node storage ------------------------------------------------------------

pub trait NodeReader {
    fn size(&self) -> u64;
    fn node(&self, pos: u64) -> Hash;
}

pub trait NodeAppender: NodeReader {
    fn append_nodes(&mut self, hashes: &[Hash]);
}

#[derive(Default, Clone)]
pub struct MemoryNodeStore {
    nodes: Vec<Hash>,
}

impl MemoryNodeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NodeReader for MemoryNodeStore {
    fn size(&self) -> u64 {
        self.nodes.len() as u64
    }

    fn node(&self, pos: u64) -> Hash {
        self.nodes[pos as usize]
    }
}

impl NodeAppender for MemoryNodeStore {
    fn append_nodes(&mut self, hashes: &[Hash]) {
        self.nodes.extend_from_slice(hashes);
    }
}

/// Append `leaf` (already a leaf hash) to the MMR exposed by `nodes`.
/// Returns the leaf's position and all nodes appended (leaf first, then
/// parents), in append order.
pub fn add_leaf(nodes: &mut impl NodeAppender, leaf: Hash) -> Result<(u64, Vec<Hash>), MmrError> {
    let size = nodes.size();
    let leaf_pos = size;
    let mut new_nodes: Vec<Hash> = vec![leaf];

    let existing_peaks = if size == 0 { Vec::new() } else { peaks(size)? };
    let mut peak_idx = existing_peaks.len() as i64 - 1;

    let mut height: u32 = 0;
    let mut cur_hash = leaf;

    while peak_idx >= 0 && height_at(existing_peaks[peak_idx as usize]) == height {
        let left_pos = existing_peaks[peak_idx as usize];
        let left_hash = nodes.node(left_pos);
        let parent_pos = leaf_pos + new_nodes.len() as u64;
        let parent_hash = interior_hash(&left_hash, &cur_hash, parent_pos);
        new_nodes.push(parent_hash);
        cur_hash = parent_hash;
        height += 1;
        peak_idx -= 1;
    }

    nodes.append_nodes(&new_nodes);
    Ok((leaf_pos, new_nodes))
}

// -- proof paths -------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct PathStep {
    sibling_pos: u64,
    /// True if the node on the path-so-far is the RIGHT child here.
    target_is_right: bool,
    parent_pos: u64,
}

/// Index of the peak whose mountain contains `pos`, or `None`.
fn find_containing_peak(pos: u64, peak_positions: &[u64]) -> Option<usize> {
    for (i, &peak_pos) in peak_positions.iter().enumerate() {
        let h = height_at(peak_pos);
        let m_size = (1u64 << (h + 1)) - 1;
        let start = peak_pos + 1 - m_size;
        if start <= pos && pos <= peak_pos {
            return Some(i);
        }
    }
    None
}

/// Bottom-up sibling path from `target_pos` up to (but excluding) the
/// mountain root at `root_pos` (height `height`).
fn locate_path(root_pos: u64, height: u32, target_pos: u64) -> Vec<PathStep> {
    let mut top_down = Vec::new();
    let mut cur_root = root_pos;
    let mut cur_height = height;
    while cur_height > 0 && cur_root != target_pos {
        let parent_pos = cur_root;
        let left_size = (1u64 << cur_height) - 1;
        let left_child_root = cur_root - left_size - 1;
        let right_child_root = cur_root - 1;
        if target_pos <= left_child_root {
            top_down.push(PathStep {
                sibling_pos: right_child_root,
                target_is_right: false,
                parent_pos,
            });
            cur_root = left_child_root;
        } else {
            top_down.push(PathStep {
                sibling_pos: left_child_root,
                target_is_right: true,
                parent_pos,
            });
            cur_root = right_child_root;
        }
        cur_height -= 1;
    }
    top_down.reverse();
    top_down
}

pub(crate) fn parse_digest_hex(h: &str) -> Result<Hash, ()> {
    let bytes = hex::decode(h).map_err(|_| ())?;
    bytes.try_into().map_err(|_| ())
}

// -- inclusion ---------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub v: u32,
    pub kind: String,
    pub size: u64,
    pub leaf_index: u64,
    pub witness: Vec<String>,
    pub peaks_left: Vec<String>,
    pub peaks_right: Vec<String>,
}

impl fmt::Display for InclusionProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InclusionProof(size={}, leaf_index={})", self.size, self.leaf_index)
    }
}

pub fn inclusion_proof(
    reader: &impl NodeReader,
    leaf_index: u64,
    size: u64,
) -> Result<InclusionProof, MmrError> {
    let lc = leaf_count(size)?;
    if leaf_index >= lc {
        return Err(invalid(format!("leaf_index out of range: {leaf_index}")));
    }
    let reader_size = reader.size();
    if reader_size < size {
        return Err(integrity(format!(
            "reader size {reader_size} is smaller than requested size {size}"
        )));
    }

    let leaf_pos = leaf_index_to_pos(leaf_index)?;
    let pks = peaks(size)?;
    let peak_idx = find_containing_peak(leaf_pos, &pks)
        .ok_or_else(|| integrity(format!("leaf position {leaf_pos} not found under any peak")))?;
    let peak_pos = pks[peak_idx];
    let peak_height = height_at(peak_pos);
    let path = locate_path(peak_pos, peak_height, leaf_pos);

    let witness = path.iter().map(|s| hex::encode(reader.node(s.sibling_pos))).collect();
    let peaks_left = pks[..peak_idx].iter().map(|&p| hex::encode(reader.node(p))).collect();
    let peaks_right = pks[peak_idx + 1..].iter().map(|&p| hex::encode(reader.node(p))).collect();

    Ok(InclusionProof {
        v: 1,
        kind: "inclusion".to_string(),
        size,
        leaf_index,
        witness,
        peaks_left,
        peaks_right,
    })
}

/// Pure, total inclusion verification. Never panics on malformed proof data.
pub fn verify_inclusion(root: &Hash, size: u64, leaf_index: u64, body_digest: &Hash, proof: &InclusionProof) -> bool {
    (|| -> Result<bool, ()> {
        if proof.v != 1 || proof.kind != "inclusion" {
            return Ok(false);
        }
        if proof.size != size || proof.leaf_index != leaf_index {
            return Ok(false);
        }
        if size >= MAX_MMR_SIZE {
            return Ok(false);
        }

        let lc = leaf_count(size).map_err(|_| ())?;
        if leaf_index >= lc {
            return Ok(false);
        }

        let leaf_pos = leaf_index_to_pos(leaf_index).map_err(|_| ())?;
        let pks = peaks(size).map_err(|_| ())?;
        let peak_idx = match find_containing_peak(leaf_pos, &pks) {
            Some(i) => i,
            None => return Ok(false),
        };
        let peak_pos = pks[peak_idx];
        let peak_height = height_at(peak_pos);
        let path = locate_path(peak_pos, peak_height, leaf_pos);

        if proof.witness.len() != path.len() {
            return Ok(false);
        }
        if proof.peaks_left.len() != peak_idx {
            return Ok(false);
        }
        if proof.peaks_right.len() != pks.len() - peak_idx - 1 {
            return Ok(false);
        }

        let witness_bytes: Vec<Hash> = proof.witness.iter().map(|w| parse_digest_hex(w)).collect::<Result<_, _>>()?;
        let peaks_left_bytes: Vec<Hash> =
            proof.peaks_left.iter().map(|w| parse_digest_hex(w)).collect::<Result<_, _>>()?;
        let peaks_right_bytes: Vec<Hash> =
            proof.peaks_right.iter().map(|w| parse_digest_hex(w)).collect::<Result<_, _>>()?;

        let mut acc = leaf_hash(body_digest);
        for (step, sib) in path.iter().zip(witness_bytes.iter()) {
            acc = if step.target_is_right {
                interior_hash(sib, &acc, step.parent_pos)
            } else {
                interior_hash(&acc, sib, step.parent_pos)
            };
        }

        let mut all_peaks = peaks_left_bytes;
        all_peaks.push(acc);
        all_peaks.extend(peaks_right_bytes);
        let computed_root = root_from_peaks(&all_peaks);
        Ok(&computed_root == root)
    })()
    .unwrap_or(false)
}

// -- consistency ---------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub v: u32,
    pub kind: String,
    pub size_a: u64,
    pub size_b: u64,
    pub old_peaks: Vec<String>,
    pub witness: Vec<Vec<String>>,
    pub new_peaks: Vec<String>,
}

pub fn consistency_proof(reader: &impl NodeReader, size_a: u64, size_b: u64) -> Result<ConsistencyProof, MmrError> {
    if size_b < size_a {
        return Err(invalid(format!("invalid size_b: {size_b} (must be >= size_a={size_a})")));
    }
    let reader_size = reader.size();
    if reader_size < size_b {
        return Err(integrity(format!(
            "reader size {reader_size} is smaller than requested size_b {size_b}"
        )));
    }

    let old_peak_positions = peaks(size_a)?;
    let new_peak_positions = peaks(size_b)?;

    let mut old_peaks = Vec::new();
    let mut witness = Vec::new();

    for &p in &old_peak_positions {
        let h = reader.node(p);
        old_peaks.push(hex::encode(h));

        let containing_idx = find_containing_peak(p, &new_peak_positions)
            .ok_or_else(|| integrity(format!("old peak at position {p} not found in new MMR of size {size_b}")))?;
        let new_peak_pos = new_peak_positions[containing_idx];
        let new_peak_height = height_at(new_peak_pos);
        let path = locate_path(new_peak_pos, new_peak_height, p);

        let w: Vec<String> = path.iter().map(|s| hex::encode(reader.node(s.sibling_pos))).collect();
        witness.push(w);
    }

    let new_peaks: Vec<String> = new_peak_positions.iter().map(|&p| hex::encode(reader.node(p))).collect();

    Ok(ConsistencyProof {
        v: 1,
        kind: "consistency".to_string(),
        size_a,
        size_b,
        old_peaks,
        witness,
        new_peaks,
    })
}

/// Pure, total consistency verification. Never panics on malformed proof data.
pub fn verify_consistency(root_a: &Hash, size_a: u64, root_b: &Hash, size_b: u64, proof: &ConsistencyProof) -> bool {
    (|| -> Result<bool, ()> {
        if proof.v != 1 || proof.kind != "consistency" {
            return Ok(false);
        }
        if proof.size_a != size_a || proof.size_b != size_b {
            return Ok(false);
        }
        if size_b < size_a {
            return Ok(false);
        }

        let old_peak_positions = peaks(size_a).map_err(|_| ())?;
        let new_peak_positions = peaks(size_b).map_err(|_| ())?;

        if proof.old_peaks.len() != old_peak_positions.len() {
            return Ok(false);
        }
        if proof.new_peaks.len() != new_peak_positions.len() {
            return Ok(false);
        }
        if proof.witness.len() != old_peak_positions.len() {
            return Ok(false);
        }

        let old_peaks_bytes: Vec<Hash> = proof.old_peaks.iter().map(|w| parse_digest_hex(w)).collect::<Result<_, _>>()?;
        let new_peaks_bytes: Vec<Hash> = proof.new_peaks.iter().map(|w| parse_digest_hex(w)).collect::<Result<_, _>>()?;

        let computed_root_a = root_from_peaks(&old_peaks_bytes);
        if &computed_root_a != root_a {
            return Ok(false);
        }
        let computed_root_b = root_from_peaks(&new_peaks_bytes);
        if &computed_root_b != root_b {
            return Ok(false);
        }

        for (i, &p) in old_peak_positions.iter().enumerate() {
            let containing_idx = match find_containing_peak(p, &new_peak_positions) {
                Some(idx) => idx,
                None => return Ok(false),
            };
            let new_peak_pos = new_peak_positions[containing_idx];
            let new_peak_height = height_at(new_peak_pos);
            let path = locate_path(new_peak_pos, new_peak_height, p);

            let w = &proof.witness[i];
            if w.len() != path.len() {
                return Ok(false);
            }
            let w_bytes: Vec<Hash> = w.iter().map(|x| parse_digest_hex(x)).collect::<Result<_, _>>()?;

            let mut acc = old_peaks_bytes[i];
            for (step, sib) in path.iter().zip(w_bytes.iter()) {
                acc = if step.target_is_right {
                    interior_hash(sib, &acc, step.parent_pos)
                } else {
                    interior_hash(&acc, sib, step.parent_pos)
                };
            }
            if acc != new_peaks_bytes[containing_idx] {
                return Ok(false);
            }
        }

        Ok(true)
    })()
    .unwrap_or(false)
}
