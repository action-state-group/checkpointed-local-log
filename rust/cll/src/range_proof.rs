//! Per-record range membership proof (CLL #13, shipped in the Python
//! reference's 0.4.0) -- byte-for-byte port of `cll.checkpoint.core`'s
//! range section.
//!
//! Replaces the earlier two-boundary design (a pair of `InclusionProof`s
//! for the endpoints only): that shape proves the two endpoints are
//! genuine leaves of a structurally-complete MMR, but never touches any
//! leaf strictly between them, so an interior leaf that has been deleted
//! or replaced is never checked -- the proof still verifies. This shape
//! makes every leaf in the range participate in the hash chain that
//! produces the root: the caller supplies every leaf's own body digest,
//! `range_proof` supplies only the O(log size) sibling hashes those
//! leaves cannot derive on their own, and `verify_range` rebuilds every
//! peak the range touches.

use crate::mmr::{
    height_at, integrity, interior_hash, invalid, leaf_count, leaf_hash, parse_digest_hex, peaks, root_from_peaks,
    Hash, MmrError, NodeReader, MAX_MMR_SIZE,
};
use std::collections::HashMap;

fn range_witnesses(reader: &impl NodeReader, pos: u64, height: u32, leaf_start: u64, lo: u64, hi: u64, out: &mut Vec<Hash>) {
    let leaf_end = leaf_start + (1u64 << height) - 1;
    if leaf_end < lo || leaf_start > hi {
        out.push(reader.node(pos));
        return;
    }
    if leaf_start >= lo && leaf_end <= hi {
        return;
    }
    let half = 1u64 << (height - 1);
    range_witnesses(reader, pos - (1u64 << height), height - 1, leaf_start, lo, hi, out);
    range_witnesses(reader, pos - 1, height - 1, leaf_start + half, lo, hi, out);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeProof {
    pub v: u32,
    pub kind: String,
    pub size: u64,
    pub from_index: u64,
    pub to_index: u64,
    pub witness: Vec<String>,
}

/// Range proof for leaf indices [from_index, to_index] (0-indexed,
/// inclusive) against the MMR of `size` nodes.
pub fn range_proof(reader: &impl NodeReader, from_index: u64, to_index: u64, size: u64) -> Result<RangeProof, MmrError> {
    if to_index < from_index {
        return Err(invalid(format!("invalid range [{from_index}, {to_index}]")));
    }
    let lc = leaf_count(size)?;
    if to_index >= lc {
        return Err(invalid(format!("to_index {to_index} out of range for size {size} ({lc} leaves)")));
    }
    let reader_size = reader.size();
    if reader_size < size {
        return Err(integrity(format!(
            "reader size {reader_size} is smaller than requested size {size}"
        )));
    }

    let pks = peaks(size)?;
    let mut out = Vec::new();
    let mut leaf_start = 0u64;
    for &p in &pks {
        let h = height_at(p);
        range_witnesses(reader, p, h, leaf_start, from_index, to_index, &mut out);
        leaf_start += 1u64 << h;
    }

    Ok(RangeProof {
        v: 1,
        kind: "range".to_string(),
        size,
        from_index,
        to_index,
        witness: out.iter().map(hex::encode).collect(),
    })
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_range_subtree(
    pos: u64,
    height: u32,
    leaf_start: u64,
    lo: u64,
    hi: u64,
    body_digests: &HashMap<u64, Hash>,
    witness_bytes: &[Hash],
    cursor: &mut usize,
) -> Result<Hash, ()> {
    let leaf_end = leaf_start + (1u64 << height) - 1;
    if leaf_end < lo || leaf_start > hi {
        if *cursor >= witness_bytes.len() {
            return Err(());
        }
        let w = witness_bytes[*cursor];
        *cursor += 1;
        return Ok(w);
    }
    if height == 0 {
        return body_digests.get(&leaf_start).map(leaf_hash).ok_or(());
    }
    let half = 1u64 << (height - 1);
    let left = reconstruct_range_subtree(pos - (1u64 << height), height - 1, leaf_start, lo, hi, body_digests, witness_bytes, cursor)?;
    let right = reconstruct_range_subtree(pos - 1, height - 1, leaf_start + half, lo, hi, body_digests, witness_bytes, cursor)?;
    Ok(interior_hash(&left, &right, pos))
}

/// Pure, total range verification. Rebuilds every peak the range touches
/// from `body_digests` (one per leaf, `body_digests[i]` for leaf index
/// `from_index + i`) folded with `proof`'s witness hashes -- an altered,
/// deleted, or replaced interior leaf changes the peak it falls under and
/// is caught here, unlike a two-boundary inclusion check that never looks
/// at any leaf strictly between the two endpoints.
pub fn verify_range(root: &Hash, size: u64, from_index: u64, to_index: u64, body_digests: &[Hash], proof: &RangeProof) -> bool {
    (|| -> Result<bool, ()> {
        if proof.v != 1 || proof.kind != "range" {
            return Ok(false);
        }
        if proof.size != size || proof.from_index != from_index || proof.to_index != to_index {
            return Ok(false);
        }
        if size >= MAX_MMR_SIZE || to_index < from_index {
            return Ok(false);
        }
        if body_digests.len() as u64 != to_index - from_index + 1 {
            return Ok(false);
        }

        let lc = leaf_count(size).map_err(|_| ())?;
        if to_index >= lc {
            return Ok(false);
        }

        let digest_by_index: HashMap<u64, Hash> =
            body_digests.iter().enumerate().map(|(i, d)| (from_index + i as u64, *d)).collect();

        let witness_bytes: Vec<Hash> = proof.witness.iter().map(|w| parse_digest_hex(w)).collect::<Result<_, _>>()?;

        let pks = peaks(size).map_err(|_| ())?;
        let mut cursor = 0usize;
        let mut leaf_start = 0u64;
        let mut reconstructed_peaks = Vec::new();
        for &p in &pks {
            let h = height_at(p);
            reconstructed_peaks.push(reconstruct_range_subtree(
                p,
                h,
                leaf_start,
                from_index,
                to_index,
                &digest_by_index,
                &witness_bytes,
                &mut cursor,
            )?);
            leaf_start += 1u64 << h;
        }

        if cursor != witness_bytes.len() {
            return Ok(false); // unconsumed witnesses -- malformed/oversized proof
        }

        let computed_root = root_from_peaks(&reconstructed_peaks);
        Ok(&computed_root == root)
    })()
    .unwrap_or(false)
}
