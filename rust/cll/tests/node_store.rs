//! `FileNodeStore` durability: proves the file-backed `NodeReader +
//! NodeAppender` produces byte-identical nodes/roots/proofs to
//! `MemoryNodeStore` over the same leaves, survives a torn trailing record,
//! and can rebuild itself from the ledger's own leaf digests.

use cll::mmr::{
    add_leaf, consistency_proof, inclusion_proof, leaf_hash, node_count, peaks, root_from_peaks,
    Hash, MemoryNodeStore, NodeReader,
};
use cll::node_store::FileNodeStore;
use std::io::Write;
use tempfile::tempdir;

fn body_digest_for_seq(seq: u64) -> Hash {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&seq.to_be_bytes());
    h
}

/// Feed `leaf_count` leaves into both a `MemoryNodeStore` and a
/// `FileNodeStore` (backed by a fresh temp file), asserting every node
/// position matches after every single append -- not just at the end, so a
/// divergence introduced partway through (e.g. an off-by-one in the file
/// offset math) cannot hide behind a final-state-only comparison.
#[test]
fn file_store_matches_memory_store_node_for_node_over_10k_leaves() {
    const LEAF_COUNT: u64 = 10_000;

    let dir = tempdir().unwrap();
    let path = dir.path().join("nodes.bin");
    let (mut file_store, report) = FileNodeStore::open(&path).unwrap();
    assert_eq!(report.node_count, 0);
    assert_eq!(report.truncated_bytes, 0);

    let mut mem_store = MemoryNodeStore::new();

    for seq in 0..LEAF_COUNT {
        let leaf = leaf_hash(&body_digest_for_seq(seq));
        let (mem_pos, mem_new) = add_leaf(&mut mem_store, leaf).unwrap();
        let (file_pos, file_new) = add_leaf(&mut file_store, leaf).unwrap();
        assert_eq!(mem_pos, file_pos);
        assert_eq!(mem_new, file_new);
        assert_eq!(mem_store.size(), file_store.size());
    }

    assert_eq!(mem_store.size(), file_store.size());
    for pos in 0..mem_store.size() {
        assert_eq!(
            mem_store.node(pos),
            file_store.node(pos),
            "node mismatch at position {pos}"
        );
    }

    // Roots and proofs computed at several (valid) MMR sizes must also be
    // byte-identical -- not just the raw node bytes, since a proof also
    // depends on how `peaks`/`locate_path` walk the reader. `node_count(k)`
    // is the MMR size after exactly `k` leaves -- an arbitrary integer is
    // not generally a valid MMR size.
    for &leaf_count in &[1u64, 7, 100, 4_096, 9_999, LEAF_COUNT] {
        let size = node_count(leaf_count);
        let mem_peaks: Vec<Hash> = peaks(size)
            .unwrap()
            .iter()
            .map(|&p| mem_store.node(p))
            .collect();
        let file_peaks: Vec<Hash> = peaks(size)
            .unwrap()
            .iter()
            .map(|&p| file_store.node(p))
            .collect();
        assert_eq!(mem_peaks, file_peaks, "peak mismatch at size {size}");
        assert_eq!(
            root_from_peaks(&mem_peaks),
            root_from_peaks(&file_peaks),
            "root mismatch at size {size}"
        );

        let leaf_index = leaf_count / 2;
        let mem_proof = inclusion_proof(&mem_store, leaf_index, size).unwrap();
        let file_proof = inclusion_proof(&file_store, leaf_index, size).unwrap();
        assert_eq!(
            mem_proof, file_proof,
            "inclusion proof mismatch at size {size}"
        );
    }

    let size_100 = node_count(100);
    let cons_mem = consistency_proof(&mem_store, size_100, mem_store.size()).unwrap();
    let cons_file = consistency_proof(&file_store, size_100, file_store.size()).unwrap();
    assert_eq!(cons_mem, cons_file);
}

#[test]
fn reopen_preserves_size_and_node_values() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nodes.bin");

    {
        let (mut store, _) = FileNodeStore::open(&path).unwrap();
        for seq in 0..50u64 {
            add_leaf(&mut store, leaf_hash(&body_digest_for_seq(seq))).unwrap();
        }
    }

    let (reopened, report) = FileNodeStore::open(&path).unwrap();
    assert_eq!(report.truncated_bytes, 0);
    let mut mem_store = MemoryNodeStore::new();
    for seq in 0..50u64 {
        add_leaf(&mut mem_store, leaf_hash(&body_digest_for_seq(seq))).unwrap();
    }
    assert_eq!(reopened.size(), mem_store.size());
    for pos in 0..mem_store.size() {
        assert_eq!(reopened.node(pos), mem_store.node(pos));
    }
}

/// A crash between `write` and `fsync` on the LAST record leaves a file
/// whose length is not a multiple of 32 bytes -- `open` must truncate that
/// torn tail away and report exactly how much it discarded, never treat it
/// as a valid node.
#[test]
fn torn_trailing_record_is_truncated_and_reported() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nodes.bin");

    {
        let (mut store, _) = FileNodeStore::open(&path).unwrap();
        for seq in 0..5u64 {
            add_leaf(&mut store, leaf_hash(&body_digest_for_seq(seq))).unwrap();
        }
    }
    let good_len = std::fs::metadata(&path).unwrap().len();
    assert_eq!(good_len % 32, 0);

    // Simulate a torn write: append 17 garbage bytes (less than one record).
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(&[0xffu8; 17]).unwrap();
    }

    let (store, report) = FileNodeStore::open(&path).unwrap();
    assert_eq!(report.truncated_bytes, 17);
    assert_eq!(report.node_count, good_len / 32);
    assert_eq!(store.size(), good_len / 32);

    let on_disk_len = std::fs::metadata(&path).unwrap().len();
    assert_eq!(
        on_disk_len, good_len,
        "torn tail must be truncated on disk, not just in memory"
    );
}

#[test]
fn rebuild_from_leaves_matches_incrementally_built_store() {
    let leaves: Vec<Hash> = (0..2_000u64)
        .map(|seq| leaf_hash(&body_digest_for_seq(seq)))
        .collect();

    let mut incremental = MemoryNodeStore::new();
    for &leaf in &leaves {
        add_leaf(&mut incremental, leaf).unwrap();
    }

    let dir = tempdir().unwrap();
    let path = dir.path().join("rebuilt.bin");
    let rebuilt = FileNodeStore::rebuild_from_leaves(&path, leaves.iter().copied()).unwrap();

    assert_eq!(rebuilt.size(), incremental.size());
    for pos in 0..incremental.size() {
        assert_eq!(rebuilt.node(pos), incremental.node(pos));
    }
}

#[test]
fn rebuild_from_leaves_overwrites_an_existing_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nodes.bin");

    {
        let (mut store, _) = FileNodeStore::open(&path).unwrap();
        for seq in 0..30u64 {
            add_leaf(&mut store, leaf_hash(&body_digest_for_seq(seq))).unwrap();
        }
    }

    let fresh_leaves: Vec<Hash> = (0..10u64)
        .map(|seq| leaf_hash(&body_digest_for_seq(seq)))
        .collect();
    let rebuilt = FileNodeStore::rebuild_from_leaves(&path, fresh_leaves.iter().copied()).unwrap();
    assert_eq!(rebuilt.size(), node_count(10));

    let (reopened, _) = FileNodeStore::open(&path).unwrap();
    assert_eq!(reopened.size(), rebuilt.size());
}
