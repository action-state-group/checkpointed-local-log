//! `cut_checkpoint`: the one implementation of the checkpoint cut, over any
//! node store.

use cll::checkpoint::{
    checkpoint_to_cose, cut_checkpoint, try_sign_checkpoint_digest, verify_checkpoint_cose_offline,
    CheckpointRecord,
};
use cll::mmr::{
    add_leaf, consistency_proof, leaf_hash, node_count, peaks, root_from_peaks, Hash,
    MemoryNodeStore, NodeReader,
};
use ed25519_dalek::SigningKey;

fn store(leaves: u64) -> MemoryNodeStore {
    let mut nodes = MemoryNodeStore::default();
    for i in 0..leaves {
        add_leaf(&mut nodes, leaf_hash(&[i as u8; 32])).unwrap();
    }
    nodes
}

fn peak_hashes(nodes: &MemoryNodeStore, size: u64) -> Vec<Hash> {
    peaks(size)
        .unwrap()
        .into_iter()
        .map(|p| nodes.node(p))
        .collect()
}

/// The cut is the record and statement built by hand from the same parts,
/// byte for byte, and the statement verifies offline.
#[test]
fn the_cut_is_the_record_and_statement_built_from_its_parts() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let nodes = store(7);
    let (size, prev) = (node_count(7), node_count(3));
    let cut = cut_checkpoint(&nodes, size, prev, "log-a", "2026-11-25T00:00:00Z", &key).unwrap();
    let want = CheckpointRecord {
        v: 1,
        kind: "mmr_checkpoint".into(),
        log_id: "log-a".into(),
        mmr_size: size,
        root: hex::encode(root_from_peaks(&peak_hashes(&nodes, size))),
        prev_size: prev,
        prev_root: hex::encode(root_from_peaks(&peak_hashes(&nodes, prev))),
        key_id: hex::encode(key.verifying_key().to_bytes()),
        timestamp: "2026-11-25T00:00:00Z".into(),
        signature: String::new(),
        witnesses: Vec::new(),
    };
    assert_eq!(cut.record, want);
    let statement = checkpoint_to_cose(
        &want,
        &key,
        &peak_hashes(&nodes, size),
        Some(&peak_hashes(&nodes, prev)),
        Some(&consistency_proof(&nodes, prev, size).unwrap()),
        None,
    )
    .unwrap();
    assert_eq!(cut.statement.as_ref().unwrap(), &statement);
    assert!(verify_checkpoint_cose_offline(&statement).ok);
    // A caller that keeps the JSON record signs it itself.
    assert!(!try_sign_checkpoint_digest(&cut.record, &key)
        .unwrap()
        .is_empty());
}

/// The first checkpoint extends nothing; a size the store does not hold and
/// a previous size past the new one are refused.
#[test]
fn the_cut_refuses_sizes_it_cannot_prove() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let nodes = store(3);
    let first = cut_checkpoint(
        &nodes,
        node_count(3),
        0,
        "log-a",
        "2026-11-25T00:00:00Z",
        &key,
    )
    .unwrap();
    assert_eq!(
        (first.record.prev_size, first.record.prev_root.as_str()),
        (0, "")
    );
    assert!(first.statement.is_ok());
    assert!(cut_checkpoint(&nodes, node_count(4), 0, "l", "2026-11-25T00:00:00Z", &key).is_err());
    assert!(cut_checkpoint(
        &nodes,
        node_count(2),
        node_count(3),
        "l",
        "2026-11-25T00:00:00Z",
        &key
    )
    .is_err());
    assert!(cut_checkpoint(&nodes, 2, 0, "l", "2026-11-25T00:00:00Z", &key).is_err());
    // Re-cutting at the same size is the cut's to make; whether a store
    // allows a checkpoint that does not grow is the store's rule.
    let same = cut_checkpoint(
        &nodes,
        node_count(3),
        node_count(3),
        "l",
        "2026-11-25T00:00:00Z",
        &key,
    )
    .unwrap();
    assert_eq!(same.record.prev_root, same.record.root);
}
