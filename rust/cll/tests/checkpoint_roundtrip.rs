//! Round-trip tests for `checkpoint::CheckpointRecord` (JSON signing form)
//! and the COSE_Sign1 wire form, including a two-checkpoint chain bridged
//! by an MMR consistency proof.

use cll::checkpoint::{
    checkpoint_to_cose, sign_checkpoint_digest, verify_checkpoint_cose_offline, CheckpointRecord,
};
use cll::mmr::{add_leaf, consistency_proof, leaf_hash, peaks, MemoryNodeStore, NodeReader};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

fn body_digest_for_seq(seq: u64) -> [u8; 32] {
    let text = format!("asg-ledger-mmr-vector-leaf-{seq}");
    Sha256::digest(text.as_bytes()).into()
}

fn peak_hashes_at(store: &MemoryNodeStore, size: u64) -> Vec<[u8; 32]> {
    peaks(size)
        .unwrap()
        .iter()
        .map(|&p| store.node(p))
        .collect()
}

fn test_key() -> SigningKey {
    // Deterministic fixture key -- not a real credential.
    SigningKey::from_bytes(&[7u8; 32])
}

#[test]
fn json_signing_round_trip() {
    let key = test_key();
    let mut cp = CheckpointRecord {
        v: 1,
        kind: "mmr_checkpoint".to_string(),
        log_id: "test-log".to_string(),
        mmr_size: 11,
        root: "a0c0e8e7d78bf06dee4c988a228ff034dca8a25964a4af89a3d7d11670f31d10".to_string(),
        prev_size: 0,
        prev_root: String::new(),
        key_id: hex::encode(key.verifying_key().to_bytes()),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        signature: String::new(),
        witnesses: Vec::new(),
    };
    cp.signature = sign_checkpoint_digest(&cp, &key);
    assert!(cp.verify_signature_offline());

    // Tamper: flip a byte of the signature -> must fail closed.
    let mut tampered = cp.clone();
    tampered.signature = "00".to_string() + &tampered.signature[2..];
    assert!(!tampered.verify_signature_offline());

    // digest()/entry_digest() are 64-char lowercase hex.
    assert_eq!(cp.digest().len(), 64);
    assert_eq!(cp.entry_digest().len(), 64);
    assert_ne!(cp.digest(), cp.entry_digest());
}

#[test]
fn cose_wire_first_checkpoint_round_trip() {
    let key = test_key();
    let mut store = MemoryNodeStore::new();
    for seq in 1..=7u64 {
        add_leaf(&mut store, leaf_hash(&body_digest_for_seq(seq))).unwrap();
    }
    let size = store.size();
    let peak_hashes = peak_hashes_at(&store, size);
    let root = cll::mmr::root_from_peaks(&peak_hashes);

    let cp = CheckpointRecord {
        v: 1,
        kind: "mmr_checkpoint".to_string(),
        log_id: "test-log".to_string(),
        mmr_size: size,
        root: hex::encode(root),
        prev_size: 0,
        prev_root: String::new(),
        key_id: hex::encode(key.verifying_key().to_bytes()),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        signature: String::new(),
        witnesses: Vec::new(),
    };

    let cose = checkpoint_to_cose(&cp, &key, &peak_hashes, None, None, Some(900)).unwrap();
    let result = verify_checkpoint_cose_offline(&cose);
    assert!(result.ok, "verification failed: {:?}", result.errors);
    let decoded = result.decoded.unwrap();
    assert_eq!(decoded.log_id, cp.log_id);
    assert_eq!(decoded.mmr_size, cp.mmr_size);
    assert_eq!(decoded.root, cp.root);
    assert_eq!(decoded.prev_size, 0);
    assert_eq!(decoded.prev_root, "");
    assert_eq!(decoded.cadence_seconds, Some(900));
    assert!(decoded.consistency_proof.is_none());
    assert_eq!(decoded.key_id, cp.key_id);

    // Tamper: flip the last byte (part of the signature) -> must fail closed.
    let mut tampered = cose.clone();
    *tampered.last_mut().unwrap() ^= 0xff;
    let bad = verify_checkpoint_cose_offline(&tampered);
    assert!(!bad.ok);
}

#[test]
fn cose_wire_chained_checkpoint_with_consistency_proof() {
    let key = test_key();
    let mut store = MemoryNodeStore::new();
    for seq in 1..=7u64 {
        add_leaf(&mut store, leaf_hash(&body_digest_for_seq(seq))).unwrap();
    }
    let size_a = store.size();
    let peaks_a = peak_hashes_at(&store, size_a);
    let root_a = cll::mmr::root_from_peaks(&peaks_a);

    let cp_a = CheckpointRecord {
        v: 1,
        kind: "mmr_checkpoint".to_string(),
        log_id: "test-log".to_string(),
        mmr_size: size_a,
        root: hex::encode(root_a),
        prev_size: 0,
        prev_root: String::new(),
        key_id: hex::encode(key.verifying_key().to_bytes()),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        signature: String::new(),
        witnesses: Vec::new(),
    };
    let cose_a = checkpoint_to_cose(&cp_a, &key, &peaks_a, None, None, None).unwrap();
    assert!(verify_checkpoint_cose_offline(&cose_a).ok);

    // Extend the log and build a second, chained checkpoint.
    for seq in 8..=12u64 {
        add_leaf(&mut store, leaf_hash(&body_digest_for_seq(seq))).unwrap();
    }
    let size_b = store.size();
    let peaks_b = peak_hashes_at(&store, size_b);
    let root_b = cll::mmr::root_from_peaks(&peaks_b);
    let proof = consistency_proof(&store, size_a, size_b).unwrap();

    let cp_b = CheckpointRecord {
        v: 1,
        kind: "mmr_checkpoint".to_string(),
        log_id: "test-log".to_string(),
        mmr_size: size_b,
        root: hex::encode(root_b),
        prev_size: size_a,
        prev_root: hex::encode(root_a),
        key_id: hex::encode(key.verifying_key().to_bytes()),
        timestamp: "2026-01-01T00:05:00Z".to_string(),
        signature: String::new(),
        witnesses: Vec::new(),
    };
    let cose_b =
        checkpoint_to_cose(&cp_b, &key, &peaks_b, Some(&peaks_a), Some(&proof), None).unwrap();
    let result = verify_checkpoint_cose_offline(&cose_b);
    assert!(
        result.ok,
        "chained verification failed: {:?}",
        result.errors
    );
    let decoded = result.decoded.unwrap();
    assert_eq!(decoded.prev_size, size_a);
    assert_eq!(decoded.prev_root, hex::encode(root_a));
    assert!(decoded.consistency_proof.is_some());

    // A checkpoint claiming continuity (prev_size > 0) with NO consistency
    // proof attached must be refused at encode time.
    let err = checkpoint_to_cose(&cp_b, &key, &peaks_b, Some(&peaks_a), None, None);
    assert!(err.is_err());
}
