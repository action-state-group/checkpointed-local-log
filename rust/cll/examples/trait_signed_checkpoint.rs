//! Emits one checkpoint's COSE_Sign1 statement (hex on stdout), signed via
//! the `checkpoint::CheckpointSigner` trait rather than a direct
//! `ed25519_dalek::SigningKey` call -- the cross-language half of the
//! signer-SPI acceptance check: `checkpoint-conformance-vectors/
//! verify_trait_signed_cose.py` verifies this output with the Python
//! reference, proving the trait indirection changed nothing about the wire
//! bytes a stranger checks.
//!
//! Run: `cargo run --quiet --example trait_signed_checkpoint`.

use cll::checkpoint::{checkpoint_to_cose, CheckpointRecord, CheckpointSigner};
use cll::mmr::{add_leaf, leaf_hash, peaks, root_from_peaks, MemoryNodeStore, NodeReader};
use ed25519_dalek::SigningKey;

fn body_digest_for_seq(seq: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&seq.to_be_bytes());
    h
}

fn main() {
    // Deterministic fixture key -- not a real credential.
    let signer = SigningKey::from_bytes(&[42u8; 32]);

    let mut store = MemoryNodeStore::new();
    for seq in 0..5u64 {
        add_leaf(&mut store, leaf_hash(&body_digest_for_seq(seq))).unwrap();
    }
    let size = store.size();
    let peak_hashes: Vec<[u8; 32]> = peaks(size)
        .unwrap()
        .iter()
        .map(|&p| store.node(p))
        .collect();
    let root = root_from_peaks(&peak_hashes);

    let cp = CheckpointRecord {
        v: 1,
        kind: "mmr_checkpoint".to_string(),
        log_id: "trait-signed-cross-language-check".to_string(),
        mmr_size: size,
        root: hex::encode(root),
        prev_size: 0,
        prev_root: String::new(),
        // `CheckpointSigner::key_id` (not `SigningKey`'s own inherent API)
        // -- the same call site a non-dalek signer would use.
        key_id: CheckpointSigner::key_id(&signer),
        timestamp: "2026-09-22T00:00:00Z".to_string(),
        signature: String::new(),
        witnesses: Vec::new(),
    };

    // `&signer` (a `&SigningKey`) coerces to `&dyn CheckpointSigner` here --
    // the exact back-compat path this crate's signer SPI relies on.
    let cose = checkpoint_to_cose(&cp, &signer, &peak_hashes, None, None, None)
        .expect("checkpoint_to_cose failed");
    println!("{}", hex::encode(cose));
}
