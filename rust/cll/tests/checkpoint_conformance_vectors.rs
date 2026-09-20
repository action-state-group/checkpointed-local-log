//! Runs every case in `checkpoint-conformance-vectors/vectors.json` against
//! this crate's checkpoint implementation -- the cross-language contract:
//! the Python reference (`cll.checkpoint.emit.CheckpointRecord`) generated
//! these vectors, Ed25519 signing is fully deterministic (RFC 8032), and
//! this test demands this crate reproduce the pinned `digest`/
//! `entry_digest`/`signature` byte-for-byte from nothing but the vector's
//! plaintext fields -- proof this crate and the Python reference are two
//! implementations of one spec, not two independent guesses at one.
//!
//! The chained case additionally round-trips through the COSE_Sign1 wire
//! form and `verify_checkpoint_cose_offline` (the same self-contained check
//! a stranger holding only checkpoint bytes performs), confirming the wire
//! layer built on top of this record shape verifies for a checkpoint whose
//! JSON form was pinned by the Python reference.

use cll::checkpoint::{checkpoint_to_cose, verify_checkpoint_cose_offline, CheckpointRecord};
use cll::mmr::{consistency_proof, ConsistencyProof, Hash};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

fn load_vectors() -> Value {
    // CARGO_MANIFEST_DIR is rust/cll; the vectors live at the repo root,
    // two levels up.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir
        .join("../..")
        .join("checkpoint-conformance-vectors/vectors.json");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
    serde_json::from_str(&text).unwrap()
}

fn hex32(s: &str) -> Hash {
    let bytes = hex::decode(s).unwrap();
    bytes.try_into().unwrap()
}

fn checkpoint_from_case(case: &Value, signature: String) -> CheckpointRecord {
    CheckpointRecord {
        v: case["v"].as_u64().unwrap() as u32,
        kind: case["kind"].as_str().unwrap().to_string(),
        log_id: case["log_id"].as_str().unwrap().to_string(),
        mmr_size: case["mmr_size"].as_u64().unwrap(),
        root: case["root"].as_str().unwrap().to_string(),
        prev_size: case["prev_size"].as_u64().unwrap(),
        prev_root: case["prev_root"].as_str().unwrap().to_string(),
        key_id: case["key_id"].as_str().unwrap().to_string(),
        timestamp: case["timestamp"].as_str().unwrap().to_string(),
        signature,
        witnesses: Vec::new(),
    }
}

fn consistency_proof_from_json(p: &Value) -> ConsistencyProof {
    let str_array = |v: &Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
    };
    ConsistencyProof {
        v: p["v"].as_u64().unwrap() as u32,
        kind: p["kind"].as_str().unwrap().to_string(),
        size_a: p["size_a"].as_u64().unwrap(),
        size_b: p["size_b"].as_u64().unwrap(),
        old_peaks: str_array(&p["old_peaks"]),
        witness: p["witness"]
            .as_array()
            .unwrap()
            .iter()
            .map(str_array)
            .collect(),
        new_peaks: str_array(&p["new_peaks"]),
    }
}

#[test]
fn checkpoint_conformance_vectors_pass() {
    let doc = load_vectors();
    let seed = hex32(doc["signing_key_seed_hex"].as_str().unwrap());
    let signing_key = SigningKey::from_bytes(&seed);
    assert_eq!(
        hex::encode(signing_key.verifying_key().to_bytes()),
        doc["key_id"].as_str().unwrap(),
        "derived key_id does not match the vector's pinned key_id"
    );

    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), doc["count"].as_u64().unwrap() as usize);

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let signature = case["signature"].as_str().unwrap().to_string();
        let cp = checkpoint_from_case(case, signature.clone());

        let digest = cp.digest();
        assert_eq!(
            digest,
            case["digest_hex"].as_str().unwrap(),
            "case {name}: digest mismatch"
        );

        // Ed25519 is deterministic (RFC 8032): re-signing the SAME digest
        // with the SAME seed must reproduce the pinned signature exactly --
        // this is the actual cross-language pin, not merely a round-trip.
        let resigned = hex::encode(signing_key.sign(digest.as_bytes()).to_bytes());
        assert_eq!(
            resigned, signature,
            "case {name}: re-signed signature does not match the pinned Python-produced signature"
        );

        assert!(
            cp.verify_signature_offline(),
            "case {name}: verify_signature_offline rejected the pinned signature"
        );

        let entry_digest = cp.entry_digest();
        assert_eq!(
            entry_digest,
            case["entry_digest_hex"].as_str().unwrap(),
            "case {name}: entry_digest mismatch"
        );
    }
}

#[test]
fn checkpoint_conformance_chained_case_verifies_over_cose_wire() {
    let doc = load_vectors();
    let seed = hex32(doc["signing_key_seed_hex"].as_str().unwrap());
    let signing_key = SigningKey::from_bytes(&seed);

    let cases = doc["cases"].as_array().unwrap();
    let case_a = cases
        .iter()
        .find(|c| c["name"] == "checkpoint-first-2-leaves")
        .unwrap();
    let case_b = cases
        .iter()
        .find(|c| c["name"] == "checkpoint-chained-2-to-7-leaves")
        .unwrap();

    let cp_a = checkpoint_from_case(case_a, case_a["signature"].as_str().unwrap().to_string());
    let cp_b = checkpoint_from_case(case_b, case_b["signature"].as_str().unwrap().to_string());
    let consistency = consistency_proof_from_json(&case_b["consistency_proof"]);

    // Rebuild the peak hashes at size_a/size_b via the SAME 7-leaf fixture
    // the MMR conformance vectors pin (asg-ledger-mmr-vector-leaf-{seq}),
    // then independently confirm the pinned consistency proof still
    // verifies (self-consistency: this crate's own reader reproduces it).
    let mut store = cll::mmr::MemoryNodeStore::new();
    for seq in 1..=7u64 {
        let text = format!("asg-ledger-mmr-vector-leaf-{seq}");
        let body_digest: Hash = Sha256::digest(text.as_bytes()).into();
        cll::mmr::add_leaf(&mut store, cll::mmr::leaf_hash(&body_digest)).unwrap();
    }
    let node = |pos: u64| cll::mmr::NodeReader::node(&store, pos);
    let peaks_a: Vec<Hash> = cll::mmr::peaks(cp_a.mmr_size)
        .unwrap()
        .iter()
        .map(|&p| node(p))
        .collect();
    let peaks_b: Vec<Hash> = cll::mmr::peaks(cp_b.mmr_size)
        .unwrap()
        .iter()
        .map(|&p| node(p))
        .collect();
    let produced_consistency = consistency_proof(&store, cp_a.mmr_size, cp_b.mmr_size).unwrap();
    assert_eq!(
        produced_consistency, consistency,
        "produced consistency proof does not match the pinned vector"
    );

    let cose = checkpoint_to_cose(
        &cp_b,
        &signing_key,
        &peaks_b,
        Some(&peaks_a),
        Some(&consistency),
        None,
    )
    .unwrap();
    let result = verify_checkpoint_cose_offline(&cose);
    assert!(
        result.ok,
        "COSE verification of the pinned chained checkpoint failed: {:?}",
        result.errors
    );
    let decoded = result.decoded.unwrap();
    assert_eq!(decoded.log_id, cp_b.log_id);
    assert_eq!(decoded.mmr_size, cp_b.mmr_size);
    assert_eq!(decoded.root, cp_b.root);
    assert_eq!(decoded.prev_size, cp_b.prev_size);
    assert_eq!(decoded.prev_root, cp_b.prev_root);
}
