//! Runs `checkpoint-conformance-vectors/cose-vectors.json` against this
//! crate's COSE wire form. Each case pins, for one `vectors.json` checkpoint
//! signed with that file's fixture seed:
//!
//! - `claims_hex`: the signed claims payload, a CBOR map in RFC 8949 §4.2.1
//!   deterministic order. This crate must produce exactly these bytes
//!   (before 0.2.1 it wrote the map in insertion order, which verifiers that
//!   require deterministic encoding refuse).
//! - `cose_hex`: the Python reference's whole statement, which this crate
//!   must verify. The protected header is not pinned across producers (its
//!   map order is each COSE library's own), so this crate's own statement is
//!   checked by verifying it and by its payload, not against `cose_hex`.

use cll::checkpoint::{
    checkpoint_to_cose, encode_checkpoint_claims, verify_checkpoint_cose_offline, CheckpointRecord,
};
use cll::mmr::{ConsistencyProof, Hash, MemoryNodeStore, NodeReader};
use coset::{CoseSign1, TaggedCborSerializable};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

fn load(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../checkpoint-conformance-vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

fn record(case: &Value) -> CheckpointRecord {
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
        signature: case["signature"].as_str().unwrap().to_string(),
        witnesses: Vec::new(),
    }
}

fn consistency(case: &Value) -> Option<ConsistencyProof> {
    let p = case.get("consistency_proof")?;
    Some(ConsistencyProof {
        v: p["v"].as_u64().unwrap() as u32,
        kind: p["kind"].as_str().unwrap().to_string(),
        size_a: p["size_a"].as_u64().unwrap(),
        size_b: p["size_b"].as_u64().unwrap(),
        old_peaks: strings(&p["old_peaks"]),
        witness: p["witness"]
            .as_array()
            .unwrap()
            .iter()
            .map(strings)
            .collect(),
        new_peaks: strings(&p["new_peaks"]),
    })
}

/// The 7-leaf fixture MMR the checkpoint vectors commit to.
fn fixture_store() -> MemoryNodeStore {
    let mut store = MemoryNodeStore::new();
    for seq in 1..=7u64 {
        let digest: Hash =
            Sha256::digest(format!("asg-ledger-mmr-vector-leaf-{seq}").as_bytes()).into();
        cll::mmr::add_leaf(&mut store, cll::mmr::leaf_hash(&digest)).unwrap();
    }
    store
}

fn peak_hashes(store: &MemoryNodeStore, size: u64) -> Vec<Hash> {
    cll::mmr::peaks(size)
        .unwrap()
        .iter()
        .map(|&p| store.node(p))
        .collect()
}

#[test]
fn cose_checkpoint_vectors_pass() {
    let doc = load("vectors.json");
    let pinned = load("cose-vectors.json");
    let seed: Hash = hex::decode(doc["signing_key_seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signing_key = SigningKey::from_bytes(&seed);
    let store = fixture_store();
    let cases = doc["cases"].as_array().unwrap();

    let vectors = pinned["cases"].as_array().unwrap();
    assert_eq!(vectors.len(), 2);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let case = cases
            .iter()
            .find(|c| c["name"] == vector["checkpoint_case"])
            .unwrap();
        let cp = record(case);
        let proof = consistency(case);
        let new_peaks = peak_hashes(&store, cp.mmr_size);
        let prev_peaks = (cp.prev_size > 0).then(|| peak_hashes(&store, cp.prev_size));

        // The signed payload: byte-identical to every other producer's.
        let claims =
            encode_checkpoint_claims(&cp, &new_peaks, prev_peaks.as_deref(), proof.as_ref(), None)
                .unwrap();
        assert_eq!(
            hex::encode(&claims),
            vector["claims_hex"].as_str().unwrap(),
            "{name}: claims payload is not the pinned deterministic encoding"
        );

        // The reference statement verifies here.
        let reference = hex::decode(vector["cose_hex"].as_str().unwrap()).unwrap();
        let result = verify_checkpoint_cose_offline(&reference);
        assert!(
            result.ok,
            "{name}: pinned statement rejected: {:?}",
            result.errors
        );
        let decoded = result.decoded.unwrap();
        assert_eq!(decoded.root, cp.root);
        assert_eq!(decoded.mmr_size, cp.mmr_size);
        assert_eq!(decoded.log_id, cp.log_id);

        // This crate's own statement verifies and carries exactly those claims.
        let own = checkpoint_to_cose(
            &cp,
            &signing_key,
            &new_peaks,
            prev_peaks.as_deref(),
            proof.as_ref(),
            None,
        )
        .unwrap();
        assert!(
            verify_checkpoint_cose_offline(&own).ok,
            "{name}: own statement rejected"
        );
        let payload = CoseSign1::from_tagged_slice(&own).unwrap().payload.unwrap();
        assert_eq!(payload, claims, "{name}: own statement signs other claims");
    }
}
