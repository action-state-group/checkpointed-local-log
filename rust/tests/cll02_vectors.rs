//! Runs `cll-02-vectors/vectors.json` (draft-mih-scitt-checkpointed-local-log-02)
//! against this crate. The log layer must match today; the wire layer is ahead
//! of the crate, so those tests pin the gap and fail the day the crate emits
//! the -02 form, at which point they become plain equality tests.

use cll::checkpoint::{checkpoint_to_cose, encode_checkpoint_claims, CheckpointRecord};
use cll::mmr::{
    add_leaf, consistency_proof, leaf_count, leaf_hash, peaks, root_from_peaks, verify_consistency,
    Hash, MemoryNodeStore, NodeReader,
};
use coset::{CoseSign1, TaggedCborSerializable};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use std::path::Path;

fn vectors() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../cll-02-vectors/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex32(s: &str) -> Hash {
    hex::decode(s).unwrap().try_into().unwrap()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

fn build(v: &Value) -> (MemoryNodeStore, Vec<u64>) {
    let mut store = MemoryNodeStore::new();
    let mut sizes = vec![0];
    for e in v["entries"].as_array().unwrap() {
        add_leaf(&mut store, leaf_hash(&hex32(e.as_str().unwrap()))).unwrap();
        sizes.push(store.size());
    }
    (store, sizes)
}

fn peak_hashes(store: &MemoryNodeStore, size: u64) -> Vec<Hash> {
    if size == 0 {
        return vec![];
    }
    peaks(size)
        .unwrap()
        .into_iter()
        .map(|p| store.node(p))
        .collect()
}

#[test]
fn log_nodes_sizes_and_accumulators_match() {
    let v = vectors();
    let (store, sizes) = build(&v);
    let nodes: Vec<String> = (0..store.size())
        .map(|i| hex::encode(store.node(i)))
        .collect();
    assert_eq!(nodes, strings(&v["nodes"]));
    for row in v["sizes"].as_array().unwrap() {
        let size = row["log_size"].as_u64().unwrap();
        let leaves = row["leaf_count"].as_u64().unwrap();
        assert_eq!(sizes[leaves as usize], size, "log_size is the node count");
        let ph = peak_hashes(&store, size);
        let got: Vec<String> = ph.iter().map(hex::encode).collect();
        assert_eq!(got, strings(&row["peaks"]));
        assert_eq!(
            hex::encode(ph.concat()),
            row["commitment"].as_str().unwrap()
        );
        if size > 0 {
            assert_eq!(leaf_count(size).unwrap(), leaves);
        }
    }
}

#[test]
fn consistency_proof_carries_the_profile_proof() {
    let v = vectors();
    let (store, _) = build(&v);
    let mut checked = 0;
    for cp in v["checkpoints"].as_array().unwrap() {
        let want = &cp["consistency_proof"];
        if want.is_null() {
            continue;
        }
        let (a, b) = (
            want["tree_size_1"].as_u64().unwrap(),
            want["tree_size_2"].as_u64().unwrap(),
        );
        let p = consistency_proof(&store, a, b).unwrap();
        let paths: Vec<Vec<String>> = want["consistency_paths"]
            .as_array()
            .unwrap()
            .iter()
            .map(strings)
            .collect();
        assert_eq!(p.witness, paths);
        let right = strings(&want["right_peaks"]);
        assert_eq!(
            p.new_peaks[p.new_peaks.len() - right.len()..].to_vec(),
            right
        );
        let old: Vec<Hash> = p.old_peaks.iter().map(|h| hex32(h)).collect();
        let new: Vec<Hash> = p.new_peaks.iter().map(|h| hex32(h)).collect();
        assert!(verify_consistency(
            &root_from_peaks(&old),
            a,
            &root_from_peaks(&new),
            b,
            &p
        ));
        checked += 1;
    }
    assert_eq!(checked, 2);
}

fn record(v: &Value, store: &MemoryNodeStore, claims: &Value) -> CheckpointRecord {
    let size = claims["log_size"].as_u64().unwrap();
    let prev = claims["prev_size"].as_u64().unwrap();
    CheckpointRecord {
        v: 1,
        kind: "mmr_checkpoint".into(),
        log_id: v["conventions"]["log_identity"]["sub"]
            .as_str()
            .unwrap()
            .into(),
        mmr_size: size,
        root: hex::encode(root_from_peaks(&peak_hashes(store, size))),
        prev_size: prev,
        prev_root: if prev == 0 {
            String::new()
        } else {
            hex::encode(root_from_peaks(&peak_hashes(store, prev)))
        },
        key_id: v["kid"].as_str().unwrap().into(),
        timestamp: claims["issued_at"].as_str().unwrap().into(),
        signature: String::new(),
        witnesses: vec![],
    }
}

#[test]
fn wire_claims_still_differ_from_02() {
    let v = vectors();
    let (store, _) = build(&v);
    for cp in v["checkpoints"].as_array().unwrap() {
        let claims = &cp["claims"];
        let rec = record(&v, &store, claims);
        let prev_peaks = peak_hashes(&store, rec.prev_size);
        let proof = (rec.prev_size > 0)
            .then(|| consistency_proof(&store, rec.prev_size, rec.mmr_size).unwrap());
        let got = encode_checkpoint_claims(
            &rec,
            &peak_hashes(&store, rec.mmr_size),
            (rec.prev_size > 0).then_some(prev_peaks.as_slice()),
            proof.as_ref(),
            claims["cadence"].as_i64(),
        )
        .unwrap();
        assert_ne!(
            hex::encode(got),
            cp["claims_hex"].as_str().unwrap(),
            "{}: the crate now emits -02 claims; make this an equality test",
            cp["id"]
        );
    }
}

#[test]
fn wire_sub_is_still_per_checkpoint() {
    let v = vectors();
    let (store, _) = build(&v);
    let cp = &v["checkpoints"][0];
    let rec = record(&v, &store, &cp["claims"]);
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let cose = checkpoint_to_cose(
        &rec,
        &key,
        &peak_hashes(&store, rec.mmr_size),
        None,
        None,
        None,
    )
    .unwrap();
    let sign1 = CoseSign1::from_tagged_slice(&cose).unwrap();
    let cwt = sign1
        .protected
        .header
        .rest
        .iter()
        .find(|(label, _)| *label == coset::Label::Int(15))
        .map(|(_, value)| value.clone())
        .unwrap();
    let sub = cwt
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_integer() == Some(2.into()))
        .map(|(_, s)| s.as_text().unwrap().to_string())
        .unwrap();
    assert_ne!(
        sub,
        v["conventions"]["log_identity"]["sub"].as_str().unwrap(),
        "the crate now sets sub to the log; make this an equality test"
    );
}
