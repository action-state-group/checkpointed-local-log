//! Runs every case in `mmr-conformance-vectors/vectors.json` and
//! `commitment-conformance-vectors/vectors.json` against this crate's MMR
//! implementation -- the shared cross-language contract (Python, Go, TS,
//! and now this crate all pass the same fixtures unchanged).

use cll::mmr::{
    add_leaf, commitment_object, consistency_proof, inclusion_proof, leaf_hash, root_from_peaks,
    verify_consistency, verify_inclusion, ConsistencyProof, Hash, InclusionProof, MemoryNodeStore,
    NodeReader,
};
use cll::range_proof::{range_proof, verify_range, RangeProof};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

fn body_digest_for_seq(seq: u64) -> Hash {
    let text = format!("asg-ledger-mmr-vector-leaf-{seq}");
    Sha256::digest(text.as_bytes()).into()
}

fn build_fixture(leaf_count: u64) -> MemoryNodeStore {
    let mut store = MemoryNodeStore::new();
    for seq in 1..=leaf_count {
        let leaf = leaf_hash(&body_digest_for_seq(seq));
        add_leaf(&mut store, leaf).unwrap();
    }
    store
}

fn hex32(s: &str) -> Hash {
    let bytes = hex::decode(s).unwrap();
    bytes.try_into().unwrap()
}

fn load_vectors(repo_relative: &str) -> Value {
    // CARGO_MANIFEST_DIR is rust/cll; the vectors live at the repo root,
    // two levels up.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join("../..").join(repo_relative);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path:?}: {e}"));
    serde_json::from_str(&text).unwrap()
}

fn inclusion_proof_from_json(p: &Value) -> InclusionProof {
    InclusionProof {
        v: p["v"].as_u64().unwrap() as u32,
        kind: p["kind"].as_str().unwrap().to_string(),
        size: p["size"].as_u64().unwrap(),
        leaf_index: p["leaf_index"].as_u64().unwrap(),
        witness: str_array(&p["witness"]),
        peaks_left: str_array(&p["peaks_left"]),
        peaks_right: str_array(&p["peaks_right"]),
    }
}

fn consistency_proof_from_json(p: &Value) -> ConsistencyProof {
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

fn range_proof_from_json(p: &Value) -> RangeProof {
    RangeProof {
        v: p["v"].as_u64().unwrap() as u32,
        kind: p["kind"].as_str().unwrap().to_string(),
        size: p["size"].as_u64().unwrap(),
        from_index: p["from_index"].as_u64().unwrap(),
        to_index: p["to_index"].as_u64().unwrap(),
        witness: str_array(&p["witness"]),
    }
}

fn str_array(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn mmr_conformance_vectors_pass() {
    let doc = load_vectors("mmr-conformance-vectors/vectors.json");
    let cases = doc["cases"].as_array().unwrap();
    let mut checked = 0usize;

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let kind = case["kind"].as_str().unwrap();
        let expect = case.get("expect").and_then(Value::as_bool).unwrap_or(true);

        match kind {
            "root" => {
                let leaf_count = case["leaf_count"].as_u64().unwrap();
                let size = case["size"].as_u64().unwrap();
                let store = build_fixture(leaf_count);
                let pks = cll::mmr::peaks(size).unwrap();
                let peak_hashes: Vec<Hash> = pks.iter().map(|&p| store.node(p)).collect();
                let root = root_from_peaks(&peak_hashes);
                let expected = hex32(case["root_hex"].as_str().unwrap());
                assert_eq!(root, expected, "case {name}: root mismatch");
            }
            "inclusion" => {
                let leaf_count = case["leaf_count"].as_u64().unwrap();
                let size = case["size"].as_u64().unwrap();
                let leaf_index = case["leaf_index"].as_u64().unwrap();
                let store = build_fixture(leaf_count);
                let root = hex32(case["root_hex"].as_str().unwrap());
                let body_digest = hex32(case["body_digest_hex"].as_str().unwrap());
                let proof = inclusion_proof_from_json(&case["proof"]);

                let ok = verify_inclusion(&root, size, leaf_index, &body_digest, &proof);
                assert_eq!(ok, expect, "case {name}: verify_inclusion mismatch");

                if expect {
                    // Self-consistency: our own producer reproduces the pinned proof.
                    let produced = inclusion_proof(&store, leaf_index, size).unwrap();
                    assert_eq!(
                        produced, proof,
                        "case {name}: inclusion_proof producer mismatch"
                    );
                }
            }
            "consistency" => {
                let leaf_count_b = case["leaf_count_b"].as_u64().unwrap();
                let size_a = case["size_a"].as_u64().unwrap();
                let size_b = case["size_b"].as_u64().unwrap();
                let store = build_fixture(leaf_count_b);
                let root_a = hex32(case["root_a_hex"].as_str().unwrap());
                let root_b = hex32(case["root_b_hex"].as_str().unwrap());
                let proof = consistency_proof_from_json(&case["proof"]);

                let ok = verify_consistency(&root_a, size_a, &root_b, size_b, &proof);
                assert_eq!(ok, expect, "case {name}: verify_consistency mismatch");

                if expect {
                    let produced = consistency_proof(&store, size_a, size_b).unwrap();
                    assert_eq!(
                        produced, proof,
                        "case {name}: consistency_proof producer mismatch"
                    );
                }
            }
            "range" => {
                let leaf_count = case["leaf_count"].as_u64().unwrap();
                let size = case["size"].as_u64().unwrap();
                let from_index = case["from_index"].as_u64().unwrap();
                let to_index = case["to_index"].as_u64().unwrap();
                let store = build_fixture(leaf_count);
                let root = hex32(case["root_hex"].as_str().unwrap());
                let body_digests: Vec<Hash> = case["body_digests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| hex32(v.as_str().unwrap()))
                    .collect();
                let proof = range_proof_from_json(&case["proof"]);

                let ok = verify_range(&root, size, from_index, to_index, &body_digests, &proof);
                assert_eq!(ok, expect, "case {name}: verify_range mismatch");

                if expect {
                    let produced = range_proof(&store, from_index, to_index, size).unwrap();
                    assert_eq!(
                        produced, proof,
                        "case {name}: range_proof producer mismatch"
                    );
                }
            }
            other => panic!("unknown vector kind {other:?} in case {name}"),
        }
        checked += 1;
    }

    let declared = doc["count"].as_u64().unwrap() as usize;
    assert_eq!(
        checked, declared,
        "vector count mismatch -- some cases were not dispatched"
    );
}

#[test]
fn commitment_conformance_vectors_pass() {
    let doc = load_vectors("commitment-conformance-vectors/vectors.json");
    let cases = doc["cases"].as_array().unwrap();

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let kind = case["kind"].as_str().unwrap();
        let peak_hashes: Vec<Hash> = case["peak_hashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| hex32(v.as_str().unwrap()))
            .collect();
        let expected_hex = case["commitment_hex"].as_str().unwrap();
        let encoded = hex::encode(commitment_object(&peak_hashes));

        match kind {
            "positive" => assert_eq!(
                encoded, expected_hex,
                "case {name}: commitment_object mismatch"
            ),
            "must-fail" => {
                // These vectors pin a byte string that a conformant
                // encoder must NEVER produce (reversed/dropped/duplicated
                // peaks, a bit-flip, or an indefinite-length encoding).
                // `commitment_object` only ever emits the canonical
                // encoding of whatever peak list it is given, so the
                // must-fail bar here is: our own encoder never happens to
                // reproduce the malformed bytes for the SAME peak list.
                assert_ne!(
                    encoded, expected_hex,
                    "case {name}: encoder must never reproduce a must-fail encoding"
                );
            }
            other => panic!("unknown commitment vector kind {other:?} in case {name}"),
        }
    }
}
