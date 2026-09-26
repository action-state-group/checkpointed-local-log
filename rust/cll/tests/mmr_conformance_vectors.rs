//! Runs every case in `mmr-conformance-vectors/vectors.json` and
//! `commitment-conformance-vectors/vectors.json` against this crate's MMR
//! implementation -- the shared cross-language contract (Python, Go, TS,
//! and now this crate all pass the same fixtures unchanged).

use cll::mmr::{
    add_leaf, commitment_object, consistency_proof, decode_commitment_object, inclusion_proof,
    leaf_hash, root_from_peaks, verify_commitment_object, verify_consistency, verify_inclusion,
    ConsistencyProof, Hash, InclusionProof, MemoryNodeStore, NodeReader,
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
            "positive" => {
                assert_eq!(
                    encoded, expected_hex,
                    "case {name}: commitment_object mismatch"
                );
                let candidate = hex::decode(expected_hex).unwrap();
                verify_commitment_object(&candidate, &peak_hashes).unwrap_or_else(|e| {
                    panic!("case {name}: verifier rejected a positive vector: {e}")
                });
            }
            "must-fail" => {
                // These vectors pin a byte string a conformant encoder
                // must never produce (reversed/dropped/duplicated peaks,
                // a bit-flip, or an indefinite-length encoding), paired
                // with the SAME true peak list. The must-fail bar is that
                // the VERIFIER actively rejects the pinned bytes against
                // that true peak list with a typed error -- not merely
                // that our own encoder doesn't happen to reproduce the
                // corrupted bytes (that would only prove the encoder is
                // deterministic, not that a decoder catches tampering).
                let candidate = hex::decode(expected_hex).unwrap();
                let result = verify_commitment_object(&candidate, &peak_hashes);
                assert!(
                    result.is_err(),
                    "case {name}: verifier accepted a must-fail commitment encoding"
                );
            }
            other => panic!("unknown commitment vector kind {other:?} in case {name}"),
        }
    }
}

#[test]
fn commitment_object_verifier_rejects_a_tampered_peak_byte() {
    // This crate's OWN conformant encoding of a real peak list, with a
    // single bit flipped in one peak hash, must be REJECTED by
    // `verify_commitment_object` -- mirrors the tampered-signature pattern
    // in `checkpoint_roundtrip.rs`. Mutant: drop the content comparison in
    // `verify_commitment_object` (accept on structural decode alone) and
    // this test goes red.
    let doc = load_vectors("commitment-conformance-vectors/vectors.json");
    let case = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == "positive" && c["peak_hashes"].as_array().unwrap().len() > 1)
        .expect("fixture must contain a multi-peak positive case");
    let peak_hashes: Vec<Hash> = case["peak_hashes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| hex32(v.as_str().unwrap()))
        .collect();

    let mut bytes = commitment_object(&peak_hashes);
    verify_commitment_object(&bytes, &peak_hashes).expect("untampered encoding must verify");

    *bytes.last_mut().unwrap() ^= 0x01;
    let result = verify_commitment_object(&bytes, &peak_hashes);
    assert!(
        result.is_err(),
        "verifier must reject a commitment object with a tampered peak byte"
    );
}

#[test]
fn commitment_object_decoder_rejects_a_hostile_array_count_without_panicking() {
    // A count header claiming far more peaks than the input holds must be
    // a typed error, not an allocation sized by the header. Mutant: drop
    // the remaining-length bound in `decode_commitment_object` and the
    // u64::MAX case panics with "capacity overflow" in `Vec::with_capacity`.
    // The other two cases are boundary sanity only: without the bound they
    // still reject, later, on truncation.
    let mut huge_u64 = vec![0x9b];
    huge_u64.extend_from_slice(&u64::MAX.to_be_bytes());
    let huge_u32 = [0x9a, 0xff, 0xff, 0xff, 0xff];
    // One peak's worth of bytes, but a count of two.
    let mut one_short = commitment_object(&[[0x11; 32]]);
    one_short[0] = 0x82;
    for (label, bytes) in [
        ("u64::MAX count", huge_u64.as_slice()),
        ("u32::MAX count", huge_u32.as_slice()),
        ("count one past the input", one_short.as_slice()),
    ] {
        assert!(
            decode_commitment_object(bytes).is_err(),
            "{label}: decoder accepted an array count the input cannot hold"
        );
    }
}

#[test]
fn commitment_object_decoder_rejects_non_minimal_cbor_headers() {
    // RFC 8949 SS4.2.1: a header must use the shortest argument encoding.
    // Each case re-encodes a valid single-peak object with one header
    // widened; the peak list it decodes to is unchanged, so only the
    // minimality check can reject it. Mutant: drop the `value < min`
    // check in `cbor_read_uint_header` and this test goes red.
    let peak: Hash = [0x22; 32];
    let canonical = commitment_object(&[peak]);
    assert_eq!(&canonical[..3], &[0x81, 0x58, 0x20]);
    assert_eq!(decode_commitment_object(&canonical).unwrap(), vec![peak]);

    let with_headers = |array_hdr: &[u8], bstr_hdr: &[u8]| {
        let mut v = array_hdr.to_vec();
        v.extend_from_slice(bstr_hdr);
        v.extend_from_slice(&peak);
        v
    };
    let cases = [
        (
            "array count 1 as 0x98 0x01",
            with_headers(&[0x98, 0x01], &[0x58, 0x20]),
        ),
        (
            "array count 1 as 2-byte",
            with_headers(&[0x99, 0x00, 0x01], &[0x58, 0x20]),
        ),
        (
            "array count 1 as 4-byte",
            with_headers(&[0x9a, 0x00, 0x00, 0x00, 0x01], &[0x58, 0x20]),
        ),
        (
            "array count 1 as 8-byte",
            with_headers(&[0x9b, 0, 0, 0, 0, 0, 0, 0, 0x01], &[0x58, 0x20]),
        ),
        (
            "bstr len 32 as 2-byte",
            with_headers(&[0x81], &[0x59, 0x00, 0x20]),
        ),
        (
            "bstr len 32 as 4-byte",
            with_headers(&[0x81], &[0x5a, 0x00, 0x00, 0x00, 0x20]),
        ),
    ];
    for (label, bytes) in &cases {
        assert!(
            decode_commitment_object(bytes).is_err(),
            "{label}: decoder accepted a non-minimal CBOR header"
        );
    }
}

#[test]
fn commitment_object_decoder_accepts_minimal_headers_at_width_boundaries() {
    // Positive half of the minimality check: 23 peaks is the last count
    // in the header byte (0x97), 24 the first needing a 1-byte argument
    // (0x98 0x18). Both are minimal and must round-trip. Mutant: an
    // off-by-one minimum (`value <= min`, or 25 for info 24) rejects the
    // 24-peak object and this test goes red.
    for n in [23u8, 24] {
        let peaks: Vec<Hash> = (0..n).map(|i| [i; 32]).collect();
        let bytes = commitment_object(&peaks);
        let expected_hdr: &[u8] = if n < 24 { &[0x80 | n] } else { &[0x98, n] };
        assert_eq!(&bytes[..expected_hdr.len()], expected_hdr);
        assert_eq!(
            decode_commitment_object(&bytes).expect("minimal encoding must decode"),
            peaks,
            "{n}-peak object did not round-trip"
        );
    }
}
