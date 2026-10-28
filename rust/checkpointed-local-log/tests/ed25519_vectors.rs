//! Runs the COSE statements in
//! `checkpoint-conformance-vectors/ed25519-vectors.json` through
//! `verify_checkpoint_cose_offline`: each statement's only defect, if any, is
//! its signing key, and those under a small-order key carry a signature that
//! needs no private key.

use cll::checkpoint::verify_checkpoint_cose_offline;
use serde_json::Value;
use std::path::Path;

#[test]
fn decides_every_shared_statement() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../checkpoint-conformance-vectors/ed25519-vectors.json");
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = vectors["cose_cases"].as_array().unwrap();
    assert!(cases.iter().any(|case| !case["valid"].as_bool().unwrap()));
    for case in cases {
        let cose = hex::decode(case["cose_hex"].as_str().unwrap()).unwrap();
        let result = verify_checkpoint_cose_offline(&cose);
        assert_eq!(
            result.ok,
            case["valid"].as_bool().unwrap(),
            "{} {:?}",
            case["name"],
            result.errors
        );
    }
}
