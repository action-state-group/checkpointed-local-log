//! A refusal signed by the Python implementation (`capsule_emit`'s
//! `evidence_request.Refusal`, key generated fresh and discarded) verifies
//! here unchanged. `tests/vectors/refusal.json` is the vector the Go
//! implementation checks in its own refusal interop test, copied byte for
//! byte, so all three implementations agree on the signing body.

use evidencebook::request::{Refusal, RefusalError};

fn vector() -> Refusal {
    let text = include_str!("vectors/refusal.json");
    serde_json::from_str(text).expect("refusal vector parses")
}

#[test]
fn python_signed_refusal_verifies() {
    vector().verify().unwrap();
}

#[test]
fn the_vector_stops_verifying_when_any_signed_field_changes() {
    let mut r = vector();
    r.issued_at = "2026-09-26T12:00:01Z".into();
    assert_eq!(r.verify(), Err(RefusalError::Unverified));
    let mut r = vector();
    r.request_digest = "cd".repeat(32);
    assert_eq!(r.verify(), Err(RefusalError::Unverified));
}
