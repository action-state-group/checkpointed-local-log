//! Padding records and store nonces.
//!
//! I-D section: *Privacy Considerations*, *What a Checkpoint Reveals*.
//!
//! A checkpoint states the size of the store's whole committed history, so
//! two checkpoints handed to one party tell it how many records the store
//! committed between them -- across every counterparty, not only that party.
//! Before a checkpoint is cut, the store appends padding records until its
//! leaf count (never the MMR node count) falls on a bucket boundary, so two
//! checkpoints reveal the count between them only to within the bucket.
//!
//! **Padding is a record, not a log mechanism.** The substrate commits a
//! padding record's id as an ordinary leaf; nothing in the Checkpointed Local
//! Log changes.
//!
//! **Shape.** `{"capsule_id", "record_type": "padding", "epistemic_type":
//! "producer_claim", "store_nonce"}`, plus any local-only producer envelope
//! (`signature`/`key_id`, outside the id preimage). Its only committed content
//! is the fresh store nonce. It carries no payload commitments, no links, no
//! subject or principal, and it is never the target of a link: a store never
//! advances a sequence head over a padding record.
//!
//! **Store nonces.** Every sealed record carries a [`STORE_NONCE_FIELD`] drawn
//! by the store from the OS CSPRNG for that record alone, inside the bytes its
//! commitment is derived from, so a record's id cannot be confirmed by
//! guessing its content. A padding record has no other content, so the nonce
//! is its whole body.
//!
//! **Readers.** A verifier treats a padding record as an ordinary leaf for
//! inclusion, consistency and checkpoints. Everything that counts, lists or
//! summarises records skips it ([`is_padding`]), and it is never returned as
//! responsive to a record, correlation or citing-records query.
//!
//! PROVISIONAL: `record_type: "padding"` is reserved by the Evidence Layer -00
//! draft text; it is a provisional constant pending that draft's privacy
//! considerations text.

use crate::canonical::{compute_capsule_id, JcsError};
use serde_json::{json, Map, Value};

/// The reserved `record_type` token. PROVISIONAL -- see the module doc.
pub const RECORD_TYPE_PADDING: &str = "padding";

/// The detached signed statement's content type for a padding record -- it
/// is not a capsule, so it never claims the capsule media type.
pub const PADDING_CONTENT_TYPE: &str = "application/json";

/// The `epistemic_type` a padding record carries.
pub const PADDING_EPISTEMIC_TYPE: &str = "producer_claim";

/// The member every sealed record's store nonce rides in.
pub const STORE_NONCE_FIELD: &str = "store_nonce";

/// A fresh [`STORE_NONCE_FIELD`] value: 32 bytes from the OS CSPRNG, as 64
/// lowercase hex.
pub fn fresh_store_nonce() -> String {
    use rand_core::RngCore;
    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Whether `record` is a padding record. Every reader that counts, lists or
/// summarises records skips a record for which this is true.
pub fn is_padding(record: &Value) -> bool {
    record.get("record_type").and_then(Value::as_str) == Some(RECORD_TYPE_PADDING)
}

/// A padding record that carries anything beyond its allowed members is not
/// one this store wrote -- refused on append and on reload. Returns the
/// offending member.
pub fn check_padding_shape(record: &Value) -> Result<(), String> {
    let obj = record
        .as_object()
        .ok_or_else(|| "padding record is not a JSON object".to_string())?;
    const ALLOWED: &[&str] = &[
        "capsule_id",
        "record_type",
        "epistemic_type",
        STORE_NONCE_FIELD,
        "signature",
        "key_id",
    ];
    if let Some(extra) = obj.keys().find(|k| !ALLOWED.contains(&k.as_str())) {
        return Err(format!(
            "padding record carries {extra:?}; its only content is the store nonce"
        ));
    }
    let nonce_ok = obj
        .get(STORE_NONCE_FIELD)
        .and_then(Value::as_str)
        .is_some_and(|n| {
            n.len() == 64
                && n.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        });
    if !nonce_ok {
        return Err("padding record's store_nonce is not 64 lowercase hex".to_string());
    }
    Ok(())
}

/// Build one padding record with a fresh store nonce, its `capsule_id`
/// computed over the committed members exactly as every other record's is.
/// The caller attaches its producer envelope and appends it.
pub fn build_padding_record() -> Result<Value, JcsError> {
    let mut body = Map::new();
    body.insert("record_type".into(), json!(RECORD_TYPE_PADDING));
    body.insert("epistemic_type".into(), json!(PADDING_EPISTEMIC_TYPE));
    body.insert(STORE_NONCE_FIELD.into(), json!(fresh_store_nonce()));
    let capsule_id = compute_capsule_id(&Value::Object(body.clone()))?;
    let mut record = Map::new();
    record.insert("capsule_id".into(), json!(capsule_id));
    record.extend(body);
    Ok(Value::Object(record))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_record_is_well_formed_and_unique() {
        let a = build_padding_record().unwrap();
        let b = build_padding_record().unwrap();
        assert!(is_padding(&a));
        check_padding_shape(&a).unwrap();
        assert_ne!(a["capsule_id"], b["capsule_id"], "fresh nonce per record");
        assert_eq!(
            compute_capsule_id(&a).unwrap(),
            a["capsule_id"].as_str().unwrap()
        );
        for absent in ["chain", "references", "timestamp", "model_attestation"] {
            assert!(a.get(absent).is_none(), "{absent} must be absent");
        }
    }

    #[test]
    fn shape_check_refuses_links_and_content() {
        let mut rec = build_padding_record().unwrap();
        rec["chain"] = json!({"parent_capsule_id": "a".repeat(64), "relation": "follows"});
        assert!(check_padding_shape(&rec).is_err());
        let mut rec = build_padding_record().unwrap();
        rec[STORE_NONCE_FIELD] = json!("short");
        assert!(check_padding_shape(&rec).is_err());
    }

    #[test]
    fn ordinary_records_are_not_padding() {
        assert!(!is_padding(&json!({"capsule_id": "a".repeat(64)})));
        assert!(!is_padding(&json!({"record_type": "close"})));
    }

    #[test]
    fn store_nonces_are_64_lowercase_hex_and_fresh() {
        let a = fresh_store_nonce();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_ne!(a, fresh_store_nonce());
    }
}
