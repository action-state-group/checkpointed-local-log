//! Signed checkpoint emission and offline verification -- byte-for-byte
//! port of the Python reference's `cll.checkpoint.emit` (the
//! `CheckpointRecord` shape and its JSON signing body) and
//! `cll.checkpoint.cose_wire` (the COSE_Sign1 wire form, Decision 1,
//! 2026-08-24).
//!
//! A *checkpoint* is a signed, tamper-evident snapshot of one log's MMR
//! peak set: `{log_id, mmr_size, root, prev_size, prev_root, key_id,
//! timestamp}`. Two independent signed forms exist for it:
//!
//! - The internal JSON form (`CheckpointRecord::signing_body`/`digest`):
//!   a hex Ed25519 signature over the canonical (sorted-key, compact) JSON
//!   of the fields above.
//! - The wire COSE_Sign1 form (`checkpoint_to_cose`/
//!   `verify_checkpoint_cose_offline`): the shape that actually leaves the
//!   producer's process (witness registration, bundle embedding). The
//!   claims map uses the CLL I-D (draft-mih-scitt-checkpointed-local-log-00)
//!   field names, and carries the MMRIVER-conformant peak-list commitment
//!   (`core::commitment_object`) rather than the bagged root, plus an
//!   optional MMR consistency proof so continuity is independently
//!   checkable, not merely asserted by field equality.

use crate::mmr::{commitment_object, root_from_peaks, ConsistencyProof, Hash, DIGEST_LEN};
use coset::cbor::value::Value as CborValue;
use coset::{iana, CoseSign1, CoseSign1Builder, HeaderBuilder, Label, RegisteredLabel, TaggedCborSerializable};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("invalid checkpoint: {0}")]
    Invalid(String),
    #[error("cbor error: {0}")]
    Cbor(String),
}

fn invalid(msg: impl Into<String>) -> CheckpointError {
    CheckpointError::Invalid(msg.into())
}

// -- canonical JSON (Python json.dumps(..., sort_keys=True, ensure_ascii=True,
// separators=(",", ":")) equivalent -- hand-rolled so the signing digest is
// byte-for-byte reproducible without depending on any JSON library's
// particular escaping/ordering defaults). ---------------------------------

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                let cp = c as u32;
                if cp <= 0xffff {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    // Surrogate pair (Python's ensure_ascii encodes non-BMP
                    // codepoints as a UTF-16 surrogate pair, same as here).
                    let v = cp - 0x10000;
                    let hi = 0xd800 + (v >> 10);
                    let lo = 0xdc00 + (v & 0x3ff);
                    out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
                }
            }
        }
    }
    out
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

// -- WitnessRecord ------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessRecord {
    pub ts_url: String,
    /// sha256(bytes.fromhex(checkpoint_digest)).hex() -- TS-derived.
    pub entry_hash: String,
    /// base64-encoded COSE Receipt (COSE_Sign1, CBOR tag 18).
    pub receipt_b64: String,
    pub leaf_index: i64,
    pub tree_size: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_stub: bool,
}

impl WitnessRecord {
    /// Canonical JSON matching Python's `WitnessRecord.to_dict()` under
    /// `json.dumps(..., sort_keys=True, separators=(",", ":"))`.
    pub fn canonical_json(&self) -> String {
        let mut fields = vec![
            format!("\"entry_hash\":{}", json_str(&self.entry_hash)),
            format!("\"leaf_index\":{}", self.leaf_index),
            format!("\"receipt_b64\":{}", json_str(&self.receipt_b64)),
            format!("\"ts_url\":{}", json_str(&self.ts_url)),
            format!("\"tree_size\":{}", self.tree_size),
        ];
        if self.is_stub {
            fields.insert(1, "\"is_stub\":true".to_string());
        }
        format!("{{{}}}", fields.join(","))
    }
}

// -- CheckpointRecord ------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckpointRecord {
    pub v: u32,
    pub kind: String,
    pub log_id: String,
    pub mmr_size: u64,
    /// hex: root_from_peaks at mmr_size (32B).
    pub root: String,
    /// 0 for the first checkpoint.
    pub prev_size: u64,
    /// hex root at prev_size; empty string for the first checkpoint.
    pub prev_root: String,
    /// signer's key id; doubles as peer id in a multi-peer deployment.
    pub key_id: String,
    /// ISO 8601 UTC.
    pub timestamp: String,
    /// hex signature (Ed25519) over `signing_body()`.
    pub signature: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witnesses: Vec<WitnessRecord>,
}

impl CheckpointRecord {
    /// Canonical JSON over the fields covered by the signature -- matches
    /// Python's `CheckpointRecord.signing_body()` byte-for-byte.
    pub fn signing_body(&self) -> String {
        format!(
            "{{\"key_id\":{},\"kind\":{},\"log_id\":{},\"mmr_size\":{},\"prev_root\":{},\"prev_size\":{},\"root\":{},\"timestamp\":{},\"v\":{}}}",
            json_str(&self.key_id),
            json_str(&self.kind),
            json_str(&self.log_id),
            self.mmr_size,
            json_str(&self.prev_root),
            self.prev_size,
            json_str(&self.root),
            json_str(&self.timestamp),
            self.v,
        )
    }

    /// 64-char lowercase hex: sha256 of the signing body (UTF-8 encoded).
    /// This is what gets registered with the Transparency Service.
    pub fn digest(&self) -> String {
        sha256_hex(self.signing_body().as_bytes())
    }

    /// Canonical JSON of the FULL persisted entry (signing body fields,
    /// `signature`, and `witnesses` alike) -- matches Python's
    /// `CheckpointRecord.to_dict()` under sorted-key canonical JSON.
    pub fn canonical_json(&self) -> String {
        let mut fields = vec![
            format!("\"key_id\":{}", json_str(&self.key_id)),
            format!("\"kind\":{}", json_str(&self.kind)),
            format!("\"log_id\":{}", json_str(&self.log_id)),
            format!("\"mmr_size\":{}", self.mmr_size),
            format!("\"prev_root\":{}", json_str(&self.prev_root)),
            format!("\"prev_size\":{}", self.prev_size),
            format!("\"root\":{}", json_str(&self.root)),
            format!("\"signature\":{}", json_str(&self.signature)),
            format!("\"timestamp\":{}", json_str(&self.timestamp)),
            format!("\"v\":{}", self.v),
        ];
        if !self.witnesses.is_empty() {
            let ws: Vec<String> = self.witnesses.iter().map(|w| w.canonical_json()).collect();
            fields.push(format!("\"witnesses\":[{}]", ws.join(",")));
        }
        format!("{{{}}}", fields.join(","))
    }

    /// 64-char lowercase hex: sha256 of the FULL persisted entry. This --
    /// not `digest()` -- is the value a checkpoint's own ledger stamp
    /// commits to the MMR as (matches Python's `entry_digest()`).
    pub fn entry_digest(&self) -> String {
        sha256_hex(self.canonical_json().as_bytes())
    }

    /// Verify `signature` using ONLY this record -- no live signer, no
    /// network. Reconstructs the Ed25519 public key straight from `key_id`
    /// (raw public key, hex-encoded) and verifies `signature` over
    /// `digest()`. Never panics -- any malformed input is a verification
    /// failure.
    pub fn verify_signature_offline(&self) -> bool {
        (|| -> Option<bool> {
            let key_bytes: [u8; 32] = hex::decode(&self.key_id).ok()?.try_into().ok()?;
            let verifying_key = VerifyingKey::from_bytes(&key_bytes).ok()?;
            let sig_bytes: [u8; 64] = hex::decode(&self.signature).ok()?.try_into().ok()?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            Some(verifying_key.verify(self.digest().as_bytes(), &signature).is_ok())
        })()
        .unwrap_or(false)
    }
}

/// Sign `cp`'s digest with `signing_key` (Ed25519) and return the hex
/// signature to store in `CheckpointRecord.signature` -- the producer-side
/// counterpart to `verify_signature_offline`.
pub fn sign_checkpoint_digest(cp: &CheckpointRecord, signing_key: &SigningKey) -> String {
    hex::encode(signing_key.sign(cp.digest().as_bytes()).to_bytes())
}

// -- COSE wire form -----------------------------------------------------

/// Pending IANA media-type registration.
pub const CLL_CHECKPOINT_CONTENT_TYPE: &str = "application/cll-checkpoint+cbor";

/// The CBOR claims map's `kind` value -- the CLL I-D SS3 spec name, always
/// written on encode regardless of the internal `CheckpointRecord.kind`
/// value (which stays `"mmr_checkpoint"`).
pub const WIRE_KIND: &str = "cll-checkpoint";

const HDR_CWT_CLAIMS: i64 = 15; // RFC 9597 SS2 ("CWT Claims") -- NOT label 13 (kcwt)
const CWT_ISS: i64 = 1;
const CWT_SUB: i64 = 2;

fn hex32(h: &str, what: &str) -> Result<Hash, CheckpointError> {
    let bytes = hex::decode(h).map_err(|e| invalid(format!("{what} is not valid hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| invalid(format!("{what} must be {DIGEST_LEN} bytes")))
}

fn consistency_proof_to_cbor(p: &ConsistencyProof) -> Result<CborValue, CheckpointError> {
    let old_peaks: Vec<CborValue> = p
        .old_peaks
        .iter()
        .map(|h| hex32(h, "old_peaks element").map(|b| CborValue::from(b.to_vec())))
        .collect::<Result<_, _>>()?;
    let witness: Vec<CborValue> = p
        .witness
        .iter()
        .map(|w| -> Result<CborValue, CheckpointError> {
            let elems: Vec<CborValue> = w
                .iter()
                .map(|h| hex32(h, "witness element").map(|b| CborValue::from(b.to_vec())))
                .collect::<Result<_, _>>()?;
            Ok(CborValue::Array(elems))
        })
        .collect::<Result<_, _>>()?;
    let new_peaks: Vec<CborValue> = p
        .new_peaks
        .iter()
        .map(|h| hex32(h, "new_peaks element").map(|b| CborValue::from(b.to_vec())))
        .collect::<Result<_, _>>()?;

    Ok(CborValue::Map(vec![
        (CborValue::from("size_a"), CborValue::from(p.size_a)),
        (CborValue::from("size_b"), CborValue::from(p.size_b)),
        (CborValue::from("old_peaks"), CborValue::Array(old_peaks)),
        (CborValue::from("witness"), CborValue::Array(witness)),
        (CborValue::from("new_peaks"), CborValue::Array(new_peaks)),
    ]))
}

fn consistency_proof_from_cbor(v: &CborValue) -> Result<ConsistencyProof, CheckpointError> {
    let map = v.as_map().ok_or_else(|| invalid("consistency_proof claim is not a map"))?;
    let get = |key: &str| -> Option<&CborValue> {
        map.iter().find_map(|(k, v)| (k.as_text() == Some(key)).then_some(v))
    };
    let size_a = get("size_a").and_then(CborValue::as_integer).ok_or_else(|| invalid("consistency_proof missing size_a"))?;
    let size_b = get("size_b").and_then(CborValue::as_integer).ok_or_else(|| invalid("consistency_proof missing size_b"))?;
    let old_peaks_v = get("old_peaks").and_then(CborValue::as_array).ok_or_else(|| invalid("consistency_proof missing old_peaks"))?;
    let witness_v = get("witness").and_then(CborValue::as_array).ok_or_else(|| invalid("consistency_proof missing witness"))?;
    let new_peaks_v = get("new_peaks").and_then(CborValue::as_array).ok_or_else(|| invalid("consistency_proof missing new_peaks"))?;

    let to_hex = |v: &CborValue| -> Result<String, CheckpointError> {
        v.as_bytes().map(hex::encode).ok_or_else(|| invalid("expected a byte string"))
    };

    let old_peaks: Vec<String> = old_peaks_v.iter().map(to_hex).collect::<Result<_, _>>()?;
    let new_peaks: Vec<String> = new_peaks_v.iter().map(to_hex).collect::<Result<_, _>>()?;
    let witness: Vec<Vec<String>> = witness_v
        .iter()
        .map(|w| {
            w.as_array()
                .ok_or_else(|| invalid("witness element is not an array"))?
                .iter()
                .map(to_hex)
                .collect::<Result<Vec<_>, _>>()
        })
        .collect::<Result<_, _>>()?;

    Ok(ConsistencyProof {
        v: 1,
        kind: "consistency".to_string(),
        size_a: i128::from(size_a) as u64,
        size_b: i128::from(size_b) as u64,
        old_peaks,
        witness,
        new_peaks,
    })
}

/// Build the CBOR claims map (I-D SS3 field names) for `cp` -- the payload
/// `checkpoint_to_cose` wraps in a COSE_Sign1 envelope. Pure translation,
/// no signing.
///
/// `new_peak_hashes` is the MMR's own peak-hash list at `cp.mmr_size` --
/// the `commitment` claim is `commitment_object(new_peak_hashes)`, NOT
/// `cp.root` (the wire form's commitment is the MMRIVER-conformant peak
/// list, independently reproducible by any conformant tool; the bagged
/// root is this crate's own internal fold, derived FROM it on both encode
/// and decode). `prev_peak_hashes` is the same for `cp.prev_size`
/// (required exactly when `cp.prev_size > 0`).
///
/// Errors if either peak list does not bag (`root_from_peaks`) to
/// `cp.root`/`cp.prev_root` respectively, or if `consistency_proof` does
/// not span exactly `(cp.prev_size, cp.mmr_size)`.
pub fn encode_checkpoint_claims(
    cp: &CheckpointRecord,
    new_peak_hashes: &[Hash],
    prev_peak_hashes: Option<&[Hash]>,
    consistency_proof: Option<&ConsistencyProof>,
    cadence_seconds: Option<i64>,
) -> Result<Vec<u8>, CheckpointError> {
    if let Some(p) = consistency_proof {
        if p.size_a != cp.prev_size || p.size_b != cp.mmr_size {
            return Err(invalid(format!(
                "consistency_proof spans ({}, {}) but checkpoint is (prev_size={}, mmr_size={})",
                p.size_a, p.size_b, cp.prev_size, cp.mmr_size
            )));
        }
    }

    let expected_root = hex32(&cp.root, "cp.root")?;
    if root_from_peaks(new_peak_hashes) != expected_root {
        return Err(invalid(
            "new_peak_hashes do not bag (root_from_peaks) to cp.root -- pass the SAME peak set \
             this checkpoint's own root was computed from",
        ));
    }

    let prev_commitment: Vec<u8> = if cp.prev_size > 0 {
        let prev_peaks = prev_peak_hashes.ok_or_else(|| {
            invalid(format!(
                "checkpoint has prev_size={} > 0 but no prev_peak_hashes was supplied",
                cp.prev_size
            ))
        })?;
        let expected_prev_root = hex32(&cp.prev_root, "cp.prev_root")?;
        if root_from_peaks(prev_peaks) != expected_prev_root {
            return Err(invalid(
                "prev_peak_hashes do not bag (root_from_peaks) to cp.prev_root -- pass the SAME \
                 peak set the prior checkpoint's own root was computed from",
            ));
        }
        commitment_object(prev_peaks)
    } else {
        Vec::new()
    };

    let mut claims: Vec<(CborValue, CborValue)> = vec![
        (CborValue::from("kind"), CborValue::from(WIRE_KIND)),
        (CborValue::from("log_size"), CborValue::from(cp.mmr_size)),
        (CborValue::from("commitment"), CborValue::from(commitment_object(new_peak_hashes))),
        (CborValue::from("prev_size"), CborValue::from(cp.prev_size)),
        (CborValue::from("prev_commitment"), CborValue::from(prev_commitment)),
        (CborValue::from("issued_at"), CborValue::from(cp.timestamp.clone())),
    ];
    if let Some(c) = cadence_seconds {
        claims.push((CborValue::from("cadence"), CborValue::from(c)));
    }
    if let Some(p) = consistency_proof {
        claims.push((CborValue::from("consistency_proof"), consistency_proof_to_cbor(p)?));
    }

    let mut out = Vec::new();
    coset::cbor::ser::into_writer(&CborValue::Map(claims), &mut out)
        .map_err(|e| CheckpointError::Cbor(format!("{e:?}")))?;
    Ok(out)
}

/// Serialize `cp` as a COSE_Sign1 statement over the CBOR claims map,
/// signed by `signing_key` -- the wire form for the two stranger-facing
/// moments (witness registration, bundle embedding).
///
/// Refuses to serialize a checkpoint that claims a prior (`prev_size > 0`)
/// without a `consistency_proof`, and symmetrically refuses a
/// `consistency_proof` on a first checkpoint.
pub fn checkpoint_to_cose(
    cp: &CheckpointRecord,
    signing_key: &SigningKey,
    new_peak_hashes: &[Hash],
    prev_peak_hashes: Option<&[Hash]>,
    consistency_proof: Option<&ConsistencyProof>,
    cadence_seconds: Option<i64>,
) -> Result<Vec<u8>, CheckpointError> {
    if cp.prev_size > 0 && consistency_proof.is_none() {
        return Err(invalid(format!(
            "checkpoint at mmr_size={} has prev_size={} > 0 but no consistency_proof was supplied",
            cp.mmr_size, cp.prev_size
        )));
    }
    if consistency_proof.is_some() && cp.prev_size == 0 {
        return Err(invalid("checkpoint has no prior (prev_size == 0) but a consistency_proof was supplied"));
    }

    let payload = encode_checkpoint_claims(cp, new_peak_hashes, prev_peak_hashes, consistency_proof, cadence_seconds)?;

    let subject = format!("{}#{}", cp.log_id, cp.mmr_size);
    let claims_hdr = CborValue::Map(vec![
        (CborValue::from(CWT_ISS), CborValue::from(cp.log_id.clone())),
        (CborValue::from(CWT_SUB), CborValue::from(subject)),
    ]);

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .content_type(CLL_CHECKPOINT_CONTENT_TYPE.to_string())
        .value(HDR_CWT_CLAIMS, claims_hdr)
        .key_id(signing_key.verifying_key().to_bytes().to_vec())
        .build();

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .create_signature(b"", |tbs| signing_key.sign(tbs).to_bytes().to_vec())
        .build();

    sign1.to_tagged_vec().map_err(|e| CheckpointError::Cbor(format!("{e:?}")))
}

#[derive(Debug, Clone)]
pub struct DecodedCheckpointCose {
    pub log_id: String,
    pub mmr_size: u64,
    pub root: String,
    pub new_peak_hashes: Vec<Hash>,
    pub prev_size: u64,
    pub prev_root: String,
    pub prev_peak_hashes: Vec<Hash>,
    pub timestamp: String,
    pub key_id: String,
    pub cadence_seconds: Option<i64>,
    pub consistency_proof: Option<ConsistencyProof>,
}

impl DecodedCheckpointCose {
    /// Reconstruct a `CheckpointRecord` from these fields -- `kind` fixed
    /// back to the internal `"mmr_checkpoint"` convention, `signature`
    /// left empty (not recoverable from the COSE envelope alone; the wire
    /// signature is over the CBOR claims, a different message from the
    /// JSON signing body).
    pub fn to_checkpoint_record(&self) -> CheckpointRecord {
        CheckpointRecord {
            v: 1,
            kind: "mmr_checkpoint".to_string(),
            log_id: self.log_id.clone(),
            mmr_size: self.mmr_size,
            root: self.root.clone(),
            prev_size: self.prev_size,
            prev_root: self.prev_root.clone(),
            key_id: self.key_id.clone(),
            timestamp: self.timestamp.clone(),
            signature: String::new(),
            witnesses: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CoseCheckpointVerification {
    pub ok: bool,
    pub decoded: Option<DecodedCheckpointCose>,
    pub errors: Vec<String>,
}

fn decode_commitment(raw: &[u8], what: &str) -> Result<Vec<Hash>, CheckpointError> {
    let value: CborValue = coset::cbor::de::from_reader(raw).map_err(|e| invalid(format!("{what} is not valid CBOR: {e:?}")))?;
    let arr = value.as_array().ok_or_else(|| invalid(format!("{what} is not a CBOR array of peak hashes")))?;
    arr.iter()
        .map(|v| {
            v.as_bytes()
                .filter(|b| b.len() == DIGEST_LEN)
                .and_then(|b| <[u8; DIGEST_LEN]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| invalid(format!("{what} is not a CBOR array of 32-byte peak hashes")))
        })
        .collect()
}

/// Verify a COSE-wire checkpoint statement using ONLY the bytes themselves
/// -- no registry, no network, no live MMR reader. Never panics.
///
/// The signing key is read straight from the envelope's own
/// protected-header `kid` (raw 32-byte Ed25519 public key) -- this proves
/// "the holder of this key signed this exact claims map", not who that key
/// belongs to.
///
/// If the claims carry a `consistency_proof` (`prev_size > 0`), it is
/// independently re-verified against the claims' OWN
/// `commitment`/`prev_commitment` -- a REAL extension proof, not field
/// equality. A checkpoint claiming `prev_size > 0` with no
/// `consistency_proof` is rejected -- continuity would be asserted, not
/// proven.
pub fn verify_checkpoint_cose_offline(cose_bytes: &[u8]) -> CoseCheckpointVerification {
    let mut result = CoseCheckpointVerification::default();

    let sign1 = match CoseSign1::from_tagged_slice(cose_bytes) {
        Ok(s) => s,
        Err(e) => {
            result.errors.push(format!("malformed COSE checkpoint statement: {e:?}"));
            return result;
        }
    };

    let kid = sign1.protected.header.key_id.clone();
    if kid.len() != DIGEST_LEN {
        result.errors.push("COSE checkpoint statement carries no 32-byte kid (label 4) -- cannot self-verify offline".to_string());
        return result;
    }
    let key_bytes: [u8; DIGEST_LEN] = kid.clone().try_into().unwrap();
    let verifying_key = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(k) => k,
        Err(e) => {
            result.errors.push(format!("kid is not a valid Ed25519 public key: {e}"));
            return result;
        }
    };

    let verify_result = sign1.verify_signature(b"", |sig, tbs| -> Result<(), ()> {
        let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| ())?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key.verify(tbs, &signature).map_err(|_| ())
    });
    if verify_result.is_err() {
        result.errors.push("COSE checkpoint signature does not verify under its own kid".to_string());
        return result;
    }

    let content_type = match &sign1.protected.header.content_type {
        Some(RegisteredLabel::Text(s)) => s.clone(),
        _ => String::new(),
    };
    if content_type != CLL_CHECKPOINT_CONTENT_TYPE {
        result.errors.push(format!("unexpected content_type {content_type:?}"));
        return result;
    }

    let claims_hdr = sign1
        .protected
        .header
        .rest
        .iter()
        .find(|(label, _)| *label == Label::Int(HDR_CWT_CLAIMS))
        .map(|(_, v)| v.clone());
    let (issuer, subject) = match claims_hdr.as_ref().and_then(CborValue::as_map) {
        Some(entries) => {
            let get = |want: i64| {
                entries.iter().find_map(|(k, v)| match (k.as_integer(), v.as_text()) {
                    (Some(i), Some(s)) if i128::from(i) == want as i128 => Some(s.to_string()),
                    _ => None,
                })
            };
            (get(CWT_ISS), get(CWT_SUB))
        }
        None => (None, None),
    };
    let issuer = match issuer {
        Some(i) if !i.is_empty() => i,
        _ => {
            result.errors.push("statement carries no CWT issuer (log identity)".to_string());
            return result;
        }
    };

    let payload = match &sign1.payload {
        Some(p) => p.clone(),
        None => {
            result.errors.push("statement has no attached payload".to_string());
            return result;
        }
    };
    let claims: CborValue = match coset::cbor::de::from_reader(payload.as_slice()) {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("payload is not valid CBOR: {e:?}"));
            return result;
        }
    };
    let claims_map = match claims.as_map() {
        Some(m) => m,
        None => {
            result.errors.push("claims payload is not a map".to_string());
            return result;
        }
    };
    let get = |key: &str| -> Option<&CborValue> {
        claims_map.iter().find_map(|(k, v)| (k.as_text() == Some(key)).then_some(v))
    };

    if get("kind").and_then(CborValue::as_text) != Some(WIRE_KIND) {
        result.errors.push(format!("claims 'kind' is {:?}, expected {WIRE_KIND:?}", get("kind")));
        return result;
    }

    let mmr_size = match get("log_size").and_then(CborValue::as_integer).map(|i| i128::from(i)) {
        Some(n) if n >= 0 => n as u64,
        _ => {
            result.errors.push("log_size must be a non-negative integer".to_string());
            return result;
        }
    };
    let prev_size = match get("prev_size").and_then(CborValue::as_integer).map(|i| i128::from(i)) {
        Some(n) if n >= 0 => n as u64,
        _ => {
            result.errors.push("prev_size must be a non-negative integer".to_string());
            return result;
        }
    };
    let commitment = match get("commitment").and_then(CborValue::as_bytes) {
        Some(b) => b,
        None => {
            result.errors.push("commitment must be a CBOR byte string".to_string());
            return result;
        }
    };
    let new_peak_hashes = match decode_commitment(commitment, "commitment") {
        Ok(v) => v,
        Err(e) => {
            result.errors.push(e.to_string());
            return result;
        }
    };
    let root = hex::encode(root_from_peaks(&new_peak_hashes));

    let prev_commitment = get("prev_commitment").and_then(CborValue::as_bytes);
    let (prev_peak_hashes, prev_root) = match prev_commitment {
        Some(b) if !b.is_empty() => match decode_commitment(b, "prev_commitment") {
            Ok(v) => {
                let r = hex::encode(root_from_peaks(&v));
                (v, r)
            }
            Err(e) => {
                result.errors.push(e.to_string());
                return result;
            }
        },
        _ => (Vec::new(), String::new()),
    };

    let issued_at = match get("issued_at").and_then(CborValue::as_text) {
        Some(s) => s.to_string(),
        None => {
            result.errors.push("issued_at must be a string (ISO 8601)".to_string());
            return result;
        }
    };

    let expected_subject = format!("{issuer}#{mmr_size}");
    if subject.as_deref() != Some(expected_subject.as_str()) {
        result.errors.push(format!("CWT subject {subject:?} does not match expected {expected_subject:?}"));
        return result;
    }

    let cadence_seconds = get("cadence").and_then(CborValue::as_integer).map(|i| i128::from(i) as i64);

    let consistency_proof = match get("consistency_proof") {
        Some(raw) => match consistency_proof_from_cbor(raw) {
            Ok(p) => {
                if p.size_a != prev_size || p.size_b != mmr_size {
                    result.errors.push("consistency_proof does not span this checkpoint's own prev_size/log_size".to_string());
                    return result;
                }
                Some(p)
            }
            Err(e) => {
                result.errors.push(e.to_string());
                return result;
            }
        },
        None => None,
    };

    let decoded = DecodedCheckpointCose {
        log_id: issuer,
        mmr_size,
        root,
        new_peak_hashes,
        prev_size,
        prev_root,
        prev_peak_hashes,
        timestamp: issued_at,
        key_id: hex::encode(&kid),
        cadence_seconds,
        consistency_proof,
    };

    match &decoded.consistency_proof {
        Some(p) => {
            let root_a = match hex32(&decoded.prev_root, "prev_commitment") {
                Ok(r) => r,
                Err(e) => {
                    result.errors.push(e.to_string());
                    return result;
                }
            };
            let root_b = match hex32(&decoded.root, "commitment") {
                Ok(r) => r,
                Err(e) => {
                    result.errors.push(e.to_string());
                    return result;
                }
            };
            if !crate::mmr::verify_consistency(&root_a, decoded.prev_size, &root_b, decoded.mmr_size, p) {
                result.errors.push(format!(
                    "consistency proof does not bridge prev_size={} to log_size={} -- checkpoint \
                     claims continuity it cannot cryptographically back",
                    decoded.prev_size, decoded.mmr_size
                ));
                return result;
            }
        }
        None => {
            if decoded.prev_size != 0 {
                result.errors.push(format!(
                    "checkpoint claims prev_size={} (not the log's first) but carries no \
                     consistency_proof -- continuity is asserted, not proven",
                    decoded.prev_size
                ));
                return result;
            }
        }
    }

    result.decoded = Some(decoded);
    result.ok = true;
    result
}
