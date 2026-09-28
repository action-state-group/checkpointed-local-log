//! Request subjects, the three outcomes of a request, and the three kinds of
//! "no".
//!
//! I-D sections: *Answering a Request*, *Three Kinds of "No"*. Subject forms,
//! outcomes and refusal reasons are the tokens of the companion request draft
//! (`draft-mih-agent-evidence-request-00`); this module does not restate that
//! draft's rules about coverage anchors.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The six subject forms a request can name, with the store capability that
/// answers each (I-D *Answering a Request*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// One record by id or digest: operational or authenticated index.
    Record,
    /// Records at stated positions, with inclusion or range proof.
    Range,
    /// Every record whose correlation field matches: operational index.
    Correlation,
    /// Every record citing the named interaction half's digest. The variant
    /// name is the request draft's wire token for this subject form.
    #[serde(rename = "exchange")] // vocabulary-gate: request-draft wire token
    CitingRecords,
    /// The store's whole evidence body, subject to disclosure policy.
    FullHistory,
    /// The substrate's checkpoint identity and receipts; no record lookup.
    Checkpoints,
}

impl SubjectKind {
    pub const ALL: [SubjectKind; 6] = [
        SubjectKind::Record,
        SubjectKind::Range,
        SubjectKind::Correlation,
        SubjectKind::CitingRecords,
        SubjectKind::FullHistory,
        SubjectKind::Checkpoints,
    ];

    /// Whether answering this subject resolves records (every form except
    /// `checkpoints`).
    pub fn resolves_records(self) -> bool {
        self != SubjectKind::Checkpoints
    }
}

/// The three mutually exclusive outcomes of one request. A responder grants
/// or refuses; recorded absence is the requester's own record that nothing
/// arrived in its window, never something a responder sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// A signed artifact response.
    Artifact,
    /// A signed refusal naming a reason token.
    Refusal,
    /// The requester's own signed record of non-arrival.
    RecordedAbsence,
}

/// The three different things "no evidence for this subject" can mean (I-D
/// *Three Kinds of "No"*). Only [`NoKind::NonMembership`] is checkable by a
/// party other than the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoKind {
    /// An authenticated-index proof that nothing occupies the position or
    /// carries the identity.
    NonMembership,
    /// It exists and is not disclosed under current policy. Not an absence.
    Withheld,
    /// The store's own unproven claim that it holds nothing. A
    /// `producer_claim`, never proof.
    AssertedAbsence,
}

impl NoKind {
    /// Whether a party that does not trust the store can check this "no".
    pub fn is_checkable(self) -> bool {
        self == NoKind::NonMembership
    }
}

/// Refusal reason tokens (the request draft's registry).
pub mod reasons {
    pub const NOT_AUTHORIZED: &str = "not_authorized";
    pub const NO_SUCH_SUBJECT: &str = "no_such_subject";
    pub const COVERAGE_UNSATISFIABLE: &str = "coverage_unsatisfiable";
    pub const DERIVATION_UNSUPPORTED: &str = "derivation_unsupported";
    pub const POLICY_DECLINED: &str = "policy_declined";
    pub const DEADLINE_UNMET: &str = "deadline_unmet";
    pub const REQUEST_MALFORMED: &str = "request_malformed";
    pub const RETENTION_EXPIRED: &str = "retention_expired";

    pub const ALL: [&str; 8] = [
        NOT_AUTHORIZED,
        NO_SUCH_SUBJECT,
        COVERAGE_UNSATISFIABLE,
        DERIVATION_UNSUPPORTED,
        POLICY_DECLINED,
        DEADLINE_UNMET,
        REQUEST_MALFORMED,
        RETENTION_EXPIRED,
    ];
}

/// A signed refusal of one request. The signature covers the sorted, compact
/// JSON of `issued_at`, `reason` and `request_digest` -- the body the Python
/// and Go implementations sign (`tests/refusal_interop.rs` verifies a refusal
/// signed by the Python one).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub request_digest: String,
    pub reason: String,
    pub issued_at: String,
    /// Raw Ed25519 public key, hex.
    pub key_id: String,
    /// Ed25519 signature over [`Refusal::signing_body`], hex.
    pub sig: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RefusalError {
    #[error("refusal reason {0:?} is not a registered token")]
    UnknownReason(String),
    #[error("refusal key_id is not a raw Ed25519 public key in hex")]
    BadKey,
    #[error("refusal signature is not 64 bytes of hex")]
    BadSignature,
    #[error("refusal signature does not verify under its key_id")]
    Unverified,
}

impl Refusal {
    /// The exact bytes a refusal signature covers.
    pub fn signing_body(&self) -> Vec<u8> {
        let body = serde_json::json!({
            "issued_at": self.issued_at,
            "reason": self.reason,
            "request_digest": self.request_digest,
        });
        crate::canonical::jcs(&body).expect("three string members always canonicalize")
    }

    /// Check the reason token and the signature, offline, against the
    /// refusal's own `key_id`.
    pub fn verify(&self) -> Result<(), RefusalError> {
        if !reasons::ALL.contains(&self.reason.as_str()) {
            return Err(RefusalError::UnknownReason(self.reason.clone()));
        }
        let key: [u8; 32] = hex::decode(&self.key_id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(RefusalError::BadKey)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| RefusalError::BadKey)?;
        let sig: [u8; 64] = hex::decode(&self.sig)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(RefusalError::BadSignature)?;
        key.verify(&self.signing_body(), &Signature::from_bytes(&sig))
            .map_err(|_| RefusalError::Unverified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(reason: &str) -> Refusal {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let mut r = Refusal {
            request_digest: "ab".repeat(32),
            reason: reason.into(),
            issued_at: "2026-09-27T00:00:00Z".into(),
            key_id: hex::encode(key.verifying_key().to_bytes()),
            sig: String::new(),
        };
        r.sig = hex::encode(key.sign(&r.signing_body()).to_bytes());
        r
    }

    #[test]
    fn subject_tokens_are_the_request_draft_tokens() {
        let tokens: Vec<String> = SubjectKind::ALL
            .iter()
            .map(|s| {
                serde_json::to_value(s)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(
            tokens,
            [
                "record",
                "range",
                "correlation",
                "exchange", // vocabulary-gate: request-draft wire token
                "full_history",
                "checkpoints"
            ]
        );
        assert!(!SubjectKind::Checkpoints.resolves_records());
        assert!(SubjectKind::ALL[..5].iter().all(|s| s.resolves_records()));
    }

    #[test]
    fn only_non_membership_is_checkable() {
        assert!(NoKind::NonMembership.is_checkable());
        assert!(!NoKind::Withheld.is_checkable());
        assert!(!NoKind::AssertedAbsence.is_checkable());
    }

    #[test]
    fn signing_body_is_sorted_compact_json() {
        let r = signed(reasons::NO_SUCH_SUBJECT);
        assert_eq!(
            String::from_utf8(r.signing_body()).unwrap(),
            format!(
                "{{\"issued_at\":\"2026-09-27T00:00:00Z\",\"reason\":\"no_such_subject\",\"request_digest\":\"{}\"}}",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn verify_accepts_a_good_refusal_and_rejects_each_tamper() {
        let good = signed(reasons::POLICY_DECLINED);
        good.verify().unwrap();

        let mut t = good.clone();
        t.reason = reasons::NOT_AUTHORIZED.into();
        assert_eq!(t.verify(), Err(RefusalError::Unverified));

        let mut t = good.clone();
        t.issued_at = "2026-09-27T00:01:00Z".into();
        assert_eq!(t.verify(), Err(RefusalError::Unverified));

        let mut t = good.clone();
        t.request_digest = "cd".repeat(32);
        assert_eq!(t.verify(), Err(RefusalError::Unverified));

        assert_eq!(
            signed("no_such_record").verify(),
            Err(RefusalError::UnknownReason("no_such_record".into()))
        );

        let mut t = good.clone();
        t.key_id = "zz".into();
        assert_eq!(t.verify(), Err(RefusalError::BadKey));

        let mut t = good;
        t.sig = "00".into();
        assert_eq!(t.verify(), Err(RefusalError::BadSignature));
    }
}
