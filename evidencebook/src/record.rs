//! The record header, its epistemic type, and typed links.
//!
//! I-D sections: the record header (anchor `record`), *Epistemic Type*,
//! *Typed Links*.
//!
//! The epistemic-type value set is not defined here. It is read from
//! `schemas/vendor/epistemic-types.json`, the same vendored file the Go and
//! Python implementations read, and [`EpistemicType::ALL`] is tested against
//! it so the three implementations cannot drift apart silently.

use crate::retention::RetentionState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

/// The vendored epistemic-type value set, byte for byte as shipped.
pub const VENDORED_EPISTEMIC_TYPES_JSON: &str =
    include_str!("../schemas/vendor/epistemic-types.json");

/// The header version this crate writes and accepts.
pub const HEADER_VERSION: u32 = 1;

/// How a record's content came to be known (I-D *Epistemic Type*). Closed
/// vocabulary, assigned once at commit and never upgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicType {
    ObservedEvent,
    SystemOfRecordFact,
    ProducerClaim,
    HumanReport,
    SemanticJudgment,
    DerivedMetric,
    Adjudication,
    ObligationReference,
}

impl EpistemicType {
    /// Every value, in the I-D's table order.
    pub const ALL: [EpistemicType; 8] = [
        EpistemicType::ObservedEvent,
        EpistemicType::SystemOfRecordFact,
        EpistemicType::ProducerClaim,
        EpistemicType::HumanReport,
        EpistemicType::SemanticJudgment,
        EpistemicType::DerivedMetric,
        EpistemicType::Adjudication,
        EpistemicType::ObligationReference,
    ];

    /// The wire token (lowercase, as the record header carries it).
    pub fn as_str(self) -> &'static str {
        match self {
            EpistemicType::ObservedEvent => "observed_event",
            EpistemicType::SystemOfRecordFact => "system_of_record_fact",
            EpistemicType::ProducerClaim => "producer_claim",
            EpistemicType::HumanReport => "human_report",
            EpistemicType::SemanticJudgment => "semantic_judgment",
            EpistemicType::DerivedMetric => "derived_metric",
            EpistemicType::Adjudication => "adjudication",
            EpistemicType::ObligationReference => "obligation_reference",
        }
    }
}

impl fmt::Display for EpistemicType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EpistemicType {
    type Err = RecordError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EpistemicType::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or_else(|| RecordError::UnknownEpistemicType(s.to_string()))
    }
}

/// A link type (I-D *Typed Links*). Closed vocabulary: a relationship the
/// list does not name is a new registered type, never an overloaded token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkType {
    Cites,
    Adjudicates,
    Supersedes,
    Acknowledges,
    Rebuts,
    Closes,
}

impl LinkType {
    /// Every value, in the I-D's order.
    pub const ALL: [LinkType; 6] = [
        LinkType::Cites,
        LinkType::Adjudicates,
        LinkType::Supersedes,
        LinkType::Acknowledges,
        LinkType::Rebuts,
        LinkType::Closes,
    ];

    /// The wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            LinkType::Cites => "cites",
            LinkType::Adjudicates => "adjudicates",
            LinkType::Supersedes => "supersedes",
            LinkType::Acknowledges => "acknowledges",
            LinkType::Rebuts => "rebuts",
            LinkType::Closes => "closes",
        }
    }
}

/// A typed, directed reference from the carrying record to a target record,
/// named by the target's record id (I-D *Typed Links*). A link is committed
/// inside the carrying record and never mutates its target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    #[serde(rename = "type")]
    pub link_type: LinkType,
    pub target: String,
}

/// Record types the book itself writes. `record_type` stays open vocabulary
/// for callers; these are the ones this crate's semantics depend on. The
/// tokens match the Go implementation's.
pub mod record_types {
    /// A Close (I-D *Reconcile and Close*).
    pub const CLOSE: &str = "close";
    /// A disclosure record (I-D *Disclosure Records*).
    pub const DISCLOSURE: &str = "disclosure";
    /// A retention change (I-D *Retention States*).
    pub const LIFECYCLE: &str = "lifecycle";
    /// A committed authenticated-index root (I-D *Index Classes*).
    pub const INDEX_ROOT: &str = "index_root";
    /// A request this book sent.
    pub const REQUEST: &str = "evidence_request";
    /// A request this book answered.
    pub const REQUEST_ANSWERED: &str = "evidence_request_answered";
    /// A response this book received.
    pub const RESPONSE: &str = "evidence_response";
    /// The requester's own record that nothing arrived in its window.
    pub const RECORDED_ABSENCE: &str = "recorded_absence";
    /// A record carrying an `acknowledges` link to a counterparty's Close.
    pub const ACKNOWLEDGEMENT: &str = "acknowledgement";
    /// A record carrying a `rebuts` link to a counterparty's Close.
    pub const REBUTTAL: &str = "rebuttal";
}

/// The durable record header (I-D section anchor `record`). Its canonical JSON is
/// what a record commits to, so every field is fixed at commit. JSON member
/// names match the Go implementation's header.
///
/// `correlation` holds the calling profile's correlation keys by name. The
/// book never interprets a key's name; [`crate::reconcile::JoinPolicy`] says
/// which keys pair two halves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    #[serde(rename = "v")]
    pub version: u32,
    pub book_id: String,
    pub seq: u64,
    pub record_type: String,
    pub epistemic_type: EpistemicType,
    pub committed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_time_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub payload_commitments: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_state: Option<RetentionState>,
    pub links: Vec<Link>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparty_ref: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub correlation: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<serde_json::Value>,
}

impl Header {
    /// Check the header against the I-D's rules for a committed record:
    /// required fields present, `epistemic_type` and link types registered
    /// (enforced by the types), `retention_state` present whenever payload
    /// commitments are, every digest and link target a lowercase SHA-256 hex
    /// value, and `epistemic_type` `adjudication` on any record carrying an
    /// `adjudicates` link.
    pub fn validate(&self) -> Result<(), RecordError> {
        if self.version != HEADER_VERSION {
            return Err(RecordError::Invalid(format!(
                "header version {}",
                self.version
            )));
        }
        if self.book_id.is_empty()
            || self.seq == 0
            || self.record_type.is_empty()
            || self.committed_at.is_empty()
        {
            return Err(RecordError::Invalid(
                "book_id, seq, record_type and committed_at are required".into(),
            ));
        }
        if !self.payload_commitments.is_empty() && self.retention_state.is_none() {
            return Err(RecordError::Invalid(
                "retention_state is required with payload_commitments".into(),
            ));
        }
        if let Some(digest) = self.payload_commitments.iter().find(|d| !is_digest(d)) {
            return Err(RecordError::Invalid(format!(
                "payload commitment {digest:?} is not a lowercase SHA-256 digest"
            )));
        }
        for link in &self.links {
            if !is_digest(&link.target) {
                return Err(RecordError::Invalid(format!(
                    "link target {:?} is not a record id",
                    link.target
                )));
            }
            if link.link_type == LinkType::Adjudicates
                && self.epistemic_type != EpistemicType::Adjudication
            {
                return Err(RecordError::Invalid(
                    "a record carrying an adjudicates link must have epistemic_type adjudication"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    /// The targets of every link of type `link_type`, in header order.
    pub fn links_to(&self, link_type: LinkType) -> Vec<&str> {
        self.links
            .iter()
            .filter(|l| l.link_type == link_type)
            .map(|l| l.target.as_str())
            .collect()
    }
}

/// True when `s` is 64 lowercase hex characters.
pub fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecordError {
    #[error("epistemic_type {0:?} is not registered")]
    UnknownEpistemicType(String),
    #[error("invalid record header: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        Header {
            version: HEADER_VERSION,
            book_id: "book-a".into(),
            seq: 1,
            record_type: "observation".into(),
            epistemic_type: EpistemicType::ObservedEvent,
            committed_at: "2026-09-27T00:00:00Z".into(),
            event_time_claim: None,
            payload_commitments: vec![],
            retention_state: None,
            links: vec![],
            subject_ref: None,
            principal_ref: None,
            counterparty_ref: None,
            correlation: BTreeMap::new(),
            statement: None,
        }
    }

    #[test]
    fn epistemic_types_match_the_vendored_set() {
        let vendored: serde_json::Value =
            serde_json::from_str(VENDORED_EPISTEMIC_TYPES_JSON).unwrap();
        let values: Vec<String> = vendored["values"]
            .as_array()
            .expect("vendored file carries a values array")
            .iter()
            .map(|v| v.as_str().unwrap().to_ascii_lowercase())
            .collect();
        let ours: Vec<&str> = EpistemicType::ALL.iter().map(|t| t.as_str()).collect();
        assert_eq!(values, ours);
    }

    #[test]
    fn wire_tokens_round_trip_through_serde_and_from_str() {
        for t in EpistemicType::ALL {
            let json = serde_json::to_string(&t).unwrap();
            assert_eq!(json, format!("\"{}\"", t.as_str()));
            assert_eq!(t.as_str().parse::<EpistemicType>().unwrap(), t);
        }
        for t in LinkType::ALL {
            assert_eq!(
                serde_json::to_string(&t).unwrap(),
                format!("\"{}\"", t.as_str())
            );
        }
        assert!("OBSERVED_EVENT".parse::<EpistemicType>().is_err());
    }

    #[test]
    fn adjudicates_link_requires_an_adjudication_record() {
        let mut h = header();
        h.links.push(Link {
            link_type: LinkType::Adjudicates,
            target: "a".repeat(64),
        });
        assert!(h.validate().is_err());
        h.epistemic_type = EpistemicType::Adjudication;
        h.validate().unwrap();
    }

    #[test]
    fn payload_commitments_require_a_retention_state() {
        let mut h = header();
        h.payload_commitments.push("b".repeat(64));
        assert!(h.validate().is_err());
        h.retention_state = Some(RetentionState::Available);
        h.validate().unwrap();
    }

    #[test]
    fn digests_must_be_lowercase_sha256_hex() {
        let mut h = header();
        h.retention_state = Some(RetentionState::Available);
        h.payload_commitments.push("B".repeat(64));
        assert!(h.validate().is_err());
        let mut h = header();
        h.links.push(Link {
            link_type: LinkType::Cites,
            target: "not-a-digest".into(),
        });
        assert!(h.validate().is_err());
    }

    #[test]
    fn required_fields_are_required() {
        for broken in [
            Header { seq: 0, ..header() },
            Header {
                book_id: String::new(),
                ..header()
            },
            Header {
                record_type: String::new(),
                ..header()
            },
            Header {
                committed_at: String::new(),
                ..header()
            },
            Header {
                version: 2,
                ..header()
            },
        ] {
            assert!(broken.validate().is_err(), "{broken:?}");
        }
    }

    #[test]
    fn links_serialize_under_the_type_member_and_are_always_present() {
        let mut h = header();
        let empty = serde_json::to_value(&h).unwrap();
        assert_eq!(empty["links"], serde_json::json!([]));
        h.links.push(Link {
            link_type: LinkType::Supersedes,
            target: "c".repeat(64),
        });
        let v = serde_json::to_value(&h).unwrap();
        assert_eq!(v["links"][0]["type"], "supersedes");
        assert_eq!(h.links_to(LinkType::Supersedes), vec!["c".repeat(64)]);
        assert!(h.links_to(LinkType::Cites).is_empty());
    }
}
