//! Disclosure records.
//!
//! I-D section: *Disclosure Records*.
//!
//! A disclosure record is the store's own statement of what it chose to
//! reveal (`epistemic_type` `producer_claim`, [`EPISTEMIC_TYPE`]). It cites
//! each record whose material it discloses and never changes their retention
//! state. A field it withholds but acknowledges is listed with its committed
//! digest: never blank, never presented as nonexistent.

use crate::record::EpistemicType;
use serde::{Deserialize, Serialize};

/// The epistemic type every disclosure record carries.
pub const EPISTEMIC_TYPE: EpistemicType = EpistemicType::ProducerClaim;

/// Whether a disclosure carried all payload material the store considered,
/// or a selected subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadsMode {
    All,
    Selected,
}

/// One item a disclosure withheld, with the digest it committed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithheldItem {
    /// The record the item belongs to.
    pub record_id: String,
    /// The withheld field, or the payload commitment for a withheld payload.
    pub field: String,
    /// The committed digest of what was withheld.
    pub digest: String,
}

/// The body of a disclosure record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureStatement {
    pub payloads: PayloadsMode,
    #[serde(default)]
    pub suppressed_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withheld: Vec<WithheldItem>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_wire_shape() {
        let s = DisclosureStatement {
            payloads: PayloadsMode::Selected,
            suppressed_fields: vec!["agent_input".into()],
            withheld: vec![WithheldItem {
                record_id: "a".repeat(64),
                field: "agent_input".into(),
                digest: "b".repeat(64),
            }],
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["payloads"], "selected");
        assert_eq!(v["suppressed_fields"][0], "agent_input");
        assert_eq!(v["withheld"][0]["digest"], "b".repeat(64));
        let back: DisclosureStatement = serde_json::from_value(v).unwrap();
        assert_eq!(back, s);
        assert_eq!(EPISTEMIC_TYPE.as_str(), "producer_claim");
    }
}
