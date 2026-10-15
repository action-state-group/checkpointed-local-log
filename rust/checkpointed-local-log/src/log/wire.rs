//! The portable JSON encodings (docs/backend-contract.md, "Portable
//! encodings"): decimal strings for counters, standard base64 for bytes,
//! `Date.toISOString()` times, absent rather than `null` optional fields.
//!
//! The JSONL journal and the SQL metadata and witness rows use these
//! encodings, and so do the conformance vectors. The public functions encode
//! a value for tools that compare logs across languages.

use super::{
    engine, CheckpointState, Entry, Error, ErrorCode, Result, State, Timestamp,
    WitnessReceiptState, WitnessState, ENTRY_BYTES, MAX_PORTABLE_INTEGER,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct WireEntry {
    pub seq: String,
    pub value: String,
    #[serde(rename = "appendedAt")]
    pub appended_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireWitness {
    pub witness_id: String,
    pub checkpoint_size: String,
    pub checkpoint: String,
    pub attempts: u32,
    pub next_attempt_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_hash_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_size: Option<i64>,
    pub permanent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireState {
    pub size: String,
    pub indexed_seq: String,
    pub nodes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_pending_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_indexed_seq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_peaks: Option<Vec<String>>,
    pub witnesses: Vec<WireWitness>,
}

pub(crate) fn encode_bytes(value: &[u8]) -> String {
    STANDARD.encode(value)
}

/// Decodes canonical standard base64 with padding; anything else is `code`.
pub(crate) fn decode_bytes(value: &str, code: ErrorCode) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|_| Error::new(code, "value is not canonical standard base64"))
}

/// Decodes a base-10 counter without sign or leading zero.
pub(crate) fn decode_decimal(value: &str, code: ErrorCode) -> Result<u64> {
    let canonical = !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'));
    canonical
        .then(|| value.parse::<u64>().ok())
        .flatten()
        .ok_or_else(|| Error::new(code, "counter is not a canonical decimal"))
}

fn decode_time(value: &str, code: ErrorCode) -> Result<Timestamp> {
    match Timestamp::parse(value) {
        Ok(time) if time.is_portable() => Ok(time),
        _ => Err(Error::new(
            code,
            "time is not a portable toISOString() time",
        )),
    }
}

pub(crate) fn entry_to_wire(entry: &Entry) -> Result<WireEntry> {
    Ok(WireEntry {
        seq: entry.seq.to_string(),
        value: encode_bytes(&entry.value),
        appended_at: entry.appended_at.to_iso_string()?,
    })
}

/// Decodes a durable entry; malformed fields are `corrupt`.
pub(crate) fn entry_from_wire(wire: &WireEntry) -> Result<Entry> {
    let code = ErrorCode::Corrupt;
    let seq = decode_decimal(&wire.seq, code)?;
    let value = decode_bytes(&wire.value, code)?;
    if seq == 0 || seq > MAX_PORTABLE_INTEGER || value.len() != ENTRY_BYTES {
        return Err(Error::corrupt("stored entry is invalid"));
    }
    Ok(Entry {
        seq,
        value,
        appended_at: decode_time(&wire.appended_at, code)?,
    })
}

pub(crate) fn witness_to_wire(value: &WitnessState) -> Result<WireWitness> {
    let receipt = value.receipt.as_ref();
    Ok(WireWitness {
        witness_id: value.witness_id.clone(),
        checkpoint_size: value.checkpoint_size.to_string(),
        checkpoint: encode_bytes(&value.checkpoint),
        attempts: value.attempts,
        next_attempt_at: value.next_attempt_at.to_iso_string()?,
        receipt: receipt.map(|r| encode_bytes(&r.bytes)),
        entry_hash: receipt.and_then(|r| r.entry_hash.clone()),
        entry_hash_scheme: receipt.and_then(|r| r.entry_hash_scheme.clone()),
        leaf_index: receipt.and_then(|r| r.leaf_index),
        tree_size: receipt.and_then(|r| r.tree_size),
        permanent: value.permanent,
        last_error: value.last_error.clone(),
    })
}

/// Decodes a durable witness row and applies the witness rules as `corrupt`.
pub(crate) fn witness_from_wire(wire: &WireWitness) -> Result<WitnessState> {
    let value = decode_witness(wire, ErrorCode::Corrupt)?;
    engine::validate_witness(&value, ErrorCode::Corrupt)?;
    Ok(value)
}

/// Decodes a witness without applying the witness rules; encoding errors
/// are reported as `code`.
pub(crate) fn decode_witness(wire: &WireWitness, code: ErrorCode) -> Result<WitnessState> {
    let receipt = match &wire.receipt {
        Some(bytes) => Some(WitnessReceiptState {
            bytes: decode_bytes(bytes, code)?,
            entry_hash: wire.entry_hash.clone(),
            entry_hash_scheme: wire.entry_hash_scheme.clone(),
            leaf_index: wire.leaf_index,
            tree_size: wire.tree_size,
        }),
        None if wire.entry_hash.is_some()
            || wire.entry_hash_scheme.is_some()
            || wire.leaf_index.is_some()
            || wire.tree_size.is_some() =>
        {
            return Err(Error::new(code, "receipt metadata without receipt bytes"));
        }
        None => None,
    };
    Ok(WitnessState {
        witness_id: wire.witness_id.clone(),
        checkpoint_size: decode_decimal(&wire.checkpoint_size, code)?,
        checkpoint: decode_bytes(&wire.checkpoint, code)?,
        attempts: wire.attempts,
        next_attempt_at: Timestamp::parse(&wire.next_attempt_at).map_err(|e| e.recode(code))?,
        receipt,
        permanent: wire.permanent,
        last_error: wire.last_error.clone(),
    })
}

pub(crate) fn state_to_wire(value: &State) -> Result<WireState> {
    let checkpoint = value.checkpoint.as_ref();
    Ok(WireState {
        size: value.size.to_string(),
        indexed_seq: value.indexed_seq.to_string(),
        nodes: value.nodes.iter().map(|n| encode_bytes(n)).collect(),
        first_pending_at: value
            .first_pending_at
            .map(Timestamp::to_iso_string)
            .transpose()?,
        checkpoint: checkpoint.map(|c| encode_bytes(&c.bytes)),
        checkpoint_size: checkpoint.map(|c| c.size.to_string()),
        checkpoint_indexed_seq: checkpoint.map(|c| c.indexed_seq.to_string()),
        checkpoint_peaks: checkpoint.map(|c| c.peaks.iter().map(|p| encode_bytes(p)).collect()),
        witnesses: value
            .witnesses
            .iter()
            .map(witness_to_wire)
            .collect::<Result<_>>()?,
    })
}

/// Decodes state without applying the state rules (a journal delta, or a
/// caller value); encoding errors are reported as `code`.
pub(crate) fn decode_state(wire: &WireState, code: ErrorCode) -> Result<State> {
    let checkpoint = match (
        &wire.checkpoint,
        &wire.checkpoint_size,
        &wire.checkpoint_indexed_seq,
        &wire.checkpoint_peaks,
    ) {
        (None, None, None, None) => None,
        (Some(bytes), Some(size), Some(indexed), Some(peaks)) => Some(CheckpointState {
            bytes: decode_bytes(bytes, code)?,
            size: decode_decimal(size, code)?,
            indexed_seq: decode_decimal(indexed, code)?,
            peaks: peaks
                .iter()
                .map(|p| decode_bytes(p, code))
                .collect::<Result<_>>()?,
        }),
        _ => return Err(Error::new(code, "checkpoint tuple is incomplete")),
    };
    Ok(State {
        size: decode_decimal(&wire.size, code)?,
        nodes: wire
            .nodes
            .iter()
            .map(|n| decode_bytes(n, code))
            .collect::<Result<_>>()?,
        indexed_seq: decode_decimal(&wire.indexed_seq, code)?,
        first_pending_at: wire
            .first_pending_at
            .as_deref()
            .map(|t| Timestamp::parse(t).map_err(|e| e.recode(code)))
            .transpose()?,
        checkpoint,
        witnesses: wire
            .witnesses
            .iter()
            .map(|w| decode_witness(w, code))
            .collect::<Result<_>>()?,
    })
}

fn to_value<T: Serialize>(wire: &T) -> serde_json::Value {
    serde_json::to_value(wire).expect("wire types always encode as JSON")
}

/// The portable JSON form of an entry. A time outside the portable range is
/// `invalid`.
pub fn entry_to_value(entry: &Entry) -> Result<serde_json::Value> {
    Ok(to_value(&entry_to_wire(entry)?))
}

/// The portable JSON form of a witness row, with the flattened receipt
/// fields (`receipt`, `entryHash`, ...).
pub fn witness_to_value(witness: &WitnessState) -> Result<serde_json::Value> {
    Ok(to_value(&witness_to_wire(witness)?))
}

/// The portable JSON form of a state, with the flattened checkpoint fields
/// (`checkpoint`, `checkpointSize`, ...).
pub fn state_to_value(state: &State) -> Result<serde_json::Value> {
    Ok(to_value(&state_to_wire(state)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimals_are_canonical() {
        assert_eq!(decode_decimal("0", ErrorCode::Corrupt).unwrap(), 0);
        assert_eq!(
            decode_decimal("18446744073709551615", ErrorCode::Corrupt).unwrap(),
            u64::MAX
        );
        for bad in ["", "01", "+1", "-1", "1.0", " 1", "18446744073709551616"] {
            assert_eq!(
                decode_decimal(bad, ErrorCode::Invalid).unwrap_err().code(),
                ErrorCode::Invalid,
                "{bad}"
            );
        }
    }

    #[test]
    fn base64_is_strict() {
        assert_eq!(decode_bytes("AQ==", ErrorCode::Corrupt).unwrap(), vec![1]);
        for bad in ["AQ", "AR==", "A Q==", "AQ==\n", "-_8="] {
            assert!(decode_bytes(bad, ErrorCode::Corrupt).is_err(), "{bad}");
        }
    }

    #[test]
    fn encodes_the_contract_examples_in_go_field_order() {
        let entry = Entry {
            seq: 1,
            value: vec![0; 32],
            appended_at: Timestamp::parse("2026-09-01T12:00:00.000Z").unwrap(),
        };
        assert_eq!(
            serde_json::to_string(&entry_to_wire(&entry).unwrap()).unwrap(),
            r#"{"seq":"1","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","appendedAt":"2026-09-01T12:00:00.000Z"}"#
        );
        assert_eq!(
            serde_json::to_string(&state_to_wire(&State::default()).unwrap()).unwrap(),
            r#"{"size":"0","indexedSeq":"0","nodes":[],"witnesses":[]}"#
        );
    }

    #[test]
    fn durable_decoding_is_corrupt_and_checks_receipt_metadata() {
        let mut wire = WireWitness {
            witness_id: "w".into(),
            checkpoint_size: "1".into(),
            checkpoint: "AQ==".into(),
            attempts: 0,
            next_attempt_at: "2026-09-01T12:00:00.000Z".into(),
            receipt: None,
            entry_hash: Some("ab".repeat(32)),
            entry_hash_scheme: None,
            leaf_index: None,
            tree_size: None,
            permanent: false,
            last_error: None,
        };
        assert_eq!(
            witness_from_wire(&wire).unwrap_err().code(),
            ErrorCode::Corrupt
        );
        wire.entry_hash = None;
        wire.next_attempt_at = "+275760-09-13T00:00:00.001Z".into();
        assert_eq!(
            witness_from_wire(&wire).unwrap_err().code(),
            ErrorCode::Corrupt
        );
        let entry = WireEntry {
            seq: "0".into(),
            value: encode_bytes(&[0; 32]),
            appended_at: "2026-09-01T12:00:00.000Z".into(),
        };
        assert_eq!(
            entry_from_wire(&entry).unwrap_err().code(),
            ErrorCode::Corrupt
        );
    }
}
