//! Row codecs shared by the SQLite and MySQL backends
//! (docs/backend-contract.md, "Relational schema").
//!
//! `cll_meta.state` holds the state JSON with empty `nodes` and `witnesses`;
//! `cll_nodes` and `cll_witnesses` are authoritative for those collections,
//! and witness JSON repeats the indexed `checkpoint_size` and `attempts`.

use super::wire::{self, WireState, WireWitness};
use super::{
    Entry, Error, Result, State, Timestamp, WitnessState, ENTRY_BYTES, MAX_PORTABLE_INTEGER,
};
use std::collections::HashSet;

/// The metadata projection: the state JSON without nodes and witness rows.
pub(crate) fn metadata_json(state: &State) -> Result<Vec<u8>> {
    encode(&wire::state_to_wire(&state.clone_header())?)
}

/// One complete witness row's JSON.
pub(crate) fn witness_json(row: &WitnessState) -> Result<Vec<u8>> {
    encode(&wire::witness_to_wire(row)?)
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| Error::corrupt(format!("encode row JSON: {e}")))
}

/// A stored witness row with its indexed columns.
pub(crate) struct WitnessRow {
    pub witness_id: String,
    pub checkpoint_size: String,
    pub attempts: i64,
    pub json: Vec<u8>,
}

/// Decodes a witness row and rejects JSON that disagrees with its index.
pub(crate) fn witness_from_row(row: &WitnessRow) -> Result<WitnessState> {
    let wire: WireWitness = serde_json::from_slice(&row.json)
        .map_err(|e| Error::corrupt(format!("decode witness row: {e}")))?;
    if wire.witness_id != row.witness_id
        || wire.checkpoint_size != row.checkpoint_size
        || i64::from(wire.attempts) != row.attempts
    {
        return Err(Error::corrupt("witness index disagrees with its JSON"));
    }
    wire::witness_from_wire(&wire)
}

/// Assembles and validates the full state from metadata, ordered node rows
/// and witness rows.
pub(crate) fn state_from_rows(
    metadata: &[u8],
    nodes: Vec<(u64, Vec<u8>)>,
    witnesses: &[WitnessRow],
) -> Result<State> {
    let mut wire: WireState = serde_json::from_slice(metadata)
        .map_err(|e| Error::corrupt(format!("decode CLL metadata: {e}")))?;
    wire.nodes.clear();
    wire.witnesses.clear();
    let mut state = wire::decode_state(&wire, super::ErrorCode::Corrupt)?;
    for (expected, (position, node)) in nodes.into_iter().enumerate() {
        if position != expected as u64 {
            return Err(Error::corrupt("stored node positions are not dense"));
        }
        state.nodes.push(node);
    }
    state.witnesses = witnesses
        .iter()
        .map(witness_from_row)
        .collect::<Result<_>>()?;
    super::engine::validate_state(&state, super::ErrorCode::Corrupt)?;
    Ok(state)
}

/// Decodes witness rows on their own (for `pendingWitnesses`), rejecting a
/// duplicated key.
pub(crate) fn witnesses_from_rows(rows: &[WitnessRow]) -> Result<Vec<WitnessState>> {
    let mut seen = HashSet::new();
    rows.iter()
        .map(|row| {
            let value = witness_from_row(row)?;
            if !seen.insert((value.witness_id.clone(), value.checkpoint_size)) {
                return Err(Error::corrupt("duplicate witness key"));
            }
            Ok(value)
        })
        .collect()
}

/// Decodes one stored entry row.
pub(crate) fn entry_from_row(seq: i128, value: Vec<u8>, appended_at: &str) -> Result<Entry> {
    if seq < 1 || seq > i128::from(MAX_PORTABLE_INTEGER) || value.len() != ENTRY_BYTES {
        return Err(Error::corrupt("stored entry is invalid"));
    }
    Ok(Entry {
        seq: seq as u64,
        value,
        appended_at: stored_time(appended_at)?,
    })
}

/// Checks one row of the open-time entry scan: dense from 1, 32 bytes, a
/// portable time.
pub(crate) fn check_entry_row(
    expected: u64,
    seq: i128,
    width: i64,
    appended_at: &str,
) -> Result<()> {
    if seq != i128::from(expected) || expected > MAX_PORTABLE_INTEGER || width != ENTRY_BYTES as i64
    {
        return Err(Error::corrupt("stored entries are not dense and valid"));
    }
    stored_time(appended_at).map(drop)
}

fn stored_time(text: &str) -> Result<Timestamp> {
    match Timestamp::parse(text) {
        Ok(time) if time.is_portable() => Ok(time),
        _ => Err(Error::corrupt("stored entry time is invalid")),
    }
}

/// The node and witness rows a commit adds, given the stored and new state.
pub(crate) fn added_rows<'a>(
    current: &State,
    updated: &'a State,
) -> (&'a [Vec<u8>], &'a [WitnessState]) {
    (
        &updated.nodes[current.nodes.len()..],
        &updated.witnesses[current.witnesses.len()..],
    )
}

impl State {
    /// The bounded fields of a state, without its nodes and witness rows.
    pub(crate) fn clone_header(&self) -> State {
        State {
            size: self.size,
            nodes: Vec::new(),
            indexed_seq: self.indexed_seq,
            first_pending_at: self.first_pending_at,
            checkpoint: self.checkpoint.clone(),
            witnesses: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_omits_collections_and_rows_must_agree() {
        let empty = metadata_json(&State::default()).unwrap();
        assert_eq!(
            empty,
            br#"{"size":"0","indexedSeq":"0","nodes":[],"witnesses":[]}"#
        );
        let row = WitnessRow {
            witness_id: "w".into(),
            checkpoint_size: "1".into(),
            attempts: 1,
            json: br#"{"witnessId":"w","checkpointSize":"1","checkpoint":"AQ==","attempts":0,"nextAttemptAt":"2026-09-01T12:00:00.000Z","permanent":false}"#.to_vec(),
        };
        assert_eq!(
            witness_from_row(&row).unwrap_err().code(),
            super::super::ErrorCode::Corrupt
        );
        let gap = state_from_rows(&empty, vec![(1, vec![0; 32])], &[]);
        assert_eq!(gap.unwrap_err().code(), super::super::ErrorCode::Corrupt);
        assert!(check_entry_row(1, 2, 32, "2026-09-01T12:00:00.000Z").is_err());
        assert!(entry_from_row(1, vec![0; 32], "2026-09-01T12:00:00Z").is_err());
    }
}
