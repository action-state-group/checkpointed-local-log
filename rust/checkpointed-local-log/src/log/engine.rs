//! The one transition engine every Rust backend shares: argument validation,
//! the contract's check order, idempotent append, the CLL compare-and-set,
//! the witness merge and the pending-witness order
//! (docs/backend-contract.md, "Operations"). It ports Go's
//! `internal/backend/engine.go`.
//!
//! Validation helpers take the error code to report, because the same rule
//! is `invalid` for a caller value and `corrupt` for durable data.

use super::{
    AppendInput, AppendOutcome, AppendResult, CheckpointState, Entry, Error, ErrorCode, Result,
    State, Timestamp, WitnessState, ENTRY_BYTES, MAX_CHECKPOINT_BYTES, MAX_PORTABLE_INTEGER,
    MAX_REASON_BYTES, MAX_SCAN_LIMIT, MAX_WITNESSES, MAX_WITNESS_RESPONSE_BYTES,
};
use std::collections::{HashMap, HashSet};

/// In-memory entries and state with the contract's transition rules. Callers
/// serialize access.
#[derive(Debug, Default)]
pub(crate) struct Engine {
    entries: Vec<Entry>,
    by_value: HashMap<Vec<u8>, usize>,
    state: State,
}

impl Engine {
    pub(crate) fn state(&self) -> &State {
        &self.state
    }

    pub(crate) fn set_state(&mut self, state: State) {
        self.state = state;
    }

    /// Replaces the witness row at `index` (from [`commit_witness_in`]).
    pub(crate) fn replace_witness(&mut self, index: usize, row: WitnessState) {
        self.state.witnesses[index] = row;
    }

    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Validates `input` and returns either the stored entry
    /// ([`AppendOutcome::Idempotent`]) or the entry an insert would create,
    /// without storing it. A durable backend persists it, then calls
    /// [`Engine::insert`].
    pub(crate) fn prepare_append(&self, input: &AppendInput) -> Result<AppendResult> {
        validate_append(input)?;
        if let Some(&index) = self.by_value.get(&input.value) {
            return Ok(AppendResult {
                entry: self.entries[index].clone(),
                outcome: AppendOutcome::Idempotent,
            });
        }
        let seq = self.entries.len() as u64 + 1;
        if seq > MAX_PORTABLE_INTEGER {
            return Err(Error::invalid("entry sequence exceeds the portable range"));
        }
        Ok(AppendResult {
            entry: Entry {
                seq,
                value: input.value.clone(),
                appended_at: input.appended_at,
            },
            outcome: AppendOutcome::Inserted,
        })
    }

    /// Stores an entry [`Engine::prepare_append`] returned as inserted.
    pub(crate) fn insert(&mut self, entry: Entry) {
        self.by_value
            .insert(entry.value.clone(), self.entries.len());
        self.entries.push(entry);
    }

    /// Replays one durable entry, which must be the next dense, new, valid one.
    pub(crate) fn replay_entry(&mut self, entry: Entry) -> Result<()> {
        if entry.seq != self.entries.len() as u64 + 1
            || entry.seq > MAX_PORTABLE_INTEGER
            || entry.value.len() != ENTRY_BYTES
            || !entry.appended_at.is_portable()
            || self.by_value.contains_key(&entry.value)
        {
            return Err(Error::corrupt(
                "stored entries are not dense, distinct and valid",
            ));
        }
        self.insert(entry);
        Ok(())
    }

    pub(crate) fn get_entry(&self, value: &[u8]) -> Result<Entry> {
        validate_entry_value(value)?;
        self.by_value
            .get(value)
            .map(|&index| self.entries[index].clone())
            .ok_or_else(|| Error::not_found("no entry holds this value"))
    }

    pub(crate) fn scan_entries(&self, after_seq: u64, limit: usize) -> Result<Vec<Entry>> {
        validate_scan(after_seq, limit)?;
        let start = usize::try_from(after_seq)
            .unwrap_or(usize::MAX)
            .min(self.entries.len());
        let end = start.saturating_add(limit).min(self.entries.len());
        Ok(self.entries[start..end].to_vec())
    }

    /// Applies a journal `cll.commit` whose nodes and witnesses hold only the
    /// rows it adds, without rebuilding log-sized collections.
    pub(crate) fn commit_delta(
        &mut self,
        expected_size: u64,
        expected_checkpoint: Option<&[u8]>,
        delta: State,
    ) -> Result<()> {
        let current = &self.state;
        if current.size != expected_size
            || !same_checkpoint(current.checkpoint.as_ref(), expected_checkpoint)
        {
            return Err(Error::contention("CLL state changed"));
        }
        let added = delta.nodes.len() as u64;
        if current.size.checked_add(added) != Some(delta.size) {
            return Err(Error::invalid("CLL node delta does not match size"));
        }
        validate_state_metadata(&delta, delta.size, ErrorCode::Invalid)?;
        if delta.nodes.iter().any(|node| node.len() != ENTRY_BYTES) {
            return Err(Error::invalid("node has the wrong width"));
        }
        let added_witnesses = validate_transition(current, &delta)?;
        let State {
            size,
            nodes,
            indexed_seq,
            first_pending_at,
            checkpoint,
            ..
        } = delta;
        let state = &mut self.state;
        state.size = size;
        state.indexed_seq = indexed_seq;
        state.first_pending_at = first_pending_at;
        state.checkpoint = checkpoint;
        state.nodes.extend(nodes);
        state.witnesses.extend(added_witnesses);
        Ok(())
    }

    pub(crate) fn pending_witnesses(
        &self,
        now: Timestamp,
        limit: usize,
    ) -> Result<Vec<WitnessState>> {
        pending_witnesses(&self.state.witnesses, now, limit)
    }

    pub(crate) fn get_witness(
        &self,
        witness_id: &str,
        checkpoint_size: u64,
    ) -> Result<Option<WitnessState>> {
        validate_witness_key(witness_id, checkpoint_size)?;
        Ok(self
            .state
            .witnesses
            .iter()
            .find(|row| row.witness_id == witness_id && row.checkpoint_size == checkpoint_size)
            .cloned())
    }
}

pub(crate) fn validate_entry_value(value: &[u8]) -> Result<()> {
    if value.len() == ENTRY_BYTES {
        Ok(())
    } else {
        Err(Error::invalid(format!(
            "entry value is {} bytes, not {ENTRY_BYTES}",
            value.len()
        )))
    }
}

pub(crate) fn validate_append(input: &AppendInput) -> Result<()> {
    validate_entry_value(&input.value)?;
    if !input.appended_at.is_portable() {
        return Err(Error::invalid("append time is outside the portable range"));
    }
    Ok(())
}

pub(crate) fn validate_scan(after_seq: u64, limit: usize) -> Result<()> {
    if after_seq > MAX_PORTABLE_INTEGER || !(1..=MAX_SCAN_LIMIT).contains(&limit) {
        return Err(Error::invalid("entry scan arguments are out of range"));
    }
    Ok(())
}

pub(crate) fn validate_witness_key(witness_id: &str, checkpoint_size: u64) -> Result<()> {
    super::validate_identifier(witness_id)?;
    if checkpoint_size == 0 {
        return Err(Error::invalid("witness checkpoint size must be above 0"));
    }
    Ok(())
}

/// The `commitCll` compare-and-set: compares, validates `next`, applies the
/// transition rules, and returns the new state (existing witness rows kept as
/// stored, new keys appended).
pub(crate) fn apply_cll(
    current: &State,
    expected_size: u64,
    expected_checkpoint: Option<&[u8]>,
    next: &State,
) -> Result<State> {
    if current.size != expected_size
        || !same_checkpoint(current.checkpoint.as_ref(), expected_checkpoint)
    {
        return Err(Error::contention("CLL state changed"));
    }
    validate_state(next, ErrorCode::Invalid)?;
    if next.size < current.size
        || next.indexed_seq < current.indexed_seq
        || next.nodes.len() < current.nodes.len()
        || next.nodes[..current.nodes.len()] != current.nodes[..]
    {
        return Err(Error::invalid("CLL state is not append-only"));
    }
    let added = validate_transition(current, next)?;
    let mut witnesses = current.witnesses.clone();
    witnesses.extend(added);
    Ok(State {
        size: next.size,
        nodes: next.nodes.clone(),
        indexed_seq: next.indexed_seq,
        first_pending_at: next.first_pending_at,
        checkpoint: next.checkpoint.clone(),
        witnesses,
    })
}

/// The checkpoint and witness-merge rules shared by live commits and journal
/// replay. Returns the witness rows `next` adds.
fn validate_transition(current: &State, next: &State) -> Result<Vec<WitnessState>> {
    if next.indexed_seq < current.indexed_seq {
        return Err(Error::invalid("CLL state is not append-only"));
    }
    match (&current.checkpoint, &next.checkpoint) {
        (Some(_), None) => return Err(Error::contention("checkpoint cannot be removed")),
        (Some(old), Some(new)) => {
            if new.size < old.size || new.indexed_seq < old.indexed_seq {
                return Err(Error::contention("checkpoint moved backward"));
            }
            if new.size == old.size && new != old {
                return Err(Error::contention("checkpoint changed at an existing size"));
            }
        }
        _ => {}
    }
    let existing: HashMap<(&str, u64), &WitnessState> = current
        .witnesses
        .iter()
        .map(|row| ((row.witness_id.as_str(), row.checkpoint_size), row))
        .collect();
    let mut seen = HashSet::new();
    let mut added = Vec::new();
    for row in &next.witnesses {
        let key = (row.witness_id.as_str(), row.checkpoint_size);
        if !seen.insert(key) {
            return Err(Error::invalid("duplicate witness key"));
        }
        match existing.get(&key) {
            Some(stored) if stored.checkpoint != row.checkpoint => {
                return Err(Error::contention("witness checkpoint changed"));
            }
            Some(_) => {}
            None => added.push(row.clone()),
        }
    }
    Ok(added)
}

/// The `commitWitness` compare-and-set against the stored row for `next`'s
/// key (`None` when there is none). Returns the row to store.
pub(crate) fn apply_witness(
    stored: Option<&WitnessState>,
    expected_attempts: u32,
    next: &WitnessState,
) -> Result<WitnessState> {
    validate_witness(next, ErrorCode::Invalid)?;
    let Some(stored) = stored else {
        return Err(Error::contention("witness state changed"));
    };
    if stored.attempts != expected_attempts {
        return Err(Error::contention("witness state changed"));
    }
    if stored.checkpoint != next.checkpoint {
        return Err(Error::contention("witness checkpoint changed"));
    }
    Ok(next.clone())
}

/// Replaces the row for `next`'s key in `state` after [`apply_witness`].
pub(crate) fn commit_witness_in(
    state: &State,
    expected_attempts: u32,
    next: &WitnessState,
) -> Result<(usize, WitnessState)> {
    let index = state.witnesses.iter().position(|row| {
        row.witness_id == next.witness_id && row.checkpoint_size == next.checkpoint_size
    });
    let updated = apply_witness(index.map(|i| &state.witnesses[i]), expected_attempts, next)?;
    // apply_witness fails when there is no stored row.
    Ok((index.unwrap_or_default(), updated))
}

pub(crate) fn pending_witnesses(
    rows: &[WitnessState],
    now: Timestamp,
    limit: usize,
) -> Result<Vec<WitnessState>> {
    if !now.is_portable() || !(1..=MAX_WITNESSES).contains(&limit) {
        return Err(Error::invalid("pending witness query is out of range"));
    }
    let mut due: Vec<&WitnessState> = rows
        .iter()
        .filter(|row| row.receipt.is_none() && !row.permanent && row.next_attempt_at <= now)
        .collect();
    due.sort_by(|a, b| {
        (a.checkpoint_size, a.witness_id.as_bytes())
            .cmp(&(b.checkpoint_size, b.witness_id.as_bytes()))
    });
    Ok(due.into_iter().take(limit).cloned().collect())
}

pub(crate) fn validate_state(value: &State, code: ErrorCode) -> Result<()> {
    validate_state_metadata(value, value.nodes.len() as u64, code)?;
    if value.nodes.iter().any(|node| node.len() != ENTRY_BYTES) {
        return Err(Error::new(code, "node has the wrong width"));
    }
    Ok(())
}

fn validate_state_metadata(value: &State, node_count: u64, code: ErrorCode) -> Result<()> {
    if value.size != node_count {
        return Err(Error::new(code, "CLL size does not match the nodes"));
    }
    match crate::mmr::leaf_count(value.size) {
        Ok(leaves) if leaves == value.indexed_seq => {}
        _ => {
            return Err(Error::new(
                code,
                "CLL nodes do not form the MMR of indexedSeq leaves",
            ))
        }
    }
    if value.first_pending_at.is_some_and(|at| !at.is_portable()) {
        return Err(Error::new(
            code,
            "pending time is outside the portable range",
        ));
    }
    if let Some(checkpoint) = &value.checkpoint {
        validate_checkpoint(checkpoint, value, code)?;
    }
    let mut seen = HashSet::new();
    for row in &value.witnesses {
        validate_witness(row, code)?;
        if !seen.insert((row.witness_id.as_str(), row.checkpoint_size)) {
            return Err(Error::new(code, "duplicate witness key"));
        }
    }
    Ok(())
}

fn validate_checkpoint(checkpoint: &CheckpointState, state: &State, code: ErrorCode) -> Result<()> {
    if checkpoint.bytes.is_empty()
        || checkpoint.bytes.len() > MAX_CHECKPOINT_BYTES
        || checkpoint.size == 0
        || checkpoint.size > state.size
        || checkpoint.indexed_seq > state.indexed_seq
    {
        return Err(Error::new(code, "checkpoint state is invalid"));
    }
    if checkpoint
        .peaks
        .iter()
        .any(|peak| peak.len() != ENTRY_BYTES)
    {
        return Err(Error::new(code, "checkpoint peak has the wrong width"));
    }
    Ok(())
}

pub(crate) fn validate_witness(value: &WitnessState, code: ErrorCode) -> Result<()> {
    if super::validate_identifier(&value.witness_id).is_err()
        || value.checkpoint_size == 0
        || value.checkpoint.is_empty()
        || value.checkpoint.len() > MAX_CHECKPOINT_BYTES
        || !value.next_attempt_at.is_portable()
        || value
            .last_error
            .as_ref()
            .is_some_and(|e| e.len() > MAX_REASON_BYTES)
    {
        return Err(Error::new(code, "witness state is invalid"));
    }
    if let Some(receipt) = &value.receipt {
        if receipt.bytes.is_empty() || receipt.bytes.len() > MAX_WITNESS_RESPONSE_BYTES {
            return Err(Error::new(code, "witness receipt is invalid"));
        }
        if receipt.entry_hash.as_deref().is_some_and(|hash| {
            hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        }) {
            return Err(Error::new(code, "witness entry hash is invalid"));
        }
        if receipt
            .entry_hash_scheme
            .as_deref()
            .is_some_and(|scheme| scheme != "legacy")
        {
            return Err(Error::new(code, "witness entry hash scheme is invalid"));
        }
        let in_range = |position: Option<i64>| {
            position.is_none_or(|p| p >= 0 && p.unsigned_abs() <= MAX_PORTABLE_INTEGER)
        };
        if !in_range(receipt.leaf_index) || !in_range(receipt.tree_size) {
            return Err(Error::new(code, "witness receipt position is invalid"));
        }
    }
    Ok(())
}

fn same_checkpoint(current: Option<&CheckpointState>, expected: Option<&[u8]>) -> bool {
    match (current, expected) {
        (None, None) => true,
        (Some(checkpoint), Some(expected)) => checkpoint.bytes == expected,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::WitnessReceiptState;

    fn witness(id: &str, size: u64) -> WitnessState {
        WitnessState {
            witness_id: id.into(),
            checkpoint_size: size,
            checkpoint: vec![1],
            attempts: 0,
            next_attempt_at: Timestamp::from_unix_millis(0),
            receipt: None,
            permanent: false,
            last_error: None,
        }
    }

    #[test]
    fn delta_replay_matches_a_full_commit() {
        let next = State {
            size: 3,
            nodes: vec![vec![1; 32], vec![2; 32], vec![3; 32]],
            indexed_seq: 2,
            witnesses: vec![witness("w", 3)],
            ..State::default()
        };
        let full = apply_cll(&State::default(), 0, None, &next).unwrap();
        let mut engine = Engine::default();
        engine.commit_delta(0, None, next.clone()).unwrap();
        assert_eq!(engine.state(), &full);
        assert_eq!(
            engine
                .commit_delta(0, None, State::default())
                .unwrap_err()
                .code(),
            ErrorCode::Contention
        );
        let wrong = State {
            size: 9,
            ..State::default()
        };
        assert_eq!(
            engine.commit_delta(3, None, wrong).unwrap_err().code(),
            ErrorCode::Invalid
        );
    }

    #[test]
    fn replay_rejects_gaps_duplicates_and_bad_values() {
        let entry = |seq, byte| Entry {
            seq,
            value: vec![byte; 32],
            appended_at: Timestamp::from_unix_millis(0),
        };
        let mut engine = Engine::default();
        engine.replay_entry(entry(1, 1)).unwrap();
        for bad in [
            entry(3, 2),
            entry(2, 1),
            Entry {
                value: vec![2; 31],
                ..entry(2, 2)
            },
        ] {
            assert_eq!(
                engine.replay_entry(bad).unwrap_err().code(),
                ErrorCode::Corrupt
            );
        }
        assert_eq!(engine.entry_count(), 1);
    }

    #[test]
    fn witness_validation_reports_the_requested_code() {
        let mut row = witness("w", 1);
        row.receipt = Some(WitnessReceiptState {
            bytes: vec![1],
            tree_size: Some(-1),
            ..WitnessReceiptState::default()
        });
        assert_eq!(
            validate_witness(&row, ErrorCode::Corrupt)
                .unwrap_err()
                .code(),
            ErrorCode::Corrupt
        );
        assert!(commit_witness_in(&State::default(), 0, &witness("w", 1)).is_err());
    }
}
