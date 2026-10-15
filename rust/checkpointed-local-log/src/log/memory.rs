//! The in-memory backend: a [`Backend`] with no durable state
//! (docs/backend-contract.md). It has only a constructor.

use super::engine::{self, Engine};
use super::{
    AppendInput, AppendOutcome, AppendResult, Backend, CheckpointStateStore, Entry, EntrySource,
    EntryStore, Error, Result, State, Timestamp, WitnessState, WitnessStateStore,
};
use std::sync::{Mutex, MutexGuard};

/// An in-memory [`Backend`]. Share one handle across threads by reference or
/// in an `Arc`.
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    engine: Engine,
    closed: bool,
}

impl MemoryStore {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    fn open(&self) -> Result<MutexGuard<'_, Inner>> {
        // A panic cannot leave the engine half-mutated: every mutation is a
        // single assignment or push after validation.
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.closed {
            return Err(Error::closed());
        }
        Ok(inner)
    }
}

impl EntrySource for MemoryStore {
    fn scan_entries(&self, after_seq: u64, limit: usize) -> Result<Vec<Entry>> {
        self.open()?.engine.scan_entries(after_seq, limit)
    }
}

impl EntryStore for MemoryStore {
    fn append(&self, input: &AppendInput) -> Result<AppendResult> {
        let mut inner = self.open()?;
        let result = inner.engine.prepare_append(input)?;
        if result.outcome == AppendOutcome::Inserted {
            inner.engine.insert(result.entry.clone());
        }
        Ok(result)
    }

    fn get_entry(&self, value: &[u8]) -> Result<Entry> {
        self.open()?.engine.get_entry(value)
    }
}

impl CheckpointStateStore for MemoryStore {
    fn load_cll(&self) -> Result<State> {
        Ok(self.open()?.engine.state().clone())
    }

    fn commit_cll(
        &self,
        expected_size: u64,
        expected_checkpoint: Option<&[u8]>,
        next: &State,
    ) -> Result<()> {
        let mut inner = self.open()?;
        let updated = engine::apply_cll(
            inner.engine.state(),
            expected_size,
            expected_checkpoint,
            next,
        )?;
        inner.engine.set_state(updated);
        Ok(())
    }
}

impl WitnessStateStore for MemoryStore {
    fn pending_witnesses(&self, now: Timestamp, limit: usize) -> Result<Vec<WitnessState>> {
        self.open()?.engine.pending_witnesses(now, limit)
    }

    fn get_witness(&self, witness_id: &str, checkpoint_size: u64) -> Result<Option<WitnessState>> {
        self.open()?.engine.get_witness(witness_id, checkpoint_size)
    }

    fn commit_witness(&self, expected_attempts: u32, next: &WitnessState) -> Result<()> {
        let mut inner = self.open()?;
        let (index, updated) =
            engine::commit_witness_in(inner.engine.state(), expected_attempts, next)?;
        inner.engine.replace_witness(index, updated);
        Ok(())
    }
}

impl Backend for MemoryStore {
    fn close(&self) -> Result<()> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).closed = true;
        Ok(())
    }
}
