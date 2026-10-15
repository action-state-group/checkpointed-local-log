//! The JSONL v4 backend: one log per append-only journal file
//! (docs/backend-contract.md, "JSONL v4"). Go, TypeScript and Python read and
//! write the same files.
//!
//! - [`JsonlStore::init`] creates the journal (writing `cll.init`) or, for an
//!   existing one, truncates an incomplete final line. [`JsonlStore::open`]
//!   requires an initialized journal and rejects a torn tail without
//!   changing the file.
//! - The writer holds a non-blocking exclusive `flock` on the journal
//!   descriptor itself, so writers in every language exclude each other; a
//!   second writer fails with `contention`.
//! - An event is durable once its line is written and fsynced. A failed write
//!   is truncated back to the previous durable offset.
//! - A version 3 journal is rejected as unsupported legacy data (`corrupt`).
//!
//! Available on Unix only, because the lock is `flock(2)`.

use super::engine::{self, Engine};
use super::wire::{self, WireEntry, WireState, WireWitness};
use super::{
    AppendInput, AppendOutcome, AppendResult, Backend, CheckpointStateStore, Entry, EntrySource,
    EntryStore, Error, ErrorCode, Result, State, Timestamp, WitnessState, WitnessStateStore,
    MAX_JOURNAL_EVENT_BYTES,
};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

const SCHEMA_VERSION: i64 = 4;

/// One journal event, with Go's field order.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Event {
    version: i64,
    #[serde(rename = "type")]
    kind: String,
    #[serde(
        default,
        deserialize_with = "wire::present",
        skip_serializing_if = "Option::is_none"
    )]
    entry: Option<WireEntry>,
    #[serde(
        default,
        deserialize_with = "wire::present",
        skip_serializing_if = "Option::is_none"
    )]
    expected_size: Option<String>,
    #[serde(
        default,
        deserialize_with = "wire::present",
        skip_serializing_if = "Option::is_none"
    )]
    expected_checkpoint: Option<String>,
    #[serde(
        default,
        deserialize_with = "wire::present",
        skip_serializing_if = "Option::is_none"
    )]
    state: Option<WireState>,
    #[serde(
        default,
        deserialize_with = "wire::present",
        skip_serializing_if = "Option::is_none"
    )]
    expected_attempts: Option<u32>,
    #[serde(
        default,
        deserialize_with = "wire::present",
        skip_serializing_if = "Option::is_none"
    )]
    witness: Option<WireWitness>,
}

impl Event {
    fn new(kind: &str) -> Self {
        Self {
            version: SCHEMA_VERSION,
            kind: kind.into(),
            ..Self::default()
        }
    }
}

/// A [`Backend`] over one JSONL v4 journal. The handle is the log's single
/// writer until it is closed or dropped.
#[derive(Debug)]
pub struct JsonlStore {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// `None` once closed.
    file: Option<File>,
    engine: Engine,
}

impl JsonlStore {
    /// Opens an initialized journal under the writer lock. A missing or
    /// uninitialized file, a torn tail or a malformed line fails without
    /// writing to the file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        open(path.as_ref(), false)
    }

    /// Creates the journal with its `cll.init` header, or validates an
    /// existing one and truncates only an incomplete final line. Complete
    /// corrupt lines are never removed. Repeating it is harmless.
    pub fn init(path: impl AsRef<Path>) -> Result<()> {
        open(path.as_ref(), true)?.close()
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.file.is_none() {
            return Err(Error::closed());
        }
        Ok(inner)
    }
}

fn open(path: &Path, initialize: bool) -> Result<JsonlStore> {
    if path.as_os_str().is_empty() {
        return Err(Error::invalid("journal path is required"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(initialize)
        .truncate(false)
        .mode(0o640)
        .open(path)
        .map_err(|e| Error::with_source(ErrorCode::Storage, "open JSONL journal", e))?;
    // SAFETY: flock only reads the descriptor, which `file` owns for the
    // duration of the call. The lock is released when the descriptor closes.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Error::with_source(
                ErrorCode::Contention,
                "JSONL journal already has a writer",
                error,
            )
        } else {
            Error::with_source(ErrorCode::Storage, "lock JSONL journal", error)
        });
    }
    let mut engine = Engine::default();
    replay(&mut file, &mut engine, initialize)?;
    let mut inner = Inner {
        file: Some(file),
        engine,
    };
    let empty = inner.file()?.metadata()?.len() == 0;
    if empty {
        if !initialize {
            return Err(Error::corrupt(
                "JSONL journal is not initialized; call init",
            ));
        }
        inner.append_event(&Event::new("cll.init"))?;
    }
    Ok(JsonlStore {
        inner: Mutex::new(inner),
    })
}

fn replay(file: &mut File, engine: &mut Engine, repair: bool) -> Result<()> {
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let mut valid_end = 0;
    let mut start = 0;
    while let Some(relative) = data[start..].iter().position(|&b| b == b'\n') {
        let end = start + relative;
        if end - start > MAX_JOURNAL_EVENT_BYTES {
            return Err(Error::corrupt("JSONL event exceeds the size limit"));
        }
        apply_line(engine, &data[start..end], valid_end == 0)
            .map_err(|e| Error::corrupt(format!("event at byte {start}: {}", e.message())))?;
        valid_end = end + 1;
        start = end + 1;
    }
    if valid_end != data.len() {
        if !repair {
            return Err(Error::corrupt(
                "incomplete final JSONL line; call init to recover",
            ));
        }
        file.set_len(valid_end as u64)?;
        file.sync_all()?;
    }
    file.seek(SeekFrom::End(0))?;
    Ok(())
}

fn apply_line(engine: &mut Engine, line: &[u8], first: bool) -> Result<()> {
    let text = std::str::from_utf8(line).map_err(|_| Error::corrupt("invalid UTF-8"))?;
    let header: serde_json::Value =
        serde_json::from_str(text).map_err(|e| Error::corrupt(format!("malformed JSON: {e}")))?;
    let version = header.get("version").and_then(serde_json::Value::as_i64);
    if version != Some(SCHEMA_VERSION) {
        let legacy =
            version == Some(3) || header.get("v").and_then(serde_json::Value::as_i64) == Some(3);
        return Err(Error::corrupt(if legacy {
            "legacy JSONL schema version 3 is unsupported"
        } else {
            "unsupported JSONL schema version"
        }));
    }
    let event: Event = serde_json::from_value(header)
        .map_err(|e| Error::corrupt(format!("malformed event: {e}")))?;
    if first && event.kind != "cll.init" {
        return Err(Error::corrupt("journal does not begin with cll.init"));
    }
    apply_event(engine, event).map_err(|e| e.recode(ErrorCode::Corrupt))
}

/// Replays one event with the same transition rules as a live mutation.
fn apply_event(engine: &mut Engine, event: Event) -> Result<()> {
    match event.kind.as_str() {
        "cll.init" => {
            if engine.entry_count() != 0 || engine.state().size != 0 {
                return Err(Error::corrupt("cll.init after state"));
            }
            if event.entry.is_some() || event.state.is_some() || event.witness.is_some() {
                return Err(Error::corrupt("cll.init carries state"));
            }
            Ok(())
        }
        "entry.append" => {
            let wire = event.entry.ok_or_else(|| Error::corrupt("missing entry"))?;
            engine.replay_entry(wire::entry_from_wire(&wire)?)
        }
        "cll.commit" => {
            let delta = event.state.ok_or_else(|| Error::corrupt("missing state"))?;
            let expected_size = wire::decode_decimal(
                event.expected_size.as_deref().unwrap_or_default(),
                ErrorCode::Corrupt,
            )?;
            let expected_checkpoint = event
                .expected_checkpoint
                .as_deref()
                .map(|c| wire::decode_bytes(c, ErrorCode::Corrupt))
                .transpose()?;
            let delta = wire::decode_state(&delta, ErrorCode::Corrupt)?;
            engine.commit_delta(expected_size, expected_checkpoint.as_deref(), delta)
        }
        "witness.commit" => {
            let (Some(expected), Some(row)) = (event.expected_attempts, event.witness) else {
                return Err(Error::corrupt("missing witness commit fields"));
            };
            let row = wire::witness_from_wire(&row)?;
            let (index, updated) = engine::commit_witness_in(engine.state(), expected, &row)?;
            engine.replace_witness(index, updated);
            Ok(())
        }
        other => Err(Error::corrupt(format!("unknown event type {other:?}"))),
    }
}

impl Inner {
    fn file(&mut self) -> Result<&mut File> {
        self.file.as_mut().ok_or_else(Error::closed)
    }

    /// Writes and fsyncs one complete line, or truncates back to the previous
    /// durable offset. If even that fails the handle closes, because its
    /// memory no longer matches the file.
    fn append_event(&mut self, event: &Event) -> Result<()> {
        let mut line = serde_json::to_vec(event)
            .map_err(|e| Error::with_source(ErrorCode::Storage, "encode JSONL event", e))?;
        line.push(b'\n');
        if line.len() > MAX_JOURNAL_EVENT_BYTES {
            return Err(Error::invalid("JSONL event exceeds the size limit"));
        }
        let file = self.file()?;
        let start = file.seek(SeekFrom::End(0))?;
        let written = file.write_all(&line).and_then(|()| file.sync_all());
        let Err(cause) = written else {
            return Ok(());
        };
        let rollback = file
            .set_len(start)
            .and_then(|()| file.seek(SeekFrom::Start(start)).map(drop))
            .and_then(|()| file.sync_all());
        match rollback {
            Ok(()) => Err(Error::with_source(
                ErrorCode::Storage,
                "write JSONL event",
                cause,
            )),
            Err(rollback) => {
                self.file = None;
                Err(Error::with_source(
                    ErrorCode::Corrupt,
                    format!("write JSONL event failed ({cause}) and rollback failed"),
                    rollback,
                ))
            }
        }
    }
}

impl EntrySource for JsonlStore {
    fn scan_entries(&self, after_seq: u64, limit: usize) -> Result<Vec<Entry>> {
        self.lock()?.engine.scan_entries(after_seq, limit)
    }
}

impl EntryStore for JsonlStore {
    fn append(&self, input: &AppendInput) -> Result<AppendResult> {
        let mut inner = self.lock()?;
        let result = inner.engine.prepare_append(input)?;
        if result.outcome == AppendOutcome::Inserted {
            let event = Event {
                entry: Some(wire::entry_to_wire(&result.entry)?),
                ..Event::new("entry.append")
            };
            inner.append_event(&event)?;
            inner.engine.insert(result.entry.clone());
        }
        Ok(result)
    }

    fn get_entry(&self, value: &[u8]) -> Result<Entry> {
        self.lock()?.engine.get_entry(value)
    }
}

impl CheckpointStateStore for JsonlStore {
    fn load_cll(&self) -> Result<State> {
        Ok(self.lock()?.engine.state().clone())
    }

    fn commit_cll(
        &self,
        expected_size: u64,
        expected_checkpoint: Option<&[u8]>,
        next: &State,
    ) -> Result<()> {
        let mut inner = self.lock()?;
        let current = inner.engine.state();
        let updated = engine::apply_cll(current, expected_size, expected_checkpoint, next)?;
        // The event carries only the nodes and witness rows this commit adds.
        let delta = State {
            size: updated.size,
            nodes: updated.nodes[current.nodes.len()..].to_vec(),
            indexed_seq: updated.indexed_seq,
            first_pending_at: updated.first_pending_at,
            checkpoint: updated.checkpoint.clone(),
            witnesses: updated.witnesses[current.witnesses.len()..].to_vec(),
        };
        let event = Event {
            expected_size: Some(expected_size.to_string()),
            expected_checkpoint: expected_checkpoint.map(wire::encode_bytes),
            state: Some(wire::state_to_wire(&delta)?),
            ..Event::new("cll.commit")
        };
        inner.append_event(&event)?;
        inner.engine.set_state(updated);
        Ok(())
    }
}

impl WitnessStateStore for JsonlStore {
    fn pending_witnesses(&self, now: Timestamp, limit: usize) -> Result<Vec<WitnessState>> {
        self.lock()?.engine.pending_witnesses(now, limit)
    }

    fn get_witness(&self, witness_id: &str, checkpoint_size: u64) -> Result<Option<WitnessState>> {
        self.lock()?.engine.get_witness(witness_id, checkpoint_size)
    }

    fn commit_witness(&self, expected_attempts: u32, next: &WitnessState) -> Result<()> {
        let mut inner = self.lock()?;
        let (index, updated) =
            engine::commit_witness_in(inner.engine.state(), expected_attempts, next)?;
        let event = Event {
            expected_attempts: Some(expected_attempts),
            witness: Some(wire::witness_to_wire(&updated)?),
            ..Event::new("witness.commit")
        };
        inner.append_event(&event)?;
        inner.engine.replace_witness(index, updated);
        Ok(())
    }
}

impl Backend for JsonlStore {
    /// Unlocks and closes the journal. Repeating it succeeds.
    fn close(&self) -> Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Dropping the descriptor releases the flock.
        drop(inner.file.take());
        Ok(())
    }
}
