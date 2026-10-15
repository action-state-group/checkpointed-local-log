//! The SQLite backend (Cargo feature `sqlite`): the shared relational schema
//! of docs/backend-contract.md, byte-for-byte the DDL Go, TypeScript and
//! Python use, so any of them opens a database another wrote.
//!
//! [`SqliteStore::init`] creates the tables (in WAL mode) and the log's
//! metadata row and is idempotent. [`SqliteStore::open`] requires both and
//! never creates them. Writers serialize with `BEGIN IMMEDIATE` and a bounded
//! busy wait; contention left after it is `contention`. One database holds
//! any number of logs, keyed by log ID, beside the application's own tables.

use super::engine;
use super::sql::{self, WitnessRow};
use super::{
    validate_identifier, AppendInput, AppendOutcome, AppendResult, Backend, CheckpointStateStore,
    Entry, EntrySource, EntryStore, Error, ErrorCode, Result, State, Timestamp, WitnessState,
    WitnessStateStore,
};
use rusqlite::types::ValueRef;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

/// The shared SQLite DDL (docs/backend-contract.md, "Relational schema").
pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS cll_meta (
  log_id TEXT PRIMARY KEY,
  state BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS cll_entries (
  log_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  value BLOB NOT NULL,
  appended_at TEXT NOT NULL,
  PRIMARY KEY(log_id, seq),
  UNIQUE(log_id, value)
);
CREATE TABLE IF NOT EXISTS cll_nodes (
  log_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  node BLOB NOT NULL,
  PRIMARY KEY(log_id, position)
);
CREATE TABLE IF NOT EXISTS cll_witnesses (
  log_id TEXT NOT NULL,
  witness_id TEXT NOT NULL,
  checkpoint_size TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  witness BLOB NOT NULL,
  PRIMARY KEY(log_id, witness_id, checkpoint_size)
);";

/// How long a writer waits for another before reporting `contention`.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// A [`Backend`] over one log in a SQLite database. The handle owns one
/// connection; operations on it serialize.
#[derive(Debug)]
pub struct SqliteStore {
    conn: Mutex<Option<Connection>>,
    log_id: String,
}

fn classify(error: rusqlite::Error) -> Error {
    let code = match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            ErrorCode::Contention
        }
        _ => ErrorCode::Storage,
    };
    Error::with_source(code, "SQLite", error)
}

/// Reads a BLOB or TEXT column as bytes: Go writes JSON as BLOB, TypeScript
/// as TEXT.
fn bytes(value: ValueRef<'_>) -> rusqlite::Result<Vec<u8>> {
    match value {
        ValueRef::Blob(b) | ValueRef::Text(b) => Ok(b.to_vec()),
        other => Err(rusqlite::Error::InvalidColumnType(
            0,
            "bytes".into(),
            other.data_type(),
        )),
    }
}

impl SqliteStore {
    /// Creates the schema (in WAL mode) and the log's metadata row if absent,
    /// then validates the log. Existing entries and state are preserved;
    /// repeating it is harmless.
    pub fn init(path: impl AsRef<Path>, log_id: &str) -> Result<()> {
        Self::connect(path.as_ref(), log_id, true)?.close()
    }

    /// Opens and validates an existing log without schema or data writes.
    pub fn open(path: impl AsRef<Path>, log_id: &str) -> Result<Self> {
        Self::connect(path.as_ref(), log_id, false)
    }

    fn connect(path: &Path, log_id: &str, initialize: bool) -> Result<Self> {
        if path.as_os_str().is_empty() {
            return Err(Error::invalid("database path is required"));
        }
        validate_identifier(log_id)?;
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if initialize {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let conn = Connection::open_with_flags(path, flags).map_err(classify)?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(classify)?;
        conn.execute_batch("PRAGMA foreign_keys=ON")
            .map_err(classify)?;
        if initialize {
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(classify)?;
            conn.execute_batch(SCHEMA).map_err(classify)?;
            conn.execute(
                "INSERT OR IGNORE INTO cll_meta(log_id,state) VALUES(?,?)",
                params![log_id, sql::metadata_json(&State::default())?],
            )
            .map_err(classify)?;
        }
        let store = Self {
            conn: Mutex::new(Some(conn)),
            log_id: log_id.to_owned(),
        };
        store.read(|tx, log_id| {
            validate_entries(tx, log_id)?;
            load_state(tx, log_id).map(drop)
        })?;
        Ok(store)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Option<Connection>>> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            return Err(Error::closed());
        }
        Ok(guard)
    }

    fn transaction<T>(
        &self,
        behavior: TransactionBehavior,
        operation: impl FnOnce(&Transaction<'_>, &str) -> Result<T>,
    ) -> Result<T> {
        let mut guard = self.connection()?;
        let conn = guard.as_mut().ok_or_else(Error::closed)?;
        let tx = conn.transaction_with_behavior(behavior).map_err(classify)?;
        let value = operation(&tx, &self.log_id)?;
        tx.commit().map_err(classify)?;
        Ok(value)
    }

    fn read<T>(&self, operation: impl FnOnce(&Transaction<'_>, &str) -> Result<T>) -> Result<T> {
        self.transaction(TransactionBehavior::Deferred, operation)
    }

    fn write<T>(&self, operation: impl FnOnce(&Transaction<'_>, &str) -> Result<T>) -> Result<T> {
        self.transaction(TransactionBehavior::Immediate, operation)
    }
}

fn validate_entries(tx: &Transaction<'_>, log_id: &str) -> Result<()> {
    let mut statement = tx
        .prepare(
            "SELECT seq,length(value),appended_at FROM cll_entries WHERE log_id=? ORDER BY seq",
        )
        .map_err(classify)?;
    let mut rows = statement.query([log_id]).map_err(classify)?;
    let mut expected = 1u64;
    while let Some(row) = rows.next().map_err(classify)? {
        let seq: i64 = row.get(0).map_err(classify)?;
        let width: i64 = row.get(1).map_err(classify)?;
        let at: String = row.get(2).map_err(classify)?;
        sql::check_entry_row(expected, i128::from(seq), width, &at)?;
        expected += 1;
    }
    Ok(())
}

fn witness_rows(tx: &Transaction<'_>, log_id: &str) -> Result<Vec<WitnessRow>> {
    let mut statement = tx
        .prepare(
            "SELECT witness_id,checkpoint_size,attempts,witness FROM cll_witnesses WHERE log_id=? ORDER BY checkpoint_size,witness_id",
        )
        .map_err(classify)?;
    let rows = statement
        .query_map([log_id], |row| {
            Ok(WitnessRow {
                witness_id: row.get(0)?,
                checkpoint_size: row.get(1)?,
                attempts: row.get(2)?,
                json: bytes(row.get_ref(3)?)?,
            })
        })
        .map_err(classify)?;
    rows.collect::<rusqlite::Result<_>>().map_err(classify)
}

fn load_state(tx: &Transaction<'_>, log_id: &str) -> Result<State> {
    let metadata = tx
        .query_row(
            "SELECT state FROM cll_meta WHERE log_id=?",
            [log_id],
            |row| bytes(row.get_ref(0)?),
        )
        .optional()
        .map_err(classify)?
        .ok_or_else(|| Error::corrupt("missing CLL metadata; call init"))?;
    let mut statement = tx
        .prepare("SELECT position,node FROM cll_nodes WHERE log_id=? ORDER BY position")
        .map_err(classify)?;
    let nodes = statement
        .query_map([log_id], |row| {
            Ok((row.get::<_, i64>(0)?, bytes(row.get_ref(1)?)?))
        })
        .map_err(classify)?
        .map(|row| row.map(|(position, node)| (u64::try_from(position).unwrap_or(u64::MAX), node)))
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(classify)?;
    sql::state_from_rows(&metadata, nodes, &witness_rows(tx, log_id)?)
}

fn find_entry(tx: &Transaction<'_>, log_id: &str, value: &[u8]) -> Result<Option<Entry>> {
    let row = tx
        .query_row(
            "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND value=?",
            params![log_id, value],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    bytes(row.get_ref(1)?)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(classify)?;
    row.map(|(seq, value, at)| sql::entry_from_row(i128::from(seq), value, &at))
        .transpose()
}

fn find_witness(
    tx: &Transaction<'_>,
    log_id: &str,
    witness_id: &str,
    checkpoint_size: u64,
) -> Result<Option<WitnessState>> {
    let size = checkpoint_size.to_string();
    let row = tx
        .query_row(
            "SELECT attempts,witness FROM cll_witnesses WHERE log_id=? AND witness_id=? AND checkpoint_size=?",
            params![log_id, witness_id, size],
            |row| Ok((row.get::<_, i64>(0)?, bytes(row.get_ref(1)?)?)),
        )
        .optional()
        .map_err(classify)?;
    row.map(|(attempts, json)| {
        sql::witness_from_row(&WitnessRow {
            witness_id: witness_id.to_owned(),
            checkpoint_size: size.clone(),
            attempts,
            json,
        })
    })
    .transpose()
}

impl EntrySource for SqliteStore {
    fn scan_entries(&self, after_seq: u64, limit: usize) -> Result<Vec<Entry>> {
        self.read(|tx, log_id| {
            engine::validate_scan(after_seq, limit)?;
            let mut statement = tx
                .prepare("SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND seq>? ORDER BY seq LIMIT ?")
                .map_err(classify)?;
            let rows = statement
                .query_map(params![log_id, after_seq as i64, limit as i64], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        bytes(row.get_ref(1)?)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(classify)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(classify)?;
            rows.into_iter()
                .map(|(seq, value, at)| sql::entry_from_row(i128::from(seq), value, &at))
                .collect()
        })
    }
}

impl EntryStore for SqliteStore {
    fn append(&self, input: &AppendInput) -> Result<AppendResult> {
        self.write(|tx, log_id| {
            engine::validate_append(input)?;
            if let Some(entry) = find_entry(tx, log_id, &input.value)? {
                return Ok(AppendResult {
                    entry,
                    outcome: AppendOutcome::Idempotent,
                });
            }
            // The next seq comes from the entry rows, never the MMR size.
            let last: Option<i64> = tx
                .query_row(
                    "SELECT MAX(seq) FROM cll_entries WHERE log_id=?",
                    [log_id],
                    |row| row.get(0),
                )
                .map_err(classify)?;
            let seq = last.map_or(1, |last| last as u64 + 1);
            if seq > super::MAX_PORTABLE_INTEGER {
                return Err(Error::invalid("entry sequence exceeds the portable range"));
            }
            tx.execute(
                "INSERT INTO cll_entries(log_id,seq,value,appended_at) VALUES(?,?,?,?)",
                params![
                    log_id,
                    seq as i64,
                    input.value,
                    input.appended_at.to_iso_string()?
                ],
            )
            .map_err(classify)?;
            Ok(AppendResult {
                entry: Entry {
                    seq,
                    value: input.value.clone(),
                    appended_at: input.appended_at,
                },
                outcome: AppendOutcome::Inserted,
            })
        })
    }

    fn get_entry(&self, value: &[u8]) -> Result<Entry> {
        self.read(|tx, log_id| {
            engine::validate_entry_value(value)?;
            find_entry(tx, log_id, value)?
                .ok_or_else(|| Error::not_found("no entry holds this value"))
        })
    }
}

impl CheckpointStateStore for SqliteStore {
    fn load_cll(&self) -> Result<State> {
        self.read(load_state)
    }

    fn commit_cll(
        &self,
        expected_size: u64,
        expected_checkpoint: Option<&[u8]>,
        next: &State,
    ) -> Result<()> {
        self.write(|tx, log_id| {
            let current = load_state(tx, log_id)?;
            let updated = engine::apply_cll(&current, expected_size, expected_checkpoint, next)?;
            tx.execute(
                "UPDATE cll_meta SET state=? WHERE log_id=?",
                params![sql::metadata_json(&updated)?, log_id],
            )
            .map_err(classify)?;
            let (nodes, witnesses) = sql::added_rows(&current, &updated);
            for (offset, node) in nodes.iter().enumerate() {
                tx.execute(
                    "INSERT INTO cll_nodes(log_id,position,node) VALUES(?,?,?)",
                    params![log_id, (current.nodes.len() + offset) as i64, node],
                )
                .map_err(classify)?;
            }
            for row in witnesses {
                tx.execute(
                    "INSERT INTO cll_witnesses(log_id,witness_id,checkpoint_size,attempts,witness) VALUES(?,?,?,?,?)",
                    params![
                        log_id,
                        row.witness_id,
                        row.checkpoint_size.to_string(),
                        row.attempts,
                        sql::witness_json(row)?
                    ],
                )
                .map_err(classify)?;
            }
            Ok(())
        })
    }
}

impl WitnessStateStore for SqliteStore {
    fn pending_witnesses(&self, now: Timestamp, limit: usize) -> Result<Vec<WitnessState>> {
        self.read(|tx, log_id| {
            let rows = sql::witnesses_from_rows(&witness_rows(tx, log_id)?)?;
            engine::pending_witnesses(&rows, now, limit)
        })
    }

    fn get_witness(&self, witness_id: &str, checkpoint_size: u64) -> Result<Option<WitnessState>> {
        self.read(|tx, log_id| {
            engine::validate_witness_key(witness_id, checkpoint_size)?;
            find_witness(tx, log_id, witness_id, checkpoint_size)
        })
    }

    fn commit_witness(&self, expected_attempts: u32, next: &WitnessState) -> Result<()> {
        self.write(|tx, log_id| {
            engine::validate_witness(next, ErrorCode::Invalid)?;
            let stored = find_witness(tx, log_id, &next.witness_id, next.checkpoint_size)?;
            let updated = engine::apply_witness(stored.as_ref(), expected_attempts, next)?;
            let changed = tx
                .execute(
                    "UPDATE cll_witnesses SET attempts=?,witness=? WHERE log_id=? AND witness_id=? AND checkpoint_size=? AND attempts=?",
                    params![
                        updated.attempts,
                        sql::witness_json(&updated)?,
                        log_id,
                        updated.witness_id,
                        updated.checkpoint_size.to_string(),
                        expected_attempts
                    ],
                )
                .map_err(classify)?;
            if changed != 1 {
                return Err(Error::contention("witness compare-and-set failed"));
            }
            Ok(())
        })
    }
}

impl Backend for SqliteStore {
    /// Closes the connection. Repeating it succeeds.
    fn close(&self) -> Result<()> {
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        match guard.take() {
            Some(conn) => conn.close().map_err(|(_, error)| classify(error)),
            None => Ok(()),
        }
    }
}
