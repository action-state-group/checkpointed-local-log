//! The MySQL 8 backend (Cargo feature `mysql`): the shared relational schema
//! of docs/backend-contract.md, byte-for-byte the DDL Go, TypeScript and
//! Python use, so any of them opens a log another wrote.
//!
//! [`MysqlStore::init`] creates the tables and the log's metadata row and is
//! idempotent (MySQL DDL is not transactional, so it may be retried after a
//! partial failure). [`MysqlStore::open`] requires both and never creates
//! them. Writers serialize per log by locking its `cll_meta` row with
//! `SELECT ... FOR UPDATE`; `commitWitness` relies on its attempts
//! compare-and-set instead. A duplicate key, lock wait timeout or deadlock
//! is `contention`.
//!
//! The target is a `mysql://user:password@host:port/database` URL.

use super::engine;
use super::sql::{self, WitnessRow};
use super::{
    validate_identifier, AppendInput, AppendOutcome, AppendResult, Backend, CheckpointStateStore,
    Entry, EntrySource, EntryStore, Error, ErrorCode, Result, State, Timestamp, WitnessState,
    WitnessStateStore,
};
use ::mysql::consts::CapabilityFlags;
use ::mysql::prelude::Queryable;
use ::mysql::{
    AccessMode, IsolationLevel, Opts, OptsBuilder, Pool, PoolConstraints, PoolOpts, TxOpts,
};
use std::sync::RwLock;

/// The shared MySQL DDL (docs/backend-contract.md, "Relational schema"), one
/// statement per element.
pub const SCHEMA: [&str; 4] = [
    "CREATE TABLE IF NOT EXISTS cll_meta (
  log_id VARCHAR(191) PRIMARY KEY,
  state LONGBLOB NOT NULL
) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS cll_entries (
  log_id VARCHAR(191) NOT NULL,
  seq BIGINT UNSIGNED NOT NULL,
  value BINARY(32) NOT NULL,
  appended_at VARCHAR(32) NOT NULL,
  PRIMARY KEY(log_id, seq),
  UNIQUE KEY uq_cll_entry(log_id, value)
) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS cll_nodes (
  log_id VARCHAR(191) NOT NULL,
  position BIGINT UNSIGNED NOT NULL,
  node BINARY(32) NOT NULL,
  PRIMARY KEY(log_id, position)
) ENGINE=InnoDB",
    "CREATE TABLE IF NOT EXISTS cll_witnesses (
  log_id VARCHAR(191) NOT NULL,
  witness_id VARCHAR(191) NOT NULL,
  checkpoint_size VARCHAR(32) NOT NULL,
  attempts INT UNSIGNED NOT NULL,
  witness LONGBLOB NOT NULL,
  PRIMARY KEY(log_id, witness_id, checkpoint_size)
) ENGINE=InnoDB",
];

/// The most connections one handle opens.
const MAX_CONNECTIONS: usize = 8;

/// A [`Backend`] over one log in a MySQL 8 database. The handle owns a small
/// connection pool and can be shared across threads.
#[derive(Debug)]
pub struct MysqlStore {
    pool: RwLock<Option<Pool>>,
    log_id: String,
}

fn classify(error: ::mysql::Error) -> Error {
    let code = match &error {
        ::mysql::Error::MySqlError(e) if matches!(e.code, 1062 | 1205 | 1213) => {
            ErrorCode::Contention
        }
        _ => ErrorCode::Storage,
    };
    Error::with_source(code, "MySQL", error)
}

fn connect(url: &str, log_id: &str) -> Result<Pool> {
    validate_identifier(log_id)?;
    let opts =
        Opts::from_url(url).map_err(|e| Error::with_source(ErrorCode::Invalid, "MySQL URL", e))?;
    let constraints = PoolConstraints::new(0, MAX_CONNECTIONS).expect("0 <= max");
    let opts = OptsBuilder::from_opts(opts)
        .pool_opts(PoolOpts::default().with_constraints(constraints))
        // Report matched rather than changed rows, so a witness commit that
        // rewrites an identical row is not mistaken for a lost CAS.
        .additional_capabilities(CapabilityFlags::CLIENT_FOUND_ROWS);
    Pool::new(opts).map_err(classify)
}

impl MysqlStore {
    /// Creates the schema and the log's metadata row if absent, then
    /// validates the log. Existing records are preserved.
    pub fn init(url: &str, log_id: &str) -> Result<()> {
        let pool = connect(url, log_id)?;
        let mut conn = pool.get_conn().map_err(classify)?;
        for statement in SCHEMA {
            conn.query_drop(statement).map_err(classify)?;
        }
        conn.exec_drop(
            "INSERT IGNORE INTO cll_meta(log_id,state) VALUES(?,?)",
            (log_id, sql::metadata_json(&State::default())?),
        )
        .map_err(classify)?;
        drop(conn);
        Self::validated(pool, log_id)?.close()
    }

    /// Opens and validates an existing log without DDL or data writes.
    /// Reads need only SELECT; writes need the matching grants.
    pub fn open(url: &str, log_id: &str) -> Result<Self> {
        Self::validated(connect(url, log_id)?, log_id)
    }

    fn validated(pool: Pool, log_id: &str) -> Result<Self> {
        let store = Self {
            pool: RwLock::new(Some(pool)),
            log_id: log_id.to_owned(),
        };
        store.read(validate_entries)?;
        store.load_cll()?;
        Ok(store)
    }

    fn pool(&self) -> Result<std::sync::RwLockReadGuard<'_, Option<Pool>>> {
        let guard = self.pool.read().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            return Err(Error::closed());
        }
        Ok(guard)
    }

    /// Runs `operation` on a pooled connection outside a transaction.
    fn read<T>(
        &self,
        operation: impl FnOnce(&mut ::mysql::PooledConn, &str) -> Result<T>,
    ) -> Result<T> {
        let guard = self.pool()?;
        let pool = guard.as_ref().ok_or_else(Error::closed)?;
        let mut conn = pool.get_conn().map_err(classify)?;
        operation(&mut conn, &self.log_id)
    }

    /// Runs `operation` in a transaction, committing on success. Dropping an
    /// uncommitted transaction rolls it back.
    fn transaction<T>(
        &self,
        options: TxOpts,
        operation: impl FnOnce(&mut ::mysql::Transaction<'static>, &str) -> Result<T>,
    ) -> Result<T> {
        let guard = self.pool()?;
        let pool = guard.as_ref().ok_or_else(Error::closed)?;
        let mut tx = pool.start_transaction(options).map_err(classify)?;
        let value = operation(&mut tx, &self.log_id)?;
        tx.commit().map_err(classify)?;
        Ok(value)
    }

    fn write<T>(
        &self,
        operation: impl FnOnce(&mut ::mysql::Transaction<'static>, &str) -> Result<T>,
    ) -> Result<T> {
        self.transaction(TxOpts::default(), operation)
    }
}

fn lock_metadata(tx: &mut impl Queryable, log_id: &str) -> Result<Vec<u8>> {
    tx.exec_first::<Vec<u8>, _, _>(
        "SELECT state FROM cll_meta WHERE log_id=? FOR UPDATE",
        (log_id,),
    )
    .map_err(classify)?
    .ok_or_else(|| Error::corrupt("missing CLL metadata; call init"))
}

fn validate_entries(conn: &mut impl Queryable, log_id: &str) -> Result<()> {
    let rows: Vec<(u64, i64, String)> = conn
        .exec(
            "SELECT seq,OCTET_LENGTH(value),appended_at FROM cll_entries WHERE log_id=? ORDER BY seq",
            (log_id,),
        )
        .map_err(classify)?;
    for (expected, (seq, width, at)) in (1u64..).zip(rows) {
        sql::check_entry_row(expected, i128::from(seq), width, &at)?;
    }
    Ok(())
}

fn witness_rows(conn: &mut impl Queryable, log_id: &str) -> Result<Vec<WitnessRow>> {
    let rows: Vec<(String, String, i64, Vec<u8>)> = conn
        .exec(
            "SELECT witness_id,checkpoint_size,attempts,witness FROM cll_witnesses WHERE log_id=? ORDER BY checkpoint_size,witness_id",
            (log_id,),
        )
        .map_err(classify)?;
    Ok(rows
        .into_iter()
        .map(|(witness_id, checkpoint_size, attempts, json)| WitnessRow {
            witness_id,
            checkpoint_size,
            attempts,
            json,
        })
        .collect())
}

fn load_state(conn: &mut impl Queryable, log_id: &str, metadata: Option<Vec<u8>>) -> Result<State> {
    let metadata = match metadata {
        Some(metadata) => metadata,
        None => conn
            .exec_first::<Vec<u8>, _, _>("SELECT state FROM cll_meta WHERE log_id=?", (log_id,))
            .map_err(classify)?
            .ok_or_else(|| Error::corrupt("missing CLL metadata; call init"))?,
    };
    let nodes: Vec<(u64, Vec<u8>)> = conn
        .exec(
            "SELECT position,node FROM cll_nodes WHERE log_id=? ORDER BY position",
            (log_id,),
        )
        .map_err(classify)?;
    sql::state_from_rows(&metadata, nodes, &witness_rows(conn, log_id)?)
}

fn find_entry(conn: &mut impl Queryable, log_id: &str, value: &[u8]) -> Result<Option<Entry>> {
    conn.exec_first::<(u64, Vec<u8>, String), _, _>(
        "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND value=?",
        (log_id, value),
    )
    .map_err(classify)?
    .map(|(seq, value, at)| sql::entry_from_row(i128::from(seq), value, &at))
    .transpose()
}

fn find_witness(
    conn: &mut impl Queryable,
    log_id: &str,
    witness_id: &str,
    checkpoint_size: u64,
) -> Result<Option<WitnessState>> {
    let size = checkpoint_size.to_string();
    conn.exec_first::<(i64, Vec<u8>), _, _>(
        "SELECT attempts,witness FROM cll_witnesses WHERE log_id=? AND witness_id=? AND checkpoint_size=?",
        (log_id, witness_id, &size),
    )
    .map_err(classify)?
    .map(|(attempts, json)| {
        sql::witness_from_row(&WitnessRow {
            witness_id: witness_id.to_owned(),
            checkpoint_size: size.clone(),
            attempts,
            json,
        })
    })
    .transpose()
}

impl EntrySource for MysqlStore {
    fn scan_entries(&self, after_seq: u64, limit: usize) -> Result<Vec<Entry>> {
        self.read(|conn, log_id| {
            engine::validate_scan(after_seq, limit)?;
            let rows: Vec<(u64, Vec<u8>, String)> = conn
                .exec(
                    "SELECT seq,value,appended_at FROM cll_entries WHERE log_id=? AND seq>? ORDER BY seq LIMIT ?",
                    (log_id, after_seq, limit as u64),
                )
                .map_err(classify)?;
            rows.into_iter()
                .map(|(seq, value, at)| sql::entry_from_row(i128::from(seq), value, &at))
                .collect()
        })
    }
}

impl EntryStore for MysqlStore {
    fn append(&self, input: &AppendInput) -> Result<AppendResult> {
        self.write(|tx, log_id| {
            engine::validate_append(input)?;
            lock_metadata(tx, log_id)?;
            if let Some(entry) = find_entry(tx, log_id, &input.value)? {
                return Ok(AppendResult {
                    entry,
                    outcome: AppendOutcome::Idempotent,
                });
            }
            // The next seq comes from the entry rows, never the MMR size.
            let last: Option<u64> = tx
                .exec_first::<Option<u64>, _, _>(
                    "SELECT MAX(seq) FROM cll_entries WHERE log_id=?",
                    (log_id,),
                )
                .map_err(classify)?
                .flatten();
            let seq = last.map_or(1, |last| last + 1);
            if seq > super::MAX_PORTABLE_INTEGER {
                return Err(Error::invalid("entry sequence exceeds the portable range"));
            }
            tx.exec_drop(
                "INSERT INTO cll_entries(log_id,seq,value,appended_at) VALUES(?,?,?,?)",
                (
                    log_id,
                    seq,
                    &input.value,
                    input.appended_at.to_iso_string()?,
                ),
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
        self.read(|conn, log_id| {
            engine::validate_entry_value(value)?;
            find_entry(conn, log_id, value)?
                .ok_or_else(|| Error::not_found("no entry holds this value"))
        })
    }
}

impl CheckpointStateStore for MysqlStore {
    /// Reads metadata, nodes and witness rows in one consistent read-only
    /// snapshot; never reads entries.
    fn load_cll(&self) -> Result<State> {
        let options = TxOpts::default()
            .set_isolation_level(Some(IsolationLevel::RepeatableRead))
            .set_access_mode(Some(AccessMode::ReadOnly));
        self.transaction(options, |tx, log_id| load_state(tx, log_id, None))
    }

    fn commit_cll(
        &self,
        expected_size: u64,
        expected_checkpoint: Option<&[u8]>,
        next: &State,
    ) -> Result<()> {
        self.write(|tx, log_id| {
            let metadata = lock_metadata(tx, log_id)?;
            let current = load_state(tx, log_id, Some(metadata))?;
            let updated = engine::apply_cll(&current, expected_size, expected_checkpoint, next)?;
            tx.exec_drop(
                "UPDATE cll_meta SET state=? WHERE log_id=?",
                (sql::metadata_json(&updated)?, log_id),
            )
            .map_err(classify)?;
            let (nodes, witnesses) = sql::added_rows(&current, &updated);
            for (offset, node) in nodes.iter().enumerate() {
                tx.exec_drop(
                    "INSERT INTO cll_nodes(log_id,position,node) VALUES(?,?,?)",
                    (log_id, (current.nodes.len() + offset) as u64, node),
                )
                .map_err(classify)?;
            }
            for row in witnesses {
                tx.exec_drop(
                    "INSERT INTO cll_witnesses(log_id,witness_id,checkpoint_size,attempts,witness) VALUES(?,?,?,?,?)",
                    (
                        log_id,
                        &row.witness_id,
                        row.checkpoint_size.to_string(),
                        row.attempts,
                        sql::witness_json(row)?,
                    ),
                )
                .map_err(classify)?;
            }
            Ok(())
        })
    }
}

impl WitnessStateStore for MysqlStore {
    fn pending_witnesses(&self, now: Timestamp, limit: usize) -> Result<Vec<WitnessState>> {
        self.read(|conn, log_id| {
            let rows = sql::witnesses_from_rows(&witness_rows(conn, log_id)?)?;
            engine::pending_witnesses(&rows, now, limit)
        })
    }

    fn get_witness(&self, witness_id: &str, checkpoint_size: u64) -> Result<Option<WitnessState>> {
        self.read(|conn, log_id| {
            engine::validate_witness_key(witness_id, checkpoint_size)?;
            find_witness(conn, log_id, witness_id, checkpoint_size)
        })
    }

    fn commit_witness(&self, expected_attempts: u32, next: &WitnessState) -> Result<()> {
        self.write(|tx, log_id| {
            engine::validate_witness(next, ErrorCode::Invalid)?;
            let stored = find_witness(tx, log_id, &next.witness_id, next.checkpoint_size)?;
            let updated = engine::apply_witness(stored.as_ref(), expected_attempts, next)?;
            tx.exec_drop(
                "UPDATE cll_witnesses SET attempts=?,witness=? WHERE log_id=? AND witness_id=? AND checkpoint_size=? AND attempts=?",
                (
                    updated.attempts,
                    sql::witness_json(&updated)?,
                    log_id,
                    &updated.witness_id,
                    updated.checkpoint_size.to_string(),
                    expected_attempts,
                ),
            )
            .map_err(classify)?;
            if tx.affected_rows() != 1 {
                return Err(Error::contention("witness compare-and-set failed"));
            }
            Ok(())
        })
    }
}

impl Backend for MysqlStore {
    /// Waits for operations on this handle, then closes its connections.
    /// Repeating it succeeds.
    fn close(&self) -> Result<()> {
        drop(self.pool.write().unwrap_or_else(|e| e.into_inner()).take());
        Ok(())
    }
}
