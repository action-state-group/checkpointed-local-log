//! The CLL entry log, checkpoint state and witness state: the storage
//! interfaces every CLL backend implements, in every language.
//!
//! [`docs/backend-contract.md`] is the source of truth for everything here:
//! the operations and their argument order, the error codes and the order in
//! which they are checked, the not-found convention, capabilities, limits and
//! the portable JSONL and SQL formats. The shared conformance vectors turn it
//! into cases; [`conformance`] runs them against any backend, built-in or
//! user-supplied.
//!
//! | Contract | Trait |
//! |---|---|
//! | Entry source (`scanEntries`) | [`EntrySource`] |
//! | Entry log (+ `append`, `getEntry`) | [`EntryStore`] |
//! | Checkpoint state (`loadCll`, `commitCll`) | [`CheckpointStateStore`] |
//! | Witness state (`pendingWitnesses`, `getWitness`, `commitWitness`) | [`WitnessStateStore`] |
//! | Checkpoint store (entry source + checkpoint and witness state) | [`CheckpointStore`] |
//! | Full backend (all of the above + `close`) | [`Backend`] |
//!
//! The traits are synchronous, as the contract says for Rust. Every method
//! takes `&self`: backends use interior mutability, so one handle can be
//! shared across threads (for example in an `Arc`), like a Go backend.
//!
//! Backends:
//!
//! - [`memory`]: in-process, no durable state.
//! - [`jsonl`] (Unix): one log per JSONL v4 journal file.
//! - `sqlite` (Cargo feature `sqlite`): the shared relational schema on SQLite.
//! - `mysql` (Cargo feature `mysql`): the shared relational schema on MySQL 8.
//!
//! The log stores opaque 32-byte identities and does not know what they name.
//!
//! [`docs/backend-contract.md`]: https://github.com/action-state-group/checkpointed-local-log/blob/main/docs/backend-contract.md

use std::fmt;

pub mod conformance;
mod engine;
#[cfg(unix)]
pub mod jsonl;
pub mod memory;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(any(feature = "sqlite", feature = "mysql"))]
mod sql;
#[cfg(feature = "sqlite")]
pub mod sqlite;
mod time;
pub mod wire;

pub use time::Timestamp;

/// `EntryBytes`: the width of every identity, node and peak.
pub const ENTRY_BYTES: usize = 32;
/// `MaxWitnesses`: the largest `pendingWitnesses` limit.
pub const MAX_WITNESSES: usize = 32;
/// `MaxCheckpointBytes`: the largest checkpoint byte string.
pub const MAX_CHECKPOINT_BYTES: usize = 65_536;
/// `MaxJournalEventBytes`: the largest JSONL event line.
pub const MAX_JOURNAL_EVENT_BYTES: usize = 4_194_304;
/// `MaxWitnessResponseBytes`: the largest witness receipt.
pub const MAX_WITNESS_RESPONSE_BYTES: usize = 2_097_152;
/// `MaxIdentifierBytes`: the longest witness or log identifier, in bytes.
pub const MAX_IDENTIFIER_BYTES: usize = 191;
/// `MaxReasonBytes`: the longest `lastError`, in UTF-8 bytes.
pub const MAX_REASON_BYTES: usize = 4096;
/// `DefaultScanLimit`: the conventional entry batch size.
pub const DEFAULT_SCAN_LIMIT: usize = 100;
/// `MaxScanLimit`: the largest `scanEntries` limit.
pub const MAX_SCAN_LIMIT: usize = 1000;
/// `MaxPortableInteger`: JavaScript `Number.MAX_SAFE_INTEGER`, the largest
/// sequence and receipt position.
pub const MAX_PORTABLE_INTEGER: u64 = 9_007_199_254_740_991;
/// `MinPortableUnixMillis`: the earliest ECMAScript `Date`.
pub const MIN_PORTABLE_UNIX_MILLIS: i64 = -8_640_000_000_000_000;
/// `MaxPortableUnixMillis`: the latest ECMAScript `Date`.
pub const MAX_PORTABLE_UNIX_MILLIS: i64 = 8_640_000_000_000_000;

/// The contract's error codes (docs/backend-contract.md, "Error codes").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// `not_found`: a direct lookup found nothing.
    NotFound,
    /// `invalid`: a caller-supplied value or transition breaks the contract.
    Invalid,
    /// `corrupt`: durable bytes, rows or events are malformed or inconsistent.
    Corrupt,
    /// `closed`: the backend was closed.
    Closed,
    /// `contention`: a compare-and-set failed, or another writer holds the log.
    Contention,
    /// `rejected`: a witness or offline verification permanently rejected a
    /// response. Storage operations never return it.
    Rejected,
    /// `unsupported`: the store does not offer this operation.
    Unsupported,
    /// Rust only: an I/O or database-driver failure the contract does not
    /// classify (a lost connection, a permission error). Go and TypeScript
    /// surface these as their platform's own errors, which carry no CLL
    /// code; Rust gives every error a code, so they carry this one.
    Storage,
}

impl ErrorCode {
    /// The contract's spelling, for example `not_found`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Invalid => "invalid",
            Self::Corrupt => "corrupt",
            Self::Closed => "closed",
            Self::Contention => "contention",
            Self::Rejected => "rejected",
            Self::Unsupported => "unsupported",
            Self::Storage => "storage",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A CLL storage failure. [`Error::code`] is its contract error code.
#[derive(Debug)]
pub struct Error {
    code: ErrorCode,
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    /// An error with `code` and a human-readable message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            source: None,
        }
    }

    /// An error with `code` caused by `source`.
    pub fn with_source(
        code: ErrorCode,
        message: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// The contract error code.
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// The message, without the code.
    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Invalid, message)
    }

    pub(crate) fn corrupt(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Corrupt, message)
    }

    pub(crate) fn contention(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Contention, message)
    }

    pub(crate) fn closed() -> Self {
        Self::new(ErrorCode::Closed, "the backend is closed")
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    /// The same failure reported under another code, for example a decoding
    /// error in durable data, which is `corrupt` rather than `invalid`.
    pub(crate) fn recode(mut self, code: ErrorCode) -> Self {
        self.code = code;
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)?;
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::with_source(ErrorCode::Storage, "I/O failure", error)
    }
}

/// The result of every CLL storage operation.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// One log entry: a dense 1-based `seq`, a 32-byte identity and its UTC
/// millisecond observation time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub value: Vec<u8>,
    pub appended_at: Timestamp,
}

/// The identity and observation time an application appends. Any byte length
/// and any time are representable; the backend rejects contract-invalid
/// values as `invalid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendInput {
    pub value: Vec<u8>,
    pub appended_at: Timestamp,
}

/// Whether `append` stored a new entry or found the identity already present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppendOutcome {
    /// `inserted`
    Inserted,
    /// `idempotent`: the original entry, with its original `seq` and time.
    Idempotent,
}

impl AppendOutcome {
    /// The contract's spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inserted => "inserted",
            Self::Idempotent => "idempotent",
        }
    }
}

/// The result of `append`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendResult {
    pub entry: Entry,
    pub outcome: AppendOutcome,
}

/// The complete checkpoint tuple of a [`State`]: present or absent as a whole.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckpointState {
    pub bytes: Vec<u8>,
    pub size: u64,
    pub indexed_seq: u64,
    pub peaks: Vec<Vec<u8>>,
}

/// The restartable MMR, checkpoint and witness state (`State`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub size: u64,
    pub nodes: Vec<Vec<u8>>,
    pub indexed_seq: u64,
    pub first_pending_at: Option<Timestamp>,
    pub checkpoint: Option<CheckpointState>,
    pub witnesses: Vec<WitnessState>,
}

/// A verified witness receipt: its bytes and optional metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WitnessReceiptState {
    pub bytes: Vec<u8>,
    /// 64 lowercase hex digits.
    pub entry_hash: Option<String>,
    /// `legacy`.
    pub entry_hash_scheme: Option<String>,
    pub leaf_index: Option<i64>,
    pub tree_size: Option<i64>,
}

/// Delivery state for one witness and checkpoint, keyed by
/// (`witness_id`, `checkpoint_size`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessState {
    pub witness_id: String,
    pub checkpoint_size: u64,
    pub checkpoint: Vec<u8>,
    pub attempts: u32,
    pub next_attempt_at: Timestamp,
    pub receipt: Option<WitnessReceiptState>,
    pub permanent: bool,
    pub last_error: Option<String>,
}

/// `EntrySource`: bounded scans after a dense sequence position.
pub trait EntrySource {
    /// Entries with `seq > after_seq`, ascending, at most `limit`
    /// (1..=[`MAX_SCAN_LIMIT`]).
    fn scan_entries(&self, after_seq: u64, limit: usize) -> Result<Vec<Entry>>;
}

/// `EntryStore`: the entry log. Appends opaque identities and looks them up.
pub trait EntryStore: EntrySource {
    /// Appends `input.value`, or returns its original entry as
    /// [`AppendOutcome::Idempotent`]. A store without the `digest-append`
    /// capability returns `unsupported` for an identity it does not hold.
    fn append(&self, input: &AppendInput) -> Result<AppendResult>;

    /// The entry holding `value`; `not_found` when there is none.
    fn get_entry(&self, value: &[u8]) -> Result<Entry>;
}

/// `CheckpointStateStore`: append-only CLL state with compare-and-set.
pub trait CheckpointStateStore {
    /// The current state.
    fn load_cll(&self) -> Result<State>;

    /// Replaces the state with `next` if the current size and checkpoint
    /// bytes are `expected_size` and `expected_checkpoint` (`None` when there
    /// is no checkpoint), under the contract's transition rules.
    fn commit_cll(
        &self,
        expected_size: u64,
        expected_checkpoint: Option<&[u8]>,
        next: &State,
    ) -> Result<()>;
}

/// `WitnessStateStore`: independent witness-delivery state.
pub trait WitnessStateStore {
    /// Due rows (no receipt, not permanent, `next_attempt_at <= now`) ordered
    /// by checkpoint size then witness ID, at most `limit`
    /// (1..=[`MAX_WITNESSES`]).
    fn pending_witnesses(&self, now: Timestamp, limit: usize) -> Result<Vec<WitnessState>>;

    /// The row for the key, or `Ok(None)` when there is none (the contract's
    /// not-found convention for Rust). A malformed key is still `invalid`.
    fn get_witness(&self, witness_id: &str, checkpoint_size: u64) -> Result<Option<WitnessState>>;

    /// Replaces the row for `next`'s key if its stored attempts equal
    /// `expected_attempts` and its checkpoint bytes are unchanged.
    fn commit_witness(&self, expected_attempts: u32, next: &WitnessState) -> Result<()>;
}

/// `CheckpointStore`: the surface a checkpoint runner needs.
pub trait CheckpointStore: EntrySource + CheckpointStateStore + WitnessStateStore {}

impl<T: EntrySource + CheckpointStateStore + WitnessStateStore + ?Sized> CheckpointStore for T {}

/// `Backend` (TypeScript `CllBackend`): the full backend.
pub trait Backend: EntryStore + CheckpointStateStore + WitnessStateStore {
    /// Closes the backend. Repeating it succeeds; every other operation then
    /// fails with `closed`.
    fn close(&self) -> Result<()>;
}

/// Checks the identifier rules: 1..=191 UTF-8 bytes of `[A-Za-z0-9._:/-]`.
pub fn validate_identifier(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(Error::invalid(format!(
            "identifier must be 1..={MAX_IDENTIFIER_BYTES} bytes of [A-Za-z0-9._:/-]"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_follow_the_portable_subset() {
        for ok in ["primary", "a", "x.y_z:1/2-3", &"a".repeat(191)] {
            validate_identifier(ok).unwrap();
        }
        for bad in ["", "bad id", "ü", "a\n", &"a".repeat(192)] {
            assert_eq!(
                validate_identifier(bad).unwrap_err().code(),
                ErrorCode::Invalid
            );
        }
    }

    #[test]
    fn errors_carry_code_message_and_source() {
        let io = std::io::Error::other("disk");
        let error = Error::from(io);
        assert_eq!(error.code(), ErrorCode::Storage);
        assert_eq!(error.to_string(), "storage: I/O failure: disk");
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(Error::closed().code().as_str(), "closed");
        assert_eq!(AppendOutcome::Idempotent.as_str(), "idempotent");
        for code in [
            ErrorCode::NotFound,
            ErrorCode::Invalid,
            ErrorCode::Corrupt,
            ErrorCode::Closed,
            ErrorCode::Contention,
            ErrorCode::Rejected,
            ErrorCode::Unsupported,
        ] {
            assert_eq!(Error::new(code, "m").code().to_string(), code.as_str());
        }
    }
}
