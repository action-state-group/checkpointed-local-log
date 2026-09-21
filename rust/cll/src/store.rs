//! `checkpoints.jsonl` reader/writer -- the exact on-disk shape
//! `capsule-emit-mesh/checkpointing.py`'s `CheckpointState` reads and
//! writes (which is itself wire-identical to the Amendment E CLL
//! checkpoint shape this crate's `checkpoint::CheckpointRecord` carries):
//! one JSON object per line, each line `CheckpointRecord::canonical_json()`
//! (i.e. `CheckpointRecord.to_dict()`) with an ADDITIVE `checkpoint_cose`
//! hex field when a COSE_Sign1 envelope was built alongside the JSON
//! record. Lines are strictly append-only and strictly chained (each
//! line's `prev_size`/`prev_root` must match the previous line's
//! `mmr_size`/`root`) -- this module does not enforce that chain (callers
//! building a checkpointer do), only reads/writes the shape faithfully so
//! a Rust checkpointer and `checkpoint_daemon.py` can share one file.
//!
//! No I/O policy, no cadence: this is a pure reader/writer over a path,
//! nothing scheduled or cached.

use crate::checkpoint::CheckpointRecord;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("malformed checkpoints.jsonl line {line}: {source}")]
    Parse {
        line: usize,
        source: serde_json::Error,
    },
}

/// One line of `checkpoints.jsonl`: the checkpoint record plus the
/// optional sibling `checkpoint_cose` hex field (the COSE_Sign1 envelope
/// bytes, hex-encoded) that a producer additively attaches -- never folded
/// into `CheckpointRecord.to_dict()`/`entry_digest()`'s own coverage,
/// since the COSE_Sign1 statement already self-authenticates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointLine {
    pub record: CheckpointRecord,
    pub checkpoint_cose_hex: Option<String>,
}

impl CheckpointLine {
    /// Canonical JSON for one line: `record`'s own canonical form with
    /// `checkpoint_cose` spliced in (alphabetically, matching this
    /// crate's sorted-key convention throughout).
    fn canonical_json(&self) -> String {
        let record_json = self.record.canonical_json();
        match &self.checkpoint_cose_hex {
            None => record_json,
            Some(cose_hex) => {
                // Splice `"checkpoint_cose":"<hex>"` into the record's
                // canonical object at the correct alphabetical position
                // (before "key_id", since 'c' < 'k').
                let needle = "\"key_id\":";
                let idx = record_json
                    .find(needle)
                    .expect("CheckpointRecord::canonical_json always starts its object with the sorted key_id field");
                let mut out = String::with_capacity(record_json.len() + cose_hex.len() + 24);
                out.push_str(&record_json[..idx]);
                out.push_str(&format!("\"checkpoint_cose\":\"{cose_hex}\","));
                out.push_str(&record_json[idx..]);
                out
            }
        }
    }
}

/// Read every line of `path` as a `CheckpointLine`, in file order. Returns
/// an empty vec if the file does not exist (a checkpointer's first run).
pub fn read_checkpoints(path: impl AsRef<Path>) -> Result<Vec<CheckpointLine>, StoreError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut value: serde_json::Value =
            serde_json::from_str(&line).map_err(|source| StoreError::Parse {
                line: i + 1,
                source,
            })?;
        let checkpoint_cose_hex = value
            .as_object_mut()
            .and_then(|obj| obj.remove("checkpoint_cose"))
            .and_then(|v| v.as_str().map(str::to_string));
        let record: CheckpointRecord =
            serde_json::from_value(value).map_err(|source| StoreError::Parse {
                line: i + 1,
                source,
            })?;
        out.push(CheckpointLine {
            record,
            checkpoint_cose_hex,
        });
    }
    Ok(out)
}

/// Return the last line of `path`, or `None` if the file is missing or
/// empty -- the resume point for a restarting checkpointer.
pub fn read_last_checkpoint(path: impl AsRef<Path>) -> Result<Option<CheckpointLine>, StoreError> {
    Ok(read_checkpoints(path)?.pop())
}

/// Append one line to `path`, creating the file (and nothing else -- the
/// parent directory must already exist) if it does not exist yet.
pub fn append_checkpoint(path: impl AsRef<Path>, line: &CheckpointLine) -> Result<(), StoreError> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", line.canonical_json())?;
    Ok(())
}
