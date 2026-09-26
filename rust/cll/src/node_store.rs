//! Durable, append-only MMR node store: a flat file of fixed 32-byte
//! records, `position = record index` (byte offset = `pos * 32`). This is
//! the `NodeReader`/`NodeAppender` a serving-path plugin should hold so its
//! MMR survives a process restart without replaying the whole ledger to
//! rebuild it -- `mmr::MemoryNodeStore` stays the in-memory store for tests
//! and short-lived processes.
//!
//! Crash-safety: `append_nodes` writes then `fsync`s before returning, so a
//! crash mid-append can leave at most one torn TRAILING record (a partial
//! write of the last 32-byte chunk) -- never a torn record followed by a
//! good one, since every completed append is durable before the next one
//! starts. `FileNodeStore::open` detects a torn tail (file length not a
//! multiple of 32 bytes) and truncates it away, reporting how much was
//! discarded; a torn record is never treated as a valid node.
//!
//! If the file itself is lost or judged untrustworthy, `rebuild_from_leaves`
//! regenerates it from the ledger's own leaf digests -- the same "JSONL
//! durable, index rebuildable" discipline `store.rs` already uses for
//! checkpoints.

use crate::mmr::{add_leaf, Hash, NodeAppender, NodeReader, DIGEST_LEN};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};

#[derive(Debug, thiserror::Error)]
pub enum NodeStoreError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// What `FileNodeStore::open` found: how many whole 32-byte records are
/// present, and how many trailing bytes (always `< 32`) were discarded as a
/// torn record left by a crash between `write` and `fsync`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenReport {
    pub node_count: u64,
    pub truncated_bytes: u64,
}

/// A file-backed `NodeReader + NodeAppender`. One node = one fixed 32-byte
/// record; `size()` is `file_len / 32`, `node(pos)` seeks to `pos * 32`.
pub struct FileNodeStore {
    file: File,
    node_count: u64,
}

impl FileNodeStore {
    /// Open (creating if absent) the node file at `path`. A trailing
    /// partial record is truncated off and reported via `OpenReport` --
    /// never silently accepted as a valid node.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<(Self, OpenReport), NodeStoreError> {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        let len = file.metadata()?.len();
        let record_size = DIGEST_LEN as u64;
        let whole_records = len / record_size;
        let truncated_bytes = len % record_size;
        if truncated_bytes != 0 {
            file.set_len(whole_records * record_size)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        let report = OpenReport {
            node_count: whole_records,
            truncated_bytes,
        };
        Ok((
            Self {
                file,
                node_count: whole_records,
            },
            report,
        ))
    }

    /// Rebuild a fresh node file at `path` from an iterator of already
    /// leaf-hashed digests (i.e. `mmr::leaf_hash` output, one per ledger
    /// entry in order) -- the recovery path when the node file is lost or
    /// too damaged to trust. Overwrites any existing file at `path`.
    pub fn rebuild_from_leaves(
        path: impl AsRef<std::path::Path>,
        leaves: impl IntoIterator<Item = Hash>,
    ) -> Result<Self, NodeStoreError> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        let mut store = Self {
            file,
            node_count: 0,
        };
        for leaf in leaves {
            // `add_leaf` only ever calls back into `NodeReader`/`NodeAppender`
            // on positions it just wrote or that were already present --
            // never fails against a store it is building itself.
            add_leaf(&mut store, leaf)
                .expect("rebuild_from_leaves: add_leaf failed against a store it is building");
        }
        Ok(store)
    }
}

impl NodeReader for FileNodeStore {
    fn size(&self) -> u64 {
        self.node_count
    }

    fn node(&self, pos: u64) -> Hash {
        let mut buf = [0u8; DIGEST_LEN];
        (&self.file)
            .seek(SeekFrom::Start(pos * DIGEST_LEN as u64))
            .expect("FileNodeStore::node: seek failed");
        (&self.file)
            .read_exact(&mut buf)
            .expect("FileNodeStore::node: short read -- node file is shorter than size() claims");
        buf
    }
}

impl NodeAppender for FileNodeStore {
    fn append_nodes(&mut self, hashes: &[Hash]) {
        // A prior `node()` call may have left the shared file cursor
        // mid-file -- always seek to the true end before appending so reads
        // and writes never fight over one cursor.
        self.file
            .seek(SeekFrom::End(0))
            .expect("FileNodeStore::append_nodes: seek to end failed");
        for h in hashes {
            self.file
                .write_all(h)
                .expect("FileNodeStore::append_nodes: write failed");
        }
        self.file
            .sync_all()
            .expect("FileNodeStore::append_nodes: fsync failed");
        self.node_count += hashes.len() as u64;
    }
}
