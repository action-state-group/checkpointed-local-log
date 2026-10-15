//! The Rust driver for `go/scripts/check-storage-interop.sh`: the same modes
//! and deterministic fixture as the Go (`go/test/interop/storage`) and
//! TypeScript (`go/test/interop/storage.mjs`) drivers, so a log written by any
//! language continues and verifies here with identical checkpoint roots.
//!
//! ```text
//! storage_interop advance|verify|summary|hold|expect-contention <jsonl|sqlite|mysql> <target> <log-id> [argument...]
//! ```
//!
//! The MySQL target is a `mysql://user:password@host:port/database` URL.

use cll::log::jsonl::JsonlStore;
use cll::log::mysql::MysqlStore;
use cll::log::sqlite::SqliteStore;
use cll::log::{
    wire, AppendInput, AppendOutcome, Backend, CheckpointState, ErrorCode, State, Timestamp,
    WitnessReceiptState, WitnessState, MAX_SCAN_LIMIT, MAX_WITNESSES,
};
use cll::mmr::{
    add_leaf, leaf_hash, peaks, root_from_peaks, Hash, MemoryNodeStore, NodeAppender, NodeReader,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, Instant};

const WITNESS_ID: &str = "interop-witness";
/// 2026-09-03T12:00:00.123Z
const BASE_MILLIS: i64 = 1_788_436_800_123;

type Failure = Box<dyn std::error::Error>;

fn main() {
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("storage_interop: {error}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), Failure> {
    let [mode, backend, target, log_id, rest @ ..] = args else {
        return Err("usage: storage_interop <advance|verify|summary|hold|expect-contention> <jsonl|sqlite|mysql> <target> <log-id> [argument...]".into());
    };
    if mode == "advance" || mode == "hold" {
        match backend.as_str() {
            "jsonl" => JsonlStore::init(target)?,
            "sqlite" => SqliteStore::init(target, log_id)?,
            "mysql" => MysqlStore::init(target, log_id)?,
            other => return Err(format!("unsupported backend {other}").into()),
        }
    }
    if mode == "expect-contention" {
        return match open(backend, target, log_id) {
            Ok(store) => {
                store.close()?;
                Err("second writer unexpectedly opened".into())
            }
            Err(error) if error.code() == ErrorCode::Contention => Ok(()),
            Err(error) => Err(format!("expected contention, got {error}").into()),
        };
    }
    let store = open(backend, target, log_id)?;
    let result = match (mode.as_str(), rest) {
        ("advance", []) => advance(store.as_ref()),
        ("verify", [count]) => verify(store.as_ref(), count.parse()?),
        ("summary", []) => summary(store.as_ref()),
        ("hold", [ready, stop]) => hold(Path::new(ready), Path::new(stop)),
        _ => Err(format!("unsupported mode or arguments: {mode} {rest:?}").into()),
    };
    let closed = store.close();
    result?;
    Ok(closed?)
}

fn open(backend: &str, target: &str, log_id: &str) -> cll::log::Result<Box<dyn Backend>> {
    Ok(match backend {
        "jsonl" => Box::new(JsonlStore::open(target)?),
        "sqlite" => Box::new(SqliteStore::open(target, log_id)?),
        "mysql" => Box::new(MysqlStore::open(target, log_id)?),
        other => {
            return Err(cll::log::Error::new(
                ErrorCode::Invalid,
                format!("unsupported backend {other}"),
            ))
        }
    })
}

fn identity_for(sequence: u8) -> Vec<u8> {
    vec![sequence; 32]
}

fn checkpoint_for(sequence: u8) -> Vec<u8> {
    vec![0xc0, sequence]
}

fn receipt_for(sequence: u8) -> Vec<u8> {
    vec![0xd0, sequence]
}

fn time_for(sequence: u8) -> Timestamp {
    Timestamp::from_unix_millis(BASE_MILLIS + i64::from(sequence) * 1000)
}

fn hash(bytes: &[u8]) -> Result<Hash, Failure> {
    Ok(bytes.try_into()?)
}

/// The MMR over the stored nodes.
fn tree(nodes: &[Vec<u8>]) -> Result<MemoryNodeStore, Failure> {
    let mut tree = MemoryNodeStore::new();
    let hashes = nodes
        .iter()
        .map(|n| hash(n))
        .collect::<Result<Vec<_>, _>>()?;
    tree.append_nodes(&hashes);
    Ok(tree)
}

fn nodes(tree: &MemoryNodeStore) -> Vec<Vec<u8>> {
    (0..tree.size()).map(|p| tree.node(p).to_vec()).collect()
}

fn peak_hashes(tree: &MemoryNodeStore) -> Result<Vec<Vec<u8>>, Failure> {
    Ok(peaks(tree.size())?
        .into_iter()
        .map(|p| tree.node(p).to_vec())
        .collect())
}

fn advance(store: &dyn Backend) -> Result<(), Failure> {
    let entries = store.scan_entries(0, MAX_SCAN_LIMIT)?;
    verify(store, entries.len()).map_err(|e| format!("verify before advance: {e}"))?;
    let sequence =
        u8::try_from(entries.len() + 1).map_err(|_| "interop sequence exceeds fixture range")?;
    let identity = identity_for(sequence);
    let result = store.append(&AppendInput {
        value: identity.clone(),
        appended_at: time_for(sequence),
    })?;
    if result.outcome != AppendOutcome::Inserted || result.entry.seq != u64::from(sequence) {
        return Err(format!("unexpected append result: {result:?}").into());
    }

    let state = store.load_cll()?;
    let mut mmr = tree(&state.nodes)?;
    add_leaf(&mut mmr, leaf_hash(&hash(&identity)?))?;
    let checkpoint = checkpoint_for(sequence);
    let previous = state.checkpoint.clone();
    let mut witnesses = state.witnesses.clone();
    witnesses.push(WitnessState {
        witness_id: WITNESS_ID.into(),
        checkpoint_size: mmr.size(),
        checkpoint: checkpoint.clone(),
        attempts: 0,
        next_attempt_at: time_for(sequence),
        receipt: None,
        permanent: false,
        last_error: None,
    });
    let next = State {
        size: mmr.size(),
        nodes: nodes(&mmr),
        indexed_seq: u64::from(sequence),
        first_pending_at: state.first_pending_at,
        checkpoint: Some(CheckpointState {
            bytes: checkpoint,
            size: mmr.size(),
            indexed_seq: u64::from(sequence),
            peaks: peak_hashes(&mmr)?,
        }),
        witnesses,
    };
    store.commit_cll(
        state.size,
        previous.as_ref().map(|c| c.bytes.as_slice()),
        &next,
    )?;
    if let Some(previous) = previous {
        complete_witness(store, previous.size, sequence - 1, sequence)?;
    }
    verify(store, usize::from(sequence))
}

fn complete_witness(
    store: &dyn Backend,
    checkpoint_size: u64,
    checkpoint_sequence: u8,
    current_sequence: u8,
) -> Result<(), Failure> {
    let current = store
        .get_witness(WITNESS_ID, checkpoint_size)?
        .ok_or("previous witness is missing")?;
    let next = WitnessState {
        attempts: current.attempts + 1,
        next_attempt_at: time_for(current_sequence),
        receipt: Some(WitnessReceiptState {
            bytes: receipt_for(checkpoint_sequence),
            entry_hash: Some(hex::encode(Sha256::digest(&current.checkpoint))),
            entry_hash_scheme: Some("legacy".into()),
            leaf_index: Some(i64::from(checkpoint_sequence) - 1),
            tree_size: Some(i64::from(current_sequence)),
        }),
        permanent: false,
        ..current.clone()
    };
    Ok(store.commit_witness(current.attempts, &next)?)
}

fn verify(store: &dyn Backend, expected: usize) -> Result<(), Failure> {
    let entries = store.scan_entries(0, MAX_SCAN_LIMIT)?;
    if entries.len() != expected {
        return Err(format!("got {} entries, want {expected}", entries.len()).into());
    }
    let mut mmr = MemoryNodeStore::new();
    let mut sizes = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let sequence = u8::try_from(index + 1)?;
        if entry.seq != u64::from(sequence)
            || entry.value != identity_for(sequence)
            || entry.appended_at != time_for(sequence)
        {
            return Err(format!("entry {sequence} disagrees with portable fixture").into());
        }
        add_leaf(&mut mmr, leaf_hash(&hash(&entry.value)?))?;
        sizes.push(mmr.size());
    }

    let state = store.load_cll()?;
    if state.size != mmr.size()
        || state.indexed_seq != expected as u64
        || state.nodes != nodes(&mmr)
        || state.witnesses.len() != expected
        || state.first_pending_at.is_some()
    {
        return Err("CLL state disagrees with portable fixture".into());
    }
    let Some(last) = sizes.last() else {
        return match state.checkpoint {
            Some(_) => Err("empty fixture has a checkpoint".into()),
            None => Ok(()),
        };
    };
    let latest = u8::try_from(expected)?;
    match &state.checkpoint {
        Some(c)
            if c.size == mmr.size()
                && c.indexed_seq == expected as u64
                && c.bytes == checkpoint_for(latest)
                && c.peaks == peak_hashes(&mmr)? => {}
        _ => return Err("latest checkpoint disagrees with portable fixture".into()),
    }
    for (index, size) in sizes.iter().enumerate() {
        let sequence = u8::try_from(index + 1)?;
        let item = store
            .get_witness(WITNESS_ID, *size)?
            .ok_or_else(|| format!("witness {sequence} is missing"))?;
        if item.checkpoint != checkpoint_for(sequence) {
            return Err(format!("witness {sequence} checkpoint mismatch").into());
        }
        if sequence == latest {
            if item.attempts != 0 || item.receipt.is_some() {
                return Err("latest witness is not pending".into());
            }
            continue;
        }
        let digest = hex::encode(Sha256::digest(checkpoint_for(sequence)));
        let receipt_ok = item.receipt.as_ref().is_some_and(|r| {
            r.bytes == receipt_for(sequence)
                && r.entry_hash.as_deref() == Some(digest.as_str())
                && r.entry_hash_scheme.as_deref() == Some("legacy")
                && r.leaf_index == Some(i64::from(sequence) - 1)
                && r.tree_size == Some(i64::from(sequence) + 1)
        });
        if item.attempts != 1 || !receipt_ok {
            return Err(format!("witness {sequence} receipt mismatch").into());
        }
    }
    let day_later = Timestamp::from_unix_millis(BASE_MILLIS + 24 * 60 * 60 * 1000);
    let pending = store.pending_witnesses(day_later, MAX_WITNESSES)?;
    if pending.len() != 1 || pending[0].checkpoint_size != *last {
        return Err("pending witness projection mismatch".into());
    }
    Ok(())
}

/// Prints the entries, the state (witness rows sorted by numeric checkpoint
/// size, then witness ID) and the root bagged from the checkpoint peaks.
fn summary(store: &dyn Backend) -> Result<(), Failure> {
    let entries = store
        .scan_entries(0, MAX_SCAN_LIMIT)?
        .iter()
        .map(wire::entry_to_value)
        .collect::<Result<Vec<_>, _>>()?;
    let mut state = store.load_cll()?;
    state.witnesses.sort_by(|a, b| {
        (a.checkpoint_size, a.witness_id.as_bytes())
            .cmp(&(b.checkpoint_size, b.witness_id.as_bytes()))
    });
    let root = match &state.checkpoint {
        Some(checkpoint) => {
            let peaks = checkpoint
                .peaks
                .iter()
                .map(|p| hash(p))
                .collect::<Result<Vec<_>, _>>()?;
            hex::encode(root_from_peaks(&peaks))
        }
        None => String::new(),
    };
    let summary = serde_json::json!({
        "entries": entries,
        "state": wire::state_to_value(&state)?,
        "root": root,
    });
    println!("{summary}");
    Ok(())
}

fn hold(ready: &Path, stop: &Path) -> Result<(), Failure> {
    std::fs::write(ready, "ready\n")?;
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if stop.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("timed out waiting for stop file".into())
}
