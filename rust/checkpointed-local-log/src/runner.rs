//! The checkpoint runner: indexes a [`CheckpointStore`]'s entries into its
//! MMR and signs a COSE checkpoint when the cadence says one is due -- a
//! port of Go's `checkpoint.Runner` (`go/checkpoint/runner.go`).
//!
//! A pass ([`CheckpointRunner::run_once`]) loads the durable state, checks
//! that its MMR and stored checkpoint are consistent and that the checkpoint
//! verifies under this runner's log and key, scans one batch of
//! `scan_limit` entries after the indexed sequence, appends their leaves,
//! and commits the result with [`CheckpointStateStore::commit_cll`]. When a
//! checkpoint is due it is signed in the same commit, and one
//! [`WitnessState`] row per configured witness is queued for a
//! [`DeliveryRunner`](crate::witness_delivery::DeliveryRunner).
//!
//! A checkpoint is due when entries are uncheckpointed and either
//! `cadence_entries` of them are, or the oldest has waited `cadence_age`.
//! Checkpoint statements are byte-identical to Go's and TypeScript's for the
//! same key, log, MMR and time; the shared runner vectors
//! (`runner-conformance-vectors/`) pin them.
//!
//! [`CheckpointStateStore::commit_cll`]: crate::log::CheckpointStateStore::commit_cll

use crate::checkpoint::{
    checkpoint_to_cose, verify_checkpoint_cose_offline, CheckpointError, CheckpointRecord,
    CheckpointSigner,
};
use crate::log::{
    validate_identifier, CheckpointState, CheckpointStore, Error, ErrorCode, Result, State,
    Timestamp, WitnessState, DEFAULT_SCAN_LIMIT, MAX_SCAN_LIMIT, MAX_WITNESSES,
};
use crate::mmr::{self, Hash, MemoryNodeStore, NodeAppender, NodeReader};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Configuration for a [`CheckpointRunner`] (Go `RunnerConfig` with its
/// `Cadence`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerConfig {
    /// The checkpoint issuer: the CWT `iss` claim of every statement.
    pub log_id: String,
    /// Sign once this many entries are uncheckpointed (at least 1).
    pub cadence_entries: u64,
    /// Sign once the oldest uncheckpointed entry is this old (above zero).
    pub cadence_age: Duration,
    /// Entries indexed per pass, 1..=[`MAX_SCAN_LIMIT`].
    pub scan_limit: usize,
    /// How long [`CheckpointRunner::run`] waits between passes when it is
    /// not notified (above zero).
    pub poll_interval: Duration,
    /// Witnesses that get one delivery row per checkpoint: at most
    /// [`MAX_WITNESSES`] distinct identifiers.
    pub witness_ids: Vec<String>,
}

impl RunnerConfig {
    /// The interoperable defaults for `log_id`: 100 entries or 15 minutes,
    /// [`DEFAULT_SCAN_LIMIT`] entries per pass, a one-minute poll and no
    /// witnesses.
    pub fn new(log_id: impl Into<String>) -> Self {
        Self {
            log_id: log_id.into(),
            cadence_entries: 100,
            cadence_age: Duration::from_secs(15 * 60),
            scan_limit: DEFAULT_SCAN_LIMIT,
            poll_interval: Duration::from_secs(60),
            witness_ids: Vec::new(),
        }
    }

    fn validate(&self) -> Result<()> {
        if validate_identifier(&self.log_id).is_err()
            || !(1..=MAX_SCAN_LIMIT).contains(&self.scan_limit)
            || self.poll_interval.is_zero()
        {
            return Err(Error::invalid("invalid runner configuration"));
        }
        if self.cadence_entries == 0 || self.cadence_age.is_zero() {
            return Err(Error::invalid("invalid checkpoint cadence"));
        }
        if self.witness_ids.len() > MAX_WITNESSES {
            return Err(Error::invalid("too many witnesses"));
        }
        let mut seen = HashSet::with_capacity(self.witness_ids.len());
        for id in &self.witness_ids {
            if validate_identifier(id).is_err() {
                return Err(Error::invalid("invalid witness ID"));
            }
            if !seen.insert(id.as_str()) {
                return Err(Error::invalid("duplicate witness ID"));
            }
        }
        Ok(())
    }

    /// Go `Config.Due`: whether `entries` uncheckpointed entries, the oldest
    /// appended at `first`, make a checkpoint due at `now`.
    fn due(&self, entries: u64, first: Timestamp, now: Timestamp) -> bool {
        if entries == 0 {
            return false;
        }
        if entries >= self.cadence_entries {
            return true;
        }
        let waited = i128::from(now.unix_millis()) - i128::from(first.unix_millis());
        waited >= 0
            && Duration::from_millis(u64::try_from(waited).unwrap_or(u64::MAX)) >= self.cadence_age
    }
}

/// The checkpoint timestamp form shared with Go and TypeScript: RFC 3339 in
/// UTC with the fraction's trailing zeros dropped, for example
/// `2026-08-27T12:34:56Z` or `2026-08-27T12:34:56.5Z` (Go's
/// `time.RFC3339Nano`). Unlike stored backend times it has no fixed
/// millisecond field. A year outside 0000..=9999 is `invalid`.
pub fn checkpoint_timestamp(time: Timestamp) -> Result<String> {
    let text = time.to_iso_string()?;
    if text.starts_with('+') || text.starts_with('-') {
        return Err(Error::invalid(
            "checkpoint timestamp year must be 0000..=9999",
        ));
    }
    // `to_iso_string` is always `YYYY-MM-DDTHH:MM:SS.mmmZ` here.
    let (whole, fraction) = text[..text.len() - 1]
        .split_once('.')
        .ok_or_else(|| Error::invalid("unexpected time form"))?;
    let fraction = fraction.trim_end_matches('0');
    Ok(if fraction.is_empty() {
        format!("{whole}Z")
    } else {
        format!("{whole}.{fraction}Z")
    })
}

/// Wakes a host loop: [`notify`](Wake::notify) never blocks, and a
/// notification sent while no one waits is kept for the next wait, like Go's
/// one-slot notify channel.
#[derive(Debug, Default)]
pub(crate) struct Wake {
    pending: Mutex<bool>,
    signal: Condvar,
}

impl Wake {
    pub(crate) fn notify(&self) {
        *self.pending.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.signal.notify_all();
    }

    /// Waits until notified or `timeout` passes, then clears the
    /// notification.
    pub(crate) fn wait(&self, timeout: Duration) {
        let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let (mut pending, _) = self
            .signal
            .wait_timeout_while(pending, timeout, |pending| !*pending)
            .unwrap_or_else(|e| e.into_inner());
        *pending = false;
    }
}

/// The state a pass works from: the stored state and its MMR.
struct Loaded {
    state: State,
    nodes: MemoryNodeStore,
}

/// Advances durable CLL state when its host runs it (Go `checkpoint.Runner`).
///
/// `B` is the store, shared in an [`Arc`] so a
/// [`DeliveryRunner`](crate::witness_delivery::DeliveryRunner) can use the
/// same one; `S` signs the checkpoints, and its
/// [`key_id`](CheckpointSigner::key_id) must be the hex raw Ed25519 public
/// key, which becomes each statement's `kid`. Passes are serialized: one
/// runner never runs two at once.
pub struct CheckpointRunner<B: ?Sized, S> {
    config: RunnerConfig,
    store: Arc<B>,
    signer: S,
    lock: Mutex<()>,
    wake: Wake,
}

impl<B, S> CheckpointRunner<B, S>
where
    B: CheckpointStore + ?Sized,
    S: CheckpointSigner,
{
    /// Validates `config` without starting background work: an invalid log
    /// or witness identifier, scan limit, cadence or poll interval, more
    /// than [`MAX_WITNESSES`] witnesses or a repeated one is `invalid`.
    pub fn new(config: RunnerConfig, store: Arc<B>, signer: S) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            store,
            signer,
            lock: Mutex::new(()),
            wake: Wake::default(),
        })
    }

    /// The configuration.
    pub fn config(&self) -> &RunnerConfig {
        &self.config
    }

    /// Wakes a running [`run`](Self::run) loop without blocking the caller.
    pub fn notify(&self) {
        self.wake.notify();
    }

    /// Catches up until `stop` is set, then waits for
    /// [`notify`](Self::notify) or the poll interval. Contention is retried
    /// on the next wakeup; any other error ends the loop. To stop promptly,
    /// set `stop` and then call [`notify`](Self::notify).
    pub fn run(&self, stop: &AtomicBool) -> Result<()> {
        while !stop.load(Ordering::SeqCst) {
            match self.catch_up_until(Timestamp::now(), Some(stop)) {
                Err(error) if error.code() != ErrorCode::Contention => return Err(error),
                _ => {}
            }
            if stop.load(Ordering::SeqCst) {
                break;
            }
            self.wake.wait(self.config.poll_interval);
        }
        Ok(())
    }

    /// Advances durable state by at most one entry scan batch at `now`.
    /// Returns `true` when it commits nodes, a checkpoint, or both. A stored
    /// state whose MMR, indexed sequence or checkpoint is inconsistent, or
    /// whose checkpoint does not verify under this log and key, is
    /// `corrupt`; a lost compare-and-set is `contention`.
    pub fn run_once(&self, now: Timestamp) -> Result<bool> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let now = runner_time(now)?;
        let mut loaded = self.load()?;
        self.advance(now, &mut loaded)
    }

    /// Runs passes until one commits nothing, all at the one time `now`, so
    /// every checkpoint it signs shares one evaluation time. Contention
    /// reloads the state once; contention again right after the reload is
    /// returned.
    pub fn catch_up(&self, now: Timestamp) -> Result<()> {
        self.catch_up_until(now, None)
    }

    /// [`catch_up`](Self::catch_up) that also returns once `stop` is set,
    /// checked between batches, so a log that grows faster than it is
    /// indexed cannot keep [`run`](Self::run) from stopping.
    fn catch_up_until(&self, now: Timestamp, stop: Option<&AtomicBool>) -> Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let now = runner_time(now)?;
        let mut loaded = self.load()?;
        let mut reloaded = false;
        loop {
            match self.advance(now, &mut loaded) {
                Err(error) if error.code() == ErrorCode::Contention && !reloaded => {
                    loaded = self.load()?;
                    reloaded = true;
                }
                Err(error) => return Err(error),
                Ok(false) => return Ok(()),
                Ok(true) if stop.is_some_and(|stop| stop.load(Ordering::SeqCst)) => return Ok(()),
                Ok(true) => reloaded = false,
            }
        }
    }

    fn load(&self) -> Result<Loaded> {
        let state = self.store.load_cll()?;
        if state.size != state.nodes.len() as u64 {
            return Err(Error::corrupt("MMR size does not match indexed sequence"));
        }
        let leaves = mmr::leaf_count(state.size)
            .map_err(|_| Error::corrupt("MMR size is not a complete MMR"))?;
        if leaves != state.indexed_seq {
            return Err(Error::corrupt("MMR size does not match indexed sequence"));
        }
        let mut nodes = MemoryNodeStore::new();
        let hashes = state
            .nodes
            .iter()
            .map(|node| to_hash(node).ok_or_else(|| Error::corrupt("MMR node is not 32 bytes")))
            .collect::<Result<Vec<_>>>()?;
        nodes.append_nodes(&hashes);
        self.verify_checkpoint(&state, &nodes)?;
        Ok(Loaded { state, nodes })
    }

    fn verify_checkpoint(&self, state: &State, nodes: &MemoryNodeStore) -> Result<()> {
        let Some(checkpoint) = &state.checkpoint else {
            return Ok(());
        };
        let position = || Error::corrupt("invalid stored checkpoint position");
        let leaves = mmr::leaf_count(checkpoint.size).map_err(|_| position())?;
        if checkpoint.size > state.size
            || leaves != checkpoint.indexed_seq
            || checkpoint.indexed_seq > state.indexed_seq
        {
            return Err(position());
        }
        let expected = peak_hashes(nodes, checkpoint.size)?;
        if !same_peaks(&expected, &checkpoint.peaks) {
            return Err(Error::corrupt("stored checkpoint peaks mismatch"));
        }
        self.check_statement(&checkpoint.bytes, checkpoint.size, &expected)
            .map_err(|reason| Error::corrupt(format!("stored checkpoint {reason}")))
    }

    /// Checks that `statement` verifies under its own key and is this
    /// runner's checkpoint of `peaks` at `size`.
    fn check_statement(
        &self,
        statement: &[u8],
        size: u64,
        peaks: &[Hash],
    ) -> std::result::Result<(), &'static str> {
        let verified = verify_checkpoint_cose_offline(statement);
        let decoded = match verified.decoded {
            Some(decoded) if verified.ok => decoded,
            _ => return Err("signature mismatch"),
        };
        if decoded.log_id != self.config.log_id
            || decoded.key_id != self.signer.key_id()
            || decoded.mmr_size != size
            || decoded.new_peak_hashes != peaks
            || decoded.root != hex::encode(mmr::root_from_peaks(peaks))
        {
            return Err("metadata mismatch");
        }
        Ok(())
    }

    fn advance(&self, now: Timestamp, loaded: &mut Loaded) -> Result<bool> {
        let state = &loaded.state;
        let nodes = &mut loaded.nodes;
        let entries = self
            .store
            .scan_entries(state.indexed_seq, self.config.scan_limit)?;
        let mut first_pending = state.first_pending_at;
        let mut indexed = state.indexed_seq;
        let mut new_nodes: Vec<Vec<u8>> = Vec::new();
        for entry in &entries {
            if Some(entry.seq) != indexed.checked_add(1) || !entry.appended_at.is_portable() {
                return Err(Error::corrupt("CLL entry sequence or time is invalid"));
            }
            let value = to_hash(&entry.value)
                .ok_or_else(|| Error::corrupt("CLL entry value is not 32 bytes"))?;
            let (_, appended) = mmr::add_leaf(nodes, mmr::leaf_hash(&value))
                .map_err(|e| Error::with_source(ErrorCode::Corrupt, "append MMR entry", e))?;
            new_nodes.extend(appended.iter().map(|node| node.to_vec()));
            indexed = entry.seq;
            first_pending.get_or_insert(entry.appended_at);
        }
        let last_checkpointed = state.checkpoint.as_ref().map_or(0, |c| c.indexed_seq);
        let uncheckpointed = indexed - last_checkpointed;
        let due = first_pending.is_some_and(|first| self.config.due(uncheckpointed, first, now));
        let size = nodes.size();
        let mut next = State {
            size,
            nodes: state.nodes.iter().cloned().chain(new_nodes).collect(),
            indexed_seq: indexed,
            first_pending_at: first_pending,
            checkpoint: state.checkpoint.clone(),
            witnesses: state.witnesses.clone(),
        };
        if due {
            let statement = self.sign(now, state.checkpoint.as_ref(), nodes, size)?;
            let peaks = peak_hashes(nodes, size)?;
            next.checkpoint = Some(CheckpointState {
                bytes: statement.clone(),
                size,
                indexed_seq: indexed,
                peaks: peaks.iter().map(|peak| peak.to_vec()).collect(),
            });
            next.first_pending_at = None;
            next.witnesses
                .extend(self.config.witness_ids.iter().map(|id| WitnessState {
                    witness_id: id.clone(),
                    checkpoint_size: size,
                    checkpoint: statement.clone(),
                    attempts: 0,
                    next_attempt_at: now,
                    receipt: None,
                    permanent: false,
                    last_error: None,
                }));
        }
        if entries.is_empty() && !due {
            return Ok(false);
        }
        let expected = state.checkpoint.as_ref().map(|c| c.bytes.as_slice());
        self.store.commit_cll(state.size, expected, &next)?;
        loaded.state = next;
        Ok(true)
    }

    /// Signs the checkpoint of `nodes` at `size`, following `previous`.
    fn sign(
        &self,
        now: Timestamp,
        previous: Option<&CheckpointState>,
        nodes: &MemoryNodeStore,
        size: u64,
    ) -> Result<Vec<u8>> {
        let peaks = peak_hashes(nodes, size)?;
        let (prev_size, prev_peaks, proof) = match previous {
            None => (0, None, None),
            Some(previous) => {
                let proof = mmr::consistency_proof(nodes, previous.size, size)
                    .map_err(|e| Error::with_source(ErrorCode::Corrupt, "consistency proof", e))?;
                (
                    previous.size,
                    Some(peak_hashes(nodes, previous.size)?),
                    Some(proof),
                )
            }
        };
        let record = CheckpointRecord {
            v: 1,
            kind: "mmr_checkpoint".to_string(),
            log_id: self.config.log_id.clone(),
            mmr_size: size,
            root: hex::encode(mmr::root_from_peaks(&peaks)),
            prev_size,
            prev_root: prev_peaks
                .as_deref()
                .map_or_else(String::new, |p| hex::encode(mmr::root_from_peaks(p))),
            key_id: self.signer.key_id(),
            timestamp: checkpoint_timestamp(now)?,
            signature: String::new(),
            witnesses: Vec::new(),
        };
        let statement = checkpoint_to_cose(
            &record,
            &self.signer,
            &peaks,
            prev_peaks.as_deref(),
            proof.as_ref(),
            None,
        )
        .map_err(sign_error)?;
        // As in Go, a statement that does not verify is never committed.
        self.check_statement(&statement, size, &peaks)
            .map_err(|reason| Error::invalid(format!("newly signed checkpoint {reason}")))?;
        Ok(statement)
    }
}

/// A signer failure is outside the contract's codes, so it is `storage`
/// (Rust's code for unclassified external failures); an encoding failure is
/// `invalid`.
fn sign_error(error: CheckpointError) -> Error {
    let code = match error {
        CheckpointError::Signer(_) => ErrorCode::Storage,
        _ => ErrorCode::Invalid,
    };
    Error::with_source(code, "sign checkpoint", error)
}

fn runner_time(now: Timestamp) -> Result<Timestamp> {
    if now.is_portable() {
        Ok(now)
    } else {
        Err(Error::invalid("invalid runner time"))
    }
}

fn to_hash(bytes: &[u8]) -> Option<Hash> {
    bytes.try_into().ok()
}

fn peak_hashes(nodes: &MemoryNodeStore, size: u64) -> Result<Vec<Hash>> {
    let positions = mmr::peaks(size).map_err(|_| Error::corrupt("invalid MMR size"))?;
    if size > nodes.size() {
        return Err(Error::corrupt("MMR is smaller than the requested size"));
    }
    Ok(positions.into_iter().map(|p| nodes.node(p)).collect())
}

fn same_peaks(expected: &[Hash], stored: &[Vec<u8>]) -> bool {
    expected.len() == stored.len()
        && expected
            .iter()
            .zip(stored)
            .all(|(left, right)| left.as_slice() == right.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::memory::MemoryStore;
    use crate::log::{
        AppendInput, CheckpointStateStore, Entry, EntrySource, EntryStore, WitnessStateStore,
    };
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::AtomicUsize;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).unwrap()
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn config() -> RunnerConfig {
        RunnerConfig {
            cadence_entries: 2,
            witness_ids: vec!["w-a".into()],
            ..RunnerConfig::new("unit-log")
        }
    }

    fn append(store: &MemoryStore, byte: u8, time: &str) {
        store
            .append(&AppendInput {
                value: vec![byte; 32],
                appended_at: at(time),
            })
            .unwrap();
    }

    #[test]
    fn checkpoint_timestamps_drop_trailing_fraction_zeros() {
        for (text, expected) in [
            ("2026-08-27T12:34:56.000Z", "2026-08-27T12:34:56Z"),
            ("2026-08-27T12:34:56.500Z", "2026-08-27T12:34:56.5Z"),
            ("2026-08-27T12:34:56.120Z", "2026-08-27T12:34:56.12Z"),
            ("2026-08-27T12:34:56.123Z", "2026-08-27T12:34:56.123Z"),
            ("0000-01-01T00:00:00.000Z", "0000-01-01T00:00:00Z"),
        ] {
            assert_eq!(checkpoint_timestamp(at(text)).unwrap(), expected);
        }
        for text in ["+010000-01-01T00:00:00.000Z", "-000001-01-01T00:00:00.000Z"] {
            assert_eq!(
                checkpoint_timestamp(at(text)).unwrap_err().code(),
                ErrorCode::Invalid
            );
        }
    }

    #[test]
    fn configuration_is_validated() {
        let store = Arc::new(MemoryStore::new());
        let cases: Vec<(RunnerConfig, &str)> = vec![
            (RunnerConfig::new("bad id"), "invalid runner configuration"),
            (
                RunnerConfig {
                    scan_limit: 0,
                    ..config()
                },
                "invalid runner configuration",
            ),
            (
                RunnerConfig {
                    scan_limit: MAX_SCAN_LIMIT + 1,
                    ..config()
                },
                "invalid runner configuration",
            ),
            (
                RunnerConfig {
                    poll_interval: Duration::ZERO,
                    ..config()
                },
                "invalid runner configuration",
            ),
            (
                RunnerConfig {
                    cadence_entries: 0,
                    ..config()
                },
                "invalid checkpoint cadence",
            ),
            (
                RunnerConfig {
                    cadence_age: Duration::ZERO,
                    ..config()
                },
                "invalid checkpoint cadence",
            ),
            (
                RunnerConfig {
                    witness_ids: (0..=MAX_WITNESSES).map(|i| format!("w-{i}")).collect(),
                    ..config()
                },
                "too many witnesses",
            ),
            (
                RunnerConfig {
                    witness_ids: vec!["bad witness".into()],
                    ..config()
                },
                "invalid witness ID",
            ),
            (
                RunnerConfig {
                    witness_ids: vec!["w-a".into(), "w-a".into()],
                    ..config()
                },
                "duplicate witness ID",
            ),
        ];
        for (config, message) in cases {
            let error = CheckpointRunner::new(config, store.clone(), key())
                .err()
                .expect("configuration must be rejected");
            assert_eq!(error.code(), ErrorCode::Invalid);
            assert_eq!(error.message(), message);
        }
        let full = RunnerConfig {
            witness_ids: (0..MAX_WITNESSES).map(|i| format!("w-{i}")).collect(),
            scan_limit: MAX_SCAN_LIMIT,
            ..config()
        };
        CheckpointRunner::new(full, store, key()).unwrap();
    }

    #[test]
    fn invalid_times_are_rejected() {
        let runner = CheckpointRunner::new(config(), Arc::new(MemoryStore::new()), key()).unwrap();
        let late = Timestamp::from_unix_millis(crate::log::MAX_PORTABLE_UNIX_MILLIS + 1);
        assert_eq!(
            runner.run_once(late).unwrap_err().code(),
            ErrorCode::Invalid
        );
        assert_eq!(
            runner.catch_up(late).unwrap_err().code(),
            ErrorCode::Invalid
        );
    }

    #[test]
    fn indexes_signs_and_queues_witnesses() {
        let store = Arc::new(MemoryStore::new());
        let runner = CheckpointRunner::new(config(), store.clone(), key()).unwrap();
        assert!(!runner.run_once(at("2026-10-01T12:00:00.000Z")).unwrap());
        append(&store, 1, "2026-10-01T12:00:00.000Z");
        assert!(runner.run_once(at("2026-10-01T12:00:01.000Z")).unwrap());
        let state = store.load_cll().unwrap();
        assert_eq!((state.size, state.indexed_seq), (1, 1));
        assert!(state.checkpoint.is_none());
        assert_eq!(state.first_pending_at, Some(at("2026-10-01T12:00:00.000Z")));
        // Nothing new and not due yet: no commit.
        assert!(!runner.run_once(at("2026-10-01T12:00:02.000Z")).unwrap());
        // The age cadence makes the single entry due.
        assert!(runner.run_once(at("2026-10-01T12:15:00.000Z")).unwrap());
        let state = store.load_cll().unwrap();
        let checkpoint = state.checkpoint.clone().unwrap();
        assert_eq!((checkpoint.size, checkpoint.indexed_seq), (1, 1));
        assert!(state.first_pending_at.is_none());
        assert_eq!(state.witnesses.len(), 1);
        assert_eq!(
            state.witnesses[0].next_attempt_at,
            at("2026-10-01T12:15:00.000Z")
        );
        // The next checkpoint carries a consistency proof from the first.
        append(&store, 2, "2026-10-01T12:16:00.000Z");
        append(&store, 3, "2026-10-01T12:16:01.000Z");
        runner.catch_up(at("2026-10-01T12:17:00.000Z")).unwrap();
        let state = store.load_cll().unwrap();
        let decoded = verify_checkpoint_cose_offline(&state.checkpoint.unwrap().bytes);
        assert!(decoded.ok, "{:?}", decoded.errors);
        let decoded = decoded.decoded.unwrap();
        assert_eq!((decoded.prev_size, decoded.mmr_size), (1, 4));
        assert_eq!(decoded.timestamp, "2026-10-01T12:17:00Z");
        assert!(decoded.consistency_proof.is_some());
        assert_eq!(state.witnesses.len(), 2);
    }

    #[test]
    fn catch_up_runs_one_batch_per_pass_until_idle() {
        let store = Arc::new(MemoryStore::new());
        let config = RunnerConfig {
            scan_limit: 2,
            cadence_entries: 3,
            ..config()
        };
        let runner = CheckpointRunner::new(config, store.clone(), key()).unwrap();
        for byte in 1..=5 {
            append(&store, byte, "2026-10-01T12:00:00.000Z");
        }
        assert!(runner.run_once(at("2026-10-01T12:00:01.000Z")).unwrap());
        assert_eq!(store.load_cll().unwrap().indexed_seq, 2);
        runner.catch_up(at("2026-10-01T12:00:01.000Z")).unwrap();
        let state = store.load_cll().unwrap();
        assert_eq!(state.indexed_seq, 5);
        assert_eq!(state.checkpoint.unwrap().indexed_seq, 4);
    }

    fn checkpointed_store() -> Arc<MemoryStore> {
        let store = Arc::new(MemoryStore::new());
        let runner = CheckpointRunner::new(config(), store.clone(), key()).unwrap();
        append(&store, 1, "2026-10-01T12:00:00.000Z");
        append(&store, 2, "2026-10-01T12:00:01.000Z");
        assert!(runner.run_once(at("2026-10-01T12:00:02.000Z")).unwrap());
        assert!(store.load_cll().unwrap().checkpoint.is_some());
        store
    }

    /// A store whose state is whatever the test put there, over a real
    /// entry log.
    struct Tampered {
        entries: MemoryStore,
        state: State,
    }

    impl EntrySource for Tampered {
        fn scan_entries(&self, after_seq: u64, limit: usize) -> Result<Vec<Entry>> {
            self.entries.scan_entries(after_seq, limit)
        }
    }

    impl CheckpointStateStore for Tampered {
        fn load_cll(&self) -> Result<State> {
            Ok(self.state.clone())
        }

        fn commit_cll(&self, _: u64, _: Option<&[u8]>, _: &State) -> Result<()> {
            panic!("a corrupt state must not be committed over");
        }
    }

    impl WitnessStateStore for Tampered {
        fn pending_witnesses(&self, _: Timestamp, _: usize) -> Result<Vec<WitnessState>> {
            Ok(Vec::new())
        }

        fn get_witness(&self, _: &str, _: u64) -> Result<Option<WitnessState>> {
            Ok(None)
        }

        fn commit_witness(&self, _: u32, _: &WitnessState) -> Result<()> {
            Ok(())
        }
    }

    fn assert_corrupt(state: State, config: RunnerConfig, signer: SigningKey) {
        let store = Arc::new(Tampered {
            entries: MemoryStore::new(),
            state,
        });
        let runner = CheckpointRunner::new(config, store, signer).unwrap();
        let error = runner.run_once(at("2026-10-01T12:01:00.000Z")).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Corrupt, "{error}");
    }

    #[test]
    fn corrupt_stored_state_is_refused() {
        let good = checkpointed_store().load_cll().unwrap();

        let mut bad = good.clone();
        bad.size = 2;
        assert_corrupt(bad, config(), key());

        let mut bad = good.clone();
        bad.nodes.pop();
        assert_corrupt(bad, config(), key());

        let mut bad = good.clone();
        bad.indexed_seq = 1;
        assert_corrupt(bad, config(), key());

        // The checkpointed peak (node 2 of a 3-node MMR) no longer matches.
        let mut bad = good.clone();
        bad.nodes[2][0] ^= 1;
        assert_corrupt(bad, config(), key());

        let mut bad = good.clone();
        bad.checkpoint.as_mut().unwrap().indexed_seq = 1;
        assert_corrupt(bad, config(), key());

        let mut bad = good.clone();
        bad.checkpoint.as_mut().unwrap().peaks[0][0] ^= 1;
        assert_corrupt(bad, config(), key());

        // A flipped bit in the signed statement breaks its signature.
        let mut bad = good.clone();
        let bytes = &mut bad.checkpoint.as_mut().unwrap().bytes;
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_corrupt(bad, config(), key());

        // A valid statement from another log or key is not this runner's.
        assert_corrupt(good.clone(), RunnerConfig::new("other-log"), key());
        assert_corrupt(good, config(), SigningKey::from_bytes(&[8; 32]));
    }

    #[test]
    fn a_gap_in_the_entry_log_is_corrupt() {
        struct Gappy(MemoryStore);
        impl EntrySource for Gappy {
            fn scan_entries(&self, after_seq: u64, limit: usize) -> Result<Vec<Entry>> {
                let mut entries = self.0.scan_entries(after_seq, limit)?;
                entries.iter_mut().for_each(|e| e.seq += 1);
                Ok(entries)
            }
        }
        impl CheckpointStateStore for Gappy {
            fn load_cll(&self) -> Result<State> {
                self.0.load_cll()
            }
            fn commit_cll(&self, s: u64, c: Option<&[u8]>, n: &State) -> Result<()> {
                self.0.commit_cll(s, c, n)
            }
        }
        impl WitnessStateStore for Gappy {
            fn pending_witnesses(&self, n: Timestamp, l: usize) -> Result<Vec<WitnessState>> {
                self.0.pending_witnesses(n, l)
            }
            fn get_witness(&self, w: &str, s: u64) -> Result<Option<WitnessState>> {
                self.0.get_witness(w, s)
            }
            fn commit_witness(&self, a: u32, n: &WitnessState) -> Result<()> {
                self.0.commit_witness(a, n)
            }
        }
        let inner = MemoryStore::new();
        append(&inner, 1, "2026-10-01T12:00:00.000Z");
        let runner = CheckpointRunner::new(config(), Arc::new(Gappy(inner)), key()).unwrap();
        let error = runner.run_once(at("2026-10-01T12:00:01.000Z")).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Corrupt);
    }

    /// A memory store whose next `fail` commits lose a race: another writer
    /// indexes the pending entries first, then the commit is `contention`.
    struct Racing {
        inner: Arc<MemoryStore>,
        fail: AtomicUsize,
        loads: AtomicUsize,
    }

    impl EntrySource for Racing {
        fn scan_entries(&self, after_seq: u64, limit: usize) -> Result<Vec<Entry>> {
            self.inner.scan_entries(after_seq, limit)
        }
    }

    impl CheckpointStateStore for Racing {
        fn load_cll(&self) -> Result<State> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            self.inner.load_cll()
        }

        fn commit_cll(&self, size: u64, checkpoint: Option<&[u8]>, next: &State) -> Result<()> {
            // Commits are serialized by the runner, so load-then-store is
            // race-free here.
            let racing = self.fail.load(Ordering::SeqCst) > 0;
            if racing {
                self.fail.fetch_sub(1, Ordering::SeqCst);
            }
            if racing {
                // The other writer: a runner over the same store.
                let rival = CheckpointRunner::new(
                    RunnerConfig {
                        scan_limit: 1,
                        ..config()
                    },
                    self.inner.clone(),
                    key(),
                )
                .unwrap();
                rival.run_once(at("2026-10-01T12:00:05.000Z")).unwrap();
            }
            self.inner.commit_cll(size, checkpoint, next)
        }
    }

    impl WitnessStateStore for Racing {
        fn pending_witnesses(&self, n: Timestamp, l: usize) -> Result<Vec<WitnessState>> {
            self.inner.pending_witnesses(n, l)
        }
        fn get_witness(&self, w: &str, s: u64) -> Result<Option<WitnessState>> {
            self.inner.get_witness(w, s)
        }
        fn commit_witness(&self, a: u32, n: &WitnessState) -> Result<()> {
            self.inner.commit_witness(a, n)
        }
    }

    #[test]
    fn catch_up_reloads_once_after_contention() {
        let inner = Arc::new(MemoryStore::new());
        append(&inner, 1, "2026-10-01T12:00:00.000Z");
        append(&inner, 2, "2026-10-01T12:00:01.000Z");
        append(&inner, 3, "2026-10-01T12:00:02.000Z");
        let store = Arc::new(Racing {
            inner: inner.clone(),
            fail: AtomicUsize::new(1),
            loads: AtomicUsize::new(0),
        });
        let runner = CheckpointRunner::new(config(), store.clone(), key()).unwrap();
        runner.catch_up(at("2026-10-01T12:00:10.000Z")).unwrap();
        assert_eq!(store.loads.load(Ordering::SeqCst), 2);
        let state = inner.load_cll().unwrap();
        assert_eq!(state.indexed_seq, 3);
        assert_eq!(state.checkpoint.unwrap().indexed_seq, 3);

        // run_once never reloads: the lost race is the caller's to retry.
        let inner = Arc::new(MemoryStore::new());
        append(&inner, 1, "2026-10-01T12:00:00.000Z");
        let store = Arc::new(Racing {
            inner,
            fail: AtomicUsize::new(1),
            loads: AtomicUsize::new(0),
        });
        let runner = CheckpointRunner::new(config(), store, key()).unwrap();
        let error = runner.run_once(at("2026-10-01T12:00:10.000Z")).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Contention);
    }

    #[test]
    fn catch_up_returns_contention_right_after_a_reload() {
        let inner = Arc::new(MemoryStore::new());
        for byte in 1..=4 {
            append(&inner, byte, "2026-10-01T12:00:00.000Z");
        }
        let store = Arc::new(Racing {
            inner,
            fail: AtomicUsize::new(2),
            loads: AtomicUsize::new(0),
        });
        let runner = CheckpointRunner::new(config(), store.clone(), key()).unwrap();
        let error = runner.catch_up(at("2026-10-01T12:00:10.000Z")).unwrap_err();
        assert_eq!(error.code(), ErrorCode::Contention);
        assert_eq!(store.loads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn catch_up_stops_between_batches_once_asked() {
        let store = Arc::new(MemoryStore::new());
        for byte in 1..=5 {
            append(&store, byte, "2026-10-01T12:00:00.000Z");
        }
        let config = RunnerConfig {
            scan_limit: 2,
            ..config()
        };
        let runner = CheckpointRunner::new(config, store.clone(), key()).unwrap();
        let stop = AtomicBool::new(true);
        runner
            .catch_up_until(at("2026-10-01T12:00:01.000Z"), Some(&stop))
            .unwrap();
        assert_eq!(store.load_cll().unwrap().indexed_seq, 2);
    }

    #[test]
    fn run_stops_when_asked() {
        let store = Arc::new(MemoryStore::new());
        append(&store, 1, "2026-10-01T12:00:00.000Z");
        let config = RunnerConfig {
            poll_interval: Duration::from_secs(3600),
            ..config()
        };
        let runner = CheckpointRunner::new(config, store.clone(), key()).unwrap();
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| runner.run(&stop));
            while store.load_cll().unwrap().indexed_seq == 0 {
                std::thread::yield_now();
            }
            stop.store(true, Ordering::SeqCst);
            runner.notify();
            handle.join().unwrap().unwrap();
        });
    }
}
