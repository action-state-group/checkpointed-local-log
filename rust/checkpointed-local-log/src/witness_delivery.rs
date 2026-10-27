//! Witness delivery: the [`DeliveryRunner`] delivers the witness rows a
//! [`CheckpointRunner`](crate::runner::CheckpointRunner) queues, and the
//! [`HttpWitnessClient`] posts a checkpoint statement to a witness's
//! `/checkpoints` route -- ports of Go's `witness.DeliveryRunner` and
//! `witness.Client` (`go/witness/`).
//!
//! A [`Submitter`] returns a [`SubmitError`] that says whether the failure
//! is worth retrying ([`SubmitError::is_retryable`]: a transport failure or
//! HTTP 408, 429 or 5xx). A retryable failure backs the row off and ends
//! that witness's pass; a permanent one, or a receipt the [`Verifier`]
//! refuses, marks the row permanent.
//!
//! This crate has no SCITT receipt verifier yet: the host supplies the
//! [`Verifier`] that checks each receipt under the witness's pinned
//! authority key.

use crate::checkpoint::{verify_checkpoint_cose_offline, CLL_CHECKPOINT_CONTENT_TYPE};
use crate::log::{
    validate_identifier, Error, ErrorCode, Result, Timestamp, WitnessReceiptState, WitnessState,
    WitnessStateStore, MAX_PORTABLE_INTEGER, MAX_REASON_BYTES, MAX_WITNESSES,
    MAX_WITNESS_RESPONSE_BYTES,
};
use crate::runner::Wake;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The witness protocol's label for a checkpoint digest registered as raw
/// bytes with the transparency log.
pub const ENTRY_HASH_SCHEME_CHECKPOINT_DIGEST: &str = "legacy";

/// How long one [`HttpWitnessClient`] request may take by default, so one
/// unavailable witness cannot hang its runner.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A witness receipt: the bounded response needed to verify the
/// registration offline.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Receipt {
    /// The receipt bytes (a COSE receipt).
    pub bytes: Vec<u8>,
    /// 64 lowercase hex digits.
    pub entry_hash: String,
    /// [`ENTRY_HASH_SCHEME_CHECKPOINT_DIGEST`].
    pub entry_hash_scheme: String,
    pub leaf_index: i64,
    pub tree_size: i64,
}

/// Why a submission failed, and whether it is worth retrying.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubmitError {
    /// A non-2xx response. Retryable for 408, 429 and 5xx.
    #[error("witness returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    /// The request did not complete (connection, timeout, I/O). Retryable.
    #[error("witness request failed: {0}")]
    Transport(String),
    /// A permanent failure: an invalid checkpoint or witness response.
    #[error("{0}")]
    Rejected(String),
}

impl SubmitError {
    /// Go `IsRetryable`: transport failures and HTTP 408, 429 and 5xx.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http { status, .. } => *status == 408 || *status == 429 || *status >= 500,
            Self::Transport(_) => true,
            Self::Rejected(_) => false,
        }
    }
}

/// Sends a signed checkpoint statement to one witness.
pub trait Submitter: Send + Sync {
    fn submit(&self, checkpoint: &[u8]) -> std::result::Result<Receipt, SubmitError>;
}

/// The error a [`Verifier`] returns; its text is stored as the row's
/// `last_error`.
pub type VerifyError = Box<dyn std::error::Error + Send + Sync>;

/// Checks a receipt for `checkpoint` without trusting the witness that
/// returned it. Every failure is permanent.
pub trait Verifier: Send + Sync {
    fn verify(&self, checkpoint: &[u8], receipt: &Receipt) -> std::result::Result<(), VerifyError>;
}

/// Configuration for a [`DeliveryRunner`] (Go `DeliveryConfig`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryConfig {
    /// How long [`DeliveryRunner::run`] waits between passes when it is not
    /// notified (above zero).
    pub poll_interval: Duration,
    /// The delay after a first failure (above zero); it doubles per earlier
    /// attempt up to `max_backoff` (at least `base_backoff`).
    pub base_backoff: Duration,
    pub max_backoff: Duration,
    /// Draws each delay uniformly below the computed one, so witnesses that
    /// failed together do not retry together.
    pub jitter: bool,
}

impl Default for DeliveryConfig {
    /// Go `DefaultDeliveryConfig`: a one-minute poll, 1 s doubling to 1 h,
    /// with jitter.
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(60),
            base_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(3600),
            jitter: true,
        }
    }
}

/// Delivers pending checkpoints independently per witness (Go
/// `witness.DeliveryRunner`). A pass handles witnesses concurrently, one
/// thread each, and one witness's rows in checkpoint order. Passes are
/// serialized: one runner never runs two at once.
pub struct DeliveryRunner<B: ?Sized> {
    config: DeliveryConfig,
    store: Arc<B>,
    clients: HashMap<String, Box<dyn Submitter>>,
    verifiers: HashMap<String, Box<dyn Verifier>>,
    lock: Mutex<()>,
    wake: Wake,
}

impl<B: WitnessStateStore + Send + Sync + ?Sized> DeliveryRunner<B> {
    /// Validates the dependencies without starting background work. There
    /// must be 1..=[`MAX_WITNESSES`] clients, keyed by valid witness
    /// identifiers, each with a verifier under the same key; otherwise, or
    /// for a zero poll interval or base backoff or a `max_backoff` below
    /// `base_backoff`, it is `invalid`.
    pub fn new(
        config: DeliveryConfig,
        store: Arc<B>,
        clients: HashMap<String, Box<dyn Submitter>>,
        verifiers: HashMap<String, Box<dyn Verifier>>,
    ) -> Result<Self> {
        if config.poll_interval.is_zero()
            || config.base_backoff.is_zero()
            || config.max_backoff < config.base_backoff
            || clients.is_empty()
            || clients.len() > MAX_WITNESSES
            || verifiers.len() != clients.len()
        {
            return Err(Error::invalid("invalid witness delivery configuration"));
        }
        for id in clients.keys() {
            if validate_identifier(id).is_err() || !verifiers.contains_key(id) {
                return Err(Error::invalid(format!(
                    "invalid witness dependency for {id:?}"
                )));
            }
        }
        Ok(Self {
            config,
            store,
            clients,
            verifiers,
            lock: Mutex::new(()),
            wake: Wake::default(),
        })
    }

    /// The configuration.
    pub fn config(&self) -> &DeliveryConfig {
        &self.config
    }

    /// Wakes a running [`run`](Self::run) loop without blocking the caller.
    pub fn notify(&self) {
        self.wake.notify();
    }

    /// Delivers until `stop` is set, up to [`MAX_WITNESSES`] rows per pass.
    /// Contention is retried on the next wakeup; any other error ends the
    /// loop. To stop promptly, set `stop` and then call
    /// [`notify`](Self::notify).
    pub fn run(&self, stop: &AtomicBool) -> Result<()> {
        while !stop.load(Ordering::SeqCst) {
            match self.run_once(Timestamp::now(), MAX_WITNESSES) {
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

    /// Delivers the rows due at `now`, at most `limit`
    /// (1..=[`MAX_WITNESSES`]). Returns the number that received a verified
    /// receipt. A store error stops that witness's pass; the first one is
    /// returned once every witness's pass has ended.
    pub fn run_once(&self, now: Timestamp, limit: usize) -> Result<usize> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut groups: BTreeMap<&str, Vec<WitnessState>> = BTreeMap::new();
        let pending = self.store.pending_witnesses(now, limit)?;
        for item in &pending {
            groups
                .entry(item.witness_id.as_str())
                .or_default()
                .push(item.clone());
        }
        let outcomes: Vec<(usize, Option<Error>)> = std::thread::scope(|scope| {
            let handles: Vec<_> = groups
                .into_values()
                .map(|items| scope.spawn(move || self.deliver_all(now, items)))
                .collect();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
                })
                .collect()
        });
        let mut completed = 0;
        let mut first_error = None;
        for (count, error) in outcomes {
            completed += count;
            if first_error.is_none() {
                first_error = error;
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(completed),
        }
    }

    fn deliver_all(&self, now: Timestamp, items: Vec<WitnessState>) -> (usize, Option<Error>) {
        let mut completed = 0;
        for item in items {
            match self.deliver(now, item) {
                Err(error) => return (completed, Some(error)),
                Ok((success, retryable)) => {
                    completed += usize::from(success);
                    if retryable {
                        break;
                    }
                }
            }
        }
        (completed, None)
    }

    /// One row: `(verified receipt, retryable failure)`.
    fn deliver(&self, now: Timestamp, item: WitnessState) -> Result<(bool, bool)> {
        let (Some(client), Some(verifier)) = (
            self.clients.get(&item.witness_id),
            self.verifiers.get(&item.witness_id),
        ) else {
            return Err(Error::invalid(format!(
                "no configured client and verifier for witness {:?}",
                item.witness_id
            )));
        };
        if !verify_checkpoint_cose_offline(&item.checkpoint).ok {
            self.fail(now, item, true, "stored checkpoint failed verification")?;
            return Ok((false, false));
        }
        let receipt = match client.submit(&item.checkpoint) {
            Ok(receipt) => receipt,
            Err(error) => {
                let retryable = error.is_retryable();
                self.fail(now, item, !retryable, &error.to_string())?;
                return Ok((false, retryable));
            }
        };
        if let Err(error) = verifier.verify(&item.checkpoint, &receipt) {
            self.fail(now, item, true, &error.to_string())?;
            return Ok((false, false));
        }
        let expected = item.attempts;
        let next = WitnessState {
            attempts: next_attempts(expected)?,
            next_attempt_at: now,
            receipt: Some(WitnessReceiptState {
                bytes: receipt.bytes,
                entry_hash: Some(receipt.entry_hash).filter(|s| !s.is_empty()),
                entry_hash_scheme: Some(receipt.entry_hash_scheme).filter(|s| !s.is_empty()),
                leaf_index: Some(receipt.leaf_index),
                tree_size: Some(receipt.tree_size),
            }),
            permanent: false,
            last_error: None,
            ..item
        };
        self.store.commit_witness(expected, &next)?;
        Ok((true, false))
    }

    fn fail(
        &self,
        now: Timestamp,
        item: WitnessState,
        permanent: bool,
        reason: &str,
    ) -> Result<()> {
        let expected = item.attempts;
        let delay = i64::try_from(self.backoff(expected).as_millis()).unwrap_or(i64::MAX);
        let next = WitnessState {
            attempts: next_attempts(expected)?,
            permanent,
            last_error: Some(bounded_text(reason)),
            next_attempt_at: Timestamp::from_unix_millis(now.unix_millis().saturating_add(delay)),
            ..item
        };
        self.store.commit_witness(expected, &next)
    }

    /// `base_backoff` doubled per earlier attempt, capped at `max_backoff`,
    /// then drawn uniformly below that when `jitter` is set.
    fn backoff(&self, attempts: u32) -> Duration {
        let max = self.config.max_backoff;
        let mut delay = self.config.base_backoff;
        let mut count = 0;
        while count < attempts && delay < max {
            delay = delay.checked_mul(2).map_or(max, |doubled| doubled.min(max));
            count += 1;
        }
        if self.config.jitter && !delay.is_zero() {
            let nanos = u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX);
            delay = Duration::from_nanos(random_u64() % nanos);
        }
        delay
    }
}

fn next_attempts(attempts: u32) -> Result<u32> {
    attempts
        .checked_add(1)
        .ok_or_else(|| Error::invalid("witness attempts overflow"))
}

/// A uniformly distributed `u64` for backoff jitter, which needs no
/// cryptographic strength. The crate has no RNG dependency, so it hashes a
/// counter with the standard library's randomly keyed SipHash.
fn random_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.finish()
}

/// Error text that stays within [`MAX_REASON_BYTES`] once stored, cut at a
/// character boundary (Go `boundedText`; Rust strings are already valid
/// UTF-8).
pub(crate) fn bounded_text(value: &str) -> String {
    if value.len() <= MAX_REASON_BYTES {
        return value.to_string();
    }
    let mut end = MAX_REASON_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// Posts checkpoint statements to `{base_url}/checkpoints` (Go
/// `witness.Client`). Redirects are not followed, the response is bounded,
/// and every receipt field the runner stores is validated.
#[derive(Clone)]
pub struct HttpWitnessClient {
    endpoint: String,
    agent: ureq::Agent,
    max_response_bytes: usize,
}

impl std::fmt::Debug for HttpWitnessClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpWitnessClient")
            .field("endpoint", &self.endpoint)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl HttpWitnessClient {
    /// A client for `base_url` with [`DEFAULT_REQUEST_TIMEOUT`] and a
    /// [`MAX_WITNESS_RESPONSE_BYTES`] response limit.
    pub fn new(base_url: &str) -> Result<Self> {
        Self::with_options(
            base_url,
            DEFAULT_REQUEST_TIMEOUT,
            MAX_WITNESS_RESPONSE_BYTES,
        )
    }

    /// A client with its own request timeout and response limit. The base
    /// URL must be an `http` or `https` origin or path with no user
    /// information, query or fragment; it, a zero timeout or a zero limit
    /// is `invalid`.
    pub fn with_options(
        base_url: &str,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self> {
        let rest = base_url
            .strip_prefix("http://")
            .or_else(|| base_url.strip_prefix("https://"));
        let valid = rest.is_some_and(|rest| {
            let authority = rest.split('/').next().unwrap_or("");
            !authority.is_empty()
                && !authority.contains('@')
                && !rest.contains('?')
                && !rest.contains('#')
        });
        if !valid {
            return Err(Error::invalid("base URL must be an HTTP(S) origin or path"));
        }
        if timeout.is_zero() || max_response_bytes == 0 {
            return Err(Error::invalid(
                "witness timeout and response limit must be positive",
            ));
        }
        Ok(Self {
            endpoint: format!("{}/checkpoints", base_url.trim_end_matches('/')),
            // A redirect is never followed: the statement goes to the URL
            // the host chose and nowhere else.
            agent: ureq::AgentBuilder::new()
                .timeout(timeout)
                .redirects(0)
                .build(),
            max_response_bytes,
        })
    }

    /// The URL statements are posted to.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl Submitter for HttpWitnessClient {
    fn submit(&self, checkpoint: &[u8]) -> std::result::Result<Receipt, SubmitError> {
        let verified = verify_checkpoint_cose_offline(checkpoint);
        if !verified.ok {
            return Err(SubmitError::Rejected(format!(
                "signed checkpoint failed verification: {}",
                verified.errors.join("; ")
            )));
        }
        let result = self
            .agent
            .post(&self.endpoint)
            .set("Content-Type", CLL_CHECKPOINT_CONTENT_TYPE)
            .set("Accept", "application/json")
            .send_bytes(checkpoint);
        let response = match result {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(error) => return Err(SubmitError::Transport(error.to_string())),
        };
        let status = response.status();
        let mut raw = Vec::new();
        response
            .into_reader()
            .take(self.max_response_bytes as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|e| SubmitError::Transport(e.to_string()))?;
        if raw.len() > self.max_response_bytes {
            return Err(SubmitError::Rejected(format!(
                "witness response exceeds {} bytes",
                self.max_response_bytes
            )));
        }
        if !(200..300).contains(&status) {
            return Err(SubmitError::Http {
                status,
                body: bounded_text(String::from_utf8_lossy(&raw).trim()),
            });
        }
        parse_receipt(&raw)
    }
}

/// The fields of a witness response this client consumes. The response is
/// versioned additively, so unknown fields are allowed.
#[derive(Deserialize)]
struct WireReceipt {
    #[serde(default)]
    receipt_b64: String,
    #[serde(default)]
    entry_hash: String,
    #[serde(default)]
    entry_hash_scheme: String,
    #[serde(default)]
    leaf_index: i64,
    #[serde(default)]
    tree_size: i64,
}

fn parse_receipt(raw: &[u8]) -> std::result::Result<Receipt, SubmitError> {
    let wire: WireReceipt = serde_json::from_slice(raw)
        .map_err(|e| SubmitError::Rejected(format!("decode witness response: {e}")))?;
    if wire.entry_hash_scheme != ENTRY_HASH_SCHEME_CHECKPOINT_DIGEST {
        return Err(SubmitError::Rejected(format!(
            "unsupported entry hash scheme {:?}",
            wire.entry_hash_scheme
        )));
    }
    if wire.entry_hash.len() != 64
        || !wire
            .entry_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SubmitError::Rejected("invalid entry hash".into()));
    }
    let portable = |value: i64| u64::try_from(value).is_ok_and(|v| v <= MAX_PORTABLE_INTEGER);
    if wire.tree_size <= 0
        || wire.leaf_index < 0
        || wire.leaf_index >= wire.tree_size
        || !portable(wire.tree_size)
        || !portable(wire.leaf_index)
    {
        return Err(SubmitError::Rejected(
            "invalid transparency position".into(),
        ));
    }
    let bytes = STANDARD
        .decode(&wire.receipt_b64)
        .ok()
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| SubmitError::Rejected("invalid receipt base64".into()))?;
    Ok(Receipt {
        bytes,
        entry_hash: wire.entry_hash,
        entry_hash_scheme: wire.entry_hash_scheme,
        leaf_index: wire.leaf_index,
        tree_size: wire.tree_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::memory::MemoryStore;
    use crate::log::{AppendInput, CheckpointStateStore, EntryStore};
    use crate::runner::{CheckpointRunner, RunnerConfig};
    use ed25519_dalek::SigningKey;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::atomic::AtomicUsize;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).unwrap()
    }

    /// A store with one checkpoint queued for each of `witnesses`.
    fn queued(witnesses: &[&str]) -> (Arc<MemoryStore>, Vec<u8>) {
        let store = Arc::new(MemoryStore::new());
        store
            .append(&AppendInput {
                value: vec![1; 32],
                appended_at: at("2026-10-01T12:00:00.000Z"),
            })
            .unwrap();
        let config = RunnerConfig {
            cadence_entries: 1,
            witness_ids: witnesses.iter().map(|w| w.to_string()).collect(),
            ..RunnerConfig::new("unit-log")
        };
        let runner =
            CheckpointRunner::new(config, store.clone(), SigningKey::from_bytes(&[7; 32])).unwrap();
        runner.run_once(at("2026-10-01T12:00:00.000Z")).unwrap();
        let checkpoint = store.load_cll().unwrap().checkpoint.unwrap().bytes;
        (store, checkpoint)
    }

    struct Fixed(
        fn() -> std::result::Result<Receipt, SubmitError>,
        AtomicUsize,
    );
    impl Submitter for Fixed {
        fn submit(&self, _: &[u8]) -> std::result::Result<Receipt, SubmitError> {
            self.1.fetch_add(1, Ordering::SeqCst);
            (self.0)()
        }
    }

    struct Accept(bool);
    impl Verifier for Accept {
        fn verify(&self, _: &[u8], _: &Receipt) -> std::result::Result<(), VerifyError> {
            if self.0 {
                Ok(())
            } else {
                Err("receipt rejected".into())
            }
        }
    }

    fn receipt() -> std::result::Result<Receipt, SubmitError> {
        Ok(Receipt {
            bytes: b"receipt".to_vec(),
            entry_hash: "ab".repeat(32),
            entry_hash_scheme: "legacy".into(),
            leaf_index: 0,
            tree_size: 1,
        })
    }

    fn runner(
        store: Arc<MemoryStore>,
        submit: fn() -> std::result::Result<Receipt, SubmitError>,
        accept: bool,
        config: DeliveryConfig,
    ) -> DeliveryRunner<MemoryStore> {
        let clients: HashMap<String, Box<dyn Submitter>> = HashMap::from([(
            "w-a".to_string(),
            Box::new(Fixed(submit, AtomicUsize::new(0))) as _,
        )]);
        let verifiers: HashMap<String, Box<dyn Verifier>> =
            HashMap::from([("w-a".to_string(), Box::new(Accept(accept)) as _)]);
        DeliveryRunner::new(config, store, clients, verifiers).unwrap()
    }

    fn no_jitter() -> DeliveryConfig {
        DeliveryConfig {
            jitter: false,
            ..DeliveryConfig::default()
        }
    }

    #[test]
    fn configuration_is_validated() {
        let store = Arc::new(MemoryStore::new());
        let make = |config: DeliveryConfig, client_ids: &[&str], verifier_ids: &[&str]| {
            let clients: HashMap<String, Box<dyn Submitter>> = client_ids
                .iter()
                .map(|id| {
                    (
                        id.to_string(),
                        Box::new(Fixed(receipt, AtomicUsize::new(0))) as Box<dyn Submitter>,
                    )
                })
                .collect();
            let verifiers: HashMap<String, Box<dyn Verifier>> = verifier_ids
                .iter()
                .map(|id| (id.to_string(), Box::new(Accept(true)) as Box<dyn Verifier>))
                .collect();
            DeliveryRunner::new(config, store.clone(), clients, verifiers)
        };
        let ok = DeliveryConfig::default();
        make(ok.clone(), &["w-a"], &["w-a"]).unwrap();
        for (config, clients, verifiers) in [
            (
                DeliveryConfig {
                    poll_interval: Duration::ZERO,
                    ..ok.clone()
                },
                &["w-a"][..],
                &["w-a"][..],
            ),
            (
                DeliveryConfig {
                    base_backoff: Duration::ZERO,
                    ..ok.clone()
                },
                &["w-a"],
                &["w-a"],
            ),
            (
                DeliveryConfig {
                    max_backoff: Duration::from_millis(999),
                    ..ok.clone()
                },
                &["w-a"],
                &["w-a"],
            ),
            (ok.clone(), &[], &[]),
            (ok.clone(), &["w-a"], &[]),
            (ok.clone(), &["w-a"], &["w-b"]),
            (ok.clone(), &["bad id"], &["bad id"]),
        ] {
            let error = make(config, clients, verifiers)
                .err()
                .expect("must be rejected");
            assert_eq!(error.code(), ErrorCode::Invalid);
        }
        let many: Vec<String> = (0..=MAX_WITNESSES).map(|i| format!("w-{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(make(ok, &many, &many).is_err());
    }

    #[test]
    fn a_verified_receipt_completes_the_row() {
        let (store, _) = queued(&["w-a"]);
        let runner = runner(store.clone(), receipt, true, no_jitter());
        assert_eq!(
            runner.run_once(at("2026-10-01T12:00:01.000Z"), 32).unwrap(),
            1
        );
        let row = store.get_witness("w-a", 1).unwrap().unwrap();
        assert_eq!(row.attempts, 1);
        assert_eq!(row.next_attempt_at, at("2026-10-01T12:00:01.000Z"));
        assert!(!row.permanent && row.last_error.is_none());
        let stored = row.receipt.unwrap();
        assert_eq!(stored.bytes, b"receipt");
        assert_eq!(stored.entry_hash_scheme.as_deref(), Some("legacy"));
        assert_eq!((stored.leaf_index, stored.tree_size), (Some(0), Some(1)));
        assert_eq!(
            runner.run_once(at("2026-10-01T12:00:02.000Z"), 32).unwrap(),
            0
        );
    }

    #[test]
    fn failures_back_off_or_become_permanent() {
        let (store, _) = queued(&["w-a"]);
        let retry = runner(
            store.clone(),
            || {
                Err(SubmitError::Http {
                    status: 503,
                    body: "busy".into(),
                })
            },
            true,
            DeliveryConfig {
                base_backoff: Duration::from_secs(1),
                max_backoff: Duration::from_secs(3),
                ..no_jitter()
            },
        );
        // 1 s, then 2 s, then capped at 3 s.
        for (now, next) in [
            ("2026-10-01T12:00:00.000Z", "2026-10-01T12:00:01.000Z"),
            ("2026-10-01T12:00:01.000Z", "2026-10-01T12:00:03.000Z"),
            ("2026-10-01T12:00:03.000Z", "2026-10-01T12:00:06.000Z"),
            ("2026-10-01T12:00:06.000Z", "2026-10-01T12:00:09.000Z"),
        ] {
            assert_eq!(retry.run_once(at(now), 32).unwrap(), 0);
            let row = store.get_witness("w-a", 1).unwrap().unwrap();
            assert_eq!(row.next_attempt_at, at(next));
            assert!(!row.permanent);
            assert_eq!(
                row.last_error.as_deref(),
                Some("witness returned HTTP 503: busy")
            );
        }

        let (store, _) = queued(&["w-a"]);
        let rejected = runner(store.clone(), receipt, false, no_jitter());
        assert_eq!(
            rejected
                .run_once(at("2026-10-01T12:00:00.000Z"), 32)
                .unwrap(),
            0
        );
        let row = store.get_witness("w-a", 1).unwrap().unwrap();
        assert!(row.permanent && row.receipt.is_none());
        assert_eq!(row.last_error.as_deref(), Some("receipt rejected"));

        let (store, _) = queued(&["w-a"]);
        let permanent = runner(
            store.clone(),
            || {
                Err(SubmitError::Http {
                    status: 400,
                    body: "no".into(),
                })
            },
            true,
            no_jitter(),
        );
        permanent
            .run_once(at("2026-10-01T12:00:00.000Z"), 32)
            .unwrap();
        assert!(store.get_witness("w-a", 1).unwrap().unwrap().permanent);
    }

    #[test]
    fn jitter_stays_below_the_backoff() {
        let (store, _) = queued(&["w-a"]);
        let runner = runner(store, receipt, true, DeliveryConfig::default());
        for attempts in 0..40 {
            let ceiling = Duration::from_secs(1 << attempts.min(12)).min(Duration::from_secs(3600));
            assert!(runner.backoff(attempts) < ceiling);
        }
    }

    /// A witness store holding one row, recording what is committed.
    struct OneRow(Mutex<WitnessState>);

    impl WitnessStateStore for OneRow {
        fn pending_witnesses(&self, _: Timestamp, _: usize) -> Result<Vec<WitnessState>> {
            Ok(vec![self.0.lock().unwrap().clone()])
        }

        fn get_witness(&self, _: &str, _: u64) -> Result<Option<WitnessState>> {
            Ok(Some(self.0.lock().unwrap().clone()))
        }

        fn commit_witness(&self, expected: u32, next: &WitnessState) -> Result<()> {
            let mut row = self.0.lock().unwrap();
            assert_eq!(row.attempts, expected);
            *row = next.clone();
            Ok(())
        }
    }

    #[test]
    fn a_tampered_stored_checkpoint_is_not_submitted() {
        let (store, _) = queued(&["w-a"]);
        let mut row = store.get_witness("w-a", 1).unwrap().unwrap();
        let last = row.checkpoint.len() - 1;
        row.checkpoint[last] ^= 1;
        let tampered = Arc::new(OneRow(Mutex::new(row)));
        let submitted = Arc::new(AtomicUsize::new(0));
        struct Counting(Arc<AtomicUsize>);
        impl Submitter for Counting {
            fn submit(&self, _: &[u8]) -> std::result::Result<Receipt, SubmitError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                receipt()
            }
        }
        let clients: HashMap<String, Box<dyn Submitter>> = HashMap::from([(
            "w-a".to_string(),
            Box::new(Counting(submitted.clone())) as _,
        )]);
        let verifiers: HashMap<String, Box<dyn Verifier>> =
            HashMap::from([("w-a".to_string(), Box::new(Accept(true)) as _)]);
        let runner =
            DeliveryRunner::new(no_jitter(), tampered.clone(), clients, verifiers).unwrap();
        assert_eq!(
            runner.run_once(at("2026-10-01T12:00:00.000Z"), 32).unwrap(),
            0
        );
        assert_eq!(submitted.load(Ordering::SeqCst), 0);
        let row = tampered.0.lock().unwrap().clone();
        assert!(row.permanent && row.receipt.is_none());
        assert_eq!(row.attempts, 1);
        assert_eq!(row.next_attempt_at, at("2026-10-01T12:00:01.000Z"));
        assert_eq!(
            row.last_error.as_deref(),
            Some("stored checkpoint failed verification")
        );
    }

    #[test]
    fn a_retryable_failure_ends_that_witness_pass_only() {
        // Two checkpoints queued for w-a and w-b; w-a always fails
        // retryably, w-b always succeeds.
        let (store, _) = queued(&["w-a", "w-b"]);
        store
            .append(&AppendInput {
                value: vec![2; 32],
                appended_at: at("2026-10-01T12:00:00.000Z"),
            })
            .unwrap();
        let config = RunnerConfig {
            cadence_entries: 1,
            witness_ids: vec!["w-a".into(), "w-b".into()],
            ..RunnerConfig::new("unit-log")
        };
        CheckpointRunner::new(config, store.clone(), SigningKey::from_bytes(&[7; 32]))
            .unwrap()
            .run_once(at("2026-10-01T12:00:00.000Z"))
            .unwrap();
        let failing = Arc::new(Fixed(
            || Err(SubmitError::Transport("down".into())),
            AtomicUsize::new(0),
        ));
        struct Shared(Arc<Fixed>);
        impl Submitter for Shared {
            fn submit(&self, c: &[u8]) -> std::result::Result<Receipt, SubmitError> {
                self.0.submit(c)
            }
        }
        let clients: HashMap<String, Box<dyn Submitter>> = HashMap::from([
            ("w-a".to_string(), Box::new(Shared(failing.clone())) as _),
            (
                "w-b".to_string(),
                Box::new(Fixed(receipt, AtomicUsize::new(0))) as _,
            ),
        ]);
        let verifiers: HashMap<String, Box<dyn Verifier>> = HashMap::from([
            ("w-a".to_string(), Box::new(Accept(true)) as _),
            ("w-b".to_string(), Box::new(Accept(true)) as _),
        ]);
        let runner = DeliveryRunner::new(no_jitter(), store.clone(), clients, verifiers).unwrap();
        assert_eq!(
            runner.run_once(at("2026-10-01T12:00:00.000Z"), 32).unwrap(),
            2
        );
        assert_eq!(failing.1.load(Ordering::SeqCst), 1);
        assert_eq!(store.get_witness("w-a", 1).unwrap().unwrap().attempts, 1);
        assert_eq!(store.get_witness("w-a", 3).unwrap().unwrap().attempts, 0);
    }

    #[test]
    fn bounded_text_cuts_at_a_character_boundary() {
        assert_eq!(bounded_text("short"), "short");
        let long = format!("{}é", "a".repeat(MAX_REASON_BYTES - 1));
        let bounded = bounded_text(&long);
        assert_eq!(bounded.len(), MAX_REASON_BYTES - 1);
        assert_eq!(
            bounded_text(&"é".repeat(MAX_REASON_BYTES)).len(),
            MAX_REASON_BYTES
        );
    }

    // -- HTTP client ------------------------------------------------------

    /// The request one connection sent: its head and body.
    struct Request {
        head: String,
        body: Vec<u8>,
    }

    /// Serves `response` to one connection on a fresh port and hands back
    /// what the client sent.
    fn serve_once(response: Vec<u8>) -> (String, std::thread::JoinHandle<Option<Request>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().ok()?;
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                let n = stream.read(&mut chunk).ok()?;
                if n == 0 {
                    return None;
                }
                raw.extend_from_slice(&chunk[..n]);
                if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
            let length: usize = head
                .lines()
                .find_map(|line| {
                    let lower = line.to_ascii_lowercase();
                    lower
                        .strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse().ok())
                })
                .unwrap_or(0);
            while raw.len() < head_end + length {
                let n = stream.read(&mut chunk).ok()?;
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
            }
            let _ = stream.write_all(&response);
            Some(Request {
                head,
                body: raw[head_end..].to_vec(),
            })
        });
        (url, handle)
    }

    fn http(status: &str, extra: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn json_body(scheme: &str, entry_hash: &str, receipt: &str) -> String {
        format!(
            r#"{{"receipt_b64":"{receipt}","entry_hash":"{entry_hash}","entry_hash_scheme":"{scheme}","leaf_index":2,"tree_size":5,"newer_field":true}}"#
        )
    }

    fn submit(response: Vec<u8>) -> (std::result::Result<Receipt, SubmitError>, Option<Request>) {
        let (_, checkpoint) = queued(&[]);
        let (url, server) = serve_once(response);
        let client = HttpWitnessClient::new(&format!("{url}/")).unwrap();
        let result = client.submit(&checkpoint);
        (result, server.join().unwrap())
    }

    #[test]
    fn a_valid_response_is_a_receipt() {
        let hash = "cd".repeat(32);
        let (result, request) = submit(http(
            "200 OK",
            "",
            &json_body("legacy", &hash, "cmVjZWlwdA=="),
        ));
        let receipt = result.unwrap();
        assert_eq!(receipt.bytes, b"receipt");
        assert_eq!(receipt.entry_hash, hash);
        assert_eq!((receipt.leaf_index, receipt.tree_size), (2, 5));
        let request = request.unwrap();
        assert!(
            request.head.starts_with("POST /checkpoints HTTP/1.1\r\n"),
            "{}",
            request.head
        );
        let head = request.head.to_ascii_lowercase();
        assert!(head.contains("content-type: application/cll-checkpoint+cbor\r\n"));
        assert!(head.contains("accept: application/json\r\n"));
        assert_eq!(request.body, queued(&[]).1);
    }

    #[test]
    fn error_statuses_are_classified() {
        for (status, retryable) in [
            ("503 Service Unavailable", true),
            ("500 Internal Server Error", true),
            ("429 Too Many Requests", true),
            ("408 Request Timeout", true),
            ("400 Bad Request", false),
            ("404 Not Found", false),
        ] {
            let (result, _) = submit(http(status, "", " overloaded \n"));
            let error = result.unwrap_err();
            assert_eq!(error.is_retryable(), retryable, "{status}");
            let code: u16 = status[..3].parse().unwrap();
            assert!(
                matches!(&error, SubmitError::Http { status, body } if *status == code && body == "overloaded"),
                "{error:?}"
            );
        }
    }

    #[test]
    fn invalid_responses_are_permanent() {
        let hash = "cd".repeat(32);
        for (body, message) in [
            ("not json".to_string(), "decode witness response"),
            ("[1]".to_string(), "decode witness response"),
            (
                json_body("rfc9162", &hash, "cmVjZWlwdA=="),
                "unsupported entry hash scheme",
            ),
            (
                json_body("", &hash, "cmVjZWlwdA=="),
                "unsupported entry hash scheme",
            ),
            (
                json_body("legacy", &"CD".repeat(32), "cmVjZWlwdA=="),
                "invalid entry hash",
            ),
            (
                json_body("legacy", "cd", "cmVjZWlwdA=="),
                "invalid entry hash",
            ),
            (json_body("legacy", &hash, ""), "invalid receipt base64"),
            (
                json_body("legacy", &hash, "cmVjZWlwdA"),
                "invalid receipt base64",
            ),
            (
                json_body("legacy", &hash, "cmVjZWlwdA==")
                    .replace(r#""leaf_index":2"#, r#""leaf_index":5"#),
                "invalid transparency position",
            ),
            (
                json_body("legacy", &hash, "cmVjZWlwdA==")
                    .replace(r#""tree_size":5"#, r#""tree_size":9007199254740992"#),
                "invalid transparency position",
            ),
        ] {
            let (result, _) = submit(http("200 OK", "", &body));
            let error = result.unwrap_err();
            assert!(!error.is_retryable(), "{body}");
            assert!(error.to_string().starts_with(message), "{body}: {error}");
        }
    }

    #[test]
    fn an_oversized_response_is_permanent() {
        let (_, checkpoint) = queued(&[]);
        let (url, server) = serve_once(http("503 Service Unavailable", "", &"x".repeat(65)));
        let client = HttpWitnessClient::with_options(&url, Duration::from_secs(5), 64).unwrap();
        let error = client.submit(&checkpoint).unwrap_err();
        server.join().unwrap();
        assert!(!error.is_retryable());
        assert_eq!(error.to_string(), "witness response exceeds 64 bytes");
    }

    #[test]
    fn a_redirect_is_not_followed() {
        let (target, target_server) = serve_once(http("200 OK", "", "{}"));
        let (result, _) = submit(http(
            "307 Temporary Redirect",
            &format!("Location: {target}/checkpoints\r\n"),
            "",
        ));
        let error = result.unwrap_err();
        assert!(
            matches!(error, SubmitError::Http { status: 307, .. }),
            "{error:?}"
        );
        assert!(!error.is_retryable());
        // Nothing ever connected to the redirect target; release it.
        drop(std::net::TcpStream::connect(
            target.trim_start_matches("http://"),
        ));
        let request = target_server.join().unwrap();
        assert!(request.is_none_or(|r| r.head.is_empty()));
    }

    #[test]
    fn transport_failures_are_retryable() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let (_, checkpoint) = queued(&[]);
        let error = HttpWitnessClient::new(&url)
            .unwrap()
            .submit(&checkpoint)
            .unwrap_err();
        assert!(matches!(error, SubmitError::Transport(_)), "{error:?}");
        assert!(error.is_retryable());
    }

    #[test]
    fn an_unverifiable_checkpoint_is_not_sent() {
        let client = HttpWitnessClient::new("http://127.0.0.1:9").unwrap();
        let error = client.submit(b"not a checkpoint").unwrap_err();
        assert!(matches!(error, SubmitError::Rejected(_)));
    }

    #[test]
    fn base_urls_are_validated() {
        for url in [
            "http://witness.example",
            "https://witness.example:8443/base/",
            "http://127.0.0.1:8080",
        ] {
            HttpWitnessClient::new(url).unwrap();
        }
        assert_eq!(
            HttpWitnessClient::new("https://w.example/base/")
                .unwrap()
                .endpoint(),
            "https://w.example/base/checkpoints"
        );
        for url in [
            "",
            "ftp://witness.example",
            "http://",
            "http:///path",
            "https://user@witness.example",
            "https://witness.example/?q=1",
            "https://witness.example/#frag",
            "witness.example",
        ] {
            assert_eq!(
                HttpWitnessClient::new(url).unwrap_err().code(),
                ErrorCode::Invalid,
                "{url}"
            );
        }
        assert!(HttpWitnessClient::with_options("http://w.example", Duration::ZERO, 1).is_err());
        assert!(
            HttpWitnessClient::with_options("http://w.example", Duration::from_secs(1), 0).is_err()
        );
    }
}
