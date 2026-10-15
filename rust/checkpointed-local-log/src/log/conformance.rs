//! Runs the language-neutral CLL backend conformance vectors
//! (`backend-conformance-vectors/` in the repository, pinned here as
//! `conformance/vectors.json`) against any backend, built-in or
//! user-supplied.
//!
//! The vectors implement docs/backend-contract.md. Each case runs its steps
//! against a fresh backend from [`Config::open`]. A backend exposes the
//! interfaces it implements through [`Target`]; every [`Backend`] does so
//! automatically, and an entry-log-only store implements
//! [`Target::entry_store`] alone and runs only the cases that need it.
//!
//! ```
//! use cll::log::{conformance, memory::MemoryStore};
//!
//! let report = conformance::run(conformance::Config::new(MemoryStore::new));
//! report.assert_ok();
//! assert!(report.passed() > 0);
//! ```

use super::wire::{self, WireState, WireWitness};
use super::{
    AppendInput, Backend, CheckpointStateStore, EntryStore, Error, ErrorCode, Result, Timestamp,
    WitnessStateStore,
};
use serde_json::Value;
use std::fmt;

/// The pinned conformance vectors, byte-identical to
/// `backend-conformance-vectors/vectors.json`.
pub const VECTORS: &str = include_str!("conformance/vectors.json");

/// The interfaces a store under test implements. Each method returns `None`
/// for an interface the store does not offer; cases that need it are skipped.
pub trait Target {
    /// The entry log (`entries` cases).
    fn entry_store(&self) -> Option<&dyn EntryStore> {
        None
    }
    /// Checkpoint state (`checkpoint` cases).
    fn checkpoint_state_store(&self) -> Option<&dyn CheckpointStateStore> {
        None
    }
    /// Witness state (`witness` cases).
    fn witness_state_store(&self) -> Option<&dyn WitnessStateStore> {
        None
    }
    /// Whether the store has `close` (`close` cases).
    fn supports_close(&self) -> bool {
        false
    }
    /// Closes the store. Called only when [`Target::supports_close`].
    fn close(&self) -> Result<()> {
        Ok(())
    }
}

impl<B: Backend> Target for B {
    fn entry_store(&self) -> Option<&dyn EntryStore> {
        Some(self)
    }
    fn checkpoint_state_store(&self) -> Option<&dyn CheckpointStateStore> {
        Some(self)
    }
    fn witness_state_store(&self) -> Option<&dyn WitnessStateStore> {
        Some(self)
    }
    fn supports_close(&self) -> bool {
        true
    }
    fn close(&self) -> Result<()> {
        Backend::close(self)
    }
}

/// The store under test.
pub struct Config<'a, T> {
    /// Returns a fresh, empty store for one case. The runner closes it when
    /// the case ends.
    pub open: Box<dyn FnMut() -> T + 'a>,
    /// Closes the given store and opens the same durable state again. `None`
    /// for a store without durable state; cases that reopen are skipped.
    pub reopen: Option<Box<dyn FnMut(T) -> T + 'a>>,
    /// Whether `append` stores a bare identity (the `digest-append`
    /// capability). Without it, `append` of a new identity is `unsupported`.
    pub digest_append: bool,
}

impl<'a, T> Config<'a, T> {
    /// A store with `digest-append` and no reopen.
    pub fn new(open: impl FnMut() -> T + 'a) -> Self {
        Self {
            open: Box::new(open),
            reopen: None,
            digest_append: true,
        }
    }

    /// Declares durable state that `reopen` closes and opens again.
    pub fn with_reopen(mut self, reopen: impl FnMut(T) -> T + 'a) -> Self {
        self.reopen = Some(Box::new(reopen));
        self
    }

    /// Declares the `digest-append` capability absent.
    pub fn without_digest_append(mut self) -> Self {
        self.digest_append = false;
        self
    }
}

/// How one case ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Passed,
    /// The case does not apply to the store, with the reason.
    Skipped(String),
    /// The first failing step, with expected and actual results.
    Failed(String),
}

/// One case's outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseOutcome {
    pub name: String,
    pub status: Status,
}

/// The outcome of every case, in vector order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub cases: Vec<CaseOutcome>,
}

impl Report {
    /// Cases that passed.
    pub fn passed(&self) -> usize {
        self.count(|s| matches!(s, Status::Passed))
    }

    /// Cases that did not apply.
    pub fn skipped(&self) -> usize {
        self.count(|s| matches!(s, Status::Skipped(_)))
    }

    /// Failed cases.
    pub fn failures(&self) -> Vec<&CaseOutcome> {
        self.cases
            .iter()
            .filter(|c| matches!(c.status, Status::Failed(_)))
            .collect()
    }

    /// Panics, listing every failure, unless every applicable case passed.
    pub fn assert_ok(&self) {
        let failures = self.failures();
        assert!(failures.is_empty(), "conformance failures:\n{self}");
    }

    fn count(&self, matches: impl Fn(&Status) -> bool) -> usize {
        self.cases.iter().filter(|c| matches(&c.status)).count()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for case in &self.cases {
            match &case.status {
                Status::Passed => writeln!(f, "pass {}", case.name)?,
                Status::Skipped(why) => writeln!(f, "skip {}: {why}", case.name)?,
                Status::Failed(why) => writeln!(f, "FAIL {}: {why}", case.name)?,
            }
        }
        write!(
            f,
            "{} passed, {} skipped, {} failed",
            self.passed(),
            self.skipped(),
            self.failures().len()
        )
    }
}

/// Runs every case against the store `config` describes.
pub fn run<T: Target>(mut config: Config<'_, T>) -> Report {
    let document: Value = serde_json::from_str(VECTORS).expect("pinned vectors are JSON");
    assert_eq!(
        document["version"], 1,
        "unsupported conformance vector version"
    );
    let (digest_append, reopen) = (config.digest_append, config.reopen.is_some());
    let capability = |name: &str| match name {
        "digest-append" => digest_append,
        "reopen" => reopen,
        "extended-years" => true,
        _ => false,
    };
    let mut report = Report::default();
    for case in document["cases"].as_array().expect("cases") {
        let name = case["name"].as_str().unwrap_or_default().to_owned();
        let skip = strings(&case["requires"])
            .find(|c| !capability(c))
            .map(|c| format!("store lacks capability {c}"))
            .or_else(|| {
                strings(&case["unless"])
                    .find(|c| capability(c))
                    .map(|c| format!("case applies only without capability {c}"))
            });
        let status = match skip {
            Some(reason) => Status::Skipped(reason),
            None => run_case(&mut config, case),
        };
        report.cases.push(CaseOutcome { name, status });
    }
    report
}

fn strings(value: &Value) -> impl Iterator<Item = &str> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn implements<T: Target>(subject: &T, interface: &str) -> bool {
    match interface {
        "entries" => subject.entry_store().is_some(),
        "checkpoint" => subject.checkpoint_state_store().is_some(),
        "witness" => subject.witness_state_store().is_some(),
        "close" => subject.supports_close(),
        _ => false,
    }
}

fn run_case<T: Target>(config: &mut Config<'_, T>, case: &Value) -> Status {
    let mut subject = (config.open)();
    let close = |subject: &T| {
        if subject.supports_close() {
            subject.close()
        } else {
            Ok(())
        }
    };
    if let Some(interface) = strings(&case["interfaces"]).find(|i| !implements(&subject, i)) {
        let _ = close(&subject);
        return Status::Skipped(format!("store does not implement {interface}"));
    }
    let mut outcome = Status::Passed;
    for (index, step) in case["steps"].as_array().into_iter().flatten().enumerate() {
        let op = step["op"].as_str().unwrap_or_default();
        if op == "reopen" {
            let reopen = config.reopen.as_mut().expect("reopen cases require reopen");
            subject = reopen(subject);
            continue;
        }
        let actual = execute(&subject, op, step);
        if let Err(message) = compare(op, &step["expect"], actual) {
            outcome = Status::Failed(format!("step {index} ({op}): {message}"));
            break;
        }
    }
    if let Err(error) = close(&subject) {
        if outcome == Status::Passed {
            outcome = Status::Failed(format!("close after case: {error}"));
        }
    }
    outcome
}

fn compare(op: &str, expect: &Value, actual: Result<Value>) -> std::result::Result<(), String> {
    match (expect.get("error"), actual) {
        (Some(code), Err(error)) if code.as_str() == Some(error.code().as_str()) => Ok(()),
        (Some(code), Err(error)) => Err(format!("want error {code}, got {error}")),
        (Some(code), Ok(value)) => Err(format!("want error {code}, got {value}")),
        (None, Err(error)) => Err(format!("want {}, got {error}", expect["result"])),
        (None, Ok(value)) => {
            let want = normalize(op, expect["result"].clone());
            let got = normalize(op, value);
            if want == got {
                Ok(())
            } else {
                Err(format!("want {want}, got {got}"))
            }
        }
    }
}

/// `loadCll` witness order is not part of the contract: compare the list
/// sorted by numeric checkpoint size, then witness ID.
fn normalize(op: &str, mut value: Value) -> Value {
    if op == "loadCll" {
        if let Some(rows) = value.get_mut("witnesses").and_then(Value::as_array_mut) {
            rows.sort_by_key(|row| {
                (
                    row["checkpointSize"]
                        .as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or_default(),
                    row["witnessId"].as_str().unwrap_or_default().to_owned(),
                )
            });
        }
    }
    value
}

/// An argument Rust's types cannot hold counts as an invalid caller value.
fn unrepresentable() -> Error {
    Error::invalid("argument is not representable")
}

fn missing<T>(what: &str) -> Result<T> {
    Err(Error::invalid(format!("vector step lacks {what}")))
}

fn arg_str<'v>(step: &'v Value, name: &str) -> Result<&'v str> {
    step[name].as_str().map_or_else(|| missing(name), Ok)
}

fn arg_u64(step: &Value, name: &str) -> Result<u64> {
    step[name].as_u64().map_or_else(|| missing(name), Ok)
}

fn arg_bytes(step: &Value, name: &str) -> Result<Vec<u8>> {
    wire::decode_bytes(arg_str(step, name)?, ErrorCode::Invalid).map_err(|_| unrepresentable())
}

fn arg_decimal(step: &Value, name: &str) -> Result<u64> {
    wire::decode_decimal(arg_str(step, name)?, ErrorCode::Invalid).map_err(|_| unrepresentable())
}

fn arg_time(step: &Value, name: &str) -> Result<Timestamp> {
    Timestamp::parse(arg_str(step, name)?).map_err(|_| unrepresentable())
}

fn arg_limit(step: &Value) -> Result<usize> {
    usize::try_from(arg_u64(step, "limit")?).map_err(|_| unrepresentable())
}

fn arg_witness(value: &Value) -> Result<super::WitnessState> {
    let wire: WireWitness = serde_json::from_value(value.clone()).map_err(|_| unrepresentable())?;
    wire::decode_witness(&wire, ErrorCode::Invalid).map_err(|_| unrepresentable())
}

fn arg_state(value: &Value) -> Result<super::State> {
    let wire: WireState = serde_json::from_value(value.clone()).map_err(|_| unrepresentable())?;
    wire::decode_state(&wire, ErrorCode::Invalid).map_err(|_| unrepresentable())
}

fn json<E>(value: std::result::Result<Value, E>) -> Value
where
    E: fmt::Debug,
{
    value.expect("results always encode")
}

fn execute<T: Target>(subject: &T, op: &str, step: &Value) -> Result<Value> {
    let entries = || {
        subject
            .entry_store()
            .ok_or_else(|| Error::invalid("store does not implement entries"))
    };
    let checkpoints = || {
        subject
            .checkpoint_state_store()
            .ok_or_else(|| Error::invalid("store does not implement checkpoint"))
    };
    let witnesses = || {
        subject
            .witness_state_store()
            .ok_or_else(|| Error::invalid("store does not implement witness"))
    };
    match op {
        "append" => {
            let input = &step["input"];
            let input = AppendInput {
                value: arg_bytes(input, "value")?,
                appended_at: arg_time(input, "appendedAt")?,
            };
            let result = entries()?.append(&input)?;
            Ok(serde_json::json!({
                "entry": json(wire::entry_to_value(&result.entry)),
                "outcome": result.outcome.as_str(),
            }))
        }
        "getEntry" => {
            let value = arg_bytes(step, "value")?;
            Ok(json(wire::entry_to_value(&entries()?.get_entry(&value)?)))
        }
        "scanEntries" => {
            let after_seq = arg_decimal(step, "afterSeq")?;
            let rows = entries()?.scan_entries(after_seq, arg_limit(step)?)?;
            Ok(Value::Array(
                rows.iter().map(|e| json(wire::entry_to_value(e))).collect(),
            ))
        }
        "loadCll" => Ok(json(wire::state_to_value(&checkpoints()?.load_cll()?))),
        "commitCll" => {
            let expected_size = arg_decimal(step, "expectedSize")?;
            let expected_checkpoint = match step.get("expectedCheckpoint") {
                Some(_) => Some(arg_bytes(step, "expectedCheckpoint")?),
                None => None,
            };
            let next = arg_state(&step["next"])?;
            checkpoints()?.commit_cll(expected_size, expected_checkpoint.as_deref(), &next)?;
            Ok(Value::Null)
        }
        "pendingWitnesses" => {
            let now = arg_time(step, "now")?;
            let rows = witnesses()?.pending_witnesses(now, arg_limit(step)?)?;
            Ok(Value::Array(
                rows.iter()
                    .map(|w| json(wire::witness_to_value(w)))
                    .collect(),
            ))
        }
        "getWitness" => {
            let size = arg_decimal(step, "checkpointSize")?;
            match witnesses()?.get_witness(arg_str(step, "witnessId")?, size)? {
                Some(row) => Ok(json(wire::witness_to_value(&row))),
                // The contract's not-found convention: Rust's absent value
                // compares as the `not_found` code.
                None => Err(Error::not_found("no witness row for this key")),
            }
        }
        "commitWitness" => {
            let expected =
                u32::try_from(arg_u64(step, "expectedAttempts")?).map_err(|_| unrepresentable())?;
            let next = arg_witness(&step["next"])?;
            witnesses()?.commit_witness(expected, &next)?;
            Ok(Value::Null)
        }
        "close" => subject.close().map(|()| Value::Null),
        other => Err(Error::invalid(format!("unknown conformance op {other:?}"))),
    }
}
