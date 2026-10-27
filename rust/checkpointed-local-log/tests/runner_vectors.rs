//! Replays `runner-conformance-vectors/vectors.json` (built by the Go
//! runners, `go/internal/runnervectors`) with the Rust checkpoint and
//! witness delivery runners, and checks the checkpoint statement against
//! Go's interop checkpoint (`go/test/interop/checkpoint`).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cll::log::memory::MemoryStore;
use cll::log::{wire, AppendInput, CheckpointStateStore, EntryStore, Timestamp};
use cll::runner::{CheckpointRunner, RunnerConfig};
use cll::witness_delivery::{
    DeliveryConfig, DeliveryRunner, Receipt, SubmitError, Submitter, Verifier, VerifyError,
};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../runner-conformance-vectors/vectors.json"
));

/// What this implementation offers of the document's `capabilities`.
const CAPABILITIES: &[&str] = &["bounded-run", "stop-after-retryable"];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    signing_key_seed: String,
    log_id: String,
    capabilities: HashMap<String, String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    requires: Vec<String>,
    config: Config,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    cadence_entries: u64,
    cadence_age_ms: u64,
    scan_limit: usize,
    /// `null` when the case has no witnesses.
    witness_ids: Option<Vec<String>>,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Step {
    op: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    appended_at: String,
    #[serde(default)]
    now: String,
    #[serde(default)]
    limit: usize,
    #[serde(default)]
    submit: HashMap<String, Vec<Outcome>>,
    #[serde(default)]
    verify: HashMap<String, Vec<bool>>,
    expect: Option<Expect>,
}

#[derive(Clone, Deserialize)]
struct Outcome {
    receipt: Option<WireReceipt>,
    error: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireReceipt {
    bytes: String,
    entry_hash: String,
    entry_hash_scheme: String,
    leaf_index: i64,
    tree_size: i64,
}

#[derive(Deserialize)]
struct Expect {
    result: Value,
}

/// Each witness's scripted answers for one delivery step, served in order.
/// Witnesses are delivered concurrently, so access is locked.
#[derive(Default)]
struct Script {
    submit: Mutex<HashMap<String, VecDeque<Outcome>>>,
    verify: Mutex<HashMap<String, VecDeque<bool>>>,
}

impl Script {
    fn load(&self, step: &Step) {
        *self.submit.lock().unwrap() = step
            .submit
            .iter()
            .map(|(id, outcomes)| (id.clone(), outcomes.iter().cloned().collect()))
            .collect();
        *self.verify.lock().unwrap() = step
            .verify
            .iter()
            .map(|(id, answers)| (id.clone(), answers.iter().copied().collect()))
            .collect();
    }

    fn exhausted(&self) -> Result<(), String> {
        for (id, left) in self.submit.lock().unwrap().iter() {
            if !left.is_empty() {
                return Err(format!(
                    "witness {id} left {} submit outcomes unused",
                    left.len()
                ));
            }
        }
        for (id, left) in self.verify.lock().unwrap().iter() {
            if !left.is_empty() {
                return Err(format!(
                    "witness {id} left {} verify answers unused",
                    left.len()
                ));
            }
        }
        Ok(())
    }
}

struct ScriptedSubmitter {
    script: Arc<Script>,
    id: String,
}

impl Submitter for ScriptedSubmitter {
    fn submit(&self, _: &[u8]) -> Result<Receipt, SubmitError> {
        let outcome = self
            .script
            .submit
            .lock()
            .unwrap()
            .get_mut(&self.id)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| panic!("witness {} submitted more than scripted", self.id));
        match (outcome.error.as_deref(), outcome.receipt) {
            (Some("retryable"), _) => Err(SubmitError::Http {
                status: 503,
                body: "scripted retryable failure".into(),
            }),
            (Some("permanent"), _) => Err(SubmitError::Http {
                status: 400,
                body: "scripted permanent failure".into(),
            }),
            (None, Some(receipt)) => Ok(Receipt {
                bytes: STANDARD.decode(receipt.bytes).unwrap(),
                entry_hash: receipt.entry_hash,
                entry_hash_scheme: receipt.entry_hash_scheme,
                leaf_index: receipt.leaf_index,
                tree_size: receipt.tree_size,
            }),
            _ => panic!("invalid scripted outcome"),
        }
    }
}

struct ScriptedVerifier {
    script: Arc<Script>,
    id: String,
}

impl Verifier for ScriptedVerifier {
    fn verify(&self, _: &[u8], _: &Receipt) -> Result<(), VerifyError> {
        let accepted = self
            .script
            .verify
            .lock()
            .unwrap()
            .get_mut(&self.id)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| panic!("witness {} verified more than scripted", self.id));
        if accepted {
            Ok(())
        } else {
            Err("scripted receipt rejection".into())
        }
    }
}

/// `state` in the vectors' comparable form: the portable state, witnesses
/// sorted by numeric checkpoint size then witness ID, every `lastError`
/// replaced by `"<set>"`.
fn normalize(state: &cll::log::State) -> Value {
    let mut value = wire::state_to_value(state).unwrap();
    let witnesses = value["witnesses"].as_array_mut().unwrap();
    witnesses.sort_by_key(|w| {
        (
            w["checkpointSize"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap(),
            w["witnessId"].as_str().unwrap().to_string(),
        )
    });
    for witness in witnesses {
        if witness.get("lastError").is_some() {
            witness["lastError"] = Value::from("<set>");
        }
    }
    value
}

fn time(text: &str) -> Timestamp {
    Timestamp::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"))
}

fn signing_key(seed_hex: &str) -> SigningKey {
    let seed: [u8; 32] = hex::decode(seed_hex).unwrap().try_into().unwrap();
    SigningKey::from_bytes(&seed)
}

fn replay(document: &Document, case: &Case) {
    let store = Arc::new(MemoryStore::new());
    let config = RunnerConfig {
        cadence_entries: case.config.cadence_entries,
        cadence_age: Duration::from_millis(case.config.cadence_age_ms),
        scan_limit: case.config.scan_limit,
        witness_ids: case.config.witness_ids.clone().unwrap_or_default(),
        ..RunnerConfig::new(document.log_id.clone())
    };
    let runner = CheckpointRunner::new(
        config,
        store.clone(),
        signing_key(&document.signing_key_seed),
    )
    .unwrap();
    let script = Arc::new(Script::default());
    let mut clients: HashMap<String, Box<dyn Submitter>> = HashMap::new();
    let mut verifiers: HashMap<String, Box<dyn Verifier>> = HashMap::new();
    for id in case.config.witness_ids.iter().flatten() {
        let (script, id) = (script.clone(), id.clone());
        clients.insert(
            id.clone(),
            Box::new(ScriptedSubmitter {
                script: script.clone(),
                id: id.clone(),
            }),
        );
        verifiers.insert(id.clone(), Box::new(ScriptedVerifier { script, id }));
    }
    // A delivery runner needs a witness; cases without one never deliver.
    let delivery = (!clients.is_empty()).then(|| {
        DeliveryRunner::new(
            DeliveryConfig {
                base_backoff: Duration::from_millis(case.config.base_backoff_ms),
                max_backoff: Duration::from_millis(case.config.max_backoff_ms),
                jitter: false,
                ..DeliveryConfig::default()
            },
            store.clone(),
            clients,
            verifiers,
        )
        .unwrap()
    });
    for (index, step) in case.steps.iter().enumerate() {
        let context = format!("{} step {index} ({})", case.name, step.op);
        let result = match step.op.as_str() {
            "append" => {
                store
                    .append(&AppendInput {
                        value: STANDARD.decode(&step.value).unwrap(),
                        appended_at: time(&step.appended_at),
                    })
                    .unwrap_or_else(|e| panic!("{context}: {e}"));
                continue;
            }
            "runCheckpoint" => {
                runner
                    .run_once(time(&step.now))
                    .unwrap_or_else(|e| panic!("{context}: {e}"));
                continue;
            }
            "deliverWitnesses" => {
                let delivery = delivery
                    .as_ref()
                    .unwrap_or_else(|| panic!("{context}: needs a witness"));
                script.load(step);
                let completed = delivery
                    .run_once(time(&step.now), step.limit)
                    .unwrap_or_else(|e| panic!("{context}: {e}"));
                script
                    .exhausted()
                    .unwrap_or_else(|e| panic!("{context}: {e}"));
                Value::from(completed)
            }
            "loadCll" => normalize(&store.load_cll().unwrap()),
            other => panic!("{context}: unknown op {other:?}"),
        };
        let expect = step
            .expect
            .as_ref()
            .unwrap_or_else(|| panic!("{context}: no expected result"));
        assert_eq!(result, expect.result, "{context}");
    }
}

#[test]
fn runner_vectors_replay() {
    let document: Document = serde_json::from_str(VECTORS).unwrap();
    for capability in CAPABILITIES {
        assert!(
            document.capabilities.contains_key(*capability),
            "the document does not define {capability:?}"
        );
    }
    assert!(!document.cases.is_empty(), "no runner cases");
    let mut ran = 0;
    for case in &document.cases {
        // Rust has every capability, so no case may be skipped.
        for required in &case.requires {
            assert!(
                CAPABILITIES.contains(&required.as_str()),
                "{} requires unknown capability {required:?}",
                case.name
            );
        }
        replay(&document, case);
        ran += 1;
    }
    assert_eq!(ran, document.cases.len());
}

/// Go's statement for seed bytes 0..31, log `interop-log`, one entry of
/// 32 bytes 0x11 and time 2026-08-27T12:34:56Z, the log's first
/// checkpoint: `cd go && go run ./test/interop/checkpoint write <file>`.
const GO_INTEROP_CHECKPOINT: &str = "d2845866a4012703781f6170706c69636174696f6e2f636c6c2d636865636b706f696e742b63626f7204582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b80fa2016b696e7465726f702d6c6f67026d696e7465726f702d6c6f672331a0588aa6646b696e646e636c6c2d636865636b706f696e74686c6f675f73697a6501696973737565645f617474323032362d30382d32375431323a33343a35365a69707265765f73697a65006a636f6d6d69746d656e7458238158204635e1fa62a599a7880a8d14a56f720a1d40f6e5448ab5a5e39bedc8bd87fa8e6f707265765f636f6d6d69746d656e74405840724d8011b298a6290ab9239a04733871ba9168f20439f2d17e92388be833f9d2bc4b1cee4bd410fd659e868cf657689573b5c8077ca0dddfe5719f16b0f84409";

#[test]
fn checkpoint_statement_matches_go() {
    let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
    let store = Arc::new(MemoryStore::new());
    store
        .append(&AppendInput {
            value: vec![0x11; 32],
            appended_at: time("2026-08-27T12:00:00.000Z"),
        })
        .unwrap();
    let config = RunnerConfig {
        cadence_entries: 1,
        ..RunnerConfig::new("interop-log")
    };
    let runner =
        CheckpointRunner::new(config, store.clone(), SigningKey::from_bytes(&seed)).unwrap();
    assert!(runner.run_once(time("2026-08-27T12:34:56.000Z")).unwrap());
    let statement = store.load_cll().unwrap().checkpoint.unwrap().bytes;
    assert_eq!(hex::encode(statement), GO_INTEROP_CHECKPOINT);
}
