//! The commitment substrate a book embeds.
//!
//! I-D section: *The Commitment-Substrate Interface*.
//!
//! A conforming substrate supplies four properties: append order, inclusion,
//! consistency/continuity, and checkpoint identity. [`Substrate`] is that
//! interface; [`CllSubstrate`] is the reference implementation over the
//! Checkpointed Local Log, with a durable file-backed MMR node store and a
//! `checkpoints.jsonl` checkpoint file.
//!
//! Nothing here exposes a `cll` type. [`Checkpoint`], [`WitnessEntry`] and
//! [`InclusionEvidence`] carry the same fields and wire shape as the log's own
//! records (so a stranger's verifier reads them unchanged), and [`Signer`] is
//! this crate's signing interface.
//!
//! **One sequence commitment.** The MMR is the only structure that commits to
//! record order. A book keeps no second hash chain beside it; a record that
//! follows another says so with a typed link, which the substrate does not
//! validate as a chain.
//!
//! **Cutting a checkpoint is two steps.** [`CllSubstrate::prepare_checkpoint`]
//! checks monotonicity, computes the root, signs, and builds the COSE wire
//! form; the caller may then attach witness receipts to the prepared
//! checkpoint (registration needs the wire bytes) before
//! [`CllSubstrate::commit_checkpoint`] persists it. Checkpoint time is the
//! caller's: coarsening it is a privacy decision of the store, not of the log.

use cll::checkpoint::{
    checkpoint_to_cose, try_sign_checkpoint_digest, CheckpointRecord, CheckpointSigner,
    Signature as CllSignature, SignerError, WitnessRecord,
};
use cll::mmr::{
    add_leaf, consistency_proof, inclusion_proof, leaf_count as mmr_leaf_count, leaf_hash,
    leaf_index_to_pos, node_count, peaks, root_from_peaks, Hash, InclusionProof, NodeReader,
};
use cll::node_store::FileNodeStore;
use cll::store::{append_checkpoint, read_last_checkpoint, CheckpointLine};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Byte length of a record id (a SHA-256 digest).
pub const RECORD_ID_LEN: usize = 32;

/// A record id as the substrate commits it.
pub type RecordId = [u8; RECORD_ID_LEN];

/// The `kind` of every checkpoint this substrate cuts.
pub const CHECKPOINT_KIND: &str = "mmr_checkpoint";

/// Parse a record id from lowercase or uppercase hex; `None` unless it is
/// exactly [`RECORD_ID_LEN`] bytes.
pub fn record_id_from_hex(s: &str) -> Option<RecordId> {
    hex::decode(s).ok()?.try_into().ok()
}

/// The substrate interface (I-D *The Commitment-Substrate Interface*).
pub trait Substrate {
    type Error;

    /// Append order: commit `record_id` at the next position and return it.
    fn append(&mut self, record_id: &RecordId) -> Result<u64, Self::Error>;

    /// Records committed so far.
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Checkpoint identity: the latest committed checkpoint, if any.
    fn latest_checkpoint(&self) -> Option<&Checkpoint>;

    /// Inclusion: evidence that the record at `position` is committed under
    /// `checkpoint`.
    fn inclusion(
        &self,
        position: u64,
        checkpoint: &Checkpoint,
    ) -> Result<InclusionEvidence, Self::Error>;
}

/// Signs checkpoint digests. Implemented for a local Ed25519 key; a remote or
/// hardware signer implements it too.
pub trait Signer {
    /// Sign `digest` (the checkpoint's hex digest, as bytes).
    fn sign(&self, digest: &[u8]) -> Result<[u8; 64], SignError>;

    /// The signer's key id: the raw Ed25519 public key, hex.
    fn key_id(&self) -> String;
}

impl Signer for ed25519_dalek::SigningKey {
    fn sign(&self, digest: &[u8]) -> Result<[u8; 64], SignError> {
        Ok(ed25519_dalek::Signer::sign(self, digest).to_bytes())
    }

    fn key_id(&self) -> String {
        hex::encode(self.verifying_key().to_bytes())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("signing failed: {0}")]
pub struct SignError(pub String);

/// Adapts a [`Signer`] to the log's own signer interface.
struct SignerAdapter<'a>(&'a dyn Signer);

impl CheckpointSigner for SignerAdapter<'_> {
    fn sign(&self, digest: &[u8]) -> Result<CllSignature, SignerError> {
        self.0
            .sign(digest)
            .map(CllSignature)
            .map_err(|e| SignerError::Failed(e.0))
    }

    fn key_id(&self) -> String {
        self.0.key_id()
    }
}

/// One witness receipt attached to a checkpoint. Same fields and wire shape
/// as the log's witness record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessEntry {
    pub ts_url: String,
    /// sha256(bytes.fromhex(checkpoint_digest)).hex() -- witness-derived.
    pub entry_hash: String,
    /// base64-encoded COSE Receipt.
    pub receipt_b64: String,
    pub leaf_index: i64,
    pub tree_size: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_stub: bool,
}

/// A signed checkpoint: one committed state, named independently of the
/// store that produced it (I-D checkpoint identity). Same fields and wire
/// shape as the log's checkpoint record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub v: u32,
    pub kind: String,
    pub log_id: String,
    pub mmr_size: u64,
    /// Hex MMR root at `mmr_size`.
    pub root: String,
    /// 0 for the first checkpoint.
    pub prev_size: u64,
    /// Hex root at `prev_size`; empty for the first checkpoint.
    pub prev_root: String,
    pub key_id: String,
    pub timestamp: String,
    /// Hex Ed25519 signature over [`Checkpoint::digest`].
    pub signature: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witnesses: Vec<WitnessEntry>,
}

impl Checkpoint {
    /// Records this checkpoint covers.
    pub fn leaf_count(&self) -> Result<u64, SubstrateError> {
        Ok(mmr_leaf_count(self.mmr_size)?)
    }

    /// The canonical JSON the signature covers.
    pub fn signing_body(&self) -> String {
        self.to_log().signing_body()
    }

    /// Hex SHA-256 of [`Checkpoint::signing_body`]: what is signed and what a
    /// witness registers.
    pub fn digest(&self) -> String {
        self.to_log().digest()
    }

    /// Verify `signature` from this record alone (key from `key_id`).
    pub fn verify_signature_offline(&self) -> bool {
        self.to_log().verify_signature_offline()
    }

    fn to_log(&self) -> CheckpointRecord {
        CheckpointRecord {
            v: self.v,
            kind: self.kind.clone(),
            log_id: self.log_id.clone(),
            mmr_size: self.mmr_size,
            root: self.root.clone(),
            prev_size: self.prev_size,
            prev_root: self.prev_root.clone(),
            key_id: self.key_id.clone(),
            timestamp: self.timestamp.clone(),
            signature: self.signature.clone(),
            witnesses: self
                .witnesses
                .iter()
                .map(|w| WitnessRecord {
                    ts_url: w.ts_url.clone(),
                    entry_hash: w.entry_hash.clone(),
                    receipt_b64: w.receipt_b64.clone(),
                    leaf_index: w.leaf_index,
                    tree_size: w.tree_size,
                    is_stub: w.is_stub,
                })
                .collect(),
        }
    }

    fn from_log(cp: CheckpointRecord) -> Self {
        Self {
            v: cp.v,
            kind: cp.kind,
            log_id: cp.log_id,
            mmr_size: cp.mmr_size,
            root: cp.root,
            prev_size: cp.prev_size,
            prev_root: cp.prev_root,
            key_id: cp.key_id,
            timestamp: cp.timestamp,
            signature: cp.signature,
            witnesses: cp
                .witnesses
                .into_iter()
                .map(|w| WitnessEntry {
                    ts_url: w.ts_url,
                    entry_hash: w.entry_hash,
                    receipt_b64: w.receipt_b64,
                    leaf_index: w.leaf_index,
                    tree_size: w.tree_size,
                    is_stub: w.is_stub,
                })
                .collect(),
        }
    }
}

/// Evidence that one record occupies one position under a checkpoint. Same
/// fields and wire shape as the log's inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionEvidence {
    pub v: u32,
    pub kind: String,
    pub size: u64,
    pub leaf_index: u64,
    pub witness: Vec<String>,
    pub peaks_left: Vec<String>,
    pub peaks_right: Vec<String>,
}

impl InclusionEvidence {
    fn from_log(p: InclusionProof) -> Self {
        Self {
            v: p.v,
            kind: p.kind,
            size: p.size,
            leaf_index: p.leaf_index,
            witness: p.witness,
            peaks_left: p.peaks_left,
            peaks_right: p.peaks_right,
        }
    }

    fn to_log(&self) -> InclusionProof {
        InclusionProof {
            v: self.v,
            kind: self.kind.clone(),
            size: self.size,
            leaf_index: self.leaf_index,
            witness: self.witness.clone(),
            peaks_left: self.peaks_left.clone(),
            peaks_right: self.peaks_right.clone(),
        }
    }

    /// The wire JSON of this evidence (the member set a `scitt_cose`
    /// inclusion-proof reader takes).
    pub fn to_wire_json(&self) -> serde_json::Value {
        serde_json::json!({
            "v": self.v,
            "kind": self.kind,
            "size": self.size,
            "leaf_index": self.leaf_index,
            "witness": self.witness,
            "peaks_left": self.peaks_left,
            "peaks_right": self.peaks_right,
        })
    }
}

/// Check `proof` places `record_id` at `leaf_index` under a checkpoint of
/// `size` with root `root`. Offline; needs nothing from the store.
pub fn verify_inclusion(
    root: &RecordId,
    size: u64,
    leaf_index: u64,
    record_id: &RecordId,
    proof: &InclusionEvidence,
) -> bool {
    cll::mmr::verify_inclusion(root, size, leaf_index, record_id, &proof.to_log())
}

/// What opening the durable node store found: its node count, and how many
/// bytes of a torn trailing write were truncated away.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenReport {
    pub node_count: u64,
    pub truncated_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum SubstrateError {
    #[error("node store error: {0}")]
    NodeStore(String),
    #[error("checkpoints.jsonl error: {0}")]
    Store(String),
    #[error("mmr error: {0}")]
    Mmr(String),
    #[error("checkpoint error: {0}")]
    Checkpoint(String),
    #[error("signer error: {0}")]
    Signer(String),
    #[error("cannot checkpoint an empty MMR (no leaves appended yet)")]
    EmptyMmr,
    #[error(
        "MMR size {current_size} is not greater than the previous checkpoint's size {prev_size} \
         -- monotonicity violated"
    )]
    RollbackSize { current_size: u64, prev_size: u64 },
    #[error(
        "MMR root at the previous checkpoint's size ({prev_size}) is {actual_root} but that \
         checkpoint recorded root {recorded_root} -- the log has been mutated since"
    )]
    RollbackRoot {
        prev_size: u64,
        actual_root: String,
        recorded_root: String,
    },
    #[error("leaf {leaf_index} is committed as {stored_leaf}, but the record id given leaf-hashes to {expected_leaf}")]
    LeafMismatch {
        leaf_index: u64,
        stored_leaf: String,
        expected_leaf: String,
    },
    #[error("cutting at {requested} leaves, but only {available} are committed")]
    CutBeyondLog { requested: u64, available: u64 },
}

impl From<cll::mmr::MmrError> for SubstrateError {
    fn from(e: cll::mmr::MmrError) -> Self {
        SubstrateError::Mmr(e.to_string())
    }
}

impl From<cll::node_store::NodeStoreError> for SubstrateError {
    fn from(e: cll::node_store::NodeStoreError) -> Self {
        SubstrateError::NodeStore(e.to_string())
    }
}

impl From<cll::store::StoreError> for SubstrateError {
    fn from(e: cll::store::StoreError) -> Self {
        SubstrateError::Store(e.to_string())
    }
}

impl From<cll::checkpoint::CheckpointError> for SubstrateError {
    fn from(e: cll::checkpoint::CheckpointError) -> Self {
        SubstrateError::Checkpoint(e.to_string())
    }
}

impl From<SignerError> for SubstrateError {
    fn from(e: SignerError) -> Self {
        SubstrateError::Signer(e.to_string())
    }
}

/// A signed checkpoint not yet persisted. Witness receipts may be attached
/// to `checkpoint.witnesses` before [`CllSubstrate::commit_checkpoint`].
#[derive(Debug, Clone)]
pub struct PreparedCheckpoint {
    pub checkpoint: Checkpoint,
    cose: Option<Vec<u8>>,
    cose_error: Option<String>,
    leaf_count: u64,
}

impl PreparedCheckpoint {
    /// The COSE wire form, when it could be built. Building it is
    /// best-effort: a failure never blocks the JSON checkpoint, it only means
    /// the checkpoint stays self-attested (no witness can register it).
    pub fn cose(&self) -> Option<&[u8]> {
        self.cose.as_deref()
    }

    /// Why the COSE wire form could not be built, if it could not.
    pub fn cose_error(&self) -> Option<&str> {
        self.cose_error.as_deref()
    }

    /// The leaf count this checkpoint was cut at.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }
}

/// The reference substrate: a Checkpointed Local Log with a durable MMR node
/// store and a JSON-lines checkpoint file.
pub struct CllSubstrate {
    node_store: FileNodeStore,
    checkpoints_path: PathBuf,
    last_checkpoint: Option<Checkpoint>,
    last_checkpoint_cose: Option<Vec<u8>>,
}

impl CllSubstrate {
    /// Open (or create) the node store at `node_store_path` and resume from
    /// the last line of `checkpoints_path` if it exists. A torn trailing
    /// node write is truncated away and reported.
    pub fn open(
        node_store_path: &Path,
        checkpoints_path: &Path,
    ) -> Result<(Self, OpenReport), SubstrateError> {
        let (node_store, report) = FileNodeStore::open(node_store_path)?;
        let last_line = read_last_checkpoint(checkpoints_path)?;
        let last_checkpoint = last_line
            .as_ref()
            .map(|l| Checkpoint::from_log(l.record.clone()));
        let last_checkpoint_cose = last_line
            .and_then(|l| l.checkpoint_cose_hex)
            .and_then(|hex_str| hex::decode(hex_str).ok());
        Ok((
            Self {
                node_store,
                checkpoints_path: checkpoints_path.to_path_buf(),
                last_checkpoint,
                last_checkpoint_cose,
            },
            OpenReport {
                node_count: report.node_count,
                truncated_bytes: report.truncated_bytes,
            },
        ))
    }

    /// Records committed so far.
    pub fn leaf_count(&self) -> Result<u64, SubstrateError> {
        Ok(mmr_leaf_count(self.node_store.size())?)
    }

    /// Commit `record_id` as the next leaf; returns its leaf index.
    pub fn append_leaf(&mut self, record_id: &RecordId) -> Result<u64, SubstrateError> {
        let index = self.leaf_count()?;
        add_leaf(&mut self.node_store, leaf_hash(record_id))?;
        Ok(index)
    }

    /// Check the leaf at `leaf_index` commits `record_id`. A store uses this
    /// to detect a record file rewritten under an existing node store: the
    /// substrate must never checkpoint over superseded leaves.
    pub fn check_leaf(&self, leaf_index: u64, record_id: &RecordId) -> Result<(), SubstrateError> {
        let expected_leaf = leaf_hash(record_id);
        let stored_leaf = self.node_store.node(leaf_index_to_pos(leaf_index)?);
        if stored_leaf != expected_leaf {
            return Err(SubstrateError::LeafMismatch {
                leaf_index,
                stored_leaf: hex::encode(stored_leaf),
                expected_leaf: hex::encode(expected_leaf),
            });
        }
        Ok(())
    }

    /// The latest persisted checkpoint.
    pub fn last_checkpoint(&self) -> Option<&Checkpoint> {
        self.last_checkpoint.as_ref()
    }

    /// The latest persisted checkpoint's COSE wire form, if it had one.
    pub fn last_checkpoint_cose(&self) -> Option<&[u8]> {
        self.last_checkpoint_cose.as_deref()
    }

    /// Mutable access to the latest checkpoint's witness list, for a late
    /// witness registration. The addition is in memory only, exactly as the
    /// registration retry has always behaved; the next persisted checkpoint
    /// supersedes it.
    pub fn last_checkpoint_witnesses_mut(&mut self) -> Option<&mut Vec<WitnessEntry>> {
        self.last_checkpoint.as_mut().map(|cp| &mut cp.witnesses)
    }

    /// Sign a checkpoint over the first `leaf_count` leaves, chained to the
    /// last persisted checkpoint. Refuses an empty cut, a cut that does not
    /// grow the log, and a log whose root at the previous checkpoint's size
    /// no longer matches the root that checkpoint recorded.
    pub fn prepare_checkpoint(
        &self,
        leaf_count: u64,
        log_id: &str,
        timestamp: &str,
        signer: &dyn Signer,
    ) -> Result<PreparedCheckpoint, SubstrateError> {
        let available = self.leaf_count()?;
        if leaf_count > available {
            return Err(SubstrateError::CutBeyondLog {
                requested: leaf_count,
                available,
            });
        }
        let current_size = node_count(leaf_count);
        if current_size == 0 {
            return Err(SubstrateError::EmptyMmr);
        }

        let (prev_size, prev_root) = match &self.last_checkpoint {
            None => (0u64, String::new()),
            Some(prev) => {
                if current_size <= prev.mmr_size {
                    return Err(SubstrateError::RollbackSize {
                        current_size,
                        prev_size: prev.mmr_size,
                    });
                }
                let actual_prev_root =
                    hex::encode(root_from_peaks(&self.peak_hashes(prev.mmr_size)?));
                if actual_prev_root != prev.root {
                    return Err(SubstrateError::RollbackRoot {
                        prev_size: prev.mmr_size,
                        actual_root: actual_prev_root,
                        recorded_root: prev.root.clone(),
                    });
                }
                (prev.mmr_size, prev.root.clone())
            }
        };

        let new_peak_hashes = self.peak_hashes(current_size)?;
        let root = hex::encode(root_from_peaks(&new_peak_hashes));
        let adapter = SignerAdapter(signer);
        let mut cp = CheckpointRecord {
            v: 1,
            kind: CHECKPOINT_KIND.to_string(),
            log_id: log_id.to_string(),
            mmr_size: current_size,
            root,
            prev_size,
            prev_root,
            key_id: adapter.key_id(),
            timestamp: timestamp.to_string(),
            signature: String::new(),
            witnesses: Vec::new(),
        };
        cp.signature = try_sign_checkpoint_digest(&cp, &adapter)?;

        // COSE wire form, best-effort: `cadence_seconds` is omitted, as the
        // Python reference omits it.
        let prev_peak_hashes = if prev_size > 0 {
            Some(self.peak_hashes(prev_size)?)
        } else {
            None
        };
        let consistency = if prev_size > 0 {
            Some(consistency_proof(
                &self.node_store,
                prev_size,
                current_size,
            )?)
        } else {
            None
        };
        let (cose, cose_error) = match checkpoint_to_cose(
            &cp,
            &adapter,
            &new_peak_hashes,
            prev_peak_hashes.as_deref(),
            consistency.as_ref(),
            None,
        ) {
            Ok(bytes) => (Some(bytes), None),
            Err(err) => (None, Some(err.to_string())),
        };

        Ok(PreparedCheckpoint {
            checkpoint: Checkpoint::from_log(cp),
            cose,
            cose_error,
            leaf_count,
        })
    }

    /// Persist a prepared checkpoint (with whatever witness receipts were
    /// attached) as the new latest checkpoint.
    pub fn commit_checkpoint(
        &mut self,
        prepared: PreparedCheckpoint,
    ) -> Result<Checkpoint, SubstrateError> {
        let PreparedCheckpoint {
            checkpoint, cose, ..
        } = prepared;
        append_checkpoint(
            &self.checkpoints_path,
            &CheckpointLine {
                record: checkpoint.to_log(),
                checkpoint_cose_hex: cose.as_ref().map(hex::encode),
            },
        )?;
        self.last_checkpoint = Some(checkpoint.clone());
        self.last_checkpoint_cose = cose;
        Ok(checkpoint)
    }

    /// Inclusion evidence for the leaf at `leaf_index` under a checkpoint of
    /// `mmr_size`.
    pub fn inclusion_at(
        &self,
        leaf_index: u64,
        mmr_size: u64,
    ) -> Result<InclusionEvidence, SubstrateError> {
        Ok(InclusionEvidence::from_log(inclusion_proof(
            &self.node_store,
            leaf_index,
            mmr_size,
        )?))
    }

    fn peak_hashes(&self, size: u64) -> Result<Vec<Hash>, SubstrateError> {
        Ok(peaks(size)?
            .iter()
            .map(|&p| self.node_store.node(p))
            .collect())
    }
}

impl Substrate for CllSubstrate {
    type Error = SubstrateError;

    fn append(&mut self, record_id: &RecordId) -> Result<u64, SubstrateError> {
        self.append_leaf(record_id)
    }

    fn len(&self) -> u64 {
        // A node store that opened cleanly always has a valid MMR size.
        self.leaf_count().unwrap_or(0)
    }

    fn latest_checkpoint(&self) -> Option<&Checkpoint> {
        self.last_checkpoint()
    }

    fn inclusion(
        &self,
        position: u64,
        checkpoint: &Checkpoint,
    ) -> Result<InclusionEvidence, SubstrateError> {
        self.inclusion_at(position, checkpoint.mmr_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn id(n: u8) -> RecordId {
        [n; RECORD_ID_LEN]
    }

    fn open(dir: &Path) -> CllSubstrate {
        CllSubstrate::open(&dir.join("mmr_nodes.dat"), &dir.join("checkpoints.jsonl"))
            .unwrap()
            .0
    }

    fn cut(
        s: &mut CllSubstrate,
        leaves: u64,
        key: &SigningKey,
    ) -> Result<Checkpoint, SubstrateError> {
        let p = s.prepare_checkpoint(leaves, "log", "2026-09-27T00:00:00.000Z", key)?;
        s.commit_checkpoint(p)
    }

    #[test]
    fn checkpoints_chain_prove_inclusion_and_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut s = open(dir.path());
        for n in 0..3 {
            assert_eq!(s.append(&id(n)).unwrap(), n as u64);
        }
        let first = cut(&mut s, 3, &key).unwrap();
        assert!(first.verify_signature_offline());
        assert_eq!((first.prev_size, first.prev_root.as_str()), (0, ""));
        for n in 3..5 {
            s.append(&id(n)).unwrap();
        }
        drop(s);

        let mut s = open(dir.path());
        assert_eq!(s.len(), 5);
        assert_eq!(s.latest_checkpoint(), Some(&first));
        let second = cut(&mut s, 5, &key).unwrap();
        assert_eq!(
            (second.prev_size, &second.prev_root),
            (first.mmr_size, &first.root)
        );
        let root = record_id_from_hex(&second.root).unwrap();
        for n in 0..5u8 {
            let proof = s.inclusion(n as u64, &second).unwrap();
            assert!(verify_inclusion(
                &root,
                second.mmr_size,
                n as u64,
                &id(n),
                &proof
            ));
            assert!(!verify_inclusion(
                &root,
                second.mmr_size,
                n as u64,
                &id(99),
                &proof
            ));
        }
    }

    #[test]
    fn a_cut_must_grow_the_log_and_cannot_be_empty_or_beyond_it() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut s = open(dir.path());
        assert!(matches!(
            cut(&mut s, 0, &key),
            Err(SubstrateError::EmptyMmr)
        ));
        s.append(&id(1)).unwrap();
        assert!(matches!(
            cut(&mut s, 2, &key),
            Err(SubstrateError::CutBeyondLog {
                requested: 2,
                available: 1
            })
        ));
        cut(&mut s, 1, &key).unwrap();
        assert!(matches!(
            cut(&mut s, 1, &key),
            Err(SubstrateError::RollbackSize { .. })
        ));
    }

    #[test]
    fn a_rewritten_history_under_a_checkpoint_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut s = open(dir.path());
        s.append(&id(1)).unwrap();
        cut(&mut s, 1, &key).unwrap();
        drop(s);
        // Rebuild the node store over a different first leaf, keep the
        // checkpoint file: the recorded root no longer matches.
        std::fs::remove_file(dir.path().join("mmr_nodes.dat")).unwrap();
        let mut s = open(dir.path());
        s.append(&id(2)).unwrap();
        s.append(&id(3)).unwrap();
        assert!(matches!(
            cut(&mut s, 2, &key),
            Err(SubstrateError::RollbackRoot { .. })
        ));
    }

    #[test]
    fn check_leaf_detects_a_different_record_at_a_position() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = open(dir.path());
        s.append(&id(1)).unwrap();
        s.check_leaf(0, &id(1)).unwrap();
        assert!(matches!(
            s.check_leaf(0, &id(2)),
            Err(SubstrateError::LeafMismatch { leaf_index: 0, .. })
        ));
    }

    #[test]
    fn witnesses_attached_before_commit_are_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut s = open(dir.path());
        s.append(&id(1)).unwrap();
        let mut p = s
            .prepare_checkpoint(1, "log", "2026-09-27T00:00:00.000Z", &key)
            .unwrap();
        assert!(p.cose().is_some(), "{:?}", p.cose_error());
        p.checkpoint.witnesses.push(WitnessEntry {
            ts_url: "https://witness.example".into(),
            entry_hash: "e".repeat(64),
            receipt_b64: "cmVjZWlwdA==".into(),
            leaf_index: 0,
            tree_size: 1,
            is_stub: false,
        });
        let committed = s.commit_checkpoint(p).unwrap();
        drop(s);
        let s = open(dir.path());
        assert_eq!(s.last_checkpoint(), Some(&committed));
        assert_eq!(s.last_checkpoint().unwrap().witnesses.len(), 1);
        assert!(s.last_checkpoint_cose().is_some());
    }

    #[test]
    fn wire_shapes_match_the_logs_own_records() {
        let cp = Checkpoint {
            v: 1,
            kind: CHECKPOINT_KIND.into(),
            log_id: "log".into(),
            mmr_size: 1,
            root: "a".repeat(64),
            prev_size: 0,
            prev_root: String::new(),
            key_id: "b".repeat(64),
            timestamp: "2026-09-27T00:00:00.000Z".into(),
            signature: "c".repeat(128),
            witnesses: vec![],
        };
        assert_eq!(
            serde_json::to_value(&cp).unwrap(),
            serde_json::to_value(cp.to_log()).unwrap()
        );
        assert_eq!(Checkpoint::from_log(cp.to_log()), cp);
        assert_eq!(cp.digest(), cp.to_log().digest());
    }
}
