//! `checkpoint::CheckpointSigner` SPI: proves a checkpoint can be signed by
//! anything implementing the trait, not just `ed25519_dalek::SigningKey`
//! held in-process -- the mesh V3 host-native-principals decision (a
//! checkpoint producer hands over a signer, never a private key).

use cll::checkpoint::{
    checkpoint_to_cose, sign_checkpoint_digest, try_sign_checkpoint_digest,
    verify_checkpoint_cose_offline, CheckpointRecord, CheckpointSigner, Signature, SignerError,
};
use cll::mmr::{add_leaf, leaf_hash, peaks, root_from_peaks, MemoryNodeStore, NodeReader};
use ed25519_dalek::SigningKey;

/// A signer that is NOT `ed25519_dalek::SigningKey` -- it wraps one
/// privately and exposes only the `CheckpointSigner` surface, proving the
/// crate's signing entry points depend on the trait, not the concrete
/// dalek type. Stands in for a Nostr/COSE/KMS-backed signer.
struct StubSigner {
    inner: SigningKey,
    key_id: String,
}

impl StubSigner {
    fn new(seed: [u8; 32]) -> Self {
        let inner = SigningKey::from_bytes(&seed);
        let key_id = hex::encode(inner.verifying_key().to_bytes());
        Self { inner, key_id }
    }
}

impl CheckpointSigner for StubSigner {
    fn sign(&self, digest: &[u8]) -> Result<Signature, SignerError> {
        let sig = ed25519_dalek::Signer::sign(&self.inner, digest);
        Ok(Signature(sig.to_bytes()))
    }

    fn key_id(&self) -> String {
        self.key_id.clone()
    }
}

/// A signer that always refuses -- proves the fallible path is real, not
/// merely typed.
struct FailingSigner;

impl CheckpointSigner for FailingSigner {
    fn sign(&self, _digest: &[u8]) -> Result<Signature, SignerError> {
        Err(SignerError::Failed("key vault unreachable".to_string()))
    }

    fn key_id(&self) -> String {
        "0".repeat(64)
    }
}

fn sample_checkpoint(signer: &dyn CheckpointSigner) -> CheckpointRecord {
    CheckpointRecord {
        v: 1,
        kind: "mmr_checkpoint".to_string(),
        log_id: "stub-signer-log".to_string(),
        mmr_size: 3,
        root: "a".repeat(64),
        prev_size: 0,
        prev_root: String::new(),
        key_id: signer.key_id(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        signature: String::new(),
        witnesses: Vec::new(),
    }
}

#[test]
fn stub_signer_round_trips_json_signing_form() {
    let signer = StubSigner::new([9u8; 32]);
    let mut cp = sample_checkpoint(&signer);
    cp.signature = sign_checkpoint_digest(&cp, &signer);
    assert!(cp.verify_signature_offline());
}

#[test]
fn stub_signer_round_trips_through_verify_checkpoint_cose_offline() {
    let signer = StubSigner::new([11u8; 32]);
    let mut store = MemoryNodeStore::new();
    for seq in 0..3u64 {
        add_leaf(&mut store, leaf_hash(&[seq as u8; 32])).unwrap();
    }
    let size = store.size();
    let peak_hashes: Vec<[u8; 32]> = peaks(size)
        .unwrap()
        .iter()
        .map(|&p| store.node(p))
        .collect();
    let root = root_from_peaks(&peak_hashes);

    let mut cp = sample_checkpoint(&signer);
    cp.mmr_size = size;
    cp.root = hex::encode(root);
    cp.signature = sign_checkpoint_digest(&cp, &signer);

    let cose = checkpoint_to_cose(&cp, &signer, &peak_hashes, None, None, None).unwrap();
    let result = verify_checkpoint_cose_offline(&cose);
    assert!(result.ok, "verification failed: {:?}", result.errors);
    let decoded = result.decoded.unwrap();
    assert_eq!(decoded.key_id, signer.key_id());
    assert_eq!(decoded.mmr_size, size);
}

#[test]
fn failing_signer_surfaces_as_a_typed_error_not_a_panic() {
    let signer = FailingSigner;
    let mut cp = sample_checkpoint(&signer);
    // An empty MMR (no peaks) bags to the zero root -- keeps
    // `encode_checkpoint_claims`'s own bagging check out of the way so this
    // test isolates the signer's failure, not a checkpoint-shape mismatch.
    cp.mmr_size = 0;
    cp.root = hex::encode(root_from_peaks(&[]));

    let err = try_sign_checkpoint_digest(&cp, &signer).unwrap_err();
    assert!(matches!(err, SignerError::Failed(_)));

    let cose_err = checkpoint_to_cose(&cp, &signer, &[], None, None, None).unwrap_err();
    assert!(matches!(
        cose_err,
        cll::checkpoint::CheckpointError::Signer(SignerError::Failed(_))
    ));
}

#[test]
#[should_panic(expected = "checkpoint signing failed")]
fn back_compat_wrapper_panics_on_a_failing_signer() {
    let signer = FailingSigner;
    let cp = sample_checkpoint(&signer);
    let _ = sign_checkpoint_digest(&cp, &signer);
}
