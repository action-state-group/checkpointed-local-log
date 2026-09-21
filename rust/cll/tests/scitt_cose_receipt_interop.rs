//! Cross-language witness-receipt boundary: each checkpoint conformance
//! vector's `digest_hex` round-trips through scitt-cose's own
//! (`cll`-agnostic) COSE Receipt build/verify path --
//! `scitt_cose.receipt.build_receipt`/`verify_receipt` never import or
//! special-case `cll`, so a witness mints a receipt over whatever hex
//! digest string it is handed, regardless of which language computed it.
//! `checkpoint_conformance_vectors.rs` already proves `digest_hex` is
//! byte-identical between this crate and the Python reference; this test
//! proves that SAME digest receipts cleanly through scitt-cose, closing
//! the loop the README calls the witness-receipt boundary being verified
//! in both languages.
//!
//! No Rust scitt-cose verifier exists yet (only the Python package and a
//! Go port do), so this crate cannot build/verify the receipt itself --
//! it drives the check by invoking the Python reference's own
//! `reference_verifier.py` as a subprocess, which performs exactly this
//! per-vector build+verify (see that file's `check_scitt_cose_receipt_
//! interop`). This is the documented fallback: once a Rust scitt-cose
//! verifier exists, this test should call it directly instead of
//! shelling out.
//!
//! Requires a Python environment with `checkpointed-local-log[dev]`
//! installed (which pulls in `scitt-cose`, the `cll` package's own
//! dependency) -- opt in with `cargo test --features
//! python-interop-tests`. CI's `rust-test` job installs that environment
//! and runs with `--all-features`.

use std::path::Path;
use std::process::Command;

#[test]
fn checkpoint_digests_receipt_through_scitt_cose_in_both_languages() {
    // CARGO_MANIFEST_DIR is rust/cll; the vectors and reference verifier
    // live at the repo root, two levels up.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.join("../..");
    let script = repo_root.join("checkpoint-conformance-vectors/reference_verifier.py");
    assert!(
        script.exists(),
        "reference_verifier.py not found at {script:?}"
    );

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(&repo_root)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn python3 {script:?}: {e}"));

    assert!(
        output.status.success(),
        "checkpoint-conformance-vectors/reference_verifier.py failed -- this includes the \
         scitt-cose witness-receipt round trip (see its check_scitt_cose_receipt_interop):\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
