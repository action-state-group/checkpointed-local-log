//! `checkpoints.jsonl` reader/writer round-trip: confirms the on-disk shape
//! `store::append_checkpoint`/`read_checkpoints` produce is exactly what
//! `capsule-emit-mesh/checkpointing.py`'s `_persist_checkpoint`/
//! `_read_last_checkpoint` write and read -- one JSON object per line, an
//! additive `checkpoint_cose` hex field spliced in alphabetically ahead of
//! `key_id`, canonical (sorted-key) JSON throughout.

use cll::checkpoint::CheckpointRecord;
use cll::store::{append_checkpoint, read_checkpoints, read_last_checkpoint, CheckpointLine};
use tempfile::tempdir;

fn sample_checkpoint(mmr_size: u64) -> CheckpointRecord {
    CheckpointRecord {
        v: 1,
        kind: "mmr_checkpoint".to_string(),
        log_id: "store-roundtrip-log".to_string(),
        mmr_size,
        root: "a".repeat(64),
        prev_size: 0,
        prev_root: String::new(),
        key_id: "b".repeat(64),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        signature: "c".repeat(128),
        witnesses: Vec::new(),
    }
}

#[test]
fn missing_file_reads_as_empty() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("checkpoints.jsonl");
    assert!(read_checkpoints(&path).unwrap().is_empty());
    assert!(read_last_checkpoint(&path).unwrap().is_none());
}

#[test]
fn append_and_read_round_trip_preserves_field_shape() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("checkpoints.jsonl");

    let line_a = CheckpointLine {
        record: sample_checkpoint(11),
        checkpoint_cose_hex: None,
    };
    let line_b = CheckpointLine {
        record: sample_checkpoint(23),
        checkpoint_cose_hex: Some("deadbeef".to_string()),
    };

    append_checkpoint(&path, &line_a).unwrap();
    append_checkpoint(&path, &line_b).unwrap();

    let lines = read_checkpoints(&path).unwrap();
    assert_eq!(lines, vec![line_a, line_b.clone()]);

    let last = read_last_checkpoint(&path).unwrap().unwrap();
    assert_eq!(last, line_b);

    // The file itself is plain one-JSON-object-per-line text, appendable by
    // any writer -- not a framed/binary format.
    let raw = std::fs::read_to_string(&path).unwrap();
    let file_lines: Vec<&str> = raw.lines().collect();
    assert_eq!(file_lines.len(), 2);
    assert!(!file_lines[0].contains("checkpoint_cose"));
    assert!(file_lines[1].starts_with("{\"checkpoint_cose\":\"deadbeef\",\"key_id\":"));
}

#[test]
fn malformed_line_is_a_typed_parse_error() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("checkpoints.jsonl");
    std::fs::write(&path, "not json\n").unwrap();

    let err = read_checkpoints(&path).unwrap_err();
    match err {
        cll::store::StoreError::Parse { line, .. } => assert_eq!(line, 1),
        other => panic!("expected a Parse error, got {other:?}"),
    }
}
