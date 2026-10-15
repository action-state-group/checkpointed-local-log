//! Backend behavior the conformance vectors do not cover
//! (docs/backend-contract.md, "Checks outside the vectors"): concurrency,
//! cross-handle visibility, copies, reopen, corrupt durable data, JSONL
//! writer exclusion and torn tails, and SQL coexistence.

use cll::log::{
    AppendInput, AppendOutcome, Backend, CheckpointStateStore, EntrySource, EntryStore, ErrorCode,
    State, Timestamp, WitnessState, WitnessStateStore,
};
use std::sync::Arc;

fn input(byte: u8, millis: i64) -> AppendInput {
    AppendInput {
        value: vec![byte; 32],
        appended_at: Timestamp::from_unix_millis(millis),
    }
}

fn wide_input(index: u32) -> AppendInput {
    let mut value = vec![0; 32];
    value[..4].copy_from_slice(&index.to_be_bytes());
    AppendInput {
        value,
        appended_at: Timestamp::from_unix_millis(1_788_264_000_000 + i64::from(index)),
    }
}

fn witness(id: &str, size: u64) -> WitnessState {
    WitnessState {
        witness_id: id.into(),
        checkpoint_size: size,
        checkpoint: b"checkpoint".to_vec(),
        attempts: 0,
        next_attempt_at: Timestamp::from_unix_millis(0),
        receipt: None,
        permanent: false,
        last_error: None,
    }
}

fn one_leaf_state() -> State {
    State {
        size: 1,
        nodes: vec![vec![7; 32]],
        indexed_seq: 1,
        witnesses: vec![witness("primary", 1)],
        ..State::default()
    }
}

/// Concurrent appends on one shared handle get distinct dense sequences.
fn concurrent_appends(store: Arc<dyn Backend + Send + Sync>) {
    let threads: Vec<_> = (0..4u32)
        .map(|thread| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for index in 0..10 {
                    let result = store.append(&wide_input(thread * 100 + index)).unwrap();
                    assert_eq!(result.outcome, AppendOutcome::Inserted);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    let entries = store.scan_entries(0, 1000).unwrap();
    assert_eq!(entries.len(), 40);
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
        assert_eq!(store.get_entry(&entry.value).unwrap(), *entry);
    }
}

/// Mutating a returned value never changes stored state.
fn results_are_copies(store: &dyn Backend) {
    let mut entry = store.append(&input(1, 0)).unwrap().entry;
    entry.value[0] = 0xff;
    assert_eq!(store.get_entry(&[1; 32]).unwrap().value, vec![1; 32]);
    store.commit_cll(0, None, &one_leaf_state()).unwrap();
    let mut state = store.load_cll().unwrap();
    state.nodes[0][0] = 0;
    state.witnesses[0].checkpoint.clear();
    assert_eq!(store.load_cll().unwrap(), one_leaf_state());
}

/// Two handles on one persistent log see each other's writes.
#[cfg(any(feature = "sqlite", feature = "mysql"))]
fn cross_handle(first: &dyn Backend, second: &dyn Backend) {
    first.append(&input(1, 0)).unwrap();
    assert_eq!(second.get_entry(&[1; 32]).unwrap().seq, 1);
    let again = second.append(&input(1, 99)).unwrap();
    assert_eq!(again.outcome, AppendOutcome::Idempotent);
    assert_eq!(second.append(&input(2, 0)).unwrap().entry.seq, 2);
    assert_eq!(first.scan_entries(0, 10).unwrap().len(), 2);
    first.commit_cll(0, None, &one_leaf_state()).unwrap();
    // The second handle's view is stale only until it reads again.
    assert_eq!(
        second
            .commit_cll(0, None, &one_leaf_state())
            .unwrap_err()
            .code(),
        ErrorCode::Contention
    );
    let mut next = witness("primary", 1);
    next.attempts = 1;
    second.commit_witness(0, &next).unwrap();
    assert_eq!(
        first.commit_witness(0, &next).unwrap_err().code(),
        ErrorCode::Contention
    );
    assert_eq!(first.get_witness("primary", 1).unwrap(), Some(next));
}

/// A commit rewriting an identical witness row succeeds.
fn identical_witness_commit(store: &dyn Backend) {
    store.commit_cll(0, None, &one_leaf_state()).unwrap();
    let row = witness("primary", 1);
    store.commit_witness(0, &row).unwrap();
    assert_eq!(store.get_witness("primary", 1).unwrap(), Some(row));
}

#[test]
fn memory_backend() {
    use cll::log::memory::MemoryStore;
    concurrent_appends(Arc::new(MemoryStore::new()));
    results_are_copies(&MemoryStore::new());
    identical_witness_commit(&MemoryStore::new());
}

#[cfg(unix)]
mod jsonl {
    use super::*;
    use cll::log::jsonl::JsonlStore;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    fn fresh(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        JsonlStore::init(&path).unwrap();
        path
    }

    fn open_code(path: &Path) -> ErrorCode {
        JsonlStore::open(path).unwrap_err().code()
    }

    #[test]
    fn shared_checks() {
        let dir = tempfile::tempdir().unwrap();
        concurrent_appends(Arc::new(JsonlStore::open(fresh(dir.path(), "a")).unwrap()));
        results_are_copies(&JsonlStore::open(fresh(dir.path(), "b")).unwrap());
        identical_witness_commit(&JsonlStore::open(fresh(dir.path(), "c")).unwrap());
    }

    #[test]
    fn init_writes_the_header_and_open_never_creates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        assert_eq!(open_code(&path), ErrorCode::Storage);
        assert!(!path.exists());
        JsonlStore::init(&path).unwrap();
        JsonlStore::init(&path).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"version\":4,\"type\":\"cll.init\"}\n"
        );
        std::fs::write(&path, "").unwrap();
        assert_eq!(open_code(&path), ErrorCode::Corrupt);
        assert_eq!(JsonlStore::open("").unwrap_err().code(), ErrorCode::Invalid);
    }

    #[test]
    fn writes_the_portable_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh(dir.path(), "log.jsonl");
        let store = JsonlStore::open(&path).unwrap();
        store.append(&input(0, 1_788_264_000_000)).unwrap();
        store.append(&input(0, 0)).unwrap(); // idempotent: no event
        store.commit_cll(0, None, &one_leaf_state()).unwrap();
        let mut next = witness("primary", 1);
        next.attempts = 1;
        store.commit_witness(0, &next).unwrap();
        store.close().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            [
                r#"{"version":4,"type":"cll.init"}"#,
                r#"{"version":4,"type":"entry.append","entry":{"seq":"1","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","appendedAt":"2026-09-01T12:00:00.000Z"}}"#,
                r#"{"version":4,"type":"cll.commit","expected_size":"0","state":{"size":"1","indexedSeq":"1","nodes":["BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="],"witnesses":[{"witnessId":"primary","checkpointSize":"1","checkpoint":"Y2hlY2twb2ludA==","attempts":0,"nextAttemptAt":"1970-01-01T00:00:00.000Z","permanent":false}]}}"#,
                r#"{"version":4,"type":"witness.commit","expected_attempts":0,"witness":{"witnessId":"primary","checkpointSize":"1","checkpoint":"Y2hlY2twb2ludA==","attempts":1,"nextAttemptAt":"1970-01-01T00:00:00.000Z","permanent":false}}"#,
            ]
        );
        // A second commit carries only the rows it adds.
        let store = JsonlStore::open(&path).unwrap();
        let mut grown = store.load_cll().unwrap();
        grown.witnesses = vec![witness("secondary", 1)];
        store.commit_cll(1, None, &grown).unwrap();
        store.close().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.lines().last().unwrap().ends_with(
            r#""state":{"size":"1","indexedSeq":"1","nodes":[],"witnesses":[{"witnessId":"secondary","checkpointSize":"1","checkpoint":"Y2hlY2twb2ludA==","attempts":0,"nextAttemptAt":"1970-01-01T00:00:00.000Z","permanent":false}]}}"#
        ));
        let reopened = JsonlStore::open(&path).unwrap();
        assert_eq!(reopened.load_cll().unwrap().witnesses.len(), 2);
    }

    #[test]
    fn a_second_writer_is_contention_until_the_first_closes() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh(dir.path(), "log.jsonl");
        let first = JsonlStore::open(&path).unwrap();
        assert_eq!(open_code(&path), ErrorCode::Contention);
        assert_eq!(
            JsonlStore::init(&path).unwrap_err().code(),
            ErrorCode::Contention
        );
        first.close().unwrap();
        let second = JsonlStore::open(&path).unwrap();
        drop(second); // dropping also releases the lock
        JsonlStore::open(&path).unwrap();
    }

    #[test]
    fn open_rejects_a_torn_tail_and_init_repairs_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh(dir.path(), "log.jsonl");
        let store = JsonlStore::open(&path).unwrap();
        store.append(&input(1, 0)).unwrap();
        store.close().unwrap();
        let durable = std::fs::read(&path).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(br#"{"version":4,"type":"entry.app"#)
            .unwrap();
        drop(file);
        let torn = std::fs::read(&path).unwrap();
        assert_eq!(open_code(&path), ErrorCode::Corrupt);
        assert_eq!(std::fs::read(&path).unwrap(), torn, "open never writes");
        JsonlStore::init(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), durable);
        let store = JsonlStore::open(&path).unwrap();
        assert_eq!(store.scan_entries(0, 10).unwrap().len(), 1);
    }

    #[test]
    fn malformed_complete_lines_are_corrupt_and_never_removed() {
        let dir = tempfile::tempdir().unwrap();
        let init = r#"{"version":4,"type":"cll.init"}"#;
        let entry = |seq: &str| {
            format!(
                r#"{{"version":4,"type":"entry.append","entry":{{"seq":"{seq}","value":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","appendedAt":"2026-09-01T12:00:00.000Z"}}}}"#
            )
        };
        // A one-node commit, with `state_extra` spliced into its state and
        // `event_extra` into the event.
        let commit_with = |state_extra: &str, event_extra: &str| {
            format!(
                r#"{{"version":4,"type":"cll.commit","expected_size":"0"{event_extra},"state":{{"size":"1","indexedSeq":"1","nodes":["BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="]{state_extra},"witnesses":[]}}}}"#
            )
        };
        let cases = [
            ("not json", vec![init.to_string(), "{".into()]),
            ("v3", vec![r#"{"v":3,"type":"entry"}"#.into()]),
            ("v3 version", vec![r#"{"version":3,"type":"cll.init"}"#.into()]),
            ("v5", vec![r#"{"version":5,"type":"cll.init"}"#.into()]),
            ("no init", vec![entry("1")]),
            ("unknown type", vec![init.into(), r#"{"version":4,"type":"cll.other"}"#.into()]),
            ("gap", vec![init.into(), entry("2")]),
            ("duplicate", vec![init.into(), entry("1"), entry("1")]),
            ("late init", vec![init.into(), entry("1"), init.into()]),
            ("missing entry", vec![init.into(), r#"{"version":4,"type":"entry.append"}"#.into()]),
            (
                "bad commit",
                vec![
                    init.into(),
                    r#"{"version":4,"type":"cll.commit","expected_size":"0","state":{"size":"2","indexedSeq":"1","nodes":[],"witnesses":[]}}"#.into(),
                ],
            ),
            // The contract encodes an optional value as an absent field,
            // never null.
            ("null checkpoint", vec![init.into(), commit_with(r#","checkpoint":null"#, "")]),
            ("null pending time", vec![init.into(), commit_with(r#","firstPendingAt":null"#, "")]),
            ("null expected checkpoint", vec![init.into(), commit_with("", r#","expected_checkpoint":null"#)]),
            (
                "null receipt",
                vec![
                    init.into(),
                    r#"{"version":4,"type":"cll.commit","expected_size":"0","state":{"size":"1","indexedSeq":"1","nodes":["BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="],"witnesses":[{"witnessId":"w","checkpointSize":"1","checkpoint":"AQ==","attempts":0,"nextAttemptAt":"2026-09-01T12:00:00.000Z","receipt":null,"permanent":false}]}}"#.into(),
                ],
            ),
            (
                "witness without row",
                vec![
                    init.into(),
                    r#"{"version":4,"type":"witness.commit","expected_attempts":0,"witness":{"witnessId":"w","checkpointSize":"1","checkpoint":"AQ==","attempts":1,"nextAttemptAt":"2026-09-01T12:00:00.000Z","permanent":false}}"#.into(),
                ],
            ),
        ];
        for (name, lines) in cases {
            let path = dir.path().join(format!("{name}.jsonl"));
            let text = lines.join("\n") + "\n";
            std::fs::write(&path, &text).unwrap();
            assert_eq!(open_code(&path), ErrorCode::Corrupt, "{name}");
            assert_eq!(
                JsonlStore::init(&path).unwrap_err().code(),
                ErrorCode::Corrupt,
                "{name}"
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text, "{name}");
        }
        // The same commit without the null opens.
        let path = dir.path().join("valid commit.jsonl");
        std::fs::write(&path, format!("{init}\n{}\n", commit_with("", ""))).unwrap();
        assert_eq!(JsonlStore::open(&path).unwrap().load_cll().unwrap().size, 1);
        // Unknown additive fields are accepted.
        let path = dir.path().join("additive.jsonl");
        std::fs::write(
            &path,
            format!("{}\n", r#"{"version":4,"type":"cll.init","note":"x"}"#),
        )
        .unwrap();
        JsonlStore::open(&path).unwrap();
    }

    #[test]
    fn an_oversized_event_is_invalid_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = fresh(dir.path(), "log.jsonl");
        let store = JsonlStore::open(&path).unwrap();
        let leaves = 1u64 << 16;
        let size = 2 * leaves - 1;
        let next = State {
            size,
            nodes: (0..size).map(|_| vec![9; 32]).collect(),
            indexed_seq: leaves,
            ..State::default()
        };
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            store.commit_cll(0, None, &next).unwrap_err().code(),
            ErrorCode::Invalid
        );
        assert_eq!(store.load_cll().unwrap(), State::default());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use cll::log::sqlite::SqliteStore;
    use rusqlite::Connection;

    #[test]
    fn shared_checks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        for log in ["a", "b", "c", "d"] {
            SqliteStore::init(&path, log).unwrap();
        }
        concurrent_appends(Arc::new(SqliteStore::open(&path, "a").unwrap()));
        results_are_copies(&SqliteStore::open(&path, "b").unwrap());
        cross_handle(
            &SqliteStore::open(&path, "c").unwrap(),
            &SqliteStore::open(&path, "c").unwrap(),
        );
        identical_witness_commit(&SqliteStore::open(&path, "d").unwrap());
        // Other logs are untouched.
        assert_eq!(
            SqliteStore::open(&path, "c")
                .unwrap()
                .scan_entries(0, 1000)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn open_requires_init_and_coexists_with_application_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        assert_eq!(
            SqliteStore::open(&path, "default").unwrap_err().code(),
            ErrorCode::Storage
        );
        assert!(!path.exists());
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE app_records(id INTEGER PRIMARY KEY, body TEXT); INSERT INTO app_records(body) VALUES('kept');")
            .unwrap();
        SqliteStore::init(&path, "default").unwrap();
        // A log that was never initialized has no metadata row.
        assert_eq!(
            SqliteStore::open(&path, "other").unwrap_err().code(),
            ErrorCode::Corrupt
        );
        assert_eq!(
            SqliteStore::open(&path, "bad id").unwrap_err().code(),
            ErrorCode::Invalid
        );
        let store = SqliteStore::open(&path, "default").unwrap();
        store.append(&input(1, 0)).unwrap();
        let body: String = conn
            .query_row("SELECT body FROM app_records", [], |row| row.get(0))
            .unwrap();
        assert_eq!(body, "kept");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
    }

    #[test]
    fn an_incompatible_table_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE cll_meta(log_id TEXT PRIMARY KEY, other TEXT)")
            .unwrap();
        assert!(SqliteStore::init(&path, "default").is_err());
    }

    #[test]
    fn corrupt_rows_fail_to_open() {
        let corruptions = [
            "UPDATE cll_meta SET state='{' WHERE log_id='default'",
            "UPDATE cll_entries SET seq=5 WHERE log_id='default'",
            "UPDATE cll_entries SET appended_at='2026-09-01' WHERE log_id='default'",
            "UPDATE cll_entries SET value=x'01' WHERE log_id='default'",
            "UPDATE cll_nodes SET position=4 WHERE log_id='default'",
            "UPDATE cll_witnesses SET attempts=9 WHERE log_id='default'",
            "DELETE FROM cll_nodes WHERE log_id='default'",
            "DELETE FROM cll_meta WHERE log_id='default'",
            // A present null where the contract wants an absent field.
            r#"UPDATE cll_meta SET state='{"size":"1","indexedSeq":"1","nodes":[],"checkpoint":null,"witnesses":[]}'"#,
            "UPDATE cll_witnesses SET witness=json_set(CAST(witness AS TEXT),'$.lastError',NULL)",
            // Values of the wrong SQL type.
            "UPDATE cll_meta SET state=123",
            "UPDATE cll_nodes SET node=5",
            "UPDATE cll_entries SET seq='abc'",
            "UPDATE cll_witnesses SET attempts='x'",
            // A dropped table.
            "DROP TABLE cll_witnesses",
        ];
        for corruption in corruptions {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("db.sqlite");
            SqliteStore::init(&path, "default").unwrap();
            let store = SqliteStore::open(&path, "default").unwrap();
            store.append(&input(1, 0)).unwrap();
            store.commit_cll(0, None, &one_leaf_state()).unwrap();
            store.close().unwrap();
            Connection::open(&path)
                .unwrap()
                .execute_batch(corruption)
                .unwrap();
            assert_eq!(
                SqliteStore::open(&path, "default").unwrap_err().code(),
                ErrorCode::Corrupt,
                "{corruption}"
            );
        }
    }

    #[test]
    fn a_database_without_the_schema_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        // An existing, empty database: never initialized.
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE app_records(id INTEGER PRIMARY KEY)")
            .unwrap();
        assert_eq!(
            SqliteStore::open(&path, "default").unwrap_err().code(),
            ErrorCode::Corrupt
        );
        SqliteStore::init(&path, "default").unwrap();
        SqliteStore::open(&path, "default").unwrap();
    }

    #[test]
    fn invalid_pending_arguments_win_over_a_corrupt_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        SqliteStore::init(&path, "default").unwrap();
        let store = SqliteStore::open(&path, "default").unwrap();
        store.commit_cll(0, None, &one_leaf_state()).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute_batch("UPDATE cll_witnesses SET witness='{'")
            .unwrap();
        let now = Timestamp::from_unix_millis(0);
        assert_eq!(
            store.pending_witnesses(now, 0).unwrap_err().code(),
            ErrorCode::Invalid
        );
        assert_eq!(
            store.pending_witnesses(now, 1).unwrap_err().code(),
            ErrorCode::Corrupt
        );
    }

    #[test]
    fn reads_json_columns_written_as_text() {
        // TypeScript stores the metadata and witness JSON as TEXT.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        SqliteStore::init(&path, "default").unwrap();
        let store = SqliteStore::open(&path, "default").unwrap();
        store.commit_cll(0, None, &one_leaf_state()).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute_batch("UPDATE cll_meta SET state=CAST(state AS TEXT); UPDATE cll_witnesses SET witness=CAST(witness AS TEXT);")
            .unwrap();
        assert_eq!(store.load_cll().unwrap(), one_leaf_state());
        assert!(store.get_witness("primary", 1).unwrap().is_some());
    }

    #[test]
    fn a_held_write_lock_is_contention_after_the_busy_wait() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        SqliteStore::init(&path, "default").unwrap();
        let store = SqliteStore::open(&path, "default").unwrap();
        let holder = Connection::open(&path).unwrap();
        holder.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = std::time::Instant::now();
        assert_eq!(
            store.append(&input(1, 0)).unwrap_err().code(),
            ErrorCode::Contention
        );
        assert!(started.elapsed() >= std::time::Duration::from_secs(4));
        holder.execute_batch("ROLLBACK").unwrap();
        store.append(&input(1, 0)).unwrap();
    }
}

#[cfg(feature = "mysql")]
mod mysql {
    use super::*;
    use ::mysql::prelude::Queryable;
    use cll::log::mysql::MysqlStore;

    fn url() -> Option<String> {
        match std::env::var("CLL_MYSQL_URL") {
            Ok(url) if !url.is_empty() => Some(url),
            _ if std::env::var_os("CI").is_some() => panic!("CI requires CLL_MYSQL_URL"),
            _ => {
                eprintln!("skipping: CLL_MYSQL_URL is unset");
                None
            }
        }
    }

    fn log_id(name: &str) -> String {
        format!(
            "rs-backend-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    /// A new, empty database on the same server, dropped when it goes out of
    /// scope, for cases that need a schema no other test shares.
    struct ScratchDatabase {
        url: String,
        name: String,
        server: ::mysql::Pool,
    }

    impl ScratchDatabase {
        fn new(url: &str) -> Self {
            let server = ::mysql::Pool::new(url).unwrap();
            let name = log_id("db").replace('-', "_");
            server
                .get_conn()
                .unwrap()
                .query_drop(format!("CREATE DATABASE `{name}`"))
                .unwrap();
            let (base, _) = url.rsplit_once('/').unwrap();
            Self {
                url: format!("{base}/{name}"),
                name,
                server,
            }
        }

        fn exec(&self, statement: &str) {
            let pool = ::mysql::Pool::new(self.url.as_str()).unwrap();
            pool.get_conn().unwrap().query_drop(statement).unwrap();
        }
    }

    impl Drop for ScratchDatabase {
        fn drop(&mut self) {
            if let Ok(mut conn) = self.server.get_conn() {
                let _ = conn.query_drop(format!("DROP DATABASE `{}`", self.name));
            }
        }
    }

    fn open_code(url: &str, log_id: &str) -> ErrorCode {
        MysqlStore::open(url, log_id).unwrap_err().code()
    }

    #[test]
    fn a_database_without_the_schema_is_corrupt() {
        let Some(url) = url() else { return };
        let db = ScratchDatabase::new(&url);
        assert_eq!(open_code(&db.url, "default"), ErrorCode::Corrupt);
        MysqlStore::init(&db.url, "default").unwrap();
        MysqlStore::open(&db.url, "default").unwrap();
        assert_eq!(open_code(&db.url, "other"), ErrorCode::Corrupt);
        db.exec("DROP TABLE cll_nodes");
        assert_eq!(open_code(&db.url, "default"), ErrorCode::Corrupt);
    }

    #[test]
    fn values_of_the_wrong_type_are_corrupt() {
        let Some(url) = url() else { return };
        for (alter, update) in [
            (
                "ALTER TABLE cll_nodes MODIFY position BIGINT NOT NULL",
                "UPDATE cll_nodes SET position=-1",
            ),
            (
                "ALTER TABLE cll_witnesses MODIFY attempts VARCHAR(10) NOT NULL",
                "UPDATE cll_witnesses SET attempts='x'",
            ),
            (
                "ALTER TABLE cll_entries MODIFY seq BIGINT NOT NULL",
                "UPDATE cll_entries SET seq=-1",
            ),
        ] {
            let db = ScratchDatabase::new(&url);
            MysqlStore::init(&db.url, "default").unwrap();
            let store = MysqlStore::open(&db.url, "default").unwrap();
            store.append(&input(1, 0)).unwrap();
            store.commit_cll(0, None, &one_leaf_state()).unwrap();
            store.close().unwrap();
            db.exec(alter);
            db.exec(update);
            assert_eq!(
                open_code(&db.url, "default"),
                ErrorCode::Corrupt,
                "{update}"
            );
        }
    }

    #[test]
    fn invalid_pending_arguments_win_over_a_corrupt_row() {
        let Some(url) = url() else { return };
        let (store, id) = fresh(&url, "pending");
        store.commit_cll(0, None, &one_leaf_state()).unwrap();
        let pool = ::mysql::Pool::new(url.as_str()).unwrap();
        pool.get_conn()
            .unwrap()
            .exec_drop(
                "UPDATE cll_witnesses SET witness='{' WHERE log_id=?",
                (&id,),
            )
            .unwrap();
        let now = Timestamp::from_unix_millis(0);
        assert_eq!(
            store.pending_witnesses(now, 0).unwrap_err().code(),
            ErrorCode::Invalid
        );
        assert_eq!(
            store.pending_witnesses(now, 1).unwrap_err().code(),
            ErrorCode::Corrupt
        );
    }

    fn fresh(url: &str, name: &str) -> (MysqlStore, String) {
        let id = log_id(name);
        MysqlStore::init(url, &id).unwrap();
        (MysqlStore::open(url, &id).unwrap(), id)
    }

    #[test]
    fn shared_checks() {
        let Some(url) = url() else { return };
        concurrent_appends(Arc::new(fresh(&url, "concurrent").0));
        results_are_copies(&fresh(&url, "copies").0);
        let (first, id) = fresh(&url, "cross");
        cross_handle(&first, &MysqlStore::open(&url, &id).unwrap());
        identical_witness_commit(&fresh(&url, "identical").0);
    }

    #[test]
    fn open_requires_init_and_rejects_bad_targets() {
        let Some(url) = url() else { return };
        assert_eq!(
            MysqlStore::open(&url, &log_id("absent"))
                .unwrap_err()
                .code(),
            ErrorCode::Corrupt
        );
        assert_eq!(
            MysqlStore::open("postgres://x", "default")
                .unwrap_err()
                .code(),
            ErrorCode::Invalid
        );
        assert_eq!(
            MysqlStore::open(&url, "bad id").unwrap_err().code(),
            ErrorCode::Invalid
        );
    }

    #[test]
    fn corrupt_rows_fail_to_open() {
        let Some(url) = url() else { return };
        let pool = ::mysql::Pool::new(url.as_str()).unwrap();
        let mut conn = pool.get_conn().unwrap();
        for corruption in [
            "UPDATE cll_meta SET state='{' WHERE log_id=?",
            "UPDATE cll_entries SET seq=5 WHERE log_id=?",
            "UPDATE cll_entries SET appended_at='2026-09-01' WHERE log_id=?",
            "UPDATE cll_nodes SET position=4 WHERE log_id=?",
            "UPDATE cll_witnesses SET attempts=9 WHERE log_id=?",
            "DELETE FROM cll_nodes WHERE log_id=?",
            // A present null where the contract wants an absent field.
            r#"UPDATE cll_meta SET state='{"size":"1","indexedSeq":"1","nodes":[],"firstPendingAt":null,"witnesses":[]}' WHERE log_id=?"#,
            "UPDATE cll_witnesses SET witness=JSON_SET(CAST(witness AS CHAR),'$.lastError',CAST('null' AS JSON)) WHERE log_id=?",
        ] {
            let (store, id) = fresh(&url, "corrupt");
            store.append(&input(1, 0)).unwrap();
            store.commit_cll(0, None, &one_leaf_state()).unwrap();
            store.close().unwrap();
            conn.exec_drop(corruption, (&id,)).unwrap();
            assert_eq!(
                MysqlStore::open(&url, &id).unwrap_err().code(),
                ErrorCode::Corrupt,
                "{corruption}"
            );
        }
    }
}
