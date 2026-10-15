//! The shared backend conformance vectors against the built-in backends and
//! two entry-log-only stores (docs/backend-contract.md, "Capabilities").

use cll::log::conformance::{self, Config, Report, Target, VECTORS};
use cll::log::memory::MemoryStore;
use cll::log::{
    AppendInput, AppendOutcome, AppendResult, Entry, EntrySource, EntryStore, Error, ErrorCode,
    Result,
};
use std::sync::Mutex;

const CASES: usize = 23;

fn check(report: &Report, passed: usize) {
    report.assert_ok();
    assert_eq!(report.cases.len(), CASES, "{report}");
    assert_eq!(report.passed(), passed, "{report}");
}

#[test]
fn pinned_vectors_equal_the_repository_copy() {
    let root = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../backend-conformance-vectors/vectors.json"
    );
    let shared = std::fs::read_to_string(root).expect("repository vectors");
    assert!(
        VECTORS == shared,
        "run backend-conformance-vectors/generate.py"
    );
}

#[test]
fn memory() {
    // Everything except reopen and the no-digest-append case.
    check(&conformance::run(Config::new(MemoryStore::new)), CASES - 2);
}

#[cfg(unix)]
#[test]
fn jsonl_with_reopen() {
    use cll::log::jsonl::JsonlStore;
    let dir = tempfile::tempdir().unwrap();
    let current = std::cell::RefCell::new(std::path::PathBuf::new());
    let mut counter = 0;
    let config = Config::new(|| {
        counter += 1;
        let path = dir.path().join(format!("case-{counter}.jsonl"));
        JsonlStore::init(&path).unwrap();
        current.replace(path.clone());
        JsonlStore::open(&path).unwrap()
    })
    .with_reopen(|store| {
        cll::log::Backend::close(&store).unwrap();
        JsonlStore::open(&*current.borrow()).unwrap()
    });
    check(&conformance::run(config), CASES - 1);
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_with_reopen() {
    use cll::log::sqlite::SqliteStore;
    let dir = tempfile::tempdir().unwrap();
    // Every case is its own log in one shared database, beside the others.
    let path = dir.path().join("conformance.sqlite");
    let current = std::cell::RefCell::new(String::new());
    let mut counter = 0;
    let config = Config::new(|| {
        counter += 1;
        let log_id = format!("case-{counter}");
        SqliteStore::init(&path, &log_id).unwrap();
        current.replace(log_id.clone());
        SqliteStore::open(&path, &log_id).unwrap()
    })
    .with_reopen(|store| {
        cll::log::Backend::close(&store).unwrap();
        SqliteStore::open(&path, &current.borrow()).unwrap()
    });
    check(&conformance::run(config), CASES - 1);
}

/// `CLL_MYSQL_URL`, or `None` to skip locally. In CI (`CI` set) a missing
/// URL fails the test, so MySQL coverage cannot silently disappear.
#[cfg(feature = "mysql")]
pub fn mysql_url() -> Option<String> {
    match std::env::var("CLL_MYSQL_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ if std::env::var_os("CI").is_some() => panic!("CI requires CLL_MYSQL_URL"),
        _ => {
            eprintln!("skipping: CLL_MYSQL_URL is unset");
            None
        }
    }
}

#[cfg(feature = "mysql")]
#[test]
fn mysql_with_reopen() {
    use cll::log::mysql::MysqlStore;
    let Some(url) = mysql_url() else { return };
    let run = format!(
        "rs-conformance-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    let current = std::cell::RefCell::new(String::new());
    let mut counter = 0;
    let config = Config::new(|| {
        counter += 1;
        let log_id = format!("{run}-{counter}");
        MysqlStore::init(&url, &log_id).unwrap();
        current.replace(log_id.clone());
        MysqlStore::open(&url, &log_id).unwrap()
    })
    .with_reopen(|store| {
        cll::log::Backend::close(&store).unwrap();
        MysqlStore::open(&url, &current.borrow()).unwrap()
    });
    check(&conformance::run(config), CASES - 1);
}

/// An entry log that is not a full backend.
struct EntriesOnly(MemoryStore);

impl Target for EntriesOnly {
    fn entry_store(&self) -> Option<&dyn EntryStore> {
        Some(&self.0)
    }
}

#[test]
fn entry_log_only_store_runs_the_entry_cases() {
    let report = conformance::run(Config::new(|| EntriesOnly(MemoryStore::new())));
    // entries/* except the no-digest-append case.
    check(&report, 6);
}

/// A store whose entries are written as application records first: it holds
/// identities but cannot accept a bare one (`digest-append` absent).
struct RecordBacked {
    entries: Mutex<Vec<Entry>>,
}

impl EntrySource for RecordBacked {
    fn scan_entries(&self, after_seq: u64, limit: usize) -> Result<Vec<Entry>> {
        if limit == 0
            || limit > cll::log::MAX_SCAN_LIMIT
            || after_seq > cll::log::MAX_PORTABLE_INTEGER
        {
            return Err(Error::new(ErrorCode::Invalid, "scan out of range"));
        }
        let entries = self.entries.lock().unwrap();
        Ok(entries
            .iter()
            .filter(|e| e.seq > after_seq)
            .take(limit)
            .cloned()
            .collect())
    }
}

impl EntryStore for RecordBacked {
    fn append(&self, input: &AppendInput) -> Result<AppendResult> {
        let entry = self.get_entry(&input.value);
        match entry {
            Ok(entry) => Ok(AppendResult {
                entry,
                outcome: AppendOutcome::Idempotent,
            }),
            Err(e) if e.code() == ErrorCode::NotFound => Err(Error::new(
                ErrorCode::Unsupported,
                "write the application record first",
            )),
            Err(e) => Err(e),
        }
    }

    fn get_entry(&self, value: &[u8]) -> Result<Entry> {
        if value.len() != 32 {
            return Err(Error::new(ErrorCode::Invalid, "wrong width"));
        }
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .find(|e| e.value == value)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "absent"))
    }
}

impl Target for RecordBacked {
    fn entry_store(&self) -> Option<&dyn EntryStore> {
        Some(self)
    }
}

#[test]
fn store_without_digest_append_runs_its_subset() {
    let config = Config::new(|| RecordBacked {
        entries: Mutex::new(Vec::new()),
    })
    .without_digest_append();
    // entries/empty-log, entries/invalid-values, entries/digest-append-unsupported.
    check(&conformance::run(config), 3);
}

#[test]
fn a_wrong_backend_fails_with_the_step_named() {
    /// Reports every missing entry as invalid instead of not found.
    struct Wrong(MemoryStore);
    impl EntrySource for Wrong {
        fn scan_entries(&self, after_seq: u64, limit: usize) -> Result<Vec<Entry>> {
            self.0.scan_entries(after_seq, limit)
        }
    }
    impl EntryStore for Wrong {
        fn append(&self, input: &AppendInput) -> Result<AppendResult> {
            self.0.append(input)
        }
        fn get_entry(&self, value: &[u8]) -> Result<Entry> {
            self.0
                .get_entry(value)
                .map_err(|e| Error::new(ErrorCode::Invalid, e.message()))
        }
    }
    impl Target for Wrong {
        fn entry_store(&self) -> Option<&dyn EntryStore> {
            Some(self)
        }
    }
    let report = conformance::run(Config::new(|| Wrong(MemoryStore::new())));
    let failures = report.failures();
    assert!(!failures.is_empty());
    let text = report.to_string();
    assert!(
        text.contains("FAIL entries/empty-log: step 1 (getEntry): want error \"not_found\""),
        "{text}"
    );
    assert!(std::panic::catch_unwind(|| report.assert_ok()).is_err());
}
