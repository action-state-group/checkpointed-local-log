//! The embedded log never escapes the crate's public API.
//!
//! Scans every source file for a public item whose signature line names a
//! `cll` path, and for a `pub use` of anything from `cll`. Private helpers may
//! use the log freely; a caller must only ever see this crate's own types.
//! The scan is line-based, so a public signature is kept on the line that
//! names its types (rustfmt's layout for every signature in this crate).

use std::fs;
use std::path::Path;

fn public_lines_naming_cll(src: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let mut in_pub_signature = false;
    for (n, line) in src.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") {
            continue;
        }
        let opens_pub = t.starts_with("pub ") && !t.starts_with("pub(crate)");
        if opens_pub {
            in_pub_signature = true;
        }
        if in_pub_signature && (t.contains("cll::") || t.starts_with("pub use cll")) {
            hits.push(format!("{}: {}", n + 1, line.trim()));
        }
        // A signature ends at its body or at the end of a declaration.
        if t.contains('{') || t.ends_with(';') {
            in_pub_signature = false;
        }
    }
    hits
}

#[test]
fn no_public_item_names_a_cll_type() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            for hit in public_lines_naming_cll(&fs::read_to_string(&path).unwrap()) {
                hits.push(format!("{}:{hit}", path.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "public API names cll:\n{}",
        hits.join("\n")
    );
}

#[test]
fn the_scan_catches_each_way_a_cll_type_could_leak() {
    for leaking in [
        "pub use cll::mmr::InclusionProof;",
        "pub fn proof(&self) -> cll::mmr::InclusionProof {",
        "pub fn load(\n    path: &Path,\n) -> Result<cll::store::CheckpointLine, E> {",
        "pub struct S {\n    pub inner: cll::node_store::FileNodeStore,\n}",
    ] {
        assert!(
            !public_lines_naming_cll(leaking).is_empty(),
            "missed: {leaking}"
        );
    }
    for fine in [
        "use cll::mmr::InclusionProof;",
        "fn private() -> cll::mmr::Hash {",
        "pub(crate) fn helper() -> cll::mmr::Hash {",
        "pub fn f() -> u64 {\n    cll::mmr::node_count(1)\n}",
    ] {
        assert!(
            public_lines_naming_cll(fine).is_empty(),
            "false hit: {fine}"
        );
    }
}
