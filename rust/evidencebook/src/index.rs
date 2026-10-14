//! The three index classes.
//!
//! I-D section: *Index Classes*.
//!
//! Each class makes a different claim and none substitutes for another:
//!
//! - [`OperationalIndex`]: fast local lookup, rebuildable from committed
//!   history, no trust value of its own.
//! - [`AuthenticatedIndex`]: a deterministic structure whose root is committed
//!   into the substrate, so membership, range, non-membership and
//!   completeness can be checked by a party that does not trust the store.
//! - [`DiscoveryIndex`]: approximate candidate-finding only, never proof.
//!
//! **Discovery never reaches a proof.** A discovery index answers with
//! [`Candidates`], which has no public fields and no conversion into the
//! inputs of any proof. A caller that wants a proof about a candidate must
//! look it up again through an operational or authenticated index, which is
//! the I-D's rule made into a type error:
//!
//! ```compile_fail
//! use evidencebook::index::{AuthenticatedIndex, Candidates, KeyRange};
//! fn prove<I: AuthenticatedIndex>(index: &I, found: Candidates) {
//!     // A Candidates value is not a KeyRange: this does not compile.
//!     let _ = index.prove_key_range(&found);
//! }
//! ```

use serde::{Deserialize, Serialize};

/// The fields an index sees for one committed record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedRecord {
    pub record_id: String,
    pub seq: u64,
    pub record_type: String,
    pub subject_ref: Option<String>,
}

/// An operational query. Every set field must match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub record_type: Option<String>,
    pub subject_ref: Option<String>,
    pub from_seq: Option<u64>,
    pub to_seq: Option<u64>,
}

impl Filter {
    /// Whether `record` satisfies every set field of this filter.
    pub fn matches(&self, record: &IndexedRecord) -> bool {
        self.record_type
            .as_ref()
            .is_none_or(|t| *t == record.record_type)
            && self
                .subject_ref
                .as_ref()
                .is_none_or(|s| record.subject_ref.as_ref() == Some(s))
            && self.from_seq.is_none_or(|from| record.seq >= from)
            && self.to_seq.is_none_or(|to| record.seq <= to)
    }
}

/// Fast local lookup (I-D *Index Classes*, 1). Rebuildable from committed
/// history at any time; a result is only as trustworthy as the store.
pub trait OperationalIndex {
    type Error;

    /// Index one newly committed record.
    fn insert(&mut self, record: &IndexedRecord) -> Result<(), Self::Error>;

    /// Record ids matching `filter`, in `seq` order.
    fn query(&self, filter: &Filter) -> Result<Vec<String>, Self::Error>;

    /// Drop everything and re-index `records` (committed history, in order).
    fn rebuild(&mut self, records: &[IndexedRecord]) -> Result<(), Self::Error>;
}

/// A committed authenticated-index root: which index, over how many keys,
/// and its root digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexRoot {
    pub index: String,
    pub size: u64,
    pub root: String,
}

/// An inclusive key range an authenticated index is asked to prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRange {
    pub low: String,
    pub high: String,
}

/// An authenticated answer for a [`KeyRange`]: every matching key, and the
/// proof that the list is complete under `root`. An empty `keys` with a
/// verifying proof is a non-membership proof (I-D *Three Kinds of "No"*, 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRangeAnswer<P> {
    pub root: IndexRoot,
    pub range: KeyRange,
    pub keys: Vec<String>,
    pub proof: P,
}

/// A deterministic index whose root is committed into the substrate (I-D
/// *Index Classes*, 2). Its answers are checkable against a checkpoint by a
/// party that does not trust the store.
pub trait AuthenticatedIndex {
    type Proof;
    type Error;

    /// Add one key (idempotent for a key already present).
    fn insert(&mut self, key: &str) -> Result<(), Self::Error>;

    /// The current root, as the book commits it.
    fn root(&self) -> IndexRoot;

    /// Every key in `range` plus a completeness proof.
    fn prove_key_range(&self, range: &KeyRange)
        -> Result<KeyRangeAnswer<Self::Proof>, Self::Error>;

    /// Check an answer against a root obtained independently of the store.
    fn verify_key_range(root: &IndexRoot, answer: &KeyRangeAnswer<Self::Proof>) -> bool;
}

/// Record ids a discovery index suggests. Opaque: no public fields, and no
/// proof function in this crate accepts it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Candidates {
    ids: Vec<String>,
}

impl Candidates {
    /// Wrap a discovery index's suggestions.
    pub fn new(ids: Vec<String>) -> Self {
        Self { ids }
    }

    /// The suggested record ids, for display or a follow-up lookup.
    pub fn suggestions(&self) -> impl Iterator<Item = &str> {
        self.ids.iter().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

/// Approximate discovery (I-D *Index Classes*, 3). Never proof of
/// completeness, never proof that a matched record is true.
pub trait DiscoveryIndex {
    type Error;

    fn discover(&self, query: &str) -> Result<Candidates, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(seq: u64, record_type: &str, subject: Option<&str>) -> IndexedRecord {
        IndexedRecord {
            record_id: format!("{seq:064x}"),
            seq,
            record_type: record_type.into(),
            subject_ref: subject.map(str::to_string),
        }
    }

    #[test]
    fn filter_matches_every_set_field() {
        let r = rec(5, "claim", Some("s1"));
        assert!(Filter::default().matches(&r));
        assert!(Filter {
            record_type: Some("claim".into()),
            subject_ref: Some("s1".into()),
            from_seq: Some(5),
            to_seq: Some(5),
        }
        .matches(&r));
        assert!(!Filter {
            record_type: Some("close".into()),
            ..Filter::default()
        }
        .matches(&r));
        assert!(!Filter {
            subject_ref: Some("s2".into()),
            ..Filter::default()
        }
        .matches(&r));
        assert!(!Filter {
            from_seq: Some(6),
            ..Filter::default()
        }
        .matches(&r));
        assert!(!Filter {
            to_seq: Some(4),
            ..Filter::default()
        }
        .matches(&r));
        assert!(!Filter {
            subject_ref: Some("s1".into()),
            ..Filter::default()
        }
        .matches(&rec(5, "claim", None)));
    }

    #[test]
    fn candidates_only_expose_suggestions() {
        let c = Candidates::new(vec!["a".into(), "b".into()]);
        assert_eq!(c.suggestions().collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(c.len(), 2);
        assert!(Candidates::default().is_empty());
    }
}
