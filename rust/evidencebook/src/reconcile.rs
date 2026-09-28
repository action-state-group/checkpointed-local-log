//! Reconcile two independently held accounts, and read a Close's status.
//!
//! I-D section: *Reconcile and Close*.
//!
//! Reconciliation pairs one side's halves with the other's and puts every
//! half seen on either side into exactly one of six states. It is code, not
//! judgment: the only content test is the profile's [`Comparator`].
//!
//! **One half unavailable is not disagreement.** An unpaired half is
//! `A_ONLY`/`B_ONLY` when the other side's account is complete, `INSUFFICIENT`
//! otherwise, and never `CONFLICTING`.
//!
//! The correlation keys are the calling profile's. A [`JoinPolicy`] names
//! them: a primary key, a secondary key tried only for halves the primary
//! left unpaired, and an optional grouping key that is recorded when both
//! halves carry the same value and never joined on. Semantics match the Go
//! implementation's `ReconcileHalves` with its keys supplied as a policy.

use crate::record::LinkType;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A pairing's state (I-D *Reconcile and Close*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PairState {
    /// Both sides hold covered, trusted, corresponding records that agree.
    Matched,
    /// Only side A holds it, and B's account is complete.
    AOnly,
    /// Only side B holds it, and A's account is complete.
    BOnly,
    /// Both sides hold a corresponding record and they disagree.
    Conflicting,
    /// The evidence cannot decide: a half is uncovered, or absence is not
    /// provable because the other account is incomplete.
    Insufficient,
    /// Paired and covered, but a half does not verify.
    Unresolved,
}

impl PairState {
    pub const ALL: [PairState; 6] = [
        PairState::Matched,
        PairState::AOnly,
        PairState::BOnly,
        PairState::Conflicting,
        PairState::Insufficient,
        PairState::Unresolved,
    ];
}

/// Which correlation keys pair two halves, in preference order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinPolicy {
    /// Tried first. An agreeing primary key whose secondary keys both exist
    /// and disagree is `CONFLICTING`, never re-paired on the secondary.
    pub primary: String,
    /// Tried for halves still unpaired after the primary pass.
    pub secondary: String,
    /// Recorded on a pair when both halves carry the same value; never a join
    /// key.
    pub group: Option<String>,
}

/// One side's record of one interaction, as reconciliation sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Half {
    pub record_id: String,
    pub seq: u64,
    /// Correlation keys by name; an empty value is treated as absent.
    pub correlation: BTreeMap<String, String>,
    pub payload_commitments: Vec<String>,
    /// Inside an authenticated checkpoint.
    pub covered: bool,
    /// The record verifies and its header matches what it committed.
    pub trusted: bool,
}

impl Half {
    fn key(&self, name: &str) -> Option<&str> {
        self.correlation
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    fn has_no_keys(&self, policy: &JoinPolicy) -> bool {
        self.key(&policy.primary).is_none()
            && self.key(&policy.secondary).is_none()
            && policy.group.as_deref().and_then(|g| self.key(g)).is_none()
    }
}

/// One side's account of a period. `complete` means the account is
/// checkpoint-covered end to end, so a missing counterpart on this side is a
/// provable absence rather than an unknown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HalfSet {
    pub halves: Vec<Half>,
    pub complete: bool,
}

/// The profile's content test. Runs only on covered, trusted, correlated
/// pairs; returns whether their contents agree.
pub type Comparator<'a> = &'a dyn Fn(&Half, &Half) -> bool;

/// A comparator for deterministic content: both halves committed the same,
/// non-empty list of payload digests. Sampled content needs a comparator over
/// the disclosed content instead.
pub fn same_payload_commitments(a: &Half, b: &Half) -> bool {
    !a.payload_commitments.is_empty() && a.payload_commitments == b.payload_commitments
}

/// One classified pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairResult {
    pub state: PairState,
    /// The name of the key the pair was joined on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub b: Option<String>,
    /// The grouping key's value, when both halves carry the same one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// Count of pairings per state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tallies {
    #[serde(rename = "MATCHED")]
    pub matched: usize,
    #[serde(rename = "A_ONLY")]
    pub a_only: usize,
    #[serde(rename = "B_ONLY")]
    pub b_only: usize,
    #[serde(rename = "CONFLICTING")]
    pub conflicting: usize,
    #[serde(rename = "INSUFFICIENT")]
    pub insufficient: usize,
    #[serde(rename = "UNRESOLVED")]
    pub unresolved: usize,
}

impl Tallies {
    fn add(&mut self, state: PairState) {
        match state {
            PairState::Matched => self.matched += 1,
            PairState::AOnly => self.a_only += 1,
            PairState::BOnly => self.b_only += 1,
            PairState::Conflicting => self.conflicting += 1,
            PairState::Insufficient => self.insufficient += 1,
            PairState::Unresolved => self.unresolved += 1,
        }
    }
}

/// Pair side A's halves with side B's and classify every half seen on either
/// side into exactly one of the six states.
///
/// Correlation runs in two passes over all halves, so the result does not
/// depend on input order within a side: first the primary key (preferring a
/// counterpart whose secondary key also agrees, or is absent on either
/// half), then the secondary key for halves still unpaired.
pub fn reconcile_halves(
    a: &HalfSet,
    b: &HalfSet,
    policy: &JoinPolicy,
    compare: Comparator<'_>,
) -> (Vec<PairResult>, Tallies) {
    let mut partner: Vec<Option<usize>> = vec![None; a.halves.len()];
    let mut joined_on: Vec<Option<&str>> = vec![None; a.halves.len()];
    let mut used = vec![false; b.halves.len()];

    // First unused B half satisfying `matches`, preferring one that also
    // satisfies `prefer`.
    let pick = |used: &[bool], matches: &dyn Fn(&Half) -> bool, prefer: &dyn Fn(&Half) -> bool| {
        let mut found = None;
        for (j, h) in b.halves.iter().enumerate() {
            if used[j] || !matches(h) {
                continue;
            }
            if prefer(h) {
                return Some(j);
            }
            found.get_or_insert(j);
        }
        found
    };

    for (i, own) in a.halves.iter().enumerate() {
        let Some(primary) = own.key(&policy.primary) else {
            continue;
        };
        let own_secondary = own.key(&policy.secondary);
        let j = pick(
            &used,
            &|h| h.key(&policy.primary) == Some(primary),
            &|h| match (h.key(&policy.secondary), own_secondary) {
                (Some(theirs), Some(ours)) => theirs == ours,
                _ => true,
            },
        );
        if let Some(j) = j {
            partner[i] = Some(j);
            joined_on[i] = Some(&policy.primary);
            used[j] = true;
        }
    }
    for (i, own) in a.halves.iter().enumerate() {
        if partner[i].is_some() {
            continue;
        }
        let Some(secondary) = own.key(&policy.secondary) else {
            continue;
        };
        if let Some(j) = pick(
            &used,
            &|h| h.key(&policy.secondary) == Some(secondary),
            &|_| true,
        ) {
            partner[i] = Some(j);
            joined_on[i] = Some(&policy.secondary);
            used[j] = true;
        }
    }

    let mut results = Vec::with_capacity(a.halves.len() + b.halves.len());
    for (i, own) in a.halves.iter().enumerate() {
        let Some(j) = partner[i] else {
            let provable = own.covered && b.complete && !own.has_no_keys(policy);
            results.push(PairResult {
                state: if provable {
                    PairState::AOnly
                } else {
                    PairState::Insufficient
                },
                join_key: None,
                a: Some(own.record_id.clone()),
                b: None,
                group: None,
            });
            continue;
        };
        let peer = &b.halves[j];
        let key = joined_on[i].expect("a paired half records its join key");
        let group = policy
            .group
            .as_deref()
            .and_then(|g| own.key(g).filter(|v| peer.key(g) == Some(*v)))
            .map(str::to_string);
        let secondaries_disagree = matches!(
            (own.key(&policy.secondary), peer.key(&policy.secondary)),
            (Some(x), Some(y)) if x != y
        );
        let state = if key == policy.primary && secondaries_disagree {
            PairState::Conflicting
        } else if !own.covered || !peer.covered {
            PairState::Insufficient
        } else if !own.trusted || !peer.trusted {
            PairState::Unresolved
        } else if compare(own, peer) {
            PairState::Matched
        } else {
            PairState::Conflicting
        };
        results.push(PairResult {
            state,
            join_key: Some(key.to_string()),
            a: Some(own.record_id.clone()),
            b: Some(peer.record_id.clone()),
            group,
        });
    }
    for (j, peer) in b.halves.iter().enumerate() {
        if used[j] {
            continue;
        }
        let provable = peer.covered && a.complete && !peer.has_no_keys(policy);
        results.push(PairResult {
            state: if provable {
                PairState::BOnly
            } else {
                PairState::Insufficient
            },
            join_key: None,
            a: None,
            b: Some(peer.record_id.clone()),
            group: None,
        });
    }

    let mut tallies = Tallies::default();
    for r in &results {
        tallies.add(r.state);
    }
    (results, tallies)
}

/// A Close's status, read from the links the counterparty's records make to
/// it -- never from a field the Close sets itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloseStatus {
    /// A counterparty record carries an `acknowledges` link to the Close.
    Agreed,
    /// No counterparty record links to the Close yet.
    Unilateral,
    /// A counterparty record carries a `rebuts` link to the Close.
    Contested,
}

/// The status of Close `close_id`, given the links carried by records the
/// caller has already authenticated as the counterparty's. A rebuttal
/// outranks an acknowledgement. A later adjustment is a new Close carrying a
/// `supersedes` link; the original is never rewritten.
pub fn close_status<'a>(
    close_id: &str,
    counterparty_links: impl IntoIterator<Item = (LinkType, &'a str)>,
) -> CloseStatus {
    let mut status = CloseStatus::Unilateral;
    for (link_type, target) in counterparty_links {
        if target != close_id {
            continue;
        }
        match link_type {
            LinkType::Rebuts => return CloseStatus::Contested,
            LinkType::Acknowledges => status = CloseStatus::Agreed,
            _ => {}
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> JoinPolicy {
        JoinPolicy {
            primary: "k1".into(),
            secondary: "k2".into(),
            group: Some("g".into()),
        }
    }

    fn keys(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn half(id: &str, correlation: &[(&str, &str)], payload: &str) -> Half {
        Half {
            record_id: id.into(),
            seq: 1,
            correlation: keys(correlation),
            payload_commitments: vec![crate::canonical::json_digest(&payload.into()).unwrap()],
            covered: true,
            trusted: true,
        }
    }

    fn by_pair(results: &[PairResult]) -> BTreeMap<String, PairState> {
        results
            .iter()
            .map(|r| {
                (
                    format!(
                        "{}|{}",
                        r.a.as_deref().unwrap_or(""),
                        r.b.as_deref().unwrap_or("")
                    ),
                    r.state,
                )
            })
            .collect()
    }

    /// Port of the Go implementation's TestReconcileSixStates.
    #[test]
    fn every_state_is_reachable_and_each_half_lands_in_exactly_one() {
        let mut uncovered = half("a-uncovered", &[("k1", "x4")], "u");
        uncovered.covered = false;
        let mut untrusted = half("a-untrusted", &[("k1", "x5")], "t");
        untrusted.trusted = false;
        let a = HalfSet {
            complete: true,
            halves: vec![
                half("a-matched", &[("k1", "x1")], "same"),
                half("a-conflicting", &[("k1", "x2")], "mine"),
                half("a-only", &[("k1", "x3")], "lonely"),
                uncovered,
                untrusted,
            ],
        };
        let b = HalfSet {
            complete: true,
            halves: vec![
                half("b-matched", &[("k1", "x1")], "same"),
                half("b-conflicting", &[("k1", "x2")], "theirs"),
                half("b-uncovered-pair", &[("k1", "x4")], "p"),
                half("b-untrusted-pair", &[("k1", "x5")], "q"),
                half("b-only", &[("k1", "x6")], "alone"),
            ],
        };
        let (results, tallies) = reconcile_halves(&a, &b, &policy(), &same_payload_commitments);
        assert_eq!(
            tallies,
            Tallies {
                matched: 1,
                a_only: 1,
                b_only: 1,
                conflicting: 1,
                insufficient: 1,
                unresolved: 1
            }
        );
        let got = by_pair(&results);
        for (pair, state) in [
            ("a-matched|b-matched", PairState::Matched),
            ("a-conflicting|b-conflicting", PairState::Conflicting),
            ("a-only|", PairState::AOnly),
            ("a-uncovered|b-uncovered-pair", PairState::Insufficient),
            ("a-untrusted|b-untrusted-pair", PairState::Unresolved),
            ("|b-only", PairState::BOnly),
        ] {
            assert_eq!(got.get(pair), Some(&state), "{pair}: {results:?}");
        }
    }

    /// Port of the Go implementation's TestOneHalfUnavailableIsNotDisagreement:
    /// a comparator that always disagrees never turns an unpaired half into
    /// CONFLICTING.
    #[test]
    fn one_half_unavailable_is_not_disagreement() {
        let disagree = |_: &Half, _: &Half| false;
        for complete in [true, false] {
            let a = HalfSet {
                complete,
                halves: vec![half("a1", &[("k2", "r1")], "x")],
            };
            let b = HalfSet {
                complete,
                halves: vec![half("b1", &[("k2", "r2")], "y")],
            };
            let (_, t) = reconcile_halves(&a, &b, &policy(), &disagree);
            assert_eq!(t.conflicting, 0, "complete={complete}: {t:?}");
            let only = usize::from(complete);
            assert_eq!(
                (t.a_only, t.b_only, t.insufficient),
                (only, only, 2 - 2 * only)
            );
        }
    }

    #[test]
    fn agreeing_primary_with_disagreeing_secondary_conflicts_and_is_not_repaired() {
        let a = HalfSet {
            complete: true,
            halves: vec![half("a", &[("k1", "x"), ("k2", "r1")], "p")],
        };
        let b = HalfSet {
            complete: true,
            halves: vec![
                half("b", &[("k1", "x"), ("k2", "r2")], "p"),
                half("b-other", &[("k2", "r1")], "p"),
            ],
        };
        let (results, t) = reconcile_halves(&a, &b, &policy(), &same_payload_commitments);
        assert_eq!(results[0].state, PairState::Conflicting);
        assert_eq!(results[0].join_key.as_deref(), Some("k1"));
        assert_eq!(results[0].b.as_deref(), Some("b"));
        assert_eq!(t.b_only, 1, "b-other stays unpaired: {results:?}");
    }

    #[test]
    fn primary_pass_prefers_a_counterpart_whose_secondary_agrees() {
        let a = HalfSet {
            complete: true,
            halves: vec![half("a", &[("k1", "x"), ("k2", "r1")], "p")],
        };
        let b = HalfSet {
            complete: true,
            halves: vec![
                half("b-wrong", &[("k1", "x"), ("k2", "r9")], "p"),
                half("b-right", &[("k1", "x"), ("k2", "r1")], "p"),
            ],
        };
        let (results, _) = reconcile_halves(&a, &b, &policy(), &same_payload_commitments);
        assert_eq!(results[0].b.as_deref(), Some("b-right"));
        assert_eq!(results[0].state, PairState::Matched);
    }

    #[test]
    fn secondary_joins_only_what_the_primary_left_unpaired() {
        let a = HalfSet {
            complete: true,
            halves: vec![half("a", &[("k1", "x"), ("k2", "r1")], "p")],
        };
        let b = HalfSet {
            complete: true,
            halves: vec![half("b", &[("k1", "y"), ("k2", "r1")], "p")],
        };
        let (results, _) = reconcile_halves(&a, &b, &policy(), &same_payload_commitments);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].join_key.as_deref(), Some("k2"));
        assert_eq!(results[0].state, PairState::Matched);
    }

    #[test]
    fn the_group_key_is_recorded_when_shared_and_never_joins() {
        let a = HalfSet {
            complete: true,
            halves: vec![
                half("a1", &[("k1", "x"), ("g", "grp")], "p"),
                half("a2", &[("g", "grp-2")], "p"),
            ],
        };
        let b = HalfSet {
            complete: true,
            halves: vec![
                half("b1", &[("k1", "x"), ("g", "grp")], "p"),
                half("b2", &[("g", "grp-2")], "p"),
            ],
        };
        let (results, t) = reconcile_halves(&a, &b, &policy(), &same_payload_commitments);
        assert_eq!(results[0].group.as_deref(), Some("grp"));
        assert_eq!(t.matched, 1);
        assert_eq!((t.a_only, t.b_only), (1, 1), "{results:?}");
    }

    #[test]
    fn the_group_key_is_not_recorded_unless_both_halves_carry_the_same_value() {
        for peer_group in [None, Some("other")] {
            let mut peer_keys = vec![("k1", "x")];
            peer_keys.extend(peer_group.map(|g| ("g", g)));
            let a = HalfSet {
                complete: true,
                halves: vec![half("a", &[("k1", "x"), ("g", "grp")], "p")],
            };
            let b = HalfSet {
                complete: true,
                halves: vec![half("b", &peer_keys, "p")],
            };
            let (results, _) = reconcile_halves(&a, &b, &policy(), &same_payload_commitments);
            assert_eq!(results[0].state, PairState::Matched);
            assert_eq!(results[0].group, None, "peer group {peer_group:?}");
        }
    }

    #[test]
    fn a_half_with_no_keys_is_insufficient_even_against_a_complete_account() {
        let a = HalfSet {
            complete: true,
            halves: vec![half("a", &[], "p")],
        };
        let b = HalfSet {
            complete: true,
            halves: vec![],
        };
        let (_, t) = reconcile_halves(&a, &b, &policy(), &same_payload_commitments);
        assert_eq!(t.insufficient, 1);
        assert_eq!(t.a_only, 0);
    }

    #[test]
    fn tallies_serialize_under_the_state_tokens() {
        let v = serde_json::to_value(Tallies::default()).unwrap();
        for s in PairState::ALL {
            let token = serde_json::to_value(s).unwrap();
            assert!(v.get(token.as_str().unwrap()).is_some(), "{token}");
        }
    }

    #[test]
    fn close_status_reads_the_counterpartys_links() {
        let id = "c".repeat(64);
        let other = "d".repeat(64);
        assert_eq!(close_status(&id, []), CloseStatus::Unilateral);
        assert_eq!(
            close_status(&id, [(LinkType::Acknowledges, other.as_str())]),
            CloseStatus::Unilateral
        );
        assert_eq!(
            close_status(&id, [(LinkType::Acknowledges, id.as_str())]),
            CloseStatus::Agreed
        );
        assert_eq!(
            close_status(
                &id,
                [
                    (LinkType::Acknowledges, id.as_str()),
                    (LinkType::Rebuts, id.as_str())
                ]
            ),
            CloseStatus::Contested
        );
        assert_eq!(
            close_status(&id, [(LinkType::Cites, id.as_str())]),
            CloseStatus::Unilateral
        );
    }
}
