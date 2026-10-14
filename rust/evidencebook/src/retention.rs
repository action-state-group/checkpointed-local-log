//! Retention states and the lifecycle records that change them.
//!
//! I-D sections: *Record/Payload Separation, Retention, and Disclosure*,
//! *Retention States*.
//!
//! A record's commitment is permanent; payload bytes are a separate resource
//! the header points at by digest. Retention belongs to one (record, payload)
//! pair: the state the record committed, folded forward through every later
//! lifecycle record that cites it for that payload. A lifecycle record is a
//! tombstone when it moves a payload to `DELETED`: the bytes may go, the
//! commitment and the record stay.

use serde::{Deserialize, Serialize};

/// A payload's retention state (I-D *Retention States*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetentionState {
    /// Resolvable under current policy.
    Available,
    /// Only some fields or preimages remain.
    Partial,
    /// May exist; this requester is not authorized. Not an absence.
    Withheld,
    /// Destroyed or expired. Permanent.
    Deleted,
    /// Deletion suspended; resolves per the payload's actual state.
    LegalHold,
}

impl RetentionState {
    /// Every value, in the I-D's table order.
    pub const ALL: [RetentionState; 5] = [
        RetentionState::Available,
        RetentionState::Partial,
        RetentionState::Withheld,
        RetentionState::Deleted,
        RetentionState::LegalHold,
    ];

    /// Whether resolving the payload in this state can return bytes.
    /// `WITHHELD` and `DELETED` both return none; only `DELETED` is permanent,
    /// so a caller that needs to tell them apart reads the state, never a
    /// resolution failure alone.
    pub fn resolves(self) -> bool {
        matches!(
            self,
            RetentionState::Available | RetentionState::Partial | RetentionState::LegalHold
        )
    }
}

/// The body of a lifecycle record: one payload of the cited record moved to
/// `retention_state`. Member names match the Go implementation's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleStatement {
    pub payload_commitment: String,
    pub retention_state: RetentionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What asking for `requested` does to a payload currently in `current`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Commit a lifecycle record moving the payload to the requested state.
    Commit,
    /// The payload is already `DELETED` and `DELETED` was asked again:
    /// commit nothing new; retry destroying the bytes.
    RetryDeletion,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RetentionError {
    #[error("payload is already deleted; deletion is permanent")]
    AlreadyDeleted,
    #[error("payload is under legal hold; deletion is blocked until the hold is lifted")]
    LegalHold,
}

/// Decide a requested retention change. `DELETED` is permanent, and a legal
/// hold blocks a move to `DELETED` without changing resolvability itself.
pub fn transition(
    current: RetentionState,
    requested: RetentionState,
) -> Result<Transition, RetentionError> {
    match (current, requested) {
        (RetentionState::Deleted, RetentionState::Deleted) => Ok(Transition::RetryDeletion),
        (RetentionState::Deleted, _) => Err(RetentionError::AlreadyDeleted),
        (RetentionState::LegalHold, RetentionState::Deleted) => Err(RetentionError::LegalHold),
        _ => Ok(Transition::Commit),
    }
}

/// The current state of one payload: `committed` folded forward through the
/// lifecycle statements that cite its record, in log order. Statements for a
/// different payload digest do not apply.
pub fn fold<'a>(
    committed: RetentionState,
    payload_commitment: &str,
    lifecycle_in_log_order: impl IntoIterator<Item = &'a LifecycleStatement>,
) -> RetentionState {
    lifecycle_in_log_order
        .into_iter()
        .filter(|s| s.payload_commitment == payload_commitment)
        .fold(committed, |_, s| s.retention_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use RetentionState::*;

    fn stmt(digest: &str, state: RetentionState) -> LifecycleStatement {
        LifecycleStatement {
            payload_commitment: digest.into(),
            retention_state: state,
            reason: None,
        }
    }

    #[test]
    fn wire_tokens_are_the_i_d_tokens() {
        let tokens: Vec<String> = RetentionState::ALL
            .iter()
            .map(|s| {
                serde_json::to_value(s)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(
            tokens,
            ["AVAILABLE", "PARTIAL", "WITHHELD", "DELETED", "LEGAL_HOLD"]
        );
    }

    #[test]
    fn withheld_and_deleted_both_return_nothing_but_are_different_states() {
        assert!(!Withheld.resolves());
        assert!(!Deleted.resolves());
        assert_ne!(Withheld, Deleted);
        assert!(Available.resolves() && Partial.resolves() && LegalHold.resolves());
    }

    #[test]
    fn deletion_is_permanent_and_blocked_by_a_legal_hold() {
        assert_eq!(
            transition(Deleted, Available),
            Err(RetentionError::AlreadyDeleted)
        );
        assert_eq!(
            transition(Deleted, LegalHold),
            Err(RetentionError::AlreadyDeleted)
        );
        assert_eq!(transition(Deleted, Deleted), Ok(Transition::RetryDeletion));
        assert_eq!(
            transition(LegalHold, Deleted),
            Err(RetentionError::LegalHold)
        );
        assert_eq!(transition(LegalHold, Available), Ok(Transition::Commit));
        assert_eq!(transition(Available, Deleted), Ok(Transition::Commit));
        assert_eq!(transition(Withheld, Available), Ok(Transition::Commit));
    }

    #[test]
    fn fold_applies_only_statements_for_this_payload_in_order() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let log = [stmt(&a, Withheld), stmt(&b, Deleted), stmt(&a, LegalHold)];
        assert_eq!(fold(Available, &a, &log), LegalHold);
        assert_eq!(fold(Available, &b, &log), Deleted);
        assert_eq!(fold(Partial, &"c".repeat(64), &log), Partial);
    }
}
