//! `cll` -- Rust implementation of the Checkpointed Local Log (CLL)
//! mechanism: a Merkle Mountain Range (MMR) over an append-only log, signed
//! COSE checkpoints, per-record range proofs, and a witness-registration
//! client.
//!
//! This crate is the Rust sibling of the `checkpointed-local-log` Python
//! package (`cll` on PyPI) -- same repository, same conformance vectors
//! (`mmr-conformance-vectors/`, `commitment-conformance-vectors/`). Rust
//! and Python are two implementations of one spec; the vectors are the
//! contract, not either implementation.
//!
//! Scope is deliberately narrow, matching this repo's Go/TypeScript ports:
//! the checkpoint + MMR + storage substrate only -- append-only log
//! indexing, the MMR with inclusion/consistency/range proofs, signed COSE
//! checkpoints, and witness delivery. This crate carries no payload
//! semantics of any kind and no ledger admission/revocation layer (that
//! stays Python-only, by decision -- see the repo README); it defines
//! nothing about how the entries it indexes are produced, interpreted, or
//! governed.
//!
//! [`log`] holds the storage interfaces every CLL implementation shares (the
//! entry log, checkpoint state and witness state of the repository's
//! `docs/backend-contract.md`), their in-memory, JSONL, SQLite (feature
//! `sqlite`) and MySQL (feature `mysql`) backends, and the conformance runner
//! for any backend.
//!
//! [`runner`] and [`witness_delivery`] are the host-run loops over those
//! interfaces, ports of the Go runners: [`runner::CheckpointRunner`] indexes
//! entries and signs checkpoints on a cadence, and
//! [`witness_delivery::DeliveryRunner`] delivers each checkpoint to its
//! witnesses (over [`witness_delivery::HttpWitnessClient`] or any
//! [`witness_delivery::Submitter`]) with bounded retry. The shared
//! `runner-conformance-vectors/` pin their behavior.

pub mod checkpoint;
pub mod log;
pub mod mmr;
pub mod node_store;
pub mod range_proof;
pub mod runner;
pub mod store;
pub mod witness;
pub mod witness_delivery;
