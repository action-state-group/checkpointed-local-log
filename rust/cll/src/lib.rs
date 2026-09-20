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
//! checkpoints, and witness delivery. No capsule semantics, no
//! EvidenceBook/record-header semantics, no ledger admission/revocation
//! layer (that stays Python-only, by decision -- see the repo README).

pub mod checkpoint;
pub mod mmr;
pub mod range_proof;
pub mod store;
pub mod witness;
