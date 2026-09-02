# SPDX-License-Identifier: Apache-2.0
"""``cll.checkpoint`` -- the MMR/checkpoint/COSE core of Checkpointed Local Log.

``core`` is the pure MMR algorithm (position math, domain-separated hashing,
inclusion/consistency proofs, no I/O). ``store`` is the v0 in-memory node
backing. ``index`` wires the MMR to any append-only log exposing the
``LogSource`` shape (append/scan/fetch/find_gaps/verify) -- structurally, not
by importing a concrete implementation. ``emit`` builds, signs, and registers
peaks checkpoints against a Transparency Service. ``bundle`` assembles a
standalone, offline-verifiable evidence package for one log record.

This subpackage is content-agnostic: nothing here knows what a "capsule" is.
A caller identifies leaves by whatever field name its own record shape uses
(``bundle()``'s ``id_field``); ``index.LogSource`` is a structural protocol,
not a capsule-specific binding.

**History.** Originally built inside ``capsule-emit`` (ported there from
``capsule-ledger/capsule_ledger/mmr/{core,index,store}.py`` per Amendment E,
2026-08-21, on the reasoning that the CLL core is substrate a counterparty
needs to verify a log, so it should live where any consumer can depend on
it without forking). Graduated to this repo as the ``cll`` package per the
W3 one-neutral-library-per-spec decision (2026-09-01): the log layer is
deliberately NOT capsule-specific -- that is its adoption story (e.g. a
trace registry running this exact mechanism over TRACE records) -- so it
does not live under a ``capsule-*``-branded name. ``capsule-emit`` now
depends on this package and re-exports ``capsule_emit.checkpoint`` /
``capsule_emit.bundle`` as thin compatibility wrappers over it.
"""
from .bundle import Bundle, BundleError, bundle, verify_bundle_log_integrity
from .core import (
    ConsistencyProof,
    InclusionProof,
    IntegrityError,
    InvalidArgumentError,
    add_leaf,
    commitment_object,
    consistency_proof,
    height_at,
    interior_hash,
    leaf_count,
    leaf_hash,
    leaf_index_to_pos,
    node_count,
    peaks,
    pos_to_leaf_index,
    root_from_peaks,
    verify_consistency,
    verify_inclusion,
)
from .cose_wire import (
    CLL_CHECKPOINT_CONTENT_TYPE,
    WIRE_KIND,
    CoseCheckpointVerification,
    DecodedCheckpointCose,
    checkpoint_to_cose,
    encode_checkpoint_claims,
    verify_checkpoint_cose_offline,
)
from .emit import (
    DEFAULT_TS_PUBLIC_KEY_ID,
    DEFAULT_TS_PUBLIC_KEY_PEM,
    DEFAULT_TS_URL,
    EXAMPLE_CONFIG_TOML,
    STUB_MARKER,
    STUB_TS_URL,
    CheckpointConfig,
    CheckpointError,
    CheckpointRecord,
    Grade,
    RollbackError,
    Signer,
    StampVerdict,
    WitnessRecord,
    due_for_checkpoint,
    emit_checkpoint,
    lag_exceeded,
    register_checkpoint,
    register_checkpoint_stub,
    verify_checkpoint_consistency,
    verify_checkpoint_signature,
    verify_checkpoint_signature_offline,
    verify_receipt_offline,
    verify_witness_stamp_offline,
    verify_witness_stamp_tristate,
)
from .index import LogSource, MmrLedger, RangeProof, verify_range
from .store import MemoryNodeStore

__all__ = [
    "Bundle",
    "BundleError",
    "bundle",
    "verify_bundle_log_integrity",
    "CLL_CHECKPOINT_CONTENT_TYPE",
    "WIRE_KIND",
    "CoseCheckpointVerification",
    "DecodedCheckpointCose",
    "checkpoint_to_cose",
    "encode_checkpoint_claims",
    "verify_checkpoint_cose_offline",
    "ConsistencyProof",
    "InclusionProof",
    "IntegrityError",
    "InvalidArgumentError",
    "add_leaf",
    "commitment_object",
    "consistency_proof",
    "height_at",
    "interior_hash",
    "leaf_count",
    "leaf_hash",
    "leaf_index_to_pos",
    "node_count",
    "peaks",
    "pos_to_leaf_index",
    "root_from_peaks",
    "verify_consistency",
    "verify_inclusion",
    "LogSource",
    "MmrLedger",
    "RangeProof",
    "verify_range",
    "MemoryNodeStore",
    "DEFAULT_TS_URL",
    "DEFAULT_TS_PUBLIC_KEY_PEM",
    "DEFAULT_TS_PUBLIC_KEY_ID",
    "EXAMPLE_CONFIG_TOML",
    "STUB_MARKER",
    "STUB_TS_URL",
    "CheckpointConfig",
    "CheckpointError",
    "CheckpointRecord",
    "Grade",
    "RollbackError",
    "Signer",
    "StampVerdict",
    "WitnessRecord",
    "due_for_checkpoint",
    "emit_checkpoint",
    "lag_exceeded",
    "register_checkpoint",
    "register_checkpoint_stub",
    "verify_checkpoint_consistency",
    "verify_checkpoint_signature",
    "verify_checkpoint_signature_offline",
    "verify_receipt_offline",
    "verify_witness_stamp_offline",
    "verify_witness_stamp_tristate",
]
