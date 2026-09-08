# SPDX-License-Identifier: Apache-2.0
"""Append -> fetch -> verify integration tests for draft-04 ``references[]``
(AAC >=0.3.0, `agent-action-capsule#91`).

``LedgerStore.verify()`` delegates Capsule validation to
``agent_action_capsule.verify`` wholesale (see ``store.py``) -- these tests
exercise that delegation through the real store round trip (append, fetch,
verify), not the AAC unit-test surface: a good reference verifies clean; a
duplicate-of-chain-parent or malformed-digest reference (submitted as a raw
dict, since the typed ``ReferenceEntry``/``Capsule`` producer already refuses
to construct either) fails at ``verify()``; and a reference digest edited
directly in the JSONL segment -- the actual append-only-log tamper scenario,
bypassing ``append()`` entirely -- fails the content-integrity check.
"""
from __future__ import annotations

import json

from agent_action_capsule import (
    AssuranceBlock,
    Capsule,
    Chain,
    ReferenceEntry,
    compute_capsule_id,
)


def _sealed(action_id: str, **kwargs) -> dict:
    return Capsule(
        spec_version="draft-mih-scitt-agent-action-capsule-04",
        format_version="4",
        canonicalization_id="jcs",
        action_id=action_id,
        action_type="fyi",
        operator="ACME-CO",
        developer="agent@v1",
        timestamp="2026-09-08T00:00:00Z",
        assurance=AssuranceBlock(
            attestation_mode="self_attested",
            effect_mode="not_applicable",
            ledger_mode="chained" if kwargs.get("chain") is not None else "standalone",
        ),
        **kwargs,
    ).seal()


def test_append_fetch_verify_valid_reference(store):
    parent = _sealed("parent-valid-ref")
    store.append(parent)

    child = _sealed(
        "child-valid-ref",
        references=(
            ReferenceEntry(
                type="agent-action-capsule",
                digest_alg="SHA-256",
                digest=parent["capsule_id"],
                citation_purpose="responds_to",
            ),
        ),
    )
    store.append(child)

    fetched = store.fetch(child["capsule_id"])
    assert fetched is not None
    assert fetched.capsule["references"] == child["references"]

    result = store.verify(child["capsule_id"])
    assert result is not None
    assert result.ok is True
    assert not any(f.code.startswith("reference_") for f in result.findings)


def test_append_fetch_verify_duplicate_reference_fails(store):
    parent = _sealed("parent-dup-ref")
    store.append(parent)

    # ReferenceEntry/Capsule already refuse to construct a reference
    # duplicating chain.parent_capsule_id (parse.py's own invariant) -- seal a
    # chained capsule with no references, then splice one in as a raw dict to
    # reach the store-level verifier finding, the same way an unsigned
    # raw-dict producer could submit one.
    sealed = _sealed(
        "child-dup-ref",
        chain=Chain(parent_capsule_id=parent["capsule_id"], relation="confirms"),
    )
    tampered = dict(sealed)
    tampered["references"] = [
        {"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": parent["capsule_id"]}
    ]
    tampered["capsule_id"] = compute_capsule_id(tampered)
    store.append(tampered)

    result = store.verify(tampered["capsule_id"])
    assert result is not None
    assert result.ok is False
    assert "reference_duplicates_chain_parent" in {f.code for f in result.findings}


def test_append_fetch_verify_bad_digest_reference_fails(store):
    # ReferenceEntry refuses a non-hex64 digest under the agent-action-capsule
    # /SHA-256 self-identity at construction -- bypass it the same way.
    sealed = _sealed("child-bad-digest-ref")
    tampered = dict(sealed)
    tampered["references"] = [
        {"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": "not-a-real-digest"}
    ]
    tampered["capsule_id"] = compute_capsule_id(tampered)
    store.append(tampered)

    result = store.verify(tampered["capsule_id"])
    assert result is not None
    assert result.ok is False
    assert "reference_malformed" in {f.code for f in result.findings}


def test_append_fetch_verify_tampered_reference_fails(store):
    """A reference digest edited directly in the stored JSONL segment --
    bypassing ``append()`` entirely -- is the scenario the append-only log
    actually has to catch. It trips the capsule_id/content-integrity check
    (§6 check 2), not a references[]-specific finding: the segment's bytes no
    longer match the digest the record was sealed under."""
    parent = _sealed("parent-tampered-ref")
    store.append(parent)
    other = _sealed("bystander-tampered-ref")
    store.append(other)

    child = _sealed(
        "child-tampered-ref",
        references=(
            ReferenceEntry(
                type="agent-action-capsule",
                digest_alg="SHA-256",
                digest=parent["capsule_id"],
                citation_purpose="responds_to",
            ),
        ),
    )
    record = store.append(child)
    assert store.verify(record.capsule_id).ok is True

    segment_path = store.root / "segments" / record.segment
    lines = segment_path.read_text().splitlines(keepends=True)
    target = next(i for i, line in enumerate(lines) if json.loads(line)["capsule_id"] == record.capsule_id)
    # Same-length swap (64 hex chars for 64 hex chars) so every OTHER record's
    # already-indexed byte offset in this segment stays valid.
    tampered_line = lines[target].replace(parent["capsule_id"], other["capsule_id"])
    assert tampered_line != lines[target]
    assert len(tampered_line) == len(lines[target])
    lines[target] = tampered_line
    segment_path.write_text("".join(lines))

    result = store.verify(record.capsule_id)
    assert result is not None
    assert result.ok is False
    assert "capsule_id_mismatch" in {f.code for f in result.findings}
