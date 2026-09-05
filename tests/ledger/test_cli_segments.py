# SPDX-License-Identifier: Apache-2.0
"""Tests for ``cll segments list|mount|unmount|verify``."""
from __future__ import annotations

import itertools

from cll.checkpoint import MmrLedger
from cll.cli import main
from cll.ledger.segments import MmrCheckpointer
from cll.ledger.store import LedgerStore
from cll.signing import LocalSigner

_capsule_counter = itertools.count()


def _synthetic_capsule() -> dict:
    i = next(_capsule_counter)
    return {
        "canonicalization_id": "jcs",
        "action_type": "fyi",
        "operator": "test-op",
        "developer": "test-dev",
        "timestamp": f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z",
        "event": f"test_event_{i}",
        "detail": {"i": i, "padding": "x" * 20},
    }


def _seed_managed_store(tmp_path, n: int = 30):
    store = LedgerStore(tmp_path, rotate_at_checkpoint=True, max_segment_bytes=300)
    mmr = MmrLedger(store)
    signer = LocalSigner(key_id="test-key", secret=b"secret-bytes-for-hmac-signing-01")
    store.set_checkpointer(MmrCheckpointer(mmr=mmr, signer=signer))
    for _ in range(n):
        store.append(_synthetic_capsule(), consequential=False)
    closed = [s for s in store.list_segments() if s.manifest is not None]
    store.close()
    return closed


def test_cli_segments_list(tmp_path, capsys):
    _seed_managed_store(tmp_path)
    rc = main(["segments", "list", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "seg-000001.jsonl" in out
    assert "mounted" in out


def test_cli_segments_verify_and_unmount_mount_roundtrip(tmp_path, capsys):
    closed = _seed_managed_store(tmp_path)
    target = closed[0].name

    rc = main(["segments", "verify", str(tmp_path), target])
    assert rc == 0
    assert "OK" in capsys.readouterr().out

    rc = main(["segments", "unmount", str(tmp_path), target])
    assert rc == 0

    out = capsys.readouterr()
    rc = main(["segments", "list", str(tmp_path)])
    assert rc == 0
    assert "unmounted" in capsys.readouterr().out

    rc = main(["segments", "verify", str(tmp_path), target])
    assert rc == 0
    assert "OK" in capsys.readouterr().out

    rc = main(["segments", "mount", str(tmp_path), target])
    assert rc == 0
    rc = main(["segments", "list", str(tmp_path)])
    out = capsys.readouterr().out
    assert "unmounted" not in out
