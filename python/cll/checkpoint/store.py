# SPDX-License-Identifier: Apache-2.0
"""In-memory MMR node store (v0).

Backs the ``core`` module's ``NodeReader``/``NodeAppender`` protocols. No
persistence/segment format is built here -- the MMR is rebuilt by replaying
the wrapped log source (see ``index.MmrLedger.sync``), which is already that
source's own durable record. A segment/blob format is real future work if
resuming without a full replay becomes a performance concern, but that's out
of this task's scope.
"""
from __future__ import annotations

__all__ = ["MemoryNodeStore"]


class MemoryNodeStore:
    def __init__(self) -> None:
        self._nodes: list[bytes] = []

    def size(self) -> int:
        return len(self._nodes)

    def node(self, pos: int) -> bytes:
        try:
            return self._nodes[pos]
        except IndexError as exc:
            raise IndexError(f"no node at position {pos}") from exc

    def append_nodes(self, hashes: list[bytes]) -> None:
        self._nodes.extend(hashes)
