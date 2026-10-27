# SPDX-License-Identifier: Apache-2.0
"""``cll.log.counter`` -- the entry count of the CLL entry log.

``EntryCounter`` is the contract's entry counter (docs/backend-contract.md,
"Entry count"). Every built-in backend implements it. It is a protocol of its
own, beside ``EntrySource``, so that stores which predate it, such as the
``cll.log.ledger`` adapters, still satisfy the entry log protocols.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = ["EntryCounter"]


@runtime_checkable
class EntryCounter(Protocol):
    """Reports the number of entries in the log. Sequences are dense and
    1-based, so the count is also the last sequence."""

    def entry_count(self) -> int: ...
