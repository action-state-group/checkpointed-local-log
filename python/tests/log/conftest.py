# SPDX-License-Identifier: Apache-2.0
"""Fixtures shared by the ``cll.log`` backend tests."""
from __future__ import annotations

import itertools
import os
import uuid

import pytest

_counter = itertools.count()


def mysql_url() -> str:
    """``CLL_MYSQL_URL``. Unset skips MySQL tests locally and fails them in CI,
    so a missing service never passes silently."""
    url = os.environ.get("CLL_MYSQL_URL")
    if not url:
        if os.environ.get("CI"):
            pytest.fail("CLL_MYSQL_URL is required in CI for the MySQL backend tests")
        pytest.skip("CLL_MYSQL_URL is not set")
    pytest.importorskip("pymysql")
    return url


def unique_log_id(prefix: str = "test") -> str:
    """A log ID no other test or run uses, so MySQL tests share one database."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}-{next(_counter)}"
