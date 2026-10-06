# SPDX-License-Identifier: Apache-2.0
"""Validate the Python release namespace and metadata before publication."""
import pathlib
import re
import sys


def validate(tag, metadata):
    match = re.fullmatch(r"python/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
    version = re.search(r'^version = "([^"\n]+)"$', metadata, re.MULTILINE)
    if not match or not version or tag != "python/v" + version.group(1):
        raise ValueError("Expected python/v<metadata version> release tag")


if __name__ == "__main__":
    validate(sys.argv[1], pathlib.Path(sys.argv[2]).read_text())
