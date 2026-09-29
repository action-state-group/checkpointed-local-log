# SPDX-License-Identifier: Apache-2.0
"""Check crate manifests against crates.io's publish-time metadata rules.

`cargo publish --dry-run` does not validate these; crates.io rejects them at
upload. Rules: at most 5 keywords, each at most 20 characters, starting with a
letter and using only letters, digits, '-', '_' or '+'; at most 5 categories;
description, license and repository present; not both license and
license-file.

Usage: python .github/scripts/check_crate_metadata.py rust/*/Cargo.toml
"""
import re
import sys
import tomllib

KEYWORD = re.compile(r"[A-Za-z][A-Za-z0-9_+-]*")


def problems(pkg: dict) -> list[str]:
    out = []
    kws = pkg.get("keywords", [])
    if len(kws) > 5:
        out.append(f"{len(kws)} keywords (max 5)")
    for k in kws:
        if len(k) > 20:
            out.append(f"keyword {k!r} is {len(k)} characters (max 20)")
        if not KEYWORD.fullmatch(k):
            out.append(f"keyword {k!r} has characters crates.io rejects")
    if len(pkg.get("categories", [])) > 5:
        out.append("more than 5 categories")
    for field in ("description", "license", "repository"):
        if not pkg.get(field):
            out.append(f"missing {field}")
    if pkg.get("license") and pkg.get("license-file"):
        out.append("both license and license-file")
    return out


def main(paths: list[str]) -> int:
    failed = False
    for path in paths:
        with open(path, "rb") as f:
            pkg = tomllib.load(f).get("package")
        if pkg is None:
            continue
        errs = problems(pkg)
        print(f"{path}: {pkg['name']} {pkg.get('version')}: " + ("ok" if not errs else "; ".join(errs)))
        failed |= bool(errs)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
