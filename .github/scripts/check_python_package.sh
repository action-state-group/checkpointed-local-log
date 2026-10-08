#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exercise each supported installation shape outside the source checkout.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# An optional empty output directory retains the exact validated release bytes.
dist="$work/dist"
if [ "$#" -gt 0 ]; then
  dist="$1"
  mkdir -p "$dist"
  dist=$(cd "$dist" && pwd)
  if [ -n "$(ls -A "$dist")" ]; then
    echo "package output directory must be empty: $dist" >&2; exit 1
  fi
fi
python "$root/.github/scripts/test_python_inventory.py"
python "$root/.github/scripts/check_python_inventory.py" "$root/python"
python -m build "$root/python" --outdir "$dist"
python "$root/.github/scripts/check_python_inventory.py" "$root/python" --wheel "$(find "$dist" -name '*.whl' -print -quit)"
python - "$dist" <<'PY'
import pathlib, tarfile, zipfile, sys
root = pathlib.Path(sys.argv[1])
wheel = next(root.glob('*.whl'))
sdist = next(root.glob('*.tar.gz'))
for names in [zipfile.ZipFile(wheel).namelist(), tarfile.open(sdist).getnames()]:
    assert not any('/tests/' in p or '/.env' in p or '/__pycache__/' in p for p in names)
    for module in ['__init__.py', 'cli.py', 'revocation.py', 'signing.py', 'checkpoint/__init__.py', 'ledger/__init__.py', 'LICENSE', 'LICENSE-APACHE']:
        assert any(p.endswith('/' + module) for p in names), module
assert all(p.startswith(('cll/', 'checkpointed_local_log-')) for p in zipfile.ZipFile(wheel).namelist())
PY
python -m venv "$work/rebuild"
"$work/rebuild/bin/python" -m pip wheel --no-deps "$dist/"*.tar.gz --wheel-dir "$work/sdist-wheel"
python "$root/.github/scripts/check_python_inventory.py" "$root/python" --wheel "$(find "$work/sdist-wheel" -name '*.whl' -print -quit)"
for kind in source editable wheel sdist; do
  python -m venv "$work/$kind"
  "$work/$kind/bin/python" -m pip install --upgrade pip
  case "$kind" in
    source) "$work/$kind/bin/python" -m pip install "$root/python" ;;
    editable) "$work/$kind/bin/python" -m pip install -e "$root/python" ;;
    wheel) "$work/$kind/bin/python" -m pip install "$dist/"*.whl ;;
    sdist) "$work/$kind/bin/python" -m pip install "$dist/"*.tar.gz ;;
  esac
  (cd "$work" && "$work/$kind/bin/python" -c 'import cll, cll.checkpoint, cll.ledger, cll.revocation, cll.signing' && "$work/$kind/bin/cll" --help)
done
