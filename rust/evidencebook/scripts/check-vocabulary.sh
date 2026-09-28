#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The evidencebook crate carries no deployment vocabulary: record kinds,
# correlation key names and content tests belong to the calling profile. This
# gate fails if a word that names one deployment's concepts appears anywhere in
# the crate (source, tests, manifest, docs, vendored data).
#
# Words are matched whole (grep -w), and an underscore is a word character,
# so a compound identifier such as a capsule envelope member
# (`model_attestation`) is not a hit: the gate is about vocabulary the crate
# uses for its own concepts, not member names of formats it reads.
#
# One exemption exists, and it is per line: a request-draft wire token that
# happens to be one of these words, marked on that line with
#   vocabulary-gate: request-draft wire token
# The mark is only honoured on a line that also carries the token as a quoted
# string, so it cannot silently exempt prose.
set -euo pipefail

crate_dir="$(cd "$(dirname "$0")/.." && pwd)"
words='mesh|exchange|exchanges|twin|twins|provider|providers|model|models'
mark='vocabulary-gate: request-draft wire token'

hits="$(grep -RInwiE "$words" "$crate_dir" \
  --exclude-dir=target --exclude=Cargo.lock --exclude="$(basename "$0")" || true)"

violations="$(printf '%s\n' "$hits" | grep -v '^$' | while IFS= read -r line; do
  if [[ "$line" == *"$mark"* && "$line" == *'"exchange"'* ]]; then
    continue
  fi
  printf '%s\n' "$line"
done)"

if [[ -n "$violations" ]]; then
  echo "deployment vocabulary in the evidencebook crate:" >&2
  printf '%s\n' "$violations" >&2
  exit 1
fi
echo "vocabulary gate: clean"
