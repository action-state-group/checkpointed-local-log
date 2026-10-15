# CLL backend conformance vectors

Language-neutral cases for the [CLL backend contract](../docs/backend-contract.md).
Every CLL storage backend in every language runs them, and so can a backend a
user writes against the same interfaces.

```
generate.py    deterministic generator, written from the contract
vectors.json   the cases
```

`generate.py` also writes the copies each implementation reads, because a
package cannot reach the repository root, and `--check` fails if any copy
differs from `vectors.json` by a byte:

```
python3 backend-conformance-vectors/generate.py --check
```

## Format

Each case names the interfaces it needs (`entries`, `checkpoint`, `witness`,
`close`), the capabilities it requires (`requires`) and those that exclude it
(`unless`). A runner skips a case that does not apply to its backend. The steps
run in order against one fresh, empty backend. Each step is one contract
operation with its arguments under their contract names, plus `expect`, which
is either `{"result": ...}` or `{"error": "<code>"}`.

Arguments and results use the contract's portable encodings: decimal strings
for sequences and sizes, standard base64 for bytes and `toISOString()` times.
Two rules make results comparable:

- `getWitness` of an absent key expects `{"error": "not_found"}`; a runner
  maps its language's absent value to that code.
- `loadCll` witness order is not part of the contract, so runners compare the
  witness list sorted by numeric `checkpointSize`, then `witnessId`.

An argument that a language's types cannot hold, such as an incomplete
checkpoint tuple in Go, counts as an invalid caller value: the runner expects
`invalid` without calling the backend.

The `reopen` step closes the backend and opens the same durable state again.

## Runners

| Language | Runner |
|---|---|
| Go | `github.com/action-state-group/checkpointed-local-log/go/cll/conformance` |
| TypeScript | `@action-state-group/cll/conformance` |
| Python | `cll.log.conformance` (`cases(open, reopen=None, digest_append=True, interfaces=...)`) |

Python backends lack the `extended-years` capability, because `datetime` holds
only years 0001..9999; see the contract's intentional differences.

## What the vectors do not cover

Concurrency, defensive copies, cross-handle visibility, corrupt durable data
and backend-specific behavior stay in each language's own backend tests; the
contract lists them under "Checks outside the vectors".
