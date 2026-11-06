# CLL runner conformance vectors

Language-neutral cases for the checkpoint runner and the witness delivery
runner. Every language's runners replay them over its memory backend, so a
log that one language's runner checkpointed can be continued by another's
and the stored checkpoint statements are byte-identical.

```
vectors.json   the cases
```

The Go runners (`go/checkpoint/runner.go`, `go/witness/runner.go`) are the
reference: `go/internal/runnervectors` runs each scenario with them and
records the results. Regenerate, or check that every committed copy is
current, from `go/`:

```
go run ./test/runnervectors
go run ./test/runnervectors -check
```

The copies are `go/internal/runnervectors/testdata/vectors.json` and
`ts/test/testdata/runner-vectors.json`. Python and Rust tests read this file.

## Format

`signingKeySeed` is the Ed25519 seed of the checkpoint signer and `logId` the
log every case checkpoints. Each case has a runner `config` and `steps` that
run in order against one fresh, empty backend:

| op | Meaning |
|---|---|
| `append` | Append `value` at `appendedAt` to the entry log |
| `runCheckpoint` | One checkpoint runner pass at `now`. With `witnessIds`, that pass gives its checkpoint rows to those witnesses instead of the case's (a witness added later) |
| `deliverWitnesses` | One delivery pass at `now` over at most `limit` due rows per witness. Each witness answers its submits from `submit` and its receipt checks from `verify`, in order; every scripted answer must be used. `expect.result` is the number of rows that received a verified receipt |
| `loadCll` | Read the state; `expect.result` is the backend contract's portable state |

A scripted submit `error` is `retryable` (a timeout, HTTP 408, 429 or 5xx) or
`permanent`. Jitter is off. To make states comparable, witnesses are sorted by
numeric `checkpointSize`, then `witnessId`, and every `lastError` is replaced
by `<set>`: its text is each language's own.

## Capabilities

A case that `requires` a capability runs only where the runners have it.

| Capability | Go | Python | Rust | TypeScript |
|---|---|---|---|---|
| `bounded-run`: a checkpoint pass scans one batch of `scanLimit` entries and checkpoints that batch when it is due | yes | yes | yes | no: `runOnce` catches up on the whole backlog and checkpoints once |
| `stop-after-retryable`: a retryable failure ends that witness's delivery pass | yes | yes | yes | no: later rows of the witness are still tried |
| `chain-order`: a checkpoint is released to a witness only once that witness's row for the checkpoint's `prev_size` has a receipt, or when it has no such row (the witness's own answer then decides); a row without a receipt, permanent or not, holds the witness's later checkpoints; a permanent row is cleared only by an operator (`docs/backend-contract.md`, "Held and permanent witness rows") | yes | yes | yes | no: rows are sent in checkpoint order but not held |

## Runners

| Language | Test |
|---|---|
| Go | `go/internal/runnervectors` |
| TypeScript | `ts/test/runner-vectors.test.ts` |
| Python | `python/tests/checkpoint/test_runner_vectors.py` |
| Rust | `rust/checkpointed-local-log/tests/runner_vectors.rs` |
