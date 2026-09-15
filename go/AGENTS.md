# AGENTS.md

## Project purpose

`cll-go` is an application-neutral Checkpointed Local Log implementation. It
stores dense 32-byte identities, maintains an MMR, signs checkpoints, and
delivers checkpoints to external witnesses. Record formats, record bodies,
verification, authorization, and application persistence stay outside this
module.

The Go module is `github.com/action-state-group/cll-go`.

## Source grounding

Before reading a peer repository or making a compatibility claim:

1. Confirm its branch with `git -C <repo> rev-parse --abbrev-ref HEAD`.
2. Pull the intended clean branch, or fetch and read the exact remote ref from
   an isolated worktree.
3. Record a compatibility-critical revision in `DESIGN.md` only when the exact
   revision is part of the durable contract.

Peer checkouts normally live beside this repository under `~/GitHub`.

## Architecture invariants

- Production packages must not import AAC or application-specific emitters.
- Public APIs use opaque `cll.EntryBytes` identities, not application record
  names or schemas.
- Applications verify and persist complete records before appending identities.
- Memory, JSONL, SQLite, and MySQL implement one `cll.Backend` contract.
- Go and TypeScript relational table names, columns, keys, portable encodings,
  schema semantics, and compare-and-set behavior stay compatible.
- JSONL v4 event names, fields, replay, torn-tail recovery, and locking stay
  compatible with TypeScript.
- Checkpoint and receipt wire bytes remain compatible with Go, TypeScript, and
  Python CLL implementations.
- Hosts own runner lifecycle, keys, endpoints, retries, and authorization.
- Do not add rebaseline or other one-runtime state transitions without an
  agreed cross-runtime contract.

## Compatibility review

Before a protocol, persistence, or state-transition change, refresh and inspect
the relevant implementations:

- `action-state-group/cll-ts` for generic APIs and persistent backends;
- `action-state-group/checkpointed-local-log` for Python MMR/checkpoint wire
  verification;
- the configured external witness implementation for request and receipt
  behavior.

Run the repository's cross-review workflow to convergence after design and
again after implementation. Treat peer findings as hypotheses and adjudicate
them against source and tests.

## Required checks

```bash
gofmt -w .
go mod tidy
go vet ./...
go test ./...
go test -race ./...
```

- Use `github.com/stretchr/testify/assert` and `require` in tests.
- Use `t.Context()` for context-blocked goroutines.
- Do not discard errors silently.
- Check map lookups and pointers before dereferencing.
- Use parameterized SQL and check `rows.Err()` after iteration.
- New functions and logic paths require success and edge-case tests.
- Exported identifiers and non-trivial packages require useful comments.
- New backends must run `internal/storetest.Run`; persistent multi-handle
  backends must also run `internal/storetest.CrossHandle`.

## Git requirements

- Use conventional commit prefixes.
- Sign every commit with `git commit -s` and verify its `Signed-off-by` trailer.
- Do not commit credentials, `.env`, editor state, task-local planning files,
  progress logs, review transcripts, or command history.
- Preserve unrelated user changes.
