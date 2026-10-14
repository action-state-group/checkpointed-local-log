# CLAUDE.md

Guidance for coding agents working in this repository: the Checkpointed Local
Log Internet-Draft (`spec/`) and its Python, Rust, Go and TypeScript
implementations, plus the `evidencebook` crate.

## Commands

Run each language's commands from its directory.

```bash
# python/  (Python 3.9 compatible)
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q
python -m pytest -q ../.github/test_release.py     # release helper

# rust/  (the workspace: checkpointed-local-log and evidencebook)
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features

# go/
go vet ./...
go test ./...
go test -race ./...

# ts/
npm ci
CLL_ROOT=.. npm run check
npm run build
```

`rust/evidencebook/` also runs `./scripts/check-vocabulary.sh`. Cross-language
interop checks live in `.github/scripts/` and `go/scripts/`.

## Layout

| Directory | Package |
|---|---|
| `python/` | PyPI `checkpointed-local-log`, import `cll` |
| `rust/checkpointed-local-log/` | crate `checkpointed-local-log`, library `cll` |
| `go/` | `github.com/action-state-group/checkpointed-local-log/go` |
| `ts/` | npm `@action-state-group/cll` |
| `rust/evidencebook/` | crate `evidencebook`, which depends on `checkpointed-local-log` by path |
| `spec/` | the Internet-Draft source |

The conformance vector directories (`*-vectors/`) are shared by every
implementation; change them only with all implementations agreeing.

## Rules

- Commits use conventional commit messages and a DCO sign-off
  (`git commit -s`). Do not add AI attribution trailers; the `dco` check
  rejects both an unsigned commit and an AI co-author trailer.
- New behavior needs tests in the same change, including error paths.
- One top-level directory per language. In `rust/`, `Cargo.toml` is the
  workspace, each crate is `rust/<crate-name>/` (here
  `rust/checkpointed-local-log/` and `rust/evidencebook/`), and all crates
  share `rust/Cargo.lock`. Add a Rust crate as another workspace member, never
  at `rust/` itself or outside it; its `.github/releases.json` entry names
  `rust/<crate-name>/Cargo.toml` and `rust/Cargo.lock`. The other
  action-state-group repositories use the same Rust layout.

## Releases

Follow [RELEASING.md](RELEASING.md). In short: run **Release · Prepare**, merge
its pull request, and the Release · Tag workflow tags and publishes. Never
create release tags by hand, except `go/v*`, which an admin pushes. Do not rename `publish-python.yml`,
`publish-ts.yml` or `publish-rust.yml`: the registries' trusted publishers name
them, so publishing breaks until the registry is updated first.
`.github/release.py` is an identical copy shared with the other
action-state-group repositories; change it in all of them together.
