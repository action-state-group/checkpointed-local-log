<!-- SPDX-License-Identifier: Apache-2.0 -->
# Releasing

The Python, TypeScript and Rust packages release the same way. A release is a
merged version bump: you choose the bump, review it as a pull request, and
merging it tags and publishes. The packages are listed in
[`.github/releases.json`](.github/releases.json), which
[`.github/release.py`](.github/release.py) reads.

| Package | Manifest | Tag | Publisher | Environment |
|---|---|---|---|---|
| `python` | `python/pyproject.toml` | `python/v<version>` | `publish-python.yml` | `pypi` (tag rule `python/v*`) |
| `ts` | `ts/package.json` and `ts/package-lock.json` | `ts/v<version>` | `publish-ts.yml` | `npm` (tag rule `ts/v*`) |
| `crates/checkpointed-local-log` | `rust/Cargo.toml` and `rust/Cargo.lock` | `crates/checkpointed-local-log-v<version>` | `publish-rust.yml` | `crates-io` (tag rule `crates/*-v*`) |
| `crates/evidencebook` | `evidencebook/Cargo.toml` and `evidencebook/Cargo.lock` | `crates/evidencebook-v<version>` | `publish-rust.yml` | `crates-io` (tag rule `crates/*-v*`) |

The prefix is only on the Git tag. The registry version stays plain (`0.5.1`).

## Cutting a release

1. **Prepare.** Run [Prepare release](https://github.com/action-state-group/checkpointed-local-log/actions/workflows/prepare-release.yml)
   on `main`, choosing the package and `patch`, `minor` or `major`. It raises
   the version from the current one, commits the bump with a sign-off, and
   pushes `release/<package>-v<version>`.
2. **Review.** Open the pull request from the link in the run summary. Open it
   yourself: a pull request opened by the workflow would not start CI. Add the
   CHANGELOG entry on the same branch if it is not in yet.
3. **Merge.** [Tag release](https://github.com/action-state-group/checkpointed-local-log/actions/workflows/tag-release.yml)
   runs on the merge. For each package whose version changed it creates the
   tag and GitHub Release on the merge commit and dispatches the package's
   publisher on that tag.
4. **Publish.** The publisher checks that the tag is the package's prefix plus
   its manifest version and that the commit is on `main`, then uploads through
   OIDC trusted publishing from its environment. Confirm the run and the new
   version on the registry.

Bumping a version by hand in any pull request releases it the same way when it
merges.

`evidencebook` depends on `checkpointed-local-log` by path, so bumping the
crate also updates its entry in `evidencebook/Cargo.lock`. A `minor` or
`major` bump of the crate also needs `evidencebook/Cargo.toml`'s requirement
raised on the release branch; CI's `--locked` builds fail until it is.
Release the two crates in separate merges, `checkpointed-local-log` first: if
one merge bumps both, `evidencebook` may upload before crates.io serves the new
`checkpointed-local-log` and fail; re-run its publish once that version is
live.

If a publish fails after the tag exists:

- **A transient or configuration failure** (registry outage, trusted publisher
  or environment settings): fix it and re-run the failed publisher run.
  `publish-ts.yml` skips a version npm already has from the same commit, so a
  re-run after a successful upload is harmless.
- **A defect in the code or the workflow:** a re-run uses the tagged commit
  again, so a fix merged to `main` does not reach it. Release the fix as a new
  version.
- **Tag release failed before dispatching** (no publisher run exists): re-run
  the Tag release run. It accepts a tag and GitHub Release it already created on
  the same commit and dispatches the publisher again.

## Safeguards

- **Guard.** `release.py check` refuses a tag from another package, a version
  that differs from the manifest, and a commit that is not on `main`.
  `publish-rust.yml` additionally checks the crate list, the `Cargo.toml`
  version, crates.io availability and crate metadata.
- **Environments.** `pypi`, `npm` and `crates-io` accept deployments only from
  their tag patterns, so a job started from a branch or another tag cannot
  upload.
- **Tags.** The `release tags` ruleset lets only admins move or delete tags.
  Creating `go/v*` tags is also admin-only, because a Go release is the pushed
  tag itself, with no workflow in between.

## Other artifacts

- **Go:** an admin pushes `go/v<version>`. A bad release can only be withdrawn
  with a `retract` directive in a later version.
- **TestPyPI rehearsal:** `rehearse-python.yml` builds and uploads a candidate
  to TestPyPI only.

Historical tags (`v*`, `rust-*`, and earlier `crates/*`) and published
versions keep their original layouts.

## Registry configuration

Each registry's trusted publisher names this repository, the publisher
workflow file and its environment:

| Registry | Package | Workflow | Environment |
|---|---|---|---|
| PyPI | `checkpointed-local-log` | `publish-python.yml` | `pypi` |
| npm | `@action-state-group/cll` | `publish-ts.yml` | `npm` or blank |
| crates.io | `checkpointed-local-log`, `evidencebook` | `publish-rust.yml` | `crates-io` |

Renaming a publisher workflow breaks publishing until the registry is updated
first. No registry token is stored in this repository.
