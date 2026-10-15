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
| `crates/checkpointed-local-log` | `rust/checkpointed-local-log/Cargo.toml` and `rust/Cargo.lock` | `crates/checkpointed-local-log-v<version>` | `publish-rust.yml` | `crates-io` (tag rule `crates/*-v*`) |

The prefix is only on the Git tag. The registry version stays plain (`0.5.1`).

## Cutting a release

1. **Prepare.** Run [Release · Prepare](https://github.com/action-state-group/checkpointed-local-log/actions/workflows/prepare-release.yml)
   on `main`, choosing the package and `patch`, `minor` or `major`. It raises
   the version from the current one, commits the bump with a sign-off, and
   pushes `release/<package>-v<version>`.
2. **Review.** Open the pull request from the link in the run summary. Open it
   yourself: a pull request opened by the workflow would not start CI. Add the
   CHANGELOG entry on the same branch if it is not in yet.
3. **Merge.** [Release · Tag](https://github.com/action-state-group/checkpointed-local-log/actions/workflows/tag-release.yml)
   runs on the merge. For each package whose version changed it creates the
   tag and GitHub Release on the merge commit and dispatches the package's
   publisher on that tag.
4. **Publish.** The publisher checks that the tag is the package's prefix plus
   its manifest version and that the commit is on `main`, then uploads through
   OIDC trusted publishing from its environment. Confirm the run and the new
   version on the registry.

Bumping a version by hand in any pull request releases it the same way when it
merges.

The `evidencebook` crate moved to its own repository,
[action-state-group/evidencebook](https://github.com/action-state-group/evidencebook),
which releases it. Its 0.0.1 and 0.0.3 tags here (`crates/evidencebook-v*`)
and their GitHub Releases are history and stay unchanged.

If a publish fails after the tag exists:

- **A transient or configuration failure** (registry outage, trusted publisher
  or environment settings): fix it and re-run the failed publisher run.
  `publish-ts.yml` skips a version npm already has from the same commit, so a
  re-run after a successful upload is harmless.
- **A defect in the code or the workflow:** a re-run uses the tagged commit
  again, so a fix merged to `main` does not reach it. Release the fix as a new
  version.
- **Release · Tag failed before dispatching** (no publisher run exists): re-run
  the Release · Tag run. It accepts a tag and GitHub Release it already created on
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

Historical tags (`v*`, `rust-*`, and earlier `crates/*`) and published
versions keep their original layouts.

## Registry configuration

Each registry's trusted publisher names this repository, the publisher
workflow file and its environment:

| Registry | Package | Workflow | Environment |
|---|---|---|---|
| PyPI | `checkpointed-local-log` | `publish-python.yml` | `pypi` |
| npm | `@action-state-group/cll` | `publish-ts.yml` | `npm` or blank |
| crates.io | `checkpointed-local-log` | `publish-rust.yml` | `crates-io` |

Renaming a publisher workflow breaks publishing until the registry is updated
first. No registry token is stored in this repository.
