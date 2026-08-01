# Releasing the lockstep workspace

One bare SemVer tag publishes these independently installable distributions at the same version:

- `authweave-core`
- `litestar-auth`
- `authweave-workload`
- `authweave-otel`
- `authweave-webhooks`
- `authweave-http-signatures`

## Preflight

Run the normal verification gates, then build through the version-controlled release manifest:

```bash
just setup
just check
just deptry-check
just test
just docs-build
just build
```

`just build` creates one wheel and one sdist per distribution under `dist/<distribution>/`, then
installs each wheel in its own isolated environment and imports that distribution's public module.
The Tests workflow runs the same build/import smoke. A missing manifest entry, artifact, mismatched
project name, or non-lockstep version fails the dry-run.

## Automated release flow

Prepare and review one commit on the default branch that updates every distribution version,
module `__version__`, exact cross-workspace dependency pin, `uv.lock`, and the finalized
`CHANGELOG.md` entry. Run `just build`; its release manifest rejects stale internal pins as well as
non-lockstep project versions. Then run `Tag prepared release`. The workflow accepts only this
clean, already-prepared commit and never edits release metadata itself. A new version must be
strictly greater than the latest stable SemVer tag; equality is accepted only to resume that same
tag on the unchanged commit.

The bump job runs only from the default branch in the protected `release-operations` environment.
It atomically pushes exactly that branch and the matching tag with `PERSONAL_ACCESS_TOKEN`, then
creates a draft GitHub release. Only one draft release may exist, so a second release cannot start
until the first finishes. If a run fails after its atomic push, rerun the same workflow; it resumes
only when the existing tag resolves to the unchanged default-branch commit. The token must
be able to update the protected default branch, create the tag, and trigger the Tests workflow.
Store it in the `release-operations` environment and scope it to this repository with only
read/write access to repository contents.

Each release invocation explicitly schedules one authoritative Tests run by immutable version-tag
reference, so later default-branch pushes cannot cancel or replace it. Tag pushes are not a separate
test trigger. The release workflow also requires a successful `Tag prepared release` Actions run
from the default branch for the exact tested SHA; that run is gated by the `release-operations`
environment, so a direct Tests dispatch cannot bypass the protected pre-tag path. After a
successful run, the release workflow verifies
that the tested commit has exactly one matching workspace-version tag and is the repository's only
draft release. It then:

1. builds all artifacts twice with `SOURCE_DATE_EPOCH=0` and requires byte-identical results;
2. attaches every wheel and sdist to the draft, resuming only when existing asset SHA-256 digests
   match the verified build;
3. publishes `authweave-core`, then `litestar-auth`, then `authweave-workload`; the remaining
   dependent distributions publish after core through PyPI trusted publishing;
4. builds and deploys the documentation; and
5. publishes the GitHub release only after every asset, PyPI, and documentation job succeeds.

Configure and protect these GitHub environments before release: `release-operations`, `pypi-core`,
`pypi`, `pypi-workload`, `pypi-otel`, `pypi-webhooks`, `pypi-http-signatures`, and `github-pages`.
Register `.github/workflows/3_release.yml` as the trusted publisher for each PyPI project with the
matching environment. Use a pending publisher for a project that does not exist yet, and recheck
the package name immediately before release because a pending publisher does not reserve it.

## Yank and fix forward

Published tags, versions, artifacts, and GitHub releases are immutable release evidence. Never
delete or reuse them, and never overwrite an attached asset. Correct a bad release as follows:

1. Yank the affected version in every PyPI project where it was published. Yanking prevents new
   resolver selection while preserving pinned installs and the audit trail; do not delete files.
2. Preserve the tag and GitHub release (or draft), record which distributions were published or
   downloaded, and notify the incident owner of any security or compatibility impact.
3. Add the failure/incident status to the draft notes, then publish it as a prerelease that is not
   latest (`gh release edit TAG --draft=false --prerelease --latest=false`). This preserves the
   evidence while releasing the single-draft barrier.
4. Fix the default branch, run the full preflight, and publish a new patch version.

The GitHub asset job is safe to retry because it verifies existing digests and uploads only missing
files. Retry a PyPI publish job only when its log proves that no upload began; retrying downstream
non-publish jobs is safe. If a PyPI job might have uploaded only one artifact, or its outcome is
unknown, yank every distribution that did publish, leave the tag and attached assets intact,
publish the failed draft as the non-latest prerelease described above, and fix forward with a new
patch version.
