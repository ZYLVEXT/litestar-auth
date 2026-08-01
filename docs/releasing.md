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
uv run deptry .
just test
just docs-build
just build
```

`just build` creates one wheel and one sdist per distribution under `dist/<distribution>/`, then
installs all six wheels into an isolated environment and imports their public modules. The Tests
workflow runs the same build/import smoke before a tag can reach the release workflow. A missing
manifest entry, artifact, mismatched project name, or non-lockstep version fails the dry-run.

The release workflow builds twice with `SOURCE_DATE_EPOCH=0`, requires byte-identical artifacts,
attaches every wheel/sdist to the GitHub release, and publishes each directory through its own
GitHub environment and PyPI trusted-publishing job. Configure these environments before release:
`pypi-core`, `pypi`, `pypi-workload`, `pypi-otel`, `pypi-webhooks`, and
`pypi-http-signatures`.

## Rollback and yank

The `Rollback release` workflow is destructive and operator-triggered. For the selected tag:

1. Before triggering the workflow, yank that version in **all six** PyPI projects listed above.
   Yanking prevents new resolver selection but preserves already pinned installs; do not delete
   release files.
2. Confirm every PyPI project shows the version as yanked, then trigger the workflow.
3. The workflow deletes the GitHub release/tag and reverts the tagged bump commit on the default
   branch without an additional pause or PyPI check.
4. Run the full verification and release dry-run against the revert. Publish a new patch version
   for the correction; never reuse the removed tag or version.
5. Record which distributions were downloaded before the yank and communicate any security or
   compatibility impact through the incident owner.

If only one PyPI publish job failed, do not advance or silently leave a split version. Finish the
same-version publish only when the built GitHub assets and trusted-publishing approval are intact;
otherwise yank every distribution that did publish and execute the full rollback.
