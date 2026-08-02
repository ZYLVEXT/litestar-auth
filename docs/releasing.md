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
It atomically pushes exactly that branch and the matching tag with its short-lived, job-scoped
`GITHUB_TOKEN`, then creates a draft GitHub release. The protected bump job, release trigger
verifier, asset attachment job, and final release publisher receive `contents: write`; the verifier
needs push-level access because GitHub omits draft releases from read-only API responses. Only the
bump job receives `actions: write`, and no long-lived release credential is stored. Only one draft
release may exist,
so a second release cannot start until the first finishes. If a run fails after its atomic push,
rerun the same workflow; it resumes only when the existing tag resolves to the unchanged
default-branch commit. The explicit Tests `workflow_dispatch` still creates a run when authenticated
with `GITHUB_TOKEN`; ordinary push events created by that token intentionally do not.

Each release invocation explicitly schedules one authoritative Tests run by immutable version-tag
reference, so later default-branch pushes cannot cancel or replace it. Tag pushes are not a separate
test trigger. After its required-check aggregator succeeds, that tag-bound Tests run dispatches the
release workflow on the same tag. The release workflow independently requires successful Tests and
`Tag prepared release` runs for the exact SHA; the latter is gated by the `release-operations`
environment, so a direct dispatch cannot bypass the protected pre-tag path. It also requires its
Git ref to be that one matching workspace-version tag and this to be the repository's only draft
release. The build and attestation context therefore use the tested tag SHA rather than the moving
default branch. It then:

1. builds all artifacts twice with `SOURCE_DATE_EPOCH=0` and requires byte-identical results;
2. generates each current CycloneDX 1.7 SBOM twice from the pinned uv lock graph, normalizes its UUID
   and timestamp from immutable release inputs, requires byte-identical dependency inventories, and
   records build-provenance and SBOM attestations against the exact wheel and sdist digests;
3. attaches every wheel, sdist, and SBOM to the draft, resuming only when existing asset SHA-256 digests
   match the verified build;
4. publishes `authweave-core`, then `litestar-auth`, then `authweave-workload`; the remaining
   dependent distributions publish after core through PyPI trusted publishing;
5. builds and deploys the documentation; and
6. publishes the GitHub release only after every asset, PyPI, and documentation job succeeds.

Configure and protect these GitHub environments before release: `release-operations`, `pypi-core`,
`pypi`, `pypi-workload`, `pypi-otel`, `pypi-webhooks`, `pypi-http-signatures`, and `github-pages`.
Register `.github/workflows/3_release.yml` as the trusted publisher for each PyPI project with the
matching environment. Use a pending publisher for a project that does not exist yet, and recheck
the package name immediately before release because a pending publisher does not reserve it.

## Verify published artifacts and provenance

Run this after every release from Bash 3.2+ or zsh with `gh` 2.97+, `curl`, `jq`, `sha256sum`, and `uv`
available. It requires every PyPI file to be byte-identical to the digest-verified GitHub Release
asset and verifies its PyPI publish attestation against this repository. The final Integrity API
check also requires the exact release workflow and per-project environment:

```bash
set -euo pipefail
VERSION=7.1.2
REPOSITORY=ZYLVEXT/litestar-auth
TAG_SHA=$(gh api "repos/$REPOSITORY/git/ref/tags/$VERSION" --jq .object.sha)
verification_dir=$(mktemp -d)
trap 'rm -rf "$verification_dir"' EXIT
mkdir -p "$verification_dir/github" "$verification_dir/pypi"

attestation_policy=(
  --repo "$REPOSITORY"
  --signer-workflow "$REPOSITORY/.github/workflows/3_release.yml"
  --signer-digest "$TAG_SHA"
  --source-ref "refs/tags/$VERSION"
  --source-digest "$TAG_SHA"
  --deny-self-hosted-runners
)

gh release verify "$VERSION" --repo "$REPOSITORY"
gh release download "$VERSION" --repo "$REPOSITORY" --dir "$verification_dir/github"
gh release view "$VERSION" --repo "$REPOSITORY" --json assets \
  --jq '.assets[] | "\(.digest | sub("^sha256:"; ""))  \(.name)"' \
  > "$verification_dir/SHA256SUMS"
(cd "$verification_dir/github" && sha256sum --check "$verification_dir/SHA256SUMS")
for asset in "$verification_dir/github"/*; do
  gh release verify-asset "$VERSION" "$asset" --repo "$REPOSITORY"
done

publishers=(
  authweave-core:pypi-core
  litestar-auth:pypi
  authweave-workload:pypi-workload
  authweave-otel:pypi-otel
  authweave-webhooks:pypi-webhooks
  authweave-http-signatures:pypi-http-signatures
)
for publisher in "${publishers[@]}"; do
  project=${publisher%%:*}
  environment=${publisher#*:}
  jq -e --arg project "$project" --arg version "$VERSION" '
    .bomFormat == "CycloneDX" and
    .specVersion == "1.7" and
    .metadata.component.name == $project and
    .metadata.component.version == $version
  ' "$verification_dir/github/$project-$VERSION.cdx.json" >/dev/null
  while IFS= read -r url; do
    filename=${url##*/}
    curl -fsSL "$url" -o "$verification_dir/pypi/$filename"
    cmp "$verification_dir/github/$filename" "$verification_dir/pypi/$filename"
    gh attestation verify "$verification_dir/github/$filename" "${attestation_policy[@]}"
    sbom_attestations=$(gh attestation verify \
      "$verification_dir/github/$filename" \
      "${attestation_policy[@]}" \
      --predicate-type https://cyclonedx.org/bom \
      --format json)
    jq -cS '.[].verificationResult.statement.predicate' <<< "$sbom_attestations" \
      | sort -u > "$verification_dir/signed.cdx.json"
    test "$(wc -l < "$verification_dir/signed.cdx.json")" -eq 1
    test "$(jq -cS . "$verification_dir/github/$project-$VERSION.cdx.json")" \
      = "$(cat "$verification_dir/signed.cdx.json")"
    uvx --from pypi-attestations pypi-attestations verify pypi \
      --repository "https://github.com/$REPOSITORY" "$url"
    curl -fsSL \
      "https://pypi.org/integrity/$project/$VERSION/$filename/provenance" \
      | jq -e --arg environment "$environment" '
          .attestation_bundles | length > 0 and all(.[].publisher;
            .kind == "GitHub" and
            .repository == "ZYLVEXT/litestar-auth" and
            .workflow == "3_release.yml" and
            .environment == $environment)
        ' >/dev/null
  done < <(curl -fsSL "https://pypi.org/pypi/$project/$VERSION/json" | jq -r '.urls[].url')
done
```

The GitHub attestations bind the release artifacts to the workflow that built them and to their
CycloneDX dependency inventory. The official PyPI publish action separately generates and uploads
PEP 740 attestations by default. These attestations prove provenance and artifact integrity, not
that the source is safe; code review, the required CI matrix, and reproducible-build check remain
mandatory.

## Release credential or workflow compromise

1. Cancel every affected run and disable `2_bump.yml` and `3_release.yml`. Cancelling the job ends
   its short-lived `GITHUB_TOKEN`; there is no release PAT to rotate.
2. Remove the six PyPI trusted-publisher registrations for `3_release.yml`, revoke any separately
   created PyPI API tokens, and block the release environments while the incident is investigated.
3. Preserve the workflow logs, audit events, tag, draft/release, assets, and PyPI files. Do not
   delete or reuse immutable evidence. Run the verification procedure above and record every
   mismatched or unexpectedly published file.
4. If any file may be unauthorized, follow **Yank and fix forward** below for every affected
   distribution and notify consumers through the security-response channel.
5. Restore the workflow only through a reviewed commit, recreate the exact trusted-publisher
   mappings, re-enable the workflows, and publish a new patch version. Never resume a release whose
   source SHA, workflow definition, artifact digest, or publisher identity is uncertain.

See GitHub's [`GITHUB_TOKEN` lifecycle and trigger rules](https://docs.github.com/en/actions/concepts/security/github_token)
and PyPI's [attestation verification model](https://docs.pypi.org/attestations/consuming-attestations/)
for the platform guarantees used by these procedures.

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
