# Releasing GreenGateway

GreenGateway publishes tagged releases but remains alpha software. This
checklist keeps release tags, container images, changelog entries, and release
notes aligned.

## Versioning

GreenGateway uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release git tags must use the form `vMAJOR.MINOR.PATCH`, such as `v0.1.0`.

Patch bumps are reserved for backward-compatible fixes, minor bumps add
backward-compatible functionality, and breaking changes require a major bump.
Call out every operator-visible compatibility change clearly in `CHANGELOG.md`
and the release notes.

Version-tagged container images are published to GHCR with both the git tag and
the bare version tag. For example, pushing `v0.1.0` publishes:

- `ghcr.io/<owner>/<repo>:v0.1.0`
- `ghcr.io/<owner>/<repo>:0.1.0`

A version-tag push does not update the GHCR `latest` image tag. A push to `main`
updates `latest` only after every CI check succeeds for that exact commit.
Promotion also confirms that the source branch or tag still names the checked
commit; a superseded run leaves its candidate unpromoted.

The `v`-prefixed tag mirrors the git tag, while the bare version is convenient
for consumers that expect container image tags without the prefix.

## Checked image publication

The `CI` workflow runs on pull requests, pushes to `main`, and version-tag
pushes. Pull requests build the image with read-only permissions and never
publish it. Push runs call `publish-image.yml` from the same commit to build a
candidate tagged `candidate-<commit>-<run-id>-<attempt>`. This staging tag is
not a release: failed or superseded runs can leave candidates behind.

The promotion job depends on the candidate and every validation job, including
secret scanning and all PostgreSQL/HA gates. Failure, cancellation, or a skipped
dependency blocks promotion. After those checks pass, promotion copies the
candidate's content-addressed digest to the commit and release tags without
rebuilding or resolving the staging tag. Promotions are serialized per source
ref. The run summary records the checked commit, published tags, and immutable
`ghcr.io/<owner>/<repo>@sha256:<digest>` reference; use that digest to pin a
deployment to exact image bytes.

Secret scanning now runs as the `gitleaks` job inside CI, preserving its branch
protection check name. When adding a CI validation job, add it to
`promote-image.needs`; the `image-publication` structural test rejects an
incomplete dependency list. Retry a failed run after addressing its cause;
release tags are never promoted by a failed run.

The HA mixed-binary tripwire inspects the newest release tag on a different
commit. Tags naming the current candidate are excluded, including annotated
aliases. Once a previous release supports PostgreSQL, the gate still requires
real mixed-binary coverage before a later commit can be published.

## Release Checklist

1. Ensure `main` is green in CI.
2. Update `CHANGELOG.md` by moving accumulated `[Unreleased]` entries into a new
   `## [X.Y.Z] - YYYY-MM-DD` section, then add a fresh `[Unreleased]` section at
   the top.
3. Commit the changelog update and land it on `main`.
4. Create and push the release tag from the release commit:

   ```sh
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

5. Confirm the `.github/workflows/ci.yml` (`CI`) run triggered by the tag passes
   every check and its `Promote checked image` job publishes `vX.Y.Z` and
   `X.Y.Z`. Verify the digest recorded in that job's summary.
6. Optionally create a GitHub Release. The GitHub CLI can use generated release
   notes as a starting point:

   ```sh
   gh release create vX.Y.Z --generate-notes
   ```

   Review the generated notes and align the final release description with
   `CHANGELOG.md`.
