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

A version-tag push does not update the GHCR `latest` image tag; `latest` only
tracks the most recent push to `main`.

The `v`-prefixed tag mirrors the git tag, while the bare version is convenient
for consumers that expect container image tags without the prefix.

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

5. Confirm the `.github/workflows/publish-image.yml` (`Publish image`) workflow
   run triggered by the tag publishes the versioned GHCR image tags, including
   `vX.Y.Z` and `X.Y.Z`.
6. Optionally create a GitHub Release. The GitHub CLI can use generated release
   notes as a starting point:

   ```sh
   gh release create vX.Y.Z --generate-notes
   ```

   Review the generated notes and align the final release description with
   `CHANGELOG.md`.
