# Release Process

1. **Versioning.** Update `pyproject.toml`, `src/rtx/__init__.py`, and `CHANGELOG.md` with the new semantic version.
2. **Validation.** Run `make lint typecheck test fuzz sbom`.
3. **Tagging.** Create a signed tag (`git tag -s vX.Y.Z -m "vX.Y.Z"`). Tags trigger the `release.yml` workflow.
4. **Artifacts.** The release workflow builds source and wheel distributions, generates an SBOM (CycloneDX), signs artifacts with cosign, and attaches provenance (SLSA Level 3) attestations.
5. **Publishing.** Packages are published to PyPI via GitHub OIDC credentials. Documentation is deployed to GitHub Pages.
6. **Announcement.** Post updates to GitHub Releases, Discussions (changelog), LinkedIn, Twitter, and Dev.to using templates in `docs/launch/`.
