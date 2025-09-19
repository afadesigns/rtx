# Maintenance Plan

## Release Cadence
- Monthly minor releases (first Tuesday).
- Weekly patch releases as needed for bug fixes.
- Security advisories published within 24 hours of confirmed issue.

## Triage SLA
- Security reports: acknowledge <24h, fix/mitigate <72h.
- Bug reports: initial response <2 business days.
- Feature requests: response <5 business days with prioritization label.

## Contributor Guide Highlights
- Pre-commit hooks mandatory (`pre-commit install`).
- PRs require lint, type, test, fuzz, sbom checks.
- Signed commits enforced by branch protection.

## Seed Issues
- `good first issue`: write new scanner for ecosystems with sample manifests.
- `help wanted`: improve advisory caching + offline support.
- `security hardening`: integrate deps.dev + OpenSSF Scorecard metrics.

Owner: Andreas Fahl.
