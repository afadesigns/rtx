# Real Tracker X

Real Tracker X (rtx) is a dependency trust scanner authored by **Andreas Fahl**. It gives teams a pre-upgrade view of risk across ecosystems before new dependencies ship to production.

## Why Real Tracker X?
- **Cross-ecosystem coverage.** Parse manifests from npm, PyPI, Maven, Cargo, Go modules, Composer, NuGet, RubyGems, Conda, Homebrew, and Docker.
- **Trust signals.** Blend OSV + GitHub advisories with heuristics (abandonment, typosquats, suspicious churn, compromised maintainers).
- **Developer-first.** Rich CLI output, deterministic exit codes, JSON/HTML reports, and a Python API for integrations.
- **Secure by design.** Offline metadata resolution, signed releases, CycloneDX SBOMs, and SLSA provenance.

## Quick Links
- [Getting Started](getting-started.md)
- [CLI Reference](cli.md)
- [API Reference](api.md)
- [Security Policy](../SECURITY.md)
- [Support](../SUPPORT.md)

## Feature Matrix
| Capability | Status |
|------------|--------|
| OSV.dev + GitHub advisories | ✅ |
| Typosquat detection | ✅ |
| Abandonment & churn heuristics | ✅ |
| CycloneDX SBOM export | ✅ |
| HTML / JSON table reports | ✅ |
| Signed releases + SLSA provenance | ✅ |

## Architecture Overview
1. **Scanner registry** detects manifests and normalizes dependency metadata.
2. **Graph builder** consolidates direct + transitive dependencies.
3. **Threat intel service** queries OSV, GitHub, and curated datasets.
4. **Trust policy engine** evaluates heuristics and computes risk scores.
5. **Reporters** render the results (table, JSON, HTML, SBOM).

## License & Attribution
Real Tracker X is released under the MIT License. Copyright © 2025 **Andreas Fahl**.
