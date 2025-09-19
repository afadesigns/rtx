# rtx — Real Tracker X

![PyPI](https://img.shields.io/badge/pypi-coming--soon-lightgrey)
![CI](https://github.com/afadesigns/rtx/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Downloads](https://img.shields.io/badge/downloads-prelaunch-lightgrey)
![SLSA](https://img.shields.io/badge/SLSA-level%203-blueviolet)

**Author:** Andreas Fahl  
**Tagline:** Cross-ecosystem dependency trust scanner for secure upgrades.

## Problem
Modern software supply chains depend on sprawling, fast-moving dependency graphs. Teams struggle to evaluate risk before upgrading, face alert fatigue from siloed advisories, and lack unified visibility across ecosystems. Compromised maintainers, typosquats, and abandoned packages frequently slip past point-in-time audits.

## Solution
rtx pre-computes the blast radius of any change. It ingests manifests from Python, JavaScript, Java, Rust, Go, PHP, .NET, Ruby, Conda, and Homebrew projects, builds a full dependency tree, enriches it with OSV and GitHub advisories, and evaluates trust using transparent heuristics (abandonment, churn, maintainer health, typosquats). Reports yield deterministic exit codes for CI and can be exported as Rich tables, JSON, or HTML bundles.

## Demo (10s Asciinema)
[![asciicast](docs/assets/demo.gif)](docs/demo.md)

## Installation
```bash
pip install rtx-trust
```

## Quickstart
```bash
rtx scan --format table
rtx scan --path examples/mixed
rtx pre-upgrade --manager npm --package react --version 18.0.0
rtx report --format json --output reports/rtx.json
```

## Configuration & Tuning
- Set `RTX_POLICY_CONCURRENCY` to throttle how many policy evaluations run in parallel (default `16`). Lower the value when scanning inside constrained CI runners or behind strict rate limits.
- CLI format switches are validated directly by argparse. Passing an unsupported format (for example `--format pdf`) exits with an actionable error before any network calls occur.
- Providing an unknown package manager via `--manager` now fails fast with the offending name, making misconfigurations obvious during automation.

## CLI Overview
- `rtx scan`: Detect manifests in the current directory, build the dependency graph, and score trust.
- `rtx pre-upgrade`: Simulate dependency upgrades and compare trust deltas before applying.
- `rtx report`: Render persisted reports in JSON, table, or HTML formats for CI workflows.
- `rtx list-managers`: List supported package managers, manifest file patterns, and detection confidence.

## Library API
```python
from pathlib import Path
from rtx.api import scan_project
report = scan_project(Path("./my-service"), managers=["npm", "pypi"])
print(report.summary())
```

## Examples
- `examples/npm`: Node.js service with npm lockfiles.
- `examples/pypi`: Python project using `pyproject.toml` and `uv.lock`.
- `examples/mixed`: Polyglot workspace combining npm, Poetry, Maven, Cargo, and Docker.

## Architecture
- Modular scanners per ecosystem share a common threat-evaluation core.
- Advisory providers (OSV, GitHub, ecosystem feeds) run asynchronously with caching.
- Trust policy engine computes risk scores and exit codes.
- SBOM generator emits CycloneDX v1.5 for every scan and pre-upgrade run.

## Security Notes
- No install scripts are executed; all metadata resolution is offline-first with bounded timeouts.
- All dependencies are vendored with hashes; CI blocks on unpinned packages.
- Releases publish signed wheels, SBOMs, and SLSA provenance via GitHub OIDC + cosign.

## Roadmap
1. Artifact attestation for container images.
2. Native integrations for Maven Enforcer and Gradle.
3. Streaming trust dashboards with anomaly alerts.
4. Workspace diff views for GitHub, GitLab, and Bitbucket Apps.

## FAQ
**Why another dependency scanner?** rtx focuses on pre-upgrade guardrails, not post-incident triage.  
**Does it phone home?** No. Network requests are limited to advisories and metadata endpoints; they respect enterprise proxies.  
**Can I extend support?** Yes. Create a plugin under `src/rtx/scanners` and register it in `rtx.registry`.  
**How do exit codes map to severity?** 0 = safe, 1 = medium trust gaps, 2 = high/critical risk.

## Community & Support
- Read the [Code of Conduct](CODE_OF_CONDUCT.md).
- See [CONTRIBUTING.md](CONTRIBUTING.md) for onboarding.
- File security issues via [SECURITY.md](SECURITY.md) or /.well-known/security.txt.
- Discussions and roadmaps live under GitHub Discussions.

## Author Attribution
Copyright © 2025 Andreas Fahl.
