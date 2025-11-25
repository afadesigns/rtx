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

> Requires Python 3.11 or newer. Use a virtual environment or tools like `uv`, Poetry, Conda, or `pipx` to manage interpreters and isolation.

### Environment managers
- **uv** — install the CLI as an isolated tool that tracks updates automatically:
  ```bash
  uv tool install --python 3.11 rtx-trust
  ```
  This keeps `rtx` on your `PATH` without polluting the active environment and lets you pin the interpreter version used to run the scanner.
- **Poetry** — add `rtx-trust` to an existing project and capture it in `poetry.lock`:
  ```bash
  poetry add rtx-trust
  ```
  Poetry resolves the dependency and updates both `pyproject.toml` and the lock file automatically.
- **Conda / Mamba** — create an environment with a modern Python, then install via the environment’s pip so the package stays isolated:
  ```bash
  conda create -n rtx python=3.11 pip
  conda activate rtx
  python -m pip install rtx-trust
  ```
  Always install pip-based dependencies after your conda packages to avoid solver conflicts.

## Local validation
Before opening a pull request, reproduce the CI checks inside an isolated environment (PEP 668 blocks system-wide installs on most distros):

```bash
uv sync  # or: python -m venv .venv && source .venv/bin/activate && pip install -e .[dev]
uv run make lint
uv run make typecheck
uv run make test
uv run make sbom
```

All commands avoid network access during tests unless explicitly enabled and fail fast on dependency drift or formatting issues.

## Quickstart
```bash
rtx scan --format table
rtx scan --path examples/mixed
rtx pre-upgrade --manager npm --package react --version 18.0.0
rtx report --format json --output reports/rtx.json
```

## Configuration & Tuning

RTX can be configured via `rtx.toml` (a TOML file in your project root) or environment variables. Environment variables always take precedence over `rtx.toml` settings.



**Example `rtx.toml`:**

```toml

[rtx]

cache_dir = "~/.cache/rtx"

http_timeout = 10.0

http_retries = 3

osv_batch_size = 20

osv_max_concurrency = 8

disable_osv = false

github_max_concurrency = 10

gomod_metadata_concurrency = 8



# Policy thresholds

policy_abandonment_threshold_days = 365

policy_churn_high_threshold = 15

policy_churn_medium_threshold = 7

policy_bus_factor_zero_threshold = 1

policy_bus_factor_one_threshold = 2

policy_low_maturity_threshold = 5

policy_typosquat_max_distance = 1

```



**Available settings (also configurable via `RTX_<SETTING_NAME>` environment variables):**

- `cache_dir`: Path to the directory where RTX stores persistent cache data (default `~/.cache/rtx`).

- `http_timeout`: Network request timeout in seconds (default `5.0`).

- `http_retries`: Number of retries for failed network requests (default `2`).

- `osv_batch_size`: Number of dependencies to query per OSV API batch request (default `18`).

- `osv_max_concurrency`: Maximum concurrent OSV API requests (default `4`).

- `disable_osv`: Set to `true` or `1` to bypass OSV lookups (default `false`).

- `github_max_concurrency`: Maximum concurrent GitHub Security API requests (default `6`).

- `gomod_metadata_concurrency`: Maximum concurrent Go module metadata requests (default `5`).



**Configurable Trust Policy Thresholds:**

- `policy_abandonment_threshold_days`: Number of days without a release before a package is flagged as abandoned (default `540`).

- `policy_churn_high_threshold`: Number of releases in the last 30 days to trigger a 'high churn' signal (default `10`).

- `policy_churn_medium_threshold`: Number of releases in the last 30 days to trigger a 'medium churn' signal (default `5`).

- `policy_bus_factor_zero_threshold`: Maximum number of maintainers to trigger a 'zero bus factor' signal (default `0`).

- `policy_bus_factor_one_threshold`: Maximum number of maintainers to trigger a 'single maintainer' signal (default `1`).

- `policy_low_maturity_threshold`: Minimum total releases for a package to be considered mature (default `3`).

- `policy_typosquat_max_distance`: Maximum Levenshtein distance for typosquatting detection (default `2`).



Existing Environment Variable Based Configuration:

- Set `RTX_POLICY_CONCURRENCY` to throttle how many policy evaluations run in parallel (default `16`). Lower the value when scanning inside constrained CI runners or behind strict rate limits.

- Toggle `RTX_DISABLE_GITHUB_ADVISORIES=1` when running in air-gapped or rate-limited environments to skip GitHub lookups entirely.

- Lockfile detection covers `poetry.lock`, `uv.lock`, and `environment.yml` so mixed-language workspaces are fully scanned without manual manifest hints.

- CLI format switches are validated directly by argparse. Passing an unsupported format (for example `--format pdf`) exits with an actionable error before any network calls occur.

- Providing an unknown package manager via `--manager` now fails fast with the offending name, making misconfigurations obvious during automation.

- Run `make smoke` for an end-to-end check that executes diagnostics and an offline scan against `examples/mixed`.

## CLI Overview
- `rtx scan`: Detect manifests in the current directory, build the dependency graph, and score trust.
- `rtx pre-upgrade`: Simulate dependency upgrades and compare trust deltas before applying.
- `rtx report`: Render persisted reports in JSON, table, or HTML formats for CI workflows.
- `rtx list-managers`: List supported package managers, manifest file patterns, and detection confidence.
- `rtx diagnostics`: Verify local availability of `pip`, `npm`, and `uv`; exits non-zero when a tool is missing or misconfigured.

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
1. Dependency graph visualization and export options.
2. Artifact attestation for container images.
3. Native integrations for Maven Enforcer and Gradle.
4. Streaming trust dashboards with anomaly alerts.
5. Workspace diff views for GitHub, GitLab, and Bitbucket Apps.

## FAQ
**Why another dependency scanner?** rtx focuses on pre-upgrade guardrails, not post-incident triage.  
**Does it phone home?** No. Network requests are limited to advisories and metadata endpoints; they respect enterprise proxies.  
**Can I extend support?** Yes. See [docs/extending.md](docs/extending.md) for details on adding new scanners or configuring trust policies.  
**How do exit codes map to severity?** 0 = safe, 1 = medium trust gaps, 2 = high/critical risk.

## Community & Support
- Read the [Code of Conduct](CODE_OF_CONDUCT.md).
- See [CONTRIBUTING.md](CONTRIBUTING.md) for onboarding.
- File security issues via [SECURITY.md](SECURITY.md) or /.well-known/security.txt.
- Discussions and roadmaps live under GitHub Discussions.

## Author Attribution
Copyright © 2025 Andreas Fahl.
