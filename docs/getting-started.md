# Getting Started

## Installation
```bash
uv pip install rtx-trust
```

> Consider using `uv tool install rtx-trust` for a globally managed installation that doesn't interfere with your project's virtual environment.

## First Scan
```bash
rtx scan --path examples/mixed --format table --json-output reports/mixed.json --html-output reports/mixed.html --sbom-output reports/mixed-sbom.json
```

Exit code meanings:
- `0`: safe (no medium/high risk)
- `1`: warnings present (medium severity)
- `2`: high or critical risk detected

## Pre-Upgrade Simulation
```bash
rtx pre-upgrade --path examples/mixed --package react --version 18.2.0
```

The command displays baseline vs. proposed verdicts and exits with the higher risk code.

## CI Integration
We use `rtx` itself as our security scanner in our CI/CD workflows, demonstrating our confidence and trust in its capabilities. Here's a simplified example of how you can integrate `rtx` into your GitHub Actions pipeline:

```yaml
- name: Set up Python with uv
  uses: ./.github/actions/python-uv
  with:
    python-version: "3.14" # Or your desired Python version
- name: Install dependencies with uv
  run: uv sync
- name: Run RTX Security Scan
  run: rtx scan --format json --output reports/rtx-report.json --log-level INFO
  env:
    RTX_GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }} # If fetching GitHub advisories
- name: Upload RTX Report
  uses: actions/upload-artifact@v4
  with:
    name: rtx-report
    path: reports/rtx-report.json
- name: Upload SARIF report
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/rtx-report.json # Assuming rtx can output SARIF directly or a conversion step is added
```

Refer to `.github/workflows/ci.yml` for the full, detailed CI configuration.

## Configuration
Environment variables:
- `RTX_HTTP_TIMEOUT` (default `5` seconds)
- `RTX_LOG_LEVEL` (`DEBUG`, `INFO`, `WARN`, `ERROR`)
- `RTX_GITHUB_TOKEN` (optional GraphQL advisory access)

## Next Steps
- Review [CLI Reference](cli.md)
- Explore the [API](api.md)
- Contribute via [CONTRIBUTING.md](../CONTRIBUTING.md)
