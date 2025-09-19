# Getting Started

## Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install rtx-trust
```

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
Add to your CI pipeline (GitHub Actions example):
```yaml
- name: Trust scan
  run: |
    pip install --require-hashes -r requirements.lock
    rtx scan --format json --output reports/trust.json
```

## Configuration
Environment variables:
- `RTX_HTTP_TIMEOUT` (default `5` seconds)
- `RTX_LOG_LEVEL` (`DEBUG`, `INFO`, `WARN`, `ERROR`)
- `RTX_GITHUB_TOKEN` (optional GraphQL advisory access)

## Next Steps
- Review [CLI Reference](cli.md)
- Explore the [API](api.md)
- Contribute via [CONTRIBUTING.md](../CONTRIBUTING.md)
