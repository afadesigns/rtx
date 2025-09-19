# CLI Reference

## `rtx scan`
Scan the current directory (or `--path`) for manifests and compute a trust report.

**Options**
- `--path PATH` — root directory (default `.`)
- `--managers npm pypi` — restrict scanning scope
- `--format table|json|html` — render format (default `table`)
- `--output PATH` — required for JSON/HTML rendering
- `--json-output PATH` — persist JSON report in addition to primary output
- `--html-output PATH` — persist HTML report
- `--sbom-output PATH` — write CycloneDX SBOM
- `--log-level LEVEL` — logging (`INFO` default)

## `rtx pre-upgrade`
Simulate upgrading a dependency before applying changes.

**Options**
- `--path PATH`
- `--manager NAME` — optional (auto-detected otherwise)
- `--package NAME` — dependency to evaluate
- `--version VERSION` — proposed version

Outputs baseline vs. proposed verdict and exits with the higher risk code.

## `rtx report`
Render a stored JSON report into table, JSON, or HTML.

**Options**
- `--input PATH` — path to JSON report
- `--format table|json|html`
- `--output PATH` — required for JSON/HTML

## `rtx list-managers`
List supported package managers and manifest patterns.

```
$ rtx list-managers
npm: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
pypi: pyproject.toml, poetry.lock, requirements.txt, ...
```

## Exit Codes
- `0`: safe
- `1`: warnings (medium severity)
- `2`: high or critical risk detected
