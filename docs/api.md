# Python API

```python
from pathlib import Path

from rtx.api import scan_project

report = scan_project(Path("examples/mixed"))
for finding in report:
    print(finding.dependency.coordinate, finding.verdict)
```

## `scan_project(path: Path, managers: list[str] | None = None) -> Report`
- `path`: Project root.
- `managers`: Optional list (e.g., `['npm', 'pypi']`). Default auto-detect.
- Returns a [`Report`](../src/rtx/models.py) object with findings and summary helpers.

## Report Helpers
- `Report.summary()` — returns counts, signal aggregates, exit code, managers, path.
- `Report.signal_summary` — reusable object with per-category and per-severity signal counts.
- `Report.exit_code()` — convert verdicts into CI-friendly exit code.
- `Report.to_dict()` — JSON-serializable structure (now includes `signal_summary`).

## Extending Scanners
Subclass `rtx.scanners.base.BaseScanner` and register in `rtx.registry.SCANNER_CLASSES`.

```python
from rtx.scanners.base import BaseScanner

class CustomScanner(BaseScanner):
    manager = "custom"
    manifests = ["custom.lock"]
    ecosystem = "custom"

    def scan(self, root):
        ...
```

Re-run `rtx list-managers` to confirm registration.
