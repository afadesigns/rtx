from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class GoScanner(BaseScanner):
    manager = "go"
    manifests = ["go.mod", "go.sum"]
    ecosystem = "go"

    def scan(self, root: Path) -> List[Dependency]:
        dependencies: Dict[str, str] = {}
        origins: Dict[str, Path] = {}

        go_mod = root / "go.mod"
        if go_mod.exists():
            for name, version in common.read_go_mod(go_mod).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, go_mod)

        go_sum = root / "go.sum"
        if go_sum.exists():
            for line in go_sum.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    name, version = parts[:2]
                    if name.endswith("/go.mod"):
                        name = name[:-7]
                    dependencies.setdefault(name, version)
                    origins.setdefault(name, go_sum)

        return [
            self._dependency(
                name=name,
                version=version,
                manifest=origins.get(name, root),
                direct=True,
                metadata={"source": origins.get(name, root).name},
            )
            for name, version in sorted(dependencies.items())
        ]
