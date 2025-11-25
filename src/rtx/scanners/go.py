from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rtx.models import Dependency, ScannerResult
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class GoScanner(BaseScanner):
    manager: ClassVar[str] = "go"
    manifests: ClassVar[list[str]] = ["go.mod", "go.sum"]
    ecosystem: ClassVar[str] = "go"

    def scan(self, root: Path) -> ScannerResult:
        dependencies: dict[str, str] = {}
        origins: dict[str, Path] = {}
        relationships: list[tuple[str, str]] = []

        go_mod = root / "go.mod"
        if go_mod.exists():
            deps, rels = common.read_go_mod(go_mod)
            for name, version in deps.items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, go_mod)
            relationships.extend(rels)

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

        results: list[Dependency] = [
            self._dependency(
                name=name,
                version=version,
                manifest=origins.get(name, root),
                direct=True,
                metadata={"source": origins.get(name, root).name},
            )
            for name, version in sorted(dependencies.items())
        ]
        return ScannerResult(dependencies=results, relationships=relationships)
