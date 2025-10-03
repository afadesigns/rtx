from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class CondaScanner(BaseScanner):
    manager: ClassVar[str] = "conda"
    manifests: ClassVar[list[str]] = ["environment.yml", "environment.yaml"]
    ecosystem: ClassVar[str] = "conda"

    def scan(self, root: Path) -> list[Dependency]:
        dependencies: dict[str, str] = {}
        origins: dict[str, Path] = {}

        for filename in ("environment.yml", "environment.yaml"):
            path = root / filename
            if path.exists():
                for name, version in common.read_environment_yml(path).items():
                    dependencies.setdefault(name, version)
                    origins.setdefault(name, path)

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
