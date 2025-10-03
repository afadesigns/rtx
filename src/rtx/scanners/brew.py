from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class BrewScanner(BaseScanner):
    manager: ClassVar[str] = "brew"
    manifests: ClassVar[list[str]] = ["Brewfile"]
    ecosystem: ClassVar[str] = "homebrew"

    def scan(self, root: Path) -> list[Dependency]:
        brewfile = root / "Brewfile"
        dependencies: dict[str, str] = {}
        if brewfile.exists():
            dependencies.update(common.read_brewfile(brewfile))

        return [
            self._dependency(
                name=name,
                version=version,
                manifest=brewfile,
                direct=True,
                metadata={"source": brewfile.name},
            )
            for name, version in sorted(dependencies.items())
        ]
