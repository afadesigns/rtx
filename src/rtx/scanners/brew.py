from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class BrewScanner(BaseScanner):
    manager = "brew"
    manifests = ["Brewfile"]
    ecosystem = "homebrew"

    def scan(self, root: Path) -> List[Dependency]:
        brewfile = root / "Brewfile"
        dependencies: Dict[str, str] = {}
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
