from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class ComposerScanner(BaseScanner):
    manager = "composer"
    manifests = ["composer.json", "composer.lock"]
    ecosystem = "packagist"

    def scan(self, root: Path) -> List[Dependency]:
        dependencies: Dict[str, str] = {}
        origins: Dict[str, Path] = {}

        composer_lock = root / "composer.lock"
        if composer_lock.exists():
            for name, version in common.read_composer_lock(composer_lock).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, composer_lock)

        composer_json = root / "composer.json"
        if composer_json.exists():
            data = common.read_json(composer_json)  # type: ignore[attr-defined]
            for section in ("require", "require-dev"):
                section_data = data.get(section, {})
                if isinstance(section_data, dict):
                    for name, version in section_data.items():
                        dependencies.setdefault(name, str(version))
                        origins.setdefault(name, composer_json)

        return [
            self._dependency(
                name=name,
                version=common.normalize_version(version),
                manifest=origins.get(name, root),
                direct=True,
                metadata={"source": origins.get(name, root).name},
            )
            for name, version in sorted(dependencies.items())
        ]
